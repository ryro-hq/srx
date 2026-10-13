//! Checking the application, loader and libraries before execution.
//!
//! # Verifying the executable closure
//!
//! Verification reads artifact ELF metadata and resolves dependencies only through
//! declared providers. It neither calls `ldd` nor executes a file to discover its
//! libraries.
//!
//! # Retaining files until execution ends
//!
//! [`RuntimeClosure`] keeps complete [`RuntimeFile`] values and handles for all
//! outputs. The launcher retains this closure until the namespace settles, before
//! propagating status or releasing retention. [`launch_preparation`](../../src/syrox_engine/runtime/launch_preparation.rs.html) gathers the
//! invocation resources; [`crate::execution`] owns admission and process evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::Read as _;
use std::io::Write as _;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
#[cfg(test)]
use std::process::Child;
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::result::artifact;
use crate::{
    result::MaterializationError, result::MaterializedArtifact, store::ContentDigest,
    store::RootName, store::Store, store::StoreError,
};

pub const MAX_RUNTIME_LIBRARIES: usize = 64;

pub(crate) mod command_proxy;
pub(crate) use crate::execution::configuration;
pub(crate) mod launch_preparation;
mod retention;
pub(crate) mod terminal_custody;
pub use configuration::RuntimeConfiguration;
pub(crate) use configuration::valid_runtime_environment_name;
pub(crate) use elf::validate_static_worker_image;
pub use retention::RetainedRuntime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeOutput {
    pub root: RootName,
    pub receipt: ContentDigest,
    pub output: String,
}

/// An executable path selected within one retained output. Output identity
/// remains independent of the command paths that use it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeFile<T = RuntimeOutput> {
    pub output: T,
    pub path: String,
}

#[derive(Clone, Debug)]
pub struct RuntimeRequest {
    pub application: RuntimeFile,
    /// The exact output containing the ELF interpreter, when `PT_INTERP` exists.
    pub loader: Option<RuntimeFile>,
    /// Outputs supplying `DT_NEEDED` libraries, including transitive ones.
    pub libraries: Vec<RuntimeOutput>,
}

pub use crate::execution::error::RuntimeError;

/// Retains all verified output views for the whole lifetime of the consumer.
/// The launcher holds this value until the namespace init has exited.
#[derive(Debug)]
pub struct RuntimeClosure {
    application: RuntimeFile<MaterializedArtifact>,
    loader: Option<RuntimeFile<MaterializedArtifact>>,
    libraries: Vec<MaterializedArtifact>,
    utf8_locale: Option<String>,
}

#[derive(Debug)]
pub struct RuntimeMount {
    pub source: PathBuf,
    pub target: String,
}

impl RuntimeClosure {
    pub(crate) fn process_retention(&self) -> Result<std::fs::File, StoreError> {
        let interests: Vec<_> = std::iter::once(&self.application.output)
            .chain(self.loader.iter().map(|file| &file.output))
            .chain(self.libraries.iter())
            .map(MaterializedArtifact::object_lease)
            .collect();
        crate::store::ObjectLease::combine(&interests)?.process_retention()
    }

    pub fn application(&self) -> &RuntimeFile<MaterializedArtifact> {
        &self.application
    }
    pub fn loader(&self) -> Option<&RuntimeFile<MaterializedArtifact>> {
        self.loader.as_ref()
    }
    pub fn libraries(&self) -> &[MaterializedArtifact] {
        &self.libraries
    }
    pub fn entry(&self) -> String {
        format!(
            "{}/{}",
            self.application.output.logical_prefix(),
            self.application.path
        )
    }
    /// Revalidate every physical source immediately before constructing the
    /// private mount namespace. The launcher must keep this closure alive until
    /// its process tree settles, and bind these targets read-only.
    pub fn mounts(&self) -> Result<Vec<RuntimeMount>, RuntimeError> {
        Ok(self
            .mount_bindings()?
            .into_iter()
            .map(|(mount, _)| mount)
            .collect())
    }

    fn mount_bindings(&self) -> Result<Vec<(RuntimeMount, BorrowedFd<'_>)>, RuntimeError> {
        let mut seen = BTreeSet::new();
        std::iter::once(&self.application.output)
            .chain(self.loader.iter().map(|file| &file.output))
            .chain(&self.libraries)
            .filter(|view| seen.insert((view.action(), view.identity().output.clone())))
            .map(|view| {
                Ok((
                    RuntimeMount {
                        source: view.directory()?,
                        target: view.logical_prefix(),
                    },
                    view.mount_fd(),
                ))
            })
            .collect()
    }
}

/// Synchronous rootless session. The borrowed closure holds granular Store interests
/// throughout namespace settlement; a private PID namespace kills all
/// remaining descendants when its init exits. No ambient host `/usr` or
/// library-search environment enters the child.
pub fn run_runtime(
    closure: &RuntimeClosure,
    argv: &[OsString],
    working_directory: &std::path::Path,
) -> Result<ExitStatus, RuntimeError> {
    run_runtime_with_cancellation(
        closure,
        argv,
        working_directory,
        &crate::cancellation::Cancellation::default(),
    )
}

/// Run the verified closure while observing CLI cancellation. The native monitor
/// settles its private PID namespace before releasing the process retention.
pub fn run_runtime_with_cancellation(
    closure: &RuntimeClosure,
    argv: &[OsString],
    working_directory: &std::path::Path,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<ExitStatus, RuntimeError> {
    run_runtime_configured_with_cancellation(
        closure,
        argv,
        working_directory,
        &RuntimeConfiguration::default(),
        cancellation,
    )
}

pub fn run_runtime_configured_with_cancellation(
    closure: &RuntimeClosure,
    argv: &[OsString],
    working_directory: &std::path::Path,
    configuration: &RuntimeConfiguration,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<ExitStatus, RuntimeError> {
    run_runtime_attached(
        closure,
        argv,
        working_directory,
        configuration,
        None,
        RuntimeProfile {
            worker: None,
        },
        cancellation,
    )
}

/// Foreground command with the same UID and minimal filesystem profile as a
/// manager-owned service, retaining the direct runtime's exit-status protocol.
/// Its explicit working directory excludes nested host mounts.
#[cfg(test)]
fn run_runtime_managed_with_cancellation(
    worker: &std::path::Path,
    closure: &RuntimeClosure,
    argv: &[OsString],
    working_directory: &std::path::Path,
    configuration: &RuntimeConfiguration,
    terminal: Option<BorrowedFd<'_>>,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<ExitStatus, RuntimeError> {
    check_runtime(cancellation)?;
    if let Some(terminal) = terminal {
        crate::platform::linux::fd::terminal::validate_slave(terminal)?;
    }
    if crate::platform::linux::fd::real_uid() == 0
        || crate::platform::linux::fd::real_uid() != crate::platform::linux::fd::effective_uid()
    {
        return Err(invalid(
            "managed foreground requires an ordinary nonzero user identity",
        ));
    }
    if !crate::execution::resources::valid_managed_working_directory(working_directory) {
        return Err(invalid(
            "working directory overlaps managed runtime filesystems",
        ));
    }
    run_runtime_attached(
        closure,
        argv,
        working_directory,
        configuration,
        terminal,
        RuntimeProfile {
            worker: Some(worker),
        },
        cancellation,
    )
}

#[derive(Clone, Copy)]
struct RuntimeProfile<'a> {
    // Explicit worker is used by low-level managed-profile namespace fixtures.
    // ManagedShell uses command_proxy::launch and its journal authorization.
    worker: Option<&'a std::path::Path>,
}
impl RuntimeProfile<'_> {
    const fn worker_mode(self) -> &'static str {
        if self.worker.is_some() {
            "__runtime-managed"
        } else {
            "__runtime"
        }
    }
}

/// Attach a dedicated PTY slave to the verified payload. The caller owns the
/// master, relay, terminal restoration and cancellation. The runtime retains
/// outputs until the PID namespace is settled; this is not a Shell supervisor.
/// Observe this call's completion independently of master EOF: caller-owned
/// slave copies keep the PTY open and must be closed before waiting for drain.
pub fn run_runtime_with_terminal(
    closure: &RuntimeClosure,
    argv: &[OsString],
    working_directory: &std::path::Path,
    configuration: &RuntimeConfiguration,
    terminal: BorrowedFd<'_>,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<ExitStatus, RuntimeError> {
    check_runtime(cancellation)?;
    crate::platform::linux::fd::terminal::validate_slave(terminal)?;
    run_runtime_attached(
        closure,
        argv,
        working_directory,
        configuration,
        Some(terminal),
        RuntimeProfile {
            worker: None,
        },
        cancellation,
    )
}

struct RuntimeMountPreparation<'a> {
    cwd_descriptor: crate::platform::linux::fd::OpenedPath,
    cwd: PathBuf,
    mounts: Vec<(RuntimeMount, BorrowedFd<'a>)>,
    masked_store: Option<PathBuf>,
}

/// Shared path and descriptor validation for direct and manager-owned launches.
fn prepare_runtime_mounts<'a>(
    closure: &'a RuntimeClosure,
    working_directory: &std::path::Path,
    configuration: &RuntimeConfiguration,
) -> Result<RuntimeMountPreparation<'a>, RuntimeError> {
    if !working_directory.is_absolute()
        || working_directory == std::path::Path::new("/")
        || working_directory.starts_with("/syrox")
    {
        return Err(invalid(
            "runtime working directory must be a non-root absolute path outside /syrox",
        ));
    }
    let cwd_descriptor = crate::platform::linux::fd::open_top_directory(working_directory)
        .map_err(|error| {
            invalid(&format!(
                "cannot open runtime working directory: {error:?}"
            ))
        })?;
    let cwd = crate::platform::linux::fd::directory_path(&cwd_descriptor)?;
    configuration.validate_cwd(&cwd)?;
    let mounts = closure.mount_bindings()?;
    let slots = mounts.len()
        + 1
        + usize::from(configuration.directory.is_some())
        + usize::from(configuration.state.is_some())
        + configuration.secrets.len();
    if slots > crate::execution::resources::MAX_SERVICE_FDS {
        return Err(invalid("runtime descriptor capacity exceeded"));
    }
    let source = &mounts[0].0.source;
    let views = source
        .parent()
        .ok_or_else(|| invalid("invalid view source"))?;
    let private = views
        .parent()
        .ok_or_else(|| invalid("invalid view parent"))?;
    let store = private
        .parent()
        .ok_or_else(|| invalid("invalid Store path"))?;
    if views
        .file_name()
        .is_none_or(|name| name != "views")
        || private
            .file_name()
            .is_none_or(|name| name != ".syrox-store")
        || mounts
            .iter()
            .any(|(mount, _)| !mount.source.starts_with(views))
        || cwd.starts_with(store)
    {
        return Err(invalid(
            "runtime working directory would expose the writable Store",
        ));
    }
    let masked_store = store
        .starts_with(&cwd)
        .then(|| store.to_path_buf());
    Ok(RuntimeMountPreparation {
        cwd_descriptor,
        cwd,
        mounts,
        masked_store,
    })
}

fn runtime_worker(profile: RuntimeProfile<'_>) -> Result<PathBuf, RuntimeError> {
    if let Some(worker) = profile.worker {
        if !worker.is_absolute() {
            return Err(invalid(
                "managed runtime requires an explicit worker snapshot",
            ));
        }
        return Ok(worker.to_owned());
    }
    let executable = std::env::current_exe()?;
    let mut helper = executable.with_file_name("syrox-worker");
    if !helper.is_file()
        && executable
            .parent()
            .is_some_and(|path| path.ends_with("deps"))
    {
        helper = executable
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or_else(|| invalid("missing runtime helper directory"))?
            .join("syrox-worker");
    }
    Ok(helper)
}

fn run_runtime_attached(
    closure: &RuntimeClosure,
    argv: &[OsString],
    working_directory: &std::path::Path,
    configuration: &RuntimeConfiguration,
    terminal: Option<BorrowedFd<'_>>,
    profile: RuntimeProfile<'_>,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<ExitStatus, RuntimeError> {
    if cancellation.is_cancelled() {
        return Err(RuntimeError::Cancelled);
    }
    let RuntimeMountPreparation {
        cwd_descriptor,
        cwd,
        mounts,
        masked_store,
    } = prepare_runtime_mounts(closure, working_directory, configuration)?;
    if profile.worker.is_some() {
        crate::execution::resources::validate_managed_working_descriptor(cwd_descriptor.fd())?;
    }
    // The monitor and sync EOF can both precede kernel teardown of descendants.
    // Block the payload until its namespace PID 1 is pinned by a pidfd, then
    // await that pidfd even on cancellation and post-spawn errors.
    let (mut settled, keepalive) = UnixStream::pair()?;
    let (info, info_writer) = crate::platform::linux::fd::seqpacket_pair()?;
    let (mut gate, gate_reader) = UnixStream::pair()?;
    let keepalive_fd = keepalive.as_raw_fd();
    let info_fd = info_writer.as_raw_fd();
    let gate_fd = gate_reader.as_raw_fd();
    let helper = runtime_worker(profile)?;
    let process_retention = closure.process_retention()?;
    let mut command = crate::platform::linux::fd::PreparedLaunch::new(helper.as_os_str())?;
    command.inherit(process_retention.as_fd());
    // The monitor owns PID 1 and watches the coordinator channel through exit.
    command.args([profile.worker_mode(), "monitor"])?;
    command.arg(keepalive_fd.to_string())?;
    command.arg(info_fd.to_string())?;
    command.arg(gate_fd.to_string())?;
    if let Some(terminal) = terminal {
        command.inherit(terminal);
        command
            .arg("--terminal")?
            .arg(terminal.as_raw_fd().to_string())?;
    }
    for (mount, directory) in mounts {
        let fd = directory.as_raw_fd();
        command.inherit(directory);
        command
            .arg("--ro")?
            .arg(format!("/proc/self/fd/{fd}"))?
            .arg(mount.target)?;
    }
    if let Some(directory) = &configuration.directory {
        configuration::validate_configuration_directory(directory.fd())?;
        let fd = directory.fd().as_raw_fd();
        command.inherit(directory.fd());
        command
            .arg("--config-ro")?
            .arg(format!("/proc/self/fd/{fd}"))?
            .arg(
                configuration
                    .prefix()
                    .expect("configuration prefix"),
            )?;
    }
    if let Some((target, directory)) = &configuration.state {
        configuration::validate_state_directory(directory.fd())?;
        command.inherit(directory.fd());
        command
            .arg("--state-rw")?
            .arg(format!(
                "/proc/self/fd/{}",
                directory.fd().as_raw_fd()
            ))?
            .arg(target)?;
    }
    for (target, file) in &configuration.secrets {
        crate::platform::linux::fd::sealed_file::validate(file.as_fd())?;
        command.inherit(file.as_fd());
        command
            .arg("--secret-ro")?
            .arg(format!("/proc/self/fd/{}", file.as_raw_fd()))?
            .arg(target)?;
    }
    for (name, value) in &configuration.environment {
        command
            .arg("--env")?
            .arg(format!("{name}={value}"))?;
    }
    let cwd_fd = cwd_descriptor.fd().as_raw_fd();
    command.inherit(cwd_descriptor.fd());
    command
        .arg("--rw")?
        .arg(format!("/proc/self/fd/{cwd_fd}"))?
        .arg(&cwd)?;
    if let Some(store) = masked_store {
        // Preserve getcwd while hiding the Store under a private, empty mount.
        // Logical views were already bound by descriptor-verified sources above.
        command.arg("--mask")?.arg(store)?;
    }
    command.arg("--cwd")?.arg(&cwd)?;
    if let Some(locale) = &closure.utf8_locale {
        command.arg("--locale")?.arg(locale)?;
    }
    command.args(["--", &closure.entry()])?;
    command.args(argv)?;
    // Clear CLOEXEC only through spawn actions, so concurrent process launches
    // cannot inherit a writable endpoint and delay the settlement barrier.
    command.inherit(keepalive.as_fd());
    command.inherit(info_writer.as_fd());
    command.inherit(gate_reader.as_fd());
    let mut child = command.spawn()?;
    drop((keepalive, info_writer, gate_reader));
    let mut namespace = None;
    let prepared = prepare_namespace(
        info.as_fd(),
        &mut gate,
        cancellation,
        &mut namespace,
        || {},
    );
    let namespace = match prepared {
        Ok(()) => namespace.expect("successful preparation pinned namespace init"),
        Err(error) => {
            return Err(abort_launch(
                || child.wait(),
                namespace.as_ref(),
                settled,
                gate,
                error,
            ));
        }
    };
    drop(gate);
    let monitor = match crate::platform::linux::fd::pidfd_open(child.id()) {
        Ok(fd) => fd,
        Err(error) => {
            drop(settled);
            child.wait()?;
            crate::platform::linux::fd::wait_pidfd(namespace.as_fd())?;
            return Err(error.into());
        }
    };
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Err(error) => {
                drop(settled);
                crate::platform::linux::fd::kill_pidfd(namespace.as_fd())?;
                let _ = child.wait();
                crate::platform::linux::fd::wait_pidfd(namespace.as_fd())?;
                return Err(error.into());
            }
            Ok(None) => {}
        }
        if cancellation.is_cancelled() {
            drop(settled);
            let status = child.wait();
            crate::platform::linux::fd::wait_pidfd(namespace.as_fd())?;
            return status.map_err(Into::into);
        }
        if let Err(error) = crate::execution::native::wait_event(monitor.as_fd(), cancellation) {
            drop(settled);
            child.wait()?;
            crate::platform::linux::fd::wait_pidfd(namespace.as_fd())?;
            return Err(error.into());
        }
    };
    let mut buffer = [0_u8; 1];
    let sync = settled.read(&mut buffer);
    crate::platform::linux::fd::wait_pidfd(namespace.as_fd())?;
    if sync? != 0 {
        return Err(invalid(
            "runtime settlement descriptor contained data",
        ));
    }
    Ok(status)
}

fn receive_namespace(
    info: BorrowedFd<'_>,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<std::os::fd::OwnedFd, RuntimeError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        check_runtime(cancellation)?;
        match crate::platform::linux::fd::receive_fd(info) {
            Ok(fd) => {
                crate::platform::linux::fd::validate_pidfd(fd.as_fd())?;
                return Ok(fd);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(invalid("runtime namespace preparation timed out"));
        }
        crate::execution::native::wait_event_timeout(
            info,
            cancellation,
            i32::try_from(remaining.as_millis()).unwrap_or(10_000),
        )?;
    }
}

/// Pin the namespace descriptor before authorizing execution. The hook allows
/// tests to cancel at the exact boundary used by the production coordinator.
fn prepare_namespace(
    info: BorrowedFd<'_>,
    gate: &mut UnixStream,
    cancellation: &crate::cancellation::Cancellation,
    namespace: &mut Option<std::os::fd::OwnedFd>,
    after_pin: impl FnOnce(),
) -> Result<(), RuntimeError> {
    *namespace = Some(receive_namespace(info, cancellation)?);
    after_pin();
    check_runtime(cancellation)?;
    gate.write_all(b"x")?;
    Ok(())
}

fn abort_launch(
    wait_monitor: impl FnOnce() -> std::io::Result<ExitStatus>,
    namespace: Option<&std::os::fd::OwnedFd>,
    settled: UnixStream,
    gate: UnixStream,
    primary: RuntimeError,
) -> RuntimeError {
    // Coordinator loss and authorization EOF both fail closed. The monitor
    // settles its init before exit and before releasing process interests.
    drop((settled, gate));
    if let Err(error) = wait_monitor() {
        return error.into();
    }
    if let Some(pinned) = namespace
        && let Err(error) = crate::platform::linux::fd::wait_pidfd(pinned.as_fd())
    {
        return error.into();
    }
    primary
}

/// Materializes only explicitly named, retained outputs. Reads ELF metadata as
/// bytes from verified artifacts; it never calls `ldd` or runs a supplied file.
pub fn verify_runtime(
    store: &Store,
    request: &RuntimeRequest,
) -> Result<RuntimeClosure, RuntimeError> {
    verify_runtime_with_cancellation(
        store,
        request,
        &crate::cancellation::Cancellation::default(),
    )
}

pub fn verify_runtime_with_cancellation(
    store: &Store,
    request: &RuntimeRequest,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<RuntimeClosure, RuntimeError> {
    verify_runtime_request(store, request, cancellation, true)
}

fn verify_runtime_request(
    store: &Store,
    request: &RuntimeRequest,
    cancellation: &crate::cancellation::Cancellation,
    allow_application_retention: bool,
) -> Result<RuntimeClosure, RuntimeError> {
    check_runtime(cancellation)?;
    if request.libraries.len() > MAX_RUNTIME_LIBRARIES {
        return Err(invalid("too many library outputs"));
    }
    let application = crate::result::materialize::materialize_named_with_cancellation(
        store,
        &request.application.output.root,
        request.application.output.receipt,
        &request.application.output.output,
        cancellation,
    )
    .map_err(materialization_error)?;
    let mut views: BTreeMap<(RootName, ContentDigest, String), MaterializedArtifact> =
        BTreeMap::new();
    let mut provider_view = |output: &RuntimeOutput| -> Result<MaterializedArtifact, RuntimeError> {
        check_runtime(cancellation)?;
        let key = (
            output.root.clone(),
            output.receipt,
            output.output.clone(),
        );
        if let Some(view) = views.get(&key) {
            return Ok(view.share());
        }
        let lease = store.operation()?;
        check_runtime(cancellation)?;
        let independent = lease.build_references(&output.root)?.is_some();
        drop(lease);
        let view = if independent || !allow_application_retention {
            crate::result::materialize::materialize_named_with_cancellation(
                store,
                &output.root,
                output.receipt,
                &output.output,
                cancellation,
            )
            .map_err(materialization_error)?
        } else {
            crate::result::materialize::materialize_provider_with_cancellation(
                store,
                &request.application.output.root,
                request.application.output.receipt,
                output.receipt,
                &output.output,
                cancellation,
            )
            .map_err(materialization_error)?
        };
        views.insert(key, view.share());
        Ok(view)
    };
    let loader = request
        .loader
        .as_ref()
        .map(|file| {
            Ok::<_, RuntimeError>(RuntimeFile {
                output: provider_view(&file.output)?,
                path: file.path.clone(),
            })
        })
        .transpose()?;
    let libraries = request
        .libraries
        .iter()
        .map(provider_view)
        .collect::<Result<Vec<_>, _>>()?;
    verify_materialized_runtime(
        RuntimeFile {
            output: application,
            path: request.application.path.clone(),
        },
        loader,
        libraries,
        cancellation,
    )
}

/// Verify retained materialized outputs independently of their build or import
/// origin. All ELF metadata is read from verified artifact bytes; supplied files
/// are never executed. The returned closure owns every view until settlement.
pub fn verify_materialized_runtime(
    application: RuntimeFile<MaterializedArtifact>,
    loader: Option<RuntimeFile<MaterializedArtifact>>,
    libraries: Vec<MaterializedArtifact>,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<RuntimeClosure, RuntimeError> {
    check_runtime(cancellation)?;
    if libraries.len() > MAX_RUNTIME_LIBRARIES {
        return Err(invalid("too many library outputs"));
    }
    if !valid_runtime_path(&application.path)
        || loader
            .as_ref()
            .is_some_and(|file| !valid_runtime_path(&file.path))
    {
        return Err(invalid(
            "runtime file path must be canonical and relative",
        ));
    }
    verify_output_identities(&application, loader.as_ref(), &libraries)?;
    let mut inspection = RuntimeInspection {
        inspected: BTreeMap::new(),
        cancellation,
    };
    let executable = inspection.application(&application)?;
    let (consumers, loader_soname) = inspection.interpreter(executable, loader.as_ref())?;
    let mut providers = inspection.providers(&libraries)?;
    verify_elf_dependencies(
        consumers,
        loader_soname.as_deref(),
        loader.as_ref(),
        &mut providers,
        cancellation,
    )?;
    check_runtime(cancellation)?;
    Ok(RuntimeClosure {
        application,
        loader,
        libraries,
        utf8_locale: providers.utf8_locale,
    })
}

fn verify_output_identities(
    application: &RuntimeFile<MaterializedArtifact>,
    loader: Option<&RuntimeFile<MaterializedArtifact>>,
    libraries: &[MaterializedArtifact],
) -> Result<(), RuntimeError> {
    let mut actions = BTreeMap::new();
    for view in std::iter::once(&application.output)
        .chain(loader.map(|file| &file.output))
        .chain(libraries)
    {
        if actions
            .insert(
                (view.action(), view.identity().output.clone()),
                view.identity(),
            )
            .is_some_and(|identity| identity != view.identity())
        {
            return Err(invalid(
                "a runtime output prefix is bound to conflicting identities",
            ));
        }
    }
    Ok(())
}

/// Artifact inspection belongs to this verification operation; repeated roles
/// share verified metadata while the caller retains every materialized handle.
struct RuntimeInspection<'a> {
    inspected: BTreeMap<(crate::result::OutputIdentity, String), Arc<[InspectedFile]>>,
    cancellation: &'a crate::cancellation::Cancellation,
}

struct RuntimeProviders {
    directories: BTreeMap<String, String>,
    elf: BTreeMap<String, Elf>,
    utf8_locale: Option<String>,
}

impl RuntimeInspection<'_> {
    fn files(
        &mut self,
        view: &MaterializedArtifact,
        entry: &str,
    ) -> Result<Arc<[InspectedFile]>, RuntimeError> {
        let key = (view.identity().clone(), entry.to_owned());
        if let Some(found) = self.inspected.get(&key) {
            return Ok(Arc::clone(found));
        }
        let found = Arc::from(files(view, entry, self.cancellation)?);
        self.inspected.insert(key, Arc::clone(&found));
        Ok(found)
    }

    fn application(
        &mut self,
        application: &RuntimeFile<MaterializedArtifact>,
    ) -> Result<Elf, RuntimeError> {
        let program_files = self.files(&application.output, &application.path)?;
        let program = program_files
            .iter()
            .find(|file| file.path == application.path)
            .ok_or_else(|| invalid("missing application entry"))?;
        let executable = program
            .elf
            .clone()
            .ok_or_else(|| invalid("application is not ELF"))?;
        if executable.kind != 2 && executable.kind != 3 {
            return Err(invalid("application is not an ELF executable"));
        }
        if executable.interpreter.is_none() && !executable.needed.is_empty() {
            return Err(invalid(
                "application has dependencies but no declared ELF interpreter",
            ));
        }
        Ok(executable)
    }

    fn interpreter(
        &mut self,
        executable: Elf,
        loader: Option<&RuntimeFile<MaterializedArtifact>>,
    ) -> Result<(Vec<Elf>, Option<String>), RuntimeError> {
        let mut consumers = vec![executable];
        let mut loader_soname = None;
        match (&consumers[0].interpreter, loader) {
            (None, None) => {}
            (Some(interpreter), Some(loader))
                if *interpreter
                    == format!(
                        "{}/{}",
                        loader.output.logical_prefix(),
                        loader.path
                    ) =>
            {
                let loader_files = self.files(&loader.output, &loader.path)?;
                let loader_file = loader_files
                    .iter()
                    .find(|file| file.path == loader.path)
                    .ok_or_else(|| invalid("missing loader entry"))?;
                let loader_elf = loader_file
                    .elf
                    .clone()
                    .ok_or_else(|| invalid("loader is not ELF"))?;
                if loader_elf.kind != 3 || loader_elf.interpreter.is_some() {
                    return Err(invalid(
                        "loader is not a standalone ELF interpreter",
                    ));
                }
                loader_soname.clone_from(&loader_elf.soname);
                consumers.push(loader_elf);
            }
            _ => {
                return Err(invalid(
                    "ELF interpreter is missing, undeclared or points outside the closure",
                ));
            }
        }
        Ok((consumers, loader_soname))
    }

    fn providers(
        &mut self,
        libraries: &[MaterializedArtifact],
    ) -> Result<RuntimeProviders, RuntimeError> {
        let mut providers = BTreeMap::new();
        let mut provider_elf = BTreeMap::new();
        let mut utf8_locale = None;
        for view in libraries {
            check_runtime(self.cancellation)?;
            let artifact_files = self.files(view, "")?;
            if artifact_files
                .iter()
                .any(|file| file.path == "usr/lib/locale/C.utf8/LC_CTYPE")
                && utf8_locale
                    .replace(format!(
                        "{}/usr/lib/locale",
                        view.logical_prefix()
                    ))
                    .is_some()
            {
                return Err(invalid("duplicate UTF-8 locale providers"));
            }
            let mut supplied = 0;
            for file in artifact_files.iter().filter(|file| {
                file.path
                    .strip_prefix("usr/lib/")
                    .is_some_and(|name| !name.contains('/') && name.contains(".so"))
            }) {
                // A development output may contain a linker script named libc.so;
                // the runtime loader resolves only ELF DT_NEEDED SONAMEs. A needed
                // name backed solely by a script still fails the provider check.
                let Some(lib) = file.elf.clone() else {
                    continue;
                };
                if lib.kind != 3 {
                    return Err(invalid("library is not an ELF shared object"));
                }
                let soname = lib
                    .soname
                    .as_ref()
                    .ok_or_else(|| invalid("library has no SONAME"))?;
                if file.path.rsplit('/').next() != Some(soname) {
                    if file.alias_target {
                        continue;
                    }
                    return Err(invalid("library filename disagrees with SONAME"));
                }
                if providers
                    .insert(
                        soname.clone(),
                        format!("{}/usr/lib", view.logical_prefix()),
                    )
                    .is_some()
                {
                    return Err(invalid("duplicate library SONAME"));
                }
                provider_elf.insert(soname.clone(), lib);
                supplied += 1;
            }
            if supplied == 0 {
                return Err(invalid("library output supplies no ELF library"));
            }
        }
        Ok(RuntimeProviders {
            directories: providers,
            elf: provider_elf,
            utf8_locale,
        })
    }
}

fn verify_elf_dependencies(
    mut consumers: Vec<Elf>,
    loader_soname: Option<&str>,
    loader: Option<&RuntimeFile<MaterializedArtifact>>,
    provider: &mut RuntimeProviders,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<(), RuntimeError> {
    let providers = &mut provider.directories;
    let provider_elf = &mut provider.elf;
    // Installed NSS, tracing and math modules are legitimate members of a
    // complete glibc runtime, but their DT_NEEDED entries are not dependencies
    // of this executable unless the executable's graph actually reaches them.
    // Require every installed module's dependencies to have providers, while
    // resolving RUNPATH only along the graph rooted at the application and its
    // declared interpreter.
    if provider_elf
        .values()
        .flat_map(|elf| &elf.needed)
        .any(|name| Some(name.as_str()) != loader_soname && !providers.contains_key(name))
    {
        return Err(invalid(
            "installed library has an undeclared ELF dependency",
        ));
    }
    let mut required = BTreeSet::new();
    let mut frontier = consumers
        .iter()
        .flat_map(|elf| elf.needed.iter().cloned())
        .collect::<Vec<_>>();
    while let Some(name) = frontier.pop() {
        check_runtime(cancellation)?;
        if !required.insert(name.clone()) {
            continue;
        }
        if required.len() > MAX_NEEDED {
            return Err(invalid("too many ELF dependencies"));
        }
        if Some(name.as_str()) == loader_soname {
            continue;
        }
        let library = provider_elf
            .remove(&name)
            .ok_or_else(|| invalid("missing declared ELF library"))?;
        frontier.extend(library.needed.iter().cloned());
        consumers.push(library);
    }
    if let Some(soname) = loader_soname.filter(|name| required.contains(*name)) {
        let expected = format!(
            "{}/usr/lib",
            loader
                .expect("loader was validated")
                .output
                .logical_prefix()
        );
        if loader.and_then(|file| file.path.rsplit('/').next()) != Some(soname)
            || providers
                .get(soname)
                .is_some_and(|actual| actual != &expected)
        {
            return Err(invalid(
                "loader SONAME must be supplied by its own output",
            ));
        }
        providers.insert(soname.to_owned(), expected);
    }
    if required.len() > MAX_NEEDED
        || required
            .iter()
            .any(|name| !providers.contains_key(name))
    {
        return Err(invalid("missing declared ELF library"));
    }
    if !required.is_empty() && loader.is_none() {
        return Err(invalid(
            "dynamic libraries require a declared loader",
        ));
    }
    let permitted = providers
        .values()
        .cloned()
        .collect::<BTreeSet<_>>();
    for elf in &consumers {
        check_runtime(cancellation)?;
        let directories = elf
            .needed
            .iter()
            // glibc's libc.so.6 names its interpreter as DT_NEEDED but its
            // loader is already bound exactly by PT_INTERP, without RUNPATH.
            .filter(|name| Some(name.as_str()) != loader_soname)
            .map(|name| {
                providers
                    .get(name)
                    .cloned()
                    .ok_or_else(|| invalid("missing declared ELF library"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let search = elf.runpath.as_deref().unwrap_or("");
        let declared = if search.is_empty() {
            BTreeSet::new()
        } else {
            search.split(':').map(str::to_owned).collect()
        };
        if !directories.is_subset(&declared)
            || !declared.is_subset(&permitted)
            || (!search.is_empty() && search.split(':').count() != declared.len())
        {
            return Err(invalid(
                "ELF RUNPATH does not resolve solely through declared library directories",
            ));
        }
    }
    Ok(())
}

#[derive(Clone)]
struct InspectedFile {
    path: String,
    elf: Option<Elf>,
    alias_target: bool,
}

fn files(
    view: &MaterializedArtifact,
    entry: &str,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<Vec<InspectedFile>, RuntimeError> {
    check_runtime(cancellation)?;
    let input = view
        .open_artifact(cancellation)
        .map_err(materialization_error)?;
    let mut indexed =
        artifact::IndexedArtifact::open_checked(input, entry, cancellation).map_err(|_| {
            if cancellation.is_cancelled() {
                RuntimeError::Cancelled
            } else {
                invalid("invalid runtime artifact")
            }
        })?;
    let mut files = Vec::with_capacity(indexed.files().len());
    let (indexed_files, reader) = indexed.parts();
    for file in indexed_files.iter() {
        check_runtime(cancellation)?;
        let inspect = file.path == entry
            || file
                .path
                .strip_prefix("usr/lib/")
                .is_some_and(|name| !name.contains('/') && name.contains(".so"));
        let elf = if inspect {
            let size =
                usize::try_from(file.size).map_err(|_| invalid("ELF exceeds address space"))?;
            let magic = artifact::IndexedArtifact::<crate::store::VerifiedReader>::range_from(
                reader,
                &file,
                0,
                size.min(4),
                cancellation,
            )
            .map_err(runtime_read_error)?;
            if magic == b"\x7fELF" {
                Some(inspect_ranges(size, |start, length| {
                    artifact::IndexedArtifact::<crate::store::VerifiedReader>::range_from(
                        reader,
                        &file,
                        start,
                        length,
                        cancellation,
                    )
                    .map_err(runtime_read_error)
                })?)
            } else {
                None
            }
        } else {
            None
        };
        files.push(InspectedFile {
            path: file.path.to_owned(),
            elf,
            alias_target: file.alias_target,
        });
    }
    Ok(files)
}

fn valid_runtime_path(path: &str) -> bool {
    path.len() <= 4096 && crate::build::relative_path(path)
}

fn check_runtime(cancellation: &crate::cancellation::Cancellation) -> Result<(), RuntimeError> {
    if cancellation.is_cancelled() {
        Err(RuntimeError::Cancelled)
    } else {
        Ok(())
    }
}

fn runtime_read_error(error: std::io::Error) -> RuntimeError {
    if crate::cancellation::is_cancellation_io(&error) {
        RuntimeError::Cancelled
    } else {
        RuntimeError::Io(error)
    }
}

fn materialization_error(error: MaterializationError) -> RuntimeError {
    if matches!(error, MaterializationError::Cancelled) {
        RuntimeError::Cancelled
    } else {
        error.into()
    }
}

fn invalid(reason: &str) -> RuntimeError {
    RuntimeError::Invalid(reason.to_owned())
}

mod elf;
use elf::{Elf, MAX_NEEDED, inspect_ranges};
#[cfg(test)]
use elf::{checked, inspect};

#[cfg(test)]
pub(crate) mod tests;

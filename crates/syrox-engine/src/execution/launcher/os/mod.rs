use crate::deployment::os::{
    activation::{ActivationJournal, ExecutionEpoch},
    installation::{GenerationInstallation, RetainedGeneration},
    launch_binding::OsLaunchBinding,
    paths::OsExecutionPaths,
    runtime::prepare_bound_os_runtime,
};
use crate::runtime::launch_preparation::PreparedRuntimeLaunch;
use crate::systemd::persistent::{OsUnitContract, OsUnitInput};
use crate::{
    cancellation::Cancellation, store::ContentDigest, store::Store, systemd::SystemdManager,
    systemd::SystemdNotifier, systemd::SystemdNotifyEndpoint, systemd::SystemdUnitStatus,
};
use std::ffi::OsString;
use std::io;
use std::os::fd::AsFd as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use thiserror::Error;
mod context;
use context::{Arguments, check, remaining};

#[derive(Debug, Error)]
pub enum OsWorkerError {
    #[error("Os start denied: {0}")]
    Denied(&'static str),
    #[error("invalid Os worker: {0}")]
    Invalid(&'static str),
    #[error("Os worker I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Manager(#[from] crate::systemd::SystemdError),
    #[error("Os worker evidence failed: {0}")]
    Evidence(&'static str),
}
fn invalid(message: &'static str) -> OsWorkerError {
    OsWorkerError::Invalid(message)
}
fn evidence<E>(stage: &'static str) -> impl FnOnce(E) -> OsWorkerError {
    move |_| OsWorkerError::Evidence(stage)
}

/// # Safety
/// Dedicated single-threaded worker only. The process must exit after return;
/// runtime namespaces and process signal masks are deliberately not restored.
pub unsafe fn run_os_service(
    args: &[OsString],
    cancel: &Cancellation,
) -> Result<i32, OsWorkerError> {
    let started = Instant::now();
    let arguments = Arguments::parse(args)?;
    let invocation = context::invocation(
        &std::env::var("INVOCATION_ID").map_err(|_| invalid("missing invocation"))?,
    )?;
    let endpoint = SystemdNotifyEndpoint::new(
        &std::env::var("NOTIFY_SOCKET").map_err(|_| invalid("missing notify endpoint"))?,
    )?;
    let installation = GenerationInstallation::open_existing(
        &arguments.installation,
        cancel,
        started + Duration::from_secs(300),
    )
    .map_err(evidence("open installation"))?;
    let binding = installation
        .read_launch_binding(
            arguments.binding,
            cancel,
            started + Duration::from_secs(300),
        )
        .map_err(evidence("read launch binding"))?;
    let deadline = started + binding.context().start_timeout();
    check(deadline, cancel)?;
    if arguments.store != binding.context().store()
        || installation.id() != binding.installation_id()
    {
        return Err(invalid("argv differs from pinned launch context"));
    }
    context::identity(&binding)?;
    let mut manager = SystemdManager::connect(
        binding.context().scope(),
        remaining(deadline)?,
        cancel,
    )?;
    authenticate(
        &mut manager,
        &binding,
        &invocation,
        deadline,
        cancel,
    )?;
    let opened = open_runtime(
        &arguments,
        &installation,
        binding,
        cancel,
        deadline,
    )?;
    let loaded = manager.observe_os_unit(&opened.contract, remaining(deadline)?, cancel)?;
    let (_launcher_identity, admission) = capture_admission(
        &opened,
        arguments.binding,
        &invocation,
        cancel,
        deadline,
    )?;
    let notifier = SystemdNotifier::connect(&endpoint, remaining(deadline)?, cancel)?;
    let retention = handoff_retention(
        &mut manager,
        &opened,
        &invocation,
        &notifier,
        deadline,
        cancel,
    )?;
    let worker = opened
        .prepared
        .spec
        .worker_request(&opened.prepared.descriptors)
        .map_err(evidence("validate runtime descriptors"))?;
    let result = (|| {
        // SAFETY: this entry point requires the dedicated single-threaded worker.
        let mut runtime = unsafe { crate::execution::native::prepare_managed_runtime(&worker) }?;
        runtime.wait_prepared(deadline, cancel)?;
        crate::platform::linux::fd::validate_pidfd(runtime.namespace())?;
        opened.revalidate(cancel, deadline)?;
        authenticate(
            &mut manager,
            &opened.binding,
            &invocation,
            deadline,
            cancel,
        )?;
        observe_store(
            &mut manager,
            &opened.binding,
            &invocation,
            1,
            deadline,
            cancel,
        )?;
        let current = manager.observe_os_unit(&opened.contract, remaining(deadline)?, cancel)?;
        if current.fingerprint() != loaded.fingerprint() || current.manager() != loaded.manager() {
            return Err(invalid(
                "loaded unit changed before namespace release",
            ));
        }
        authenticate(
            &mut manager,
            &opened.binding,
            &invocation,
            deadline,
            cancel,
        )?;
        let namespace =
            crate::platform::linux::fd::persisted_namespace::CapturedNamespace::capture(
                runtime.namespace(),
                cancel,
                deadline,
            )?;
        opened
            .journal
            .with_namespace_start(admission, &namespace, cancel, deadline, || {
                runtime.release_gate(deadline, cancel)
            })
            .map_err(admission_error)?;
        runtime.await_exec(deadline, cancel)?;
        notifier.ready(remaining(deadline)?, cancel)?;
        let status = runtime.wait(|| {
            let _ = notifier.stopping(Duration::from_secs(1), &Cancellation::default());
        })?;
        Ok(payload_envelope(status))
    })();
    let _ = notifier.stopping(Duration::from_secs(1), &Cancellation::default());
    // Runtime drops/settles its namespace before either local interest is released.
    drop(retention);
    drop(opened);
    result
}
fn payload_envelope(status: std::process::ExitStatus) -> i32 {
    // The manager observes the launcher envelope, not the original payload status.
    eprintln!(
        "syrox Os payload: code={:?} signal={:?}",
        status.code(),
        status.signal()
    );
    i32::from(!status.success())
}
#[allow(clippy::needless_pass_by_value)] // map_err consumes the journal error; only its typed denial survives classification.
fn admission_error(error: crate::deployment::os::activation::ActivationError) -> OsWorkerError {
    match error {
        crate::deployment::os::activation::ActivationError::StartDenied(reason) => {
            OsWorkerError::Denied(reason)
        }
        _ => OsWorkerError::Evidence("start admission or gate failed"),
    }
}
fn capture_admission(
    opened: &Opened,
    pin: ContentDigest,
    invocation: &[u8; 16],
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<
    (
        crate::platform::linux::fd::persisted_namespace::CapturedLauncher,
        crate::deployment::os::activation::StartAdmission,
    ),
    OsWorkerError,
> {
    let launcher_identity =
        crate::platform::linux::fd::persisted_namespace::CapturedLauncher::capture_self(
            cancel, deadline,
        )?;
    let admission = opened
        .journal
        .admit_captured_start(
            &opened.binding.process_key(),
            pin,
            &opened.binding.unit(),
            &context::hex(invocation),
            opened.binding.epoch(),
            &launcher_identity,
            cancel,
            deadline,
        )
        .map_err(admission_error)?;
    Ok((launcher_identity, admission))
}
fn handoff_retention(
    manager: &mut SystemdManager,
    opened: &Opened,
    invocation: &[u8; 16],
    notifier: &SystemdNotifier,
    deadline: Instant,
    cancel: &Cancellation,
) -> Result<std::fs::File, OsWorkerError> {
    let retention = opened
        .generation
        .process_retention()
        .map_err(evidence("retain generation objects"))?;
    // The loaded contract requires FileDescriptorStorePreserve=no. Each attempt
    // starts a fresh handoff; durable generation roots, not this ephemeral FD,
    // retain its closure and launcher between invocations. Zero is not settlement.
    observe_store(
        manager,
        &opened.binding,
        invocation,
        0,
        deadline,
        cancel,
    )?;
    notifier.store_fd(
        "retention",
        retention.as_fd(),
        remaining(deadline)?,
        cancel,
    )?;
    notifier.barrier(remaining(deadline)?, cancel)?;
    observe_store(
        manager,
        &opened.binding,
        invocation,
        1,
        deadline,
        cancel,
    )?;
    Ok(retention)
}

struct Opened {
    binding: OsLaunchBinding,
    paths: OsExecutionPaths,
    generation: RetainedGeneration,
    configuration: crate::deployment::os::installation::GenerationConfiguration,
    launcher: crate::deployment::os::installation::GenerationLauncher,
    prepared: PreparedRuntimeLaunch,
    journal: ActivationJournal,
    contract: OsUnitContract,
}
impl Opened {
    fn revalidate(&self, cancel: &Cancellation, deadline: Instant) -> Result<(), OsWorkerError> {
        self.paths
            .revalidate(cancel, deadline)
            .map_err(evidence("revalidate execution paths"))?;
        self.launcher
            .verify_path(cancel, deadline)
            .map_err(evidence("verify launcher snapshot"))?;
        self.configuration
            .service(self.binding.service())
            .map_err(evidence("verify configuration"))?;
        Ok(())
    }
}

fn open_runtime(
    args: &Arguments,
    installation: &GenerationInstallation,
    binding: OsLaunchBinding,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<Opened, OsWorkerError> {
    let paths = OsExecutionPaths::open(
        &args.installation,
        &args.store,
        binding.cwd(),
        cancel,
        deadline,
    )
    .map_err(evidence("open execution paths"))?;
    let store = Store::open_existing(paths.store()).map_err(evidence("open Store"))?;
    let generation = installation
        .open(&store, binding.generation(), cancel, deadline)
        .map_err(evidence("open retained generation"))?;
    let launcher = installation
        .open_launcher(&generation, cancel, deadline)
        .map_err(evidence("open launcher snapshot"))?;
    launcher
        .verify_path(cancel, deadline)
        .map_err(evidence("verify launcher snapshot"))?;
    context::verify_image(launcher.digest(), cancel, deadline)?;
    let configuration = installation
        .open_configuration(&generation, cancel, deadline)
        .map_err(evidence("open configuration"))?;
    let (file, path) = configuration
        .service(binding.service())
        .map_err(evidence("verify configuration"))?;
    if path != binding.configuration() {
        return Err(invalid(
            "configuration differs from launch binding",
        ));
    }
    let prepared = prepare_bound_os_runtime(&generation, &binding, file, cancel)
        .map_err(evidence("prepare bound runtime"))?;
    let journal = ActivationJournal::open_existing(paths.installation(), cancel, deadline)
        .map_err(evidence("open activation journal"))?;
    let context = binding.context();
    let contract = OsUnitContract::new(OsUnitInput {
        restart: context.restart(),
        unit: binding.unit(),
        scope: context.scope(),
        worker: launcher.path().into(),
        installation: paths.installation().into(),
        store: paths.store().into(),
        binding: args.binding,
        fragment: context.fragment().into(),
        uid: context.uid(),
        gid: context.gid(),
        start_timeout: context.start_timeout(),
        stop_timeout: context.stop_timeout(),
    })?;
    check(deadline, cancel)?;
    Ok(Opened {
        binding,
        paths,
        generation,
        configuration,
        launcher,
        prepared,
        journal,
        contract,
    })
}
fn authenticate(
    manager: &mut SystemdManager,
    binding: &OsLaunchBinding,
    invocation: &[u8; 16],
    deadline: Instant,
    cancel: &Cancellation,
) -> Result<(), OsWorkerError> {
    let identity = manager.observe_identity(remaining(deadline)?, cancel)?;
    let epoch = ExecutionEpoch {
        boot: crate::platform::linux::boot::BootId::current(cancel, deadline)
            .map_err(evidence("observe boot identity"))?,
        manager: identity.fingerprint().to_string(),
        scope: binding.context().scope_key(),
    };
    if &epoch != binding.epoch() {
        return Err(OsWorkerError::Denied(
            "boot or manager epoch differs from authorization",
        ));
    }
    let status = manager
        .query(&binding.unit(), remaining(deadline)?, cancel)?
        .ok_or_else(|| invalid("worker unit is absent"))?;
    validate_main(
        &status,
        &binding.unit(),
        invocation,
        std::process::id(),
    )
}
fn validate_main(
    status: &SystemdUnitStatus,
    unit: &crate::systemd::SystemdUnitName,
    invocation: &[u8; 16],
    pid: u32,
) -> Result<(), OsWorkerError> {
    if &status.unit != unit
        || status.invocation != invocation
        || status.main_pid != pid
        || pid == 0
        || status.active_state != "activating"
    {
        return Err(invalid(
            "worker is not the activating MainPID invocation",
        ));
    }
    Ok(())
}
fn observe_store(
    manager: &mut SystemdManager,
    binding: &OsLaunchBinding,
    invocation: &[u8; 16],
    count: u32,
    deadline: Instant,
    cancel: &Cancellation,
) -> Result<(), OsWorkerError> {
    authenticate(manager, binding, invocation, deadline, cancel)?;
    let state = manager
        .query_fd_store(&binding.unit(), remaining(deadline)?, cancel)?
        .ok_or_else(|| invalid("FD store unit disappeared"))?;
    if state.invocation != invocation
        || state.count != count
        || state.max != 1
        || state.notify_access != "main"
    {
        return Err(invalid("manager FD store observation differs"));
    }
    Ok(())
}
#[cfg(test)]
mod tests;

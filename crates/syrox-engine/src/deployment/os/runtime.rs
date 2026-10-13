//! Preparing the runtime of an Os generation's process.
//!
//! The caller owns configuration publication and separation of installation from
//! cwd. A directory descriptor cannot stop its owner from removing files;
//! configuration must remain immutable until execution settles.

use super::{
    installation::RetainedGeneration,
    launch_binding::OsLaunchBinding,
    manifest::{Argument, Config},
};
use crate::execution::configuration::{
    MAX_CONFIGURATION_BYTES, MAX_CONFIGURATION_DEPTH, MAX_CONFIGURATION_ENTRIES,
};
use crate::platform::linux::fd::{self as linux_fd, FileType, OpenedPath};
use crate::runtime::launch_preparation::{PreparedRuntimeLaunch, prepare_runtime_launch};
use crate::{cancellation::Cancellation, runtime::RuntimeConfiguration, store::ContentDigest};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum OsRuntimeError {
    #[error("invalid retained Os runtime: {0}")]
    Invalid(&'static str),
    #[error("Os runtime preparation cancelled")]
    Cancelled,
    #[error("Os runtime preparation deadline expired")]
    Deadline,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Runtime(#[from] crate::runtime::RuntimeError),
}
type Result<T> = std::result::Result<T, OsRuntimeError>;

pub(crate) fn prepare_os_runtime(
    generation: &RetainedGeneration,
    service: &str,
    process: &str,
    cwd: &Path,
    configuration: File,
    cancellation: &Cancellation,
) -> Result<PreparedRuntimeLaunch> {
    check(cancellation)?;
    let manifest = generation.manifest();
    let key = format!("{service}/{process}");
    let process = manifest
        .processes
        .get(&key)
        .ok_or_else(|| invalid("process is absent from retained generation"))?;
    let command_key = &process.command;
    let command = manifest
        .commands
        .get(command_key)
        .ok_or_else(|| invalid("retained process command is absent"))?;
    if command.service.as_deref() != Some(service) {
        return Err(invalid(
            "retained process command belongs to another service",
        ));
    }
    let closure = generation
        .commands()
        .get(command_key)
        .ok_or_else(|| invalid("verified runtime closure is absent"))?;
    verify_configuration(generation, service, &configuration, cancellation)?;
    let argv = command
        .arguments
        .iter()
        .map(|argument| render(service, argument).map(OsString::from))
        .collect::<Result<Vec<_>>>()?;
    let environment = command
        .environment
        .iter()
        .map(|(name, argument)| Ok((name.clone(), render(service, argument)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let configuration = RuntimeConfiguration::new(service, configuration, environment)?;
    check(cancellation)?;
    prepare_runtime_launch(closure, &argv, cwd, &configuration, cancellation).map_err(Into::into)
}

pub(crate) fn prepare_bound_os_runtime(
    generation: &RetainedGeneration,
    binding: &OsLaunchBinding,
    configuration: File,
    cancellation: &Cancellation,
) -> Result<PreparedRuntimeLaunch> {
    check(cancellation)?;
    if generation.installation_id() != binding.installation_id()
        || generation.digest() != binding.generation()
        || &generation.manifest().launcher != binding.launcher()
    {
        return Err(invalid(
            "launch binding belongs to another retained generation or launcher",
        ));
    }
    if !generation
        .manifest()
        .processes
        .get(&binding.process_key())
        .is_some_and(|process| {
            process.command == binding.command_key()
                && process.restart == binding.context().restart()
        })
    {
        return Err(invalid(
            "launch binding command differs from retained process",
        ));
    }
    let pinned = linux_fd::open_beneath(configuration.as_fd(), Path::new("."), true)
        .map_err(|_| invalid("configuration is not an opened directory"))?;
    if linux_fd::directory_path(&pinned)? != binding.configuration() {
        return Err(invalid(
            "configuration descriptor differs from bound path",
        ));
    }
    let prepared = prepare_os_runtime(
        generation,
        binding.service(),
        binding.process(),
        binding.cwd(),
        configuration,
        cancellation,
    )?;
    let bytes = prepared
        .spec
        .canonical_bytes()
        .map_err(|_| invalid("prepared specification is invalid"))?;
    if ContentDigest::sha256(&bytes) != binding.spec() {
        return Err(invalid(
            "prepared runtime differs from bound specification",
        ));
    }
    check(cancellation)?;
    Ok(prepared)
}
fn render(service: &str, argument: &Argument) -> Result<String> {
    match argument {
        Argument::StateDirectory => Err(invalid("session state is not supported by Os")),
        Argument::SecretFile(_) => Err(invalid("secrets are not supported by Os")),
        Argument::Literal(value) => Ok(value.clone()),
        Argument::File(path) => {
            // GenerationManifest already validates that File refers to a declared
            // configuration file in this service, not another namespace.
            let value = format!("/syrox/config/{service}/{path}");
            if value.len() > crate::execution::resources::MAX_SERVICE_ARGUMENT_BYTES {
                return Err(invalid(
                    "rendered configuration argument exceeds limit",
                ));
            }
            Ok(value)
        }
    }
}
struct Expected<'a> {
    files: BTreeMap<PathBuf, &'a Config>,
    directories: BTreeSet<PathBuf>,
}
fn expected<'a>(configs: impl Iterator<Item = &'a Config>) -> Expected<'a> {
    let files: BTreeMap<_, _> = configs
        .map(|config| (PathBuf::from(&config.path), config))
        .collect();
    let mut directories = BTreeSet::new();
    for path in files.keys() {
        let mut parent = path.parent();
        while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
            directories.insert(path.to_path_buf());
            parent = path.parent();
        }
    }
    Expected {
        files,
        directories,
    }
}
#[derive(Default)]
struct Observed {
    entries: usize,
    bytes: u64,
    files: BTreeSet<PathBuf>,
    directories: BTreeSet<PathBuf>,
}
fn verify_configuration(
    generation: &RetainedGeneration,
    service: &str,
    configuration: &File,
    cancellation: &Cancellation,
) -> Result<()> {
    verify_configuration_inner(
        generation,
        service,
        configuration,
        cancellation,
        None,
    )
}
fn verify_configuration_inner(
    generation: &RetainedGeneration,
    service: &str,
    configuration: &File,
    cancellation: &Cancellation,
    deadline: Option<std::time::Instant>,
) -> Result<()> {
    verify_check(cancellation, deadline)?;
    let root = linux_fd::open_beneath(configuration.as_fd(), Path::new("."), true)
        .map_err(|_| invalid("configuration is not an opened directory"))?;
    let expected = expected(
        generation
            .manifest()
            .configs
            .values()
            .filter(|config| config.service == service),
    );
    let mut observed = Observed::default();
    verify_directory(
        &root,
        Path::new(""),
        &expected,
        &mut observed,
        0,
        cancellation,
        deadline,
    )?;
    if observed.files.len() != expected.files.len() || observed.directories != expected.directories
    {
        return Err(invalid(
            "configuration tree differs from retained generation",
        ));
    }
    Ok(())
}
pub(in crate::deployment::os) fn verify_configuration_subset_until(
    configs: &[&Config],
    configuration: &File,
    cancellation: &Cancellation,
    deadline: std::time::Instant,
) -> Result<()> {
    verify_check(cancellation, Some(deadline))?;
    let root = linux_fd::open_beneath(configuration.as_fd(), Path::new("."), true)
        .map_err(|_| invalid("configuration is not an opened directory"))?;
    let expected = expected(configs.iter().copied());
    let mut observed = Observed::default();
    verify_directory(
        &root,
        Path::new(""),
        &expected,
        &mut observed,
        0,
        cancellation,
        Some(deadline),
    )?;
    if observed.files.len() != expected.files.len() || observed.directories != expected.directories
    {
        return Err(invalid(
            "configuration tree differs from retained generation",
        ));
    }
    Ok(())
}
fn verify_directory(
    directory: &OpenedPath,
    prefix: &Path,
    expected: &Expected<'_>,
    observed: &mut Observed,
    depth: usize,
    cancellation: &Cancellation,
    deadline: Option<std::time::Instant>,
) -> Result<()> {
    verify_check(cancellation, deadline)?;
    let metadata = directory.metadata();
    if depth > MAX_CONFIGURATION_DEPTH
        || !metadata.is_trusted_directory()
        || metadata.mode() & 0o7777 != 0o500
    {
        return Err(invalid(
            "configuration directory is not private and immutable",
        ));
    }
    let names = linux_fd::read_directory(directory, |_| {
        verify_check(cancellation, deadline)?;
        observed.entries += 1;
        if observed.entries > MAX_CONFIGURATION_ENTRIES {
            return Err(invalid("configuration entry bound exceeded"));
        }
        Ok(())
    })
    .map_err(|error| match error {
        linux_fd::ReadDirectoryError::Admission(error) => error,
        linux_fd::ReadDirectoryError::Io(_) => invalid("cannot enumerate configuration"),
    })?;
    for name in names {
        verify_check(cancellation, deadline)?;
        let path = prefix.join(&name);
        let child = linux_fd::open_beneath(directory.fd(), Path::new(&name), false)
            .map_err(|_| invalid("configuration entry cannot be opened safely"))?;
        match child.metadata().file_type() {
            FileType::Directory if expected.directories.contains(&path) => {
                observed.directories.insert(path.clone());
                verify_directory(
                    &child,
                    &path,
                    expected,
                    observed,
                    depth + 1,
                    cancellation,
                    deadline,
                )?;
            }
            FileType::Regular => {
                let config = expected
                    .files
                    .get(&path)
                    .ok_or_else(|| invalid("undeclared configuration file"))?;
                observed.bytes = observed
                    .bytes
                    .checked_add(child.metadata().size())
                    .filter(|size| *size <= MAX_CONFIGURATION_BYTES)
                    .ok_or_else(|| invalid("configuration byte bound exceeded"))?;
                verify_file(child, config, cancellation, deadline)?;
                observed.files.insert(path);
            }
            _ => {
                return Err(invalid(
                    "undeclared or unsupported configuration entry",
                ));
            }
        }
    }
    Ok(())
}
fn verify_file(
    file: OpenedPath,
    expected: &Config,
    cancellation: &Cancellation,
    deadline: Option<std::time::Instant>,
) -> Result<()> {
    let metadata = file.metadata();
    if !metadata.is_trusted_regular()
        || metadata.mode() & 0o7777 != expected.mode
        || metadata.size() != expected.text.len() as u64
    {
        return Err(invalid("configuration file metadata differs"));
    }
    let mut reader = file.into_file();
    let mut position = 0;
    let mut buffer = [0_u8; 8192];
    loop {
        verify_check(cancellation, deadline)?;
        let size = reader.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        let end = position + size;
        if expected.text.as_bytes().get(position..end) != Some(&buffer[..size]) {
            return Err(invalid("configuration file contents differ"));
        }
        position = end;
    }
    if position != expected.text.len() {
        return Err(invalid("configuration file was truncated"));
    }
    Ok(())
}
fn check(cancellation: &Cancellation) -> Result<()> {
    cancellation
        .check()
        .map_err(|_| OsRuntimeError::Cancelled)
}
const fn invalid(message: &'static str) -> OsRuntimeError {
    OsRuntimeError::Invalid(message)
}

fn verify_check(cancellation: &Cancellation, deadline: Option<std::time::Instant>) -> Result<()> {
    check(cancellation)?;
    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
        return Err(OsRuntimeError::Deadline);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::os::{
        LauncherIdentity, PreparedGeneration, activation::ExecutionEpoch,
        installation::GenerationInstallation, launch_binding::LaunchBindingInput,
    };
    use crate::{store::GcRequest, store::Store};
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::time::{Duration, Instant};

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }
    fn mode(path: &Path, bits: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(bits)).unwrap();
    }
    struct Fixture {
        project: tempfile::TempDir,
        _installation: tempfile::TempDir,
        config: tempfile::TempDir,
        cwd: tempfile::TempDir,
        store: Store,
        generation: Option<RetainedGeneration>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            mode(self.config.path(), 0o700);
            mode(&self.config.path().join("nested"), 0o700);
        }
    }
    impl Fixture {
        fn new() -> Self {
            let (project, consumer) =
                crate::deployment::manifest::tests::prepared_service_payload_fixture_kind(
                    &crate::runtime::tests::elf(2, None, &[], None, None),
                    r#"std::CommandArgument::Literal("--config"), std::CommandArgument::File("nested/config")"#,
                    "Os",
                );
            let worker = project.path().join("launcher");
            fs::write(&worker, b"retained candidate").unwrap();
            let launcher =
                LauncherIdentity::new(ContentDigest::sha256(b"retained candidate"), 1).unwrap();
            let prepared = PreparedGeneration::freeze(consumer, launcher).unwrap();
            let store = Store::open(&project.path().join("store")).unwrap();
            let installation = tempfile::tempdir().unwrap();
            mode(installation.path(), 0o700);
            let cancel = Cancellation::default();
            let owner =
                GenerationInstallation::initialize(installation.path(), &cancel, deadline())
                    .unwrap();
            let retained = owner
                .prepare(&prepared, &store, &worker, &cancel, deadline())
                .unwrap();
            let pin = retained.digest();
            drop((retained, prepared, owner));
            fs::remove_file(project.path().join("main.srx")).unwrap();
            fs::remove_file(worker).unwrap();
            let owner =
                GenerationInstallation::open_existing(installation.path(), &cancel, deadline())
                    .unwrap();
            let generation = owner
                .open(&store, pin, &cancel, deadline())
                .unwrap();
            let config = tempfile::tempdir().unwrap();
            fs::create_dir(config.path().join("nested")).unwrap();
            fs::write(config.path().join("nested/config"), b"controlled").unwrap();
            mode(&config.path().join("nested/config"), 0o400);
            mode(&config.path().join("nested"), 0o500);
            mode(config.path(), 0o500);
            Self {
                project,
                _installation: installation,
                config,
                cwd: tempfile::tempdir().unwrap(),
                store,
                generation: Some(generation),
            }
        }
        fn generation(&self) -> &RetainedGeneration {
            self.generation.as_ref().unwrap()
        }
        fn directory(&self) -> File {
            File::open(self.config.path()).unwrap()
        }
        fn prepare(&self) -> Result<PreparedRuntimeLaunch> {
            prepare_os_runtime(
                self.generation(),
                "probe",
                "worker",
                self.cwd.path(),
                self.directory(),
                &Cancellation::default(),
            )
        }
        fn input(&self, prepared: &PreparedRuntimeLaunch) -> LaunchBindingInput {
            let context = crate::deployment::os::launch_binding::OsLaunchContext::new(
                crate::systemd::SystemdScope::User {
                    bus_socket: "/run/user/1000/bus".into(),
                },
                self.project.path().join("store"),
                "/home/user/.config/systemd/user/syrox-os-probe.service".into(),
                1000,
                1000,
                Duration::from_secs(30),
                Duration::from_secs(10),
            )
            .unwrap();
            LaunchBindingInput {
                installation: self.generation().installation_id().into(),
                generation: self.generation().digest(),
                service: "probe".into(),
                process: "worker".into(),
                command: "serve".into(),
                unit: crate::systemd::SystemdUnitName::new("syrox-os-probe.service").unwrap(),
                launcher: self.generation().manifest().launcher.clone(),
                spec: ContentDigest::sha256(&prepared.spec.canonical_bytes().unwrap()),
                epoch: ExecutionEpoch {
                    boot: crate::platform::linux::boot::BootId::parse(
                        "11111111-1111-1111-1111-111111111111",
                    )
                    .unwrap(),
                    manager: "test-manager".into(),
                    scope: context.scope_key(),
                },
                context,
                configuration: self.config.path().into(),
                cwd: self.cwd.path().into(),
            }
        }
    }

    #[test]
    fn reopened_generation_recomposes_arguments_environment_and_bound_spec_offline() {
        let fixture = Fixture::new();
        let prepared = fixture.prepare().unwrap();
        assert_eq!(
            prepared.spec.arguments,
            [
                "--config",
                "/syrox/config/probe/nested/config"
            ]
        );
        assert_eq!(
            prepared.spec.environment["APP_CONFIG"],
            "/syrox/config/probe/nested/config"
        );
        assert!(prepared.spec.program.ends_with("/bin/run"));
        assert_eq!(
            prepared.spec.mounts.len(),
            prepared.descriptors.len()
        );
        let binding = OsLaunchBinding::new(fixture.input(&prepared)).unwrap();
        let recomposed = prepare_bound_os_runtime(
            fixture.generation(),
            &binding,
            fixture.directory(),
            &Cancellation::default(),
        )
        .unwrap();
        assert_eq!(
            recomposed.spec.canonical_bytes().unwrap(),
            prepared.spec.canonical_bytes().unwrap()
        );
        assert!(!fixture.project.path().join("main.srx").exists());
        assert!(!fixture.project.path().join("launcher").exists());
    }

    #[test]
    fn missing_process_and_changed_configuration_are_refused_before_cwd_open() {
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        assert!(matches!(
            prepare_os_runtime(
                fixture.generation(),
                "probe",
                "absent",
                Path::new("/missing-cwd"),
                fixture.directory(),
                &cancel
            ),
            Err(OsRuntimeError::Invalid(
                "process is absent from retained generation"
            ))
        ));
        let file = fixture.config.path().join("nested/config");
        mode(&file, 0o600);
        fs::write(&file, b"corruption").unwrap();
        mode(&file, 0o400);
        assert!(matches!(
            prepare_os_runtime(
                fixture.generation(),
                "probe",
                "worker",
                Path::new("/missing-cwd"),
                fixture.directory(),
                &cancel
            ),
            Err(OsRuntimeError::Invalid(
                "configuration file contents differ"
            ))
        ));
    }

    #[test]
    fn extra_missing_symlink_and_mutable_configuration_entries_are_rejected() {
        let fixture = Fixture::new();
        mode(fixture.config.path(), 0o700);
        let extra = fixture.config.path().join("extra");
        fs::write(&extra, b"undeclared").unwrap();
        mode(&extra, 0o400);
        mode(fixture.config.path(), 0o500);
        assert!(fixture.prepare().is_err());
        mode(fixture.config.path(), 0o700);
        fs::remove_file(&extra).unwrap();
        symlink("nested/config", &extra).unwrap();
        mode(fixture.config.path(), 0o500);
        assert!(fixture.prepare().is_err());
        mode(fixture.config.path(), 0o700);
        fs::remove_file(extra).unwrap();
        mode(fixture.config.path(), 0o500);
        let file = fixture.config.path().join("nested/config");
        mode(&file, 0o600);
        assert!(fixture.prepare().is_err());
        mode(&file, 0o400);
        mode(&fixture.config.path().join("nested"), 0o700);
        fs::remove_file(file).unwrap();
        mode(&fixture.config.path().join("nested"), 0o500);
        assert!(fixture.prepare().is_err());
    }

    #[test]
    fn bound_preparation_rejects_command_path_spec_and_generation_discrepancies() {
        let fixture = Fixture::new();
        let prepared = fixture.prepare().unwrap();
        let mut inputs = Vec::new();
        let mut changed = fixture.input(&prepared);
        changed.command = "other".into();
        inputs.push(changed);
        let mut changed = fixture.input(&prepared);
        changed.configuration = PathBuf::from("/another/private/config");
        inputs.push(changed);
        let mut changed = fixture.input(&prepared);
        changed.spec = ContentDigest::sha256(b"other spec");
        inputs.push(changed);
        let mut changed = fixture.input(&prepared);
        changed.generation = ContentDigest::sha256(b"other generation");
        inputs.push(changed);
        let mut changed = fixture.input(&prepared);
        changed.context = changed
            .context
            .with_restart(
                crate::execution::restart::ProcessRestart::OnFailure(
                    crate::execution::restart::RestartLimits::new(1, 10, 3).unwrap(),
                ),
            )
            .unwrap();
        inputs.push(changed);
        for input in inputs {
            let binding = OsLaunchBinding::new(input).unwrap();
            assert!(
                prepare_bound_os_runtime(
                    fixture.generation(),
                    &binding,
                    fixture.directory(),
                    &Cancellation::default()
                )
                .is_err()
            );
        }
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            prepare_os_runtime(
                fixture.generation(),
                "probe",
                "worker",
                fixture.cwd.path(),
                fixture.directory(),
                &cancel
            ),
            Err(OsRuntimeError::Cancelled)
        ));
    }

    #[test]
    fn prepared_runtime_retains_outputs_after_generation_handle_and_output_roots_drop() {
        let mut fixture = Fixture::new();
        let prepared = fixture.prepare().unwrap();
        let output = fixture
            .generation()
            .outputs()
            .values()
            .next()
            .unwrap();
        let artifact = output.artifact();
        let physical = output.directory().unwrap();
        let mut roots = fixture
            .store
            .operation()
            .unwrap()
            .managed_build_roots()
            .unwrap();
        roots.extend(
            fixture
                .generation()
                .retained_outputs()
                .values()
                .map(|output| output.root.clone()),
        );
        drop(fixture.generation.take());
        let junk = ContentDigest::sha256(b"unrelated");
        fixture
            .store
            .operation()
            .unwrap()
            .ingest(&b"unrelated"[..], junk, 9)
            .unwrap();
        let report = fixture
            .store
            .maintenance()
            .unwrap()
            .garbage_collect(&GcRequest {
                collect: true,
                remove_roots: roots,
                ..GcRequest::default()
            })
            .unwrap();
        assert!(report.removed_objects.contains(&junk));
        assert!(!report.removed_objects.contains(&artifact));
        assert_eq!(
            fs::read(physical.join("bin/run")).unwrap(),
            crate::runtime::tests::elf(2, None, &[], None, None)
        );
        drop(prepared);
        let report = fixture
            .store
            .maintenance()
            .unwrap()
            .garbage_collect(&GcRequest {
                collect: true,
                ..GcRequest::default()
            })
            .unwrap();
        assert!(report.removed_objects.contains(&artifact));
    }
}

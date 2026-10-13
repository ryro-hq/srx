use crate::deployment::os::{
    activation::ExecutionEpoch,
    installation::{
        GenerationConfiguration, GenerationInstallation, GenerationLauncher, InstallationError,
        RetainedGeneration,
    },
    launch_binding::{LaunchBindingError, LaunchBindingInput, OsLaunchBinding, OsLaunchContext},
    paths::{OsExecutionPaths, OsPathsError},
    runtime::{OsRuntimeError, prepare_os_runtime},
};
use crate::platform::linux::fd::{self as linux_fd, OpenedPath};
use crate::systemd::persistent::{OsUnitContract, OsUnitInput};
use crate::{
    cancellation::Cancellation, store::ContentDigest, store::Store, systemd::SystemdError,
    systemd::SystemdScope, systemd::SystemdUnitName,
};
use std::collections::BTreeMap;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub(crate) enum PreparationError {
    #[error("invalid Os resource preparation: {0}")]
    Invalid(&'static str),
    #[error("Os resource preparation cancelled")]
    Cancelled,
    #[error("Os resource preparation deadline expired")]
    Deadline,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error(transparent)]
    Paths(#[from] OsPathsError),
    #[error(transparent)]
    Installation(#[from] InstallationError),
    #[error(transparent)]
    Runtime(#[from] OsRuntimeError),
    #[error(transparent)]
    Binding(#[from] LaunchBindingError),
    #[error(transparent)]
    Systemd(#[from] SystemdError),
}
type Result<T> = std::result::Result<T, PreparationError>;

pub(crate) struct ResourcePreparation<'a> {
    pub installation: &'a GenerationInstallation,
    pub generation: &'a RetainedGeneration,
    pub store: &'a Store,
    pub paths: &'a OsExecutionPaths,
    pub units: &'a Path,
    pub epoch: &'a ExecutionEpoch,
    pub scope: SystemdScope,
    pub uid: u32,
    pub gid: u32,
    pub start_timeout: Duration,
    pub stop_timeout: Duration,
}
impl ResourcePreparation<'_> {
    pub(super) fn revalidate(&self, cancellation: &Cancellation, deadline: Instant) -> Result<()> {
        check(cancellation, deadline)?;
        self.paths.revalidate(cancellation, deadline)?;
        self.installation
            .validate_path(self.paths.installation(), cancellation, deadline)?;
        self.store
            .validate_directory(self.paths.store())?;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct PreparedResource {
    pub binding: OsLaunchBinding,
    pub contract: OsUnitContract,
}

pub(crate) fn prepare_resources(
    input: &ResourcePreparation<'_>,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<BTreeMap<String, PreparedResource>> {
    resources(
        input,
        SnapshotMode::Prepare,
        cancellation,
        deadline,
    )
}

pub(crate) fn reopen_resources(
    input: &ResourcePreparation<'_>,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<BTreeMap<String, PreparedResource>> {
    resources(
        input,
        SnapshotMode::Existing,
        cancellation,
        deadline,
    )
}

#[derive(Clone, Copy)]
enum SnapshotMode {
    Prepare,
    Existing,
}

fn resources(
    input: &ResourcePreparation<'_>,
    mode: SnapshotMode,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<BTreeMap<String, PreparedResource>> {
    input.revalidate(cancellation, deadline)?;
    let units = open_units(input.units, input.paths)?;
    input
        .epoch
        .validate()
        .map_err(|_| PreparationError::Invalid("invalid execution epoch"))?;
    if input.generation.installation_id() != input.installation.id() {
        return Err(PreparationError::Invalid(
            "generation belongs to another installation",
        ));
    }
    // Reopen the admitted candidate before creating any executable/configuration snapshots.
    let generation = input.installation.open(
        input.store,
        input.generation.digest(),
        cancellation,
        deadline,
    )?;
    let contexts = contexts(input, &generation)?;
    let (launcher, configuration) = match mode {
        SnapshotMode::Prepare => (
            input.installation.prepare_launcher(
                &generation,
                input.store,
                cancellation,
                deadline,
            )?,
            input
                .installation
                .prepare_configuration(&generation, cancellation, deadline)?,
        ),
        SnapshotMode::Existing => (
            input
                .installation
                .open_launcher(&generation, cancellation, deadline)?,
            input
                .installation
                .open_configuration(&generation, cancellation, deadline)?,
        ),
    };
    let mut resources = BTreeMap::new();
    for (key, (unit, context)) in contexts {
        check(cancellation, deadline)?;
        let resource = compose_resource(
            input,
            &generation,
            &launcher,
            &configuration,
            (&key, unit, context),
            cancellation,
        )?;
        resources.insert(key, resource);
    }
    launcher.verify_path(cancellation, deadline)?;
    input.paths.revalidate(cancellation, deadline)?;
    let current = open_units(input.units, input.paths)?;
    if current.metadata().identity() != units.metadata().identity()
        || linux_fd::directory_path(&units)? != input.units
    {
        return Err(PreparationError::Invalid(
            "unit directory was replaced or renamed",
        ));
    }
    check(cancellation, deadline)?;
    Ok(resources)
}

fn contexts(
    input: &ResourcePreparation<'_>,
    generation: &RetainedGeneration,
) -> Result<BTreeMap<String, (SystemdUnitName, OsLaunchContext)>> {
    // Check the scope even for a data-only generation with no process to render.
    let context = context_for_unit(
        input,
        &unit_name(input.installation.id(), "scope")?,
    )?;
    if context.scope_key() != input.epoch.scope {
        return Err(PreparationError::Invalid(
            "execution epoch differs from operational scope",
        ));
    }
    generation
        .manifest()
        .processes
        .iter()
        .map(|(key, process)| {
            let unit = unit_name(input.installation.id(), key)?;
            let context = context_for_unit(input, &unit)?.with_restart(process.restart)?;
            Ok((key.clone(), (unit, context)))
        })
        .collect()
}
pub(super) fn context_for_unit(
    input: &ResourcePreparation<'_>,
    unit: &SystemdUnitName,
) -> Result<OsLaunchContext> {
    Ok(OsLaunchContext::new(
        input.scope.clone(),
        input.paths.store().into(),
        input.units.join(unit.as_str()),
        input.uid,
        input.gid,
        input.start_timeout,
        input.stop_timeout,
    )?)
}

fn compose_resource(
    input: &ResourcePreparation<'_>,
    generation: &RetainedGeneration,
    launcher: &GenerationLauncher,
    configuration: &GenerationConfiguration,
    resource: (&str, SystemdUnitName, OsLaunchContext),
    cancellation: &Cancellation,
) -> Result<PreparedResource> {
    let (key, unit, context) = resource;
    let (service, process) = key
        .split_once('/')
        .ok_or(PreparationError::Invalid("invalid process key"))?;
    let command = &generation.manifest().commands[&generation.manifest().processes[key].command];
    let (descriptor, configuration_path) = configuration.service(service)?;
    let runtime = prepare_os_runtime(
        generation,
        service,
        process,
        input.paths.cwd(),
        descriptor,
        cancellation,
    )?;
    let spec = runtime
        .spec
        .canonical_bytes()
        .map_err(|_| PreparationError::Invalid("invalid runtime specification"))?;
    let fragment = context.fragment().to_owned();
    let binding = OsLaunchBinding::new(LaunchBindingInput {
        installation: input.installation.id().into(),
        generation: generation.digest(),
        service: service.into(),
        process: process.into(),
        command: command.name.clone(),
        unit: unit.clone(),
        launcher: generation.manifest().launcher.clone(),
        spec: ContentDigest::sha256(&spec),
        epoch: input.epoch.clone(),
        context,
        configuration: configuration_path,
        cwd: input.paths.cwd().into(),
    })?;
    let contract = OsUnitContract::new(OsUnitInput {
        restart: binding.context().restart(),
        unit,
        scope: input.scope.clone(),
        worker: launcher.path().into(),
        installation: input.paths.installation().into(),
        store: input.paths.store().into(),
        binding: binding.digest()?,
        fragment,
        uid: input.uid,
        gid: input.gid,
        start_timeout: input.start_timeout,
        stop_timeout: input.stop_timeout,
    })?;
    Ok(PreparedResource {
        binding,
        contract,
    })
}

fn unit_name(installation: &str, process: &str) -> Result<SystemdUnitName> {
    Ok(SystemdUnitName::new(format!(
        "syrox-os-{installation}-{}.service",
        ContentDigest::sha256(process.as_bytes())
    ))?)
}
fn open_units(path: &Path, paths: &OsExecutionPaths) -> Result<OpenedPath> {
    let text = path.to_str().ok_or(PreparationError::Invalid(
        "non-UTF8 unit directory",
    ))?;
    if !path.is_absolute()
        || text.len() > 4096
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
    {
        return Err(PreparationError::Invalid(
            "unit directory must be absolute and canonical",
        ));
    }
    for selected in [
        paths.installation(),
        paths.store(),
        paths.cwd(),
    ] {
        if path.starts_with(selected) || selected.starts_with(path) {
            return Err(PreparationError::Invalid(
                "unit directory overlaps execution directories",
            ));
        }
    }
    let directory = linux_fd::open_top_directory(path).map_err(|_| {
        PreparationError::Invalid("unit directory cannot be opened without symlinks")
    })?;
    if !directory.metadata().is_trusted_directory() || linux_fd::directory_path(&directory)? != path
    {
        return Err(PreparationError::Invalid(
            "unit directory authority differs",
        ));
    }
    for selected in [
        paths.installation(),
        paths.store(),
        paths.cwd(),
    ] {
        let opened = linux_fd::open_top_directory(selected)
            .map_err(|_| PreparationError::Invalid("execution directory changed"))?;
        if opened.metadata().identity() == directory.metadata().identity() {
            return Err(PreparationError::Invalid(
                "unit directory aliases execution directory",
            ));
        }
    }
    Ok(directory)
}
pub(super) fn check(cancel: &Cancellation, deadline: Instant) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(PreparationError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(PreparationError::Deadline);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::os::{LauncherIdentity, PreparedGeneration};
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(15)
    }
    fn directory() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    struct Fixture {
        project: tempfile::TempDir,
        installation_directory: tempfile::TempDir,
        cwd: tempfile::TempDir,
        units: tempfile::TempDir,
        installation: GenerationInstallation,
        generation: RetainedGeneration,
        store: Store,
    }
    impl Fixture {
        fn new() -> Self {
            let (project, consumer) =
                crate::deployment::manifest::tests::prepared_service_payload_fixture_kind(
                    &crate::runtime::tests::elf(2, None, &[], None, None),
                    "",
                    "Os",
                );
            let worker = project.path().join("candidate-worker");
            fs::write(&worker, b"authenticated worker fixture").unwrap();
            let generation = PreparedGeneration::freeze(
                consumer,
                LauncherIdentity::new(
                    ContentDigest::sha256(b"authenticated worker fixture"),
                    1,
                )
                .unwrap(),
            )
            .unwrap();
            let store = Store::open(&project.path().join("store")).unwrap();
            let installation_directory = directory();
            let installation = GenerationInstallation::initialize(
                installation_directory.path(),
                &Cancellation::default(),
                deadline(),
            )
            .unwrap();
            let generation = installation
                .prepare(
                    &generation,
                    &store,
                    &worker,
                    &Cancellation::default(),
                    deadline(),
                )
                .unwrap();
            fs::remove_file(worker).unwrap();
            fs::remove_file(project.path().join("main.srx")).unwrap();
            Self {
                project,
                installation_directory,
                cwd: directory(),
                units: directory(),
                installation,
                generation,
                store,
            }
        }
        fn paths(&self, cwd: &Path) -> OsExecutionPaths {
            OsExecutionPaths::open(
                self.installation_directory.path(),
                &self.project.path().join("store"),
                cwd,
                &Cancellation::default(),
                deadline(),
            )
            .unwrap()
        }
        fn input<'a>(
            &'a self,
            paths: &'a OsExecutionPaths,
            epoch: &'a ExecutionEpoch,
        ) -> ResourcePreparation<'a> {
            ResourcePreparation {
                installation: &self.installation,
                generation: &self.generation,
                store: &self.store,
                paths,
                units: self.units.path(),
                epoch,
                scope: SystemdScope::System,
                uid: 1000,
                gid: 1000,
                start_timeout: Duration::from_secs(30),
                stop_timeout: Duration::from_secs(10),
            }
        }
        fn epoch(&self, paths: &OsExecutionPaths) -> ExecutionEpoch {
            let context = OsLaunchContext::new(
                SystemdScope::System,
                paths.store().into(),
                self.units.path().join("example.service"),
                1000,
                1000,
                Duration::from_secs(30),
                Duration::from_secs(10),
            )
            .unwrap();
            ExecutionEpoch {
                boot: crate::platform::linux::boot::BootId::parse(
                    "11111111-1111-4111-8111-111111111111",
                )
                .unwrap(),
                manager: "controlled-manager".into(),
                scope: context.scope_key(),
            }
        }
    }

    #[test]
    fn offline_composition_is_stable_but_cwd_changes_binding() {
        let fixture = Fixture::new();
        let paths = fixture.paths(fixture.cwd.path());
        let epoch = fixture.epoch(&paths);
        let first = prepare_resources(
            &fixture.input(&paths, &epoch),
            &Cancellation::default(),
            deadline(),
        )
        .unwrap();
        let second = prepare_resources(
            &fixture.input(&paths, &epoch),
            &Cancellation::default(),
            deadline(),
        )
        .unwrap();
        assert_eq!(first.len(), 1);
        for (key, value) in &first {
            assert_eq!(value.binding, second[key].binding);
            assert_eq!(
                value.contract.render(),
                second[key].contract.render()
            );
            assert_eq!(
                value.binding.generation(),
                fixture.generation.digest()
            );
            assert_eq!(value.binding.process_key(), *key);
            assert!(!value.binding.context().fragment().exists());
            assert!(
                fixture
                    .installation
                    .read_launch_binding(
                        value.binding.digest().unwrap(),
                        &Cancellation::default(),
                        deadline()
                    )
                    .is_err()
            );
        }
        let cwd = directory();
        let changed_paths = fixture.paths(cwd.path());
        let changed = prepare_resources(
            &fixture.input(&changed_paths, &epoch),
            &Cancellation::default(),
            deadline(),
        )
        .unwrap();
        for (key, value) in &first {
            assert_ne!(
                value.binding.digest().unwrap(),
                changed[key].binding.digest().unwrap()
            );
            assert_eq!(
                value.contract.unit(),
                changed[key].contract.unit()
            );
        }
        assert_eq!(
            fs::read_dir(fixture.units.path())
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn process_units_are_stable_and_installation_scoped() {
        let id = "a".repeat(32);
        let first = unit_name(&id, "probe/main").unwrap();
        assert_eq!(first, unit_name(&id, "probe/main").unwrap());
        assert_ne!(first, unit_name(&id, "probe/other").unwrap());
        assert_ne!(
            first,
            unit_name(&"b".repeat(32), "probe/main").unwrap()
        );
        assert_eq!(
            first.as_str(),
            format!(
                "syrox-os-{id}-{}.service",
                ContentDigest::sha256(b"probe/main")
            )
        );
    }

    #[test]
    fn conflicting_and_symlink_unit_directories_are_rejected_before_snapshots() {
        let fixture = Fixture::new();
        let paths = fixture.paths(fixture.cwd.path());
        let epoch = fixture.epoch(&paths);
        for selected in [
            paths.installation(),
            paths.store(),
            paths.cwd(),
        ] {
            let child = selected.join("units");
            fs::create_dir(&child).unwrap();
            for conflict in [
                selected,
                child.as_path(),
                selected.parent().unwrap(),
            ] {
                let mut input = fixture.input(&paths, &epoch);
                input.units = conflict;
                assert!(prepare_resources(&input, &Cancellation::default(), deadline()).is_err());
            }
        }
        let links = directory();
        let link = links.path().join("units");
        symlink(fixture.units.path(), &link).unwrap();
        let mut input = fixture.input(&paths, &epoch);
        input.units = &link;
        assert!(prepare_resources(&input, &Cancellation::default(), deadline()).is_err());
        assert!(
            fixture
                .installation
                .open_launcher(
                    &fixture.generation,
                    &Cancellation::default(),
                    deadline()
                )
                .is_err()
        );
        assert!(
            fixture
                .installation
                .open_configuration(
                    &fixture.generation,
                    &Cancellation::default(),
                    deadline()
                )
                .is_err()
        );
    }

    #[test]
    fn cancelled_and_wrong_epoch_preparation_has_no_snapshots() {
        let fixture = Fixture::new();
        let paths = fixture.paths(fixture.cwd.path());
        let mut epoch = fixture.epoch(&paths);
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            prepare_resources(
                &fixture.input(&paths, &epoch),
                &cancel,
                deadline()
            ),
            Err(PreparationError::Cancelled)
        ));
        epoch.scope = "another-scope".into();
        assert!(
            prepare_resources(
                &fixture.input(&paths, &epoch),
                &Cancellation::default(),
                deadline()
            )
            .is_err()
        );
        assert!(
            fixture
                .installation
                .open_launcher(
                    &fixture.generation,
                    &Cancellation::default(),
                    deadline()
                )
                .is_err()
        );
    }

    #[test]
    fn reopening_resources_never_creates_missing_snapshots_and_matches_preparation() {
        let fixture = Fixture::new();
        let paths = fixture.paths(fixture.cwd.path());
        let epoch = fixture.epoch(&paths);
        let input = fixture.input(&paths, &epoch);
        let cancel = Cancellation::default();
        assert!(reopen_resources(&input, &cancel, deadline()).is_err());
        assert!(
            fixture
                .installation
                .open_launcher(&fixture.generation, &cancel, deadline())
                .is_err()
        );
        assert!(
            fixture
                .installation
                .open_configuration(&fixture.generation, &cancel, deadline())
                .is_err()
        );
        let prepared = prepare_resources(&input, &cancel, deadline()).unwrap();
        let reopened = reopen_resources(&input, &cancel, deadline()).unwrap();
        assert_eq!(prepared.len(), reopened.len());
        for (key, old) in &prepared {
            assert_eq!(old.binding, reopened[key].binding);
            assert_eq!(
                old.contract.render(),
                reopened[key].contract.render()
            );
        }
        let config = prepared
            .values()
            .next()
            .unwrap()
            .binding
            .configuration()
            .join("nested/config");
        let parent = config.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(&config).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(reopen_resources(&input, &cancel, deadline()).is_err());
        assert!(!config.exists());
        assert_eq!(
            fs::read_dir(fixture.units.path())
                .unwrap()
                .count(),
            0
        );
    }
}

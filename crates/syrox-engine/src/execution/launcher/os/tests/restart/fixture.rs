use super::*;
use crate::deployment::os::installation::GenerationInstallation;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
pub(super) struct Inputs {
    parent: PathBuf,
    units: PathBuf,
    bus: PathBuf,
    worker: Vec<u8>,
    payload: Vec<u8>,
}
impl Inputs {
    pub(super) fn read() -> Result<Self> {
        let parent = parameter("SYROX_RESTART_PARENT")?;
        private(&parent)?;
        let units = parameter("SYROX_RESTART_UNITS")?;
        let bus = parameter("SYROX_SYSTEMD_USER_BUS")?;
        Ok(Self {
            parent,
            units,
            bus,
            worker: candidate("SYROX_RESTART_WORKER")?,
            payload: candidate("SYROX_RESTART_PAYLOAD")?,
        })
    }
}
fn parameter(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os(name).ok_or_else(|| invalid("missing explicit gate input"))?,
    );
    check(path.is_absolute(), "gate input must be absolute")?;
    Ok(path)
}
fn private(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    check(
        meta.is_dir()
            && meta.uid() == crate::platform::linux::fd::effective_uid()
            && meta.mode() & 0o7777 == 0o700,
        "gate directory must be owned0700",
    )
}
fn candidate(name: &str) -> Result<Vec<u8>> {
    let path = parameter(name)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    check(
        meta.is_file() && meta.len() <= 128 * 1024 * 1024,
        "invalid gate candidate",
    )?;
    let mut bytes = Vec::new();
    file.take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    check(
        bytes.len() as u64 == meta.len(),
        "candidate changed during read",
    )?;
    let pin: ContentDigest = std::env::var(format!("{name}_SHA256"))?.parse()?;
    check(
        ContentDigest::sha256(&bytes) == pin,
        "candidate pin differs",
    )?;
    crate::runtime::validate_static_worker_image(&bytes)?;
    Ok(bytes)
}
fn directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
pub(super) struct Fixture {
    pub(super) root: PathBuf,
    pub(super) cwd: PathBuf,
    pub(super) request: crate::deployment::os::OsApplyRequest,
    pub(super) journal: ActivationJournal,
    pub(super) cancel: Cancellation,
    pub(super) manager: SystemdManager,
    pub(super) reference: Option<crate::systemd::SystemdUnitReference>,
}
impl Fixture {
    pub(super) fn prepare(input: &Inputs, revoke: bool) -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix(if revoke {
                "restart-revoke-"
            } else {
                "restart-limit-"
            })
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(&input.parent)?
            .keep();
        eprintln!("restart gate evidence {}", root.display());
        let cwd = root.join("work");
        directory(&cwd)?;
        let installation = root.join("installation");
        directory(&installation)?;
        let worker = root.join("worker");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&worker)?;
        file.write_all(&input.worker)?;
        file.sync_all()?;
        let cancel = Cancellation::default();
        let (project, prepared) =
            crate::deployment::manifest::tests::prepared_service_payload_fixture_with_source(
                &input.payload,
                r#"std::CommandArgument::Literal("restart78"), std::CommandArgument::Literal("witness"), std::CommandArgument::Literal("release")"#,
                "Os",
                Some(&root.join("store")),
                |source| {
                    source.replace(
                "id = \"worker\"; command = \"serve\";",
                "id = \"worker\"; command = \"serve\"; restart = std::ProcessRestart::OnFailure(std::RestartLimits { delay_seconds = std::RestartDelay(1); window_seconds = std::RestartWindow(3600); burst = std::RestartBurst(2); });")
                },
            );
        let store = Store::open(&root.join("store"))?;
        let installed =
            crate::deployment::os::initialize_os_installation(&installation, &cancel, deadline())?;
        let summary = crate::deployment::os::prepare_os_generation(
            prepared,
            &crate::deployment::os::OsPreparation {
                installation: &installed,
                store: &store,
                launcher: &worker,
                launcher_digest: ContentDigest::sha256(&input.worker),
            },
            &cancel,
            deadline(),
        )?;
        // Only snapshots and retained CAS bytes remain available to both starts.
        project.close()?;
        fs::remove_file(&worker)?;
        let request = crate::deployment::os::OsApplyRequest {
            installation,
            store: root.join("store"),
            units: input.units.clone(),
            cwd: cwd.clone(),
            candidate: summary.pin,
            expected: None,
            scope: crate::systemd::SystemdScope::User {
                bus_socket: input.bus.clone(),
            },
            uid: crate::platform::linux::fd::effective_uid(),
            gid: crate::platform::linux::fd::effective_gid(),
            start_timeout: Duration::from_secs(20),
            stop_timeout: Duration::from_secs(5),
        };
        let journal = ActivationJournal::open_existing(&request.installation, &cancel, deadline())?;
        let manager = SystemdManager::connect(
            request.scope.clone(),
            Duration::from_secs(5),
            &cancel,
        )?;
        Ok(Self {
            root,
            cwd,
            request,
            journal,
            cancel,
            manager,
            reference: None,
        })
    }
    pub(super) fn apply(&mut self) -> Result<()> {
        let report =
            crate::deployment::os::apply_os_generation(&self.request, &self.cancel, deadline())?;
        fs::write(self.root.join("operation"), &report.operation)?;
        fs::write(
            self.root.join("apply-report.txt"),
            format!("{report:#?}"),
        )?;
        check(
            !report.needs_reconciliation
                && report.resources.iter().any(|r| {
                    r.resource == "probe/worker"
                        && matches!(
                            r.state,
                            crate::deployment::os::OsApplyResourceState::Started
                        )
                }),
            "apply did not observe started payload",
        )
    }
    pub(super) fn release(&self, number: u32) -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.cwd.join(format!("release.{number}")))?;
        file.write_all(b"X")?;
        file.sync_all()?;
        fs::File::open(&self.cwd)?.sync_all()?;
        Ok(())
    }
    pub(super) fn verify_retention(&self) -> Result<()> {
        let store = Store::open_existing(&self.request.store)?;
        store
            .maintenance()?
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                ..crate::store::GcRequest::default()
            })?;
        let installation = GenerationInstallation::open_existing(
            &self.request.installation,
            &self.cancel,
            deadline(),
        )?;
        let generation = installation.open(
            &store,
            self.request.candidate,
            &self.cancel,
            deadline(),
        )?;
        installation
            .open_launcher(&generation, &self.cancel, deadline())?
            .verify_path(&self.cancel, deadline())?;
        installation.open_configuration(&generation, &self.cancel, deadline())?;
        Ok(())
    }
}

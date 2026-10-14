use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{ManagedShellSession, ManagedShellStart};
use crate::execution::journal::SessionJournal;
use crate::platform::linux::fd::{self as linux_fd, OpenedPath};
use crate::{
    cancellation::Cancellation, deployment::manifest::PreparedConsumer,
    deployment::shell::SessionError, store::ContentDigest, store::ObjectLease,
    systemd::SystemdManager, systemd::SystemdScope,
};

const MAX_WORKER_BYTES: u64 = 128 * 1024 * 1024;

/// Explicit Linux user-manager installation. Paths must be absolute, UTF-8 and
/// canonical in spelling; `state_directory` must already be owned mode 0700.
#[derive(Clone, Debug)]
pub struct ManagedShellConfiguration {
    pub worker: PathBuf,
    pub worker_digest: ContentDigest,
    pub bus_socket: PathBuf,
    pub state_directory: PathBuf,
    pub cwd: PathBuf,
    pub secrets: crate::config::ShellSecretSources,
}
impl ManagedShellConfiguration {
    /// Read-only preflight, including a bounded manager connection. This does
    /// not create directories, units or journal authorization. Worker bytes are
    /// checked against `worker_digest` when the immutable launch snapshot is made.
    pub fn validate(&self, cancellation: &Cancellation) -> Result<(), SessionError> {
        check(cancellation)?;
        for path in [
            &self.worker,
            &self.bus_socket,
            &self.state_directory,
            &self.cwd,
        ] {
            canonical_path(path)?;
        }
        validate_state_separation(&self.cwd, &self.state_directory)?;
        let real_uid = linux_fd::real_uid();
        if real_uid == 0 || real_uid != linux_fd::effective_uid() {
            return Err(invalid(
                "managed Shell requires an ordinary nonzero user identity",
            ));
        }
        let state = open_private(&self.state_directory)?;
        let cwd = linux_fd::open_top_directory(&self.cwd).map_err(open_error)?;
        if linux_fd::directory_path(&state)? != self.state_directory
            || linux_fd::directory_path(&cwd)? != self.cwd
        {
            return Err(invalid(
                "configured directory path differs from its pinned identity",
            ));
        }
        if !crate::execution::resources::valid_managed_working_directory(&self.cwd) {
            return Err(invalid(
                "working directory overlaps managed runtime filesystems",
            ));
        }
        crate::execution::resources::validate_managed_working_descriptor(cwd.fd())?;
        let worker = linux_fd::open_top(&self.worker).map_err(open_error)?;
        if worker.metadata().file_type() != linux_fd::FileType::Regular
            || worker.metadata().size() > MAX_WORKER_BYTES
        {
            return Err(invalid(
                "worker must be a regular candidate within 128 MiB",
            ));
        }
        check(cancellation)?;
        SystemdManager::connect(
            SystemdScope::User {
                bus_socket: self.bus_socket.clone(),
            },
            Duration::from_secs(5),
            cancellation,
        )
        .map_err(|error| invalid(&error.to_string()))?;
        check(cancellation)
    }
}

/// A live session. Dropping it closes the owner's lifetime channel but preserves
/// journal/configuration evidence. Use close for observed, bounded settlement.
pub struct ManagedShell {
    inner: ManagedShellSession,
    journal: Arc<SessionJournal>,
    layout: StateLayout,
}
impl std::fmt::Debug for ManagedShell {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedShell")
            .field("session", &self.session_id())
            .field("state_directory", &self.state_directory())
            .finish_non_exhaustive()
    }
}
impl ManagedShell {
    pub fn start(
        prepared: PreparedConsumer,
        configuration: &ManagedShellConfiguration,
        cancellation: &Cancellation,
    ) -> Result<Self, SessionError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        check(cancellation)?;
        if prepared.consumer().kind() != crate::plan::PlanConsumerKind::Shell {
            return Err(SessionError::NotShell);
        }
        if prepared.outputs().is_empty() {
            return Err(invalid(
                "managed Shell has no realizable output; use ShellSession for configuration-only consumers",
            ));
        }
        let interests: Vec<_> = prepared
            .outputs()
            .values()
            .map(crate::result::MaterializedArtifact::object_lease)
            .collect();
        let retention =
            ObjectLease::combine(&interests).map_err(|error| invalid(&error.to_string()))?;
        configuration
            .secrets
            .for_consumer(prepared.consumer())
            .map_err(|_| invalid("missing secret authorization"))?;
        configuration.validate(cancellation)?;
        let layout = StateLayout::open(&configuration.state_directory)?;
        let journal_path = linux_fd::directory_path(&layout.journal)?;
        let operations = linux_fd::directory_path(&layout.operations)?;
        let journal = Arc::new(
            SessionJournal::open(&journal_path).map_err(|error| invalid(&error.to_string()))?,
        );
        check(cancellation)?;
        let inner = ManagedShellSession::start(
            prepared,
            &ManagedShellStart {
                worker: &configuration.worker,
                worker_digest: configuration.worker_digest,
                bus_socket: &configuration.bus_socket,
                private_directory: &operations,
                journal: &journal,
                retention: &retention,
                cwd: &configuration.cwd,
                secrets: &configuration.secrets,
            },
            cancellation,
            deadline,
        )?;
        Ok(Self {
            inner,
            journal,
            layout,
        })
    }

    pub fn session_id(&self) -> &str {
        self.inner.owner.session.as_str()
    }
    pub fn state_directory(&self) -> &Path {
        &self.layout.path
    }

    pub fn run_command(
        &self,
        name: &str,
        arguments: &[OsString],
        cancellation: &Cancellation,
    ) -> Result<ExitStatus, SessionError> {
        self.inner
            .run_command(name, arguments, cancellation)
    }

    /// Run an exposed command on a dedicated, caller-owned PTY slave while
    /// monitoring this session's owner and services. The caller owns the master,
    /// relay, resize and external terminal restoration. Completion includes
    /// namespace settlement; it is not inferred from PTY EOF. This does not
    /// construct a shared command PATH or enable an interactive CLI session.
    pub fn run_command_with_terminal(
        &self,
        name: &str,
        arguments: &[OsString],
        terminal: std::os::fd::BorrowedFd<'_>,
        cancellation: &Cancellation,
    ) -> Result<ExitStatus, SessionError> {
        self.inner
            .run_command_with_terminal(name, arguments, terminal, cancellation)
    }

    /// Run an exposed command with a prepared terminal and monitor custody.
    /// Keeps owner/service supervision through execution, output drain and
    /// terminal restoration. Completion waits for namespace settlement.
    /// This does not compose a shared PATH for other exposed commands.
    pub fn run_prepared_terminal(
        &self,
        name: &str,
        arguments: &[OsString],
        terminal: crate::deployment::shell::PreparedShellTerminal,
        cancellation: &Cancellation,
    ) -> Result<ExitStatus, SessionError> {
        self.inner
            .run_prepared_terminal(name, arguments, terminal, cancellation)
    }

    /// Revokes and stops with a fresh cleanup token and a 30-second deadline.
    /// Any uncertainty preserves evidence; this does not publish journal Closed.
    pub fn close(self) -> Result<(), SessionError> {
        self.inner.close(
            &self.journal,
            &Cancellation::default(),
            Instant::now() + Duration::from_secs(30),
        )
    }
}

struct StateLayout {
    path: PathBuf,
    _parent: OpenedPath,
    journal: OpenedPath,
    operations: OpenedPath,
}
impl StateLayout {
    fn open(path: &Path) -> Result<Self, SessionError> {
        let parent = open_private(path)?;
        let journal = private_child(&parent, "journal")?;
        let operations = private_child(&parent, "operations")?;
        linux_fd::sync_directory(parent.fd())?;
        let path = linux_fd::directory_path(&parent)?;
        Ok(Self {
            path,
            _parent: parent,
            journal,
            operations,
        })
    }
}
fn private_child(parent: &OpenedPath, name: &str) -> Result<OpenedPath, SessionError> {
    let child = linux_fd::ensure_directory_beneath(parent.fd(), Path::new(name))
        .map_err(|error| invalid(&format!("state directory refused: {error:?}")))?;
    private(&child)?;
    linux_fd::sync_directory(child.fd())?;
    Ok(child)
}
fn open_private(path: &Path) -> Result<OpenedPath, SessionError> {
    let opened = linux_fd::open_top_directory(path).map_err(open_error)?;
    private(&opened)?;
    Ok(opened)
}
fn private(opened: &OpenedPath) -> Result<(), SessionError> {
    let metadata = linux_fd::metadata(opened.fd())?;
    if !metadata.is_trusted_directory() || metadata.mode() & 0o7777 != 0o700 {
        return Err(invalid(
            "state directories must be owned and mode 0700",
        ));
    }
    Ok(())
}
fn validate_state_separation(cwd: &Path, state: &Path) -> Result<(), SessionError> {
    if cwd.starts_with(state) || state.starts_with(cwd) {
        return Err(invalid(
            "working directory overlaps managed session state",
        ));
    }
    Ok(())
}

fn canonical_path(path: &Path) -> Result<(), SessionError> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid("managed Shell paths must be UTF-8"))?;
    if !path.is_absolute()
        || text.len() > 4096
        || text.contains('\0')
        || text[1..]
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(invalid(
            "managed Shell paths must be explicit absolute canonical paths",
        ));
    }
    Ok(())
}
fn open_error(error: linux_fd::OpenError) -> SessionError {
    match error {
        linux_fd::OpenError::Other(error) | linux_fd::OpenError::Unsupported(error) => error.into(),
        linux_fd::OpenError::Symlink => invalid("managed Shell paths cannot traverse symlinks"),
    }
}
fn invalid(message: &str) -> SessionError {
    SessionError::Supervision(message.into())
}
fn check(cancellation: &Cancellation) -> Result<(), SessionError> {
    cancellation
        .check()
        .map_err(|_| SessionError::Cancelled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn private_directory() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn explicit_paths_reject_relative_noncanonical_and_nul_spelling() {
        for path in [
            "relative",
            "",
            "/tmp/../state",
            "/tmp/./state",
            "/tmp//state",
            "/tmp/state/",
            "/tmp/sta\0te",
        ] {
            assert!(
                canonical_path(Path::new(path)).is_err(),
                "accepted {path:?}"
            );
        }
        canonical_path(Path::new("/tmp/state-1")).unwrap();
    }

    #[test]
    fn layout_keeps_journal_and_operation_evidence_separate_and_reuses_identities() {
        let root = private_directory();
        let layout = StateLayout::open(root.path()).unwrap();
        std::fs::write(
            root.path().join("operations/evidence"),
            b"retained",
        )
        .unwrap();
        let again = StateLayout::open(root.path()).unwrap();
        assert_eq!(
            layout.journal.metadata().identity(),
            again.journal.metadata().identity()
        );
        assert_eq!(
            layout.operations.metadata().identity(),
            again.operations.metadata().identity()
        );
        assert_ne!(
            layout.journal.metadata().identity(),
            layout.operations.metadata().identity()
        );
        drop((layout, again));
        assert_eq!(
            std::fs::read(root.path().join("operations/evidence")).unwrap(),
            b"retained"
        );
    }

    #[test]
    fn layout_refuses_unprotected_parent_and_symlink_or_unprotected_children() {
        let root = private_directory();
        std::fs::set_permissions(
            root.path(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(StateLayout::open(root.path()).is_err());
        assert!(!root.path().join("journal").exists());
        std::fs::set_permissions(
            root.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let foreign = private_directory();
        std::os::unix::fs::symlink(foreign.path(), root.path().join("journal")).unwrap();
        assert!(StateLayout::open(root.path()).is_err());
        std::fs::remove_file(root.path().join("journal")).unwrap();
        std::fs::create_dir(root.path().join("journal")).unwrap();
        std::fs::set_permissions(
            root.path().join("journal"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(StateLayout::open(root.path()).is_err());
        assert!(!root.path().join("operations").exists());
    }

    #[test]
    fn wrong_destination_and_configuration_only_fail_before_manager_or_state_access() {
        for kind in ["Os", "Shell"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(
                root.path().join("main.srx"),
                format!(
                    "outputs {{ selected: std::{kind} = std::{kind} {{ pkgs = []; services = []; }}; }}"
                ),
            )
            .unwrap();
            let checks = crate::project::CheckConfiguration {
                standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
                ..crate::project::CheckConfiguration::default()
            };
            crate::project::lock_project_with(root.path(), &checks).unwrap();
            let plan =
                crate::project::prepare_project_consumer_with(root.path(), &checks, "selected")
                    .unwrap();
            let user =
                crate::config::UserConfiguration::parse("", root.path().join("store")).unwrap();
            let prepared = crate::deployment::manifest::prepare_consumer(
                plan,
                "selected",
                &user,
                Path::new("missing-worker"),
                true,
                &Cancellation::default(),
                |_, _| panic!("no outputs can build"),
            )
            .unwrap();
            let configuration = ManagedShellConfiguration {
                secrets: crate::config::ShellSecretSources::default(),
                worker: "missing-worker".into(),
                worker_digest: ContentDigest::sha256(b"missing"),
                bus_socket: "missing-bus".into(),
                state_directory: root.path().join("must-not-exist"),
                cwd: "missing-cwd".into(),
            };
            let error = ManagedShell::start(prepared, &configuration, &Cancellation::default())
                .unwrap_err();
            if kind == "Os" {
                assert!(matches!(error, SessionError::NotShell));
            } else {
                assert!(
                    matches!(error, SessionError::Supervision(message) if message.contains("no realizable output"))
                );
            }
            assert!(!configuration.state_directory.exists());
        }
    }

    #[test]
    fn state_overlap_is_rejected_before_uid_manager_or_layout_effects() {
        let root = private_directory();
        let state = root.path().join("state");
        let descendant = state.join("work");
        std::fs::create_dir_all(&descendant).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let worker = root.path().join("candidate");
        std::fs::write(&worker, b"candidate fixture").unwrap();
        for cwd in [
            root.path(),
            state.as_path(),
            descendant.as_path(),
        ] {
            let configuration = ManagedShellConfiguration {
                secrets: crate::config::ShellSecretSources::default(),
                worker: worker.clone(),
                worker_digest: ContentDigest::sha256(b"candidate fixture"),
                bus_socket: root.path().join("absent-manager"),
                state_directory: state.clone(),
                cwd: cwd.into(),
            };
            let error = configuration
                .validate(&Cancellation::default())
                .unwrap_err();
            assert!(
                matches!(error, SessionError::Supervision(message) if message == "working directory overlaps managed session state")
            );
            assert!(!state.join("journal").exists());
            assert!(!state.join("operations").exists());
            assert!(!configuration.bus_socket.exists());
        }
        // Component comparisons must not confuse similarly prefixed sibling names.
        validate_state_separation(&root.path().join("state-work"), &state).unwrap();
        validate_state_separation(&root.path().join("work"), &state).unwrap();
    }
}

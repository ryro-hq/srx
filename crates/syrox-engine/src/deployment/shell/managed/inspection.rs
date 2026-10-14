use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{record, supervision};
use crate::execution::journal::{SessionId, SessionJournal, SessionPhase};
use crate::{cancellation::Cancellation, deployment::shell::SessionError, store::ContentDigest};

#[derive(Debug)]
pub struct ManagedSessionEntry {
    pub session: String,
    pub evidence: Result<ManagedSessionEvidence, String>,
}

/// Journal observations alone do not prove current manager/process state.
#[derive(Debug)]
pub struct ManagedSessionEvidence {
    pub boot: String,
    pub phase: String,
    pub pin: ContentDigest,
    pub attempts: usize,
    pub configuration_hint: PathBuf,
    /// Mutable data hint only; no authority to remove its contents.
    pub state_hint: Option<PathBuf>,
    pub cwd: PathBuf,
}

pub fn list_managed_shell_sessions(
    state_directory: &Path,
    cancellation: &Cancellation,
) -> Result<Vec<ManagedSessionEntry>, SessionError> {
    cancellation
        .check()
        .map_err(|_| SessionError::Cancelled)?;
    let journal = open_existing(state_directory)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let ids = journal
        .session_ids(cancellation, deadline)
        .map_err(supervision)?;
    let mut entries = Vec::with_capacity(ids.len());
    for id in ids {
        check_budget(cancellation, deadline)?;
        let evidence =
            inspect(&journal, &id, cancellation, deadline).map_err(|error| error.to_string());
        check_budget(cancellation, deadline)?;
        entries.push(ManagedSessionEntry {
            session: id.to_string(),
            evidence,
        });
    }
    Ok(entries)
}

/// Revoke admission and reconcile recorded unit identities. Unconfirmed process
/// settlement remains pending; this never deletes configuration or restarts units.
pub fn recover_managed_shell_session(
    state_directory: &Path,
    session: &str,
    bus_socket: &Path,
    store: &Path,
    cancellation: &Cancellation,
) -> Result<super::recovery::ShellRecoveryReport, SessionError> {
    cancellation
        .check()
        .map_err(|_| SessionError::Cancelled)?;
    let id = SessionId::parse(session).map_err(supervision)?;
    let journal = open_existing(state_directory)?;
    super::recovery::recover_shell(
        &journal,
        &id,
        bus_socket,
        store,
        cancellation,
        Instant::now() + Duration::from_secs(30),
    )
    .map_err(supervision)
}

pub(super) fn open_existing(state: &Path) -> Result<SessionJournal, SessionError> {
    let state = std::path::absolute(state)?;
    let descriptor = crate::platform::linux::fd::open_top_directory(&state)
        .map_err(|error| SessionError::Supervision(format!("invalid session state: {error:?}")))?;
    if !descriptor.metadata().is_trusted_directory()
        || descriptor.metadata().mode() & 0o7777 != 0o700
    {
        return Err(SessionError::Supervision(
            "session state must be owned and mode 0700".into(),
        ));
    }
    let journal = SessionJournal::open_existing(&state.join("journal")).map_err(supervision)?;
    // Detect replacement during opening. Journal operations independently pin
    // their authority and revalidate its published path before every lock.
    if crate::platform::linux::fd::directory_path(&descriptor)? != state {
        return Err(SessionError::Supervision(
            "session state directory was replaced".into(),
        ));
    }
    Ok(journal)
}

fn inspect(
    journal: &SessionJournal,
    id: &SessionId,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<ManagedSessionEvidence, SessionError> {
    let (snapshot, bytes) = journal
        .snapshot_with_manifest(id, cancellation, deadline)
        .map_err(supervision)?;
    let operation = record::decode(&bytes, snapshot.pin).map_err(|_| {
        SessionError::Supervision("invalid Shell operation record; evidence preserved".into())
    })?;
    check_budget(cancellation, deadline)?;
    let phase = match snapshot.phase {
        SessionPhase::Pending => "pending",
        SessionPhase::Authorized => "authorized",
        SessionPhase::Running => "running",
        SessionPhase::Closing => "closing",
        SessionPhase::Closed => "closed",
    };
    Ok(ManagedSessionEvidence {
        boot: operation.boot().as_str().into(),
        phase: phase.into(),
        pin: snapshot.pin,
        attempts: snapshot.attempts.len(),
        configuration_hint: operation.configuration().into(),
        state_hint: operation.state().map(Path::to_path_buf),
        cwd: operation.cwd().into(),
    })
}

fn check_budget(cancellation: &Cancellation, deadline: Instant) -> Result<(), SessionError> {
    cancellation
        .check()
        .map_err(|_| SessionError::Cancelled)?;
    if Instant::now() >= deadline {
        return Err(SessionError::Supervision(
            "session inspection deadline exceeded".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn missing_registry_is_never_initialized_by_inspection() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(list_managed_shell_sessions(root.path(), &Cancellation::default()).is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        fs::create_dir(root.path().join("journal")).unwrap();
        fs::set_permissions(
            root.path().join("journal"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(list_managed_shell_sessions(root.path(), &Cancellation::default()).is_err());
        assert_eq!(
            fs::read_dir(root.path().join("journal"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn inspection_preserves_valid_and_incomplete_session_evidence() {
        let (project, plan) = super::super::super::tests::configuration_plan();
        let user =
            crate::config::UserConfiguration::parse("", project.path().join("store")).unwrap();
        let cancel = Cancellation::default();
        let prepared = crate::deployment::manifest::prepare_consumer(
            plan,
            "shell",
            &user,
            Path::new("missing"),
            true,
            &cancel,
            |_, _| panic!("configuration cannot build"),
        )
        .unwrap();
        let (snapshot, _) = crate::deployment::os::shell_snapshot(
            &prepared,
            crate::deployment::os::LauncherIdentity::new(ContentDigest::sha256(b"candidate"), 1)
                .unwrap(),
        )
        .unwrap();
        let bytes = record::encode(
            &boot(),
            &snapshot,
            Path::new("/private/config"),
            Path::new("/work"),
        )
        .unwrap();
        let state = tempfile::tempdir().unwrap();
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let registry = state.path().join("journal");
        fs::create_dir(&registry).unwrap();
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
        let journal = SessionJournal::open(&registry).unwrap();
        let id = journal
            .create(
                &bytes,
                ContentDigest::sha256(&bytes),
                &cancel,
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
        let incomplete = "11111111111111111111111111111111";
        fs::create_dir(registry.join(incomplete)).unwrap();
        fs::set_permissions(
            registry.join(incomplete),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let before = fs::read(registry.join(id.as_str()).join("state")).unwrap();
        let entries = list_managed_shell_sessions(state.path(), &cancel).unwrap();
        assert_eq!(entries.len(), 2);
        let entry = entries
            .iter()
            .find(|entry| entry.session == id.as_str())
            .unwrap();
        let evidence = entry.evidence.as_ref().unwrap();
        assert_eq!(evidence.phase, "pending");
        assert_eq!(
            evidence.configuration_hint,
            Path::new("/private/config")
        );
        assert_eq!(evidence.cwd, Path::new("/work"));
        assert_eq!(evidence.attempts, 0);
        assert!(
            entries
                .iter()
                .find(|entry| entry.session == incomplete)
                .unwrap()
                .evidence
                .is_err()
        );
        assert_eq!(
            before,
            fs::read(registry.join(id.as_str()).join("state")).unwrap()
        );
        assert!(!project.path().join("store").exists());
    }

    fn boot() -> crate::platform::linux::boot::BootId {
        crate::platform::linux::boot::BootId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap()
    }
}

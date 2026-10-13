use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::{ExecutionId, OwnershipError, SessionId, SessionJournal, record, storage};
use crate::execution::command_evidence::{
    GuardianIdentity, ObservedCommandExecutionSettlement, SettlementReceiver,
};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest};

const MAX_EXECUTIONS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExecutionPhase {
    Prepared,
    Retained,
    Started,
    Settled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutionRecord {
    index: String,
    phase: ExecutionPhase,
    retention: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guardian: Option<GuardianIdentity>,
    #[serde(default, skip_serializing_if = "zero")]
    next_gate: u64,
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct ExecutionSnapshot {
    pub(crate) phase: ExecutionPhase,
    pub(crate) next_gate: u64,
}

pub(crate) struct ExecutionGuard<'a> {
    journal: &'a SessionJournal,
    session: SessionId,
    execution: ExecutionId,
    index: ContentDigest,
    directory: linux_fd::OpenedPath,
    lock: linux_fd::OpenedPath,
    phase: ExecutionPhase,
    retention: Option<crate::store::DurableInterest>,
    guardian: Option<GuardianIdentity>,
}

impl SessionJournal {
    pub(crate) fn prepare_execution(
        &self,
        session: &SessionId,
        index: ContentDigest,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<ExecutionGuard<'_>, OwnershipError> {
        let _authority = self.storage.lock(cancel, deadline)?;
        let (directory, mut state) = self.load(session)?;
        state.require_open()?;
        if !matches!(
            state.phase,
            record::SessionPhase::Authorized | record::SessionPhase::Running
        ) {
            return Err(OwnershipError::State(
                "execution requires an admitted session",
            ));
        }
        if state.executions.len() >= MAX_EXECUTIONS {
            return Err(OwnershipError::State(
                "execution capacity exhausted",
            ));
        }
        // Count physical evidence, including locks left by a crash before the
        // state write. Do not erase orphaned records merely to recover capacity.
        let mut evidence = 0_usize;
        linux_fd::read_directory(&directory, |name| {
            storage::check(cancel, deadline)?;
            if name != "state" && name != "manifest" {
                evidence += 1;
                if evidence >= MAX_EXECUTIONS {
                    return Err(OwnershipError::State(
                        "execution evidence capacity exhausted",
                    ));
                }
            }
            Ok(())
        })
        .map_err(|error| match error {
            linux_fd::ReadDirectoryError::Io(error) => OwnershipError::Io(error),
            linux_fd::ReadDirectoryError::Admission(error) => error,
        })?;
        for _ in 0..64 {
            let execution = ExecutionId::fresh()?;
            let name = format!("execution-{}.lock", execution.as_str());
            let (lock, created) = linux_fd::initialize_regular(directory.fd(), Path::new(&name))?;
            if !created {
                continue;
            }
            if !linux_fd::flock(
                lock.fd(),
                linux_fd::FlockMode::ExclusiveNonblocking,
            )? {
                return Err(OwnershipError::State(
                    "new execution lock is busy",
                ));
            }
            linux_fd::sync_file(lock.fd())?;
            linux_fd::sync_directory(directory.fd())?;
            state.executions.insert(
                execution.to_string(),
                ExecutionRecord {
                    index: index.to_string(),
                    phase: ExecutionPhase::Prepared,
                    retention: None,
                    guardian: None,
                    next_gate: 0,
                },
            );
            state.advance()?;
            storage::check(cancel, deadline)?;
            self.storage
                .write(directory.fd(), "state", &state.encode()?)?;
            return Ok(ExecutionGuard {
                journal: self,
                session: session.clone(),
                execution,
                index,
                directory,
                lock,
                phase: ExecutionPhase::Prepared,
                retention: None,
                guardian: None,
            });
        }
        Err(OwnershipError::State(
            "execution identity retries exhausted",
        ))
    }
}

impl ExecutionGuard<'_> {
    pub(crate) fn session(&self) -> &SessionId {
        &self.session
    }
    pub(crate) fn execution(&self) -> &ExecutionId {
        &self.execution
    }
    pub(crate) fn index(&self) -> ContentDigest {
        self.index
    }
    pub(crate) fn retention_digest(&self) -> Option<ContentDigest> {
        self.retention
            .as_ref()
            .map(crate::store::DurableInterest::digest)
    }

    /// Consumes the actual published record; a string pin cannot authorize this
    /// transition. Uncertain journal publication preserves the durable interest.
    pub(crate) fn retain(
        &mut self,
        retention: crate::store::DurableInterest,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), OwnershipError> {
        if self.phase != ExecutionPhase::Prepared
            || self.retention.is_some()
            || retention.execution() != self.execution.as_str()
        {
            return Err(OwnershipError::State(
                "retention belongs to another execution or phase",
            ));
        }
        let digest = retention.digest();
        self.retention = Some(retention);
        self.advance(
            ExecutionPhase::Retained,
            Some(digest),
            cancel,
            deadline,
        )
    }

    /// Persist single-use start intent BEFORE launching the guardian. There is
    /// deliberately no recovery method that turns Started back into Retained.
    pub(crate) fn begin_start(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), OwnershipError> {
        if self.phase != ExecutionPhase::Retained {
            return Err(OwnershipError::State(
                "execution is not ready for a unique start",
            ));
        }
        let digest = self
            .retention
            .as_ref()
            .ok_or(OwnershipError::State(
                "execution lacks durable retention",
            ))?
            .digest();
        self.advance(
            ExecutionPhase::Started,
            Some(digest),
            cancel,
            deadline,
        )
    }

    /// Associate the live, pinned receiver before authorizing any namespace.
    pub(crate) fn bind_guardian(
        &mut self,
        receiver: &SettlementReceiver,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), OwnershipError> {
        let retention = self
            .retention_digest()
            .ok_or(OwnershipError::State("missing retention"))?;
        if self.phase != ExecutionPhase::Started
            || self.guardian.is_some()
            || !receiver.matches(
                &self.session,
                &self.execution,
                self.index,
                retention,
            )
        {
            return Err(OwnershipError::State(
                "guardian binding differs from execution",
            ));
        }
        receiver.revalidate()?;
        let _authority = self.journal.storage.lock(cancel, deadline)?;
        let (directory, mut state) = self.journal.load(&self.session)?;
        state.require_open()?;
        self.check_record(&directory, &state)?;
        receiver.revalidate()?;
        let guardian = receiver.guardian();
        state
            .executions
            .get_mut(self.execution.as_str())
            .unwrap()
            .guardian = Some(guardian);
        state.advance()?;
        storage::check(cancel, deadline)?;
        self.journal
            .storage
            .write(directory.fd(), "state", &state.encode()?)?;
        self.guardian = Some(guardian);
        Ok(())
    }

    /// The private admission handler validates the request's namespace/spec
    /// before this callback. Sequence consumption is durable before ACK, and
    /// Closing shares this authority lock. An uncertain ACK is never retried.
    pub(crate) fn with_started_execution<T>(
        &self,
        sequence: u64,
        cancel: &Cancellation,
        deadline: Instant,
        acknowledge: impl FnOnce() -> std::io::Result<T>,
    ) -> Result<T, OwnershipError> {
        if self.phase != ExecutionPhase::Started || self.guardian.is_none() {
            return Err(OwnershipError::State(
                "execution lacks guardian authority",
            ));
        }
        let _authority = self.journal.storage.lock(cancel, deadline)?;
        let (directory, mut state) = self.journal.load(&self.session)?;
        state.require_open()?;
        self.check_record(&directory, &state)?;
        let entry = state
            .executions
            .get_mut(self.execution.as_str())
            .unwrap();
        if entry.next_gate != sequence {
            return Err(OwnershipError::State(
                "execution gate sequence differs",
            ));
        }
        entry.next_gate = sequence
            .checked_add(1)
            .ok_or(OwnershipError::State(
                "execution gate sequence exhausted",
            ))?;
        state.advance()?;
        storage::check(cancel, deadline)?;
        self.journal
            .storage
            .write(directory.fd(), "state", &state.encode()?)?;
        storage::check(cancel, deadline)?;
        Ok(acknowledge()?)
    }

    /// A wire claim alone cannot call this: the receiver must authenticate the
    /// guardian's proof and independently observe that exact guardian's exit.
    // Settlement authority is consumed, never lent for reuse by another finish.
    #[allow(clippy::needless_pass_by_value)] // Serde skip predicates receive a reference even for copyable identity fields.
    pub(crate) fn finish(
        mut self,
        proof: ObservedCommandExecutionSettlement,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), OwnershipError> {
        if self.phase != ExecutionPhase::Started
            || proof.session() != &self.session
            || proof.execution() != &self.execution
            || proof.index() != self.index
            || Some(proof.retention()) != self.retention_digest()
            || Some(proof.guardian()) != self.guardian
        {
            return Err(OwnershipError::State(
                "settlement belongs to another execution",
            ));
        }
        let _authority = self.journal.storage.lock(cancel, deadline)?;
        let (directory, mut state) = self.journal.load(&self.session)?;
        // Closing revokes starts, but does not prevent authentic settlement.
        self.check_record(&directory, &state)?;
        state
            .executions
            .get_mut(self.execution.as_str())
            .unwrap()
            .phase = ExecutionPhase::Settled;
        state.advance()?;
        storage::check(cancel, deadline)?;
        self.journal
            .storage
            .write(directory.fd(), "state", &state.encode()?)?;
        self.phase = ExecutionPhase::Settled;
        self.retention
            .take()
            .ok_or(OwnershipError::State(
                "missing retained resources",
            ))?
            .retire_checked(|| {
                cancel
                    .check()
                    .map_err(|_| crate::cancellation::cancellation_io())?;
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "retention retirement deadline",
                    ));
                }
                Ok(())
            })
            .map_err(OwnershipError::Store)
    }

    fn advance(
        &mut self,
        phase: ExecutionPhase,
        retention: Option<ContentDigest>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), OwnershipError> {
        let _authority = self.journal.storage.lock(cancel, deadline)?;
        let (directory, mut state) = self.journal.load(&self.session)?;
        state.require_open()?;
        self.check_record(&directory, &state)?;
        let entry = state
            .executions
            .get_mut(self.execution.as_str())
            .unwrap();
        entry.phase = phase;
        entry.retention = retention.map(|pin| pin.to_string());
        state.advance()?;
        storage::check(cancel, deadline)?;
        self.journal
            .storage
            .write(directory.fd(), "state", &state.encode()?)?;
        self.phase = phase;
        Ok(())
    }

    fn check_record(
        &self,
        directory: &linux_fd::OpenedPath,
        state: &record::Record,
    ) -> Result<(), OwnershipError> {
        if directory.metadata().identity() != self.directory.metadata().identity() {
            return Err(OwnershipError::Invalid(
                "execution directory replaced",
            ));
        }
        let name = format!("execution-{}.lock", self.execution.as_str());
        let current = linux_fd::open_existing_regular(directory.fd(), Path::new(&name))?;
        if current.metadata().identity() != self.lock.metadata().identity()
            || current.metadata().mode() & 0o7777 != 0o600
            || current.metadata().size() != 0
        {
            return Err(OwnershipError::Invalid("execution lock replaced"));
        }
        let entry = state
            .executions
            .get(self.execution.as_str())
            .ok_or(OwnershipError::State("unknown execution"))?;
        let previous_retention = if self.phase == ExecutionPhase::Prepared {
            None
        } else {
            self.retention_digest().map(|pin| pin.to_string())
        };
        if entry.phase != self.phase
            || entry.index != self.index.to_string()
            || entry.retention != previous_retention
            || entry.guardian != self.guardian
        {
            return Err(OwnershipError::State("execution phase changed"));
        }
        Ok(())
    }
}

// No Drop releases retention, marks settlement or removes recovery evidence.

pub(super) fn validate_records(state: &record::Record) -> Result<(), OwnershipError> {
    if state.executions.len() > MAX_EXECUTIONS {
        return Err(OwnershipError::Invalid(
            "execution inventory too large",
        ));
    }
    if state.phase == record::SessionPhase::Pending && !state.executions.is_empty() {
        return Err(OwnershipError::Invalid(
            "pending session contains executions",
        ));
    }
    for (id, entry) in &state.executions {
        ExecutionId::parse(id)?;
        digest(&entry.index)?;
        if (entry.phase == ExecutionPhase::Prepared) != entry.retention.is_none() {
            return Err(OwnershipError::Invalid(
                "execution retention phase differs",
            ));
        }
        if let Some(pin) = &entry.retention {
            digest(pin)?;
        }
        if entry.guardian.is_some()
            && !matches!(
                entry.phase,
                ExecutionPhase::Started | ExecutionPhase::Settled
            )
            || entry.guardian.is_none() && entry.next_gate != 0
            || entry.phase == ExecutionPhase::Settled && entry.guardian.is_none()
        {
            return Err(OwnershipError::Invalid(
                "invalid execution guardian phase",
            ));
        }
        if let Some(guardian) = entry.guardian
            && (guardian.pid <= 1
                || guardian.uid == 0
                || guardian.uid == u32::MAX
                || guardian.gid == u32::MAX
                || guardian.device == 0
                || guardian.inode == 0)
        {
            return Err(OwnershipError::Invalid(
                "invalid guardian identity",
            ));
        }
        if state.phase == record::SessionPhase::Closed && entry.phase != ExecutionPhase::Settled {
            return Err(OwnershipError::Invalid(
                "closed session has unsettled execution",
            ));
        }
    }
    Ok(())
}

// serde's skip_serializing_if callback receives a reference.
#[allow(clippy::trivially_copy_pass_by_ref)] // Serde skip predicates receive a reference even for copyable identity fields.
fn zero(value: &u64) -> bool {
    *value == 0
}

fn digest(text: &str) -> Result<ContentDigest, OwnershipError> {
    let pin: ContentDigest = text
        .parse()
        .map_err(|_| OwnershipError::Invalid("invalid execution pin"))?;
    Ok(pin)
}

#[cfg(test)]
pub(super) fn snapshots(state: &record::Record) -> Result<Vec<ExecutionSnapshot>, OwnershipError> {
    state
        .executions
        .values()
        .map(|entry| {
            Ok(ExecutionSnapshot {
                phase: entry.phase,
                next_gate: entry.next_gate,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::journal::AttemptBinding;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    fn setup() -> (
        tempfile::TempDir,
        SessionJournal,
        SessionId,
        crate::store::Store,
        crate::store::ObjectLease,
    ) {
        let root = tempfile::tempdir().unwrap();
        let registry = root.path().join("sessions");
        std::fs::create_dir(&registry).unwrap();
        std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = SessionJournal::open(&registry).unwrap();
        let cancel = Cancellation::default();
        let manifest = b"execution session fixture";
        let session = journal
            .create(
                manifest,
                ContentDigest::sha256(manifest),
                &cancel,
                deadline(),
            )
            .unwrap();
        let attempt = journal
            .prepare_attempt(&session, "owner", &cancel, deadline())
            .unwrap();
        let binding = AttemptBinding::new(
            crate::systemd::SystemdUnitName::new("syrox-owner.service").unwrap(),
            [1; 16],
        )
        .unwrap();
        journal
            .authorize_attempt(&session, &attempt, &binding, &cancel, deadline())
            .unwrap();
        std::fs::create_dir(root.path().join("store")).unwrap();
        let store = crate::store::Store::open(&root.path().join("store")).unwrap();
        let operation = store.operation().unwrap();
        let bytes: &[u8] = b"retained command artifact";
        let digest = ContentDigest::sha256(bytes);
        operation
            .ingest(bytes, digest, bytes.len() as u64)
            .unwrap();
        let lease = operation
            .retain_objects(&[digest], &[digest])
            .unwrap();
        drop(operation);
        (root, journal, session, store, lease)
    }

    fn phase(journal: &SessionJournal, session: &SessionId) -> ExecutionPhase {
        journal
            .snapshot(session, &Cancellation::default(), deadline())
            .unwrap()
            .executions[0]
            .phase
    }

    #[test]
    fn start_intent_is_durable_single_use_and_does_not_hold_global_authority() {
        let (root, journal, session, store, lease) = setup();
        let cancel = Cancellation::default();
        let mut execution = journal
            .prepare_execution(
                &session,
                ContentDigest::sha256(b"index"),
                &cancel,
                deadline(),
            )
            .unwrap();
        assert_eq!(
            phase(&journal, &session),
            ExecutionPhase::Prepared
        );
        assert!(
            execution
                .begin_start(&cancel, deadline())
                .is_err()
        );
        let hold = lease
            .persist_checked(execution.execution().as_str(), || Ok(()))
            .unwrap();
        execution
            .retain(hold, &cancel, deadline())
            .unwrap();
        execution
            .begin_start(&cancel, deadline())
            .unwrap();
        assert_eq!(phase(&journal, &session), ExecutionPhase::Started);
        assert!(
            execution
                .begin_start(&cancel, deadline())
                .is_err()
        );
        let lock_path = root
            .path()
            .join("sessions")
            .join(session.as_str())
            .join(format!(
                "execution-{}.lock",
                execution.execution()
            ));
        let parent = linux_fd::open_top_directory(lock_path.parent().unwrap()).unwrap();
        let lock = linux_fd::open_existing_regular(
            parent.fd(),
            Path::new(lock_path.file_name().unwrap()),
        )
        .unwrap();
        assert!(
            !linux_fd::flock(
                lock.fd(),
                linux_fd::FlockMode::ExclusiveNonblocking
            )
            .unwrap()
        );
        drop((execution, lease));
        assert!(
            linux_fd::flock(
                lock.fd(),
                linux_fd::FlockMode::ExclusiveNonblocking
            )
            .unwrap()
        );
        assert_eq!(phase(&journal, &session), ExecutionPhase::Started);
        assert!(
            store
                .maintenance()
                .unwrap()
                .garbage_collect(&crate::store::GcRequest {
                    collect: true,
                    ..crate::store::GcRequest::default()
                })
                .unwrap()
                .removed_objects
                .is_empty()
        );
    }

    #[test]
    fn closing_revokes_pending_start_but_preserves_execution_and_retention() {
        let (_root, journal, session, store, lease) = setup();
        let cancel = Cancellation::default();
        let mut execution = journal
            .prepare_execution(
                &session,
                ContentDigest::sha256(b"index"),
                &cancel,
                deadline(),
            )
            .unwrap();
        execution
            .retain(
                lease
                    .persist_checked(execution.execution().as_str(), || Ok(()))
                    .unwrap(),
                &cancel,
                deadline(),
            )
            .unwrap();
        journal
            .begin_closing(&session, "fixture close", &cancel, deadline())
            .unwrap();
        assert!(
            execution
                .begin_start(&cancel, deadline())
                .is_err()
        );
        assert_eq!(
            phase(&journal, &session),
            ExecutionPhase::Retained
        );
        drop((execution, lease));
        assert!(
            store
                .maintenance()
                .unwrap()
                .garbage_collect(&crate::store::GcRequest {
                    collect: true,
                    ..crate::store::GcRequest::default()
                })
                .unwrap()
                .removed_objects
                .is_empty()
        );
    }

    #[test]
    fn foreign_hold_and_replaced_execution_lock_cannot_authorize_start() {
        let (root, journal, session, _store, lease) = setup();
        let cancel = Cancellation::default();
        let mut execution = journal
            .prepare_execution(
                &session,
                ContentDigest::sha256(b"index"),
                &cancel,
                deadline(),
            )
            .unwrap();
        let foreign = lease
            .persist_checked("abcdef1234567890abcdef1234567890", || Ok(()))
            .unwrap();
        assert!(
            execution
                .retain(foreign, &cancel, deadline())
                .is_err()
        );
        execution
            .retain(
                lease
                    .persist_checked(execution.execution().as_str(), || Ok(()))
                    .unwrap(),
                &cancel,
                deadline(),
            )
            .unwrap();
        let path = root
            .path()
            .join("sessions")
            .join(session.as_str())
            .join(format!(
                "execution-{}.lock",
                execution.execution()
            ));
        std::fs::rename(&path, root.path().join("displaced-lock")).unwrap();
        std::fs::write(&path, []).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            execution
                .begin_start(&cancel, deadline())
                .is_err()
        );
        assert_eq!(
            phase(&journal, &session),
            ExecutionPhase::Retained
        );
    }

    #[test]
    fn cancellation_never_records_a_started_execution() {
        let (_root, journal, session, _store, lease) = setup();
        let cancel = Cancellation::default();
        let mut execution = journal
            .prepare_execution(
                &session,
                ContentDigest::sha256(b"index"),
                &cancel,
                deadline(),
            )
            .unwrap();
        execution
            .retain(
                lease
                    .persist_checked(execution.execution().as_str(), || Ok(()))
                    .unwrap(),
                &cancel,
                deadline(),
            )
            .unwrap();
        cancel.cancel();
        assert!(matches!(
            execution.begin_start(&cancel, deadline()),
            Err(OwnershipError::Cancelled)
        ));
        assert_eq!(
            phase(&journal, &session),
            ExecutionPhase::Retained
        );
    }

    #[test]
    fn orphaned_lock_files_consume_execution_capacity_without_being_removed() {
        let (root, journal, session, _store, _lease) = setup();
        let directory = root
            .path()
            .join("sessions")
            .join(session.as_str());
        for index in 1..=MAX_EXECUTIONS {
            std::fs::write(
                directory.join(format!("execution-{index:032x}.lock")),
                [],
            )
            .unwrap();
        }
        assert!(matches!(
            journal.prepare_execution(
                &session,
                ContentDigest::sha256(b"index"),
                &Cancellation::default(),
                deadline()
            ),
            Err(OwnershipError::State(
                "execution evidence capacity exhausted"
            ))
        ));
        assert_eq!(
            std::fs::read_dir(directory).unwrap().count(),
            MAX_EXECUTIONS + 2
        );
        assert!(
            journal
                .snapshot(&session, &Cancellation::default(), deadline())
                .unwrap()
                .executions
                .is_empty()
        );
    }

    // These tests establish journal state directly. They test only serialization
    // and one-use authority, never guardian authentication or settlement transport.
    fn bind_journal_fixture(execution: &mut ExecutionGuard<'_>) {
        let identity = GuardianIdentity {
            pid: 42,
            uid: 1000,
            gid: 1000,
            device: 1,
            inode: 2,
        };
        let cancel = Cancellation::default();
        let _authority = execution
            .journal
            .storage
            .lock(&cancel, deadline())
            .unwrap();
        let (directory, mut state) = execution
            .journal
            .load(execution.session())
            .unwrap();
        state
            .executions
            .get_mut(execution.execution().as_str())
            .unwrap()
            .guardian = Some(identity);
        state.advance().unwrap();
        execution
            .journal
            .storage
            .write(directory.fd(), "state", &state.encode().unwrap())
            .unwrap();
        execution.guardian = Some(identity);
    }

    #[test]
    fn gate_ack_failure_consumes_sequence_and_closing_prevents_callback() {
        let (_root, journal, session, _store, lease) = setup();
        let cancel = Cancellation::default();
        let mut execution = journal
            .prepare_execution(
                &session,
                ContentDigest::sha256(b"index"),
                &cancel,
                deadline(),
            )
            .unwrap();
        execution
            .retain(
                lease
                    .persist_checked(execution.execution().as_str(), || Ok(()))
                    .unwrap(),
                &cancel,
                deadline(),
            )
            .unwrap();
        execution
            .begin_start(&cancel, deadline())
            .unwrap();
        assert!(
            execution
                .with_started_execution::<()>(0, &cancel, deadline(), || panic!(
                    "missing guardian must refuse"
                ))
                .is_err()
        );
        bind_journal_fixture(&mut execution);
        assert!(
            execution
                .with_started_execution::<()>(0, &cancel, deadline(), || Err::<(), _>(
                    std::io::Error::other("uncertain ACK")
                ))
                .is_err()
        );
        assert_eq!(
            journal
                .snapshot(&session, &cancel, deadline())
                .unwrap()
                .executions[0]
                .next_gate,
            1
        );
        assert!(
            execution
                .with_started_execution::<()>(0, &cancel, deadline(), || panic!(
                    "replay must refuse"
                ))
                .is_err()
        );
        assert_eq!(
            execution
                .with_started_execution(1, &cancel, deadline(), || Ok(7))
                .unwrap(),
            7
        );
        journal
            .begin_closing(&session, "fixture close", &cancel, deadline())
            .unwrap();
        assert!(
            execution
                .with_started_execution::<()>(2, &cancel, deadline(), || panic!(
                    "revoked gate must refuse"
                ))
                .is_err()
        );
    }
}

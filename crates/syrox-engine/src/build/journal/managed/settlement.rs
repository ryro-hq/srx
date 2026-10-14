use super::*;
use crate::build::managed::execution::ManagedBuildSettlement;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u8,
    attempt: String,
    nonce: String,
    action: String,
    worker: String,
    boot: String,
    manager: String,
    scope: String,
    unit: String,
    uid: u32,
    gid: u32,
}
impl Marker {
    fn expected(record: &Record, bytes: &[u8]) -> Result<Vec<u8>, BuildError> {
        if !matches!(
            record.state,
            State::CommitConsumed | State::Revoked | State::LocalAborted
        ) {
            return Err(invalid(
                "managed settlement requires a terminal attempt",
            ));
        }
        let marker = Self {
            version: 1,
            attempt: ContentDigest::sha256(bytes).to_string(),
            nonce: ContentDigest::sha256(record.nonce.as_bytes()).to_string(),
            action: record.action.clone(),
            worker: record.worker.clone(),
            boot: record.boot.clone(),
            manager: record.manager.clone(),
            scope: record.scope.clone(),
            unit: record.unit.clone(),
            uid: record.uid,
            gid: record.gid,
        };
        serde_json::to_vec(&marker).map_err(|_| invalid("managed settlement encoding failed"))
    }
}

/// A valid terminal marker authenticates one exact canonical attempt snapshot.
/// Absence is not settlement; malformed or foreign markers fail closed.
pub(in crate::build) fn settled_managed(
    directory: &linux_fd::OpenedPath,
) -> Result<bool, BuildError> {
    let Some(marker) = read(directory, SETTLED_FILE, LIMIT)? else {
        return Ok(false);
    };
    let bytes = read(directory, FILE, LIMIT)?.ok_or_else(|| invalid("settled attempt missing"))?;
    let record = Record::parse(&bytes)?;
    if let Some(attempt) = super::super::Attempt::read(directory)?
        && attempt.action != record.context()?.action
    {
        return Err(invalid(
            "managed settlement Action disagrees with producer",
        ));
    }
    let decoded: Marker =
        serde_json::from_slice(&marker).map_err(|_| invalid("invalid managed settlement"))?;
    if serde_json::to_vec(&decoded).map_err(|_| invalid("invalid managed settlement"))? != marker
        || Marker::expected(&record, &bytes)? != marker
    {
        return Err(invalid(
            "managed settlement disagrees with attempt",
        ));
    }
    Ok(true)
}

impl Operation {
    /// Persist the execution owner's closed proof without deleting staged bytes.
    pub(in crate::build) fn record_managed_settlement(
        &self,
        proof: &ManagedBuildSettlement,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        let guard = acquire_guard(self, cancellation, deadline)?;
        let bytes = read(&self.directory, FILE, LIMIT)?
            .ok_or_else(|| invalid("managed attempt missing"))?;
        let record = Record::parse(&bytes)?;
        let context = record.context()?;
        validate_current_context(self, &context)?;
        if &context != proof.context()
            || ContentDigest::sha256(record.nonce.as_bytes()) != proof.nonce()
        {
            return Err(invalid(
                "managed settlement proof differs from attempt",
            ));
        }
        let marker = Marker::expected(&record, &bytes)?;
        if let Some(existing) = read(&self.directory, SETTLED_FILE, LIMIT)? {
            if existing != marker {
                return Err(invalid("conflicting managed settlement"));
            }
            check(cancellation, deadline)?;
            validate_guard(self, &guard)?;
            // A prior write may have installed bytes but failed directory sync.
            linux_fd::sync_directory(self.directory.fd())?;
            return Ok(());
        }
        check(cancellation, deadline)?;
        validate_guard(self, &guard)?;
        write(&self.directory, SETTLED_FILE, &marker)
    }
}

/// Called under recovery's exclusive operation and namespace locks.
pub(in crate::build::journal) fn validate_settled_identity(
    directory: &linux_fd::OpenedPath,
    unit: &str,
    boot: &str,
) -> Result<(), BuildError> {
    if !settled_managed(directory)? {
        return Err(invalid("managed settlement missing"));
    }
    let bytes = read(directory, FILE, LIMIT)?.ok_or_else(|| invalid("managed attempt missing"))?;
    let record = Record::parse(&bytes)?;
    if record.unit != unit || record.boot != boot {
        return Err(invalid(
            "managed settlement operation identity differs",
        ));
    }
    Ok(())
}

// Only the live, exclusive local preparation token may invoke this path.
// The v4 local-only phase remains distinguishable if marker persistence fails.
pub(super) fn record_unstarted(
    operation: &Operation,
    guard: &linux_fd::OpenedPath,
    record: &Record,
) -> Result<(), BuildError> {
    validate_guard(operation, guard)?;
    validate_current_context(operation, &record.context()?)?;
    let bytes = record.encode()?;
    write(&operation.directory, FILE, &bytes)?;
    validate_guard(operation, guard)?;
    if read(&operation.directory, FILE, LIMIT)?.as_deref() != Some(bytes.as_slice()) {
        return Err(invalid(
            "local revocation changed before settlement",
        ));
    }
    write(
        &operation.directory,
        SETTLED_FILE,
        &Marker::expected(record, &bytes)?,
    )
}

/// Recovery holds all operation locks; v4 Awaiting has never exposed dispatch authority.
pub(in crate::build::journal) fn settle_local_awaiting(
    directory: &linux_fd::OpenedPath,
    unit: &str,
    boot: &str,
) -> Result<bool, BuildError> {
    let bytes = read(directory, FILE, LIMIT)?.ok_or_else(|| invalid("managed attempt missing"))?;
    let mut record = Record::parse(&bytes)?;
    if record.unit != unit || record.boot != boot {
        return Err(invalid("managed operation identity differs"));
    }
    validate_shared_attempt(directory, record.context()?.action)?;
    if !matches!(
        record.state,
        State::Awaiting | State::LocalAborted
    ) {
        return Ok(false);
    }
    for name in [
        "authorized",
        "revoked",
        "cleaned",
        "cgroup",
    ] {
        if read(directory, name, LIMIT)?.is_some() {
            return Err(invalid(
                "managed local attempt contains legacy authority",
            ));
        }
    }
    if record.state == State::Awaiting {
        record.state = State::LocalAborted;
        write(directory, FILE, &record.encode()?)?;
    }
    let bytes = record.encode()?;
    write(
        directory,
        SETTLED_FILE,
        &Marker::expected(&record, &bytes)?,
    )?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build::BuildRecoveryState, store::Store};
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    fn fixture() -> (
        tempfile::TempDir,
        Store,
        Operation,
        ManagedAttemptContext,
        String,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::initialize(&temp.path().join("store")).unwrap();
        let operation = Operation::create(&store.operation().unwrap()).unwrap();
        let context = ManagedAttemptContext {
            action: ContentDigest::sha256(b"action"),
            worker: ContentDigest::sha256(b"worker"),
            boot: boot_id().unwrap(),
            manager: ContentDigest::sha256(b"manager"),
            scope: "user:/run/user/1000/bus".into(),
            unit: SystemdUnitName::new(operation.unit()).unwrap(),
            uid: linux_fd::real_uid(),
            gid: linux_fd::real_gid(),
        };
        let nonce = operation
            .prepare_managed(&context, &Cancellation::default(), deadline())
            .unwrap();
        (temp, store, operation, context, nonce)
    }
    fn proof(context: ManagedAttemptContext, nonce: &str) -> ManagedBuildSettlement {
        ManagedBuildSettlement::for_test(context, ContentDigest::sha256(nonce.as_bytes()))
    }
    #[test]
    fn terminal_marker_is_durable_idempotent_and_keeps_stage_until_recovery() {
        let (_temp, store, operation, context, nonce) = fixture();
        let cancel = Cancellation::default();
        operation
            .write_stage("source", b"retained until publication", false)
            .unwrap();
        let proof = proof(context.clone(), &nonce);
        assert!(
            operation
                .record_managed_settlement(&proof, &cancel, deadline())
                .is_err()
        );
        operation
            .revoke_managed(&cancel, deadline())
            .unwrap();
        operation
            .record_managed_settlement(&proof, &cancel, deadline())
            .unwrap();
        let bytes = read(&operation.directory, SETTLED_FILE, LIMIT)
            .unwrap()
            .unwrap();
        operation
            .record_managed_settlement(&proof, &cancel, deadline())
            .unwrap();
        assert_eq!(
            read(&operation.directory, SETTLED_FILE, LIMIT)
                .unwrap()
                .unwrap(),
            bytes
        );
        assert!(settled_managed(&operation.directory).unwrap());
        assert!(super::super::super::terminal_settlement(&operation.directory).unwrap());
        assert!(operation.path.join("stage/source").exists());
        assert!(
            operation
                .revoke_managed(&cancel, deadline())
                .is_err()
        );
        assert!(
            operation
                .prepare_managed(&context, &cancel, deadline())
                .is_err()
        );
        let active = super::super::super::recover(&store).unwrap();
        assert!(matches!(
            active.entries[0].state,
            BuildRecoveryState::Active
        ));
        let path = operation.path.clone();
        drop(operation);
        let recovered = super::super::super::recover(&store).unwrap();
        assert!(matches!(
            recovered.entries[0].state,
            BuildRecoveryState::Recovered
        ));
        assert!(!path.exists());
    }
    #[test]
    fn wrong_proof_cancel_and_missing_terminal_evidence_do_not_authorize_cleanup() {
        let (_temp, store, operation, context, nonce) = fixture();
        let cancel = Cancellation::default();
        operation
            .revoke_managed(&cancel, deadline())
            .unwrap();
        assert!(
            operation
                .record_managed_settlement(
                    &proof(context.clone(), "wrong"),
                    &cancel,
                    deadline()
                )
                .is_err()
        );
        let mut foreign = context.clone();
        foreign.manager = ContentDigest::sha256(b"foreign manager");
        assert!(
            operation
                .record_managed_settlement(&proof(foreign, &nonce), &cancel, deadline())
                .is_err()
        );
        let cancelled = Cancellation::default();
        cancelled.cancel();
        assert!(matches!(
            operation.record_managed_settlement(&proof(context, &nonce), &cancelled, deadline()),
            Err(BuildError::Cancelled)
        ));
        write(
            &operation.directory,
            "cleaned",
            b"syrox-build-cleaned\n",
        )
        .unwrap();
        assert!(!super::super::super::terminal_settlement(&operation.directory).unwrap());
        let path = operation.path.clone();
        drop(operation);
        let report = super::super::super::recover(&store).unwrap();
        assert!(matches!(
            report.entries[0].state,
            BuildRecoveryState::Retained(_)
        ));
        assert!(path.exists());
    }
    #[test]
    fn changed_attempt_or_marker_is_retained_instead_of_reconciled() {
        for change_record in [false, true] {
            let (_temp, store, operation, context, nonce) = fixture();
            let cancel = Cancellation::default();
            operation
                .revoke_managed(&cancel, deadline())
                .unwrap();
            operation
                .record_managed_settlement(&proof(context, &nonce), &cancel, deadline())
                .unwrap();
            if change_record {
                let bytes = read(&operation.directory, FILE, LIMIT)
                    .unwrap()
                    .unwrap();
                let mut record = Record::parse(&bytes).unwrap();
                record.worker = ContentDigest::sha256(b"changed worker").to_string();
                write(
                    &operation.directory,
                    FILE,
                    &record.encode().unwrap(),
                )
                .unwrap();
            } else {
                write(&operation.directory, SETTLED_FILE, b"{}").unwrap();
            }
            assert!(settled_managed(&operation.directory).is_err());
            let path = operation.path.clone();
            drop(operation);
            let report = super::super::super::recover(&store).unwrap();
            assert!(matches!(
                report.entries[0].state,
                BuildRecoveryState::Retained(_)
            ));
            assert!(path.exists());
        }
    }
    #[test]
    fn successful_consumed_snapshot_accepts_marker_without_revocation() {
        let (_temp, _store, operation, context, nonce) = fixture();
        let bytes = read(&operation.directory, FILE, LIMIT)
            .unwrap()
            .unwrap();
        let mut record = Record::parse(&bytes).unwrap();
        record.state = State::CommitConsumed;
        record.binding = Some(Binding {
            invocation: "11".repeat(16),
            main_pid: 99,
            contract: ContentDigest::sha256(b"contract").to_string(),
        });
        record.namespace = Some(NamespaceRecord {
            resources: ContentDigest::sha256(b"resources").to_string(),
            pid: 100,
            device: 1,
            inode: 2,
        });
        write(
            &operation.directory,
            FILE,
            &record.encode().unwrap(),
        )
        .unwrap();
        operation
            .record_managed_settlement(
                &proof(context, &nonce),
                &Cancellation::default(),
                deadline(),
            )
            .unwrap();
        assert!(settled_managed(&operation.directory).unwrap());
    }

    #[test]
    fn settled_old_boot_garbage_resumes_only_after_observer_is_gone() {
        let (_temp, store, operation, context, nonce) = fixture();
        let cancel = Cancellation::default();
        operation
            .revoke_managed(&cancel, deadline())
            .unwrap();
        operation
            .record_managed_settlement(&proof(context, &nonce), &cancel, deadline())
            .unwrap();
        let lease = store.operation().unwrap();
        let parent = lease.build_directory().unwrap();
        let old_boot = "11111111-1111-4111-8111-111111111111";
        let mut record = Record::parse(
            &read(&operation.directory, FILE, LIMIT)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        record.boot = old_boot.into();
        let bytes = record.encode().unwrap();
        write(&operation.directory, FILE, &bytes).unwrap();
        write(
            &operation.directory,
            SETTLED_FILE,
            &Marker::expected(&record, &bytes).unwrap(),
        )
        .unwrap();
        let identity = super::super::super::identity(
            &operation.name,
            old_boot,
            parent.metadata().identity(),
            operation.directory.metadata().identity(),
        );
        write(
            &operation.directory,
            "identity",
            identity.as_bytes(),
        )
        .unwrap();
        let observer = linux_fd::open_existing_regular(
            operation.directory.fd(),
            std::path::Path::new("observers"),
        )
        .unwrap();
        assert!(linux_fd::flock(observer.fd(), linux_fd::FlockMode::Shared).unwrap());
        let garbage = format!("gc-{}", &operation.name[3..]);
        linux_fd::rename_directory(
            parent.fd(),
            std::path::Path::new(&operation.name),
            std::path::Path::new(&garbage),
            operation.directory.metadata().identity(),
        )
        .unwrap();
        drop(operation);
        assert!(matches!(
            super::super::super::recover(&store)
                .unwrap()
                .entries[0]
                .state,
            BuildRecoveryState::Active
        ));
        drop(observer);
        assert!(matches!(
            super::super::super::recover(&store)
                .unwrap()
                .entries[0]
                .state,
            BuildRecoveryState::Recovered
        ));
    }
}

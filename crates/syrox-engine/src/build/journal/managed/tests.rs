use super::*;
use crate::store::Store;
use std::time::Duration;

fn fixture() -> (
    tempfile::TempDir,
    Store,
    Operation,
    ManagedAttemptContext,
) {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::initialize(&temporary.path().join("store")).unwrap();
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
    (temporary, store, operation, context)
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn observation(
    context: ManagedAttemptContext,
    nonce: String,
) -> crate::build::managed::supervision::ObservedManagedBuildBinding {
    crate::build::managed::supervision::ObservedManagedBuildBinding::for_test(
        context,
        nonce,
        [1; 16],
        100,
        ContentDigest::sha256(b"contract"),
    )
}
#[test]
fn durable_binding_is_single_use_and_never_host_authorization() {
    let (_temporary, _store, operation, context) = fixture();
    let cancel = Cancellation::default();
    let nonce = operation
        .prepare_managed(&context, &cancel, deadline())
        .unwrap();
    assert!(super::super::enter_gate(&operation.path).is_err());
    assert!(operation.clean_stage().is_err());
    assert!(
        operation
            .bind(super::super::Attempt::new(context.action, 30).unwrap())
            .is_err()
    );
    assert!(
        read(&operation.directory, "authorized", 64)
            .unwrap()
            .is_none()
    );
    operation
        .authorize_managed_start(&context, &nonce, &cancel, deadline())
        .unwrap();
    let observed = observation(context, nonce);
    operation
        .bind_managed(&observed, &cancel, deadline())
        .unwrap();
    assert!(
        operation
            .bind_managed(&observed, &cancel, deadline())
            .is_err()
    );
    let bytes = read(&operation.directory, FILE, LIMIT)
        .unwrap()
        .unwrap();
    let record = Record::parse(&bytes).unwrap();
    assert!(record.state == State::Bound);
    assert_eq!(record.binding.unwrap().main_pid, 100);
    operation
        .revoke_managed(&cancel, deadline())
        .unwrap();
    operation
        .revoke_managed(&cancel, deadline())
        .unwrap();
    assert!(
        operation
            .bind_managed(&observed, &cancel, deadline())
            .is_err()
    );
    let revoked = Record::parse(
        &read(&operation.directory, FILE, LIMIT)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(revoked.state == State::Revoked && revoked.binding.is_some());
}
#[test]
fn cancellation_old_boot_and_context_mismatch_do_not_bind() {
    let (_temporary, _store, operation, mut context) = fixture();
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(
        operation
            .prepare_managed(&context, &cancel, deadline())
            .is_err()
    );
    assert!(!present(&operation.directory).unwrap());
    let cancel = Cancellation::default();
    let actual_boot = context.boot.clone();
    context.boot = "00000000-0000-0000-0000-000000000000".into();
    assert!(
        operation
            .prepare_managed(&context, &cancel, deadline())
            .is_err()
    );
    context.boot = actual_boot;
    let nonce = operation
        .prepare_managed(&context, &cancel, deadline())
        .unwrap();
    context.manager = ContentDigest::sha256(b"replacement manager");
    assert!(
        operation
            .bind_managed(&observation(context, nonce), &cancel, deadline())
            .is_err()
    );
    assert!(
        Record::parse(
            &read(&operation.directory, FILE, LIMIT)
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .state
            == State::Awaiting
    );
}
#[test]
fn managed_evidence_survives_recovery_even_in_initial_or_garbage_namespace() {
    for prefix in ["op-", "init-", "gc-"] {
        let (_temporary, store, operation, context) = fixture();
        let nonce = operation
            .prepare_managed(&context, &Cancellation::default(), deadline())
            .unwrap();
        operation
            .authorize_managed_start(
                &context,
                &nonce,
                &Cancellation::default(),
                deadline(),
            )
            .unwrap();
        let old_path = operation.path.clone();
        let path = old_path.with_file_name(format!("{prefix}{}", &operation.name[3..]));
        drop(operation);
        if old_path != path {
            std::fs::rename(old_path, &path).unwrap();
        }
        let report = super::super::recover(&store).unwrap();
        assert!(report.entries.iter().any(|entry| matches!(
            entry.state,
            crate::build::BuildRecoveryState::Retained(_)
        )));
        assert!(path.join(FILE).exists());
        assert!(!path.join("revoked").exists());
        std::fs::write(path.join(FILE), b"malformed").unwrap();
        let report = super::super::recover(&store).unwrap();
        assert!(report.entries.iter().any(|entry| matches!(
            entry.state,
            crate::build::BuildRecoveryState::Retained(_)
        )));
        assert!(path.join(FILE).exists());
    }
}
#[test]
fn codec_rejects_tampered_or_noncanonical_state() {
    let (_temporary, _store, operation, context) = fixture();
    operation
        .prepare_managed(&context, &Cancellation::default(), deadline())
        .unwrap();
    let bytes = read(&operation.directory, FILE, LIMIT)
        .unwrap()
        .unwrap();
    let mut record = Record::parse(&bytes).unwrap();
    record.state = State::Bound;
    assert!(Record::parse(&record.encode().unwrap()).is_err());
    record.state = State::Awaiting;
    record.nonce = "caller nonce".into();
    assert!(Record::parse(&record.encode().unwrap()).is_err());
    let mut trailing = bytes;
    trailing.push(b'\n');
    assert!(Record::parse(&trailing).is_err());
    assert!(Record::parse(&vec![b' '; LIMIT + 1]).is_err());
}

#[test]
fn copied_record_and_replaced_operation_namespace_cannot_bind_or_revoke() {
    let (_temporary, store, operation, context) = fixture();
    let cancel = Cancellation::default();
    let nonce = operation
        .prepare_managed(&context, &cancel, deadline())
        .unwrap();
    operation
        .authorize_managed_start(&context, &nonce, &cancel, deadline())
        .unwrap();
    let observed = observation(context, nonce);
    let second = Operation::create(&store.operation().unwrap()).unwrap();
    let bytes = read(&operation.directory, FILE, LIMIT)
        .unwrap()
        .unwrap();
    write(&second.directory, FILE, &bytes).unwrap();
    assert!(
        second
            .bind_managed(&observed, &cancel, deadline())
            .is_err()
    );
    let moved = operation.path.with_extension("moved");
    std::fs::rename(&operation.path, &moved).unwrap();
    std::fs::create_dir(&operation.path).unwrap();
    assert!(
        operation
            .bind_managed(&observed, &cancel, deadline())
            .is_err()
    );
    assert!(
        operation
            .revoke_managed(&cancel, deadline())
            .is_err()
    );
    assert_eq!(std::fs::read(moved.join(FILE)).unwrap(), bytes);
}

#[test]
fn previous_boot_managed_record_is_retained_without_legacy_cleanup() {
    let (_temporary, store, operation, context) = fixture();
    operation
        .prepare_managed(&context, &Cancellation::default(), deadline())
        .unwrap();
    let mut record = Record::parse(
        &read(&operation.directory, FILE, LIMIT)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    record.boot = "11111111-1111-1111-1111-111111111111".into();
    write(
        &operation.directory,
        FILE,
        &record.encode().unwrap(),
    )
    .unwrap();
    let path = operation.path.clone();
    drop(operation);
    let report = super::super::recover(&store).unwrap();
    assert!(report.entries.iter().any(|entry| matches!(
        entry.state,
        crate::build::BuildRecoveryState::Retained(_)
    )));
    assert!(path.join(FILE).exists());
    assert!(!path.join("revoked").exists());
}

#[test]
fn worker_read_snapshot_rejects_lock_and_parent_namespace_replacement() {
    let (_temporary, _store, operation, context) = fixture();
    let cancellation = Cancellation::default();
    let nonce = operation
        .prepare_managed(&context, &cancellation, deadline())
        .unwrap();
    operation
        .authorize_managed_start(&context, &nonce, &cancellation, deadline())
        .unwrap();
    let attempt = inspect_worker_attempt(
        &operation.path,
        context.action,
        &nonce,
        &cancellation,
        deadline(),
    )
    .unwrap();
    let gate = operation.path.join("gate");
    let moved_gate = operation.path.join("gate-old");
    std::fs::rename(&gate, &moved_gate).unwrap();
    std::fs::write(&gate, b"").unwrap();
    assert!(attempt.revalidate().is_err());
    std::fs::remove_file(&gate).unwrap();
    std::fs::rename(&moved_gate, &gate).unwrap();
    assert!(attempt.revalidate().is_ok());
    let parent = operation.path.parent().unwrap();
    let moved = parent.with_extension("moved");
    std::fs::rename(parent, &moved).unwrap();
    std::fs::create_dir(parent).unwrap();
    assert!(attempt.revalidate().is_err());
}

#[test]
fn worker_inspection_refuses_path_aliases_and_new_legacy_markers() {
    let (_temporary, _store, operation, context) = fixture();
    let cancellation = Cancellation::default();
    let nonce = operation
        .prepare_managed(&context, &cancellation, deadline())
        .unwrap();
    let parent = operation.path.parent().unwrap().display();
    for alias in [
        format!("{parent}/./{}", operation.name),
        format!("{parent}//{}", operation.name),
        format!("{}/", operation.path.display()),
    ] {
        assert!(
            inspect_worker_attempt(
                std::path::Path::new(&alias),
                context.action,
                &nonce,
                &cancellation,
                deadline()
            )
            .is_err()
        );
    }
    operation
        .authorize_managed_start(&context, &nonce, &cancellation, deadline())
        .unwrap();
    let attempt = inspect_worker_attempt(
        &operation.path,
        context.action,
        &nonce,
        &cancellation,
        deadline(),
    )
    .unwrap();
    write(
        &operation.directory,
        "authorized",
        super::super::AUTHORIZED,
    )
    .unwrap();
    assert!(attempt.revalidate().is_err());
}

fn namespace_record() -> NamespaceRecord {
    NamespaceRecord {
        resources: ContentDigest::sha256(b"authenticated resource manifest").to_string(),
        pid: 200,
        device: 1,
        inode: 300,
    }
}
fn bound_record() -> (
    tempfile::TempDir,
    Store,
    Operation,
    crate::build::managed::supervision::ObservedManagedBuildBinding,
    Vec<u8>,
) {
    let (temporary, store, operation, context) = fixture();
    let cancel = Cancellation::default();
    let nonce = operation
        .prepare_managed(&context, &cancel, deadline())
        .unwrap();
    operation
        .authorize_managed_start(&context, &nonce, &cancel, deadline())
        .unwrap();
    let observed = observation(context, nonce);
    operation
        .bind_managed(&observed, &cancel, deadline())
        .unwrap();
    let bytes = read(&operation.directory, FILE, LIMIT)
        .unwrap()
        .unwrap();
    (temporary, store, operation, observed, bytes)
}
#[test]
fn namespace_record_is_single_use_and_full_binding_matched_without_kernel_claims() {
    let (_temporary, _store, _operation, observed, bytes) = bound_record();
    for change in 0..8 {
        let mut context = observed.context().clone();
        let mut nonce = observed.nonce().to_owned();
        let mut invocation = *observed.invocation();
        let mut pid = observed.main_pid();
        let mut contract = observed.contract();
        match change {
            0 => context.action = ContentDigest::sha256(b"different action"),
            1 => context.worker = ContentDigest::sha256(b"different worker"),
            2 => context.manager = ContentDigest::sha256(b"different manager"),
            3 => context.scope = "system".into(),
            4 => nonce = "22222222222222222222222222222222".into(),
            5 => invocation = [2; 16],
            6 => pid = 101,
            _ => contract = ContentDigest::sha256(b"different contract"),
        }
        let wrong = crate::build::managed::supervision::ObservedManagedBuildBinding::for_test(
            context, nonce, invocation, pid, contract,
        );
        assert!(
            Record::parse(&bytes)
                .unwrap()
                .namespace_prepared(&wrong, namespace_record())
                .is_err()
        );
    }
    let mut record = Record::parse(&bytes).unwrap();
    record
        .namespace_prepared(&observed, namespace_record())
        .unwrap();
    assert!(record.state == State::NamespacePrepared);
    assert!(
        record
            .namespace_prepared(&observed, namespace_record())
            .is_err()
    );
    record.state = State::Revoked;
    assert!(
        record
            .namespace_prepared(&observed, namespace_record())
            .is_err()
    );
}
#[test]
fn namespace_codec_enforces_phase_evidence_matrix_and_identity_bounds() {
    let (_temporary, _store, _operation, _observed, bytes) = bound_record();
    for state in [
        State::Awaiting,
        State::StartAuthorized,
        State::LocalAborted,
        State::Bound,
        State::NamespacePrepared,
        State::CommitAuthorized,
        State::CommitConsumed,
        State::Revoked,
    ] {
        for has_binding in [false, true] {
            for has_namespace in [false, true] {
                let mut record = Record::parse(&bytes).unwrap();
                record.state = state;
                if !has_binding {
                    record.binding = None;
                }
                record.namespace = has_namespace.then(namespace_record);
                let expected = match state {
                    State::Awaiting | State::StartAuthorized | State::LocalAborted => {
                        !has_binding && !has_namespace
                    }
                    State::Bound => has_binding && !has_namespace,
                    State::NamespacePrepared | State::CommitAuthorized | State::CommitConsumed => {
                        has_binding && has_namespace
                    }
                    State::Revoked => !has_namespace || has_binding,
                };
                assert_eq!(
                    Record::parse(&record.encode().unwrap()).is_ok(),
                    expected
                );
            }
        }
    }
    for change in 0..7 {
        let mut record = Record::parse(&bytes).unwrap();
        let mut namespace = namespace_record();
        match change {
            0 => namespace.pid = 1,
            1 => namespace.pid = observed_main_pid(&record),
            2 => namespace.pid = u32::MAX,
            3 => namespace.device = 0,
            4 => namespace.inode = 0,
            5 => namespace.resources = "invalid pin".into(),
            _ => record.version = 1,
        }
        record.state = State::NamespacePrepared;
        record.namespace = Some(namespace);
        assert!(Record::parse(&record.encode().unwrap()).is_err());
    }
}
fn observed_main_pid(record: &Record) -> u32 {
    record.binding.as_ref().unwrap().main_pid
}
#[test]
fn namespace_fixture_recovery_and_revocation_preserve_evidence_without_authorizing() {
    let (_temporary, store, operation, observed, bytes) = bound_record();
    // A persisted codec fixture exercises recovery only. It is deliberately not
    // an opaque kernel observation and never calls the production transition.
    let mut record = Record::parse(&bytes).unwrap();
    record
        .namespace_prepared(&observed, namespace_record())
        .unwrap();
    write(
        &operation.directory,
        FILE,
        &record.encode().unwrap(),
    )
    .unwrap();
    let cancel = Cancellation::default();
    let attempt = inspect_worker_attempt(
        &operation.path,
        observed.context().action,
        observed.nonce(),
        &cancel,
        deadline(),
    )
    .unwrap();
    assert_eq!(
        attempt.bound_process().unwrap(),
        Some((*observed.invocation(), observed.main_pid()))
    );
    let snapshot = attempt.namespace_snapshot().unwrap().unwrap();
    assert_eq!(
        snapshot.resources,
        ContentDigest::sha256(b"authenticated resource manifest")
    );
    assert_eq!(
        (snapshot.pid, snapshot.device, snapshot.inode),
        (200, 1, 300)
    );
    drop(attempt);
    assert!(super::super::enter_gate(&operation.path).is_err());
    assert!(operation.clean_stage().is_err());
    operation
        .revoke_managed(&cancel, deadline())
        .unwrap();
    let revoked = read(&operation.directory, FILE, LIMIT)
        .unwrap()
        .unwrap();
    assert!(Record::parse(&revoked).unwrap().state == State::Revoked);
    assert!(
        Record::parse(&revoked)
            .unwrap()
            .namespace
            .is_some()
    );
    assert!(
        inspect_worker_attempt(
            &operation.path,
            observed.context().action,
            observed.nonce(),
            &cancel,
            deadline()
        )
        .is_err()
    );
    let path = operation.path.clone();
    drop(operation);
    let report = super::super::recover(&store).unwrap();
    assert!(report.entries.iter().any(|entry| matches!(
        entry.state,
        crate::build::BuildRecoveryState::Retained(_)
    )));
    assert_eq!(std::fs::read(path.join(FILE)).unwrap(), revoked);
    assert!(!path.join("authorized").exists());
}

#[test]
fn mutation_guard_detects_gate_replacement_before_persisting() {
    let (_temporary, _store, operation, context) = fixture();
    let cancellation = Cancellation::default();
    operation
        .prepare_managed(&context, &cancellation, deadline())
        .unwrap();
    let before = read(&operation.directory, FILE, LIMIT)
        .unwrap()
        .unwrap();
    let locked = guard(&operation, &cancellation, deadline()).unwrap();
    let gate = operation.path.join("gate");
    let moved = operation.path.join("gate-moved");
    std::fs::rename(&gate, &moved).unwrap();
    std::fs::write(&gate, b"").unwrap();
    assert!(validate_guard(&operation, &locked).is_err());
    assert_eq!(
        read(&operation.directory, FILE, LIMIT)
            .unwrap()
            .unwrap(),
        before
    );
    std::fs::remove_file(&gate).unwrap();
    std::fs::rename(&moved, &gate).unwrap();
    validate_guard(&operation, &locked).unwrap();
    std::fs::write(&gate, b"unexpected lock bytes").unwrap();
    assert!(validate_guard(&operation, &locked).is_err());
}

#[test]
fn commit_transitions_compare_all_evidence_and_cannot_replay() {
    let (_temporary, _store, _operation, observed, bytes) = bound_record();
    let expected = Record::parse(&bytes).unwrap();
    for field in 0..16 {
        let mut record = Record::parse(&bytes).unwrap();
        record
            .namespace_prepared(&observed, namespace_record())
            .unwrap();
        match field {
            0 => record.action = ContentDigest::sha256(b"different").to_string(),
            1 => record.worker = ContentDigest::sha256(b"different").to_string(),
            2 => record.manager = ContentDigest::sha256(b"different").to_string(),
            3 => record.boot = "11111111-1111-1111-1111-111111111111".into(),
            4 => record.scope = "system".into(),
            5 => record.unit = "different.service".into(),
            6 => record.uid += 1,
            7 => record.gid += 1,
            8 => record.nonce = "22222222222222222222222222222222".into(),
            9 => record.binding.as_mut().unwrap().main_pid += 1,
            10 => {
                record.binding.as_mut().unwrap().invocation =
                    "22222222222222222222222222222222".into();
            }
            11 => {
                record.binding.as_mut().unwrap().contract =
                    ContentDigest::sha256(b"different").to_string();
            }
            12 => {
                record.namespace.as_mut().unwrap().resources =
                    ContentDigest::sha256(b"different").to_string();
            }
            13 => record.namespace.as_mut().unwrap().pid += 1,
            14 => record.namespace.as_mut().unwrap().inode += 1,
            _ => record.namespace.as_mut().unwrap().device += 1,
        }
        assert!(
            record
                .commit_transition(
                    &expected,
                    namespace_record().snapshot().unwrap(),
                    State::NamespacePrepared,
                    State::CommitAuthorized
                )
                .is_err(),
            "field {field}"
        );
    }
    let mut record = Record::parse(&bytes).unwrap();
    record
        .namespace_prepared(&observed, namespace_record())
        .unwrap();
    let namespace = namespace_record().snapshot().unwrap();
    record
        .commit_transition(
            &expected,
            namespace,
            State::NamespacePrepared,
            State::CommitAuthorized,
        )
        .unwrap();
    assert!(
        record
            .commit_transition(
                &expected,
                namespace,
                State::NamespacePrepared,
                State::CommitAuthorized
            )
            .is_err()
    );
    record
        .commit_transition(
            &expected,
            namespace,
            State::CommitAuthorized,
            State::CommitConsumed,
        )
        .unwrap();
    assert!(
        record
            .commit_transition(
                &expected,
                namespace,
                State::CommitAuthorized,
                State::CommitConsumed
            )
            .is_err()
    );
    record.state = State::Revoked;
    assert!(
        record
            .commit_transition(
                &expected,
                namespace,
                State::CommitAuthorized,
                State::CommitConsumed
            )
            .is_err()
    );
}
#[test]
fn send_and_release_failures_preserve_durable_single_use_phases() {
    // Fixture-only state transitions test ordering, not kernel/manager evidence.
    let (_temporary, _store, operation, observed, bytes) = bound_record();
    let cancel = Cancellation::default();
    let mut record = Record::parse(&bytes).unwrap();
    record
        .namespace_prepared(&observed, namespace_record())
        .unwrap();
    write(
        &operation.directory,
        FILE,
        &record.encode().unwrap(),
    )
    .unwrap();
    let expected = Record::parse(&bytes).unwrap();
    let namespace = namespace_record().snapshot().unwrap();
    record
        .commit_transition(
            &expected,
            namespace,
            State::NamespacePrepared,
            State::CommitAuthorized,
        )
        .unwrap();
    {
        let guard = guard(&operation, &cancel, deadline()).unwrap();
        let result: Result<(), BuildError> = commit_send(
            &operation,
            &guard,
            &record,
            &cancel,
            deadline(),
            || {
                let persisted = Record::parse(&read(&operation.directory, FILE, LIMIT)?.unwrap())?;
                assert!(persisted.state == State::CommitAuthorized);
                assert!(lock_existing(&operation.directory, "gate")?.is_none());
                Err(BuildError::InputChanged)
            },
        );
        assert!(result.is_err());
    }
    let attempt = inspect_worker_attempt(
        &operation.path,
        expected.context().unwrap().action,
        &expected.nonce,
        &cancel,
        deadline(),
    )
    .unwrap();
    record
        .commit_transition(
            &expected,
            namespace,
            State::CommitAuthorized,
            State::CommitConsumed,
        )
        .unwrap();
    let result: Result<(), BuildError> =
        commit_worker_release(&attempt, &record, &cancel, deadline(), || {
            let persisted = Record::parse(&read(&operation.directory, FILE, LIMIT)?.unwrap())?;
            assert!(persisted.state == State::CommitConsumed);
            assert!(lock_existing(&operation.directory, "gate")?.is_none());
            Err(BuildError::InputChanged)
        });
    assert!(result.is_err());
    drop(attempt);
    let persisted = Record::parse(
        &read(&operation.directory, FILE, LIMIT)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(persisted.state == State::CommitConsumed);
    operation
        .revoke_managed(&cancel, deadline())
        .unwrap();
    let revoked = Record::parse(
        &read(&operation.directory, FILE, LIMIT)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(revoked.state == State::Revoked && revoked.namespace.is_some());
}

#[test]
fn cancelled_commit_does_not_publish_or_invoke_callback() {
    let (_temporary, _store, operation, observed, bytes) = bound_record();
    let active = Cancellation::default();
    let cancel = Cancellation::default();
    let mut record = Record::parse(&bytes).unwrap();
    record
        .namespace_prepared(&observed, namespace_record())
        .unwrap();
    write(
        &operation.directory,
        FILE,
        &record.encode().unwrap(),
    )
    .unwrap();
    let previous = read(&operation.directory, FILE, LIMIT)
        .unwrap()
        .unwrap();
    record
        .commit_transition(
            &Record::parse(&bytes).unwrap(),
            namespace_record().snapshot().unwrap(),
            State::NamespacePrepared,
            State::CommitAuthorized,
        )
        .unwrap();
    let guard = guard(&operation, &active, deadline()).unwrap();
    cancel.cancel();
    assert!(
        commit_send(
            &operation,
            &guard,
            &record,
            &cancel,
            deadline(),
            || -> Result<(), BuildError> {
                panic!("cancelled commit must not send");
            }
        )
        .is_err()
    );
    assert_eq!(
        read(&operation.directory, FILE, LIMIT)
            .unwrap()
            .unwrap(),
        previous
    );
}

#[test]
fn canonical_shared_attempt_allows_managed_preparation_but_not_host_gate() {
    let (_temporary, _store, operation, context) = fixture();
    operation
        .bind(super::super::Attempt::new(context.action, 37).unwrap())
        .unwrap();
    let cancellation = Cancellation::default();
    let nonce = operation
        .prepare_managed(&context, &cancellation, deadline())
        .unwrap();
    operation
        .authorize_managed_start(&context, &nonce, &cancellation, deadline())
        .unwrap();
    let inspection = inspect_worker_attempt(
        &operation.path,
        context.action,
        &nonce,
        &cancellation,
        deadline(),
    )
    .unwrap();
    inspection.revalidate().unwrap();
    drop(inspection);
    assert!(super::super::enter_gate(&operation.path).is_err());
    assert!(operation.authorize(context.action, None).is_err());
}

#[test]
fn managed_preparation_rejects_foreign_and_noncanonical_shared_attempts() {
    for bytes in [
        super::super::Attempt::new(ContentDigest::sha256(b"foreign"), 30)
            .unwrap()
            .encode()
            .into_bytes(),
        b"syrox-build-attempt-v1\naction broken\ntimeout 30\n".to_vec(),
    ] {
        let (_temporary, _store, operation, context) = fixture();
        write(&operation.directory, "action", &bytes).unwrap();
        assert!(
            operation
                .prepare_managed(&context, &Cancellation::default(), deadline())
                .is_err()
        );
        assert!(
            read(&operation.directory, FILE, LIMIT)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn start_boundary_is_durable_single_use_and_worker_requires_it() {
    let (_temporary, _store, operation, context) = fixture();
    let cancellation = Cancellation::default();
    let nonce = operation
        .prepare_managed(&context, &cancellation, deadline())
        .unwrap();
    assert!(
        inspect_worker_attempt(
            &operation.path,
            context.action,
            &nonce,
            &cancellation,
            deadline()
        )
        .is_err()
    );
    let observed = observation(context.clone(), nonce.clone());
    assert!(
        operation
            .bind_managed(&observed, &cancellation, deadline())
            .is_err()
    );
    operation
        .authorize_managed_start(&context, &nonce, &cancellation, deadline())
        .unwrap();
    assert!(
        operation
            .authorize_managed_start(&context, &nonce, &cancellation, deadline())
            .is_err()
    );
    let record = Record::parse(
        &read(&operation.directory, FILE, LIMIT)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(record.state == State::StartAuthorized);
    operation
        .bind_managed(&observed, &cancellation, deadline())
        .unwrap();
}

#[test]
fn failed_start_authorization_never_dispatches_and_recovery_preserves_uncertainty() {
    let (_temporary, store, operation, context) = fixture();
    let cancellation = Cancellation::default();
    let nonce = operation
        .prepare_managed(&context, &cancellation, deadline())
        .unwrap();
    linux_fd::fail_next_lock_after_rename();
    let mut dispatched = false;
    let result = operation
        .authorize_managed_start(&context, &nonce, &cancellation, deadline())
        .map(|()| {
            dispatched = true;
        });
    assert!(result.is_err());
    assert!(!dispatched);
    let path = operation.path.clone();
    assert!(
        Record::parse(&std::fs::read(path.join(FILE)).unwrap())
            .unwrap()
            .state
            == State::StartAuthorized
    );
    drop(operation);
    let report = super::super::recover(&store).unwrap();
    assert!(report.entries.iter().any(|entry| matches!(
        entry.state,
        crate::build::BuildRecoveryState::Retained(_)
    )));
    assert!(path.exists());
}

#[test]
fn recovery_closes_only_local_v4_awaiting_and_respects_live_owner() {
    for version in [3, 4] {
        let (_temporary, store, operation, context) = fixture();
        operation
            .prepare_managed(&context, &Cancellation::default(), deadline())
            .unwrap();
        let mut record = Record::parse(
            &read(&operation.directory, FILE, LIMIT)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        record.version = version;
        write(
            &operation.directory,
            FILE,
            &record.encode().unwrap(),
        )
        .unwrap();
        let path = operation.path.clone();
        let _ = super::super::recover(&store).unwrap();
        assert!(path.exists());
        drop(operation);
        let report = super::super::recover(&store).unwrap();
        assert_eq!(path.exists(), version == 3);
        assert!(
            report
                .entries
                .iter()
                .any(|entry| if version == 4 {
                    matches!(
                        entry.state,
                        crate::build::BuildRecoveryState::Recovered
                    )
                } else {
                    matches!(
                        entry.state,
                        crate::build::BuildRecoveryState::Retained(_)
                    )
                })
        );
    }
}

#[test]
fn local_abort_recovery_resumes_after_both_uncertain_durable_writes() {
    for already_aborted in [false, true] {
        let (_temporary, store, operation, context) = fixture();
        operation
            .prepare_managed(&context, &Cancellation::default(), deadline())
            .unwrap();
        if already_aborted {
            let mut record = Record::parse(
                &read(&operation.directory, FILE, LIMIT)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            record.state = State::LocalAborted;
            write(
                &operation.directory,
                FILE,
                &record.encode().unwrap(),
            )
            .unwrap();
        }
        let path = operation.path.clone();
        drop(operation);
        linux_fd::fail_next_lock_after_rename();
        let report = super::super::recover(&store).unwrap();
        assert!(report.entries.iter().any(|entry| matches!(
            entry.state,
            crate::build::BuildRecoveryState::Retained(_)
        )));
        assert!(path.exists());
        let report = super::super::recover(&store).unwrap();
        assert!(report.entries.iter().any(|entry| matches!(
            entry.state,
            crate::build::BuildRecoveryState::Recovered
        )));
        assert!(!path.exists());
    }
}

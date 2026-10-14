use super::*;
use std::fs;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::sync::{Arc, Barrier};
use std::time::Duration;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

#[test]
fn opening_existing_evidence_does_not_initialize_missing_authority() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(SessionJournal::open_existing(root.path()).is_err());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    let journal = SessionJournal::open(root.path()).unwrap();
    let pin = ContentDigest::sha256(b"existing");
    let id = journal
        .create(
            b"existing",
            pin,
            &Cancellation::default(),
            deadline(),
        )
        .unwrap();
    let reopened = SessionJournal::open_existing(root.path()).unwrap();
    assert_eq!(
        reopened
            .manifest(&id, &Cancellation::default(), deadline())
            .unwrap(),
        b"existing"
    );
}
fn binding(byte: u8) -> AttemptBinding {
    AttemptBinding::new(
        SystemdUnitName::new("syrox-session-owner.service").unwrap(),
        [byte; 16],
    )
    .unwrap()
}
fn fixture() -> (
    tempfile::TempDir,
    SessionJournal,
    SessionId,
    AttemptId,
    ContentDigest,
) {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal = SessionJournal::open(temp.path()).unwrap();
    let cancellation = Cancellation::default();
    let pin = ContentDigest::sha256(b"pinned launcher manifest");
    let session = journal
        .create(
            b"pinned launcher manifest",
            pin,
            &cancellation,
            deadline(),
        )
        .unwrap();
    let attempt = journal
        .prepare_attempt(&session, "owner", &cancellation, deadline())
        .unwrap();
    journal
        .authorize_attempt(
            &session,
            &attempt,
            &binding(1),
            &cancellation,
            deadline(),
        )
        .unwrap();
    (temp, journal, session, attempt, pin)
}

#[test]
fn identities_are_canonical_and_nonzero() {
    for text in [
        "",
        "ABCDEFABCDEFABCDEFABCDEFABCDEFABCD",
        "00000000000000000000000000000000",
        "../00000000000000000000000000001",
    ] {
        assert!(SessionId::parse(text).is_err());
        assert!(AttemptId::parse(text).is_err());
    }
    let id = SessionId::fresh().unwrap();
    assert_eq!(SessionId::parse(id.as_str()).unwrap(), id);
    assert_ne!(id, SessionId::fresh().unwrap());
    assert!(
        AttemptBinding::new(
            SystemdUnitName::new("syrox-owner.service").unwrap(),
            [0; 16]
        )
        .is_err()
    );
}

#[test]
fn attempt_consumption_is_durable_single_use_and_bound_to_manifest_and_invocation() {
    let (temp, journal, session, attempt, pin) = fixture();
    let cancellation = Cancellation::default();
    assert!(
        journal
            .consume_attempt(
                &session,
                &attempt,
                ContentDigest::sha256(b"other"),
                &binding(1),
                &cancellation,
                deadline()
            )
            .is_err()
    );
    assert!(
        journal
            .consume_attempt(
                &session,
                &attempt,
                pin,
                &binding(2),
                &cancellation,
                deadline()
            )
            .is_err()
    );
    journal
        .consume_attempt(
            &session,
            &attempt,
            pin,
            &binding(1),
            &cancellation,
            deadline(),
        )
        .unwrap();
    let state = journal
        .snapshot(&session, &cancellation, deadline())
        .unwrap();
    assert_eq!(state.pin, pin);
    let consumed = state
        .attempts
        .iter()
        .find(|entry| entry.id == attempt)
        .unwrap();
    assert_eq!(consumed.phase, AttemptPhase::Consumed);
    assert_eq!(consumed.binding.as_ref(), Some(&binding(1)));
    drop(journal);
    let journal = SessionJournal::open(temp.path()).unwrap();
    assert!(
        journal
            .consume_attempt(
                &session,
                &attempt,
                pin,
                &binding(1),
                &cancellation,
                deadline()
            )
            .is_err()
    );
    assert!(
        journal
            .prepare_attempt(&session, "owner", &cancellation, deadline())
            .is_err()
    );
    let state = journal
        .snapshot(&session, &cancellation, deadline())
        .unwrap();
    assert_eq!(state.attempts[0].phase, AttemptPhase::Consumed);
    assert_eq!(
        journal
            .manifest(&session, &cancellation, deadline())
            .unwrap(),
        b"pinned launcher manifest"
    );
}

#[test]
fn closing_revokes_unconsumed_attempts_and_preserves_admitted_evidence() {
    let (temp, journal, session, attempt, pin) = fixture();
    let cancellation = Cancellation::default();
    journal
        .consume_attempt(
            &session,
            &attempt,
            pin,
            &binding(1),
            &cancellation,
            deadline(),
        )
        .unwrap();
    let pending = journal
        .prepare_attempt(
            &session,
            "service:nginx:server",
            &cancellation,
            deadline(),
        )
        .unwrap();
    journal
        .authorize_attempt(
            &session,
            &pending,
            &binding(2),
            &cancellation,
            deadline(),
        )
        .unwrap();
    let state = journal
        .begin_closing(
            &session,
            "terminal closed",
            &cancellation,
            deadline(),
        )
        .unwrap();
    assert_eq!(state.phase, SessionPhase::Closing);
    assert_eq!(
        state
            .attempts
            .iter()
            .find(|entry| entry.id == attempt)
            .unwrap()
            .phase,
        AttemptPhase::Consumed
    );
    assert_eq!(
        state
            .attempts
            .iter()
            .find(|entry| entry.id == pending)
            .unwrap()
            .phase,
        AttemptPhase::Revoked
    );
    assert!(
        journal
            .consume_attempt(
                &session,
                &pending,
                pin,
                &binding(2),
                &cancellation,
                deadline()
            )
            .is_err()
    );
    assert!(
        journal
            .prepare_attempt(&session, "late", &cancellation, deadline())
            .is_err()
    );
    drop(journal);
    let journal = SessionJournal::open(temp.path()).unwrap();
    let recovered = journal
        .recover(&session, &cancellation, deadline())
        .unwrap();
    assert_eq!(recovered.phase, SessionPhase::Closing);
    assert_eq!(state.revision, recovered.revision);
    assert!(
        temp.path()
            .join(session.as_str())
            .join("manifest")
            .is_file()
    );
}

#[test]
fn competing_launchers_cannot_consume_the_same_attempt() {
    let (temp, _journal, session, attempt, pin) = fixture();
    let barrier = Arc::new(Barrier::new(3));
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..2 {
            let barrier = Arc::clone(&barrier);
            let journal = SessionJournal::open(temp.path()).unwrap();
            let session = session.clone();
            let attempt = attempt.clone();
            workers.push(scope.spawn(move || {
                barrier.wait();
                journal
                    .consume_attempt(
                        &session,
                        &attempt,
                        pin,
                        &binding(1),
                        &Cancellation::default(),
                        deadline(),
                    )
                    .is_ok()
            }));
        }
        barrier.wait();
        let successful = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|success| *success)
            .count();
        assert_eq!(successful, 1);
    });
    let state = SessionJournal::open(temp.path())
        .unwrap()
        .snapshot(&session, &Cancellation::default(), deadline())
        .unwrap();
    assert_eq!(state.attempts[0].phase, AttemptPhase::Consumed);
    assert_eq!(state.revision, 3);
}

#[test]
fn publication_failure_never_returns_an_admission_and_uncertainty_requires_reopen() {
    let (temp, journal, session, attempt, pin) = fixture();
    let cancellation = Cancellation::default();
    crate::platform::linux::fd::fail_next_lock_before_rename();
    assert!(
        journal
            .consume_attempt(
                &session,
                &attempt,
                pin,
                &binding(1),
                &cancellation,
                deadline()
            )
            .is_err()
    );
    assert_eq!(
        journal
            .snapshot(&session, &cancellation, deadline())
            .unwrap()
            .attempts[0]
            .phase,
        AttemptPhase::Authorized
    );
    crate::platform::linux::fd::fail_next_lock_after_rename();
    assert!(matches!(
        journal.consume_attempt(
            &session,
            &attempt,
            pin,
            &binding(1),
            &cancellation,
            deadline()
        ),
        Err(OwnershipError::Uncertain(_))
    ));
    assert!(matches!(
        journal.snapshot(&session, &cancellation, deadline()),
        Err(OwnershipError::Uncertain(_))
    ));
    let reopened = SessionJournal::open(temp.path()).unwrap();
    assert!(
        reopened
            .consume_attempt(
                &session,
                &attempt,
                pin,
                &binding(1),
                &cancellation,
                deadline()
            )
            .is_err()
    );
    let state = reopened
        .recover(&session, &cancellation, deadline())
        .unwrap();
    assert_eq!(state.phase, SessionPhase::Closing);
    assert_eq!(state.attempts[0].phase, AttemptPhase::Consumed);
}

#[test]
fn cancellation_and_lock_deadlines_leave_authorization_unchanged() {
    let (temp, journal, session, attempt, pin) = fixture();
    let cancelled = Cancellation::default();
    cancelled.cancel();
    assert!(matches!(
        journal.consume_attempt(
            &session,
            &attempt,
            pin,
            &binding(1),
            &cancelled,
            deadline()
        ),
        Err(OwnershipError::Cancelled)
    ));
    let lock = fs::File::open(temp.path().join("authority.lock")).unwrap();
    assert!(
        crate::platform::linux::fd::flock(
            lock.as_fd(),
            crate::platform::linux::fd::FlockMode::ExclusiveNonblocking
        )
        .unwrap()
    );
    assert!(matches!(
        journal.snapshot(
            &session,
            &Cancellation::default(),
            Instant::now() + Duration::from_millis(20)
        ),
        Err(OwnershipError::Deadline)
    ));
    drop(lock);
    assert_eq!(
        journal
            .snapshot(&session, &Cancellation::default(), deadline())
            .unwrap()
            .attempts[0]
            .phase,
        AttemptPhase::Authorized
    );
}

#[test]
fn tampered_manifest_links_modes_and_replaced_lock_are_refused() {
    let (temp, journal, session, attempt, pin) = fixture();
    let cancellation = Cancellation::default();
    let path = temp
        .path()
        .join(session.as_str())
        .join("manifest");
    fs::write(&path, b"changed bytes").unwrap();
    assert!(
        journal
            .consume_attempt(
                &session,
                &attempt,
                pin,
                &binding(1),
                &cancellation,
                deadline()
            )
            .is_err()
    );
    fs::write(&path, b"pinned launcher manifest").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        journal
            .snapshot(&session, &cancellation, deadline())
            .is_err()
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&path, temp.path().join("alias")).unwrap();
    assert!(
        journal
            .snapshot(&session, &cancellation, deadline())
            .is_err()
    );
    fs::remove_file(temp.path().join("alias")).unwrap();
    fs::remove_file(temp.path().join("authority.lock")).unwrap();
    symlink(&path, temp.path().join("authority.lock")).unwrap();
    assert!(
        journal
            .snapshot(&session, &cancellation, deadline())
            .is_err()
    );
}

#[test]
fn state_encoding_rejects_duplicates_unknown_fields_and_extra_bytes() {
    let (temp, journal, session, _attempt, _pin) = fixture();
    let path = temp.path().join(session.as_str()).join("state");
    let bytes = fs::read(&path).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    for changed in [
        format!("{text}\n"),
        text.replace("syrox-session-state-v2", "syrox-session-state-v1"),
        text.replace("\"revision\":2", "\"revision\":2,\"revision\":2"),
        text.replace("\"revision\":2", "\"unknown\":2,\"revision\":2"),
    ] {
        fs::write(&path, changed).unwrap();
        assert!(
            journal
                .snapshot(&session, &Cancellation::default(), deadline())
                .is_err()
        );
    }
    fs::write(path, bytes).unwrap();
    assert!(
        journal
            .snapshot(&session, &Cancellation::default(), deadline())
            .is_ok()
    );
}

#[test]
fn state_rejects_duplicate_roles_bindings_and_phase_contradictions() {
    let (temp, _journal, session, attempt, _) = fixture();
    let bytes = fs::read(temp.path().join(session.as_str()).join("state")).unwrap();
    let original = record::Record::parse(&bytes).unwrap();
    let mut changed = original.clone();
    changed.phase = SessionPhase::Pending;
    assert!(changed.encode().is_err());
    changed.phase = SessionPhase::Closing;
    assert!(changed.encode().is_err());
    let second_id = AttemptId::fresh().unwrap();
    let mut duplicate = original.attempts[attempt.as_str()].clone();
    changed = original.clone();
    duplicate.binding = Some((&binding(2)).into());
    changed
        .attempts
        .insert(second_id.to_string(), duplicate.clone());
    assert!(
        changed.encode().is_err(),
        "duplicate logical role"
    );
    duplicate.role = "other role".into();
    duplicate.binding = Some((&binding(1)).into());
    changed
        .attempts
        .insert(second_id.to_string(), duplicate.clone());
    assert!(
        changed.encode().is_err(),
        "duplicate manager invocation"
    );
    duplicate.binding = Some((&binding(2)).into());
    changed
        .attempts
        .insert(second_id.to_string(), duplicate);
    assert!(changed.encode().is_ok());
}

#[test]
fn registry_bound_preserves_incomplete_identities_and_refuses_new_creation() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal = SessionJournal::open(temp.path()).unwrap();
    for number in 1..=MAX_SESSIONS {
        fs::create_dir(temp.path().join(format!("{number:032x}"))).unwrap();
    }
    let cancellation = Cancellation::default();
    assert_eq!(
        journal
            .session_ids(&cancellation, deadline())
            .unwrap()
            .len(),
        MAX_SESSIONS
    );
    assert!(
        journal
            .create(
                b"manifest",
                ContentDigest::sha256(b"manifest"),
                &cancellation,
                deadline()
            )
            .is_err()
    );
    assert_eq!(
        journal
            .session_ids(&cancellation, deadline())
            .unwrap()
            .len(),
        MAX_SESSIONS
    );
    fs::create_dir(
        temp.path()
            .join(format!("{:032x}", MAX_SESSIONS + 1)),
    )
    .unwrap();
    assert!(
        journal
            .session_ids(&cancellation, deadline())
            .is_err()
    );
}

#[test]
fn waiting_lock_rechecks_ambiguous_publication_poison() {
    let (_temp, journal, _session, _attempt, _) = fixture();
    let cancellation = Cancellation::default();
    let authority = journal
        .storage
        .lock(&cancellation, deadline())
        .unwrap();
    std::thread::scope(|scope| {
        let waiting = scope.spawn(|| journal.storage.lock(&cancellation, deadline()));
        // The second check must reject both an already-waiting and a newly scheduled caller.
        journal.storage.mark_uncertain_for_test();
        drop(authority);
        assert!(matches!(
            waiting.join().unwrap(),
            Err(OwnershipError::Uncertain(_))
        ));
    });
}

#[test]
fn final_gate_requires_consumption_exact_pin_and_binding_and_never_reauthorizes() {
    let (temp, journal, session, attempt, pin) = fixture();
    let cancel = Cancellation::default();
    let calls = std::cell::Cell::new(0);
    let action = || {
        calls.set(calls.get() + 1);
        Ok(())
    };
    assert!(
        journal
            .with_consumed_attempt(
                &session,
                &attempt,
                pin,
                &binding(1),
                &cancel,
                deadline(),
                action
            )
            .is_err()
    );
    journal
        .consume_attempt(
            &session,
            &attempt,
            pin,
            &binding(1),
            &cancel,
            deadline(),
        )
        .unwrap();
    for (wrong_pin, wrong_binding) in [
        (ContentDigest::sha256(b"other"), binding(1)),
        (pin, binding(2)),
    ] {
        assert!(
            journal
                .with_consumed_attempt(
                    &session,
                    &attempt,
                    wrong_pin,
                    &wrong_binding,
                    &cancel,
                    deadline(),
                    action
                )
                .is_err()
        );
    }
    assert_eq!(calls.get(), 0);
    let error = journal
        .with_consumed_attempt(
            &session,
            &attempt,
            pin,
            &binding(1),
            &cancel,
            deadline(),
            || {
                calls.set(calls.get() + 1);
                Err::<(), _>(std::io::Error::other("ambiguous send"))
            },
        )
        .unwrap_err();
    assert!(matches!(error, OwnershipError::Io(_)));
    assert_eq!(calls.get(), 1);
    drop(journal);
    let journal = SessionJournal::open(temp.path()).unwrap();
    assert_eq!(
        journal
            .snapshot(&session, &cancel, deadline())
            .unwrap()
            .attempts[0]
            .phase,
        AttemptPhase::Consumed
    );
    assert!(
        journal
            .consume_attempt(
                &session,
                &attempt,
                pin,
                &binding(1),
                &cancel,
                deadline()
            )
            .is_err()
    );
    journal
        .begin_closing(&session, "ambiguous send", &cancel, deadline())
        .unwrap();
    assert!(
        journal
            .with_consumed_attempt(
                &session,
                &attempt,
                pin,
                &binding(1),
                &cancel,
                deadline(),
                action
            )
            .is_err()
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn final_gate_serializes_with_closing_and_returns_callback_value() {
    let (_temp, journal, session, attempt, pin) = fixture();
    let cancel = Cancellation::default();
    journal
        .consume_attempt(
            &session,
            &attempt,
            pin,
            &binding(1),
            &cancel,
            deadline(),
        )
        .unwrap();
    let journal = Arc::new(journal);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let gate_journal = Arc::clone(&journal);
    let gate_session = session.clone();
    let gate = std::thread::spawn(move || {
        gate_journal
            .with_consumed_attempt(
                &gate_session,
                &attempt,
                pin,
                &binding(1),
                &Cancellation::default(),
                deadline(),
                || {
                    entered_tx.send(()).unwrap();
                    release_rx
                        .recv_timeout(Duration::from_secs(2))
                        .unwrap();
                    Ok(42)
                },
            )
            .unwrap()
    });
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    // A competing revoker cannot cross the gate's critical section.
    assert!(matches!(
        journal.begin_closing(
            &session,
            "race",
            &cancel,
            Instant::now() + Duration::from_millis(30)
        ),
        Err(OwnershipError::Deadline)
    ));
    release_tx.send(()).unwrap();
    assert_eq!(gate.join().unwrap(), 42);
    assert_eq!(
        journal
            .begin_closing(&session, "after gate", &cancel, deadline())
            .unwrap()
            .phase,
        SessionPhase::Closing
    );
}

#[test]
fn full_length_service_process_role_roundtrips_and_oversize_is_rejected() {
    let (temp, journal, session, _, _) = fixture();
    let cancel = Cancellation::default();
    let role = format!("service:{}:{}", "s".repeat(128), "p".repeat(128));
    assert_eq!(role.len(), 265);
    journal
        .prepare_attempt(&session, &role, &cancel, deadline())
        .unwrap();
    assert!(
        journal
            .prepare_attempt(
                &session,
                &"x".repeat(ROLE_BYTES + 1),
                &cancel,
                deadline()
            )
            .is_err()
    );
    drop(journal);
    let journal = SessionJournal::open(temp.path()).unwrap();
    assert!(
        journal
            .snapshot(&session, &cancel, deadline())
            .unwrap()
            .attempts
            .iter()
            .any(|attempt| attempt.role == role)
    );
}

#[test]
fn final_gate_cancel_and_deadline_never_call_action() {
    let (_temp, journal, session, attempt, pin) = fixture();
    let cancel = Cancellation::default();
    journal
        .consume_attempt(
            &session,
            &attempt,
            pin,
            &binding(1),
            &cancel,
            deadline(),
        )
        .unwrap();
    let action = || -> std::io::Result<()> { panic!("cancelled gate must not run") };
    let cancelled = Cancellation::default();
    cancelled.cancel();
    assert!(matches!(
        journal.with_consumed_attempt(
            &session,
            &attempt,
            pin,
            &binding(1),
            &cancelled,
            deadline(),
            action
        ),
        Err(OwnershipError::Cancelled)
    ));
    assert!(matches!(
        journal.with_consumed_attempt(
            &session,
            &attempt,
            pin,
            &binding(1),
            &cancel,
            Instant::now(),
            action
        ),
        Err(OwnershipError::Deadline)
    ));
}

#[test]
fn manifest_above_state_limit_roundtrips_without_expanding_metadata_bound() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal = SessionJournal::open(temp.path()).unwrap();
    let bytes = vec![b'x'; record::MAX_BYTES + 1];
    let pin = ContentDigest::sha256(&bytes);
    validate_manifest(&bytes, pin).unwrap();
    let cancel = Cancellation::default();
    let id = journal
        .create(&bytes, pin, &cancel, deadline())
        .unwrap();
    drop(journal);
    let journal = SessionJournal::open(temp.path()).unwrap();
    assert_eq!(
        journal
            .manifest(&id, &cancel, deadline())
            .unwrap(),
        bytes
    );
    let directory = journal.storage.directory(&id).unwrap();
    let state_before = fs::read(temp.path().join(id.as_str()).join("state")).unwrap();
    assert!(
        journal
            .storage
            .write(directory.fd(), "state", &bytes)
            .is_err()
    );
    assert_eq!(
        fs::read(temp.path().join(id.as_str()).join("state")).unwrap(),
        state_before
    );
    assert!(record::Record::parse(&bytes).is_err());
    assert!(
        journal
            .storage
            .write(directory.fd(), "unknown", b"bytes")
            .is_err()
    );
}

#[test]
fn manifest_preflight_and_sparse_files_enforce_separate_bounds_before_read_allocation() {
    assert_eq!(record::MAX_BYTES, 1024 * 1024);
    assert!(validate_manifest_size(0).is_err());
    assert!(validate_manifest_size(MAX_SESSION_MANIFEST_BYTES).is_ok());
    assert!(validate_manifest_size(MAX_SESSION_MANIFEST_BYTES + 1).is_err());
    assert!(validate_manifest(b"manifest", ContentDigest::sha256(b"wrong")).is_err());
    let (temp, journal, session, _, _) = fixture();
    let directory = journal.storage.directory(&session).unwrap();
    for (name, limit) in [
        ("manifest", MAX_SESSION_MANIFEST_BYTES),
        ("state", record::MAX_BYTES),
    ] {
        let path = temp.path().join(session.as_str()).join(name);
        // Sparse lengths exercise fstat preflight without writing giant files.
        let file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap();
        file.set_len((limit + 1) as u64).unwrap();
        assert!(matches!(
            storage::Storage::read(directory.fd(), name),
            Err(OwnershipError::Invalid("session file too large"))
        ));
    }
}

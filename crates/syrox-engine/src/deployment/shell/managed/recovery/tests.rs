use super::*;
use crate::execution::journal::AttemptBinding;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::rc::Rc;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn manifest() -> Vec<u8> {
    let snapshot = format!(
        concat!(
            "syrox-shell-session-v2\n",
            "{{\"launcher\":{{\"digest\":\"{}\",\"protocol\":1}},\"outputs\":{{}},\"provenance\":{{}},\"services\":[],\"selections\":[],\"commands\":{{}},\"exposures\":{{}},\"configs\":{{}},\"processes\":{{}}}}"
        ),
        ContentDigest::sha256(b"candidate")
    );
    super::super::record::encode(
        &boot(),
        snapshot.as_bytes(),
        Path::new("/retained/configuration"),
        Path::new("/work"),
    )
    .unwrap()
}
pub(super) fn fixture() -> (tempfile::TempDir, SessionJournal, SessionId) {
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let journal = SessionJournal::open(root.path()).unwrap();
    let bytes = manifest();
    let session = journal
        .create(
            &bytes,
            ContentDigest::sha256(&bytes),
            &Cancellation::default(),
            deadline(),
        )
        .unwrap();
    (root, journal, session)
}
fn add(journal: &SessionJournal, session: &SessionId, role: &str, byte: u8) -> AttemptBinding {
    let cancellation = Cancellation::default();
    let attempt = journal
        .prepare_attempt(session, role, &cancellation, deadline())
        .unwrap();
    let binding = AttemptBinding::new(
        SystemdUnitName::new(format!("syrox-{role}.service")).unwrap(),
        [byte; 16],
    )
    .unwrap();
    journal
        .authorize_attempt(
            session,
            &attempt,
            &binding,
            &cancellation,
            deadline(),
        )
        .unwrap();
    binding
}
fn status(binding: &AttemptBinding) -> SystemdUnitStatus {
    SystemdUnitStatus {
        unit: binding.unit().clone(),
        invocation: binding.invocation().to_vec(),
        active_state: "active".into(),
        sub_state: "running".into(),
        control_group: String::new(),
        result: String::new(),
        main_pid: 123,
        exec_main_code: 0,
        exec_main_status: 0,
    }
}
struct Fake<'a> {
    journal: &'a SessionJournal,
    session: &'a SessionId,
    states: BTreeMap<String, Option<SystemdUnitStatus>>,
    calls: Rc<RefCell<Vec<String>>>,
    lose_stop: Option<String>,
    cancel_after_query: bool,
}
impl Manager for Fake<'_> {
    type Job = String;
    fn query(
        &mut self,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<Option<SystemdUnitStatus>, SystemdError> {
        assert!(timeout <= CALL_BUDGET);
        assert_eq!(
            self.journal
                .snapshot(self.session, &Cancellation::default(), deadline())
                .unwrap()
                .phase,
            SessionPhase::Closing
        );
        self.calls
            .borrow_mut()
            .push(format!("query:{}", unit.as_str()));
        if self.cancel_after_query {
            cancellation.cancel();
        }
        Ok(self
            .states
            .remove(unit.as_str())
            .expect("unexpected query"))
    }
    fn stop(
        &mut self,
        unit: &SystemdUnitName,
        _: Duration,
        _: &Cancellation,
    ) -> Result<String, SystemdError> {
        assert_eq!(
            self.journal
                .snapshot(self.session, &Cancellation::default(), deadline())
                .unwrap()
                .phase,
            SessionPhase::Closing
        );
        self.calls
            .borrow_mut()
            .push(format!("stop:{}", unit.as_str()));
        if self.lose_stop.as_deref() == Some(unit.as_str()) {
            return Err(SystemdError::MutationUncertain {
                unit: unit.as_str().to_owned(),
                source: Box::new(SystemdError::Deadline),
            });
        }
        Ok(unit.as_str().to_owned())
    }
    fn wait(
        &mut self,
        job: &String,
        _: Duration,
        _: &Cancellation,
    ) -> Result<SystemdJobCompletion, SystemdError> {
        self.calls
            .borrow_mut()
            .push(format!("wait:{job}"));
        Ok(SystemdJobCompletion::Observed {
            result: SystemdJobResult::Done,
        })
    }
}

#[test]
fn closing_precedes_connection_and_stops_only_matching_bindings() {
    let (_root, journal, session) = fixture();
    let same = add(&journal, &session, "same", 1);
    let different = add(&journal, &session, "different", 2);
    let absent = add(&journal, &session, "absent", 3);
    journal
        .prepare_attempt(
            &session,
            "unbound",
            &Cancellation::default(),
            deadline(),
        )
        .unwrap();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let mut replaced = status(&different);
    replaced.invocation = vec![9; 16];
    let (report, _) = recover_with(
        &journal,
        &session,
        &boot(),
        &Cancellation::default(),
        deadline(),
        |_| {
            assert_eq!(
                journal
                    .snapshot(&session, &Cancellation::default(), deadline())
                    .unwrap()
                    .phase,
                SessionPhase::Closing
            );
            Ok(Fake {
                journal: &journal,
                session: &session,
                calls: Rc::clone(&calls),
                states: [
                    (
                        same.unit().as_str().to_owned(),
                        Some(status(&same)),
                    ),
                    (
                        different.unit().as_str().to_owned(),
                        Some(replaced),
                    ),
                    (absent.unit().as_str().to_owned(), None),
                ]
                .into(),
                lose_stop: None,
                cancel_after_query: false,
            })
        },
    )
    .unwrap();
    let outcomes = report
        .attempts
        .iter()
        .map(|attempt| (attempt.role.as_str(), &attempt.outcome))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        outcomes["same"],
        &AttemptRecoveryOutcome::ObservedStop
    );
    assert_eq!(
        outcomes["different"],
        &AttemptRecoveryOutcome::Conflict
    );
    assert_eq!(
        outcomes["absent"],
        &AttemptRecoveryOutcome::Absent
    );
    assert_eq!(
        outcomes["unbound"],
        &AttemptRecoveryOutcome::Unbound
    );
    assert_eq!(
        calls
            .borrow()
            .iter()
            .filter(|call| call.starts_with("stop:"))
            .count(),
        1
    );
    assert!(report.needs_reconciliation);
    assert_eq!(
        report.configuration_hint,
        Path::new("/retained/configuration")
    );
}

#[test]
fn uncertain_stop_is_not_retried_and_other_attempts_are_examined() {
    let (_root, journal, session) = fixture();
    let first = add(&journal, &session, "lost", 1);
    let second = add(&journal, &session, "other", 2);
    let calls = Rc::new(RefCell::new(Vec::new()));
    let (report, _) = recover_with(
        &journal,
        &session,
        &boot(),
        &Cancellation::default(),
        deadline(),
        |_| {
            Ok(Fake {
                journal: &journal,
                session: &session,
                calls: Rc::clone(&calls),
                states: [
                    (
                        first.unit().as_str().to_owned(),
                        Some(status(&first)),
                    ),
                    (
                        second.unit().as_str().to_owned(),
                        Some(status(&second)),
                    ),
                ]
                .into(),
                lose_stop: Some(first.unit().as_str().to_owned()),
                cancel_after_query: false,
            })
        },
    )
    .unwrap();
    assert!(
        report
            .attempts
            .iter()
            .any(|attempt| attempt.role == "lost"
                && matches!(
                    attempt.outcome,
                    AttemptRecoveryOutcome::Failed {
                        stage: RecoveryStage::Stop,
                        ..
                    }
                ))
    );
    assert!(
        report
            .attempts
            .iter()
            .any(|attempt| attempt.role == "other"
                && attempt.outcome == AttemptRecoveryOutcome::ObservedStop)
    );
    assert_eq!(
        calls
            .borrow()
            .iter()
            .filter(|call| *call == &format!("stop:{}", first.unit().as_str()))
            .count(),
        1
    );
    assert!(
        !calls
            .borrow()
            .contains(&format!("wait:{}", first.unit().as_str()))
    );
}

#[test]
fn cancellation_after_query_marks_remaining_attempts_without_more_manager_io() {
    let (_root, journal, session) = fixture();
    let first = add(&journal, &session, "first", 1);
    let second = add(&journal, &session, "second", 2);
    let calls = Rc::new(RefCell::new(Vec::new()));
    let (report, evidence) = recover_with(
        &journal,
        &session,
        &boot(),
        &Cancellation::default(),
        deadline(),
        |_| {
            Ok(Fake {
                journal: &journal,
                session: &session,
                calls: Rc::clone(&calls),
                states: [
                    (
                        first.unit().as_str().to_owned(),
                        Some(status(&first)),
                    ),
                    (
                        second.unit().as_str().to_owned(),
                        Some(status(&second)),
                    ),
                ]
                .into(),
                lose_stop: None,
                cancel_after_query: true,
            })
        },
    )
    .unwrap();
    assert_eq!(calls.borrow().len(), 1);
    // Cancellation must not discard the authenticated Closing inventory needed
    // to reconcile every process later, including the unqueried attempt.
    assert_eq!(evidence.phase, SessionPhase::Closing);
    assert_eq!(evidence.attempts.len(), 2);
    for binding in [&first, &second] {
        assert!(
            evidence
                .attempts
                .iter()
                .any(|attempt| attempt.binding.as_ref() == Some(binding))
        );
    }
    assert!(report.attempts.iter().all(|attempt| matches!(
        attempt.outcome,
        AttemptRecoveryOutcome::Failed {
            stage: RecoveryStage::Budget,
            ..
        }
    )));
}

#[test]
fn invalid_record_does_not_close_or_contact_manager() {
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let journal = SessionJournal::open(root.path()).unwrap();
    let session = journal
        .create(
            b"wrong-domain",
            ContentDigest::sha256(b"wrong-domain"),
            &Cancellation::default(),
            deadline(),
        )
        .unwrap();
    let result = recover_with::<Fake<'_>>(
        &journal,
        &session,
        &boot(),
        &Cancellation::default(),
        deadline(),
        |_| panic!("invalid record must not contact manager"),
    );
    assert!(matches!(result, Err(RecoveryError::Record(_))));
    assert_eq!(
        journal
            .snapshot(&session, &Cancellation::default(), deadline())
            .unwrap()
            .phase,
        SessionPhase::Pending
    );
}

#[test]
fn failed_connection_is_reported_for_each_binding_after_durable_revocation() {
    let (_root, journal, session) = fixture();
    add(&journal, &session, "first", 1);
    add(&journal, &session, "second", 2);
    let (report, _) = recover_with::<Fake<'_>>(
        &journal,
        &session,
        &boot(),
        &Cancellation::default(),
        deadline(),
        |_| Err(SystemdError::Deadline),
    )
    .unwrap();
    assert_eq!(report.attempts.len(), 2);
    assert!(report.attempts.iter().all(|attempt| matches!(
        attempt.outcome,
        AttemptRecoveryOutcome::Failed {
            stage: RecoveryStage::Connection,
            ..
        }
    )));
    assert!(report.needs_reconciliation);
    assert_eq!(
        journal
            .snapshot(&session, &Cancellation::default(), deadline())
            .unwrap()
            .phase,
        SessionPhase::Closing
    );
}

#[test]
fn expired_budget_performs_no_manager_io_and_diagnostics_are_bounded() {
    let (_root, journal, session) = fixture();
    add(&journal, &session, "one", 1);
    let snapshot = journal
        .recover(&session, &Cancellation::default(), deadline())
        .unwrap();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let mut manager = Fake {
        journal: &journal,
        session: &session,
        states: BTreeMap::new(),
        calls: Rc::clone(&calls),
        lose_stop: None,
        cancel_after_query: false,
    };
    let outcome = recover_attempt(
        &mut manager,
        &snapshot.attempts[0],
        &Cancellation::default(),
        Instant::now(),
    );
    assert!(matches!(
        outcome,
        AttemptRecoveryOutcome::Failed {
            stage: RecoveryStage::Budget,
            ..
        }
    ));
    assert!(calls.borrow().is_empty());
    assert_eq!(
        diagnostic(&"é".repeat(2048)).chars().count(),
        MAX_DIAGNOSTIC_CHARACTERS
    );
}

#[test]
fn malformed_record_diagnostics_do_not_quote_configuration_content() {
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let journal = SessionJournal::open(root.path()).unwrap();
    let bytes = b"syrox-shell-operation-v2\n{\"version\":\"PRIVATE_CONFIGURATION_TEXT\",\"configuration\":\"/private/config\",\"cwd\":\"/work\"}\ninvalid-snapshot";
    let session = journal
        .create(
            bytes,
            ContentDigest::sha256(bytes),
            &Cancellation::default(),
            deadline(),
        )
        .unwrap();
    let error = recover_with::<Fake<'_>>(
        &journal,
        &session,
        &boot(),
        &Cancellation::default(),
        deadline(),
        |_| panic!("malformed evidence cannot contact manager"),
    )
    .unwrap_err();
    assert!(
        !error
            .to_string()
            .contains("PRIVATE_CONFIGURATION_TEXT")
    );
    assert!(error.to_string().contains("metadata encoding"));
}

fn boot() -> BootId {
    BootId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap()
}

#[test]
fn another_boot_preserves_evidence_and_never_contacts_manager() {
    let (_root, journal, session) = fixture();
    let binding = add(&journal, &session, "same-name", 1);
    let cancel = Cancellation::default();
    let before = journal
        .snapshot(&session, &cancel, deadline())
        .unwrap();
    let next_boot = BootId::parse("11234567-89ab-cdef-0123-456789abcdef").unwrap();
    let result = recover_with::<Fake<'_>>(
        &journal,
        &session,
        &next_boot,
        &cancel,
        deadline(),
        |_| panic!("old boot bindings must never reach this manager"),
    );
    assert!(matches!(result, Err(RecoveryError::PreviousBoot)));
    let after = journal
        .snapshot(&session, &cancel, deadline())
        .unwrap();
    assert_eq!(before.phase, after.phase);
    assert_eq!(before.pin, after.pin);
    assert_eq!(after.attempts.len(), 1);
    assert_eq!(after.attempts[0].binding.as_ref(), Some(&binding));
}

#[test]
fn legacy_record_is_preserved_without_migration_or_manager_effects() {
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let journal = SessionJournal::open(root.path()).unwrap();
    let legacy = String::from_utf8(manifest())
        .unwrap()
        .replace(
            "syrox-shell-operation-v2",
            "syrox-shell-operation-v1",
        )
        .replacen("\"version\":2", "\"version\":1", 1)
        .replace(&format!("\"boot\":\"{}\",", boot().as_str()), "");
    let cancel = Cancellation::default();
    let session = journal
        .create(
            legacy.as_bytes(),
            ContentDigest::sha256(legacy.as_bytes()),
            &cancel,
            deadline(),
        )
        .unwrap();
    let result = recover_with::<Fake<'_>>(
        &journal,
        &session,
        &boot(),
        &cancel,
        deadline(),
        |_| panic!("legacy evidence cannot authorize manager effects"),
    );
    assert!(matches!(result, Err(RecoveryError::Record(_))));
    let (state, bytes) = journal
        .snapshot_with_manifest(&session, &cancel, deadline())
        .unwrap();
    assert_eq!(state.phase, SessionPhase::Pending);
    assert_eq!(bytes, legacy.as_bytes());
    assert_eq!(
        state.pin,
        ContentDigest::sha256(legacy.as_bytes())
    );
}

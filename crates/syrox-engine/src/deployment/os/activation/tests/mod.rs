use super::*;
use crate::deployment::os::installation::GenerationInstallation;
use crate::platform::linux::boot::BootId;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn context() -> crate::deployment::os::launch_binding::OsLaunchContext {
    crate::deployment::os::launch_binding::OsLaunchContext::new(
        crate::systemd::SystemdScope::User {
            bus_socket: "/run/user/1000/bus".into(),
        },
        "/private/store".into(),
        "/private/units/syrox-os-test.service".into(),
        1000,
        1000,
        Duration::from_secs(30),
        Duration::from_secs(5),
    )
    .unwrap()
}
fn epoch() -> ExecutionEpoch {
    ExecutionEpoch {
        boot: BootId::parse("11111111-1111-1111-1111-111111111111").unwrap(),
        manager: "authenticated-manager-1".into(),
        scope: context().scope_key(),
    }
}
fn pin(bytes: &[u8]) -> ContentDigest {
    ContentDigest::sha256(bytes)
}
fn fixture() -> (tempfile::TempDir, ActivationJournal, String) {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let cancel = Cancellation::default();
    GenerationInstallation::initialize(temp.path(), &cancel, deadline()).unwrap();
    let journal = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
    let operation = journal
        .begin_pin(
            pin(b"generation"),
            None,
            epoch(),
            &cancel,
            deadline(),
        )
        .unwrap();
    (temp, journal, operation)
}
impl ActivationJournal {
    fn binding_input(&self) -> crate::deployment::os::launch_binding::LaunchBindingInput {
        crate::deployment::os::launch_binding::LaunchBindingInput {
            installation: self.installation.clone(),
            generation: pin(b"generation"),
            service: "test".into(),
            process: "server".into(),
            command: "run".into(),
            unit: unit(),
            launcher: crate::deployment::os::LauncherIdentity::new(pin(b"launcher"), 1).unwrap(),
            spec: pin(b"spec"),
            epoch: epoch(),
            context: context(),
            configuration: "/private/installation/config/test".into(),
            cwd: "/project".into(),
        }
    }
    fn binding(&self) -> OsLaunchBinding {
        OsLaunchBinding::new(self.binding_input()).unwrap()
    }
    fn binding_pin(&self) -> ContentDigest {
        self.binding().digest().unwrap()
    }
}
fn publish(journal: &ActivationJournal, operation: &str) -> String {
    let cancel = Cancellation::default();
    let effect = journal
        .plan_effect(
            operation,
            "test/server",
            EffectKind::Publish,
            None,
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    journal
        .record_observed(
            operation,
            &effect,
            journal.binding_pin(),
            None,
            &cancel,
            deadline(),
        )
        .unwrap();
    journal
        .authorize_binding(
            operation,
            &effect,
            &journal.binding(),
            &cancel,
            deadline(),
        )
        .unwrap();
    effect
}
fn unit() -> SystemdUnitName {
    SystemdUnitName::new("syrox-os-test.service").unwrap()
}
fn admit(journal: &ActivationJournal, invocation: &str) -> Result<StartAdmission> {
    journal.admit_start(
        "test/server",
        journal.binding_pin(),
        &unit(),
        invocation,
        &epoch(),
        &Cancellation::default(),
        deadline(),
    )
}

#[test]
fn compare_and_swap_preserves_selection_and_rejects_superseded_operations() {
    let (_temp, journal, first) = fixture();
    let cancel = Cancellation::default();
    assert!(
        journal
            .begin_pin(pin(b"other"), None, epoch(), &cancel, deadline())
            .is_err()
    );
    let second = journal
        .begin_pin(
            pin(b"generation"),
            Some(pin(b"generation")),
            epoch(),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert_ne!(first, second);
    assert!(
        journal
            .plan_effect(
                &first,
                "file",
                EffectKind::Publish,
                None,
                pin(b"file"),
                &cancel,
                deadline()
            )
            .is_err()
    );
    assert_eq!(
        journal
            .snapshot(&cancel, deadline())
            .unwrap()
            .active_operation
            .as_deref(),
        Some(second.as_str())
    );
}

#[derive(Default)]
struct FakeManager {
    starts: usize,
    stops: usize,
}
impl FakeManager {
    fn start_losing_reply(&mut self) -> io::Result<()> {
        self.starts += 1;
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "reply lost after start",
        ))
    }
}
#[test]
fn uncertain_manager_effect_is_not_resubmitted_after_client_disappears() {
    let (temp, journal, operation) = fixture();
    publish(&journal, &operation);
    let cancel = Cancellation::default();
    let effect = journal
        .plan_effect(
            &operation,
            "test/server",
            EffectKind::Start,
            None,
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    let mut manager = FakeManager::default();
    assert!(manager.start_losing_reply().is_err());
    journal
        .record_unknown(&operation, &effect, &cancel, deadline())
        .unwrap();
    drop(journal);
    let journal = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
    assert!(
        journal
            .record_accepted(&operation, &effect, "/job/1", &cancel, deadline())
            .is_err()
    );
    assert!(
        journal
            .plan_effect(
                &operation,
                "test/server",
                EffectKind::Start,
                None,
                journal.binding_pin(),
                &cancel,
                deadline()
            )
            .is_err()
    );
    assert!(
        journal
            .begin_pin(
                pin(b"next"),
                Some(pin(b"generation")),
                epoch(),
                &cancel,
                deadline()
            )
            .is_err()
    );
    journal
        .record_observed(
            &operation,
            &effect,
            journal.binding_pin(),
            Some("22222222222222222222222222222222"),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert_eq!(manager.starts, 1);
    assert_eq!(manager.stops, 0);
    assert!(
        journal
            .snapshot(&cancel, deadline())
            .unwrap()
            .bindings["test/server"]
            .authorized
    );
}

#[test]
fn binding_requires_publication_and_matching_epoch_and_unit() {
    let (_temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    let effect = journal
        .plan_effect(
            &operation,
            "test/server",
            EffectKind::Publish,
            None,
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        journal
            .authorize_binding(
                &operation,
                &effect,
                &journal.binding(),
                &cancel,
                deadline()
            )
            .is_err()
    );
    journal
        .record_observed(
            &operation,
            &effect,
            journal.binding_pin(),
            None,
            &cancel,
            deadline(),
        )
        .unwrap();
    journal
        .authorize_binding(
            &operation,
            &effect,
            &journal.binding(),
            &cancel,
            deadline(),
        )
        .unwrap();
    let mut changed = epoch();
    changed.boot = BootId::parse("22222222-2222-2222-2222-222222222222").unwrap();
    assert!(
        journal
            .admit_start(
                "test/server",
                journal.binding_pin(),
                &unit(),
                "11111111111111111111111111111111",
                &changed,
                &cancel,
                deadline()
            )
            .is_err()
    );
    changed = epoch();
    changed.manager = "new-manager".into();
    assert!(
        journal
            .admit_start(
                "test/server",
                journal.binding_pin(),
                &unit(),
                "11111111111111111111111111111111",
                &changed,
                &cancel,
                deadline()
            )
            .is_err()
    );
    assert!(
        journal
            .admit_start(
                "test/server",
                journal.binding_pin(),
                &SystemdUnitName::new("syrox-foreign.service").unwrap(),
                "11111111111111111111111111111111",
                &epoch(),
                &cancel,
                deadline()
            )
            .is_err()
    );
}

#[test]
fn revoked_and_reauthorized_same_bytes_never_resurrect_old_admission() {
    let (_temp, journal, operation) = fixture();
    let publication = publish(&journal, &operation);
    let old = admit(&journal, "11111111111111111111111111111111").unwrap();
    let cancel = Cancellation::default();
    journal
        .revoke_binding(
            "test/server",
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        admit(&journal, "22222222222222222222222222222222"),
        Err(ActivationError::StartDenied(_))
    ));
    journal
        .authorize_binding(
            &operation,
            &publication,
            &journal.binding(),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        journal.with_consumed_start(old, &cancel, deadline(), || -> io::Result<()> {
            panic!("revoked authorization reached gate")
        }),
        Err(ActivationError::StartDenied(_))
    ));
    assert!(admit(&journal, "11111111111111111111111111111111").is_err());
    let new = admit(&journal, "22222222222222222222222222222222").unwrap();
    assert!(
        journal
            .with_consumed_start(new, &cancel, deadline(), || Err::<(), _>(
                io::Error::other("ambiguous gate write")
            ))
            .is_err()
    );
    assert!(matches!(
        admit(&journal, "22222222222222222222222222222222"),
        Err(ActivationError::StartDenied(_))
    ));
    let state = journal.snapshot(&cancel, deadline()).unwrap();
    assert_eq!(
        state
            .attempts
            .values()
            .filter(|attempt| attempt.gate_used)
            .count(),
        1
    );
}

#[test]
fn gate_and_revocation_share_exclusive_authority() {
    let (temp, journal, operation) = fixture();
    publish(&journal, &operation);
    let admission = admit(&journal, "11111111111111111111111111111111").unwrap();
    let cancel = Cancellation::default();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        journal.with_consumed_start(admission, &cancel, deadline(), || {
            entered_tx.send(()).unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            Ok(())
        })
    });
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    let cancel = Cancellation::default();
    // Opening another handle also waits for the same lock and obeys its deadline.
    assert!(
        ActivationJournal::open_existing(
            temp.path(),
            &cancel,
            Instant::now() + Duration::from_millis(30)
        )
        .is_err()
    );
    release_tx.send(()).unwrap();
    worker.join().unwrap().unwrap();
    let journal = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
    journal
        .revoke_binding(
            "test/server",
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(admit(&journal, "22222222222222222222222222222222").is_err());
}

#[test]
fn malformed_oversized_and_foreign_state_are_refused_without_rewriting() {
    let (temp, journal, _) = fixture();
    let cancel = Cancellation::default();
    let original = fs::read(temp.path().join("activation")).unwrap();
    let mut state = journal.snapshot(&cancel, deadline()).unwrap();
    state.installation = "22222222222222222222222222222222".into();
    fs::write(
        temp.path().join("activation"),
        state.bytes().unwrap(),
    )
    .unwrap();
    assert!(journal.snapshot(&cancel, deadline()).is_err());
    let file = fs::OpenOptions::new()
        .write(true)
        .open(temp.path().join("activation"))
        .unwrap();
    file.set_len((MAX_STATE_BYTES + 1) as u64)
        .unwrap();
    assert!(journal.snapshot(&cancel, deadline()).is_err());
    fs::write(temp.path().join("activation"), &original).unwrap();
    let mut noncanonical = original.clone();
    noncanonical.push(b'\n');
    assert!(ActivationSnapshot::parse(&noncanonical, &journal.installation).is_err());
    assert!(
        ActivationSnapshot::parse(
            &original[..original.len() - 1],
            &journal.installation
        )
        .is_err()
    );
    assert_eq!(
        fs::read(temp.path().join("activation")).unwrap(),
        original
    );
}

#[test]
fn cancellation_and_failed_publication_do_not_authorize_gate() {
    let (temp, journal, operation) = fixture();
    publish(&journal, &operation);
    let admission = admit(&journal, "11111111111111111111111111111111").unwrap();
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(
        journal
            .with_consumed_start(
                admission,
                &cancel,
                deadline(),
                || -> io::Result<()> { panic!("cancelled gate") }
            )
            .is_err()
    );
    let cancel = Cancellation::default();
    let admission = admit(&journal, "22222222222222222222222222222222").unwrap();
    crate::platform::linux::fd::fail_next_lock_after_rename();
    assert!(
        journal
            .with_consumed_start(
                admission,
                &cancel,
                deadline(),
                || -> io::Result<()> { panic!("uncertain persistence gate") }
            )
            .is_err()
    );
    assert!(journal.snapshot(&cancel, deadline()).is_err());
    let reopened = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
    assert!(admit(&reopened, "22222222222222222222222222222222").is_err());
}

#[test]
fn scope_is_permanent_and_failed_change_preserves_exact_record() {
    let (temp, journal, _) = fixture();
    let original = fs::read(temp.path().join("activation")).unwrap();
    let mut other_scope = epoch();
    other_scope.scope = "uid=2000;user-bus=/run/user/2000/bus".into();
    assert!(
        journal
            .begin_pin(
                pin(b"next"),
                Some(pin(b"generation")),
                other_scope,
                &Cancellation::default(),
                deadline()
            )
            .is_err()
    );
    assert_eq!(
        fs::read(temp.path().join("activation")).unwrap(),
        original
    );
}

#[test]
fn accepted_job_is_preserved_and_observation_cannot_change_confirmed_identity() {
    let (temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    let effect = journal
        .plan_effect(
            &operation,
            "test/server",
            EffectKind::Start,
            None,
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    journal
        .record_accepted(
            &operation,
            &effect,
            "/org/freedesktop/systemd1/job/42",
            &cancel,
            deadline(),
        )
        .unwrap();
    drop(journal);
    let journal = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
    assert!(
        matches!(&journal.snapshot(&cancel, deadline()).unwrap().operations[&operation].effects[&effect].state, EffectState::Accepted { job } if job.ends_with("/42"))
    );
    assert!(
        journal
            .record_observed(
                &operation,
                &effect,
                journal.binding_pin(),
                None,
                &cancel,
                deadline()
            )
            .is_err()
    );
    journal
        .record_observed(
            &operation,
            &effect,
            journal.binding_pin(),
            Some("11111111111111111111111111111111"),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        journal
            .record_observed(
                &operation,
                &effect,
                journal.binding_pin(),
                Some("22222222222222222222222222222222"),
                &cancel,
                deadline()
            )
            .is_err()
    );
    assert!(
        journal
            .record_unknown(&operation, &effect, &cancel, deadline())
            .is_err()
    );
}

#[test]
fn operation_registry_is_bounded_without_erasing_history() {
    let (temp, journal, operation) = fixture();
    let original = fs::read(temp.path().join("activation")).unwrap();
    let mut state = journal
        .snapshot(&Cancellation::default(), deadline())
        .unwrap();
    let entry = state.operations[&operation].clone();
    for index in 1..=record::MAX_OPERATIONS {
        state
            .operations
            .insert(format!("{index:032x}"), entry.clone());
    }
    assert!(state.bytes().is_err());
    assert_eq!(
        fs::read(temp.path().join("activation")).unwrap(),
        original
    );
}

#[test]
fn authorization_joins_typed_binding_to_operation_and_publication() {
    use crate::deployment::os::launch_binding::LaunchBindingInput;
    let mismatches: [fn(&mut LaunchBindingInput); 7] = [
        |input| input.installation = "22222222222222222222222222222222".into(),
        |input| input.generation = pin(b"other generation"),
        |input| input.process = "other".into(),
        |input| input.service = "other".into(),
        |input| input.epoch.manager = "other manager".into(),
        |input| input.epoch.boot = BootId::parse("22222222-2222-2222-2222-222222222222").unwrap(),
        |input| {
            input.context = crate::deployment::os::launch_binding::OsLaunchContext::new(
                crate::systemd::SystemdScope::User {
                    bus_socket: "/run/user/2000/bus".into(),
                },
                "/private/store".into(),
                "/private/units/syrox-os-test.service".into(),
                2000,
                2000,
                Duration::from_secs(30),
                Duration::from_secs(5),
            )
            .unwrap();
            input.epoch.scope = input.context.scope_key();
        },
    ];
    for change in mismatches {
        let (_temp, journal, operation) = fixture();
        let cancel = Cancellation::default();
        let mut input = journal.binding_input();
        change(&mut input);
        let binding = OsLaunchBinding::new(input).unwrap();
        let target = binding.digest().unwrap();
        let effect = journal
            .plan_effect(
                &operation,
                "test/server",
                EffectKind::Publish,
                None,
                target,
                &cancel,
                deadline(),
            )
            .unwrap();
        journal
            .record_observed(
                &operation,
                &effect,
                target,
                None,
                &cancel,
                deadline(),
            )
            .unwrap();
        assert!(
            journal
                .authorize_binding(&operation, &effect, &binding, &cancel, deadline())
                .is_err()
        );
        assert!(
            journal
                .snapshot(&cancel, deadline())
                .unwrap()
                .bindings
                .is_empty()
        );
    }
}

#[test]
fn confirmed_different_file_fingerprint_cannot_authorize_a_binding() {
    let (_temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    let target = pin(b"systemd unit file is not the launch binding");
    let effect = journal
        .plan_effect(
            &operation,
            "test/server",
            EffectKind::Publish,
            None,
            target,
            &cancel,
            deadline(),
        )
        .unwrap();
    journal
        .record_observed(
            &operation,
            &effect,
            target,
            None,
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        journal
            .authorize_binding(
                &operation,
                &effect,
                &journal.binding(),
                &cancel,
                deadline()
            )
            .is_err()
    );
    let mut forged = journal.snapshot(&cancel, deadline()).unwrap();
    assert!(forged.bindings.is_empty());
    let good = journal.binding();
    forged.bindings.insert(
        "test/server".into(),
        Binding {
            generation: pin(b"generation").to_string(),
            pin: good.digest().unwrap().to_string(),
            unit: unit().as_str().into(),
            publication: target.to_string(),
            authorization: "11111111111111111111111111111111".into(),
            epoch: epoch(),
            authorized: true,
        },
    );
    assert!(forged.bytes().is_err());
}

#[test]
fn observed_invocation_requires_current_gate_and_confirmed_start_together() {
    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    let cancel = Cancellation::default();
    let invocation = "11111111111111111111111111111111";
    let observe = || {
        journal
            .observed_invocation(
                "test/server",
                journal.binding_pin(),
                &cancel,
                deadline(),
            )
            .unwrap()
    };
    assert_eq!(observe(), None);
    let admission = admit(&journal, invocation).unwrap();
    assert_eq!(observe(), None);
    let start = journal
        .plan_effect(
            &operation,
            "test/server",
            EffectKind::Start,
            None,
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    journal
        .record_accepted(&operation, &start, "/job/1", &cancel, deadline())
        .unwrap();
    assert_eq!(observe(), None);
    journal
        .with_consumed_start(admission, &cancel, deadline(), || Ok(()))
        .unwrap();
    assert_eq!(observe(), None);
    journal
        .record_observed(
            &operation,
            &start,
            journal.binding_pin(),
            Some(invocation),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert_eq!(observe().as_deref(), Some(invocation));
}

#[test]
fn observed_invocation_survives_revocation_but_not_new_authorization_nonce() {
    let (_temp, journal, operation) = fixture();
    let publication = publish(&journal, &operation);
    let cancel = Cancellation::default();
    let invocation = "11111111111111111111111111111111";
    let admission = admit(&journal, invocation).unwrap();
    let start = journal
        .plan_effect(
            &operation,
            "test/server",
            EffectKind::Start,
            None,
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    journal
        .record_observed(
            &operation,
            &start,
            journal.binding_pin(),
            Some(invocation),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert_eq!(
        journal
            .observed_invocation(
                "test/server",
                journal.binding_pin(),
                &cancel,
                deadline()
            )
            .unwrap(),
        None
    );
    journal
        .with_consumed_start(admission, &cancel, deadline(), || Ok(()))
        .unwrap();
    journal
        .revoke_binding(
            "test/server",
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert_eq!(
        journal
            .observed_invocation(
                "test/server",
                journal.binding_pin(),
                &cancel,
                deadline()
            )
            .unwrap()
            .as_deref(),
        Some(invocation)
    );
    journal
        .authorize_binding(
            &operation,
            &publication,
            &journal.binding(),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert_eq!(
        journal
            .observed_invocation(
                "test/server",
                journal.binding_pin(),
                &cancel,
                deadline()
            )
            .unwrap(),
        None
    );
}

#[test]
fn superseded_operation_cannot_revoke_a_current_binding() {
    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    let cancel = Cancellation::default();
    let current = journal
        .begin_test_pin(
            pin(b"generation"),
            Some(pin(b"generation")),
            epoch(),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        journal
            .revoke_binding_for_operation(
                &operation,
                "test/server",
                journal.binding_pin(),
                &cancel,
                deadline()
            )
            .is_err()
    );
    assert!(
        journal
            .snapshot(&cancel, deadline())
            .unwrap()
            .bindings["test/server"]
            .authorized
    );
    journal
        .revoke_binding_for_operation(
            &current,
            "test/server",
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        !journal
            .snapshot(&cancel, deadline())
            .unwrap()
            .bindings["test/server"]
            .authorized
    );
}

fn confirmed_start(journal: &ActivationJournal, operation: &str) -> (String, String) {
    let publication = publish(journal, operation);
    let cancel = Cancellation::default();
    let invocation = "11111111111111111111111111111111";
    let admission = admit(journal, invocation).unwrap();
    journal
        .with_consumed_start(admission, &cancel, deadline(), || Ok(()))
        .unwrap();
    let start = journal
        .plan_effect(
            operation,
            "test/server",
            EffectKind::Start,
            None,
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    journal
        .record_observed(
            operation,
            &start,
            journal.binding_pin(),
            Some(invocation),
            &cancel,
            deadline(),
        )
        .unwrap();
    let nonce = journal
        .snapshot(&cancel, deadline())
        .unwrap()
        .bindings["test/server"]
        .authorization
        .clone();
    (publication, nonce)
}

#[test]
fn preservation_observes_old_generation_without_renewing_authority() {
    let (_temp, journal, operation) = fixture();
    let (_, nonce) = confirmed_start(&journal, &operation);
    let cancel = Cancellation::default();
    let current = journal
        .begin_test_pin(
            pin(b"candidate-b"),
            Some(pin(b"generation")),
            epoch(),
            &cancel,
            deadline(),
        )
        .unwrap();
    let before = journal
        .snapshot(&cancel, deadline())
        .unwrap()
        .bytes()
        .unwrap();
    assert!(
        journal
            .preservation_current(
                &current,
                "test/server",
                journal.binding_pin(),
                &nonce,
                &epoch(),
                "11111111111111111111111111111111",
                &cancel,
                deadline()
            )
            .unwrap()
    );
    assert_eq!(
        before,
        journal
            .snapshot(&cancel, deadline())
            .unwrap()
            .bytes()
            .unwrap()
    );
    let newer = journal
        .begin_test_pin(
            pin(b"candidate-c"),
            Some(pin(b"candidate-b")),
            epoch(),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        !journal
            .preservation_current(
                &current,
                "test/server",
                journal.binding_pin(),
                &nonce,
                &epoch(),
                "11111111111111111111111111111111",
                &cancel,
                deadline()
            )
            .unwrap()
    );
    assert!(
        journal
            .preservation_current(
                &newer,
                "test/server",
                journal.binding_pin(),
                &nonce,
                &epoch(),
                "11111111111111111111111111111111",
                &cancel,
                deadline()
            )
            .unwrap()
    );
}

#[test]
fn preservation_refuses_revocation_nonce_rotation_and_mismatched_evidence() {
    let (_temp, journal, operation) = fixture();
    let (publication, nonce) = confirmed_start(&journal, &operation);
    let cancel = Cancellation::default();
    let check =
        |selected_pin, selected_nonce: &str, invocation: &str, selected_epoch: &ExecutionEpoch| {
            journal
                .preservation_current(
                    &operation,
                    "test/server",
                    selected_pin,
                    selected_nonce,
                    selected_epoch,
                    invocation,
                    &cancel,
                    deadline(),
                )
                .unwrap()
        };
    let invocation = "11111111111111111111111111111111";
    assert!(!check(
        pin(b"other-binding"),
        &nonce,
        invocation,
        &epoch()
    ));
    assert!(!check(
        journal.binding_pin(),
        "22222222222222222222222222222222",
        invocation,
        &epoch()
    ));
    assert!(!check(
        journal.binding_pin(),
        &nonce,
        "22222222222222222222222222222222",
        &epoch()
    ));
    let mut different_epoch = epoch();
    different_epoch.manager = "other-manager".into();
    assert!(!check(
        journal.binding_pin(),
        &nonce,
        invocation,
        &different_epoch
    ));
    journal
        .revoke_binding(
            "test/server",
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(!check(
        journal.binding_pin(),
        &nonce,
        invocation,
        &epoch()
    ));
    journal
        .authorize_binding(
            &operation,
            &publication,
            &journal.binding(),
            &cancel,
            deadline(),
        )
        .unwrap();
    let new_nonce = journal
        .snapshot(&cancel, deadline())
        .unwrap()
        .bindings["test/server"]
        .authorization
        .clone();
    assert!(!check(
        journal.binding_pin(),
        &nonce,
        invocation,
        &epoch()
    ));
    assert!(!check(
        journal.binding_pin(),
        &new_nonce,
        invocation,
        &epoch()
    ));
}

#[test]
fn uncertain_accepted_effect_retains_job_across_reopen_and_blocks_replay() {
    let (temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    let effect = journal
        .plan_effect(
            &operation,
            "test/server",
            EffectKind::Start,
            None,
            pin(b"target"),
            &cancel,
            deadline(),
        )
        .unwrap();
    journal
        .record_accepted(
            &operation,
            &effect,
            "/org/freedesktop/systemd1/job/71",
            &cancel,
            deadline(),
        )
        .unwrap();
    journal
        .record_unknown(&operation, &effect, &cancel, deadline())
        .unwrap();
    journal
        .record_unknown(&operation, &effect, &cancel, deadline())
        .unwrap();
    drop(journal);
    let journal = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
    assert_eq!(
        journal
            .snapshot(&cancel, deadline())
            .unwrap()
            .operations[&operation]
            .effects[&effect]
            .state,
        EffectState::Accepted {
            job: "/org/freedesktop/systemd1/job/71".into()
        }
    );
    assert!(
        journal
            .record_accepted(
                &operation,
                &effect,
                "/job/replay",
                &cancel,
                deadline()
            )
            .is_err()
    );
    assert!(
        journal
            .begin_test_pin(
                pin(b"next"),
                Some(pin(b"generation")),
                epoch(),
                &cancel,
                deadline()
            )
            .is_err()
    );
    journal
        .record_observed(
            &operation,
            &effect,
            pin(b"target"),
            Some("11111111111111111111111111111111"),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        journal
            .record_unknown(&operation, &effect, &cancel, deadline())
            .is_err()
    );
}

mod abandon;
mod boot_fence;
mod not_applied;
mod rollback;

mod closed_inventory;
mod manager_change;

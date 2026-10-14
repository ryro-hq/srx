use super::*;

const OBSERVED: &str = "44444444444444444444444444444444";

fn changed() -> ExecutionEpoch {
    ExecutionEpoch {
        manager: "authenticated-manager-2".into(),
        ..epoch()
    }
}
#[test]
fn changed_manager_revokes_before_any_stop_and_rejects_old_gate() {
    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    let admission = admit(&journal, "22222222222222222222222222222222").unwrap();
    let cancel = Cancellation::default();
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    let state = journal.snapshot(&cancel, deadline()).unwrap();
    assert!(!state.bindings["test/server"].authorized);
    assert_eq!(state.manager_changes[&key].attempts.len(), 1);
    assert!(
        journal
            .with_consumed_start(
                admission,
                &cancel,
                deadline(),
                || -> io::Result<()> { panic!("revoked gate must not execute") }
            )
            .is_err()
    );
    assert!(
        journal
            .observe_changed_namespaces(&key, &cancel, deadline())
            .unwrap()
            .is_none()
    );
    assert!(
        journal
            .intent_changed_stop(&key, "test/server", OBSERVED, &cancel, deadline())
            .is_err()
    );
    assert!(
        journal
            .observe_closed_process_inventory(&key, &cancel, deadline())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        journal
            .begin_manager_change(&operation, &changed(), &cancel, deadline())
            .unwrap(),
        key
    );
}
#[test]
fn changed_manager_rejects_cross_boot_scope_and_retargeting() {
    let (_temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    for invalid in [
        epoch(),
        ExecutionEpoch {
            scope: "foreign".into(),
            ..changed()
        },
        ExecutionEpoch {
            boot: BootId::parse("22222222-2222-2222-2222-222222222222").unwrap(),
            ..changed()
        },
    ] {
        assert!(
            journal
                .begin_manager_change(&operation, &invalid, &cancel, deadline())
                .is_err()
        );
    }
    journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    let third = ExecutionEpoch {
        manager: "third-manager".into(),
        ..changed()
    };
    assert!(
        journal
            .begin_manager_change(&operation, &third, &cancel, deadline())
            .is_err()
    );
}
#[test]
fn manager_change_roundtrip_preserves_revocation_and_legacy_pending() {
    let (temp, journal, operation) = fixture();
    publish(&journal, &operation);
    let cancel = Cancellation::default();
    let admission = admit(&journal, "33333333333333333333333333333333").unwrap();
    journal
        .with_consumed_start(admission, &cancel, deadline(), || Ok(()))
        .unwrap();
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    drop(journal);
    let reopened = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
    assert!(
        reopened
            .observe_changed_namespaces(&key, &cancel, deadline())
            .unwrap()
            .is_none()
    );
    assert!(
        !reopened
            .snapshot(&cancel, deadline())
            .unwrap()
            .bindings["test/server"]
            .authorized
    );
}

fn observed_start(journal: &ActivationJournal, operation: &str) {
    let cancel = Cancellation::default();
    let invocation = "44444444444444444444444444444444";
    let admission = admit(journal, invocation).unwrap();
    journal
        .with_consumed_start(admission, &cancel, deadline(), || Ok(()))
        .unwrap();
    let effect = journal
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
            &effect,
            journal.binding_pin(),
            Some(invocation),
            &cancel,
            deadline(),
        )
        .unwrap();
}
#[test]
fn stop_intent_survives_reopen_without_authorizing_replay() {
    let (temp, journal, operation) = fixture();
    publish(&journal, &operation);
    observed_start(&journal, &operation);
    let cancel = Cancellation::default();
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    assert!(
        journal
            .intent_changed_stop(&key, "test/server", OBSERVED, &cancel, deadline())
            .unwrap()
    );
    drop(journal);
    let reopened = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
    assert!(
        !reopened
            .intent_changed_stop(&key, "test/server", OBSERVED, &cancel, deadline())
            .unwrap()
    );
    reopened
        .changed_stop_reply(
            &key,
            "test/server",
            OBSERVED,
            None,
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        !reopened
            .intent_changed_stop(&key, "test/server", OBSERVED, &cancel, deadline())
            .unwrap()
    );
    assert!(
        reopened
            .changed_stop_reply(
                &key,
                "test/server",
                OBSERVED,
                Some("/org/freedesktop/systemd1/job/1"),
                &cancel,
                deadline()
            )
            .is_err()
    );
}
#[test]
fn historical_inventory_and_invocation_cannot_be_substituted() {
    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    observed_start(&journal, &operation);
    let cancel = Cancellation::default();
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    let original = journal.snapshot(&cancel, deadline()).unwrap();
    let mut missing = original.clone();
    missing
        .manager_changes
        .get_mut(&key)
        .unwrap()
        .resources
        .clear();
    assert!(missing.bytes().is_err());
    let mut foreign = original.clone();
    foreign
        .manager_changes
        .get_mut(&key)
        .unwrap()
        .resources
        .get_mut("test/server")
        .unwrap()
        .invocations
        .insert(
            "55555555555555555555555555555555".into(),
            "66666666666666666666666666666666".into(),
        );
    assert!(foreign.bytes().is_err());
    let mut invalid_phase = original.clone();
    let resource = invalid_phase
        .manager_changes
        .get_mut(&key)
        .unwrap()
        .resources
        .get_mut("test/server")
        .unwrap();
    resource.invocations.clear();
    resource.stop = super::super::manager_change::StopState::Intent {
        invocation: OBSERVED.into(),
    };
    assert!(invalid_phase.bytes().is_err());
    let mut invalid_binding = original;
    invalid_binding
        .manager_changes
        .get_mut(&key)
        .unwrap()
        .resources
        .get_mut("test/server")
        .unwrap()
        .binding
        .unit = "foreign.service".into();
    assert!(invalid_binding.bytes().is_err());
}
#[test]
fn cancelled_transition_does_not_revoke_binding() {
    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(
        journal
            .begin_manager_change(&operation, &changed(), &cancel, deadline())
            .is_err()
    );
    let state = journal
        .snapshot(&Cancellation::default(), deadline())
        .unwrap();
    assert!(state.bindings["test/server"].authorized);
    assert!(state.manager_changes.is_empty());
}

#[test]
fn legacy_namespace_inventory_cannot_be_promoted_to_settled_bytes() {
    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    observed_start(&journal, &operation);
    let cancel = Cancellation::default();
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    let mut state = journal.snapshot(&cancel, deadline()).unwrap();
    state
        .manager_changes
        .get_mut(&key)
        .unwrap()
        .settled = true;
    assert!(state.bytes().is_err());
    assert!(
        !journal
            .snapshot(&cancel, deadline())
            .unwrap()
            .manager_fenced(&epoch(), &changed())
    );
}

#[test]
fn recovery_stop_job_path_uses_the_manager_canonical_grammar() {
    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    observed_start(&journal, &operation);
    let cancel = Cancellation::default();
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    assert!(
        journal
            .intent_changed_stop(&key, "test/server", OBSERVED, &cancel, deadline())
            .unwrap()
    );
    for job in [
        "/org/freedesktop/systemd1/job/0",
        "/org/freedesktop/systemd1/job/042",
        "/org/freedesktop/systemd1/job/../1",
        "/org/freedesktop/systemd1/job/4294967296",
    ] {
        assert!(
            journal
                .changed_stop_reply(
                    &key,
                    "test/server",
                    OBSERVED,
                    Some(job),
                    &cancel,
                    deadline()
                )
                .is_err()
        );
    }
    journal
        .changed_stop_reply(
            &key,
            "test/server",
            OBSERVED,
            Some("/org/freedesktop/systemd1/job/42"),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        !journal
            .intent_changed_stop(&key, "test/server", OBSERVED, &cancel, deadline())
            .unwrap()
    );
}

#[test]
fn no_start_proof_requires_absence_of_both_intent_and_admission() {
    use super::super::manager_change::ResourceExecution;
    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    let cancel = Cancellation::default();
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    let state = journal.snapshot(&cancel, deadline()).unwrap();
    assert_eq!(
        state
            .changed_execution(&key, "test/server")
            .unwrap(),
        ResourceExecution::NeverStarted
    );
    assert!(state.changed_epoch_never_started(&key));

    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    journal
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
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    let state = journal.snapshot(&cancel, deadline()).unwrap();
    assert_eq!(
        state
            .changed_execution(&key, "test/server")
            .unwrap(),
        ResourceExecution::Incomplete
    );
    assert!(!state.changed_epoch_never_started(&key));

    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    let _admission = admit(&journal, "77777777777777777777777777777777").unwrap();
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    let state = journal.snapshot(&cancel, deadline()).unwrap();
    assert_eq!(
        state
            .changed_execution(&key, "test/server")
            .unwrap(),
        ResourceExecution::Incomplete
    );
    assert!(!state.changed_epoch_never_started(&key));
}

#[test]
fn startup_record_selects_invocation_without_requiring_start_reply() {
    use super::super::manager_change::ResourceExecution;
    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    let cancel = Cancellation::default();
    let invocation = "88888888888888888888888888888888";
    let admission = admit(&journal, invocation).unwrap();
    let attempt_id = admission.attempt().to_owned();
    // This test exercises persisted record classification, not kernel settlement.
    // No NamespaceExitProof is manufactured and observe_exit is never called.
    journal
        .mutate(&cancel, deadline(), |state| {
            let attempt = state.attempts.get_mut(admission.attempt()).unwrap();
            attempt.gate_used = true;
            attempt.namespace = Some(
                serde_json::from_value(serde_json::json!({
                    "role": "namespace_init", "process": {"boot": epoch().boot, "observer_init": {"device": 1, "inode": 1},
                    "pid": 100, "init": {"device": 1, "inode": 2}, "start": 1}
                }))
                .unwrap(),
            );
            Ok(())
        })
        .unwrap();
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    let state = journal.snapshot(&cancel, deadline()).unwrap();
    assert_eq!(
        state.manager_changes[&key].resources["test/server"]
            .invocations
            .get(invocation)
            .map(String::as_str),
        Some(attempt_id.as_str())
    );
    assert_eq!(
        state
            .changed_execution(&key, "test/server")
            .unwrap(),
        ResourceExecution::Started
    );
    assert!(!state.manager_fenced(&epoch(), &changed()));
}

#[test]
fn structurally_empty_epoch_has_empty_closed_inventory_without_kernel_shortcuts() {
    let (_temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    let proof = journal
        .observe_closed_process_inventory(&key, &cancel, deadline())
        .unwrap()
        .unwrap();
    let state = journal.snapshot(&cancel, deadline()).unwrap();
    assert!(state.changed_epoch_never_started(&key));
    assert!(proof.matches(&state, &key));
    assert!(!proof.matches(&state, "different-transition"));
}

// Synthetic records here test parsing/classification only. Kernel exit evidence
// is exercised by closed_inventory.rs; no opaque proof is constructed here.
fn record_namespace_classification(journal: &ActivationJournal, admission: &StartAdmission) {
    journal
        .mutate(&Cancellation::default(), deadline(), |state| {
            let attempt = state
                .attempts
                .get_mut(admission.attempt())
                .unwrap();
            attempt.gate_used = true;
            attempt.namespace = Some(
                serde_json::from_value(serde_json::json!({
                    "role":"namespace_init", "process": {"boot":epoch().boot,
                        "observer_init":{"device":1,"inode":1},"pid":100,
                        "init":{"device":1,"inode":2},"start":1}
                }))
                .unwrap(),
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn multiple_invocations_are_complete_and_stop_cannot_be_retargeted_after_reopen() {
    let (temp, journal, operation) = fixture();
    publish(&journal, &operation);
    observed_start(&journal, &operation);
    let later = "11111111111111111111111111111111";
    let admission = admit(&journal, later).unwrap();
    record_namespace_classification(&journal, &admission);
    let cancel = Cancellation::default();
    assert!(
        journal
            .observed_invocation(
                "test/server",
                journal.binding_pin(),
                &cancel,
                deadline()
            )
            .is_err()
    );
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    let original = journal.snapshot(&cancel, deadline()).unwrap();
    let candidates = &original.manager_changes[&key].resources["test/server"].invocations;
    assert_eq!(candidates.len(), 2);
    assert!(candidates.contains_key(OBSERVED));
    assert_eq!(candidates[later], admission.attempt());
    for corruption in 0..3 {
        let mut altered = original.clone();
        let candidates = &mut altered
            .manager_changes
            .get_mut(&key)
            .unwrap()
            .resources
            .get_mut("test/server")
            .unwrap()
            .invocations;
        match corruption {
            0 => {
                candidates.remove(later);
            }
            1 => {
                candidates.insert(
                    later.into(),
                    "99999999999999999999999999999999".into(),
                );
            }
            _ => {
                candidates.insert(
                    "22222222222222222222222222222222".into(),
                    admission.attempt().into(),
                );
            }
        }
        assert!(altered.bytes().is_err());
    }
    assert!(
        journal
            .intent_changed_stop(&key, "test/server", OBSERVED, &cancel, deadline())
            .unwrap()
    );
    drop(journal);
    let reopened = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
    assert!(
        !reopened
            .intent_changed_stop(&key, "test/server", OBSERVED, &cancel, deadline())
            .unwrap()
    );
    assert!(
        reopened
            .intent_changed_stop(&key, "test/server", later, &cancel, deadline())
            .is_err()
    );
    assert!(
        reopened
            .changed_stop_reply(
                &key,
                "test/server",
                later,
                None,
                &cancel,
                deadline()
            )
            .is_err()
    );
    reopened
        .changed_stop_reply(
            &key,
            "test/server",
            OBSERVED,
            None,
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        reopened
            .intent_changed_stop(&key, "test/server", later, &cancel, deadline())
            .is_err()
    );
    assert!(
        !reopened
            .snapshot(&cancel, deadline())
            .unwrap()
            .manager_changes[&key]
            .settled
    );
}

#[test]
fn later_incomplete_admission_prevents_singleton_and_settlement() {
    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    observed_start(&journal, &operation);
    let _later = admit(&journal, "55555555555555555555555555555555").unwrap();
    let cancel = Cancellation::default();
    assert!(
        journal
            .observed_invocation(
                "test/server",
                journal.binding_pin(),
                &cancel,
                deadline()
            )
            .is_err()
    );
    let key = journal
        .begin_manager_change(&operation, &changed(), &cancel, deadline())
        .unwrap();
    let mut state = journal.snapshot(&cancel, deadline()).unwrap();
    assert_eq!(state.manager_changes[&key].attempts.len(), 2);
    assert_eq!(
        state.manager_changes[&key].resources["test/server"]
            .invocations
            .len(),
        1
    );
    assert!(
        journal
            .observe_changed_namespaces(&key, &cancel, deadline())
            .unwrap()
            .is_none()
    );
    state
        .manager_changes
        .get_mut(&key)
        .unwrap()
        .settled = true;
    assert!(state.bytes().is_err());
}

#[test]
fn candidate_inventory_includes_prior_bindings_and_authorizations() {
    let (_temp, journal, operation) = fixture();
    publish(&journal, &operation);
    let old_invocation = "33333333333333333333333333333333";
    let old = admit(&journal, old_invocation).unwrap();
    record_namespace_classification(&journal, &old);
    let cancel = Cancellation::default();
    journal
        .revoke_binding(
            "test/server",
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    let generation = pin(b"next generation");
    let next = journal
        .begin_pin(
            generation,
            Some(pin(b"generation")),
            epoch(),
            &cancel,
            deadline(),
        )
        .unwrap();
    let mut input = journal.binding_input();
    input.generation = generation;
    input.spec = pin(b"different runtime");
    let binding = OsLaunchBinding::new(input).unwrap();
    let digest = binding.digest().unwrap();
    let effect = journal
        .plan_effect(
            &next,
            "test/server",
            EffectKind::Publish,
            None,
            digest,
            &cancel,
            deadline(),
        )
        .unwrap();
    journal
        .record_observed(&next, &effect, digest, None, &cancel, deadline())
        .unwrap();
    journal
        .authorize_binding(&next, &effect, &binding, &cancel, deadline())
        .unwrap();
    let current_invocation = "66666666666666666666666666666666";
    let current = journal
        .admit_start(
            "test/server",
            digest,
            &unit(),
            current_invocation,
            &epoch(),
            &cancel,
            deadline(),
        )
        .unwrap();
    record_namespace_classification(&journal, &current);
    let key = journal
        .begin_manager_change(&next, &changed(), &cancel, deadline())
        .unwrap();
    let state = journal.snapshot(&cancel, deadline()).unwrap();
    let resource = &state.manager_changes[&key].resources["test/server"];
    assert_eq!(resource.invocations.len(), 2);
    assert_eq!(
        resource.invocations[old_invocation],
        old.attempt()
    );
    assert_eq!(
        resource.invocations[current_invocation],
        current.attempt()
    );
    assert_ne!(
        state.attempts[old.attempt()].binding,
        state.attempts[current.attempt()].binding
    );
    assert_ne!(
        state.attempts[old.attempt()].authorization,
        state.attempts[current.attempt()].authorization
    );
    assert_eq!(state.manager_history(&key).unwrap().len(), 2);
    let mut missing_publication = state.clone();
    missing_publication
        .operations
        .get_mut(&operation)
        .unwrap()
        .effects
        .clear();
    assert!(missing_publication.bytes().is_err());
}

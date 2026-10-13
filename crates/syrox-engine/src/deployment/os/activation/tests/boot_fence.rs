use super::*;

fn next_epoch() -> ExecutionEpoch {
    ExecutionEpoch {
        boot: BootId::parse("22222222-2222-2222-2222-222222222222").unwrap(),
        manager: "authenticated-manager-2".into(),
        ..epoch()
    }
}

fn remote(journal: &ActivationJournal, operation: &str, name: &str, kind: EffectKind) -> String {
    journal
        .plan_effect(
            operation,
            name,
            kind,
            None,
            pin(b"target"),
            &Cancellation::default(),
            deadline(),
        )
        .unwrap()
}

fn assert_immutable(journal: &ActivationJournal, operation: &str, effect: &str) {
    let cancel = Cancellation::default();
    assert!(
        journal
            .record_unknown(operation, effect, &cancel, deadline())
            .is_err()
    );
    assert!(
        journal
            .record_accepted(operation, effect, "/job/new", &cancel, deadline())
            .is_err()
    );
    assert!(
        journal
            .record_observed(
                operation,
                effect,
                pin(b"target"),
                None,
                &cancel,
                deadline()
            )
            .is_err()
    );
}

#[test]
fn boot_fence_preserves_publication_jobs_attempts_and_revokes_start_authority() {
    let (_temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    let publication = publish(&journal, &operation);
    let admission = admit(&journal, "77777777777777777777777777777777").unwrap();
    let intent = remote(&journal, &operation, "reload", EffectKind::Reload);
    let unknown = remote(&journal, &operation, "stop", EffectKind::Stop);
    journal
        .record_unknown(&operation, &unknown, &cancel, deadline())
        .unwrap();
    let accepted = remote(&journal, &operation, "start", EffectKind::Start);
    journal
        .record_accepted(
            &operation,
            &accepted,
            "/job/123",
            &cancel,
            deadline(),
        )
        .unwrap();
    let observed = remote(&journal, &operation, "done", EffectKind::Stop);
    journal
        .record_observed(
            &operation,
            &observed,
            pin(b"target"),
            None,
            &cancel,
            deadline(),
        )
        .unwrap();
    let pending_publish = remote(
        &journal,
        &operation,
        "unpublished",
        EffectKind::Publish,
    );
    let before = journal.snapshot(&cancel, deadline()).unwrap();
    let current = next_epoch();
    journal
        .fence_previous_boot(&operation, &current, &cancel, deadline())
        .unwrap();
    let after = journal.snapshot(&cancel, deadline()).unwrap();
    assert!(after.boot_fenced(&epoch(), &current));
    let effects = &after.operations[&operation].effects;
    for id in [&intent, &unknown, &accepted] {
        assert_eq!(
            effects[id].state,
            EffectState::BootFenced {
                epoch: current.clone(),
                job: (id == &accepted).then(|| "/job/123".into()),
            }
        );
        assert_immutable(&journal, &operation, id);
    }
    for id in [
        &publication,
        &observed,
        &pending_publish,
    ] {
        assert_eq!(
            effects[id].state,
            before.operations[&operation].effects[id].state
        );
    }
    assert!(!after.operations[&operation].terminal());
    assert!(!after.bindings["test/server"].authorized);
    assert_eq!(
        after.bindings["test/server"].authorization,
        before.bindings["test/server"].authorization
    );
    assert_eq!(
        serde_json::to_vec(&after.attempts).unwrap(),
        serde_json::to_vec(&before.attempts).unwrap()
    );
    assert!(admit(&journal, "88888888888888888888888888888888").is_err());
    assert!(
        journal
            .with_consumed_start(
                admission,
                &cancel,
                deadline(),
                || -> io::Result<()> { panic!("fenced start") }
            )
            .is_err()
    );
    assert!(
        journal
            .authorize_binding(
                &operation,
                &publication,
                &journal.binding(),
                &cancel,
                deadline()
            )
            .is_err()
    );
    journal
        .fence_previous_boot(&operation, &current, &cancel, deadline())
        .unwrap();
    assert_eq!(
        after.bytes().unwrap(),
        journal
            .snapshot(&cancel, deadline())
            .unwrap()
            .bytes()
            .unwrap()
    );
}

#[test]
fn boot_fence_rejects_same_boot_scope_change_and_preserves_terminal_history_on_later_boot() {
    let (_temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    let effect = remote(&journal, &operation, "start", EffectKind::Start);
    let mut current = next_epoch();
    let mut wrong = epoch();
    wrong.manager = "replacement-same-boot".into();
    assert!(
        journal
            .fence_previous_boot(&operation, &wrong, &cancel, deadline())
            .is_err()
    );
    wrong = current.clone();
    wrong.scope = "other endpoint".into();
    assert!(
        journal
            .fence_previous_boot(&operation, &wrong, &cancel, deadline())
            .is_err()
    );
    journal
        .fence_previous_boot(&operation, &current, &cancel, deadline())
        .unwrap();
    let before = journal.snapshot(&cancel, deadline()).unwrap();
    assert!(before.operations[&operation].terminal());
    for kind in [
        EffectKind::Publish,
        EffectKind::Reload,
        EffectKind::Start,
        EffectKind::Stop,
    ] {
        assert!(
            journal
                .plan_effect(
                    &operation,
                    "new",
                    kind,
                    None,
                    pin(b"new"),
                    &cancel,
                    deadline()
                )
                .is_err()
        );
    }
    assert!(
        journal
            .begin_pin(
                pin(b"new"),
                Some(pin(b"generation")),
                epoch(),
                &cancel,
                deadline()
            )
            .is_err()
    );
    assert_eq!(
        before.bytes().unwrap(),
        journal
            .snapshot(&cancel, deadline())
            .unwrap()
            .bytes()
            .unwrap()
    );
    current.boot = BootId::parse("33333333-3333-3333-3333-333333333333").unwrap();
    journal
        .fence_previous_boot(&operation, &current, &cancel, deadline())
        .unwrap();
    let after = journal.snapshot(&cancel, deadline()).unwrap();
    assert!(after.boot_fenced(&epoch(), &current));
    assert!(!after.boot_fenced(&epoch(), &next_epoch()));
    assert_eq!(
        after.operations[&operation].effects[&effect].state,
        before.operations[&operation].effects[&effect].state
    );
    journal
        .begin_pin(
            pin(b"next"),
            Some(pin(b"generation")),
            current,
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        journal
            .fence_previous_boot(&operation, &next_epoch(), &cancel, deadline())
            .is_err()
    );
}

#[test]
fn malformed_boot_fences_and_authorized_old_bindings_fail_closed() {
    let (_temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    publish(&journal, &operation);
    let effect = remote(&journal, &operation, "remote", EffectKind::Reload);
    journal
        .fence_previous_boot(&operation, &next_epoch(), &cancel, deadline())
        .unwrap();
    let valid = journal.snapshot(&cancel, deadline()).unwrap();
    for case in 0..6 {
        let mut state = valid.clone();
        match case {
            0 => state.boot_fences.clear(),
            1 => {
                state
                    .boot_fences
                    .insert(epoch().boot.as_str().into(), epoch());
            }
            2 => {
                state
                    .bindings
                    .get_mut("test/server")
                    .unwrap()
                    .authorized = true
            }
            3 => {
                state
                    .operations
                    .get_mut(&operation)
                    .unwrap()
                    .effects
                    .get_mut(&effect)
                    .unwrap()
                    .kind = EffectKind::Publish;
            }
            4 | 5 => {
                let EffectState::BootFenced {
                    epoch: fenced,
                    job,
                } = &mut state
                    .operations
                    .get_mut(&operation)
                    .unwrap()
                    .effects
                    .get_mut(&effect)
                    .unwrap()
                    .state
                else {
                    panic!()
                };
                if case == 4 {
                    *fenced = epoch();
                } else {
                    *job = Some("x".repeat(4097));
                }
            }
            _ => unreachable!(),
        }
        assert!(state.bytes().is_err(), "case {case}");
    }
}

#[test]
fn fence_covers_all_prior_boots_and_leaves_every_publication_phase_unchanged() {
    let (_temp, journal, previous) = fixture();
    let cancel = Cancellation::default();
    let done = remote(&journal, &previous, "done", EffectKind::Stop);
    journal
        .record_observed(
            &previous,
            &done,
            pin(b"target"),
            None,
            &cancel,
            deadline(),
        )
        .unwrap();
    let operation = journal
        .begin_pin(
            pin(b"second"),
            Some(pin(b"generation")),
            next_epoch(),
            &cancel,
            deadline(),
        )
        .unwrap();
    for (index, phase) in [
        EffectState::Intent,
        EffectState::Unknown,
        EffectState::Accepted {
            job: "/publication/job".into(),
        },
        EffectState::NotApplied,
        EffectState::Observed {
            fingerprint: pin(b"target").to_string(),
            invocation: None,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let effect = remote(
            &journal,
            &operation,
            &format!("publish-{index}"),
            EffectKind::Publish,
        );
        journal
            .update_effect(
                &operation,
                &effect,
                &cancel,
                deadline(),
                |effect| {
                    effect.state = phase;
                    Ok(())
                },
            )
            .unwrap();
    }
    let before = journal.snapshot(&cancel, deadline()).unwrap();
    let current = ExecutionEpoch {
        boot: BootId::parse("33333333-3333-3333-3333-333333333333").unwrap(),
        ..next_epoch()
    };
    journal
        .fence_previous_boot(&operation, &current, &cancel, deadline())
        .unwrap();
    let after = journal.snapshot(&cancel, deadline()).unwrap();
    assert!(after.boot_fenced(&epoch(), &current));
    assert!(after.boot_fenced(&next_epoch(), &current));
    assert_eq!(
        serde_json::to_vec(&after.operations).unwrap(),
        serde_json::to_vec(&before.operations).unwrap()
    );
    assert!(!after.operations[&operation].terminal());
}

#[test]
fn latest_abandonment_can_fence_a_new_boot_without_reselecting_its_generation() {
    let (_temp, journal, previous) = fixture();
    let cancel = Cancellation::default();
    publish(&journal, &previous);
    journal
        .abandon(&previous, &cancel, deadline())
        .unwrap();
    let latest = journal
        .begin_pin(pin(b"latest"), None, epoch(), &cancel, deadline())
        .unwrap();
    journal
        .abandon(&latest, &cancel, deadline())
        .unwrap();
    let before = journal.snapshot(&cancel, deadline()).unwrap();
    assert!(before.bindings["test/server"].authorized);
    assert!(
        journal
            .fence_previous_boot(&previous, &next_epoch(), &cancel, deadline())
            .is_err()
    );
    assert!(
        journal
            .fence_previous_boot(&latest, &epoch(), &cancel, deadline())
            .is_err()
    );
    assert_eq!(
        before.bytes().unwrap(),
        journal
            .snapshot(&cancel, deadline())
            .unwrap()
            .bytes()
            .unwrap()
    );
    journal
        .fence_previous_boot(&latest, &next_epoch(), &cancel, deadline())
        .unwrap();
    let fenced = journal.snapshot(&cancel, deadline()).unwrap();
    assert!(fenced.desired.is_none() && fenced.active_operation.is_none());
    assert_eq!(
        fenced.last_abandoned.as_deref(),
        Some(latest.as_str())
    );
    assert!(!fenced.bindings["test/server"].authorized);
    assert!(fenced.boot_fenced(&epoch(), &next_epoch()));
    assert_eq!(
        serde_json::to_vec(&fenced.operations).unwrap(),
        serde_json::to_vec(&before.operations).unwrap()
    );
    journal
        .fence_previous_boot(&latest, &next_epoch(), &cancel, deadline())
        .unwrap();
    assert_eq!(
        fenced.bytes().unwrap(),
        journal
            .snapshot(&cancel, deadline())
            .unwrap()
            .bytes()
            .unwrap()
    );
    let operation = journal
        .begin_pin(
            pin(b"fresh"),
            None,
            next_epoch(),
            &cancel,
            deadline(),
        )
        .unwrap();
    let selected = journal.snapshot(&cancel, deadline()).unwrap();
    assert_eq!(
        selected.active_operation.as_deref(),
        Some(operation.as_str())
    );
    assert_eq!(selected.desired, Some(pin(b"fresh").to_string()));
    assert!(selected.last_abandoned.is_none());
    assert!(!selected.bindings["test/server"].authorized);
}

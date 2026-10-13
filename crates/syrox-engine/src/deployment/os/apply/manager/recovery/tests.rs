use super::*;
use crate::deployment::os::activation::EffectState;

fn accepted_start(f: &Fixture) -> String {
    let mut manager = Fake::new(f, vec![None]);
    manager.fault = Fault::Unobserved;
    let outcome = f
        .driver(&mut manager)
        .start(&f.binding.process_key(), &f.binding, &f.contract)
        .unwrap();
    assert!(matches!(
        outcome.state,
        EffectStatus::Uncertain { .. }
    ));
    assert_eq!(
        state(f, &outcome.effect),
        EffectState::Accepted {
            job: "/job/1".into()
        }
    );
    outcome.effect
}
fn state(f: &Fixture, effect: &str) -> EffectState {
    f.journal
        .snapshot(&f.cancel, deadline())
        .unwrap()
        .operations[&f.operation]
        .effects[effect]
        .state
        .clone()
}
fn no_mutations(manager: &Fake<'_>) {
    assert!(
        manager
            .calls
            .iter()
            .all(|call| !matches!(*call, "start" | "stop" | "reload" | "wait"))
    );
}

#[test]
fn accepted_start_recovers_live_exec_evidence_without_replaying_or_claiming_job_done() {
    let f = Fixture::new();
    let effect = accepted_start(&f);
    let mut manager = Fake::new(&f, vec![Some(f.status(7, "active")); 3]);
    let outcome = f
        .driver(&mut manager)
        .reconcile_start(
            &effect,
            &f.binding.process_key(),
            &f.binding,
            &f.contract,
        )
        .unwrap();
    assert!(matches!(
        outcome.state,
        EffectStatus::Observed {
            invocation: Some(_)
        }
    ));
    assert_eq!(
        outcome.loaded,
        [(f.binding.unit(), pin(b"effective properties"))]
    );
    no_mutations(&manager);
    assert!(matches!(
        state(&f, &effect),
        EffectState::Observed { .. }
    ));
}

#[test]
fn absent_start_and_missing_fd_store_preserve_accepted_job_identity() {
    for present in [false, true] {
        let f = Fixture::new();
        let effect = accepted_start(&f);
        let statuses = if present {
            vec![Some(f.status(7, "active")); 2]
        } else {
            vec![None]
        };
        let mut manager = Fake::new(&f, statuses);
        manager.fd_count = 0;
        let outcome = f
            .driver(&mut manager)
            .reconcile_start(
                &effect,
                &f.binding.process_key(),
                &f.binding,
                &f.contract,
            )
            .unwrap();
        assert!(matches!(
            outcome.state,
            EffectStatus::Uncertain { .. }
        ));
        assert_eq!(
            state(&f, &effect),
            EffectState::Accepted {
                job: "/job/1".into()
            }
        );
        no_mutations(&manager);
    }
}

fn stopped_effect(f: &Fixture) -> String {
    stopped_effect_with_acceptance(f, true)
}

fn stopped_effect_with_acceptance(f: &Fixture, accepted: bool) -> String {
    let mut manager = Fake::new(
        f,
        vec![
            None,
            Some(f.status(7, "active")),
            Some(f.status(7, "active")),
        ],
    );
    let started = f
        .driver(&mut manager)
        .start(&f.binding.process_key(), &f.binding, &f.contract)
        .unwrap();
    assert!(matches!(
        started.state,
        EffectStatus::Observed { .. }
    ));
    f.revoke();
    let effect = f
        .journal
        .plan_effect(
            &f.operation,
            &f.binding.process_key(),
            EffectKind::Stop,
            None,
            f.binding.digest().unwrap(),
            &f.cancel,
            deadline(),
        )
        .unwrap();
    if accepted {
        f.journal
            .record_accepted(
                &f.operation,
                &effect,
                "/org/freedesktop/systemd1/job/2",
                &f.cancel,
                deadline(),
            )
            .unwrap();
    }
    if accepted {
        f.journal
            .record_unknown(&f.operation, &effect, &f.cancel, deadline())
            .unwrap();
    }
    effect
}

#[test]
fn stop_reconciliation_requires_the_owned_revoked_invocation_and_never_signals() {
    for current in [
        None,
        Some((7, "inactive")),
        Some((8, "inactive")),
        Some((7, "active")),
    ] {
        let f = Fixture::new();
        let effect = stopped_effect(&f);
        let mut manager = Fake::new(
            &f,
            vec![current.map(|(invocation, status)| f.status(invocation, status))],
        );
        let outcome = f
            .driver(&mut manager)
            .reconcile_stop(
                &effect,
                &f.binding.process_key(),
                &f.binding.unit(),
                &[7; 16],
                f.binding.digest().unwrap(),
            )
            .unwrap();
        let stopped = current.is_none() || current == Some((7, "inactive"));
        assert_eq!(
            matches!(outcome.state, EffectStatus::Observed { .. }),
            stopped
        );
        if !stopped {
            assert_eq!(
                state(&f, &effect),
                EffectState::Accepted {
                    job: "/org/freedesktop/systemd1/job/2".into()
                }
            );
        }
        no_mutations(&manager);
    }
}

#[test]
fn foreign_stop_invocation_is_rejected_before_manager_observation() {
    let f = Fixture::new();
    let effect = stopped_effect(&f);
    let mut manager = Fake::new(&f, vec![]);
    assert!(
        f.driver(&mut manager)
            .reconcile_stop(
                &effect,
                &f.binding.process_key(),
                &f.binding.unit(),
                &[8; 16],
                f.binding.digest().unwrap()
            )
            .is_err()
    );
    assert!(manager.calls.iter().all(|call| *call == "epoch"));
    assert_eq!(
        state(&f, &effect),
        EffectState::Accepted {
            job: "/org/freedesktop/systemd1/job/2".into()
        }
    );
}

#[test]
fn reload_reconciliation_observes_contracts_without_reloading() {
    for matches in [false, true] {
        let f = Fixture::new();
        let contracts = [&f.contract];
        let target = reload_target(&contracts);
        let effect = f
            .journal
            .plan_effect(
                &f.operation,
                "manager",
                EffectKind::Reload,
                None,
                target,
                &f.cancel,
                deadline(),
            )
            .unwrap();
        f.journal
            .record_unknown(&f.operation, &effect, &f.cancel, deadline())
            .unwrap();
        let mut manager = Fake::new(&f, vec![]);
        if !matches {
            manager.fault = Fault::Loaded;
        }
        let outcome = f
            .driver(&mut manager)
            .reconcile_reload(&effect, "manager", target, &contracts)
            .unwrap();
        assert_eq!(
            matches!(outcome.state, EffectStatus::Observed { .. }),
            matches
        );
        no_mutations(&manager);
    }
}

#[test]
fn recovery_rejects_different_effect_identity_without_changing_journal() {
    let f = Fixture::new();
    let effect = accepted_start(&f);
    let mut manager = Fake::new(&f, vec![]);
    assert!(
        f.driver(&mut manager)
            .reconcile_start(
                &effect,
                "different/resource",
                &f.binding,
                &f.contract
            )
            .is_err()
    );
    assert!(
        f.driver(&mut manager)
            .reconcile_reload(
                &effect,
                &f.binding.process_key(),
                reload_target(&[&f.contract]),
                &[&f.contract]
            )
            .is_err()
    );
    assert!(manager.calls.is_empty());
    assert_eq!(
        state(&f, &effect),
        EffectState::Accepted {
            job: "/job/1".into()
        }
    );
}

#[test]
fn inactive_or_absent_unit_does_not_discharge_unknown_or_pending_stop() {
    for phase in 0..3 {
        let accepted = phase == 2;
        for absent in [false, true] {
            let f = Fixture::new();
            let effect = stopped_effect_with_acceptance(&f, accepted);
            if phase == 1 {
                f.journal
                    .record_unknown(&f.operation, &effect, &f.cancel, deadline())
                    .unwrap();
            }
            let mut manager = Fake::new(
                &f,
                vec![(!absent).then(|| f.status(7, "inactive"))],
            );
            manager.fault = Fault::JobPresent;
            let before = state(&f, &effect);
            let outcome = f
                .driver(&mut manager)
                .reconcile_stop(
                    &effect,
                    &f.binding.process_key(),
                    &f.binding.unit(),
                    &[7; 16],
                    f.binding.digest().unwrap(),
                )
                .unwrap();
            assert!(matches!(
                outcome.state,
                EffectStatus::Uncertain { .. }
            ));
            let expected = if matches!(before, EffectState::Intent) {
                EffectState::Unknown
            } else {
                before
            };
            assert_eq!(state(&f, &effect), expected);
            assert!(!manager.calls.contains(&"query"));
            assert_eq!(manager.calls.contains(&"job"), accepted);
            no_mutations(&manager);
        }
    }
}

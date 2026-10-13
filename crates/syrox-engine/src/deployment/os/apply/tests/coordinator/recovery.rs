use super::*;
use crate::deployment::os::apply::recovery::{OsRecoveryReport, OsRecoveryState};

fn recover(fixture: &Fixture, manager: &mut Fake<'_>) -> OsRecoveryReport {
    let _guard = fixture
        .installation
        .execution(&fixture.cancel, deadline())
        .unwrap();
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    crate::deployment::os::apply::recovery::coordinator::reconcile(
        ApplyManager {
            manager,
            journal: &fixture.journal,
            operation: &fixture.operation,
            epoch: &fixture.epoch,
            cancellation: &fixture.cancel,
            deadline: deadline(),
        },
        &fixture.installation,
        &fixture.paths,
        &fixture.units,
        &fixture.resources,
        &snapshot,
        fixture.candidate.digest(),
    )
}
fn publication(fixture: &Fixture, resource: &str, target: ContentDigest) -> String {
    fixture
        .journal
        .plan_effect(
            &fixture.operation,
            resource,
            EffectKind::Publish,
            None,
            target,
            &fixture.cancel,
            deadline(),
        )
        .unwrap()
}
fn assert_no_manager_effects(manager: &Fake<'_>) {
    assert!(
        manager
            .calls
            .iter()
            .all(|call| !matches!(*call, "start" | "stop" | "reload"))
    );
}

#[test]
fn lost_reload_is_observed_without_resubmission_or_start_authorization() {
    let fixture = Fixture::new(false);
    let binding = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    let mut manager = Fake::new(&fixture, Some(binding));
    manager.lose_reload = true;
    assert!(
        fixture
            .run(&mut manager, &fixture.resources)
            .needs_reconciliation
    );
    assert_eq!(
        manager.effects(EffectKind::Reload, &EffectState::Unknown),
        1
    );
    manager.calls.clear();
    let report = recover(&fixture, &mut manager);
    assert!(!report.needs_reconciliation);
    assert!(
        report
            .effects
            .iter()
            .all(|effect| effect.state == OsRecoveryState::Observed)
    );
    assert!(manager.calls.contains(&"loaded"));
    assert_no_manager_effects(&manager);
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert!(
        snapshot
            .bindings
            .values()
            .all(|binding| !binding.authorized)
    );
    assert!(
        !snapshot.operations[&fixture.operation]
            .effects
            .values()
            .any(|effect| effect.kind == EffectKind::Start)
    );
}

#[test]
fn missing_binding_publication_is_not_applied_without_creating_bytes_or_authority() {
    let fixture = Fixture::new(false);
    let binding = &fixture.resources.values().next().unwrap().binding;
    let pin = binding.digest().unwrap();
    let effect = publication(&fixture, &binding.process_key(), pin);
    let mut manager = Fake::new(&fixture, Some(binding.clone()));
    let report = recover(&fixture, &mut manager);
    assert!(!report.needs_reconciliation);
    assert_eq!(
        report.effects[0].state,
        OsRecoveryState::NotApplied
    );
    assert!(
        fixture
            .installation
            .read_launch_binding(pin, &fixture.cancel, deadline())
            .is_err()
    );
    assert!(!binding.context().fragment().exists());
    let after = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert_eq!(
        after.operations[&fixture.operation].effects[&effect].state,
        EffectState::NotApplied
    );
    let repeated = recover(&fixture, &mut manager);
    assert_eq!(
        repeated.effects[0].state,
        OsRecoveryState::NotApplied
    );
    assert!(!repeated.needs_reconciliation);
    assert!(after.bindings.is_empty());
    assert_no_manager_effects(&manager);
}

#[test]
fn existing_exact_binding_is_observed_without_authorizing_a_start() {
    let fixture = Fixture::new(false);
    let binding = &fixture.resources.values().next().unwrap().binding;
    let pin = binding.digest().unwrap();
    let effect = publication(&fixture, &binding.process_key(), pin);
    fixture
        .installation
        .publish_launch_binding(
            &fixture.candidate,
            binding,
            &fixture.cancel,
            deadline(),
        )
        .unwrap();
    let mut manager = Fake::new(&fixture, Some(binding.clone()));
    let report = recover(&fixture, &mut manager);
    assert!(!report.needs_reconciliation);
    assert_eq!(report.effects[0].state, OsRecoveryState::Observed);
    let after = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert!(matches!(
        after.operations[&fixture.operation].effects[&effect].state,
        EffectState::Observed { .. }
    ));
    assert!(after.bindings.is_empty());
    assert!(
        fixture
            .journal
            .admit_start(
                &binding.process_key(),
                pin,
                &binding.unit(),
                &"07".repeat(16),
                &fixture.epoch,
                &fixture.cancel,
                deadline()
            )
            .is_err()
    );
    assert!(!binding.context().fragment().exists());
    assert_no_manager_effects(&manager);
}

#[test]
fn foreign_unit_and_wrong_target_remain_pending_without_adoption() {
    for wrong_target in [false, true] {
        let fixture = Fixture::new(false);
        let resource = fixture.resources.values().next().unwrap();
        let binding = &resource.binding;
        let bytes = b"foreign unit bytes";
        fs::write(binding.context().fragment(), bytes).unwrap();
        fs::set_permissions(
            binding.context().fragment(),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let target = if wrong_target {
            ContentDigest::sha256(b"wrong target")
        } else {
            resource.contract.file_digest()
        };
        publication(
            &fixture,
            &format!("unit/{}", binding.process_key()),
            target,
        );
        let before = serde_json::to_vec(
            &fixture
                .journal
                .snapshot(&fixture.cancel, deadline())
                .unwrap(),
        )
        .unwrap();
        let mut manager = Fake::new(&fixture, Some(binding.clone()));
        let report = recover(&fixture, &mut manager);
        assert!(report.needs_reconciliation);
        assert_eq!(report.effects[0].state, OsRecoveryState::Pending);
        assert_eq!(
            fs::read(binding.context().fragment()).unwrap(),
            bytes
        );
        assert_eq!(
            serde_json::to_vec(
                &fixture
                    .journal
                    .snapshot(&fixture.cancel, deadline())
                    .unwrap()
            )
            .unwrap(),
            before
        );
        assert!(
            fixture
                .units
                .observe(
                    resource.contract.unit(),
                    &fixture.cancel,
                    deadline()
                )
                .is_err()
        );
        assert_no_manager_effects(&manager);
    }
}

#[test]
fn service_named_unit_recovers_binding_and_unit_file_as_distinct_resources() {
    let fixture = Fixture::new_with_transform(false, |source| {
        source.replace("id = \"probe\";", "id = \"unit\";")
    });
    let next = &fixture.resources["unit/worker"];
    let pin = next.binding.digest().unwrap();
    let binding_effect = publication(&fixture, "unit/worker", pin);
    fixture
        .installation
        .publish_launch_binding(
            &fixture.candidate,
            &next.binding,
            &fixture.cancel,
            deadline(),
        )
        .unwrap();
    let unit_pin = next.contract.file_digest();
    let unit_effect = publication(&fixture, "unit/unit/worker", unit_pin);
    fixture
        .units
        .publish(
            next.contract.unit(),
            &next.contract.render(),
            None,
            &fixture.cancel,
            deadline(),
        )
        .unwrap();
    let bytes = fs::read(next.binding.context().fragment()).unwrap();
    let mut manager = Fake::new(&fixture, Some(next.binding.clone()));
    let report = recover(&fixture, &mut manager);
    assert!(!report.needs_reconciliation, "{report:?}");
    assert_eq!(report.effects.len(), 2);
    assert_eq!(report.effects[0].resource, "unit/worker");
    assert_eq!(report.effects[1].resource, "unit/unit/worker");
    assert!(
        report
            .effects
            .iter()
            .all(|effect| effect.state == OsRecoveryState::Observed)
    );
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    for effect in [&binding_effect, &unit_effect] {
        assert!(matches!(
            snapshot.operations[&fixture.operation].effects[effect].state,
            EffectState::Observed { .. }
        ));
    }
    assert!(snapshot.bindings.is_empty());
    assert_eq!(
        fs::read(next.binding.context().fragment()).unwrap(),
        bytes
    );
    assert_no_manager_effects(&manager);
}

#[test]
fn absent_unit_publication_is_terminal_without_creating_or_authorizing_it() {
    let fixture = Fixture::new(false);
    let next = fixture.resources.values().next().unwrap();
    let effect = publication(
        &fixture,
        &format!("unit/{}", next.binding.process_key()),
        next.contract.file_digest(),
    );
    let mut manager = Fake::new(&fixture, Some(next.binding.clone()));
    let report = recover(&fixture, &mut manager);
    assert!(!report.needs_reconciliation, "{report:?}");
    assert_eq!(
        report.effects[0].state,
        OsRecoveryState::NotApplied
    );
    assert!(!next.binding.context().fragment().exists());
    let after = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert_eq!(
        after.operations[&fixture.operation].effects[&effect].state,
        EffectState::NotApplied
    );
    assert!(after.bindings.is_empty());
    assert_no_manager_effects(&manager);
}

#[test]
fn fenced_remote_effect_is_reported_without_observing_or_replaying_old_manager_work() {
    let mut fixture = started_fixture();
    let binding = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    fixture.operation = fixture
        .journal
        .begin(
            &fixture.candidate,
            Some(fixture.candidate.digest()),
            fixture.epoch.clone(),
            &fixture.cancel,
            deadline(),
        )
        .unwrap();
    let effect = fixture
        .journal
        .plan_effect(
            &fixture.operation,
            &binding.process_key(),
            EffectKind::Start,
            None,
            binding.digest().unwrap(),
            &fixture.cancel,
            deadline(),
        )
        .unwrap();
    fixture
        .journal
        .record_accepted(
            &fixture.operation,
            &effect,
            "/org/freedesktop/systemd1/job/99",
            &fixture.cancel,
            deadline(),
        )
        .unwrap();
    let mut current = fixture.epoch.clone();
    current.boot =
        crate::platform::linux::boot::BootId::parse("22222222-2222-4222-8222-222222222222")
            .unwrap();
    {
        let _guard = fixture
            .installation
            .execution(&fixture.cancel, deadline())
            .unwrap();
        fixture
            .journal
            .fence_previous_boot(
                &fixture.operation,
                &current,
                &fixture.cancel,
                deadline(),
            )
            .unwrap();
    }
    let mut manager = Fake::new(&fixture, Some(binding.clone()));
    let report = recover(&fixture, &mut manager);
    assert!(!report.needs_reconciliation, "{report:?}");
    assert_eq!(
        report.effects[0].state,
        OsRecoveryState::BootFenced
    );
    assert!(manager.calls.is_empty());
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert!(!snapshot.bindings[&binding.process_key()].authorized);
    assert!(
        matches!(&snapshot.operations[&fixture.operation].effects[&effect].state,
        EffectState::BootFenced { job: Some(job), .. } if job == "/org/freedesktop/systemd1/job/99")
    );
}

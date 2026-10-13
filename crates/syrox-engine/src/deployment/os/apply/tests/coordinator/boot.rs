use super::*;

fn select_new_boot(fixture: &mut Fixture, fence: bool) {
    fixture.epoch.boot =
        crate::platform::linux::boot::BootId::parse("22222222-2222-4222-8222-222222222222")
            .unwrap();
    fixture.epoch.manager = "new-boot-manager".into();
    if fence {
        fixture
            .journal
            .fence_previous_boot(
                &fixture.operation,
                &fixture.epoch,
                &fixture.cancel,
                deadline(),
            )
            .unwrap();
    }
    let units = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .context()
        .fragment()
        .parent()
        .unwrap()
        .to_owned();
    let store = Store::open_existing(fixture.paths.store()).unwrap();
    fixture.resources = prepare_resources(
        &ResourcePreparation {
            installation: &fixture.installation,
            generation: &fixture.candidate,
            store: &store,
            paths: &fixture.paths,
            units: &units,
            epoch: &fixture.epoch,
            scope: SystemdScope::System,
            uid: 1000,
            gid: 1000,
            start_timeout: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(10),
        },
        &fixture.cancel,
        deadline(),
    )
    .unwrap();
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
}

#[test]
fn fenced_boot_republishes_and_starts_without_stopping_or_adopting_old_invocation() {
    let mut fixture = started_fixture();
    let _execution = fixture
        .installation
        .execution(&fixture.cancel, deadline())
        .unwrap();
    let previous = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    select_new_boot(&mut fixture, true);
    let next = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    assert_ne!(previous.digest().unwrap(), next.digest().unwrap());
    let mut manager = Fake::new(&fixture, Some(next.clone()));
    manager.next_invocation = 8;
    let report = fixture.run(&mut manager, &fixture.resources);
    assert!(!report.needs_reconciliation, "{report:?}");
    assert_eq!(
        report.resources[0].state,
        OsApplyResourceState::Started
    );
    assert!(manager.calls.contains(&"idle"));
    let effects: Vec<_> = manager
        .calls
        .iter()
        .copied()
        .filter(|call| matches!(*call, "stop" | "reload" | "start"))
        .collect();
    assert_eq!(effects, ["reload", "start"]);
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert!(snapshot.boot_fenced(previous.epoch(), &fixture.epoch));
    let binding = &snapshot.bindings[&next.process_key()];
    assert!(binding.authorized);
    assert_eq!(binding.epoch, fixture.epoch);
    assert_eq!(binding.pin, next.digest().unwrap().to_string());
    fixture
        .installation
        .read_launch_binding(
            previous.digest().unwrap(),
            &fixture.cancel,
            deadline(),
        )
        .unwrap();
}

#[test]
fn new_boot_requires_fence_and_refuses_current_activity_or_job_without_mutations() {
    for (fenced, active, job) in [
        (false, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        let mut fixture = started_fixture();
        let _execution = fixture
            .installation
            .execution(&fixture.cancel, deadline())
            .unwrap();
        let previous = fixture
            .resources
            .values()
            .next()
            .unwrap()
            .binding
            .clone();
        let bytes = fs::read(previous.context().fragment()).unwrap();
        select_new_boot(&mut fixture, fenced);
        let next = fixture
            .resources
            .values()
            .next()
            .unwrap()
            .binding
            .clone();
        let mut manager = Fake::new(&fixture, Some(next));
        manager.started = active;
        manager.boot_job = job.then_some(1);
        let report = fixture.run(&mut manager, &fixture.resources);
        assert!(report.needs_reconciliation, "{report:?}");
        assert_eq!(
            report.resources[0].state,
            OsApplyResourceState::Pending
        );
        assert!(
            manager
                .calls
                .iter()
                .all(|call| !matches!(*call, "stop" | "reload" | "start"))
        );
        assert_eq!(
            fs::read(previous.context().fragment()).unwrap(),
            bytes
        );
        let snapshot = fixture
            .journal
            .snapshot(&fixture.cancel, deadline())
            .unwrap();
        assert_eq!(
            snapshot.bindings[&previous.process_key()].pin,
            previous.digest().unwrap().to_string()
        );
    }
}

#[test]
fn epoch_preflight_keeps_old_selection_recoverable_until_explicit_boot_fence() {
    let fixture = started_fixture();
    let _execution = fixture
        .installation
        .execution(&fixture.cancel, deadline())
        .unwrap();
    let before = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    let mut current = fixture.epoch.clone();
    current.boot =
        crate::platform::linux::boot::BootId::parse("22222222-2222-4222-8222-222222222222")
            .unwrap();
    current.manager = "new-manager".into();
    assert!(crate::deployment::os::apply::epoch_preflight(&before, &current).is_err());
    let mut changed_manager = fixture.epoch.clone();
    changed_manager.manager = "same-boot-new-manager".into();
    assert!(crate::deployment::os::apply::epoch_preflight(&before, &changed_manager).is_err());
    assert_eq!(
        fixture
            .journal
            .snapshot(&fixture.cancel, deadline())
            .unwrap()
            .active_operation,
        Some(fixture.operation.clone())
    );
    fixture
        .journal
        .fence_previous_boot(
            &fixture.operation,
            &current,
            &fixture.cancel,
            deadline(),
        )
        .unwrap();
    let after = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    crate::deployment::os::apply::epoch_preflight(&after, &current).unwrap();
}

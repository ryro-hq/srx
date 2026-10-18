use super::*;

#[test]
fn empty_generation_stops_only_recorded_invocation_and_retains_prior_generation() {
    let mut fixture = started_fixture();
    let binding = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    let previous = fixture.candidate.digest();
    let store = Store::open_existing(fixture.paths.store()).unwrap();
    let worker = fixture.directories[0].path().join("worker");
    fs::remove_file(fixture.directories[0].path().join("main.srx")).unwrap();
    fixture.candidate = fixture
        .installation
        .prepare_empty(
            LauncherIdentity::new(
                ContentDigest::sha256(b"coordinator candidate worker"),
                1,
            )
            .unwrap(),
            &store,
            &worker,
            &fixture.cancel,
            deadline(),
        )
        .unwrap();
    assert!(fixture.candidate.manifest().processes.is_empty());
    fixture.operation = fixture
        .journal
        .begin(
            &fixture.candidate,
            Some(previous),
            fixture.epoch.clone(),
            &fixture.cancel,
            deadline(),
        )
        .unwrap();
    fixture.resources.clear();
    let mut manager = Fake::new(&fixture, Some(binding.clone()));
    manager.started = true;
    let report = fixture.run(&mut manager, &fixture.resources);
    assert!(!report.needs_reconciliation, "{report:?}");
    assert_eq!(report.resources.len(), 1);
    assert_eq!(
        report.resources[0].state,
        OsApplyResourceState::Stopped
    );
    assert_eq!(
        manager
            .calls
            .iter()
            .filter(|call| matches!(**call, "stop" | "start" | "reload"))
            .copied()
            .collect::<Vec<_>>(),
        ["stop"]
    );
    assert!(!manager.started);
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert_eq!(
        snapshot.desired,
        Some(fixture.candidate.digest().to_string())
    );
    assert!(!snapshot.bindings[&binding.process_key()].authorized);
    assert!(snapshot.operations[&fixture.operation].terminal());
    assert!(
        fixture
            .installation
            .open(&store, previous, &fixture.cancel, deadline())
            .is_ok()
    );
}

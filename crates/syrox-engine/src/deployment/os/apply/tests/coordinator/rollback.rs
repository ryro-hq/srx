use super::*;
use crate::deployment::os::activation::OperationKind;
use crate::deployment::os::apply::preparation::reopen_resources;

fn select_retained_rollback(fixture: &mut Fixture, target: ContentDigest) {
    let previous = fixture.candidate.digest();
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
    fixture.candidate = fixture
        .installation
        .open(&store, target, &fixture.cancel, deadline())
        .unwrap();
    let input = ResourcePreparation {
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
    };
    fixture.resources = reopen_resources(&input, &fixture.cancel, deadline()).unwrap();
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert!(
        prepare_conservation(
            &input,
            &fixture.resources,
            &snapshot,
            &fixture.cancel,
            deadline()
        )
        .unwrap()
        .is_empty()
    );
    fixture.operation = fixture
        .journal
        .begin_rollback(
            &fixture.candidate,
            previous,
            fixture.epoch.clone(),
            &fixture.cancel,
            deadline(),
        )
        .unwrap();
}

fn replace_running(fixture: &Fixture, previous: u8, next: u8) {
    let binding = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    let mut manager = Fake::new(fixture, Some(binding.clone()));
    manager.started = true;
    manager.invocation = previous;
    manager.next_invocation = next;
    let report = fixture.run(&mut manager, &fixture.resources);
    assert!(!report.needs_reconciliation, "{report:?}");
    assert_eq!(
        report.resources[0].state,
        OsApplyResourceState::Started
    );
    assert_eq!(manager.invocation, next);
    let mutations: Vec<_> = manager
        .calls
        .iter()
        .copied()
        .filter(|call| matches!(*call, "stop" | "reload" | "start"))
        .collect();
    assert_eq!(mutations, ["stop", "reload", "start"]);
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    let recorded = &snapshot.bindings[&binding.process_key()];
    assert!(recorded.authorized);
    assert_eq!(
        recorded.pin,
        binding.digest().unwrap().to_string()
    );
    assert_eq!(
        recorded.generation,
        fixture.candidate.digest().to_string()
    );
    assert!(
        snapshot.operations[&fixture.operation]
            .effects
            .values()
            .all(|effect| matches!(effect.state, EffectState::Observed { .. }))
    );
}

#[test]
fn rollback_reopens_a_after_b_and_restores_immutable_configuration_without_project() {
    let mut fixture = started_fixture();
    let _execution = fixture
        .installation
        .execution(&fixture.cancel, deadline())
        .unwrap();
    let target = fixture.candidate.digest();
    let original = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    let original_unit = fs::read(original.context().fragment()).unwrap();
    let external = fixture.paths.cwd().join("user-data");
    fs::write(&external, b"external mutable data").unwrap();
    assert_eq!(
        fs::read(original.configuration().join("nested/config")).unwrap(),
        b"controlled"
    );

    let preserved = fixture.next_candidate_with_transform(|source| {
        assert!(source.contains(r#"text = "controlled""#));
        source.replace(
            r#"text = "controlled""#,
            r#"text = "candidate B""#,
        )
    });
    assert!(preserved.is_empty());
    let generation_b = fixture.candidate.digest();
    let binding_b = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    assert_ne!(
        original.configuration(),
        binding_b.configuration()
    );
    assert_eq!(
        fs::read(binding_b.configuration().join("nested/config")).unwrap(),
        b"candidate B"
    );
    replace_running(&fixture, 7, 8);

    // Keep the Store and installation, remove the original authored projects and
    // launcher sources. Rollback must reopen retained snapshots exclusively.
    for directory in &fixture.directories {
        for name in ["main.srx", "Syrox.lock", "worker"] {
            let path = directory.path().join(name);
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }
    select_retained_rollback(&mut fixture, target);
    let restored = &fixture.resources.values().next().unwrap().binding;
    assert_eq!(
        restored.digest().unwrap(),
        original.digest().unwrap()
    );
    assert_eq!(restored.configuration(), original.configuration());
    replace_running(&fixture, 8, 9);
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    let operation = &snapshot.operations[&fixture.operation];
    assert_eq!(operation.kind, OperationKind::Rollback);
    assert_eq!(operation.previous, Some(generation_b.to_string()));
    assert_eq!(snapshot.desired, Some(target.to_string()));
    let status = crate::deployment::os::inspect_os_status(
        fixture.paths.installation(),
        &fixture.cancel,
        deadline(),
    )
    .unwrap();
    assert_eq!(status.active_kind, Some("rollback"));
    assert_eq!(
        fs::read(original.context().fragment()).unwrap(),
        original_unit
    );
    assert_eq!(
        fs::read(original.configuration().join("nested/config")).unwrap(),
        b"controlled"
    );
    assert_eq!(
        fs::read(binding_b.configuration().join("nested/config")).unwrap(),
        b"candidate B"
    );
    assert_eq!(
        fs::read(external).unwrap(),
        b"external mutable data"
    );
}

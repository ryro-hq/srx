use super::*;

#[test]
fn lock_is_idempotent_and_detects_project_drift() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 42; }",
    );

    let created = lock_project(&project.0).unwrap();
    assert_eq!(created.status(), lock::LockStatus::Created);
    let first = fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    assert_eq!(
        lock_project(&project.0).unwrap().status(),
        lock::LockStatus::Unchanged
    );
    assert_eq!(
        fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap(),
        first
    );
    assert_eq!(
        check_project_lock(&project.0).unwrap().status(),
        lock::LockStatus::Unchanged
    );

    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 43; }",
    );
    assert!(matches!(
        check_project_lock(&project.0),
        Err(ProjectOperationError::ProjectDrift)
    ));
    assert_eq!(
        lock_project(&project.0).unwrap().status(),
        lock::LockStatus::Updated
    );
}

#[test]
fn lock_detects_input_and_standard_library_drift() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); inputs { dep = \"path:dep\"; } outputs { answer: Number = 42; }",
    );
    project.write("dep/a.srx", "value Name(str);");
    lock_project(&project.0).unwrap();
    project.write("dep/a.srx", "value Other(str);");
    assert!(matches!(
        check_project_lock(&project.0),
        Err(ProjectOperationError::ProjectDrift)
    ));

    project.write("dep/a.srx", "value Name(str);");
    let source =
        AuthenticatedStandardSource::from_authenticated("std.srx", "value Std(str);").unwrap();
    let configured = CheckConfiguration {
        standard_library: Some(
            AuthenticatedStandardLibrary::from_authenticated(vec![source]).unwrap(),
        ),
        ..CheckConfiguration::default()
    };
    assert!(matches!(
        check_project_lock_with(&project.0, &configured),
        Err(ProjectOperationError::StandardLibraryDrift)
    ));
}

#[test]
fn locked_operations_reject_scope_and_erasure_policies() {
    let identity = |name| CanonicalItemIdentity::new(SourceDomainId::project(), [name]).unwrap();
    let policies = [
        CheckPolicy::new("scope")
            .unwrap()
            .with_scope("network")
            .unwrap(),
        CheckPolicy::new("erasure")
            .unwrap()
            .with_erasure(identity("Private"), identity("Public"))
            .unwrap(),
    ];
    for policy in policies {
        let configuration = CheckConfiguration {
            environment: EvaluationEnvironment::new(&policy),
            policy,
            ..CheckConfiguration::default()
        };
        assert!(matches!(
            lock_project_with(Path::new("unused"), &configuration),
            Err(ProjectOperationError::PolicyProvenanceRequired)
        ));
        assert!(matches!(
            check_project_lock_with(Path::new("unused"), &configuration),
            Err(ProjectOperationError::PolicyProvenanceRequired)
        ));
        assert!(matches!(
            plan_project_with(Path::new("unused"), &configuration),
            Err(ProjectOperationError::PolicyProvenanceRequired)
        ));
    }
}

#[test]
fn lock_rejects_an_environment_for_a_different_policy() {
    let environment_policy = CheckPolicy::new("other").unwrap();
    let configuration = CheckConfiguration {
        environment: EvaluationEnvironment::new(&environment_policy),
        ..CheckConfiguration::default()
    };
    assert!(matches!(
        lock_project_with(Path::new("unused"), &configuration),
        Err(ProjectOperationError::PolicyProvenanceRequired)
    ));
}

#[test]
fn generated_lock_size_failure_has_a_distinct_operation_error() {
    assert!(matches!(
        map_generated_lock_error(lock::LockFormatError::TooLarge),
        ProjectOperationError::GeneratedLockTooLarge
    ));
}

#[test]
fn lock_regenerates_a_lock_written_by_an_earlier_format() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 42; }",
    );
    assert_eq!(
        lock_project(&project.0).unwrap().status(),
        lock::LockStatus::Created
    );
    let current = fs::read_to_string(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    let earlier = current.replacen("edges 0\nassets 0\n", "", 1);
    project.write(lock::LOCK_FILE_NAME, &earlier);
    let error = check_project_lock(&project.0).unwrap_err();
    assert!(matches!(
        error,
        ProjectOperationError::MalformedLock {
            source: lock::LockFormatError::EarlierFormat
        }
    ));
    assert!(
        error
            .to_string()
            .contains("run `srx project lock`")
    );
    assert_eq!(
        lock_project(&project.0).unwrap().status(),
        lock::LockStatus::Updated
    );
    assert_eq!(
        fs::read_to_string(project.0.join(lock::LOCK_FILE_NAME)).unwrap(),
        current
    );
}

#[test]
fn lock_refuses_missing_malformed_symlink_nonregular_and_hardlinked_destinations() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 42; }",
    );
    assert!(matches!(
        check_project_lock(&project.0),
        Err(ProjectOperationError::MissingLock { .. })
    ));

    project.write(lock::LOCK_FILE_NAME, "not a lock\n");
    assert!(matches!(
        lock_project(&project.0),
        Err(ProjectOperationError::MalformedLock { .. })
    ));
    fs::remove_file(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    fs::create_dir(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    assert!(matches!(
        lock_project(&project.0),
        Err(ProjectOperationError::LockNonRegular)
    ));
    fs::remove_dir(project.0.join(lock::LOCK_FILE_NAME)).unwrap();

    project.write("target", "not a lock\n");
    symlink("target", project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    assert!(matches!(
        lock_project(&project.0),
        Err(ProjectOperationError::LockSymlink)
    ));
    fs::remove_file(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    fs::hard_link(
        project.0.join("target"),
        project.0.join(lock::LOCK_FILE_NAME),
    )
    .unwrap();
    assert!(matches!(
        lock_project(&project.0),
        Err(ProjectOperationError::LockHardLinked)
    ));
}

#[test]
fn lock_failure_before_rename_preserves_the_previous_bytes() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 1; }",
    );
    lock_project(&project.0).unwrap();
    let previous = fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 2; }",
    );
    crate::platform::linux::fd::fail_next_lock_before_rename();

    let error = lock_project(&project.0).unwrap_err();

    assert!(matches!(
        error,
        ProjectOperationError::LockPublication(LockPublicationError::BeforeRename { .. })
    ));
    assert_eq!(
        fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap(),
        previous
    );
    assert_eq!(fs::read_dir(&project.0).unwrap().count(), 2);
}

#[test]
fn graph_lock_failure_before_rename_preserves_the_whole_previous_manifest() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(child.join("main.srx"), "pub struct X {}").unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { child = \"path:../child\"; }",
    )
    .unwrap();
    lock_project(&child).unwrap();
    lock_project(&consumer).unwrap();
    let previous = fs::read(consumer.join(lock::LOCK_FILE_NAME)).unwrap();
    assert!(previous.starts_with(b"syrox-lock\n"));
    assert!(!consumer.join("Syrox.graph.lock").exists());
    fs::write(
        child.join("main.srx"),
        "pub struct X {} // changed",
    )
    .unwrap();
    lock_project(&child).unwrap();
    crate::platform::linux::fd::fail_next_lock_before_rename();
    assert!(matches!(
        lock_project(&consumer),
        Err(ProjectOperationError::LockPublication(
            LockPublicationError::BeforeRename { .. }
        ))
    ));
    assert_eq!(
        fs::read(consumer.join(lock::LOCK_FILE_NAME)).unwrap(),
        previous
    );
    assert!(!consumer.join("Syrox.graph.lock").exists());
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::GraphDrift)
    ));
    lock_project(&consumer).unwrap();
    check_project_lock(&consumer).unwrap();
}

#[test]
fn legacy_sidecar_requires_relock_and_is_removed_after_single_manifest_publication() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(child.join("main.srx"), "pub struct X {}").unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { child = \"path:../child\"; }",
    )
    .unwrap();
    lock_project(&child).unwrap();
    lock_project(&consumer).unwrap();
    let current = fs::read(consumer.join(lock::LOCK_FILE_NAME)).unwrap();
    let expected = lock::graph::GraphLock::generate([0; 32], vec![]).unwrap();
    fs::write(consumer.join("Syrox.graph.lock"), expected.data()).unwrap();
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::GraphDrift)
    ));
    assert!(matches!(
        lock_project(&consumer).unwrap().status(),
        lock::LockStatus::Updated
    ));
    assert!(!consumer.join("Syrox.graph.lock").exists());
    assert_eq!(
        fs::read(consumer.join(lock::LOCK_FILE_NAME)).unwrap(),
        current
    );
    check_project_lock(&consumer).unwrap();
}

#[test]
fn lock_failure_after_rename_reports_uncertainty_and_keeps_new_bytes() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 1; }",
    );
    lock_project(&project.0).unwrap();
    let previous = fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 2; }",
    );
    crate::platform::linux::fd::fail_next_lock_after_rename();

    let error = lock_project(&project.0).unwrap_err();

    assert!(matches!(
        error,
        ProjectOperationError::LockPublicationUncertain { .. }
    ));
    assert_ne!(
        fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap(),
        previous
    );
    check_project_lock(&project.0).unwrap();
    assert_eq!(fs::read_dir(&project.0).unwrap().count(), 2);
}

#[test]
fn lock_failure_preserves_the_primary_and_cleanup_sync_errors() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 1; }",
    );
    lock_project(&project.0).unwrap();
    let previous = fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 2; }",
    );
    crate::platform::linux::fd::fail_next_lock_before_rename();
    crate::platform::linux::fd::fail_next_lock_cleanup_sync();

    let error = lock_project(&project.0).unwrap_err();
    let ProjectOperationError::LockPublication(LockPublicationError::CleanupFailed {
        source,
        cleanup,
    }) = error
    else {
        panic!("expected primary and cleanup failures");
    };

    assert_eq!(
        source.to_string(),
        "injected lock failure before rename"
    );
    let LockCleanupError::Synchronization {
        source,
    } = cleanup
    else {
        panic!("expected cleanup synchronization failure");
    };
    assert_eq!(
        source.to_string(),
        "injected lock cleanup sync failure"
    );
    assert_eq!(
        fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap(),
        previous
    );
    assert_eq!(fs::read_dir(&project.0).unwrap().count(), 2);
}

#[test]
fn lock_io_stays_relative_to_retained_root_after_path_swap() {
    let project = TempProject::new();
    project.write("main.srx", "value Number(int);");
    let loaded = loader::load_project_linux(&project.0, &CheckConfiguration::default()).unwrap();
    let moved = project.0.with_extension("opened");
    fs::rename(&project.0, &moved).unwrap();
    fs::create_dir(&project.0).unwrap();

    crate::platform::linux::fd::write_atomic_beneath(
        loaded.root.fd(),
        Path::new(lock::LOCK_FILE_NAME),
        b"retained\n",
    )
    .unwrap();
    assert_eq!(
        fs::read(moved.join(lock::LOCK_FILE_NAME)).unwrap(),
        b"retained\n"
    );
    assert!(!project.0.join(lock::LOCK_FILE_NAME).exists());

    fs::remove_dir(&project.0).unwrap();
    fs::rename(moved, &project.0).unwrap();
}

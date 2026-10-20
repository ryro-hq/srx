use super::*;

const EMPTY: &str = "outputs { os: Os = Os { pkgs = []; services = []; }; }";

#[test]
fn root_refresh_retains_dependencies_and_prepares_the_edited_snapshot() {
    let project = TempProject::new();
    project.write("lib/main.srx", "pub value Port(int);");
    let initial = format!("inputs {{ lib = \"modules:lib\"; }} {EMPTY}");
    project.write("main.srx", &initial);
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let before = fs::read(project.0.join("Syrox.lock")).unwrap();
    project.write(
        "main.srx",
        &initial.replace(
            "services = []",
            "services = [Service { id = \"web\"; }]",
        ),
    );
    assert!(matches!(
        prepare_project_consumer_with(&project.0, &config, "os"),
        Err(ProjectOperationError::ProjectDrift)
    ));
    let prepared = prepare_project_consumer_refresh_root_with(&project.0, &config, "os").unwrap();
    assert_eq!(
        prepared
            .plan()
            .consumers()
            .next()
            .unwrap()
            .services()[0]
            .id(),
        "web"
    );
    assert_ne!(
        fs::read(project.0.join("Syrox.lock")).unwrap(),
        before
    );
    check_project_lock_with(&project.0, &config).unwrap();
    // A subsequent editor write does not alter the plan used for realization.
    project.write("main.srx", &initial);
    assert_eq!(
        prepared
            .plan()
            .consumers()
            .next()
            .unwrap()
            .services()
            .len(),
        1
    );
    assert!(matches!(
        check_project_lock_with(&project.0, &config),
        Err(ProjectOperationError::ProjectDrift)
    ));
}

#[test]
fn root_refresh_rejects_module_assets_standard_library_and_input_changes() {
    let project = TempProject::new();
    project.write("lib/main.srx", "pub value Port(int);");
    let source = format!("inputs {{ lib = \"modules:lib\"; }} {EMPTY}");
    project.write("main.srx", &source);
    project.write("assets/data", "original");
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let before = fs::read(project.0.join("Syrox.lock")).unwrap();
    for (path, changed, original) in [
        (
            "lib/main.srx",
            "pub value Port(int); // edit",
            "pub value Port(int);",
        ),
        ("assets/data", "changed", "original"),
        ("main.srx", EMPTY, source.as_str()),
    ] {
        project.write(path, changed);
        assert!(prepare_project_consumer_refresh_root_with(&project.0, &config, "os").is_err());
        assert_eq!(
            fs::read(project.0.join("Syrox.lock")).unwrap(),
            before
        );
        project.write(path, original);
    }
    assert!(matches!(
        prepare_project_consumer_refresh_root_with(
            &project.0,
            &CheckConfiguration::default(),
            "os"
        ),
        Err(ProjectOperationError::StandardLibraryDrift)
    ));
    assert_eq!(
        fs::read(project.0.join("Syrox.lock")).unwrap(),
        before
    );
}

#[test]
fn root_refresh_requires_lock_and_successful_selection_and_serializes_writers() {
    let project = TempProject::new();
    project.write("main.srx", EMPTY);
    let config = package_configuration();
    assert!(matches!(
        prepare_project_consumer_refresh_root_with(&project.0, &config, "os"),
        Err(ProjectOperationError::MissingLock { .. })
    ));
    lock_project_with(&project.0, &config).unwrap();
    let before = fs::read(project.0.join("Syrox.lock")).unwrap();
    project.write("main.srx", &format!("{EMPTY} // edit"));
    assert!(matches!(
        prepare_project_consumer_refresh_root_with(&project.0, &config, "missing"),
        Err(ProjectOperationError::MissingOutput { .. })
    ));
    assert_eq!(
        fs::read(project.0.join("Syrox.lock")).unwrap(),
        before
    );
    let guard = super::super::refresh::lock_root(&project.0).unwrap();
    assert!(matches!(
        prepare_project_consumer_refresh_root_with(&project.0, &config, "os"),
        Err(ProjectOperationError::LockBusy)
    ));
    assert!(matches!(
        lock_project_with(&project.0, &config),
        Err(ProjectOperationError::LockBusy)
    ));
    drop(guard);
    prepare_project_consumer_refresh_root_with(&project.0, &config, "os").unwrap();
}

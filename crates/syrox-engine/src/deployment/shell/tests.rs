use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;

pub(super) fn configuration_plan() -> (tempfile::TempDir, PreparedPlan) {
    let project = tempfile::tempdir().unwrap();
    fs::write(project.path().join("main.srx"), r#"
        outputs { shell: std::Shell = std::Shell { pkgs = []; services = [
            std::Service { id = "git"; files = [std::ConfigFile { path = "nested/gitconfig"; text = "[user]\nname = declared\n"; }]; },
            std::Service { id = "other"; files = [std::ConfigFile { path = "nested/gitconfig"; text = "independent"; }]; }
        ]; }; }
    "#).unwrap();
    let checks = crate::project::CheckConfiguration {
        standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
        ..crate::project::CheckConfiguration::default()
    };
    crate::project::lock_project_with(project.path(), &checks).unwrap();
    let prepared =
        crate::project::prepare_project_consumer_with(project.path(), &checks, "shell").unwrap();
    (project, prepared)
}

#[test]
fn configuration_materializes_privately_and_readonly_then_cleans_up() {
    let (_project, plan) = configuration_plan();
    let selection = crate::deployment::manifest::select_consumer(&plan, "shell").unwrap();
    let files = files::SessionFiles::new(selection.consumer(), &Cancellation::default()).unwrap();
    let root = files.path().to_path_buf();
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::read_to_string(root.join("git/nested/gitconfig")).unwrap(),
        "[user]\nname = declared\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("other/nested/gitconfig")).unwrap(),
        "independent"
    );
    assert_eq!(
        fs::metadata(root.join("git/nested"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o500
    );
    assert_eq!(
        fs::metadata(root.join("git/nested/gitconfig"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o400
    );
    let config = RuntimeConfiguration::new(
        "git",
        files.service("git").unwrap(),
        BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(config.prefix(), Some("/syrox/config/git"));
    drop(config);
    files.close().unwrap();
    assert!(!root.exists());
}

#[test]
fn session_drop_restores_its_own_directory_permissions_before_cleanup() {
    let (_project, plan) = configuration_plan();
    let selection = crate::deployment::manifest::select_consumer(&plan, "shell").unwrap();
    let files = files::SessionFiles::new(selection.consumer(), &Cancellation::default()).unwrap();
    let root = files.path().to_path_buf();
    drop(files);
    assert!(!root.exists());
    let cancelled = Cancellation::default();
    cancelled.cancel();
    assert!(files::SessionFiles::new(selection.consumer(), &cancelled).is_err());
}

#[test]
fn arguments_are_literal_and_file_bindings_use_only_logical_service_paths() {
    let literal = "$(touch /tmp/never) $HOME; 'quoted'";
    assert_eq!(
        render(
            &PlanCommandArgument::Literal(literal.into()),
            None
        )
        .unwrap(),
        literal
    );
    assert_eq!(
        render(
            &PlanCommandArgument::File("nested/config".into()),
            Some("git")
        )
        .unwrap(),
        "/syrox/config/git/nested/config"
    );
    assert!(matches!(
        render(&PlanCommandArgument::File("config".into()), None),
        Err(SessionError::MissingNamespace)
    ));
}

#[test]
fn direct_shell_rejects_session_state_before_configuration_materialization() {
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join("main.srx"),
        r#"
        outputs { shell: std::Shell = std::Shell { pkgs = []; services = [
            std::Service { id = "cache"; state = std::ServiceState::Session; }
        ]; }; }
    "#,
    )
    .unwrap();
    let checks = crate::project::CheckConfiguration {
        standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
        ..crate::project::CheckConfiguration::default()
    };
    crate::project::lock_project_with(project.path(), &checks).unwrap();
    let prepared =
        crate::project::prepare_project_consumer_with(project.path(), &checks, "shell").unwrap();
    let selected = crate::deployment::manifest::select_consumer(&prepared, "shell").unwrap();
    assert!(matches!(
        validate_consumer(selected.consumer()),
        Err(SessionError::StateUnsupported)
    ));
    assert_eq!(
        render(
            &PlanCommandArgument::StateDirectory,
            Some("cache")
        )
        .unwrap(),
        "/syrox/state/cache"
    );
    assert!(matches!(
        render(&PlanCommandArgument::StateDirectory, None),
        Err(SessionError::MissingNamespace)
    ));
}

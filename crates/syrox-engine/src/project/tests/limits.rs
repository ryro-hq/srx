use super::*;

#[test]
fn every_configurable_project_limit_has_a_hard_maximum() {
    let limits = [
        ProjectLimits {
            max_total_bytes: MAX_PROJECT_BYTES + 1,
            ..ProjectLimits::default()
        },
        ProjectLimits {
            max_sources: MAX_SOURCES + 1,
            ..ProjectLimits::default()
        },
        ProjectLimits {
            max_directory_entries: MAX_DIRECTORY_ENTRIES + 1,
            ..ProjectLimits::default()
        },
        ProjectLimits {
            max_work: MAX_PROJECT_WORK + 1,
            ..ProjectLimits::default()
        },
        ProjectLimits {
            max_directory_depth: MAX_DIRECTORY_DEPTH + 1,
            ..ProjectLimits::default()
        },
    ];
    for project_limits in limits {
        let configuration = CheckConfiguration {
            project_limits,
            ..CheckConfiguration::default()
        };
        assert!(matches!(
            check_project_with(Path::new("unused"), &configuration).unwrap_err(),
            CheckFailure::InvalidProjectLimit { .. }
        ));
    }
}

#[test]
fn zero_work_rejects_a_main_only_project_before_opening_it() {
    let project = TempProject::new();
    project.write("main.srx", "value V(str);");
    let mut configuration = CheckConfiguration::default();
    configuration.project_limits.max_work = 0;

    assert!(matches!(
        check_project_with(&project.0, &configuration).unwrap_err(),
        CheckFailure::WorkLimit {
            limit: 0
        }
    ));
}

#[test]
fn configurable_total_byte_and_work_limits_fail_closed() {
    let project = TempProject::new();
    project.write("main.srx", "inputs { dep = \"path:dep\"; }");
    project.write("dep/a.srx", "value V(str);");

    let mut configuration = CheckConfiguration::default();
    configuration.project_limits.max_total_bytes = 1;
    assert!(matches!(
        check_project_with(&project.0, &configuration).unwrap_err(),
        CheckFailure::ProjectTooLarge { .. }
    ));

    configuration.project_limits.max_total_bytes = MAX_PROJECT_BYTES;
    configuration.project_limits.max_work = 0;
    assert!(matches!(
        check_project_with(&project.0, &configuration).unwrap_err(),
        CheckFailure::WorkLimit { .. }
    ));
}

#[test]
fn directory_entry_limit_rejects_during_enumeration_without_changing_later_output() {
    let project = TempProject::new();
    project.write("main.srx", "inputs { dep = \"path:dep\"; }");
    project.write("dep/z.srx", "value Z(str);");
    project.write("dep/a.srx", "value A(str);");
    let mut configuration = CheckConfiguration::default();
    configuration.project_limits.max_directory_entries = 1;

    assert!(matches!(
        check_project_with(&project.0, &configuration).unwrap_err(),
        CheckFailure::TooManyDirectoryEntries {
            limit: 1
        }
    ));

    let loaded = loader::load_project_linux(&project.0, &CheckConfiguration::default()).unwrap();
    let paths: Vec<_> = loaded
        .inputs()
        .next()
        .unwrap()
        .files()
        .map(|source| source.relative_path().to_path_buf())
        .collect();
    assert_eq!(
        paths,
        [
            PathBuf::from("a.srx"),
            PathBuf::from("z.srx")
        ]
    );
}

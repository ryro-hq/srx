use super::*;

#[test]
fn failed_root_without_diagnostic_capacity_is_still_an_evaluation_failure() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "resource R(int); outputs { bad: [R] = [R(1), R(1)]; }",
    );
    let mut configuration = CheckConfiguration::default();
    configuration.evaluation_limits.max_diagnostics = 0;
    let error = check_path_with(&project.0.join("main.srx"), &configuration).unwrap_err();
    let CheckFailure::Evaluation {
        errors,
        failed_roots,
        ..
    } = error
    else {
        panic!("expected structured evaluation failure");
    };
    assert!(errors.is_empty());
    assert_eq!(failed_roots, ["bad"]);
}

#[test]
fn evaluation_setup_failure_is_structured() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value V(int); outputs { out: V = 1; }",
    );
    let mut configuration = CheckConfiguration::default();
    configuration.evaluation_limits.max_setup_steps = 0;
    let error = check_path_with(&project.0.join("main.srx"), &configuration).unwrap_err();
    assert!(matches!(
        error,
        CheckFailure::EvaluationSetup {
            source: EvaluationSetupError::SetupWorkLimit
        }
    ));
}

#[test]
fn package_graph_errors_are_structured_and_deterministic() {
    let homonyms = package_plan(&recipe_graph_source(&[
        ("z", "same", &[]),
        ("a", "same", &[]),
    ]))
    .unwrap();
    assert_eq!(homonyms.packages().len(), 2);
    assert_ne!(
        homonyms.packages().next().unwrap().id(),
        homonyms.packages().last().unwrap().id()
    );

    let duplicate_edge = package_plan(&recipe_graph_source(&[
        ("app", "app", &["lib", "lib"]),
        ("lib", "lib", &[]),
    ]))
    .unwrap_err();
    assert!(matches!(
        duplicate_edge,
        ProjectOperationError::Plan(crate::plan::PlanError::DuplicateDependency {
            ref package,
            ref dependency,
        }) if package.as_str() == "app" && dependency.as_str() == "lib"
    ));

    let missing_source = recipe_graph_source(&[("app", "app", &["missing"])]).replace(
        "mod catalog {",
        "mod catalog { mod missing { pub fn recipe() -> std::Recipe { recipe() } }",
    );
    let missing = package_plan(&missing_source).unwrap_err();
    assert!(matches!(
        missing,
        ProjectOperationError::Check(CheckFailure::Evaluation { .. })
    ));
}

#[test]
fn package_ids_and_cycle_witnesses_are_canonical() {
    let invalid_ids = [
        String::new(),
        "Upper".to_owned(),
        "a/b".to_owned(),
        "é".to_owned(),
        "a".repeat(256),
    ];
    for invalid in invalid_ids {
        let source = recipe_graph_source(&[("p", &invalid, &[])]);
        assert!(matches!(
            package_plan(&source),
            Err(ProjectOperationError::Plan(
                crate::plan::PlanError::InvalidPackageId { .. }
            ))
        ));
    }

    let self_cycle = package_plan(&recipe_graph_source(&[(
        "self_node",
        "self",
        &["self_node"],
    )]))
    .unwrap_err();
    assert!(matches!(
        self_cycle,
        ProjectOperationError::Plan(crate::plan::PlanError::Cycle { ref packages })
            if packages.iter().map(crate::plan::PlanPackageId::as_str).collect::<Vec<_>>() == ["self"]
    ));

    let cycle = package_plan(&recipe_graph_source(&[
        ("c", "c", &["b"]),
        ("a", "a", &["c"]),
        ("b", "b", &["a"]),
    ]))
    .unwrap_err();
    assert!(matches!(
        cycle,
        ProjectOperationError::Plan(crate::plan::PlanError::Cycle { ref packages })
            if packages.iter().map(crate::plan::PlanPackageId::as_str).collect::<Vec<_>>() == ["a", "c", "b"]
    ));
}

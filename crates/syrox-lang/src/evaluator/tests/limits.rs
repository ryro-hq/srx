use super::*;

#[test]
fn comparison_charges_string_bytes_to_the_work_budget() {
    let policy = CheckPolicy::default();
    let text = "x".repeat(1024);
    let program = checked(
        &format!(
            r#"value I(int); outputs {{ out: I = compare("{text}", "{text}", I(1), I(2), I(3)); }}"#
        ),
        &policy,
    );
    let result = evaluate_with_limits(
        &program,
        &policy,
        &EvaluationEnvironment::new(&policy),
        EvaluationLimits {
            max_steps_per_root: 512,
            ..EvaluationLimits::default()
        },
    )
    .unwrap();
    assert!(
        result
            .roots()
            .next()
            .unwrap()
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message.contains("step limit")),
        "{result:?}"
    );
}

#[test]
fn fold_and_generic_recursion_obey_evaluation_limits() {
    let policy = CheckPolicy::default();
    let recursive = run(
        "value I(int); fn looped<T>(x: T) -> T { looped<T>(x) } outputs { limited: I = looped<I>(I(1)); }",
        &policy,
    );
    assert!(!recursive.is_success());
    assert!(
        recursive
            .roots()
            .next()
            .unwrap()
            .diagnostics()
            .iter()
            .any(|error| error.message.contains("depth"))
    );
    let items = vec!["I(1)"; 200].join(",");
    let checked = checked(
        &format!(
            "value I(int); fn last(acc: I, item: I) -> I {{ item }} outputs {{ selected: I = fold([{items}], I(0), last); }}"
        ),
        &policy,
    );
    let limited = evaluate_with_limits(
        &checked,
        &policy,
        &EvaluationEnvironment::new(&policy),
        EvaluationLimits {
            max_total_steps: 450,
            ..EvaluationLimits::default()
        },
    );
    assert!(matches!(
        limited,
        Err(EvaluationSetupError::EvaluationWorkLimit)
    ));
}

#[test]
fn refinement_comparisons_consume_the_evaluation_work_budget() {
    let policy = CheckPolicy::default();
    let environment = EvaluationEnvironment::new(&policy);
    let limits = EvaluationLimits {
        max_total_steps: 30,
        ..EvaluationLimits::default()
    };
    let short = checked(
        "value V(int) where in [1]; outputs { v: V = 1; }",
        &policy,
    );
    assert!(
        evaluate_with_limits(&short, &policy, &environment, limits)
            .unwrap()
            .is_success()
    );

    let entries = (0..40)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let many = checked(
        &format!("value V(int) where in [{entries}]; outputs {{ v: V = 39; }}"),
        &policy,
    );
    assert!(matches!(
        evaluate_with_limits(&many, &policy, &environment, limits),
        Err(EvaluationSetupError::EvaluationWorkLimit)
    ));

    let text = "a".repeat(4096);
    let long = checked(
        &format!("value V(str) where in [\"{text}\"]; outputs {{ v: V = \"{text}\"; }}"),
        &policy,
    );
    assert!(matches!(
        evaluate_with_limits(&long, &policy, &environment, limits),
        Err(EvaluationSetupError::EvaluationWorkLimit)
    ));
}

#[test]
fn recursion_and_expansion_limits_do_not_poison_later_roots() {
    let source = "value I(int); fn forever() -> I { forever() } outputs { stuck: I = forever(); later: I = 7; }";
    let policy = CheckPolicy::default();
    let program = checked(source, &policy);
    let result = evaluate_with_limits(
        &program,
        &policy,
        &EvaluationEnvironment::new(&policy),
        EvaluationLimits {
            max_depth: 8,
            ..EvaluationLimits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        result.roots().next().unwrap().outcome(),
        RealizedRootOutcome::Failed(_)
    ));
    assert!(result.roots().nth(1).unwrap().value().is_some());

    let stepped = evaluate_with_limits(
        &program,
        &policy,
        &EvaluationEnvironment::new(&policy),
        EvaluationLimits {
            max_steps_per_root: 5,
            ..EvaluationLimits::default()
        },
    )
    .unwrap();
    assert!(
        stepped
            .roots()
            .next()
            .unwrap()
            .diagnostics()
            .iter()
            .any(|error| error.message.contains("step limit"))
    );

    let checked = checked(
        "value Name(str); fn copy(x: Name) -> [Name] { [x, x] } outputs { large: [Name] = copy(\"0123456789\"); }",
        &policy,
    );
    let expanded = evaluate_with_limits(
        &checked,
        &policy,
        &EvaluationEnvironment::new(&policy),
        EvaluationLimits {
            max_expansion_bytes: 32,
            ..EvaluationLimits::default()
        },
    )
    .unwrap();
    assert!(
        expanded
            .diagnostics()
            .any(|error| error.message.contains("expansion"))
    );
}

#[test]
fn setup_work_and_identity_allocations_are_bounded() {
    let policy = CheckPolicy::default();
    let module = format!("m{}", "x".repeat(4_096));
    let source = format!("mod {module} {{ value V(int); }} outputs {{ out: {module}::V = 1; }}");
    let program = checked(&source, &policy);
    let environment = EvaluationEnvironment::new(&policy);
    let realized = evaluate_with_limits(
        &program,
        &policy,
        &environment,
        EvaluationLimits {
            max_expansion_bytes: 512,
            ..EvaluationLimits::default()
        },
    )
    .unwrap();
    assert!(realized.is_success());
    assert_eq!(
        evaluate_with_limits(
            &program,
            &policy,
            &environment,
            EvaluationLimits {
                max_setup_steps: 0,
                ..EvaluationLimits::default()
            },
        )
        .unwrap_err(),
        EvaluationSetupError::SetupWorkLimit
    );
    assert_eq!(
        evaluate_with_limits(
            &program,
            &policy,
            &environment,
            EvaluationLimits {
                max_setup_bytes: 1,
                ..EvaluationLimits::default()
            },
        )
        .unwrap_err(),
        EvaluationSetupError::SetupExpansionLimit
    );
}

#[test]
fn evaluation_limits_cannot_exceed_hard_maxima() {
    let policy = CheckPolicy::new("different-policy").unwrap();
    let program = checked(
        "value I(int); outputs { out: I = 1; }",
        &CheckPolicy::default(),
    );
    let environment = EvaluationEnvironment::new(&policy);
    let maxima = [
        (
            EvaluationLimit::SetupSteps,
            MAX_EVALUATION_SETUP_STEPS,
        ),
        (
            EvaluationLimit::SetupBytes,
            MAX_EVALUATION_SETUP_BYTES,
        ),
        (
            EvaluationLimit::TotalSteps,
            MAX_EVALUATION_TOTAL_STEPS,
        ),
        (
            EvaluationLimit::StepsPerRoot,
            MAX_EVALUATION_STEPS,
        ),
        (EvaluationLimit::Depth, MAX_EVALUATION_DEPTH),
        (
            EvaluationLimit::ExpansionBytes,
            MAX_EVALUATION_EXPANSION,
        ),
        (
            EvaluationLimit::RetainedExpansionBytes,
            MAX_EVALUATION_RETAINED_EXPANSION,
        ),
        (
            EvaluationLimit::Diagnostics,
            crate::MAX_DIAGNOSTICS,
        ),
    ];

    for (limit, maximum) in maxima {
        let configured = maximum + 1;
        let mut limits = EvaluationLimits::default();
        match limit {
            EvaluationLimit::SetupSteps => limits.max_setup_steps = configured,
            EvaluationLimit::SetupBytes => limits.max_setup_bytes = configured,
            EvaluationLimit::TotalSteps => limits.max_total_steps = configured,
            EvaluationLimit::StepsPerRoot => limits.max_steps_per_root = configured,
            EvaluationLimit::Depth => limits.max_depth = configured,
            EvaluationLimit::ExpansionBytes => limits.max_expansion_bytes = configured,
            EvaluationLimit::RetainedExpansionBytes => {
                limits.max_retained_expansion_bytes = configured;
            }
            EvaluationLimit::Diagnostics => limits.max_diagnostics = configured,
        }
        assert_eq!(
            evaluate_with_limits(&program, &policy, &environment, limits).unwrap_err(),
            EvaluationSetupError::LimitExceedsMaximum {
                limit,
                configured,
                maximum,
            }
        );
    }
}

#[test]
fn operation_wide_budgets_fail_the_invocation_without_a_root_diagnostic() {
    let policy = CheckPolicy::default();
    let program = checked(
        "value I(int); outputs { first: I = 1; second: I = 2; }",
        &policy,
    );
    let environment = EvaluationEnvironment::new(&policy);
    assert_eq!(
        evaluate_with_limits(
            &program,
            &policy,
            &environment,
            EvaluationLimits {
                max_total_steps: 1,
                ..EvaluationLimits::default()
            },
        )
        .unwrap_err(),
        EvaluationSetupError::EvaluationWorkLimit
    );

    let program = checked(
        "value I(int); outputs { only: I = I(1); }",
        &policy,
    );
    assert_eq!(
        evaluate_with_limits(
            &program,
            &policy,
            &environment,
            EvaluationLimits {
                max_total_steps: 1,
                max_steps_per_root: 1,
                ..EvaluationLimits::default()
            },
        )
        .unwrap_err(),
        EvaluationSetupError::EvaluationWorkLimit
    );

    let text = "x".repeat(200);
    let program = checked(
        &format!("value S(str); outputs {{ first: S = \"{text}\"; second: S = \"{text}\"; }}"),
        &policy,
    );
    assert_eq!(
        evaluate_with_limits(
            &program,
            &policy,
            &environment,
            EvaluationLimits {
                max_retained_expansion_bytes: 1_024,
                ..EvaluationLimits::default()
            },
        )
        .unwrap_err(),
        EvaluationSetupError::EvaluationRetainedExpansionLimit
    );
}

use super::*;

#[test]
fn deterministic_roots_are_independent_and_failures_are_explicit() {
    let result = run(
        "resource Port(int); outputs { bad: [Port] = [Port(80), Port(80)]; good: Port = Port(80); }",
        &CheckPolicy::default(),
    );
    let roots: Vec<_> = result.roots().collect();
    assert_eq!(roots.len(), 2);
    assert!(matches!(
        roots[0].outcome(),
        RealizedRootOutcome::Failed(_)
    ));
    assert!(
        roots[0].diagnostics()[0]
            .message
            .contains("conflicts")
    );
    assert!(matches!(
        roots[1].outcome(),
        RealizedRootOutcome::Value(_)
    ));
    assert_eq!(roots[1].claims().count(), 1);

    let independent = run(
        "resource Port(int); outputs { first: Port = Port(80); second: Port = Port(80); }",
        &CheckPolicy::default(),
    );
    assert!(independent.is_success());

    let again = run(
        "resource Port(int); outputs { bad: [Port] = [Port(80), Port(80)]; good: Port = Port(80); }",
        &CheckPolicy::default(),
    );
    assert_eq!(format!("{result:?}"), format!("{again:?}"));
}

#[test]
fn policy_and_environment_mismatches_fail_before_evaluation() {
    fn accepts(_: i64) -> bool {
        true
    }
    let first = CheckPolicy::new("first")
        .unwrap()
        .with_predicate("p", PrimitiveType::Int)
        .unwrap();
    let second = CheckPolicy::new("second").unwrap();
    let checked = checked("value I(int); outputs { out: I = 1; }", &first);
    assert!(matches!(
        evaluate(
            &checked,
            &second,
            &EvaluationEnvironment::new(&second)
        ),
        Err(EvaluationSetupError::PolicyMismatch { .. })
    ));
    assert!(matches!(
        evaluate(
            &checked,
            &first,
            &EvaluationEnvironment::new(&first)
        ),
        Err(EvaluationSetupError::MissingPredicateCallback)
    ));
    let wrong = EvaluationEnvironment::new(&second);
    assert!(matches!(
        evaluate(&checked, &first, &wrong),
        Err(EvaluationSetupError::EnvironmentPolicyMismatch)
    ));
    let complete = EvaluationEnvironment::new(&first)
        .with_int_predicate("p", accepts)
        .unwrap();
    assert!(evaluate(&checked, &first, &complete).is_ok());
}

#[test]
fn private_scopes_isolate_nested_claims_while_inherited_scopes_share() {
    let source = r"
            resource Port(int) in net;
            struct Box in [net] { port: Port; }
            struct Pair { left: Box; right: Box; }
            outputs { pair: Pair = Pair { left = Box { port = Port(9); }; right = Box { port = Port(9); }; }; }
        ";
    let private = CheckPolicy::new("private")
        .unwrap()
        .with_scope_rule("net", ScopeRule::Private)
        .unwrap();
    assert!(run(source, &private).is_success());

    let inherited = CheckPolicy::new("inherited")
        .unwrap()
        .with_scope_rule("net", ScopeRule::Inherited)
        .unwrap();
    let result = run(source, &inherited);
    assert!(matches!(
        result.roots().next().unwrap().outcome(),
        RealizedRootOutcome::Failed(_)
    ));
}

#[test]
fn diagnostics_are_globally_capped_without_omitting_failed_roots() {
    use std::fmt::Write as _;

    let mut source = String::from("resource R(int); outputs {");
    for index in 0..crate::MAX_DIAGNOSTICS + 4 {
        write!(
            source,
            "r{index}: [R] = [R({index}), R({index})];"
        )
        .unwrap();
    }
    source.push('}');
    let result = run(&source, &CheckPolicy::default());
    assert_eq!(result.roots().len(), crate::MAX_DIAGNOSTICS + 4);
    assert_eq!(
        result.diagnostics().count(),
        crate::MAX_DIAGNOSTICS
    );
    assert!(
        result
            .roots()
            .all(|root| matches!(root.outcome(), RealizedRootOutcome::Failed(_)))
    );
}

#[test]
fn predicate_panics_become_failed_root_diagnostics() {
    fn panics(_: i64) -> bool {
        panic!("host predicate panic");
    }

    let policy = CheckPolicy::new("predicate-panic")
        .unwrap()
        .with_predicate("host::accepts", PrimitiveType::Int)
        .unwrap();
    let program = checked(
        "value V(int) where host::accepts(self); outputs { out: V = V(1); }",
        &policy,
    );
    let environment = EvaluationEnvironment::new(&policy)
        .with_int_predicate("host::accepts", panics)
        .unwrap();
    let result = evaluate(&program, &policy, &environment).unwrap();
    let root = result.roots().next().unwrap();
    assert!(matches!(
        root.outcome(),
        RealizedRootOutcome::Failed(_)
    ));
    assert!(
        root.diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message == "predicate callback panicked")
    );
}

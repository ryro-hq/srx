use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::{
    checker::PrimitiveType, checker::check, evaluator::Value, resolver::resolve, source::SourceSet,
    syntax::parse_sources,
};

fn checked(source: &str, policy: &CheckPolicy) -> CheckedProgram {
    let mut sources = SourceSet::new();
    sources.add("main.srx", source).unwrap();
    check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        policy,
    )
    .unwrap()
}

#[test]
fn queries_are_lazy_and_repeated_roots_and_value_aliases_share_evaluation() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn observed(_: i64) -> bool {
        CALLS.fetch_add(1, Ordering::Relaxed);
        true
    }
    let policy = CheckPolicy::new("session-observation")
        .unwrap()
        .with_predicate("observed", PrimitiveType::Int)
        .unwrap();
    let environment = EvaluationEnvironment::new(&policy)
        .with_int_predicate("observed", observed)
        .unwrap();
    let program = checked(
        r"
        value I(int) where observed(self);
        fn diverge() -> I { diverge() }
        outputs { good: I = I(1); alias: I = good; disconnected: I = diverge(); }
    ",
        &policy,
    );
    for first in ["good", "alias"] {
        CALLS.store(0, Ordering::Relaxed);
        let mut session = EvaluationSession::new(
            &program,
            &policy,
            &environment,
            EvaluationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            session.root_names().collect::<Vec<_>>(),
            ["alias", "disconnected", "good"]
        );
        assert!(session.root_type("good").is_some());
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
        assert!(matches!(
            session.evaluate_root("absent"),
            Err(EvaluationQueryError::UnknownRoot)
        ));
        assert!(
            session
                .evaluate_root(first)
                .unwrap()
                .value()
                .is_some()
        );
        session.evaluate_root("good").unwrap();
        session.evaluate_root("alias").unwrap();
        session.evaluate_root("good").unwrap();
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        let realized = session.into_realized().unwrap();
        assert!(realized.is_success());
        assert_eq!(
            realized
                .roots()
                .map(RealizedRoot::name)
                .collect::<Vec<_>>(),
            ["good", "alias"]
        );
    }
}

#[test]
fn affine_results_are_borrowed_and_failures_are_not_reexecuted() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn rejects(_: i64) -> bool {
        CALLS.fetch_add(1, Ordering::Relaxed);
        false
    }
    let policy = CheckPolicy::new("session-rejection")
        .unwrap()
        .with_predicate("rejects", PrimitiveType::Int)
        .unwrap();
    let environment = EvaluationEnvironment::new(&policy)
        .with_int_predicate("rejects", rejects)
        .unwrap();
    let program = checked(
        "resource R(int); value I(int) where rejects(self); outputs { affine: R = R(1); failure: I = I(0); }",
        &policy,
    );
    let mut session = EvaluationSession::new(
        &program,
        &policy,
        &environment,
        EvaluationLimits::default(),
    )
    .unwrap();
    let pointer = std::ptr::from_ref(session.evaluate_root("affine").unwrap());
    assert_eq!(
        std::ptr::from_ref(session.evaluate_root("affine").unwrap()),
        pointer
    );
    assert_eq!(
        session
            .evaluate_root("affine")
            .unwrap()
            .claims()
            .len(),
        1
    );
    assert!(
        session
            .evaluate_root("failure")
            .unwrap()
            .value()
            .is_none()
    );
    assert!(
        session
            .evaluate_root("failure")
            .unwrap()
            .value()
            .is_none()
    );
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    let realized = session.into_realized().unwrap();
    assert_eq!(realized.roots().len(), 2);
    assert!(!realized.is_success());
}

#[test]
fn function_outputs_accept_expressions_and_aliases_and_are_directly_callable() {
    let policy = CheckPolicy::default();
    let environment = EvaluationEnvironment::new(&policy);
    let program = checked(
        r"
        value I(int); type Factory = fn(I) -> I;
        fn identity<T>(item: T) -> T { item }
        fn capture(item: I) -> Factory { fn(ignored: I) -> I { item } }
        outputs {
            literal: fn(I) -> I = fn(item: I) -> I { item };
            alias: Factory = literal;
            generic: fn(I) -> I = identity;
            captured: fn(I) -> I = capture(I(4));
            selected: fn(I) -> I = compare(I(1), I(2), literal, alias, generic);
            results: [I] = [literal(I(1)), alias(I(2)), generic(I(3)), captured(I(0)), selected(I(5))];
        }
    ",
        &policy,
    );
    let mut session = EvaluationSession::new(
        &program,
        &policy,
        &environment,
        EvaluationLimits::default(),
    )
    .unwrap();
    assert_eq!(
        session.root_type("literal"),
        session.root_type("alias")
    );
    let root = session.evaluate_root("results").unwrap();
    let Value::List {
        items,
        ..
    } = root.value().unwrap()
    else {
        panic!("expected list");
    };
    let numbers: Vec<_> = items
        .iter()
        .map(|item| match item {
            Value::Nominal {
                value: crate::evaluator::PrimitiveValue::Int(value),
                ..
            } => *value,
            _ => panic!("expected I"),
        })
        .collect();
    assert_eq!(numbers, [1, 2, 3, 4, 5]);
}

#[test]
fn query_budgets_are_operation_wide_and_exhaustion_is_terminal() {
    let policy = CheckPolicy::default();
    let environment = EvaluationEnvironment::new(&policy);
    let program = checked(
        "value I(int); outputs { a: I = I(1); b: I = I(2); }",
        &policy,
    );
    let mut measured = EvaluationSession::new(
        &program,
        &policy,
        &environment,
        EvaluationLimits::default(),
    )
    .unwrap();
    measured.evaluate_root("a").unwrap();
    let steps = measured.total_steps;
    let bytes = measured.retained_expansion;
    for (limits, expected) in [
        (
            EvaluationLimits {
                max_total_steps: steps,
                ..EvaluationLimits::default()
            },
            EvaluationSetupError::EvaluationWorkLimit,
        ),
        (
            EvaluationLimits {
                max_retained_expansion_bytes: bytes,
                ..EvaluationLimits::default()
            },
            EvaluationSetupError::EvaluationRetainedExpansionLimit,
        ),
    ] {
        let mut session = EvaluationSession::new(&program, &policy, &environment, limits).unwrap();
        assert!(
            session
                .evaluate_root("a")
                .unwrap()
                .value()
                .is_some()
        );
        assert!(
            matches!(session.evaluate_root("b"), Err(EvaluationQueryError::Setup(error)) if error == expected)
        );
        assert!(
            matches!(session.evaluate_root("a"), Err(EvaluationQueryError::Setup(error)) if error == expected)
        );
        assert!(matches!(session.into_realized(), Err(error) if error == expected));
    }
}

#[test]
fn retained_consumer_index_shares_the_evaluation_budget() {
    let policy = CheckPolicy::default();
    let environment = EvaluationEnvironment::new(&policy);
    let program = checked("value I(int); outputs { a: I = I(1); }", &policy);
    let mut measured = EvaluationSession::new(
        &program,
        &policy,
        &environment,
        EvaluationLimits::default(),
    )
    .unwrap();
    measured.evaluate_root("a").unwrap();
    let mut session = EvaluationSession::new(
        &program,
        &policy,
        &environment,
        EvaluationLimits {
            max_retained_expansion_bytes: measured.retained_expansion + 1,
            ..EvaluationLimits::default()
        },
    )
    .unwrap();
    session.evaluate_root("a").unwrap();
    session.reserve_metadata_bytes(1).unwrap();
    assert_eq!(
        session.reserve_metadata_bytes(1),
        Err(EvaluationSetupError::EvaluationRetainedExpansionLimit)
    );
    assert!(matches!(
        session.evaluate_root("a"),
        Err(EvaluationQueryError::Setup(
            EvaluationSetupError::EvaluationRetainedExpansionLimit
        ))
    ));
}

#[test]
fn querying_a_cycle_fails_only_the_selected_root() {
    let policy = CheckPolicy::default();
    let environment = EvaluationEnvironment::new(&policy);
    let program = checked(
        "value I(int); outputs { a: I = b; b: I = a; good: I = 1; }",
        &policy,
    );
    let mut session = EvaluationSession::new(
        &program,
        &policy,
        &environment,
        EvaluationLimits::default(),
    )
    .unwrap();
    assert!(
        session
            .evaluate_root("good")
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        session
            .evaluate_root("a")
            .unwrap()
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message.contains("cycle"))
    );
    assert_eq!(session.into_realized().unwrap().roots().len(), 2);
}

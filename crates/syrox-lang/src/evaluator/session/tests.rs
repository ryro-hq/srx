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

#[test]
fn module_bindings_are_lazy_and_shared_across_roots_with_memo_identity() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn observed(_: i64) -> bool {
        CALLS.fetch_add(1, Ordering::Relaxed);
        true
    }
    let policy = CheckPolicy::new("global-sharing")
        .unwrap()
        .with_predicate("observed", PrimitiveType::Int)
        .unwrap();
    let environment = EvaluationEnvironment::new(&policy)
        .with_int_predicate("observed", observed)
        .unwrap();
    let program = checked(
        r"value I(int) where observed(self); let shared = memoize(fn() -> I { I(7) }); let literal = 4; let forward = later; let later: I = literal; outputs { a: fn() -> I = shared; b: fn() -> I = shared; first: I = forward; second: I = later; }",
        &policy,
    );
    let mut session = EvaluationSession::new(
        &program,
        &policy,
        &environment,
        EvaluationLimits::default(),
    )
    .unwrap();
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    let memo = |value: &Value| match value {
        Value::MemoizedFunction {
            id,
            ..
        } => id.clone(),
        _ => panic!("expected memoized function"),
    };
    let first = memo(
        session
            .evaluate_root("a")
            .unwrap()
            .value()
            .unwrap(),
    );
    let second = memo(
        session
            .evaluate_root("b")
            .unwrap()
            .value()
            .unwrap(),
    );
    assert_eq!(first, second);
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    session.evaluate_root("first").unwrap();
    session.evaluate_root("second").unwrap();
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    assert!(session.into_realized().unwrap().is_success());
}

#[test]
fn deferred_global_callbacks_remain_lazy_and_can_create_resources_in_outputs() {
    let policy = CheckPolicy::default();
    let program = checked(
        "resource R(int); value I(int); let factory = memoize(fn() -> fn() -> R { fn() -> R { R(7) } }); let callback = factory(); let identity = fn(argument: I) -> I { argument }; let answer = identity(1); let once_factory = fn() -> I { let f = once fn() -> I { I(2) }; f() }; outputs { first: R = callback(); second: R = callback(); pure: I = answer; once_result: I = once_factory(); }",
        &policy,
    );
    let environment = EvaluationEnvironment::new(&policy);
    let mut session = EvaluationSession::new(
        &program,
        &policy,
        &environment,
        EvaluationLimits::default(),
    )
    .unwrap();
    for name in ["first", "second", "pure", "once_result"] {
        let result = session.evaluate_root(name).unwrap();
        assert!(
            result.value().is_some(),
            "{:?}",
            result.diagnostics()
        );
    }
    assert!(session.into_realized().unwrap().is_success());
}

#[test]
fn forward_global_facts_survive_discovery_inside_specialized_calls() {
    let policy = CheckPolicy::default();
    let program = checked(
        r#"value I(int); value S(str); enum E { A, B } let alpha = select("known"); fn select(const key: S) -> I { omega } let omega: I = match E::A { A => I(7), B => I(8) }; outputs { direct: I = omega; indirect: I = alpha; }"#,
        &policy,
    );
    let environment = EvaluationEnvironment::new(&policy);
    let mut session = EvaluationSession::new(
        &program,
        &policy,
        &environment,
        EvaluationLimits::default(),
    )
    .unwrap();
    for root in ["direct", "indirect"] {
        let result = session.evaluate_root(root).unwrap();
        assert!(
            result.diagnostics().is_empty(),
            "{:?}",
            result.diagnostics()
        );
        assert!(matches!(
            result.value(),
            Some(Value::Nominal {
                value: super::super::PrimitiveValue::Int(7),
                ..
            })
        ));
    }
}

#[test]
fn static_enum_matches_evaluate_selected_payloads_and_keep_specializations_separate() {
    let policy = CheckPolicy::default();
    let program = checked(
        r#"
        value I(int); value S(str); enum Target { Gnu, Musl } enum Choice<T> { Empty, Selected(T) }
        fn unavailable(const target: S) -> I { match target { "gnu" => I(0) } }
        fn select(const target: Target) -> _ { match target { Gnu => S("gnu"), Musl => I(7) } }
        fn unwrap(const choice: Choice<I>) -> I { match choice { Empty => unavailable("musl"), Selected(number) => number } }
        let target: Target = Musl;
        let forwarded = match Choice::Selected(target) { Selected(inner) => inner, Empty => Target::Gnu };
        let global = select(forwarded);
        let payload = unwrap(Choice::Selected<I>(8));
        let lazy = Choice::Selected(memoize(fn() -> I { 9 }));
        let projected = match lazy { Selected(factory) => factory, Empty => unavailable("musl") };
        outputs {
            selected: I = global;
            from_payload: I = payload;
            other: S = select(Target::Gnu);
            interpolated: S = "${payload}";
            from_lazy: I = projected();
        }
    "#,
        &policy,
    );
    let environment = EvaluationEnvironment::new(&policy);
    let mut session = EvaluationSession::new(
        &program,
        &policy,
        &environment,
        EvaluationLimits::default(),
    )
    .unwrap();
    for (root, expected) in [
        ("selected", 7),
        ("from_payload", 8),
        ("from_lazy", 9),
    ] {
        let result = session.evaluate_root(root).unwrap();
        assert!(
            result.diagnostics().is_empty(),
            "{:?}",
            result.diagnostics()
        );
        assert!(
            matches!(result.value(), Some(Value::Nominal { value: super::super::PrimitiveValue::Int(number), .. }) if *number == expected)
        );
    }
    for (root, expected) in [("other", "gnu"), ("interpolated", "8")] {
        let result = session.evaluate_root(root).unwrap();
        assert!(
            result.diagnostics().is_empty(),
            "{:?}",
            result.diagnostics()
        );
        assert!(
            matches!(result.value(), Some(Value::Nominal { value: super::super::PrimitiveValue::Str(text), .. }) if text == expected)
        );
    }
}

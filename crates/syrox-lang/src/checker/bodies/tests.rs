use super::*;
use crate::{
    analysis::AnalysisCancellation, checker::CheckLimits, checker::CheckPolicy,
    diagnostic::DiagnosticCode, resolver::resolve, source::SourceSet, syntax::parse_sources,
};
use std::fmt::Write;

fn resolved(text: &str) -> crate::resolver::ResolvedProgram {
    let mut sources = SourceSet::new();
    sources.add("main.srx", text).unwrap();
    resolve(parse_sources(&sources).unwrap()).unwrap()
}

fn assert_parity(program: &crate::resolver::ResolvedProgram, limits: CheckLimits, editor: bool) {
    let policy = CheckPolicy::default();
    let cancellation = AnalysisCancellation::default();
    let mut flat = Checker::new(program, &policy, limits);
    flat.unpartitioned_bodies = true;
    flat.cancellation = editor.then_some(&cancellation);
    flat.run();
    let mut partitioned = Checker::new(program, &policy, limits);
    partitioned.cancellation = editor.then_some(&cancellation);
    partitioned.run();
    assert_eq!(
        partitioned.diagnostics, flat.diagnostics,
        "{limits:?}"
    );
    assert_eq!(
        partitioned.expressions, flat.expressions,
        "{limits:?}"
    );
    assert_eq!(partitioned.patterns, flat.patterns);
    assert_eq!(partitioned.editor, flat.editor, "{limits:?}");
    assert_eq!(
        partitioned.generic_instances,
        flat.generic_instances
    );
    assert_eq!(
        partitioned.budget_position(),
        flat.budget_position()
    );
    assert!(partitioned.body.bindings.is_empty());
    assert!(!partitioned.body.active);
}

#[test]
fn publication_retention_exhaustion_preserves_strict_facts_and_costs() {
    let program = resolved(
        "value I(int); fn inspect(x: I) -> I { let y=x; y } outputs { result: I = inspect(I(1)); }",
    );
    let policy = CheckPolicy::default();
    let cancel = AnalysisCancellation::default();
    let mut full = Checker::new(&program, &policy, CheckLimits::default());
    full.cancellation = Some(&cancel);
    full.run();
    let mut bounded = Checker::new(&program, &policy, CheckLimits::default());
    bounded.cancellation = Some(&cancel);
    bounded.publications.units = 262_144;
    bounded.run();
    assert!(!full.publications.entries.is_empty());
    assert!(bounded.publications.truncated && bounded.publications.entries.is_empty());
    assert_eq!(full.diagnostics, bounded.diagnostics);
    assert_eq!(full.expressions, bounded.expressions);
    assert_eq!(full.patterns, bounded.patterns);
    assert_eq!(full.editor, bounded.editor);
    assert_eq!(full.generic_instances, bounded.generic_instances);
    assert_eq!(full.budget_position(), bounded.budget_position());
}

#[test]
fn partitioned_functions_defaults_and_outputs_match_flat_checking_and_global_limits() {
    let program = resolved(
        r"
        value I(int); resource R(int);
        enum Choice<T> { Left(T), Right(T) }
        struct Box<T> { payload: T; }
        struct Defaults { make: fn(I) -> I = fn(x: I) -> I { x }; }
        fn identity<T>(x: T) -> T { x }
        fn reusable(x: I) -> I { let f = fn(y: I) -> I { identity(y) }; f(x) }
        fn affine(x: R) -> R { let f = once fn() -> R { x }; f() }
        fn branches(x: Choice<R>) -> R { match x { Left(y) => y, Right(y) => y } }
        fn bad(x: R) { x; x; }
        fn first() -> Box<I> { Box<I> { payload = I(1); } }
        fn second() -> Box<I> { Box<I> { payload = I(2); } }
        mod authority { pub opaque struct Owned<owner T> { payload: I; } }
        struct Key {}
        fn authorized() -> authority::Owned<Key> { authority::Owned<Key> { payload = I(1); } }
        outputs { result: I = reusable(I(3)); factory: fn(I) -> I = fn(x: I) -> I { x }; }
    ",
    );
    for editor in [false, true] {
        assert_parity(&program, CheckLimits::default(), editor);
        for work in [0, 1, 30, 100, 300, 600, 1000] {
            assert_parity(
                &program,
                CheckLimits {
                    max_work: work,
                    ..CheckLimits::default()
                },
                editor,
            );
        }
        for metadata in [0, 1, 8, 32, 64, 128] {
            assert_parity(
                &program,
                CheckLimits {
                    max_metadata_units: metadata,
                    ..CheckLimits::default()
                },
                editor,
            );
        }
        for instances in [0, 1, 2] {
            assert_parity(
                &program,
                CheckLimits {
                    max_generic_instances: instances,
                    ..CheckLimits::default()
                },
                editor,
            );
        }
    }
}

#[test]
fn recovered_body_regions_and_later_bodies_match_flat_editor_analysis() {
    let text = "value I(int); resource R(int); struct Box<T> { first: T; second: T; } fn broken(r: R) { let local = I(1); let local: I = ; let b = Box<R> { bad = ; first = r; second = r; }; let captured = once fn() -> R { r.; r }; } fn later(r: R) -> R { r } outputs { item: I = I(2); }";
    let source = crate::source::Source::new("main.srx", text).unwrap();
    let parsed = crate::syntax::parse_file(&source);
    assert!(!parsed.diagnostics().is_empty());
    let sources = crate::syntax::ParsedSources {
        sources: vec![crate::syntax::ParsedSource {
            source_id: crate::source::SourceId::SINGLE,
            domain: crate::source::SourceDomainId::project(),
            module: Vec::new(),
            program: parsed.recovered_program().clone(),
        }],
        input_domains: BTreeMap::new(),
        project_roots: BTreeSet::new(),
    };
    let (program, _, exhausted) = crate::resolver::resolve_partial(sources, None);
    assert!(!exhausted);
    assert_parity(&program, CheckLimits::default(), true);
    for metadata in [16, 32, 64] {
        assert_parity(
            &program,
            CheckLimits {
                max_metadata_units: metadata,
                ..CheckLimits::default()
            },
            true,
        );
    }
}

#[test]
fn diagnostics_are_capped_across_bodies_instead_of_per_body() {
    let mut text = "resource R(int);".to_owned();
    for index in 0..crate::MAX_DIAGNOSTICS + 8 {
        write!(text, "fn bad{index}(x: R) {{ x; x; }}").unwrap();
    }
    let program = resolved(&text);
    assert_parity(&program, CheckLimits::default(), true);
    let policy = CheckPolicy::default();
    let mut checker = Checker::new(&program, &policy, CheckLimits::default());
    checker.run();
    assert_eq!(checker.diagnostics.len(), crate::MAX_DIAGNOSTICS);
    assert!(
        checker
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code == DiagnosticCode::MovedValue)
    );
}

#[test]
fn body_results_own_facts_and_include_already_deduplicated_generic_requests() {
    let program = resolved(
        "value I(int); struct Box<T> { payload: T; } fn f() -> Box<I> { Box<I> { payload = I(1); } }",
    );
    let policy = CheckPolicy::default();
    let cancellation = AnalysisCancellation::default();
    let mut checker = Checker::new(&program, &policy, CheckLimits::default());
    checker.cancellation = Some(&cancellation);
    checker.index_resolution_metadata();
    checker.index();
    checker.validate_declarations();
    checker.propagate_carriers();
    checker.collect_function_types();
    checker.collect_editor_types();
    let info = *checker.functions.values().next().unwrap();
    let expression = info.declaration.body.tail.as_ref().unwrap();
    for _ in 0..2 {
        let before = checker.expressions.clone();
        let result = checker.evaluate_body(|checker| {
            checker.check_expr(expression, None, info.context, true);
        });
        assert_eq!(
            checker.expressions, before,
            "facts stay private until publication"
        );
        assert!(!result.facts.expressions.is_empty());
        assert_eq!(
            result.instances.len(),
            1,
            "must include an instance declared in the signature already"
        );
        assert_eq!(
            result.before.generic_instances,
            result.after.generic_instances
        );
        assert!(result.after.work > result.before.work);
        let facts = result.facts.expressions.len();
        checker.publish_body(result);
        assert_eq!(checker.expressions.len(), before.len() + facts);
    }
    let prefix = checker.expressions.clone();
    let result = checker.evaluate_body(|checker| {
        checker.check_expr(expression, None, info.context, true);
    });
    assert!(!result.cancelled);
    cancellation.cancel();
    checker.publish_body(result);
    assert_eq!(
        checker.expressions, prefix,
        "cancelled body facts must not be published"
    );
    let result = checker.evaluate_body(|checker| {
        checker.check_expr(expression, None, info.context, true);
    });
    assert!(result.cancelled);
    checker.publish_body(result);
    assert_eq!(checker.expressions, prefix);
    assert!(!checker.body.active);
}

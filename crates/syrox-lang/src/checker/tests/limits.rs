use super::*;

#[test]
fn default_constant_dependencies_obey_depth_work_and_metadata_limits() {
    use std::fmt::Write as _;

    let mut text = String::from("value I(int); let first = Layer0 {}; ");
    for index in 0..12 {
        write!(
            text,
            "struct Layer{index} {{ next: Layer{} = Layer{} {{}}; }} ",
            index + 1,
            index + 1,
        )
        .unwrap();
    }
    text.push_str("struct Layer12 { number: I = 1; }");
    checked(&text);
    for (limits, expected) in [
        (
            CheckLimits {
                max_specialization_depth: 4,
                ..CheckLimits::default()
            },
            "default dependency depth limit",
        ),
        (
            CheckLimits {
                max_work: 100,
                ..CheckLimits::default()
            },
            "work limit",
        ),
        (
            CheckLimits {
                max_metadata_units: 20,
                ..CheckLimits::default()
            },
            "metadata limit",
        ),
    ] {
        let errors =
            check_with_limits(resolved(&text), &CheckPolicy::default(), limits).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains(expected)),
            "{errors:?}"
        );
    }
    let errors = messages(
        "value I(int); struct Recursive { next: Recursive = Recursive {}; } fn select(const argument: Recursive) -> I { 1 } let selected = select(Recursive {});",
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("const argument must be a known")),
        "{errors:?}"
    );
}

#[test]
fn repeated_constant_fields_share_storage_within_the_checking_budget() {
    use std::fmt::Write as _;
    let mut source = String::from(
        "value I(int); struct Pair<T> { left: T; right: T; } fn choose<T>(const selection: T) -> I { 1 } fn use_it() -> I { let n0: I = 1;",
    );
    let mut ty = String::from("I");
    for index in 1..=24 {
        write!(
            source,
            "let n{index} = Pair<{ty}> {{ left = n{}; right = n{}; }};",
            index - 1,
            index - 1
        )
        .unwrap();
        ty = format!("Pair<{ty}>");
    }
    source.push_str("choose(n24) }");
    checked(&source);
}

#[test]
fn module_export_entries_count_toward_the_metadata_budget() {
    use std::fmt::Write as _;
    let mut modules = String::new();
    for index in 0..40 {
        write!(
            modules,
            "mod m{index} {{ pub use implementation::make; }}"
        )
        .unwrap();
    }
    let source = format!(
        r"
        value Key(str); value I(int);
        mod implementation {{ pub fn make() -> I {{ I(1) }} }}
        mod collection {{ {modules} }}
        outputs {{ keys: [Key] = module_exports(collection, make, fn(key: Key, make: fn() -> I) -> Key {{ key }}); }}
    "
    );
    let errors = check_with_limits(
        resolved(&source),
        &CheckPolicy::default(),
        CheckLimits {
            max_metadata_units: 20,
            ..CheckLimits::default()
        },
    )
    .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("checked metadata limit")),
        "{errors:?}"
    );
}

#[test]
fn inferred_function_and_enum_instances_use_the_shared_budget() {
    for source in [
        "value I(int); value S(str); fn id<T>(x: T) -> T { x } outputs { a: I = id(I(1)); b: S = id(S(\"x\")); }",
        "value I(int); value S(str); enum Option<T> { None, Some(T) } outputs { a: Option<I> = Option::Some(I(1)); b: Option<S> = Option::Some(S(\"x\")); }",
    ] {
        let errors = check_with_limits(
            resolved(source),
            &CheckPolicy::default(),
            CheckLimits {
                max_generic_instances: 1,
                ..CheckLimits::default()
            },
        )
        .unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("generic instance limit")),
            "{errors:?}"
        );
    }
}

#[test]
fn generic_function_instances_share_the_checker_instance_budget() {
    let program = resolved(
        "value I(int); value S(str); fn id<T>(x: T) -> T { x } outputs { first: I = id<I>(I(1)); second: S = id<S>(S(\"s\")); }",
    );
    let errors = check_with_limits(
        program,
        &CheckPolicy::default(),
        CheckLimits {
            max_generic_instances: 1,
            ..CheckLimits::default()
        },
    )
    .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("generic instance limit"))
    );
}

#[test]
fn alias_cycles_through_lists_terminate_and_share_the_depth_budget() {
    for text in [
        "type A = [A];",
        "type A = B; type B = [A];",
        "type A = [B]; type B = A;",
    ] {
        assert!(
            messages(text)
                .iter()
                .any(|message| message.contains("cyclic type alias")),
            "cycle was not diagnosed: {text}"
        );
    }

    checked(
        "value V(int); type A = V; type B = A; type C = A; struct Pair { left: [B]; right: [C]; }",
    );

    let errors = check_with_limits(
        resolved("value V(int); type A = V; type B = [A]; type C = B;"),
        &CheckPolicy::default(),
        CheckLimits {
            max_alias_depth: 1,
            ..CheckLimits::default()
        },
    )
    .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("alias expansion depth"))
    );
}

#[test]
fn shared_non_affine_type_graph_does_not_exhaust_checker_work() {
    use std::fmt::Write as _;
    let mut source = String::from("struct N0 {} ");
    for n in 1..23 {
        write!(
            source,
            "struct N{n} {{ a: N{}; b: N{}; }} ",
            n - 1,
            n - 1
        )
        .unwrap();
    }
    source.push_str("fn f(x: N22) { x; x; }");
    let program = resolved(&source);
    check_with_limits(
        program,
        &CheckPolicy::default(),
        CheckLimits {
            max_work: 100_000,
            ..CheckLimits::default()
        },
    )
    .unwrap();
}

#[test]
fn checker_work_limit_fails_closed() {
    let errors = check_with_limits(
        resolved("struct S {}"),
        &CheckPolicy::default(),
        CheckLimits {
            max_work: 0,
            ..CheckLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(
        errors[0].message,
        "type checking work limit reached"
    );
}

#[test]
fn generic_substitution_charges_the_expanded_tree_before_cloning() {
    let program = resolved("struct S {} fn f(x: S) -> S { x }");
    let span = program.locals().next().unwrap().span();
    let parameter = program.locals().next().unwrap().id();
    let template = program.items().next().unwrap().id();
    let mut expansion = Ty::Nominal(template);
    for _ in 0..16 {
        expansion = Ty::Specialization {
            template,
            arguments: vec![expansion.clone(), expansion],
        };
    }
    let policy = CheckPolicy::default();
    let mut checker = Checker::new(
        &program,
        &policy,
        CheckLimits {
            max_work: 512,
            ..CheckLimits::default()
        },
    );
    assert!(
        checker
            .concretize(
                RawTy::Parameter(parameter),
                &BTreeMap::from([(parameter, expansion)]),
                span
            )
            .is_none()
    );
    assert_eq!(
        checker.diagnostics[0].message,
        "type checking work limit reached"
    );
}

#[test]
fn generic_instance_and_metadata_limits_fail_closed() {
    let generic_errors = check_with_limits(
        resolved(
            "struct A {} struct B {} struct Box<T> { x: T; } type One = Box<A>; type Two = Box<B>;",
        ),
        &CheckPolicy::default(),
        CheckLimits {
            max_generic_instances: 1,
            ..CheckLimits::default()
        },
    )
    .unwrap_err();
    assert!(
        generic_errors
            .iter()
            .any(|error| error.message == "generic instance limit reached")
    );

    let metadata_errors = check_with_limits(
        resolved("value V(int); fn f(x: V) { x; x; }"),
        &CheckPolicy::default(),
        CheckLimits {
            max_metadata_units: 1,
            ..CheckLimits::default()
        },
    )
    .unwrap_err();
    assert!(
        metadata_errors
            .iter()
            .any(|error| error.message == "checked metadata limit reached")
    );
}

#[test]
fn moved_value_diagnostics_obey_the_phase_cap() {
    let mut source = String::from("resource R(int); fn f(x: R) {");
    for _ in 0..MAX_DIAGNOSTICS + 44 {
        source.push_str("x;");
    }
    source.push('}');
    assert_eq!(messages(&source).len(), MAX_DIAGNOSTICS);
}

#[test]
fn checked_metadata_builds_complete_span_indexes_once() {
    let mut source = String::from("value V(int); fn f(x: V) {");
    for _ in 0..2_048 {
        source.push_str("x;");
    }
    source.push('}');
    let program = checked(&source);
    assert_eq!(
        program.expression_index.len(),
        program.expressions.len()
    );
    assert_eq!(
        program.pattern_index.len(),
        program.patterns.len()
    );
    assert!(
        program
            .expressions()
            .all(|expression| program.expression(expression.span()).is_some())
    );
}

#[test]
fn editor_retention_does_not_exhaust_language_metadata_or_change_diagnostics() {
    let mut sources = SourceSet::new();
    sources.add("main.srx", "value I(int); struct Box<T> { entry: T; } fn inspect(x: I) { let one = x; let two = one; let three = two; }").unwrap();
    let program = resolve(parse_sources(&sources).unwrap()).unwrap();
    let policy = CheckPolicy::default();
    let limits = CheckLimits {
        max_metadata_units: 4,
        ..CheckLimits::default()
    };
    let mut strict = Checker::new(&program, &policy, limits);
    strict.run();
    let cancellation = crate::analysis::AnalysisCancellation::default();
    let mut editor = Checker::new(&program, &policy, limits);
    editor.cancellation = Some(&cancellation);
    editor.run();
    assert!(
        strict.diagnostics.is_empty(),
        "{:?}",
        strict.diagnostics
    );
    assert_eq!(strict.diagnostics, editor.diagnostics);
    assert_eq!(strict.work, editor.work);
    assert!(editor.editor.truncated);
    assert!(editor.editor.units <= limits.max_metadata_units);
}

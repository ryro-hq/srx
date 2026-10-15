use std::sync::Arc;

use super::*;
use crate::{
    checker::CanonicalItemIdentity, checker::PrimitiveType, checker::ScopeRule, checker::check,
    resolver::resolve, source::SourceDomainId, source::SourceSet, syntax::parse_sources,
};

fn checked(source: &str, policy: &CheckPolicy) -> CheckedProgram {
    let mut sources = SourceSet::new();
    let prelude = "mod std { pub enum Bool { False, True } }";
    let source = if source.contains(prelude) {
        sources
            .add_standard_library("std.srx", prelude)
            .unwrap();
        source.replace(prelude, "")
    } else {
        source.to_owned()
    };
    sources.add("main.srx", source).unwrap();
    check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        policy,
    )
    .unwrap()
}

fn run(source: &str, policy: &CheckPolicy) -> RealizedProgram {
    let checked = checked(source, policy);
    evaluate(
        &checked,
        policy,
        &EvaluationEnvironment::new(policy),
    )
    .unwrap()
}

#[test]
fn sorting_moves_affine_elements_stably_and_rejects_mismatched_lengths() {
    let policy = CheckPolicy::default();
    let result = run(
        r#"resource R(int); value Key(str); outputs {
        sorted: [R] = sort_by_keys([R(1), R(2), R(3), R(4)], [Key("b"), Key("a"), Key("b"), Key("a")]);
    }"#,
        &policy,
    );
    let root = result.roots().next().unwrap();
    assert_eq!(root.claims().len(), 4);
    let Value::List {
        items,
        ..
    } = root.value().unwrap()
    else {
        panic!("expected sorted resources");
    };
    let values: Vec<_> = items
        .iter()
        .map(|item| match item {
            Value::Nominal {
                value: PrimitiveValue::Int(value),
                resource: true,
                ..
            } => *value,
            _ => panic!("resource was not preserved"),
        })
        .collect();
    assert_eq!(values, [2, 4, 1, 3]);
    let invalid = run(
        "value I(int); outputs { bad: [I] = sort_by_keys([I(1)], [I(0), I(1)]); }",
        &policy,
    );
    assert!(
        invalid
            .diagnostics()
            .any(|error| error.message.contains("equal lengths"))
    );
    let items = (0..100)
        .rev()
        .map(|n| format!("I({n})"))
        .collect::<Vec<_>>()
        .join(",");
    let program = checked(
        &format!("value I(int); outputs {{ sorted: [I] = sort_by_keys([{items}], [{items}]); }}"),
        &policy,
    );
    assert!(matches!(
        evaluate_with_limits(
            &program,
            &policy,
            &EvaluationEnvironment::new(&policy),
            EvaluationLimits {
                max_total_steps: 800,
                ..EvaluationLimits::default()
            }
        ),
        Err(EvaluationSetupError::EvaluationWorkLimit)
    ));
}

fn identity(path: &str) -> CanonicalItemIdentity {
    CanonicalItemIdentity::new(SourceDomainId::project(), path.split("::")).unwrap()
}

#[test]
fn constant_calls_keep_distinct_facts_for_each_selected_branch() {
    let result = run(
        r#"
        mod std { pub enum Bool { False, True } }
        value S(str); value I(int);
        struct Selection { version: S; }
        struct Old { port: I; } struct New { host: S; }
        fn select(const selection: Selection) -> _ {
            if selection.version != "new" { match selection.version { "old" => Old { port = 7; } } }
            else { New { host = "server"; } }
        }
        outputs { old: Old = select({ version = "old"; }); new: New = select({ version = "new"; }); }
    "#,
        &CheckPolicy::default(),
    );
    assert!(result.diagnostics().next().is_none());
    let names: Vec<_> = result
        .roots()
        .map(|root| match root.value().unwrap() {
            Value::Struct {
                fields,
                ..
            } => fields[0].0.clone(),
            _ => panic!("expected selected struct"),
        })
        .collect();
    assert_eq!(names, ["port", "host"]);
}

#[test]
fn static_traits_dispatch_with_associated_settings_and_generic_bounds() {
    let result = run(
        r#"
        value S(str); struct Settings { host: S; } struct P {}
        trait Package { type Settings; fn render(package: Self, settings: Self::Settings) -> S; }
        impl Package for P { type Settings = project::Settings; fn render(package: Self, settings: Self::Settings) -> S { settings.host } }
        fn configure<T: Package>(package: T, settings: T::Settings) -> S { T::render(package, settings) }
        outputs { text: S = configure(P {}, { host = "server"; }); }
    "#,
        &CheckPolicy::default(),
    );
    assert!(result.diagnostics().next().is_none());
    assert!(
        matches!(result.roots().next().unwrap().value().unwrap(), Value::Nominal { value: PrimitiveValue::Str(value), .. } if value == "server")
    );
}

#[test]
fn package_sets_are_values_and_specialized_closures_retain_their_facts() {
    let result = run(
        r#"
        value S(str); value I(int); struct Set { system: S; } struct Selection { version: S = "one"; }
        impl Set { fn nginx(const set: Self, const selection: Selection) -> I { match set.system { "musl" => match selection.version { "one" => 7 }, "gnu" => 8 } } }
        fn forSystem(const system: S) -> Set { Set { system = system; } }
        trait Render { type Settings; fn render(package: Self, settings: Self::Settings) -> S; }
        struct P {} struct Settings { host: S; }
        impl Render for P { type Settings = project::Settings; fn render(package: Self, settings: Self::Settings) -> S { settings.host } }
        fn delayed<T: Render>(package: T) -> fn(T::Settings) -> S { fn(settings: T::Settings) -> S { T::render(package, settings) } }
        outputs {
            abi: I = let packages = forSystem("musl"); in packages.nginx { version = "one"; };
            text: S = delayed(P {})({ host = "captured"; });
        }
    "#,
        &CheckPolicy::default(),
    );
    assert!(
        result.diagnostics().next().is_none(),
        "{:?}",
        result.diagnostics().collect::<Vec<_>>()
    );
    let values: Vec<_> = result
        .roots()
        .map(|root| root.value().unwrap())
        .collect();
    assert!(matches!(
        values[0],
        Value::Nominal {
            value: PrimitiveValue::Int(7),
            ..
        }
    ));
    assert!(
        matches!(values[1], Value::Nominal { value: PrimitiveValue::Str(value), .. } if value == "captured")
    );
}

#[test]
fn annotated_lets_contextualize_literals_lists_and_generics_once() {
    let result = run(
        "value I(int); fn id<T>(x: T) -> T { x } fn materialize() -> I { let empty: [I] = []; let concrete: I = id(7); concrete } outputs { answer: I = materialize(); }",
        &CheckPolicy::default(),
    );
    assert!(matches!(
        result.roots().next().unwrap().value().unwrap(),
        Value::Nominal {
            value: PrimitiveValue::Int(7),
            ..
        }
    ));
    let mut sources = SourceSet::new();
    sources
        .add(
            "main.srx",
            "resource R(int); fn duplicate(r: R) { let first: R = r; let second: R = r; }",
        )
        .unwrap();
    let errors = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap_err();
    assert_eq!(
        errors
            .iter()
            .filter(|error| error.code == crate::diagnostic::DiagnosticCode::MovedValue)
            .count(),
        1
    );
}

#[test]
fn functions_pass_as_values_and_locals_call_through_typed_parameters() {
    let program = run(
        "value I(int); fn id(x: I) -> I { x } fn apply(f: fn(I) -> I, x: I) -> I { f(x) } fn indirect(x: I) -> I { let f = id; f(x) } outputs { first: I = apply(id, I(7)); second: I = indirect(I(9)); }",
        &CheckPolicy::default(),
    );
    let values: Vec<_> = program
        .roots()
        .map(|root| root.value().unwrap())
        .collect();
    assert!(matches!(
        values.as_slice(),
        [
            Value::Nominal {
                value: PrimitiveValue::Int(7),
                ..
            },
            Value::Nominal {
                value: PrimitiveValue::Int(9),
                ..
            }
        ]
    ));
}

#[test]
fn generic_functions_specialize_as_values_and_compose() {
    let program = run(
        r#"
        value I(int);
        value S(str);
        fn id<T>(x: T) -> T { x }
        fn apply<T, U>(f: fn(T) -> U, x: T) -> U { f(x) }
        fn wrap<T, U>(f: fn(T) -> U) -> fn(T) -> U {
            fn(x: T) -> U { apply<T, U>(f, x) }
        }
        outputs {
            first: I = apply<I, I>(id<I>, I(7));
            second: S = wrap<S, S>(id<S>)(S("ok"));
        }
    "#,
        &CheckPolicy::default(),
    );
    assert!(program.is_success(), "{program:?}");
    let values: Vec<_> = program
        .roots()
        .map(|root| root.value().unwrap())
        .collect();
    assert!(matches!(
        values[0],
        Value::Nominal {
            value: PrimitiveValue::Int(7),
            ..
        }
    ));
    assert!(
        matches!(values[1], Value::Nominal { value: PrimitiveValue::Str(text), .. } if text == "ok")
    );
}

#[test]
fn generic_functions_move_affine_arguments_once() {
    let program = run(
        r"
        resource R(int);
        struct Box<T> { item: T; }
        fn boxed<T>(item: T) -> Box<T> { Box<T> { item = item; } }
        outputs { single: Box<R> = boxed<R>(R(12)); }
    ",
        &CheckPolicy::default(),
    );
    assert!(program.is_success(), "{program:?}");
    assert_eq!(
        program.roots().next().unwrap().claims().count(),
        1
    );
}

#[test]
fn generic_enum_payloads_move_resources_through_exhaustive_matches() {
    let program = run(
        r"
        resource R(int);
        enum Option<T> { None, Some(T) }
        enum Result<T, E> { Ok(T), Err(E) }
        fn unwrap<T>(item: Option<T>, fallback: T) -> T {
            match item { Some(found) => found, None => fallback }
        }
        fn wrap<T>(item: T) -> Result<Option<T>, T> { Result::Ok<Option<T>, T>(Option::Some<T>(item)) }
        outputs {
            result: R = match wrap<R>(R(1)) {
                Ok(maybe) => unwrap<R>(maybe, R(2)),
                Err(error) => error,
            };
            empty: Option<R> = Option::None<R>();
        }
    ",
        &CheckPolicy::default(),
    );
    assert!(program.is_success(), "{program:?}");
    let roots: Vec<_> = program.roots().collect();
    assert!(matches!(
        roots[0].value(),
        Some(Value::Nominal {
            value: PrimitiveValue::Int(1),
            resource: true,
            ..
        })
    ));
    assert_eq!(roots[0].claims().count(), 2);
    assert!(
        matches!(roots[1].value(), Some(Value::Variant { index: 0, payload, .. }) if payload.is_empty())
    );
}

#[test]
fn payload_enum_constructors_can_be_specialized_function_values() {
    let program = run(
        r"
        value I(int);
        enum Pair { Both(I, I) }
        enum Option<T> { None, Some(T) }
        fn apply<T, U>(f: fn(T) -> U, item: T) -> U { f(item) }
        outputs {
            selected: I = match Pair::Both(I(7), I(9)) { Both(_, right) => right };
            optional: Option<I> = apply<I, Option<I>>(Option::Some<I>, I(3));
        }
    ",
        &CheckPolicy::default(),
    );
    assert!(program.is_success(), "{program:?}");
    let roots: Vec<_> = program.roots().collect();
    assert!(matches!(
        roots[0].value(),
        Some(Value::Nominal {
            value: PrimitiveValue::Int(9),
            ..
        })
    ));
    assert!(
        matches!(roots[1].value(), Some(Value::Variant { index: 1, payload, .. }) if payload.len() == 1)
    );
}

#[test]
fn enum_payloads_preserve_nested_lists_and_consumable_closures() {
    let program = run(
        r"
        resource R(int);
        enum Option<T> { None, Some(T) }
        type Nested<T> = Option<[[T]]>;
        fn delay<T>(item: T) -> Option<once fn() -> T> {
            Option::Some<once fn() -> T>(once fn() -> T { item })
        }
        outputs {
            nested: Nested<R> = Option::Some<[[R]]>([[R(1)]]);
            selected: [R] = match delay<[R]>([R(2)]) {
                Some(f) => f(), None => []
            };
        }
    ",
        &CheckPolicy::default(),
    );
    assert!(program.is_success(), "{program:?}");
    let roots: Vec<_> = program.roots().collect();
    assert_eq!(roots[0].claims().count(), 1);
    assert_eq!(roots[1].claims().count(), 1);
    assert!(matches!(roots[1].value(), Some(Value::List { items, .. }) if items.len() == 1));
}

#[test]
fn local_inference_composes_functions_enums_and_affine_closures() {
    let program = run(
        r"
        resource R(int);
        value I(int);
        enum Option<T> { None, Some(T) }
        fn id<T>(item: T) -> T { item }
        fn apply<T, U>(item: T, f: fn(T) -> U) -> U { f(item) }
        fn defer<T>(item: T) -> once fn() -> T {
            once fn() -> T { id(item) }
        }
        fn make<T>(item: T) -> Option<once fn() -> T> { Option::Some(defer(item)) }
        outputs {
            selected: [R] = match make([R(1)]) {
                Some(f) => apply(f(), id), None => []
            };
            empty: Option<[I]> = Option::None();
            literal: I = id(7);
        }
    ",
        &CheckPolicy::default(),
    );
    assert!(program.is_success(), "{program:?}");
    let roots: Vec<_> = program.roots().collect();
    assert_eq!(roots[0].claims().count(), 1);
    assert!(matches!(roots[0].value(), Some(Value::List { items, .. }) if items.len() == 1));
    assert!(
        matches!(roots[1].value(), Some(Value::Variant { index: 0, payload, .. }) if payload.is_empty())
    );
    assert!(matches!(
        roots[2].value(),
        Some(Value::Nominal {
            value: PrimitiveValue::Int(7),
            ..
        })
    ));
}

#[test]
fn recursive_affine_enum_payloads_are_depth_bounded_even_in_fold() {
    let policy = CheckPolicy::default();
    let items = vec!["I(0)"; 40].join(",");
    for constructor in [
        "Chain::Next(acc)",
        "Chain::Via(Link::More<Chain>(acc))",
    ] {
        let source = format!(
            r"
            resource R(int); value I(int);
            enum Link<T> {{ More(T) }}
            enum Chain {{ End(R), Next(Chain), Via(Link<Chain>) }}
            outputs {{ out: Chain = fold([{items}], Chain::End(R(1)),
                fn(acc: Chain, item: I) -> Chain {{ {constructor} }}); }}
        "
        );
        let program = checked(&source, &policy);
        let result = evaluate_with_limits(
            &program,
            &policy,
            &EvaluationEnvironment::new(&policy),
            EvaluationLimits {
                max_depth: 16,
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
                .any(|diagnostic| diagnostic
                    .message
                    .contains("enum payload value depth limit")),
            "{result:?}"
        );
    }
}

#[test]
fn comparisons_evaluate_only_the_selected_branch_with_bytewise_order() {
    let program = run(
        r#"
        value Text(str);
        resource R(int) where 1..=3;
        fn selected() -> R { let r = R(1); compare(1, 2, r, r, r) }
        outputs {
            less: R = selected();
            equal: R = compare(Text("a\n"), Text("a\n"), R(9), R(2), R(9));
            greater: R = compare("é", "z", R(9), R(9), R(3));
        }
    "#,
        &CheckPolicy::default(),
    );
    assert!(program.is_success(), "{program:?}");
    for (name, expected) in [
        ("less", 1),
        ("equal", 2),
        ("greater", 3),
    ] {
        let root = program
            .roots()
            .find(|root| root.name() == name)
            .unwrap();
        assert_eq!(root.claims().count(), 1);
        assert!(
            matches!(root.value(), Some(Value::Nominal { value: PrimitiveValue::Int(actual), .. }) if *actual == expected)
        );
    }
}

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
fn module_exports_are_typed_byte_sorted_and_do_not_call_factories() {
    let program = run(
        r"
        value Key(str);
        value I(int);
        mod library {
            pub fn factory() -> I { I(1) }
            mod a { mod child { pub use library::factory; } }
            mod a0 { pub use library::factory; }
            mod hidden { fn factory() -> I { I(2) } }
            mod z { pub fn factory() -> I { factory() } }
        }
        outputs {
            keys: [Key] = module_exports(library, factory, fn(key: Key, make: fn() -> I) -> Key { key });
        }
    ",
        &CheckPolicy::default(),
    );
    assert!(program.is_success(), "{program:?}");
    let Some(Value::List {
        items,
        ..
    }) = program.roots().next().unwrap().value()
    else {
        panic!("expected module keys");
    };
    let names: Vec<_> = items
        .iter()
        .map(|item| match item {
            Value::Nominal {
                value: PrimitiveValue::Str(key),
                ..
            } => key.as_str(),
            _ => panic!("expected key value"),
        })
        .collect();
    assert_eq!(names, ["", "a0", "a::child", "z"]);
}

#[test]
fn module_exports_apply_key_refinements_and_runtime_budgets() {
    use std::fmt::Write as _;
    let policy = CheckPolicy::default();
    let invalid = run(
        r#"
        value Key(str) where in ["allowed"];
        value I(int);
        mod collection { mod denied { pub fn make() -> I { I(1) } } }
        outputs { keys: [Key] = module_exports(collection, make, fn(key: Key, make: fn() -> I) -> Key { key }); }
    "#,
        &policy,
    );
    assert!(!invalid.is_success());
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
    let program = checked(&source, &policy);
    for (limits, expected) in [
        (
            EvaluationLimits {
                max_steps_per_root: 20,
                ..EvaluationLimits::default()
            },
            "step limit",
        ),
        (
            EvaluationLimits {
                max_expansion_bytes: 2048,
                ..EvaluationLimits::default()
            },
            "expansion byte limit",
        ),
    ] {
        let result = evaluate_with_limits(
            &program,
            &policy,
            &EvaluationEnvironment::new(&policy),
            limits,
        )
        .unwrap();
        assert!(
            result
                .roots()
                .next()
                .unwrap()
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.message.contains(expected)),
            "{result:?}"
        );
    }
}

#[test]
fn consumable_closures_capture_and_return_affine_values() {
    let program = run(
        r"
        resource R(int);
        fn deferred<T>(item: T) -> once fn() -> T { once fn() -> T { item } }
        fn force(f: once fn() -> R) -> R { f() }
        fn map<T, U>(items: [T], f: fn(T) -> U) -> [U] {
            fold(items, [], fn(acc: [U], item: T) -> [U] { acc ++ [f(item)] })
        }
        outputs {
            realized: [R] = map<once fn() -> R, R>([deferred<R>(R(1)), deferred<R>(R(2))], force);
        }
    ",
        &CheckPolicy::default(),
    );
    assert!(program.is_success(), "{program:?}");
    let root = program.roots().next().unwrap();
    assert_eq!(root.claims().count(), 2);
    let Value::List {
        items,
        ..
    } = root.value().unwrap()
    else {
        panic!("expected forced resources");
    };
    assert_eq!(items.len(), 2);
    assert!(matches!(
        &items[0],
        Value::Nominal {
            value: PrimitiveValue::Int(1),
            resource: true,
            ..
        }
    ));
    assert!(matches!(
        &items[1],
        Value::Nominal {
            value: PrimitiveValue::Int(2),
            resource: true,
            ..
        }
    ));
}

#[test]
fn generic_list_map_and_flatten_are_composed_in_the_language() {
    let program = run(
        r"
        resource R(int);
        struct Box<T> { item: T; }
        fn boxed<T>(item: T) -> Box<T> { Box<T> { item = item; } }
        fn map<T, U>(items: [T], transform: fn(T) -> U) -> [U] {
            fold(items, [], fn(acc: [U], item: T) -> [U] { acc ++ [transform(item)] })
        }
        fn flatten<T>(items: [[T]]) -> [T] {
            fold(items, [], fn(acc: [T], part: [T]) -> [T] { acc ++ part })
        }
        outputs {
            mapped: [Box<R>] = map<R, Box<R>>(flatten<R>([[R(1)], [], [R(2)]]), boxed<R>);
        }
    ",
        &CheckPolicy::default(),
    );
    assert!(program.is_success(), "{program:?}");
    let root = program.roots().next().unwrap();
    assert_eq!(root.claims().count(), 2);
    let Value::List {
        items,
        ..
    } = root.value().unwrap()
    else {
        panic!("expected mapped list");
    };
    assert_eq!(items.len(), 2);
    for (item, expected) in items.iter().zip([1, 2]) {
        let Value::Struct {
            fields,
            ..
        } = item
        else {
            panic!("expected box");
        };
        assert!(
            matches!(&fields[0].1, Value::Nominal { value: PrimitiveValue::Int(value), resource: true, .. } if *value == expected)
        );
    }
}

#[test]
fn generic_factory_from_an_import_keeps_its_types_after_return() {
    let policy = CheckPolicy::default();
    let mut sources = SourceSet::new();
    sources
        .add(
            "consumer/main.srx",
            r#"
        inputs { lib = "path:lib"; }
        value I(int);
        fn identity(x: I) -> I { x }
        outputs { result: [I] = lib::map<I, I>([I(1), I(2)], lib::wrap<I, I>(identity)); }
    "#,
        )
        .unwrap();
    let lib = sources
        .create_project_domain(SourceDomainId::project(), "lib")
        .unwrap();
    sources
        .add_to_project_domain(
            lib,
            "lib/main.srx",
            r"
        pub fn wrap<T, U>(f: fn(T) -> U) -> fn(T) -> U { fn(x: T) -> U { f(x) } }
        pub fn map<T, U>(items: [T], f: fn(T) -> U) -> [U] {
            fold(items, [], fn(acc: [U], x: T) -> [U] { acc ++ [f(x)] })
        }
    ",
        )
        .unwrap();
    let program = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &policy,
    )
    .unwrap();
    let result = evaluate(
        &program,
        &policy,
        &EvaluationEnvironment::new(&policy),
    )
    .unwrap();
    assert!(result.is_success(), "{result:?}");
    let Value::List {
        items,
        ..
    } = result.roots().next().unwrap().value().unwrap()
    else {
        panic!("expected imported map result");
    };
    assert_eq!(items.len(), 2);
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
fn function_values_survive_returns_and_struct_fields() {
    let program = run(
        "value I(int); type Transform = fn(I) -> I; struct Holder { operation: Transform; } fn id(x: I) -> I { x } fn choose() -> Transform { id } fn apply(holder: Holder, x: I) -> I { let f = holder.operation; f(x) } outputs { result: I = apply(Holder { operation = choose(); }, I(42)); }",
        &CheckPolicy::default(),
    );
    assert!(matches!(
        program.roots().next().unwrap().value(),
        Some(Value::Nominal {
            value: PrimitiveValue::Int(42),
            ..
        })
    ));
}

#[test]
fn lists_of_function_types_and_generic_aliases_keep_callable_values() {
    let program = run(
        "value I(int); type Helpers<T> = [fn(T) -> T]; fn id(x: I) -> I { x } fn keep(xs: Helpers<I>) -> Helpers<I> { xs } outputs { functions: Helpers<I> = keep([id, id] ++ [id]); }",
        &CheckPolicy::default(),
    );
    let Value::List {
        items,
        ..
    } = program.roots().next().unwrap().value().unwrap()
    else {
        panic!("expected a function list");
    };
    assert_eq!(items.len(), 3);
    assert!(
        items
            .iter()
            .all(|value| matches!(value, Value::Function { .. }))
    );
}

#[test]
fn nested_lists_hold_specialized_values_and_keep_their_shape() {
    let program = run(
        "value I(int); struct Box<T> { item: T; } outputs { nested: [[Box<I>]] = [[Box<I> { item = I(7); }], []]; }",
        &CheckPolicy::default(),
    );
    let Value::List {
        items,
        ..
    } = program.roots().next().unwrap().value().unwrap()
    else {
        panic!("expected an outer list");
    };
    assert_eq!(items.len(), 2);
    assert!(matches!(&items[0], Value::List { items, .. } if items.len() == 1));
    assert!(matches!(&items[1], Value::List { items, .. } if items.is_empty()));
}

#[test]
fn projected_and_returned_functions_are_callable_as_expressions() {
    let program = run(
        "value I(int); type Transform = fn(I) -> I; struct Holder { operation: Transform; } fn id(x: I) -> I { x } fn choose() -> Transform { id } outputs { projected: I = Holder { operation = id; }.operation(I(11)); returned: I = choose()(I(12)); grouped: I = (id)(I(13)); }",
        &CheckPolicy::default(),
    );
    let values: Vec<_> = program
        .roots()
        .map(|root| root.value().unwrap())
        .collect();
    assert!(matches!(
        values.as_slice(),
        [
            Value::Nominal {
                value: PrimitiveValue::Int(11),
                ..
            },
            Value::Nominal {
                value: PrimitiveValue::Int(12),
                ..
            },
            Value::Nominal {
                value: PrimitiveValue::Int(13),
                ..
            }
        ]
    ));
}

#[test]
fn closures_capture_immutable_locals_and_survive_the_defining_call() {
    let result = run(
        "value I(int); fn factory(a: I) -> fn(I) -> I { fn(x: I) -> I { a } } fn apply(f: fn(I) -> I, x: I) -> I { f(x) } outputs { direct: I = factory(I(7))(I(0)); repeated: I = apply(factory(I(9)), I(0)); }",
        &CheckPolicy::default(),
    );
    let values: Vec<_> = result
        .roots()
        .map(|root| root.value().unwrap())
        .collect();
    assert!(matches!(
        values.as_slice(),
        [
            Value::Nominal {
                value: PrimitiveValue::Int(7),
                ..
            },
            Value::Nominal {
                value: PrimitiveValue::Int(9),
                ..
            }
        ]
    ));
}

#[test]
fn closure_without_captures_can_be_called_repeatedly() {
    let result = run(
        "value I(int); fn use_it(x: I) -> I { let f = fn(y: I) -> I { y }; let ignored = f(I(1)); f(x) } outputs { out: I = use_it(I(3)); }",
        &CheckPolicy::default(),
    );
    assert!(matches!(
        result.roots().next().unwrap().value(),
        Some(Value::Nominal {
            value: PrimitiveValue::Int(3),
            ..
        })
    ));
}

#[test]
fn nested_closure_captures_only_referenced_non_affine_bindings() {
    let result = run(
        "value I(int); resource R(int); fn make(x: I, unused: R) -> fn() -> fn() -> I { fn() -> fn() -> I { fn() -> I { x } } } fn use_it() -> I { let outer = make(I(15), R(1)); let inner = outer(); let one = inner(); inner() } outputs { out: I = use_it(); }",
        &CheckPolicy::default(),
    );
    assert!(matches!(
        result.roots().next().unwrap().value(),
        Some(Value::Nominal {
            value: PrimitiveValue::Int(15),
            ..
        })
    ));
}

#[test]
fn repeated_imported_output_is_evaluated_once_per_root() {
    let policy = CheckPolicy::default();
    let mut sources = SourceSet::new();
    sources.add("consumer/main.srx", "inputs { dep = \"path:child\"; } struct Pair { a: dep::X; b: dep::X; } outputs { pair: Pair = Pair { a = dep::item; b = dep::item; }; }").unwrap();
    let child = sources
        .create_project_domain(SourceDomainId::project(), "dep")
        .unwrap();
    let work = "let x = X {}; ".repeat(110);
    sources.add_to_project_domain(child, "child/main.srx", format!("pub struct X {{}} fn slow() -> X {{ {work} X {{}} }} outputs {{ item: X = slow(); }}")).unwrap();
    let program = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &policy,
    )
    .unwrap();
    let result = evaluate_with_limits(
        &program,
        &policy,
        &EvaluationEnvironment::new(&policy),
        EvaluationLimits {
            max_steps_per_root: 300,
            ..EvaluationLimits::default()
        },
    )
    .unwrap();
    assert!(result.is_success(), "{result:?}");
}

#[test]
fn claim_free_imported_output_is_shared_across_selected_roots() {
    let policy = CheckPolicy::default();
    let mut sources = SourceSet::new();
    sources.add("consumer/main.srx", "inputs { dep = \"path:child\"; } outputs { first: dep::X = dep::item; second: dep::X = dep::item; }").unwrap();
    let child = sources
        .create_project_domain(SourceDomainId::project(), "dep")
        .unwrap();
    let work = "let x = X {}; ".repeat(110);
    sources.add_to_project_domain(child, "child/main.srx", format!("pub struct X {{}} fn slow() -> X {{ {work} X {{}} }} outputs {{ item: X = slow(); }}")).unwrap();
    let program = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &policy,
    )
    .unwrap();
    let result = evaluate_with_limits(
        &program,
        &policy,
        &EvaluationEnvironment::new(&policy),
        EvaluationLimits {
            max_total_steps: 300,
            ..EvaluationLimits::default()
        },
    )
    .unwrap();
    assert!(result.is_success(), "{result:?}");
    assert_eq!(result.roots().len(), 2);
}

#[test]
fn standard_helper_uses_the_imported_project_callers_asset_origin() {
    let policy = CheckPolicy::default();
    let mut sources = SourceSet::new();
    sources
        .add(
            "consumer/main.srx",
            "inputs { child = \"path:child\"; } struct Pair { external: std::Request; local: std::Request; } outputs { request: Pair = Pair { external = child::make(); local = std::request(std::Url(\"project:assets/local\")); }; }",
        )
        .unwrap();
    let child = sources
        .create_project_domain(SourceDomainId::project(), "child")
        .unwrap();
    sources
        .add_to_project_domain(
            child,
            "child/main.srx",
            "pub fn make() -> std::Request { std::request(std::Url(\"project:assets/source\")) }",
        )
        .unwrap();
    sources.add_standard_library("std/lib.srx", "mod std { pub value Url(str); pub struct Request { url: Url; } pub fn request(url: Url) -> Request { Request { url = url; } } }").unwrap();
    let program = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &policy,
    )
    .unwrap();
    let result = evaluate(
        &program,
        &policy,
        &EvaluationEnvironment::new(&policy),
    )
    .unwrap();
    let Value::Struct {
        fields,
        ..
    } = result.roots().next().unwrap().value().unwrap()
    else {
        panic!("expected a pair");
    };
    let Value::Struct {
        owner: external,
        ..
    } = &fields[0].1
    else {
        panic!("expected imported request");
    };
    let Value::Struct {
        owner: local,
        ..
    } = &fields[1].1
    else {
        panic!("expected local request");
    };
    assert_eq!(*external, Some(child));
    assert_eq!(*local, Some(SourceDomainId::project()));
}

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
fn values_refine_without_claiming_and_predicates_run_on_evaluated_values() {
    fn even(value: i64) -> bool {
        value % 2 == 0
    }

    let policy = CheckPolicy::new("predicates")
        .unwrap()
        .with_predicate("number::even", PrimitiveType::Int)
        .unwrap();
    let program = checked(
        "value Even(int) where 2..=10, in [2, 4, 6, 8, 10], number::even(self); outputs { values: [Even] = [4, Even(6), 8]; }",
        &policy,
    );
    let environment = EvaluationEnvironment::new(&policy)
        .with_int_predicate("number::even", even)
        .unwrap();
    let result = evaluate(&program, &policy, &environment).unwrap();
    let root = result.roots().next().unwrap();
    assert!(root.value().is_some());
    assert_eq!(root.claims().count(), 0);

    let failed = checked(
        "value Even(int) where number::even(self); outputs { bad: Even = 3; }",
        &policy,
    );
    let failed = evaluate(&failed, &policy, &environment).unwrap();
    assert!(matches!(
        failed.roots().next().unwrap().outcome(),
        RealizedRootOutcome::Failed(_)
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
fn interpolation_concat_defaults_calls_match_fields_and_erasure_execute_checked_paths() {
    let policy = CheckPolicy::new("erasure")
        .unwrap()
        .with_erasure(identity("Box"), identity("Public"))
        .unwrap();
    let source = r#"
            value Name(str);
            value Text(str);
            enum Mode { Fast, Slow }
            struct Config { name: Name; mode: Mode = Fast; }
            struct Public { name: Name; }
            struct Box<T> { name: Name; hidden: T; }
            fn choose(mode: Mode) -> Name { match mode { Fast => "quick", Slow => "slow" } }
            fn greet(name: Name) -> Text { "hello ${name}" }
            fn config(name: Name) -> Config { let made = Config { name = name; }; made }
            outputs {
                words: [Name] = ["a"] ++ ["b"];
                greeting: Text = greet("world");
                selected: Name = choose(Slow);
                projected: Name = config("field").name;
                public: Public = erase<Public>(Box<Name> { name = "visible"; hidden = "secret"; });
            }
        "#;
    let result = run(source, &policy);
    assert!(
        result.is_success(),
        "{:?}",
        result.diagnostics().collect::<Vec<_>>()
    );
    assert_eq!(result.roots().len(), 5);
    assert!(matches!(
        result.roots().nth(1).unwrap().value(),
        Some(Value::Nominal { value: PrimitiveValue::Str(value), .. }) if value == "hello world"
    ));
    assert!(matches!(
        result.roots().nth(4).unwrap().value(),
        Some(Value::Struct { fields, .. }) if fields.len() == 1 && fields[0].0 == "name"
    ));
}

#[test]
fn generic_defaults_are_substituted_at_the_specialization() {
    let result = run(
        "struct Phantom<T> {} struct Holder<T> { marker: Phantom<T> = Phantom<T> {}; } struct S {} outputs { out: Holder<S> = Holder<S> {}; }",
        &CheckPolicy::default(),
    );
    let root = result.roots().next().unwrap();
    assert!(root.value().is_some(), "{:?}", root.diagnostics());
    assert!(matches!(
        root.ty(),
        Some(CanonicalType::Specialization { arguments, .. }) if arguments.len() == 1
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

#[test]
fn canonical_types_are_shared_and_root_claim_keys_are_distinct() {
    let result = run(
        "resource R(int); outputs { first: R = R(1); second: R = R(1); }",
        &CheckPolicy::default(),
    );
    let roots: Vec<_> = result.roots().collect();
    let first = roots[0].claims().next().unwrap();
    let second = roots[1].claims().next().unwrap();
    assert_ne!(first.key, second.key);
    assert_ne!(first.key.scope.root, second.key.scope.root);
    let value_ty = roots[0].value().unwrap().canonical_type();
    assert!(Arc::ptr_eq(&first.key.ty, &value_ty));
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

#[test]
fn maximum_supported_value_depth_drops_safely() {
    let ty = Arc::new(CanonicalType::Unit);
    let mut value = Value::Unit;
    for _ in 0..MAX_EVALUATION_DEPTH {
        value = Value::Struct {
            owner: None,
            ty: ty.clone(),
            fields: vec![(String::from("next"), value)],
        };
    }
    drop(value);
}

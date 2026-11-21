use super::*;

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

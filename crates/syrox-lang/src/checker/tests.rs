use super::*;
use crate::{resolver::resolve, source::SourceSet, syntax::parse_sources};

fn resolved(text: &str) -> ResolvedProgram {
    let mut sources = SourceSet::new();
    let prelude = "mod std { pub enum Bool { False, True } }";
    let text = if text.contains(prelude) {
        sources
            .add_standard_library("std.srx", prelude)
            .unwrap();
        text.replace(prelude, "")
    } else {
        text.to_owned()
    };
    sources.add("main.srx", text).unwrap();
    resolve(parse_sources(&sources).unwrap()).unwrap()
}

fn checked(text: &str) -> CheckedProgram {
    check(resolved(text), &CheckPolicy::default()).unwrap()
}

fn messages(text: &str) -> Vec<String> {
    check(resolved(text), &CheckPolicy::default())
        .unwrap_err()
        .into_iter()
        .map(|diagnostic| diagnostic.message)
        .collect()
}

fn identity(path: &str) -> CanonicalItemIdentity {
    CanonicalItemIdentity::new(SourceDomainId::project(), path.split("::")).unwrap()
}

#[test]
fn computed_and_nested_defaults_are_constants_in_globals_and_outputs() {
    checked(
        r#"
        value S(str); value I(int);
        enum Mode { Old, New }
        struct Inner { mode: Mode = choose("new"); }
        struct Selection { inner: Inner = Inner {}; }
        struct Old { port: I; } struct New { host: S; }
        fn choose(const name: S) -> Mode { match name { "new" => Mode::New } }
        fn select(const selection: Selection) -> _ {
            match selection.inner.mode {
                Old => Old { port = 7; }, New => New { host = "server"; }
            }
        }
        let selected = select(Selection {});
        outputs {
            global: New = selected;
            implicit: New = select(Selection {});
            explicit: New = select(Selection { inner = Inner { mode = choose("new"); }; });
        }
        "#,
    );
    checked(
        r#"
        value S(str); value I(int);
        let selected = select(Selection {});
        struct Selection { name: S = later; }
        let later: S = "new";
        fn select(const selection: Selection) -> I { match selection.name { "new" => 1 } }
        outputs { result: I = selected; }
        "#,
    );
    assert!(
        messages(
            r#"value S(str); value I(int); struct Selection { name: S = choose("bad"); } fn choose(const name: S) -> S { name } fn select(const selection: Selection) -> I { match selection.name { "new" => 1 } } let selected = select(Selection {});"#
        )
        .iter()
        .any(|message| message.contains("no applicable case"))
    );
}

#[test]
fn method_lookup_does_not_consume_computed_affine_receivers_twice() {
    let declarations = r"
        resource R(int); value I(int); struct Box { payload: R; }
        impl R {
            fn identity(r: R) -> R { r }
            fn selected(r: R, const choice: I) -> R { match choice { 1 => r } }
        }
        fn pass(r: R) -> R { r }
        struct Callback { run: once fn() -> R; }
        fn callback(r: R) -> Callback { Callback { run = once fn() -> R { r }; } }
    ";
    checked(&format!(
        "{declarations} fn call(r: R) -> R {{ pass(r).identity() }} fn projected(boxed: Box) -> R {{ boxed.payload.identity() }} fn selected(r: R) -> R {{ pass(r).selected(1) }} fn stored(r: R) -> R {{ callback(r).run() }}"
    ));
    for body in [
        "pass(r).identity(); r",
        "pass(r).selected(1); r",
        "callback(r).run(); r",
        "pass(r).identity().identity(); r",
    ] {
        assert!(
            messages(&format!(
                "{declarations} fn invalid(r: R) -> R {{ {body} }}"
            ))
            .iter()
            .any(|message| message.contains("moved affine value")),
            "{body}"
        );
    }
}

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
fn ordinary_control_flow_checks_coverage_branch_types_and_affine_moves() {
    checked(
        r#"mod std { pub enum Bool { False, True } } value S(str); value I(int); fn f(x: S) -> I { if x == "yes" { 1 } else { match x { "no" => 2, _ => 3 } } }"#,
    );
    for (source, expected) in [
        (
            r#"value S(str); value I(int); fn f(x: S) -> I { match x { "a" => 1 } }"#,
            "not exhaustive",
        ),
        (
            r"value I(int); fn f(x: I) -> I { match x { 1 => 1, 1 => 2, _ => 3 } }",
            "more than once",
        ),
        (
            r#"mod std { pub enum Bool { False, True } } value I(int); value S(str); fn f(x: std::Bool) -> I { if x { I(1) } else { S("bad") } }"#,
            "if branch",
        ),
        (
            r"mod std { pub enum Bool { False, True } } resource R(int); fn f(b: std::Bool, r: R) -> R { if b { let used = r; } else {}; r }",
            "moved",
        ),
        (
            r"mod std { pub enum Bool { False, True } } value I(int); fn f() -> I { if 1 { 1 } else { 2 } }",
            "if condition",
        ),
    ] {
        assert!(
            messages(source)
                .iter()
                .any(|message| message.contains(expected)),
            "{source}"
        );
    }
}

#[test]
fn constant_selectors_infer_each_contract_and_diagnose_at_the_call() {
    let declarations = r#"value S(str); value I(int); struct Selection { version: S; } struct Old { port: I; } struct New { host: S; } fn select(const selection: Selection) -> _ { match selection.version { "old" => Old { port = 7; }, "new" => New { host = "server"; } } }"#;
    checked(&format!(
        r#"{declarations} fn f() -> New {{ let version: S = "new"; select({{ version = version; }}) }} fn g() -> Old {{ select({{ version = "old"; }}) }}"#
    ));
    assert!(
        messages(&format!(
            r#"{declarations} fn f() -> Old {{ select({{ version = "unknown"; }}) }}"#
        ))
        .iter()
        .any(|message| message.contains("no applicable case"))
    );
    assert!(
        messages(&format!(
            r"{declarations} fn f(version: S) -> Old {{ select({{ version = version; }}) }}"
        ))
        .iter()
        .any(|message| message.contains("must be a known"))
    );
    assert!(
        messages(&format!(
            r#"{declarations} fn f() -> Old {{ select({{ version = "new"; }}) }}"#
        ))
        .iter()
        .any(|message| message.contains("function return"))
    );
    let recursive = resolved(
        r"value I(int); fn recurse(const n: I) -> _ { recurse(n) } fn f() -> I { recurse(1) }",
    );
    let errors = check_with_limits(
        recursive,
        &CheckPolicy::default(),
        CheckLimits {
            max_specialization_depth: 4,
            ..CheckLimits::default()
        },
    )
    .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("specialization limit"))
    );
}

#[test]
fn static_traits_enforce_complete_coherent_implementations_and_bounds() {
    let declarations = "value I(int); struct P {} trait Package { type Settings; fn render(p: Self, settings: Self::Settings) -> I; }";
    for (implementation, expected) in [
        ("impl Package for P {}", "associated types"),
        (
            "impl Package for P { type Settings = I; }",
            "missing method",
        ),
        (
            "impl Package for P { type Settings = I; fn render(p: P, settings: P) -> I { 1 } }",
            "signature differs",
        ),
        (
            "impl Package for P { type Settings = I; type Extra = I; fn render(p: P, settings: I) -> I { settings } }",
            "associated types",
        ),
        (
            "impl Package for P { type Settings = I; fn render(p: P, settings: I) -> I { settings } } impl Package for P { type Settings = I; fn render(p: P, settings: I) -> I { settings } }",
            "ambiguous duplicate",
        ),
        (
            "fn render<T: Package>(p: T, settings: T::Settings) -> I { T::render(p, settings) } fn use_it() -> I { render(P {}, 1) }",
            "trait",
        ),
    ] {
        let errors = messages(&format!("{declarations} {implementation}"));
        assert!(
            errors
                .iter()
                .any(|message| message.contains(expected)),
            "{implementation}: {errors:?}"
        );
    }
    checked(&format!(
        "{declarations} impl Package for P {{ type Settings = I; fn render(p: P, settings: I) -> I {{ settings }} }} fn render<T: Package>(p: T, settings: T::Settings) -> I {{ T::render(p, settings) }} fn use_it() -> I {{ render(P {{}}, 7) }}"
    ));
}

#[test]
fn static_traits_check_inheritance_ambiguity_and_affine_consumption() {
    for (source, expected) in [
        ("trait A: B {} trait B: A {}", "cyclic trait"),
        (
            "struct P {} trait A {} trait B: A {} impl B for P {}",
            "parent trait",
        ),
        (
            "value I(int); struct P {} trait A { type Settings; } trait B: A { type Settings; } impl A for P { type Settings = I; } impl B for P { type Settings = I; } fn f<T: B>(p: T, s: T::Settings) -> I { 1 } fn g() -> I { f(P {}, 1) }",
            "ambiguous associated type",
        ),
        (
            "resource R(int); struct P {} trait Take { fn take(p: Self, r: R) -> R; } impl Take for P { fn take(p: P, r: R) -> R { r; r } }",
            "moved affine",
        ),
    ] {
        let errors = messages(source);
        assert!(
            errors
                .iter()
                .any(|message| message.contains(expected)),
            "{source}: {errors:?}"
        );
    }
}

#[test]
fn failed_static_match_reports_the_invocation_span() {
    let source = r#"value S(str); value I(int); fn inner(const v: S) -> _ { match v { "known" => I(1) } } fn select(const v: S) -> _ { inner(v) } fn use_it() -> I { select("unknown") }"#;
    let errors = check(resolved(source), &CheckPolicy::default()).unwrap_err();
    let error = errors
        .iter()
        .find(|error| error.message.contains("no applicable case"))
        .unwrap();
    assert!(source[error.span.start() as usize..error.span.end() as usize].contains("select"));
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
fn aliases_expand_structurally_and_cycles_are_rejected() {
    checked("struct S {} type A = S; type B = A; fn f(x: B) -> S { x }");
    assert!(
        messages("type A = B; type B = A;")
            .iter()
            .any(|message| message.contains("cyclic type alias"))
    );
}

#[test]
fn generic_aliases_and_public_templates_preserve_specialization() {
    checked(
        "struct Item {} struct Box<T> { item: T; } type Wrapped<T> = Box<T>; \
         mod api { outputs { type Box = Box; type Wrapped = Wrapped; } } \
         outputs { out: api::Wrapped<Item> = Box<Item> { item = Item {}; }; }",
    );
    checked(
        "struct Item {} struct Box<T> { item: T; } type Wrapped<T> = Box<T>; \
         outputs { out: Wrapped<Item> = Box<Item> { item = Item {}; }; }",
    );
    assert!(
        messages("struct Box<T> {} type Wrapped<T> = Box<T>; type Bad = Wrapped;")
            .iter()
            .any(|message| message.contains("generic alias expects 1"))
    );
    assert!(
        messages("struct Box<T> {} type Loop<T> = Loop<T>;")
            .iter()
            .any(|message| message.contains("cyclic type alias"))
    );
    let mut sources = SourceSet::new();
    sources
        .add("duplicate.srx", "type Alias<T, T> = T;")
        .unwrap();
    assert!(
        resolve(parse_sources(&sources).unwrap())
            .unwrap_err()
            .iter()
            .any(|error| error.message.contains("duplicate type parameter"))
    );
}

#[test]
fn generic_reexports_from_an_input_keep_their_original_type_identity() {
    let mut sources = SourceSet::new();
    sources
        .add(
            "main.srx",
            r#"inputs { dep = "path:dep"; }
        struct Item {}
        outputs { result: dep::Wrapped<Item> = dep::Box<Item> { item = Item {}; }; }"#,
        )
        .unwrap();
    let input = sources.create_input_domain("dep").unwrap();
    sources
        .add_to_input_domain(
            input,
            "dep/box.srx",
            r"
        struct Box<T> { item: T; }
        type Wrapped<T> = Box<T>;
        outputs { type Wrapped = Wrapped; type Box = Box; }
    ",
        )
        .unwrap();
    check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap();
}

#[test]
fn public_type_and_function_are_exported_without_an_outputs_block() {
    let mut sources = SourceSet::new();
    sources
        .add(
            "main.srx",
            r#"inputs { dep = "path:dep"; }
        outputs { result: dep::Box<dep::Item> = dep::make(); }"#,
        )
        .unwrap();
    let input = sources.create_input_domain("dep").unwrap();
    sources
        .add_to_input_domain(
            input,
            "dep/lib.srx",
            r"
        pub struct Item {}
        pub struct Box<T> { item: T; }
        pub fn make() -> Box<Item> { Box<Item> { item = Item {}; } }
    ",
        )
        .unwrap();
    check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap();
}

#[test]
fn public_declarations_cannot_repeat_explicit_exports() {
    let mut sources = SourceSet::new();
    sources.add("main.srx", "pub fn make() -> Item { Item {} } struct Item {} outputs { make: fn() -> Item = make; }").unwrap();
    assert!(
        resolve(parse_sources(&sources).unwrap())
            .unwrap_err()
            .iter()
            .any(|error| error.message.contains("duplicate output name"))
    );
}

#[test]
fn public_import_reexports_the_original_item_identity() {
    let mut sources = SourceSet::new();
    sources
        .add(
            "main.srx",
            r#"inputs { dep = "path:dep"; }
        mod facade { pub use dep::Item; }
        outputs { result: facade::Item = dep::Item {}; }"#,
        )
        .unwrap();
    let dep = sources.create_input_domain("dep").unwrap();
    sources
        .add_to_input_domain(dep, "dep/item.srx", "pub struct Item {}")
        .unwrap();
    check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap();
}

#[test]
fn function_value_signature_and_callee_are_checked() {
    assert!(messages("value I(int); value S(str); fn id(x: I) -> I { x } fn use_it(f: fn(S) -> S) -> S { f(S(\"ok\")) } outputs { bad: S = use_it(id); }")
        .iter().any(|message| message.contains("call argument type mismatch")));
    assert!(
        messages("value I(int); fn bad(x: I) -> I { x(I(2)) }")
            .iter()
            .any(|message| message.contains("callee is not a function value"))
    );
}

#[test]
fn generic_functions_reject_duplication_and_invalid_specializations() {
    for source in [
        "fn duplicate<T>(x: T) -> [T] { [x, x] }",
        "fn captured<T>(x: T) -> fn() -> T { fn() -> T { x } }",
        "value I(int); fn id<T>(x: T) -> T { x } fn bad() -> I { let unresolved = id; I(1) }",
        "value I(int); fn id<T>(x: T) -> T { x } outputs { bad: I = id<I, I>(I(1)); }",
        "value I(int); value S(str); fn id<T>(x: T) -> T { x } outputs { bad: I = id<I>(S(\"wrong\")); }",
        "value I(int); fn id<T>(x: T) -> T { x } outputs { bad: [I] = fold([I(1)], [], id<I>); }",
    ] {
        assert!(!messages(source).is_empty(), "{source}");
    }
}

#[test]
fn local_generic_inference_rejects_ambiguity_conflicts_and_double_moves() {
    for (source, expected) in [
        (
            "value I(int); fn phantom<T>(x: I) -> I { x } outputs { bad: I = phantom(I(1)); }",
            "cannot infer all generic arguments",
        ),
        (
            "value I(int); value S(str); fn same<T>(left: T, right: T) -> T { left } outputs { bad: I = same(I(1), S(\"x\")); }",
            "inferred generic argument type mismatch",
        ),
        (
            "resource R(int); fn pair<T>(left: T, right: T) -> [T] { [left, right] } fn bad(r: R) -> [R] { pair(r, r) }",
            "use of moved affine value",
        ),
        (
            "value I(int); enum Option<T> { None, Some(T) } fn bad() -> I { let x = Option::None(); I(1) }",
            "cannot infer all generic arguments",
        ),
        (
            "value I(int); value S(str); fn id<T>(x: T) -> T { x } fn bad() -> fn(I) -> S { id }",
            "inferred generic argument type mismatch",
        ),
    ] {
        let diagnostics = messages(source);
        assert!(
            diagnostics
                .iter()
                .any(|message| message.contains(expected)),
            "{source}: {diagnostics:?}"
        );
    }
}

#[test]
fn comparisons_join_affine_moves_and_require_ordered_matching_operands() {
    checked("resource R(int); fn pick(r: R) -> R { compare(1, 2, r, r, r) }");
    for (source, expected) in [
        (
            "resource R(int); fn bad(r: R) -> [R] { let selected = compare(1, 2, [r], [], []); selected ++ [r] }",
            "use of moved affine value",
        ),
        (
            "resource R(int); fn bad(r: R) -> R { compare(1, 2, r, r, r); r }",
            "use of moved affine value",
        ),
        (
            "value I(int); fn bad() -> I { compare(1, \"x\", I(1), I(2), I(3)) }",
            "comparison operand type mismatch",
        ),
        (
            "resource R(int); value I(int); fn bad(a: R, b: R) -> I { compare(a, b, I(1), I(2), I(3)) }",
            "comparison requires",
        ),
        (
            "value I(int); fn bad() -> I { compare([], [], I(1), I(2), I(3)) }",
            "empty list requires",
        ),
        (
            "value I(int); value S(str); fn bad() -> I { compare(1, 2, I(1), S(\"x\"), I(3)) }",
            "comparison branch type mismatch",
        ),
    ] {
        let diagnostics = messages(source);
        assert!(
            diagnostics
                .iter()
                .any(|message| message.contains(expected)),
            "{source}: {diagnostics:?}"
        );
    }
}

#[test]
fn module_exports_require_concrete_public_function_signatures_and_reusable_mappers() {
    for (declarations, mapper, expected) in [
        (
            "value Key(str); value I(int); mod collection { pub fn make() -> I { I(1) } }",
            "once fn(key: Key, make: fn() -> I) -> Key { key }",
            "module mapper must be a reusable function",
        ),
        (
            "resource Key(str); value I(int); mod collection { pub fn make() -> I { I(1) } }",
            "fn(key: Key, make: fn() -> I) -> Key { key }",
            "module key must be a reusable value(str)",
        ),
        (
            "value Key(str); value I(int); mod collection { pub fn make<T>(item: T) -> T { item } }",
            "fn(key: Key, make: fn() -> I) -> Key { key }",
            "requires explicit generic specialization",
        ),
        (
            "value Key(str); value I(int); mod collection { pub fn make(item: I) -> I { item } }",
            "fn(key: Key, make: fn() -> I) -> Key { key }",
            "module export `` type mismatch",
        ),
    ] {
        let source = format!(
            "{declarations} outputs {{ keys: [Key] = module_exports(collection, make, {mapper}); }}"
        );
        let errors = messages(&source);
        assert!(
            errors
                .iter()
                .any(|message| message.contains(expected)),
            "{errors:?}"
        );
    }
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
fn payload_enum_patterns_are_exhaustive_scoped_and_affine() {
    for (source, expected) in [
        (
            "resource R(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<[[R]]>) -> [Maybe<[[R]]>] { [x, x] }",
            "use of moved affine value",
        ),
        (
            "value I(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<once fn() -> I>) -> [I] { match x { Some(f) => [f(), f()], None => [] } }",
            "use of moved affine value",
        ),
        (
            "resource R(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<R>) -> [R] { match x { Some(r) => [r, r], None => [] } }",
            "use of moved affine value",
        ),
        (
            "resource R(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<R>) -> [Maybe<R>] { [x, x] }",
            "use of moved affine value",
        ),
        (
            "value I(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<I>) -> [I] { match x { None => [] } }",
            "match is not exhaustive",
        ),
        (
            "value I(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<I>) -> [I] { match x { Some => [], None => [] } }",
            "pattern payload binding count mismatch",
        ),
        (
            "value I(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<I>) -> [I] { match x { Some(a, b) => [a], None => [] } }",
            "pattern payload binding count mismatch",
        ),
        (
            "value I(int); enum Maybe<T> { None, Some(T) } outputs { bad: Maybe<I> = Maybe::Some<I>(); }",
            "expected 1 argument",
        ),
        (
            "value I(int); enum Maybe<T> { None, Some(T) } outputs { bad: Maybe<I> = Maybe::Some; }",
            "payload requires a constructor",
        ),
    ] {
        assert!(
            messages(source)
                .iter()
                .any(|message| message.contains(expected)),
            "{source}"
        );
    }
}

#[test]
fn consumable_closures_move_captures_and_cannot_be_called_twice() {
    for source in [
        "resource R(int); fn bad(r: R) -> R { let f = once fn() -> R { r }; r }",
        "resource R(int); fn bad(r: R) -> [R] { let f = once fn() -> R { r }; [f(), f()] }",
        "resource R(int); fn bad(r: R) -> [R] { let moved = r; let f = once fn() -> R { r }; [moved, f()] }",
        "resource R(int); struct H { deferred: once fn() -> R; } fn bad(h: H) -> [H] { [h, h] }",
        "resource R(int); fn bad(r: R) -> fn() -> R { once fn() -> R { r } }",
        "resource R(int); fn bad(r: R) -> [R] { fold([r], [], once fn(acc: [R], x: R) -> [R] { acc ++ [x] }) }",
    ] {
        assert!(!messages(source).is_empty(), "{source}");
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
fn function_list_element_signature_must_match() {
    assert!(messages(
        "value I(int); value S(str); fn id(x: I) -> I { x } outputs { bad: [fn(S) -> S] = [id]; }"
    ).iter().any(|message| message.contains("type mismatch")));
    check(
        resolved("value I(int); outputs { good: [[I]] = [[I(1)], []]; }"),
        &CheckPolicy::default(),
    )
    .unwrap();
    assert!(messages("resource R(int); struct Holder { items: [[R]]; } fn bad(h: Holder) -> Holder { let first = h; h }")
        .iter().any(|message| message.contains("use of moved affine value")));
}

#[test]
fn closure_rejects_affine_capture_and_checks_return_type() {
    assert!(
        messages("resource R(int); fn bad(r: R) -> fn() -> R { fn() -> R { r } }")
            .iter()
            .any(|message| message.contains("closure cannot capture an affine value"))
    );
    assert!(
        messages(
            "value I(int); value S(str); fn bad() -> fn() -> I { fn() -> I { S(\"wrong\") } }"
        )
        .iter()
        .any(|message| message.contains("closure return type mismatch"))
    );
}

#[test]
fn imported_projects_resolve_their_own_input_aliases() {
    let mut sources = SourceSet::new();
    sources
        .add(
            "consumer/main.srx",
            r#"inputs { pkgs = "path:../pkgs"; recipes = "path:local"; }
        outputs { from_child: pkgs::X = pkgs::get(); from_local: recipes::X = recipes::make(); }"#,
        )
        .unwrap();
    let child = sources
        .create_project_domain(SourceDomainId::project(), "pkgs")
        .unwrap();
    sources
        .add_to_project_domain(
            child,
            "pkgs/main.srx",
            r#"inputs { recipes = "path:recipes"; }
        pub type X = recipes::X; pub fn get() -> X { recipes::make() }"#,
        )
        .unwrap();
    let child_recipes = sources
        .create_child_input_domain(child, "recipes")
        .unwrap();
    sources
        .add_to_input_domain(
            child_recipes,
            "pkgs/recipes/item.srx",
            "pub struct X {} pub fn make() -> X { X {} }",
        )
        .unwrap();
    let local = sources.create_input_domain("recipes").unwrap();
    sources
        .add_to_input_domain(
            local,
            "consumer/local/item.srx",
            "pub struct X {} pub fn make() -> X { X {} }",
        )
        .unwrap();
    let checked = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap();
    let policy = CheckPolicy::default();
    let result = crate::evaluator::evaluate(
        &checked,
        &policy,
        &crate::evaluator::EvaluationEnvironment::new(&policy),
    )
    .unwrap();
    assert_eq!(result.roots().count(), 2);
    assert!(result.is_success());

    let mut isolated = SourceSet::new();
    isolated
        .add(
            "consumer/main.srx",
            "inputs { pkgs = \"path:../pkgs\"; recipes = \"path:local\"; }",
        )
        .unwrap();
    let child = isolated
        .create_project_domain(SourceDomainId::project(), "pkgs")
        .unwrap();
    isolated
        .add_to_project_domain(
            child,
            "pkgs/main.srx",
            "pub fn bad(x: recipes::X) -> recipes::X { x }",
        )
        .unwrap();
    let local = isolated.create_input_domain("recipes").unwrap();
    isolated
        .add_to_input_domain(
            local,
            "consumer/local/item.srx",
            "pub struct X {}",
        )
        .unwrap();
    assert!(
        resolve(parse_sources(&isolated).unwrap())
            .unwrap_err()
            .iter()
            .any(|error| error.message.contains("unknown type"))
    );
}

#[test]
fn imported_project_value_outputs_are_checked_and_realized_on_reference() {
    let mut sources = SourceSet::new();
    sources
        .add(
            "consumer/main.srx",
            "inputs { dep = \"path:child\"; } outputs { selected: dep::X = dep::selected; }",
        )
        .unwrap();
    let child = sources
        .create_project_domain(SourceDomainId::project(), "dep")
        .unwrap();
    sources.add_to_project_domain(child, "child/main.srx", "pub struct X {} fn forever() -> X { forever() } outputs { selected: X = X {}; disconnected: X = forever(); }").unwrap();
    let policy = CheckPolicy::default();
    let checked = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &policy,
    )
    .unwrap();
    let result = crate::evaluator::evaluate(
        &checked,
        &policy,
        &crate::evaluator::EvaluationEnvironment::new(&policy),
    )
    .unwrap();
    assert_eq!(result.roots().count(), 1);
    assert!(result.is_success());

    let mut cyclic = SourceSet::new();
    cyclic
        .add(
            "consumer/main.srx",
            "inputs { dep = \"path:child\"; } outputs { selected: dep::X = dep::a; }",
        )
        .unwrap();
    let child = cyclic
        .create_project_domain(SourceDomainId::project(), "dep")
        .unwrap();
    cyclic
        .add_to_project_domain(
            child,
            "child/main.srx",
            "pub struct X {} outputs { a: X = b; b: X = a; }",
        )
        .unwrap();
    let checked = check(
        resolve(parse_sources(&cyclic).unwrap()).unwrap(),
        &policy,
    )
    .unwrap();
    let result = crate::evaluator::evaluate(
        &checked,
        &policy,
        &crate::evaluator::EvaluationEnvironment::new(&policy),
    )
    .unwrap();
    assert!(result.diagnostics().any(|error| {
        error
            .message
            .contains("cycle in imported value outputs")
    }));
    let mut affine = SourceSet::new();
    affine
        .add(
            "consumer/main.srx",
            "inputs { dep = \"path:child\"; } outputs { selected: dep::R = dep::port; }",
        )
        .unwrap();
    let child = affine
        .create_project_domain(SourceDomainId::project(), "dep")
        .unwrap();
    affine
        .add_to_project_domain(
            child,
            "child/main.srx",
            "pub resource R(int); outputs { port: R = R(1); }",
        )
        .unwrap();
    assert!(
        check(
            resolve(parse_sources(&affine).unwrap()).unwrap(),
            &policy
        )
        .unwrap_err()
        .iter()
        .any(|error| error
            .message
            .contains("imported value output cannot carry an affine resource"))
    );
}

#[test]
fn public_import_conflicts_with_a_repeated_output_export() {
    let mut sources = SourceSet::new();
    sources.add("main.srx", "mod base { struct Item {} outputs { type Item = Item; } } mod facade { pub use base::Item; outputs { type Item = base::Item; } }").unwrap();
    let errors = resolve(parse_sources(&sources).unwrap()).unwrap_err();
    assert!(
        errors.iter().any(|error| error
            .message
            .contains("public import conflicts with an export")),
        "{errors:?}"
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
fn generic_arity_and_composite_arguments_are_checked() {
    checked(
        "struct S {} struct Box<T> { item: T; } struct Outer<T> { inner: Box<T>; } outputs { out: Outer<S> = Outer<S> { inner = Box<S> { item = S {}; }; }; }",
    );
    assert!(
        messages("struct Box<T> {} type Bad = Box;")
            .iter()
            .any(|message| message.contains("expects 1 type argument"))
    );
    checked(
        "struct Box<T> { item: T; } struct S {} type Nested<T> = Box<[[T]]>; outputs { out: Nested<S> = Box<[[S]]> { item = [[S {}]]; }; }",
    );
}

#[test]
fn contextual_variants_literals_and_empty_lists_are_elaborated() {
    let program = checked(
        "value Name(str); enum Mode { Fast, Slow } struct C { name: Name; modes: [Mode]; } outputs { c: C = C { name = \"x\"; modes = [Fast, Slow]; }; }",
    );
    assert!(program.expressions().any(|expression| matches!(
        expression.elaboration(),
        Some(Elaboration::ValueLiteral(_))
    )));
    assert_eq!(
        program
            .expressions()
            .filter(|expression| matches!(
                expression.elaboration(),
                Some(Elaboration::ContextualVariant { .. })
            ))
            .count(),
        2
    );
    checked("enum E { A } outputs { values: [E] = []; }");
    assert!(
        messages("fn f() { []; }")
            .iter()
            .any(|message| message.contains("empty list requires"))
    );
}

#[test]
fn calls_structs_returns_and_outputs_must_match_exactly() {
    let errors = messages(
        "value V(str); struct S { v: V; } fn make(v: V) -> S { S { v = 1; extra = v; } } outputs { bad: V = make(\"x\"); }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("struct field type mismatch"))
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("unknown field"))
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("output value type mismatch"))
    );

    assert!(
        messages("value V(str); fn f(x: V) -> V { 1 }")
            .iter()
            .any(|message| message.contains("function return type mismatch"))
    );
}

#[test]
fn match_requires_unique_reachable_exhaustive_homogeneous_arms() {
    let errors =
        messages("value I(int); enum E { A, B } fn f(e: E) -> I { match e { A => 1, A => 2 } }");
    assert!(
        errors
            .iter()
            .any(|message| message.contains("more than once"))
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("not exhaustive"))
    );
    assert!(
        messages("value I(int); enum E { A } fn f(e: E) -> I { match e { _ => 1, A => \"x\" } }")
            .iter()
            .any(|message| message.contains("unreachable"))
    );
}

#[test]
fn affine_values_cannot_be_reused_and_branch_moves_join() {
    checked("resource R(int); struct Phantom<T> {} fn f(x: Phantom<R>) { x; x; }");
    assert!(
        messages("resource R(int); struct Box<T> { item: T; } fn f(x: Box<R>) { x; x; }")
            .iter()
            .any(|message| message.contains("moved affine"))
    );
    assert!(
        messages("resource R(int); fn f(x: R) { x; x; }")
            .iter()
            .any(|message| message.contains("moved affine"))
    );
    let errors = messages(
        "resource R(int); enum E { A, B } fn take(x: R) {} fn nothing() {} fn f(e: E, x: R) { match e { A => take(x), B => nothing() }; take(x); }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("moved affine"))
    );
}

#[test]
fn nested_generic_resource_remains_affine() {
    let errors =
        messages("resource R(int); struct Box<T> { item: T; } fn f(x: Box<Box<R>>) { x; x; }");
    assert!(
        errors
            .iter()
            .any(|message| message.contains("moved affine")),
        "{errors:?}"
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
fn opaque_construction_rejects_a_different_authenticated_domain() {
    let mut sources = SourceSet::new();
    sources
        .add_standard_library(
            "std.srx",
            "mod std { opaque struct Secret {} outputs { type Secret = Secret; } }",
        )
        .unwrap();
    sources
        .add(
            "main.srx",
            "outputs { bad: std::Secret = std::Secret {}; }",
        )
        .unwrap();
    let errors = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap_err();
    assert!(errors.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("opaque struct constructor")
    }));
}

#[test]
fn opaque_fields_are_private_through_aliases_projection_chains_and_interpolation() {
    for body in [
        "fn leak(item: vault::Secret<I>) -> I { item.payload }",
        "type Alias = vault::Secret<I>; fn leak(item: Alias) -> I { item.payload }",
        "struct Holder { hidden: vault::Secret<I>; } fn leak(item: Holder) -> I { item.hidden.payload }",
        "fn leak(item: vault::Secret<I>) -> S { S(\"${item.payload}\") }",
        "mod impostor { pub use vault::Secret; fn leak(item: Secret<I>) -> I { item.payload } }",
    ] {
        let source = format!(
            r"
            value I(int); value S(str);
            mod vault {{
                pub opaque struct Secret<T> {{ payload: T; }}
                pub fn reveal<T>(item: Secret<T>) -> T {{ item.payload }}
                mod nested {{ fn reveal<T>(item: Secret<T>) -> T {{ item.payload }} }}
            }}
            {body}
        "
        );
        let errors = messages(&source);
        assert!(
            errors
                .iter()
                .any(|message| message.contains("opaque struct fields are private")),
            "{errors:?}"
        );
        assert_eq!(
            errors
                .iter()
                .filter(|message| message.contains("opaque struct fields are private"))
                .count(),
            1
        );
    }
}

#[test]
fn opaque_representation_authority_is_lexical_or_explicitly_delegated() {
    check(
        resolved(
            r"
        value I(int);
        mod vault {
            pub opaque struct Secret<owner O> { payload: I; }
            pub fn reveal(item: Secret<agent::Owner>) -> I { item.payload }
        }
        mod agent {
            pub struct Owner {}
            pub fn make() -> vault::Secret<Owner> { vault::Secret<Owner> { payload = I(1); } }
            pub fn reveal(item: vault::Secret<Owner>) -> I { item.payload }
        }
        outputs { result: I = vault::reveal(agent::make()); }
    ",
        ),
        &CheckPolicy::default(),
    )
    .unwrap();
}

#[test]
fn opaque_field_access_cannot_be_obtained_by_reexporting_an_authenticated_type() {
    let mut sources = SourceSet::new();
    sources
        .add_standard_library(
            "std.srx",
            r"
        mod std {
            pub value I(int);
            pub opaque struct Secret { payload: I; }
            pub fn reveal(item: Secret) -> I { item.payload }
        }
    ",
        )
        .unwrap();
    sources
        .add(
            "main.srx",
            r"
        pub use std::Secret;
        fn valid(item: Secret) -> std::I { std::reveal(item) }
        fn invalid(item: Secret) -> std::I { item.payload }
    ",
        )
        .unwrap();
    let errors = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0]
            .message
            .contains("opaque struct fields are private")
    );
}

#[test]
fn direct_calls_cannot_copy_affine_outputs_or_call_plain_values() {
    let errors = messages(
        "value I(int); outputs { factory: once fn() -> I = once fn() -> I { I(1) }; bad: I = factory(); }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("value output cannot carry an affine resource")),
        "{errors:?}"
    );
    let errors = messages("value I(int); outputs { number: I = I(1); bad: I = number(); }");
    assert!(
        errors
            .iter()
            .any(|message| message.contains("callee is not a function value")),
        "{errors:?}"
    );
}

#[test]
fn refinements_are_validated_against_closed_policy_data() {
    let policy = CheckPolicy::new("test")
        .unwrap()
        .with_scope("net")
        .unwrap()
        .with_predicate("path::clean", PrimitiveType::Str)
        .unwrap();
    let errors = check(
            resolved(
                "resource Mixed(int) where in [1, \"x\"]; resource Bad(str) where 2..2; value V(str) in net; value P(int) where path::clean(self);",
            ),
            &policy,
        )
        .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("homogeneous"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("only refine `int`"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("ownership scope"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("wrong primitive"))
    );
}

#[test]
fn erasure_is_explicitly_policy_controlled() {
    let source = "struct Public { n: N; } value N(int); struct Box<T> { n: N; hidden: T; } outputs { p: Public = erase<Public>(Box<N> { n = 1; hidden = 2; }); }";
    assert!(
        messages(source)
            .iter()
            .any(|message| message.contains("not allowed"))
    );
    check(
        resolved(source),
        &CheckPolicy::new("erase-v1")
            .unwrap()
            .with_erasure(identity("Box"), identity("Public"))
            .unwrap(),
    )
    .unwrap();
}

#[test]
fn checked_program_carries_policy_identity_and_detects_mismatch() {
    let first = CheckPolicy::new("first").unwrap();
    let program = check(resolved("struct S {}"), &first).unwrap();
    assert_eq!(program.policy_identity(), "first");
    assert!(program.require_policy(&first).is_ok());
    let mismatch = program
        .require_policy(&CheckPolicy::new("second").unwrap())
        .unwrap_err();
    assert_ne!(mismatch.checked, mismatch.supplied);
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
fn policy_is_canonical_bounded_and_rejects_conflicts() {
    let once = CheckPolicy::new("policy")
        .unwrap()
        .with_scope("net")
        .unwrap()
        .with_predicate("p", PrimitiveType::Int)
        .unwrap();
    let duplicate = once
        .clone()
        .with_scope("net")
        .unwrap()
        .with_predicate("p", PrimitiveType::Int)
        .unwrap();
    assert_eq!(once, duplicate);
    assert_eq!(once.fingerprint(), duplicate.fingerprint());
    assert_eq!(once.predicates().count(), 1);
    assert!(matches!(
        once.with_predicate("p", PrimitiveType::Str),
        Err(PolicyError::ConflictingPredicate { .. })
    ));
    assert!(matches!(
        CheckPolicy::new("x".repeat(MAX_POLICY_BYTES + 1)),
        Err(PolicyError::TooManyBytes)
    ));

    let mut policy = CheckPolicy::new("entries").unwrap();
    for index in 0..MAX_POLICY_ENTRIES {
        policy = policy.with_scope(format!("s{index}")).unwrap();
    }
    assert_eq!(
        policy.with_scope("overflow").unwrap_err(),
        PolicyError::TooManyEntries
    );
}

#[test]
fn policy_matching_is_exact_and_erasure_authority_includes_domain() {
    let first = CheckPolicy::new("same")
        .unwrap()
        .with_scope("a")
        .unwrap();
    let second = CheckPolicy::new("same")
        .unwrap()
        .with_scope("b")
        .unwrap();
    let checked = check(resolved("struct S {}"), &first).unwrap();
    assert!(checked.require_policy(&second).is_err());

    let mut sources = SourceSet::new();
    sources
            .add_standard_library(
                "std.srx",
                "mod std { value N(int); struct Public { n: N; } struct Box<T> { n: N; hidden: T; } outputs { type N = N; type Public = Public; type BoxN = Box<N>; } }",
            )
            .unwrap();
    sources
            .add(
                "main.srx",
                "mod std { value N(int); struct Public { n: N; } struct Box<T> { n: N; hidden: T; } fn exploit() -> Public { erase<Public>(Box<N> { n = 1; hidden = 2; }) } }",
            )
            .unwrap();
    let policy = CheckPolicy::new("domain erasure")
        .unwrap()
        .with_erasure(
            CanonicalItemIdentity::new(SourceDomainId::standard_library(), ["std", "Box"]).unwrap(),
            CanonicalItemIdentity::new(
                SourceDomainId::standard_library(),
                ["std", "Public"],
            )
            .unwrap(),
        )
        .unwrap();
    let errors = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &policy,
    )
    .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("erasure is not allowed"))
    );
}

#[test]
fn indirect_specialized_carriers_remain_affine_but_phantoms_do_not() {
    let errors = messages(
        "resource R(int); struct Inner { r: R; } struct Box<T> { x: T; } struct Outer { b: Box<Inner>; } fn f(x: Outer) { x; x; }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("moved affine"))
    );
    checked("resource R(int); struct Phantom<T> {} fn f(x: Phantom<R>) { x; x; }");
    checked(
        "resource R(int); struct Phantom<T> {} struct Outer { item: Phantom<R>; } fn f(x: Outer) { x; x; }",
    );
}

#[test]
fn contextual_match_patterns_are_validated_and_recorded() {
    let errors = messages(
        "enum E { A } enum Other { Bogus } fn f(e: E) -> E { match e { Bogus => E::A, _ => E::A } }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("enum has no variant `Bogus`"))
    );

    let program = checked("enum E { A } fn f(e: E) -> E { match e { A => E::A } }");
    let pattern = program.patterns().next().unwrap();
    assert_eq!(pattern.index(), 0);
}

#[test]
fn declared_return_type_elaborates_function_tails() {
    checked(
        "enum E { A } value V(int); fn enum_value() -> E { A } fn wrapped() -> V { 1 } fn empty() -> [E] { [] }",
    );
}

#[test]
fn generic_defaults_are_checked_symbolically() {
    let program = checked(
        "struct Phantom<T> {} struct G<T> { p: Phantom<T> = Phantom<T> {}; } struct S {} outputs { g: G<S> = G<S> {}; }",
    );
    assert!(program.expressions().any(|expression| matches!(
        expression.ty(),
        Ty::Specialization { arguments, .. }
            if matches!(arguments.as_slice(), [Ty::Parameter(_)])
    )));
    assert!(
        messages("struct Bad<T> { item: T = 1; }")
            .iter()
            .any(|message| message.contains("struct field default type mismatch"))
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

#[test]
fn globals_infer_forward_dependencies_and_contextualize_literals() {
    checked(
        r#"value S(str); value I(int); struct Target { system: S; libc: S; }
        let packages = select(target); let target: Target = { system = system; libc = "musl"; };
        let system = "linux-x86_64";
        fn select(const target: Target) -> _ { match target.libc { "musl" => I(7), "gnu" => S("gnu") } }
        outputs { number: I = packages; text: S = system; }
    "#,
    );
    checked(
        r"value I(int); let identity: fn(I) -> I = fn(x: I) -> I { x }; let result = identity(7); outputs { number: I = result; }",
    );
    for (source, expected) in [
        (
            "let a = b; let b = a;",
            "cycle in global bindings",
        ),
        (
            "resource R(int); let r = R(1);",
            "affine resource",
        ),
        (
            "resource R(int); value I(int); fn consume(r: R) -> I { I(1) } let result = consume(R(1));",
            "affine resource",
        ),
        (
            "resource R(int); value I(int); fn hidden() -> I { let r = R(1); I(1) } let result = hidden();",
            "affine resource",
        ),
    ] {
        assert!(
            messages(source)
                .iter()
                .any(|message| message.contains(expected)),
            "{source}"
        );
    }
}

#[test]
fn configuration_selects_known_branches_but_ordinary_functions_check_both() {
    let source = r#"mod std { pub enum Bool { False, True } } value I(int); value S(str);
        fn unavailable(const system: S) -> _ { match system { "gnu" => S("gnu") } }
        let libc: S = "musl";
        let bool_selection = match Bool::True { True => S("gnu") };
        let bool_selected = unavailable(bool_selection);
        let selected = if libc == "musl" { I(1) } else { unavailable(libc) };
        let matched = match libc { "musl" => I(2), "gnu" => unavailable(libc) };
        let boolean = match Bool::True { False => unavailable(libc), True => I(3) };
        outputs { a: I = selected; b: I = matched; c: I = boolean;
            d: I = if libc == "musl" { I(4) } else { unavailable(libc) };
        }"#;
    checked(source);
    let failures = messages(&source.replace(
        "let libc: S = \"musl\"",
        "let libc: S = \"other\"",
    ));
    assert!(
        failures
            .iter()
            .any(|message| message.contains("no applicable case")
                && message.contains("unavailable")
                && message.contains("other")
                && message.contains("gnu")),
        "{failures:?}"
    );
    assert!(messages(r#"mod std { pub enum Bool { False, True } } value I(int); value S(str); fn ordinary() -> I { if Bool::True { I(1) } else { S("bad") } }"#).iter().any(|message| message.contains("if branch")));
    assert!(messages(r#"mod std { pub enum Bool { False, True } } value I(int); value S(str); let callback = fn() -> I { if Bool::True { I(1) } else { S("bad") } };"#).iter().any(|message| message.contains("if branch")));
}

#[test]
fn contextual_variant_names_preserve_inference_and_static_branch_contracts() {
    checked(
        r#"
        mod std { pub enum Bool { False, True } }
        value S(str); value I(int);
        enum Target { Gnu, Musl } enum Other { Gnu, Musl }
        fn target(entry: Target) -> Target { entry }
        fn other(entry: Other) -> Other { entry }
        fn unavailable(const key: S) -> I { match key { "gnu" => I(0) } }
        fn select(const key: S) -> _ {
            if key == "gnu" { target(Gnu) } else { other(Musl) }
        }
        let direct: Target = if Bool::True { Gnu } else { Musl };
        let literal: Target = match "gnu" { "gnu" => Gnu, _ => Musl };
        let enumeration: Target = match Target::Gnu { Gnu => Gnu, Musl => Musl };
        let inferred = select("musl");
        outputs {
            a: Target = direct;
            b: Target = literal;
            c: Target = enumeration;
            d: Other = inferred;
            e: Target = if Bool::True { Gnu } else { unavailable("musl") };
            f: Target = match "gnu" { "gnu" => Gnu, _ => unavailable("musl") };
        }
        "#,
    );
}

#[test]
fn known_matches_validate_every_pattern_before_selecting() {
    for (arms, expected) in [
        (r#""ok" => I(1), "ok" => I(2)"#, "more than once"),
        (
            r#""ok" => I(1), 2 => I(2)"#,
            "pattern type differs",
        ),
        (r#"_ => I(1), "ok" => I(2)"#, "unreachable"),
    ] {
        let source = format!(
            r#"value I(int); value S(str); fn select(const key: S) -> _ {{ match key {{ {arms} }} }} let answer = select("ok");"#
        );
        assert!(
            messages(&source)
                .iter()
                .any(|message| message.contains(expected)),
            "{source}"
        );
    }
}

#[test]
fn interpolation_checks_global_value_kinds_and_affine_outputs_without_evaluation() {
    for (source, expected) in [
        (
            r#"value S(str); fn example() -> S { "x" } let text: S = "${example}";"#,
            "interpolation requires a primitive",
        ),
        (
            r#"value S(str); let text: S = "${S}";"#,
            "a declaration is not a value",
        ),
        (
            r#"resource R(int); value S(str); outputs { held: R = R(1); text: S = "${held}"; }"#,
            "imported value output cannot carry an affine resource",
        ),
        (
            r#"resource R(int); value S(str); struct Box { held: R; } outputs { boxed: Box = { held = R(1); }; text: S = "${boxed.held}"; }"#,
            "imported value output cannot carry an affine resource",
        ),
        (
            r#"resource R(int); value S(str); fn consume(held: R) -> S { let first: S = "${held}"; "${held}" }"#,
            "moved",
        ),
    ] {
        let errors = messages(source);
        assert!(
            errors
                .iter()
                .any(|message| message.contains(expected)),
            "{source}: {errors:?}"
        );
    }
    checked(
        r#"value S(str); value I(int); struct Box { count: I; } let boxed: Box = { count = 7; }; let text: S = "${boxed.count}"; outputs { original: S = "ok"; alias: S = "${original}"; }"#,
    );
    checked(r#"resource R(int); value S(str); fn consume(held: R) -> S { "${held}" }"#);
}

#[test]
fn known_enums_select_variants_and_propagate_constant_payloads() {
    checked(
        r#"
        value S(str); value I(int); enum Target { Gnu, Musl }
        enum Selection<T> { Default, Selected(T) }
        fn unavailable(const target: S) -> I { match target { "gnu" => I(1) } }
        fn select(const target: Target) -> _ { match target { Gnu => S("gnu"), Musl => I(2) } }
        fn payload(const selected: Selection<S>) -> _ {
            match selected { Default => unavailable("musl"), Selected(target) => match target { "musl" => I(3) } }
        }
        let target: Target = Musl;
        let direct = match Target::Musl { Gnu => unavailable("musl"), Musl => I(4) };
        let constant = select(target);
        let carried = payload(Selection::Selected("musl"));
        let explicit = payload(Selection::Selected<S>("musl"));
        let forwarded = match Selection::Selected(Target::Musl) { Selected(inner) => inner, Default => Target::Gnu };
        let nested = select(forwarded);
        outputs { a: I = direct; b: I = constant; c: I = carried; d: I = explicit; e: I = nested; }
    "#,
    );
    for source in [
        r#"value S(str); value I(int); enum Target { Gnu, Musl } fn ordinary() -> I { match Target::Musl { Gnu => S("gnu"), Musl => I(2) } }"#,
        r#"value S(str); value I(int); enum Target { Gnu, Musl } fn ordinary(target: Target) -> I { match target { Gnu => S("gnu"), Musl => I(2) } }"#,
    ] {
        assert!(
            messages(source)
                .iter()
                .any(|message| message.contains("match arm"))
        );
    }
}

#[test]
fn known_enums_validate_discarded_patterns_and_report_unavailable_variants() {
    for (arms, expected) in [
        (
            "Musl => I(1), Musl => I(2)",
            "covered more than once",
        ),
        (
            "Musl => I(1), Gnu => I(2)",
            "payload binding count mismatch",
        ),
        (
            "Musl => I(1), Other::Musl => I(2)",
            "different enum",
        ),
        ("_ => I(1), Musl => I(2)", "unreachable"),
    ] {
        let source = format!(
            "value I(int); enum Target {{ Gnu(I), Musl }} enum Other {{ Musl }} let selected = match Target::Musl {{ {arms} }};"
        );
        let errors = messages(&source);
        assert!(
            errors
                .iter()
                .any(|message| message.contains(expected)),
            "{errors:?}"
        );
    }
    let errors = messages(
        "value I(int); enum Target { Gnu, Musl } fn select(const target: Target) -> I { match target { Gnu => I(1) } } let selected = select(Target::Musl);",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("select(Target::Musl)")
                && message.contains("requested Target::Musl")
                && message.contains("alternatives: Gnu")),
        "{errors:?}"
    );
}

#[test]
fn known_enum_discriminants_select_lazy_payloads_without_making_them_const_arguments() {
    checked(
        r#"
        value I(int); value S(str); enum Choice<T> { Empty, Selected(T) }
        fn unavailable(const target: S) -> I { match target { "gnu" => I(0) } }
        let lazy = Choice::Selected(memoize(fn() -> I { 7 }));
        let selected = match lazy { Selected(factory) => factory, Empty => unavailable("musl") };
        outputs { result: I = selected(); }
    "#,
    );
    for (ty, argument) in [
        ("Choice<fn() -> I>", "Choice::Selected(callback)"),
        (
            "[Choice<fn() -> I>]",
            "[Choice::Selected(callback)]",
        ),
        (
            "Wrapped",
            "Wrapped { selected = Choice::Selected(callback); }",
        ),
    ] {
        let source = format!(
            "value I(int); enum Choice<T> {{ Empty, Selected(T) }} struct Wrapped {{ selected: Choice<fn() -> I>; }} fn select(const selected: {ty}) -> I {{ 1 }} fn ordinary(callback: fn() -> I) -> I {{ select({argument}) }}"
        );
        let errors = messages(&source);
        assert!(
            errors
                .iter()
                .any(|message| message.contains("const argument must be a known")),
            "{source}: {errors:?}"
        );
    }
}

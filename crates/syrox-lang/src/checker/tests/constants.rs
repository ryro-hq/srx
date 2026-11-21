use super::*;

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

use super::*;

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

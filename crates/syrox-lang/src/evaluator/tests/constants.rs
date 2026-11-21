use super::*;

#[test]
fn computed_defaults_keep_declaration_facts_when_discovered_inside_static_calls() {
    let result = run(
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
        fn nested(const unused: I) -> _ { select(Selection {}) }
        let selected = nested(0);
        outputs {
            global: New = selected;
            implicit: New = select(Selection {});
            explicit: New = select(Selection { inner = Inner { mode = choose("new"); }; });
        }
        "#,
        &CheckPolicy::default(),
    );
    assert!(result.is_success(), "{result:?}");
    let values: Vec<_> = result
        .roots()
        .map(|root| root.value().unwrap())
        .collect();
    assert_eq!(values.len(), 3);
    assert_eq!(values[0], values[1]);
    assert_eq!(values[1], values[2]);
}

#[test]
fn computed_method_receivers_evaluate_once_and_keep_resource_claims() {
    let result = run(
        r"
        resource R(int); value I(int); struct Box { payload: R; }
        impl R {
            fn identity(r: R) -> R { r }
            fn selected(r: R, const choice: I) -> R { match choice { 1 => r } }
        }
        fn pass(r: R) -> R { r }
        struct Callback { run: once fn() -> R; }
        fn callback(r: R) -> Callback { Callback { run = once fn() -> R { r }; } }
        fn call(r: R) -> R { pass(r).identity() }
        fn projected(boxed: Box) -> R { boxed.payload.identity() }
        fn selected(r: R) -> R { pass(r).selected(1) }
        fn stored(r: R) -> R { callback(r).run() }
        outputs {
            called: R = call(R(1));
            projection: R = projected(Box { payload = R(1); });
            selection: R = selected(R(1));
            closure: R = stored(R(1));
        }
        ",
        &CheckPolicy::default(),
    );
    assert!(result.is_success(), "{result:?}");
    for root in result.roots() {
        assert_eq!(root.claims().len(), 1);
        assert!(matches!(
            root.value(),
            Some(Value::Nominal {
                value: PrimitiveValue::Int(1),
                resource: true,
                ..
            })
        ));
    }
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

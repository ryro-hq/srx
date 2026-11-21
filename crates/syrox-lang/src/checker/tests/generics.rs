use super::*;

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

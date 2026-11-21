use super::*;

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

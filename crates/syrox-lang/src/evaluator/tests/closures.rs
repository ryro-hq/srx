use super::*;

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

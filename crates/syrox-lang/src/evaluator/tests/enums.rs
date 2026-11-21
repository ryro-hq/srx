use super::*;

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

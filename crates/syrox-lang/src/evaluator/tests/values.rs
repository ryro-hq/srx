use super::*;

fn identity(path: &str) -> CanonicalItemIdentity {
    CanonicalItemIdentity::new(SourceDomainId::project(), path.split("::")).unwrap()
}

#[test]
fn signed_literals_survive_refinement_matching_and_canonical_evaluation() {
    let result = run(
        r#"value I(int) where -9223372036854775808..=9223372036854775807;
        value S(str);
        fn select(const number: I) -> I { match number { -17 => -9223372036854775808, _ => 0 } }
        let selected = select(-17);
        outputs { result: S = "${selected}"; }"#,
        &CheckPolicy::default(),
    );
    assert!(result.diagnostics().next().is_none());
    assert!(matches!(
        result.roots().next().unwrap().value().unwrap(),
        Value::Nominal { value: PrimitiveValue::Str(value), .. }
            if value == "-9223372036854775808"
    ));
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

#[test]
fn record_calls_share_contextual_inference_defaults_and_evaluation() {
    let declarations = r#"
        value I(int); value S(str);
        struct Options { payload: I; name: S = "gnu"; }
        struct lowercase { payload: I; }
        enum Wrapped { Value(Options) }
        enum Holder<T> { Some(T) }
        let constructor: fn(Options) -> Holder<Options> = Holder::Some<Options>;
        fn make(options: Options) -> I { options.payload }
        fn Uppercase(options: Options) -> I { options.payload }
        fn generic<T>(options: T) -> T { options }
        mod api { pub fn make(options: Options) -> I { options.payload } }
        let callback = fn(options: Options) -> I { options.payload };
        fn selected(const options: Options) -> _ { match options.name { "gnu" => options.payload } }
    "#;
    for expression in [
        "make({ payload = 7; })",
        "make { payload = 7; }",
        "api::make { payload = 7; }",
        "api.make { payload = 7; }",
        "callback { payload = 7; }",
        "Uppercase { payload = 7; }",
        "selected { payload = 7; }",
        "generic<Options> { payload = 7; }.payload",
        "lowercase { payload = 7; }.payload",
        "let make = callback; in make { payload = 7; }",
        "match (Wrapped::Value { payload = 7; }) { Value(options) => options.payload }",
        "match (constructor { payload = 7; }) { Some(options) => options.payload }",
    ] {
        let source =
            format!("{declarations} let answer = {expression}; outputs {{ result: I = answer; }}");
        let result = run(&source, &CheckPolicy::default());
        assert!(
            result.is_success(),
            "{expression}: {:?}",
            result.diagnostics().collect::<Vec<_>>()
        );
        assert!(
            matches!(
                result.roots().next().unwrap().value(),
                Some(Value::Nominal {
                    value: PrimitiveValue::Int(7),
                    ..
                })
            ),
            "{expression}"
        );
    }
}

use super::*;

#[test]
fn ordered_maps_sort_independently_of_insertion_and_reject_duplicate_keys() {
    let project = TempProject::new();
    project.write("main.srx", r#"
        value I(int);
        outputs {
            forward: std::Result<std::OrderedMap<I>, std::MapKey> = std::map_from_entries([
                std::MapEntry::Entry("a", I(1)), std::MapEntry::Entry("z", I(2)), std::MapEntry::Entry("é", I(3))
            ]);
            reverse: std::Result<std::OrderedMap<I>, std::MapKey> = std::map_from_entries([
                std::MapEntry::Entry("é", I(3)), std::MapEntry::Entry("z", I(2)), std::MapEntry::Entry("a", I(1))
            ]);
            duplicate: std::Result<std::OrderedMap<I>, std::MapKey> = std::map_from_entries([
                std::MapEntry::Entry("a", I(1)), std::MapEntry::Entry("a", I(2))
            ]);
            empty: std::Option<I> = std::map_get(std::map_empty<I>(), "missing");
        }
    "#);
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = value_projection_plan(&project.0, &configuration).unwrap();
    let root = |name| {
        plan.roots()
            .find(|root| root.name() == name)
            .unwrap()
            .value()
    };
    assert_eq!(root("forward"), root("reverse"));
    assert!(matches!(
        root("forward"),
        crate::plan::PlanValue::Variant {
            index: 0,
            ..
        }
    ));
    assert!(
        matches!(root("duplicate"), crate::plan::PlanValue::Variant { index: 1, payload, .. } if matches!(payload.as_slice(), [crate::plan::PlanValue::Nominal { value, .. }] if **value == crate::plan::PlanValue::Str("a".into())))
    );
    assert!(
        matches!(root("empty"), crate::plan::PlanValue::Variant { index: 0, payload, .. } if payload.is_empty())
    );
}

#[test]
fn ordered_map_factories_are_importable_and_unselected_factories_stay_dormant() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(
        child.join("main.srx"),
        r#"
        pub resource Ticket(int) where 1..=2;
        fn good() -> Ticket { Ticket(1) }
        fn disconnected() -> Ticket { Ticket(9) }
        fn make() -> std::OrderedMap<fn() -> Ticket> {
            match std::map_from_entries([
                std::MapEntry::Entry("z-unused", disconnected),
                std::MapEntry::Entry("a-selected", good)
            ]) {
                Ok(items) => items,
                Err(_) => std::map_empty(),
            }
        }
        outputs { factories: std::OrderedMap<fn() -> Ticket> = make(); }
    "#,
    )
    .unwrap();
    fs::write(
        consumer.join("main.srx"),
        r#"
        inputs { child = "path:../child"; }
        outputs {
            names: [std::MapKey] = std::map_keys(child::factories);
            selected: child::Ticket = match std::map_get(child::factories, "a-selected") {
                Some(factory) => factory(),
                None => child::Ticket(2),
            };
        }
    "#,
    )
    .unwrap();
    let configuration = package_configuration();
    lock_project_with(&child, &configuration).unwrap();
    lock_project_with(&consumer, &configuration).unwrap();
    let plan = value_projection_plan(&consumer, &configuration).unwrap();
    let names = plan
        .roots()
        .find(|root| root.name() == "names")
        .unwrap();
    assert_eq!(names.claims().count(), 0);
    let crate::plan::PlanValue::List {
        items,
        ..
    } = names.value()
    else {
        panic!("expected names");
    };
    let keys: Vec<_> = items
        .iter()
        .map(|item| match item {
            crate::plan::PlanValue::Nominal {
                value,
                ..
            } => value.as_ref(),
            _ => panic!("expected key"),
        })
        .collect();
    assert_eq!(
        keys,
        vec![
            &crate::plan::PlanValue::Str("a-selected".into()),
            &crate::plan::PlanValue::Str("z-unused".into())
        ]
    );
    let selected = plan
        .roots()
        .find(|root| root.name() == "selected")
        .unwrap();
    assert_eq!(selected.claims().count(), 1);
    assert!(
        matches!(selected.value(), crate::plan::PlanValue::Nominal { value, .. } if **value == crate::plan::PlanValue::Int(1))
    );
}

#[test]
fn ordered_map_affine_values_move_in_key_order() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        resource Ticket(int);
        outputs {
            tickets: [Ticket] = match std::map_from_entries([
                std::MapEntry::Entry("z", Ticket(2)), std::MapEntry::Entry("a", Ticket(1))
            ]) {
                Ok(items) => std::map_values(items),
                Err(_) => [],
            };
        }
    "#,
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = value_projection_plan(&project.0, &configuration).unwrap();
    let root = plan.roots().next().unwrap();
    assert_eq!(root.claims().count(), 2);
    let crate::plan::PlanValue::List {
        items,
        ..
    } = root.value()
    else {
        panic!("expected tickets");
    };
    assert_eq!(items.len(), 2);
    for (item, expected) in items.iter().zip(1..=2) {
        assert!(
            matches!(item, crate::plan::PlanValue::Nominal { value, .. } if **value == crate::plan::PlanValue::Int(expected))
        );
    }
}

#[test]
fn ordered_map_constructor_and_affine_access_cannot_bypass_invariants() {
    for (source, expected) in [
        (
            "value I(int); outputs { forged: std::OrderedMap<I> = std::OrderedMap<I> { entries = []; }; }",
            "opaque struct constructor is private",
        ),
        (
            "resource R(int); fn bad(items: std::OrderedMap<R>) -> [std::Option<R>] { [std::map_get(items, \"a\"), std::map_get(items, \"b\")] }",
            "use of moved affine value",
        ),
        (
            "resource R(int); fn bad(items: std::OrderedMap<once fn() -> R>) -> [std::OrderedMap<once fn() -> R>] { [items, items] }",
            "use of moved affine value",
        ),
    ] {
        let project = TempProject::new();
        project.write("main.srx", source);
        let result = check_project_with(&project.0, &package_configuration());
        assert!(
            matches!(&result, Err(CheckFailure::Diagnostics { errors, .. }) if errors.iter().any(|error| error.message.contains(expected))),
            "{result:?}"
        );
    }
}

#[test]
fn ordered_map_merge_preserves_values_and_reports_collisions() {
    let project = TempProject::new();
    project.write("main.srx", r#"
        resource Ticket(int);
        fn one(key: std::MapKey, item: Ticket) -> std::OrderedMap<Ticket> {
            match std::map_insert(std::map_empty<Ticket>(), key, item) {
                Ok(items) => items, Err(_) => std::map_empty(),
            }
        }
        outputs {
            joined: [Ticket] = match std::map_merge(one("z", Ticket(2)), one("a", Ticket(1))) {
                Ok(items) => std::map_values(items), Err(_) => [],
            };
            duplicate: std::Result<std::OrderedMap<Ticket>, std::MapKey> = std::map_merge(one("a", Ticket(1)), one("a", Ticket(2)));
        }
    "#);
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = value_projection_plan(&project.0, &configuration).unwrap();
    let joined = plan
        .roots()
        .find(|root| root.name() == "joined")
        .unwrap();
    assert_eq!(joined.claims().count(), 2);
    let crate::plan::PlanValue::List {
        items,
        ..
    } = joined.value()
    else {
        panic!("expected tickets");
    };
    assert_eq!(items.len(), 2);
    for (item, expected) in items.iter().zip(1..=2) {
        assert!(
            matches!(item, crate::plan::PlanValue::Nominal { value, .. } if **value == crate::plan::PlanValue::Int(expected))
        );
    }
    let duplicate = plan
        .roots()
        .find(|root| root.name() == "duplicate")
        .unwrap();
    assert!(matches!(
        duplicate.value(),
        crate::plan::PlanValue::Variant {
            index: 1,
            ..
        }
    ));
}

#[test]
fn ordered_map_composition_respects_evaluation_work_and_expansion_limits() {
    let project = TempProject::new();
    let entries = (0..16)
        .rev()
        .map(|index| format!("std::MapEntry::Entry(\"key-{index:02}\", I({index}))"))
        .collect::<Vec<_>>()
        .join(",");
    project.write("main.srx", &format!("value I(int); outputs {{ items: std::Result<std::OrderedMap<I>, std::MapKey> = std::map_from_entries([{entries}]); }}"));
    assert!(check_project_with(&project.0, &package_configuration()).is_ok());
    for work_limit in [true, false] {
        let mut configuration = package_configuration();
        if work_limit {
            configuration.evaluation_limits.max_steps_per_root = 100;
        } else {
            configuration
                .evaluation_limits
                .max_expansion_bytes = 4096;
        }
        let expected = if work_limit {
            "step limit"
        } else {
            "expansion byte limit"
        };
        let result = check_project_with(&project.0, &configuration);
        assert!(
            matches!(&result, Err(CheckFailure::Evaluation { errors, .. }) if errors.iter().any(|error| error.message.contains(expected))),
            "{result:?}"
        );
    }
}

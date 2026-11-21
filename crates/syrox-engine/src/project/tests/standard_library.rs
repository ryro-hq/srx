use super::*;

#[test]
fn standard_list_helpers_compose_project_defined_types() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r"
        value Number(int);
        struct Wrapped<T> { item: T; }
        fn wrap<T>(item: T) -> Wrapped<T> { Wrapped<T> { item = item; } }
        outputs {
            transformed: [Wrapped<Number>] = std::map<Number, Wrapped<Number>>(
                std::flatten<Number>([[Number(1)], [Number(2)]]), wrap<Number>
            );
        }
    ",
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = value_projection_plan(&project.0, &configuration).unwrap();
    assert!(plan.to_string().contains("transformed"));
}

#[test]
fn imported_filter_map_keeps_affine_payloads_and_plan_enum_arguments() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(
        child.join("main.srx"),
        r"
        pub resource Ticket(int);
        pub enum Entry { Keep(Ticket), Drop }
        pub fn keep(entry: Entry) -> std::Option<Entry> {
            match entry {
                Keep(ticket) => std::Option::Some(Entry::Keep(ticket)),
                Drop => std::Option::None(),
            }
        }
        pub fn select(entry: Entry) -> std::Option<Ticket> {
            match entry {
                Keep(ticket) => std::Option::Some(ticket),
                Drop => std::Option::None(),
            }
        }
    ",
    )
    .unwrap();
    fs::write(consumer.join("main.srx"), r#"
        inputs { child = "path:../child"; }
        value Label(str);
        outputs {
            selected: [child::Ticket] = std::filter_map(
                std::filter(
                    [child::Entry::Keep(child::Ticket(1)), child::Entry::Drop, child::Entry::Keep(child::Ticket(2))],
                    child::keep
                ),
                child::select
            );
            status: std::Result<Label, Label> = std::Result::Ok(Label("done"));
        }
    "#).unwrap();
    let configuration = package_configuration();
    lock_project_with(&child, &configuration).unwrap();
    lock_project_with(&consumer, &configuration).unwrap();
    let plan = value_projection_plan(&consumer, &configuration).unwrap();
    let selected = plan
        .roots()
        .find(|root| root.name() == "selected")
        .unwrap();
    assert_eq!(selected.claims().count(), 2);
    let crate::plan::PlanValue::List {
        items,
        ..
    } = selected.value()
    else {
        panic!("expected selected list");
    };
    assert_eq!(items.len(), 2);
    let status = plan
        .roots()
        .find(|root| root.name() == "status")
        .unwrap();
    assert!(
        matches!(status.value(), crate::plan::PlanValue::Variant { index: 0, payload, .. } if payload.len() == 1)
    );
    assert!(plan.to_string().contains("done"));
}

#[test]
fn standard_library_rejects_an_empty_snapshot() {
    let source =
        AuthenticatedStandardSource::from_authenticated("std.srx", "value Std(str);").unwrap();
    assert!(AuthenticatedStandardLibrary::from_authenticated(vec![source]).is_ok());
    assert_eq!(
        AuthenticatedStandardLibrary::from_authenticated(vec![]).unwrap_err(),
        StandardLibraryError::InvalidSourceCount
    );
}

#[test]
fn plan_carries_authenticated_standard_library_provenance() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 42; }",
    );
    let source =
        AuthenticatedStandardSource::from_authenticated("std.srx", "value Std(str);").unwrap();
    let library = AuthenticatedStandardLibrary::from_authenticated(vec![source]).unwrap();
    let configuration = CheckConfiguration {
        standard_library: Some(library.clone()),
        ..CheckConfiguration::default()
    };

    lock_project_with(&project.0, &configuration).unwrap();
    let plan = value_projection_plan(&project.0, &configuration).unwrap();
    let standard = plan.standard_library().unwrap();
    assert_eq!(standard.digest(), library.digest());
    assert!(plan.to_string().contains("std sha256 "));
}

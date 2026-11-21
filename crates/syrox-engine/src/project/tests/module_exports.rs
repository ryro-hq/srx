use super::*;

#[test]
fn module_exports_discover_locked_factories_without_a_central_recipe_list() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir_all(child.join("recipes/group")).unwrap();
    fs::create_dir(&consumer).unwrap();
    let main = r#"
        inputs { recipes = "modules:recipes"; }
        fn collect() -> std::OrderedMap<fn() -> std::Package> {
            match std::map_from_entries(module_exports(recipes, recipe, std::MapEntry::Entry<fn() -> std::Package>)) {
                Ok(items) => items, Err(_) => std::map_empty(),
            }
        }
        outputs { factories: std::OrderedMap<fn() -> std::Package> = collect(); }
    "#;
    fs::write(child.join("main.srx"), main).unwrap();
    fs::write(child.join("recipes/group/selected.srx"), r#"pub fn recipe() -> std::Package { std::Package { id = "selected"; dependencies = []; } }"#).unwrap();
    fs::write(child.join("recipes/z_unused.srx"), r#"
        resource R(int);
        pub fn recipe() -> std::Package { let conflict = [R(1), R(1)]; std::Package { id = "unused"; dependencies = []; } }
    "#).unwrap();
    fs::write(
        child.join("recipes/private.srx"),
        r#"fn recipe() -> std::Package { std::Package { id = "private"; dependencies = []; } }"#,
    )
    .unwrap();
    fs::write(
        consumer.join("main.srx"),
        r#"
        inputs { pkgs = "path:../child"; }
        outputs {
            names: [std::MapKey] = std::map_keys(pkgs::factories);
            selected: std::Package = match std::map_get(pkgs::factories, "group::selected") {
                Some(factory) => factory(),
                None => std::Package { id = "missing"; dependencies = []; },
            };
        }
    "#,
    )
    .unwrap();
    let config = package_configuration();
    lock_project_with(&child, &config).unwrap();
    lock_project_with(&consumer, &config).unwrap();
    let plan = value_projection_plan(&consumer, &config).unwrap();
    assert_eq!(plan.packages().count(), 1);
    assert!(plan.to_string().contains("package \"selected\""));
    let names = plan
        .roots()
        .find(|root| root.name() == "names")
        .unwrap();
    let crate::plan::PlanValue::List {
        items,
        ..
    } = names.value()
    else {
        panic!("expected names");
    };
    assert_eq!(items.len(), 2);
    assert!(
        matches!(&items[0], crate::plan::PlanValue::Nominal { value, .. } if **value == crate::plan::PlanValue::Str("group::selected".into()))
    );
    fs::write(
        child.join("recipes/added.srx"),
        r#"pub fn recipe() -> std::Package { std::Package { id = "added"; dependencies = []; } }"#,
    )
    .unwrap();
    assert!(matches!(
        value_projection_plan(&consumer, &config),
        Err(ProjectOperationError::Check(
            CheckFailure::InvalidChildLock { .. }
        ))
    ));
    lock_project_with(&child, &config).unwrap();
    assert!(matches!(
        value_projection_plan(&consumer, &config),
        Err(ProjectOperationError::GraphDrift)
    ));
    lock_project_with(&consumer, &config).unwrap();
    let plan = value_projection_plan(&consumer, &config).unwrap();
    let names = plan
        .roots()
        .find(|root| root.name() == "names")
        .unwrap();
    assert!(
        matches!(names.value(), crate::plan::PlanValue::List { items, .. } if items.len() == 3)
    );
    assert_eq!(
        fs::read_to_string(child.join("main.srx")).unwrap(),
        main
    );
}

#[test]
fn module_exports_respect_input_visibility_and_reexport_identity() {
    let project = TempProject::new();
    project.write("main.srx", r#"
        inputs { modules = "modules:modules"; child = "path:child"; }
        outputs {
            exposed: [std::MapKey] = module_exports(modules, recipe, fn(key: std::MapKey, factory: fn() -> std::Package) -> std::MapKey { key });
            hidden: [std::MapKey] = module_exports(child::hidden, recipe, fn(key: std::MapKey, factory: fn() -> std::Package) -> std::MapKey { key });
        }
    "#);
    project.write(
        "modules/implementation.srx",
        r#"pub fn recipe() -> std::Package { std::Package { id = "public"; dependencies = []; } }"#,
    );
    project.write(
        "modules/facade.srx",
        "pub use implementation::recipe;",
    );
    project.write("child/main.srx", r#"mod hidden { pub fn recipe() -> std::Package { std::Package { id = "private"; dependencies = []; } } }"#);
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let plan = value_projection_plan(&project.0, &config).unwrap();
    let hidden = plan
        .roots()
        .find(|root| root.name() == "hidden")
        .unwrap();
    assert!(
        matches!(hidden.value(), crate::plan::PlanValue::List { items, .. } if items.is_empty())
    );
    let exposed = plan
        .roots()
        .find(|root| root.name() == "exposed")
        .unwrap();
    assert!(
        matches!(exposed.value(), crate::plan::PlanValue::List { items, .. } if items.len() == 2)
    );
}

#[test]
fn module_exports_keep_the_original_asset_owner_through_reexports() {
    let workspace = TempProject::new();
    let leaf = workspace.0.join("leaf");
    let catalog = workspace.0.join("catalog");
    let consumer = workspace.0.join("consumer");
    for project in [&leaf, &catalog, &consumer] {
        fs::create_dir_all(project.join("assets")).unwrap();
    }
    fs::write(leaf.join("assets/source"), b"child").unwrap();
    fs::write(catalog.join("assets/source"), b"catalog").unwrap();
    fs::write(consumer.join("assets/source"), b"consumer").unwrap();
    fs::write(leaf.join("main.srx"), r#"
        pub fn source() -> std::Acquisition {
            std::Acquisition { sources = [std::source_request(
                "project:assets/source", "ddc9e669194254cef019a29d3619a2c16592e5d52e1a81e98b01bd52319149a3", 100
            )]; }
        }
    "#).unwrap();
    fs::write(catalog.join("main.srx"), r#"
        inputs { leaf = "path:../leaf"; }
        mod facade { pub use leaf::source; }
        fn collect() -> std::OrderedMap<fn() -> std::Acquisition> {
            match std::map_from_entries(module_exports(facade, source, std::MapEntry::Entry<fn() -> std::Acquisition>)) {
                Ok(items) => items, Err(_) => std::map_empty(),
            }
        }
        outputs { sources: std::OrderedMap<fn() -> std::Acquisition> = collect(); }
    "#).unwrap();
    fs::write(consumer.join("main.srx"), r#"
        inputs { catalog = "path:../catalog"; }
        mod published { mod package { pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = "app"; dependencies = []; };
                acquisition = std::Option::Some(match std::map_get(catalog::sources, "") {
                    Some(factory) => factory(), None => std::Acquisition { sources = []; },
                });
            } } } } pub publish(published, recipe): std::Recipe;
    "#).unwrap();
    let config = package_configuration();
    for project in [&leaf, &catalog, &consumer] {
        lock_project_with(project, &config).unwrap();
    }
    let prepared = prepare_project_with(&consumer, &config).unwrap();
    let plan = prepared.plan();
    let request = plan
        .acquisitions()
        .next()
        .unwrap()
        .sources()
        .next()
        .unwrap();
    let origin = prepared
        .project_root(request.owner().unwrap())
        .unwrap();
    assert_eq!(
        fs::canonicalize(origin).unwrap(),
        fs::canonicalize(&leaf).unwrap()
    );
    let store = crate::store::Store::initialize(&workspace.0.join("store")).unwrap();
    crate::realize::acquire_build_local(
        &store,
        origin,
        "assets/source",
        request.digest(),
        request.maximum_bytes(),
        &crate::store::RootName::new(format!("source_{}", request.digest())).unwrap(),
        &crate::cancellation::Cancellation::default(),
    )
    .unwrap();
}

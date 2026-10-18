use super::*;

#[test]
fn imported_function_output_is_a_lazy_value_with_a_direct_call_and_preserved_capture() {
    let workspace = TempProject::new();
    let config = package_configuration();
    workspace.write(
        "child/main.srx",
        r#"
        fn configure(id: std::PackageId) -> fn() -> std::Package {
            fn() -> std::Package { std::Package { id = id; dependencies = []; } }
        }
        fn recursive() -> fn() -> std::Package { recursive() }
        outputs {
            selected: fn() -> std::Package = configure("captured");
            unused: fn() -> std::Package = recursive();
        }
    "#,
    );
    workspace.write(
        "consumer/main.srx",
        r#"
        inputs { child = "path:../child"; }
        mod factories { mod package { pub fn recipe() -> std::Recipe { std::Recipe { package = child::selected(); } } } } pub publish(factories, recipe): std::Recipe;
    "#,
    );
    lock_project_with(&workspace.0.join("child"), &config).unwrap();
    let consumer = workspace.0.join("consumer");
    lock_project_with(&consumer, &config).unwrap();
    let plan = plan_project_with(&consumer, &config).unwrap();
    assert_eq!(plan.packages().len(), 1);
    assert_eq!(
        plan.packages().next().unwrap().id().as_str(),
        "captured"
    );
}

#[test]
fn imported_homonymous_catalog_entries_are_distinct_and_reference_aliases_keep_identity() {
    use syrox_lang::evaluator::Value;
    fn factory(reference: &Value) -> syrox_lang::evaluator::MemoId {
        let Value::Struct {
            fields,
            ..
        } = reference
        else {
            panic!("expected RecipeRef");
        };
        let Value::MemoizedFunction {
            id,
            ..
        } = &fields
            .iter()
            .find(|(name, _)| name == "factory")
            .unwrap()
            .1
        else {
            panic!("expected memoized factory");
        };
        id.clone()
    }
    let workspace = TempProject::new();
    let config = package_configuration();
    for name in ["left", "right"] {
        workspace.write(&format!("{name}/main.srx"), r#"
            mod factories { mod hello { pub fn recipe() -> std::Package { std::Package { id = "hello"; dependencies = []; } } } }
            pub publish(factories, recipe): std::Package;
        "#);
        lock_project_with(&workspace.0.join(name), &config).unwrap();
    }
    workspace.write(
        "consumer/main.srx",
        r#"
        inputs { left = "path:../left"; right = "path:../right"; }
        let shared = left::hello;
        outputs {
            left_ref: RecipeRef<Package> = shared;
            right_ref: std::RecipeRef<std::Package> = right::hello;
            alias: RecipeRef<Package> = shared;
        }
    "#,
    );
    let consumer = workspace.0.join("consumer");
    lock_project_with(&consumer, &config).unwrap();
    let project = open_locked_project_with(&consumer, &config).unwrap();
    let mut session = project.evaluation().unwrap();
    let left = factory(
        session
            .evaluate_root("left_ref")
            .unwrap()
            .value()
            .unwrap(),
    );
    let right = factory(
        session
            .evaluate_root("right_ref")
            .unwrap()
            .value()
            .unwrap(),
    );
    let alias = factory(
        session
            .evaluate_root("alias")
            .unwrap()
            .value()
            .unwrap(),
    );
    assert_eq!(left, alias);
    assert_ne!(left, right);
}

#[test]
fn named_reference_and_catalog_query_share_one_lazy_instance() {
    let project = TempProject::new();
    project.write("main.srx", r#"
        mod factories {
            mod hello { pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = "hello"; dependencies = []; }; } } }
            mod unused { pub fn recipe() -> std::Recipe { recipe() } }
        }
        pub publish(factories, recipe): std::Recipe;
        outputs { direct: std::RecipeRef<std::Recipe> = project::hello; }
    "#);
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let locked = open_locked_project_with(&project.0, &config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    assert_eq!(
        evaluation.catalog_names().unwrap().unwrap(),
        ["hello", "unused"]
    );
    let memo = |value: &syrox_lang::evaluator::Value| {
        let syrox_lang::evaluator::Value::Struct {
            fields,
            ..
        } = value
        else {
            panic!("reference")
        };
        let syrox_lang::evaluator::Value::MemoizedFunction {
            id,
            ..
        } = &fields[0].1
        else {
            panic!("memo")
        };
        id.clone()
    };
    let queried = memo(
        &evaluation
            .catalog_reference("hello")
            .unwrap()
            .unwrap(),
    );
    let named = memo(
        evaluation
            .evaluate_root("direct")
            .unwrap()
            .value()
            .unwrap(),
    );
    assert_eq!(queried, named);
    assert!(
        evaluation
            .catalog_reference("missing")
            .unwrap()
            .is_none()
    );
    assert!(evaluation.select_package("hello").unwrap());
    assert_eq!(
        evaluation
            .into_selected_plan()
            .unwrap()
            .packages()
            .len(),
        1
    );
}

#[test]
fn imported_generated_member_preserves_reference_and_navigates_to_factory() {
    fn memo_id(value: &syrox_lang::evaluator::Value) -> syrox_lang::evaluator::MemoId {
        let syrox_lang::evaluator::Value::Struct {
            fields,
            ..
        } = value
        else {
            panic!("expected RecipeRef")
        };
        let [
            (
                _,
                syrox_lang::evaluator::Value::MemoizedFunction {
                    id,
                    ..
                },
            ),
        ] = fields.as_slice()
        else {
            panic!("expected memoized factory")
        };
        id.clone()
    }
    let workspace = TempProject::new();
    let config = package_configuration();
    workspace.write(
        "catalog/main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        pub publish(recipes, recipe): std::Package;
    "#,
    );
    workspace.write(
        "catalog/recipes/hello.srx",
        "pub fn recipe() -> std::Package { std::Package { id = \"hello\"; dependencies = []; } }",
    );
    workspace.write(
        "catalog/recipes/unused.srx",
        "pub fn recipe() -> std::Package { recipe() }",
    );
    workspace.write(
        "consumer/main.srx",
        r#"
        inputs { pkgs = "path:../catalog"; }
        outputs {
            direct: std::RecipeRef<std::Package> = pkgs::hello;
            selected: std::RecipeRef<std::Package> = pkgs::hello;
        }
    "#,
    );
    let catalog = workspace.0.join("catalog");
    let consumer = workspace.0.join("consumer");
    lock_project_with(&catalog, &config).unwrap();
    lock_project_with(&consumer, &config).unwrap();
    let project = open_locked_project_with(&consumer, &config).unwrap();
    let mut session = project.evaluation().unwrap();
    let root = session.evaluate_root("direct").unwrap();
    assert!(root.value().is_some(), "{:?}", root.diagnostics());
    let direct = memo_id(root.value().unwrap());
    let selected = memo_id(
        session
            .evaluate_root("selected")
            .unwrap()
            .value()
            .unwrap(),
    );
    assert_eq!(direct, selected);
    let mut reverse = project.evaluation().unwrap();
    let selected = memo_id(
        reverse
            .evaluate_root("selected")
            .unwrap()
            .value()
            .unwrap(),
    );
    let direct = memo_id(
        reverse
            .evaluate_root("direct")
            .unwrap()
            .value()
            .unwrap(),
    );
    assert_eq!(direct, selected);
    let editor = open_project_analysis_with(&consumer, &config).unwrap();
    let snapshot = editor.snapshot();
    let (source_id, source) = snapshot
        .sources()
        .iter()
        .find(|(_, source)| source.text().contains("inputs { pkgs"))
        .unwrap();
    let analysis = snapshot
        .analyze(&syrox_lang::analysis::AnalysisCancellation::default())
        .unwrap();
    assert!(
        analysis.diagnostics().is_empty(),
        "{:?}",
        analysis.diagnostics()
    );
    let member = u32::try_from(source.text().find("pkgs::hello").unwrap() + 6).unwrap();
    let definition = analysis.definition_at(source_id, member).unwrap();
    assert_eq!(
        definition.source_id(),
        snapshot
            .sources()
            .iter()
            .find(|(_, source)| source
                .text()
                .contains("pub fn recipe() -> std::Package { std::Package"))
            .unwrap()
            .0
    );
    let completions = analysis.complete_path(source_id, member, &["pkgs".into()], "he");
    assert!(
        completions
            .iter()
            .any(|(name, _)| name == "hello")
    );
    let syrox_lang::resolver::ResolvedTarget::Item(member_item) = analysis
        .lookup_path(
            source_id,
            member,
            &["pkgs".into(), "hello".into()],
        )
        .unwrap()
    else {
        panic!("expected typed catalog member")
    };
    assert!(
        analysis
            .display_type(analysis.output_type(member_item).unwrap())
            .contains("RecipeRef<")
    );
    let symbol = analysis
        .symbol_at(
            source_id,
            member,
            &syrox_lang::analysis::AnalysisCancellation::default(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(symbol.name, "hello");
    assert!(
        analysis
            .display_type(symbol.ty.as_ref().unwrap())
            .contains("RecipeRef<")
    );
}

#[test]
fn catalog_members_participate_in_imports_and_public_reexports() {
    use syrox_lang::evaluator::Value;
    fn memo_id(value: &Value) -> syrox_lang::evaluator::MemoId {
        let Value::Struct {
            fields,
            ..
        } = value
        else {
            panic!("expected reference")
        };
        let [
            (
                _,
                Value::MemoizedFunction {
                    id,
                    ..
                },
            ),
        ] = fields.as_slice()
        else {
            panic!("expected memoized factory")
        };
        id.clone()
    }
    let workspace = TempProject::new();
    let config = package_configuration();
    workspace.write(
        "catalog/main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        pub publish(recipes, recipe): std::Package;
    "#,
    );
    workspace.write(
        "catalog/recipes/hello.srx",
        r#"
        pub fn recipe() -> std::Package {
            std::Package { id = "hello"; dependencies = []; }
        }
    "#,
    );
    workspace.write(
        "consumer/main.srx",
        r#"
        inputs { pkgs = "path:../catalog"; }
        use pkgs::hello;
        mod published { pub use pkgs::hello; }
        outputs {
            direct: std::RecipeRef<std::Package> = pkgs::hello;
            imported: std::RecipeRef<std::Package> = hello;
            reexported: std::RecipeRef<std::Package> = published::hello;
        }
    "#,
    );
    let catalog = workspace.0.join("catalog");
    let consumer = workspace.0.join("consumer");
    lock_project_with(&catalog, &config).unwrap();
    lock_project_with(&consumer, &config).unwrap();
    let locked = open_locked_project_with(&consumer, &config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    let direct = memo_id(
        evaluation
            .evaluate_root("direct")
            .unwrap()
            .value()
            .unwrap(),
    );
    let imported = memo_id(
        evaluation
            .evaluate_root("imported")
            .unwrap()
            .value()
            .unwrap(),
    );
    let reexported = memo_id(
        evaluation
            .evaluate_root("reexported")
            .unwrap()
            .value()
            .unwrap(),
    );
    assert_eq!(direct, imported);
    assert_eq!(direct, reexported);
}

#[test]
fn imported_recipe_can_name_its_owning_projects_published_reference() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        pub publish(recipes, recipe): std::Recipe;
    "#,
    );
    project.write(
        "recipes/hello.srx",
        r"
        pub fn recipe() -> std::Recipe {
            let peer: std::RecipeRef<std::Recipe> = project::glibc;
            std::recipe_value(peer)
        }
    ",
    );
    project.write(
        "recipes/glibc.srx",
        r#"
        pub fn recipe() -> std::Recipe {
            std::Recipe { package = std::Package { id = "glibc"; dependencies = []; }; }
        }
    "#,
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let locked = open_locked_project_with(&project.0, &config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    assert!(evaluation.select_package("hello").unwrap());
    let root = evaluation.into_selected_plan().unwrap();
    assert_eq!(
        root.packages().next().unwrap().id().as_str(),
        "glibc"
    );
}

#[test]
fn project_namespace_in_a_child_recipe_is_bound_to_the_child_project() {
    let workspace = TempProject::new();
    workspace.write(
        "child/main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        pub publish(recipes, recipe): std::Package;
    "#,
    );
    workspace.write(
        "child/recipes/hello.srx",
        r"
        pub fn recipe() -> std::Package { std::recipe_value(project::glibc) }
    ",
    );
    workspace.write(
        "child/recipes/glibc.srx",
        r#"
        pub fn recipe() -> std::Package {
            std::Package { id = "child"; dependencies = []; }
        }
    "#,
    );
    workspace.write(
        "consumer/main.srx",
        r#"
        inputs { pkgs = "path:../child"; }
        outputs {
            glibc: std::Package = std::Package { id = "consumer"; dependencies = []; };
            selected: std::Package = std::recipe_value(pkgs::hello);
        }
    "#,
    );
    let config = package_configuration();
    lock_project_with(&workspace.0.join("child"), &config).unwrap();
    let consumer = workspace.0.join("consumer");
    lock_project_with(&consumer, &config).unwrap();
    let locked = open_locked_project_with(&consumer, &config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    let selected = evaluation.evaluate_root("selected").unwrap();
    assert!(selected.value().is_some());
    let syrox_lang::evaluator::Value::Struct {
        fields,
        ..
    } = selected.value().unwrap()
    else {
        panic!("package");
    };
    assert!(
        matches!(&fields[0].1, syrox_lang::evaluator::Value::Nominal { value: syrox_lang::evaluator::PrimitiveValue::Str(id), .. } if id == "child")
    );
}

#[test]
fn project_namespace_cannot_be_shadowed_by_an_input_alias() {
    let project = TempProject::new();
    project.write("main.srx", "inputs { project = \"modules:deps\"; } outputs { answer: std::Package = std::Package { id = \"answer\"; dependencies = []; }; }");
    project.write(
        "deps/hello.srx",
        "pub fn recipe() -> std::Package { std::Package { id = \"hello\"; dependencies = []; } }",
    );
    let error = lock_project_with(&project.0, &package_configuration()).unwrap_err();
    assert!(
        matches!(error, ProjectOperationError::Check(CheckFailure::Diagnostics { errors, .. })
        if errors.iter().any(|diagnostic| diagnostic.message.contains("reserved for the owning project")))
    );
}

#[test]
fn reflection_without_publication_does_not_publish_static_members() {
    let workspace = TempProject::new();
    let config = package_configuration();
    workspace.write(
        "catalog/main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        fn names() -> [std::MapKey] { module_exports(recipes, recipe, fn(key: std::MapKey, factory: fn() -> std::Package) -> std::MapKey { key }) }
    "#,
    );
    workspace.write(
        "catalog/recipes/hello.srx",
        r#"
        pub fn recipe() -> std::Package {
            std::Package { id = "hello"; dependencies = []; }
        }
    "#,
    );
    workspace.write(
        "consumer/main.srx",
        r#"
        inputs { pkgs = "path:../catalog"; }
        outputs { direct: std::RecipeRef<std::Package> = pkgs::hello; }
    "#,
    );
    let catalog = workspace.0.join("catalog");
    lock_project_with(&catalog, &config).unwrap();
    let consumer = workspace.0.join("consumer");
    let error = lock_project_with(&consumer, &config).unwrap_err();
    assert!(matches!(error,
        ProjectOperationError::Check(CheckFailure::Diagnostics { errors, .. })
            if errors.iter().any(|error| error.message.contains("unknown"))));
}

#[test]
fn publication_checks_the_factory_result_against_the_declared_type() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        fn wrong() -> std::Recipe { wrong() }
        pub publish(recipes, recipe): std::Recipe;
    "#,
    );
    project.write(
        "recipes/hello.srx",
        r#"
        pub fn recipe() -> std::Package {
            std::Package { id = "hello"; dependencies = []; }
        }
    "#,
    );
    let error = lock_project_with(&project.0, &package_configuration()).unwrap_err();
    assert!(matches!(error,
        ProjectOperationError::Check(CheckFailure::Diagnostics { errors, .. })
            if errors.iter().any(|error| error.message.contains("published factory result"))));
}

#[test]
fn catalog_member_survives_a_project_reexport() {
    let workspace = TempProject::new();
    let config = package_configuration();
    workspace.write(
        "catalog/main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        pub publish(recipes, recipe): std::Package;
    "#,
    );
    workspace.write(
        "catalog/recipes/hello.srx",
        r#"
        pub fn recipe() -> std::Package {
            std::Package { id = "hello"; dependencies = []; }
        }
    "#,
    );
    workspace.write(
        "relay/main.srx",
        r#"
        inputs { pkgs = "path:../catalog"; }
        pub use pkgs::hello;
    "#,
    );
    workspace.write(
        "consumer/main.srx",
        r#"
        inputs { pkgs = "path:../catalog"; relay = "path:../relay"; }
        outputs {
            direct: std::RecipeRef<std::Package> = pkgs::hello;
            via_reexport: std::RecipeRef<std::Package> = relay::hello;
        }
    "#,
    );
    for name in ["catalog", "relay", "consumer"] {
        lock_project_with(&workspace.0.join(name), &config).unwrap();
    }
    let locked = open_locked_project_with(&workspace.0.join("consumer"), &config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    let direct = evaluation
        .evaluate_root("direct")
        .unwrap()
        .value()
        .unwrap();
    let syrox_lang::evaluator::Value::Struct {
        fields,
        ..
    } = direct
    else {
        panic!("expected reference")
    };
    let syrox_lang::evaluator::Value::MemoizedFunction {
        id: direct,
        ..
    } = &fields[0].1
    else {
        panic!("expected memoized factory")
    };
    let direct = direct.clone();
    let via_reexport = evaluation
        .evaluate_root("via_reexport")
        .unwrap()
        .value()
        .unwrap();
    let syrox_lang::evaluator::Value::Struct {
        fields,
        ..
    } = via_reexport
    else {
        panic!("expected reference")
    };
    let syrox_lang::evaluator::Value::MemoizedFunction {
        id: reexported,
        ..
    } = &fields[0].1
    else {
        panic!("expected memoized factory")
    };
    assert_eq!(direct, *reexported);
}

#[test]
fn generated_catalog_member_supports_composite_module_keys() {
    let workspace = TempProject::new();
    let config = package_configuration();
    workspace.write(
        "catalog/main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        pub publish(recipes, recipe): std::Package;
    "#,
    );
    workspace.write(
        "catalog/recipes/group/hello.srx",
        "pub fn recipe() -> std::Package { std::Package { id = \"hello\"; dependencies = []; } }",
    );
    workspace.write(
        "consumer/main.srx",
        r#"
        inputs { pkgs = "path:../catalog"; }
        outputs { direct: std::RecipeRef<std::Package> = pkgs::group::hello; }
    "#,
    );
    let catalog = workspace.0.join("catalog");
    let consumer = workspace.0.join("consumer");
    lock_project_with(&catalog, &config).unwrap();
    lock_project_with(&consumer, &config).unwrap();
    let analysis = open_project_analysis_with(&consumer, &config).unwrap();
    let snapshot = analysis.snapshot();
    let (source_id, source) = snapshot
        .sources()
        .iter()
        .find(|(_, source)| source.text().contains("pkgs::group::hello"))
        .unwrap();
    let offset = u32::try_from(source.text().find("pkgs::group::hello").unwrap() + 13).unwrap();
    let checked = snapshot
        .analyze(&syrox_lang::analysis::AnalysisCancellation::default())
        .unwrap();
    assert!(
        checked.diagnostics().is_empty(),
        "{:?}",
        checked.diagnostics()
    );
    assert!(
        checked
            .complete_path(source_id, offset, &["pkgs".into()], "gro")
            .iter()
            .any(|(name, _)| name == "group")
    );
    assert!(
        checked
            .complete_path(
                source_id,
                offset,
                &["pkgs".into(), "group".into()],
                "he"
            )
            .iter()
            .any(|(name, _)| name == "hello")
    );
}

#[test]
fn generated_catalog_member_rejects_an_explicit_output_collision() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        outputs {
            hello: std::Package = std::Package { id = "other"; dependencies = []; };
        }
        pub publish(recipes, recipe): std::Package;
    "#,
    );
    project.write(
        "recipes/hello.srx",
        "pub fn recipe() -> std::Package { std::Package { id = \"hello\"; dependencies = []; } }",
    );
    let error = lock_project_with(&project.0, &package_configuration()).unwrap_err();
    assert!(matches!(error,
        ProjectOperationError::Check(CheckFailure::Diagnostics { errors, .. })
            if errors.iter().any(|error| error.message.contains("catalog member conflicts"))));
}

#[test]
fn generated_catalog_member_rejects_an_existing_module_prefix() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        mod group { pub fn helper() {} }
        pub publish(recipes, recipe): std::Package;
    "#,
    );
    project.write(
        "recipes/group/hello.srx",
        r#"
        pub fn recipe() -> std::Package {
            std::Package { id = "hello"; dependencies = []; }
        }
    "#,
    );
    let error = lock_project_with(&project.0, &package_configuration()).unwrap_err();
    assert!(matches!(error,
        ProjectOperationError::Check(CheckFailure::Diagnostics { errors, .. })
            if errors.iter().any(|error| error.message.contains("catalog member conflicts with a declared namespace"))));
}

#[test]
fn duplicate_publication_names_are_rejected_without_running_factories() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r"
        mod left { mod same { pub fn recipe() -> std::Recipe { recipe() } } }
        mod right { mod same { pub fn recipe() -> std::Recipe { recipe() } } }
        pub publish(left, recipe): std::Recipe;
        pub publish(right, recipe): std::Recipe;
    ",
    );
    assert!(matches!(
        lock_project_with(&project.0, &package_configuration()),
        Err(ProjectOperationError::Check(
            CheckFailure::Diagnostics { .. }
        ))
    ));
}

#[test]
fn consumer_binds_a_provider_reference_into_a_recipe_factory() {
    let project = TempProject::new();
    project.write("main.srx", r#"
        fn provider() -> std::Recipe { std::Recipe {
            package = std::Package { id = "provider"; dependencies = []; };
            acquisition = None; build = None; build_inputs = None; commands = [];
        } }
        fn app(provider: std::RecipeRef<std::Recipe>) -> std::Recipe { std::Recipe {
            package = std::Package { id = "app"; dependencies = [std::Dependency { recipe = provider; }]; };
            acquisition = None; build = None; build_inputs = None; commands = [];
        } }
        mod factories {
            mod provider_ref { pub fn recipe() -> std::Recipe { project::provider() } }
            mod selected { pub fn recipe() -> std::Recipe { let factory = std::bind_recipe(project::app, project::provider_ref); factory() } }
        }
        pub publish(factories, recipe): std::Recipe;
    "#);
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let locked = open_locked_project_with(&project.0, &config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    assert!(evaluation.select_package("selected").unwrap());
    let plan = evaluation.into_selected_plan().unwrap();
    let app = plan
        .packages()
        .find(|package| package.id().as_str() == "app")
        .unwrap();
    assert_eq!(
        app.dependencies().next().unwrap().as_str(),
        "provider"
    );
}

#[test]
fn consumer_binds_its_provider_into_an_imported_recipe() {
    let workspace = TempProject::new();
    workspace.write(
        "child/main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        pub use recipes::hello::with_provider;
        pub use recipes::hello::with_output;
    "#,
    );
    workspace.write("child/recipes/hello.srx", r#"
        pub fn with_provider(provider: std::RecipeRef<std::Recipe>) -> std::Recipe {
            std::Recipe {
                package = std::Package { id = "app"; dependencies = [std::Dependency { recipe = provider; }]; };
                acquisition = None; build = None; build_inputs = None; commands = [];
            }
        }
        pub fn with_output(output: std::OutputRef<std::Recipe>) -> std::Recipe {
            std::Recipe {
                package = std::Package { id = "app-output"; dependencies = []; };
                acquisition = std::Option::Some(std::Acquisition { sources = [
                    std::source_request("https://example.test/app.tar.gz",
                        "0000000000000000000000000000000000000000000000000000000000000000", 100)
                ]; });
                build = std::Option::Some(std::autotools(std::BuildOptions {
                    source_directory = "app-output-1"; timeout_seconds = 60; }));
                build_inputs = std::Option::Some(std::BuildInputs { selected = [output]; });
                commands = [std::Command { name = "main"; output = "out"; path = "usr/bin/app";
                    loader = [std::RuntimeFile { output = std::recipe_output(std::output_recipe(output), "out"); path = "usr/lib/ld-linux-x86-64.so.2"; }];
                    libraries = [std::recipe_output(std::output_recipe(output), "out")]; }];
            }
        }
    "#);
    workspace.write("consumer/main.srx", r#"
        inputs { pkgs = "path:../child"; }
        fn provider() -> std::Recipe { std::Recipe {
            package = std::Package { id = "provided"; dependencies = []; };
            acquisition = std::Option::Some(std::Acquisition { sources = [
                std::source_request("https://example.test/provider.tar.xz",
                    "0000000000000000000000000000000000000000000000000000000000000000", 100)
            ]; });
            build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap;
                source_directory = "provided-1"; timeout_seconds = 120;  source_format = std::BuildSourceFormat::Xz; produces = ["dev", "out"]; steps = [std::BuildStep::Extract(std::BuildPath::Work("source"))]; });
            build_inputs = std::Option::None; commands = [];
        } }
        mod factories {
            mod provided { pub fn recipe() -> std::Recipe { project::provider() } }
            mod app { pub fn recipe() -> std::Recipe { let factory = std::bind_recipe(pkgs::with_provider, project::provided); factory() } }
            mod app_output { pub fn recipe() -> std::Recipe { let factory = std::bind_output(pkgs::with_output, std::recipe_output(project::provided, "dev")); factory() } }
        }
        pub publish(factories, recipe): std::Recipe;
    "#);
    let config = package_configuration();
    lock_project_with(&workspace.0.join("child"), &config).unwrap();
    let consumer = workspace.0.join("consumer");
    lock_project_with(&consumer, &config).unwrap();
    let plan = plan_project_with(&consumer, &config).unwrap();
    let app = plan
        .packages()
        .find(|package| package.id().as_str() == "app")
        .unwrap();
    assert_eq!(
        app.dependencies().next().unwrap().as_str(),
        "provided"
    );
    let output_app = plan
        .builds()
        .find(|build| build.package().as_str() == "app-output")
        .unwrap();
    assert_eq!(
        output_app.inputs()[0].package.as_str(),
        "provided"
    );
}

#[test]
fn complete_publication_plan_keeps_other_outputs_and_reports_their_failures() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        value I(int); value Text(str);
        fn make() -> std::Package { std::Package { id = "hello"; dependencies = []; } }
        fn broken() -> std::Shell { broken() }
        mod factories {
            mod hello { pub fn recipe() -> std::Recipe { std::Recipe { package = project::make(); } } }
            mod direct { pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = "extra"; dependencies = []; }; } } }
        }
        pub publish(factories, recipe): std::Recipe;
        outputs {

            label: std::Shell = std::Shell { pkgs = []; services = []; };
        }
    "#,
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let plan = plan_project_with(&project.0, &config).unwrap();
    assert_eq!(plan.packages().len(), 2);
    assert!(plan.roots().any(|root| root.name() == "label"));
    project.write(
        "main.srx",
        &fs::read_to_string(project.0.join("main.srx"))
            .unwrap()
            .replace(
                "label: std::Shell = std::Shell { pkgs = []; services = []; }",
                "label: std::Shell = broken()",
            ),
    );
    lock_project_with(&project.0, &config).unwrap();
    assert!(matches!(plan_project_with(&project.0, &config),
        Err(ProjectOperationError::Check(CheckFailure::Evaluation { failed_roots, .. }))
            if failed_roots == ["label"]));
}

#[test]
fn generated_catalog_selects_a_memoized_reference_without_forcing_other_factories() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        pub publish(recipes, recipe): std::Recipe;
        "#,
    );
    project.write(
        "recipes/group/hello.srx",
        "pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = \"hello\"; dependencies = []; }; } }",
    );
    project.write(
        "recipes/unused.srx",
        "pub fn recipe() -> std::Recipe { recipe() }",
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let locked = open_locked_project_with(&project.0, &config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    assert!(matches!(
        evaluation.catalog_reference("group::hello").unwrap(),
        Some(syrox_lang::evaluator::Value::Struct { fields, .. })
            if matches!(fields.as_slice(), [(name, syrox_lang::evaluator::Value::MemoizedFunction { .. })] if name == "factory")
    ));
    assert!(
        evaluation
            .catalog_reference("absent")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        evaluation.catalog_names().unwrap().unwrap(),
        ["group::hello", "unused"]
    );
    assert!(evaluation.select_package("group::hello").unwrap());
    let plan = evaluation.into_selected_plan().unwrap();
    assert_eq!(plan.roots().len(), 1);
    let root = plan.roots().next().unwrap();
    assert_eq!(root.name(), "group::hello");
    assert!(
        root.path()
            .ends_with(&["group".into(), "hello".into()])
    );
    assert_eq!(
        plan.packages().next().unwrap().export(),
        Some("group::hello")
    );
    let mut missing = locked.evaluation().unwrap();
    assert!(matches!(
        missing.select_package("absent"),
        Err(ProjectOperationError::MissingPackageReference { key }) if key == "absent"
    ));
}

#[test]
fn published_lookups_and_diamond_references_evaluate_a_factory_once() {
    use std::sync::atomic::AtomicUsize;
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn observe(_: i64) -> bool {
        CALLS.fetch_add(1, Ordering::Relaxed);
        true
    }
    let project = TempProject::new();
    project.write("main.srx", r#"
        value I(int); value Probe(int) where observe(self);
        fn base() -> I { let probe = Probe(1); I(7) }
        fn unused() -> I { unused() }
        mod factories {
            mod shared { pub fn recipe() -> I { project::base() } }
            mod dormant { pub fn recipe() -> I { project::unused() } }
        }
        pub publish(factories, recipe): I;
        fn selected() -> I { std::recipe_value(project::shared) }
        fn reference() -> std::RecipeRef<I> { project::shared }
        outputs {
            left: std::RecipeRef<I> = std::recipe_ref(fn() -> I { std::recipe_value(reference()) });
            right: std::RecipeRef<I> = std::recipe_ref(fn() -> I { std::recipe_value(reference()) });
            development: std::OutputRef<I> = std::recipe_output(reference(), "dev");
            name: std::OutputName = std::output_name(development);
            values: [I] = [selected(), std::recipe_value(left), std::recipe_value(right), std::recipe_value(std::output_recipe(development))];
        }
    "#);
    let policy = CheckPolicy::new("std-recipe-ref-observation")
        .unwrap()
        .with_predicate("observe", syrox_lang::checker::PrimitiveType::Int)
        .unwrap();
    let config = CheckConfiguration {
        environment: EvaluationEnvironment::new(&policy)
            .with_int_predicate("observe", observe)
            .unwrap(),
        policy,
        ..package_configuration()
    };
    let loaded = loader::load_project_linux(&project.0, &config).unwrap();
    let checked = analyze::check_loaded(&loaded, &config).unwrap();
    let mut session = syrox_lang::evaluator::EvaluationSession::new(
        &checked,
        &config.policy,
        &config.environment,
        config.evaluation_limits,
    )
    .unwrap();
    session.evaluate_root("name").unwrap();
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    let syrox_lang::evaluator::Value::List {
        items,
        ..
    } = session
        .evaluate_root("values")
        .unwrap()
        .value()
        .unwrap()
    else {
        panic!("expected values");
    };
    assert_eq!(items.len(), 4);
    assert!(items.iter().all(|value| matches!(
        value,
        syrox_lang::evaluator::Value::Nominal {
            value: syrox_lang::evaluator::PrimitiveValue::Int(7),
            ..
        }
    )));
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
}

#[test]
fn deferred_standard_factory_uses_the_reference_creation_project_for_assets() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    workspace.write("child/assets/source", "child");
    workspace.write("consumer/assets/source", "consumer");
    workspace.write(
        "child/main.srx",
        r#"
        outputs {
            source: std::RecipeRef<std::Acquisition> = std::recipe_ref(std::preset_sources);
            selected: std::OutputRef<std::Acquisition> = std::recipe_output(source, "out");
        }
    "#,
    );
    workspace.write(
        "consumer/main.srx",
        r#"
        inputs { child = "path:../child"; }
        mod factories { mod package { pub fn recipe() -> std::Recipe { std::Recipe {
            package = std::Package { id = "app"; dependencies = []; };
            acquisition = std::Option::Some(std::recipe_value(std::output_recipe(child::selected)));
        } } } }
        pub publish(factories, recipe): std::Recipe;
    "#,
    );
    let mut sources = AuthenticatedStandardLibrary::bundled()
        .sources()
        .cloned()
        .collect::<Vec<_>>();
    sources.push(AuthenticatedStandardSource::from_authenticated("std/preset.srx", r#"
        mod std {
            pub fn preset_sources() -> Acquisition {
                Acquisition { sources = [source_request(
                    "project:assets/source", "ddc9e669194254cef019a29d3619a2c16592e5d52e1a81e98b01bd52319149a3", 100
                )]; }
            }
        }
    "#).unwrap());
    let config = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::from_authenticated(sources).unwrap()),
        ..CheckConfiguration::default()
    };
    lock_project_with(&child, &config).unwrap();
    lock_project_with(&consumer, &config).unwrap();
    let prepared = prepare_project_with(&consumer, &config).unwrap();
    let plan = prepared.plan();
    let request = plan
        .acquisitions()
        .next()
        .unwrap()
        .sources()
        .next()
        .unwrap();
    assert_eq!(
        fs::canonicalize(
            prepared
                .project_root(request.owner().unwrap())
                .unwrap()
        )
        .unwrap(),
        fs::canonicalize(child).unwrap()
    );
}

#[test]
fn recipe_references_are_opaque_and_cannot_be_serialized_as_persistent_plan_values() {
    let project = TempProject::new();
    let config = package_configuration();
    project.write("main.srx", "value I(int); fn make() -> I { I(1) } outputs { instance: std::RecipeRef<I> = std::RecipeRef<I> { factory = make; }; }");
    assert!(
        matches!(lock_project_with(&project.0, &config), Err(ProjectOperationError::Check(CheckFailure::Diagnostics { errors, .. })) if errors.iter().any(|error| error.message.contains("opaque")))
    );
    project.write("main.srx", "value I(int); fn make() -> I { I(1) } outputs { instance: std::RecipeRef<I> = std::recipe_ref(make); }");
    lock_project_with(&project.0, &config).unwrap();
    assert!(matches!(
        plan_project_with(&project.0, &config),
        Err(ProjectOperationError::InvalidConsumerOutput { .. })
    ));
}

#[test]
fn public_module_bindings_export_without_exposing_private_bindings() {
    let workspace = TempProject::new();
    let config = package_configuration();
    workspace.write(
        "child/main.srx",
        r#"let private = "hidden"; pub let selected: PackageId = "hello";"#,
    );
    let child = workspace.0.join("child");
    lock_project_with(&child, &config).unwrap();
    workspace.write("consumer/main.srx", r#"inputs { child = "path:../child"; } use child::selected; let name = selected; outputs { shell: Shell = Shell { pkgs = []; services = [Service { id = "selected"; files = [ConfigFile { path = "name"; text = "${name}"; }]; }]; }; }"#);
    let consumer = workspace.0.join("consumer");
    lock_project_with(&consumer, &config).unwrap();
    let plan = plan_project_with(&consumer, &config).unwrap();
    assert_eq!(
        plan.consumers().next().unwrap().services()[0].files()[0].text(),
        "hello"
    );
    workspace.write(
        "consumer/main.srx",
        r#"inputs { child = "path:../child"; } let name = child::private;"#,
    );
    assert!(check_path_with(&consumer, &config).is_err());
}

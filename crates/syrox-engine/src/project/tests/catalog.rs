use super::*;

#[test]
fn package_factory_closure_composes_without_a_rust_package_case() {
    let plan = package_plan(
        "fn apply(factory: fn() -> std::Package) -> std::Package { factory() } mod catalog { mod pkg { pub fn recipe() -> std::Recipe { std::Recipe { package = apply(fn() -> std::Package { std::Package { id = \"closure-pkg\"; dependencies = []; } }); } } } } pub publish(catalog, recipe): std::Recipe;",
    ).unwrap();
    assert_eq!(
        plan.packages()
            .map(|package| package.id().as_str())
            .collect::<Vec<_>>(),
        ["closure-pkg"]
    );
}

#[test]
fn locked_catalog_discovers_factories_across_files_and_requires_relock_on_addition() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"inputs { catalog = "modules:recipes"; }
         pub publish(catalog, recipe): std::Recipe;"#,
    );
    project.write(
        "recipes/hello.srx",
        r#"
        pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = "hello"; dependencies = []; }; } }
    "#,
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages()
            .map(|p| p.id().as_str())
            .collect::<Vec<_>>(),
        ["hello"]
    );
    assert_eq!(
        plan.packages().next().unwrap().export(),
        Some("hello")
    );

    project.write(
        "recipes/glibc.srx",
        r#"
        pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = "glibc"; dependencies = []; }; } }
    "#,
    );
    assert!(matches!(
        plan_project_with(&project.0, &configuration),
        Err(ProjectOperationError::ProjectDrift)
    ));
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages()
            .map(|p| p.id().as_str())
            .collect::<Vec<_>>(),
        ["glibc", "hello"]
    );
    assert_eq!(
        plan.packages()
            .map(|p| p.export())
            .collect::<Vec<_>>(),
        [Some("glibc"), Some("hello")]
    );
}

#[test]
fn single_composite_recipe_exports_package_source_and_build() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"inputs { catalog = "modules:recipes"; }
         pub publish(catalog, recipe): std::Recipe;"#,
    );
    project.write(
        "recipes/glibc.srx",
        r#"pub fn recipe() -> std::Recipe {
            std::Recipe {
                package = std::Package { id = "glibc"; dependencies = []; };
                acquisition = std::Option::Some(std::Acquisition {
                    sources = [std::SourceRequest {
                        url = "https://example.test/glibc.tar.xz";
                        sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
                        maximum_bytes = 33554432;
                    }];
                });
                build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap;
                    source_directory = "glibc-2.44";
                    timeout_seconds = 1800;
                 source_format = std::BuildSourceFormat::Xz; produces = ["dev", "out"]; steps = [std::BuildStep::Extract(std::BuildPath::Work("source"))]; });
                build_inputs = std::Option::None;
                commands = [];
            }
        }
        "#,
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages().next().unwrap().export(),
        Some("glibc")
    );
    assert_eq!(plan.acquisitions().count(), 1);
    assert_eq!(
        plan.builds()
            .next()
            .unwrap()
            .program()
            .source_format,
        crate::build::BuildSourceFormat::Xz
    );
    assert_eq!(
        plan.roots()
            .filter(|root| root.name() == "glibc")
            .count(),
        1
    );
}

#[test]
fn public_factory_needs_no_repeated_output_signature() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"inputs { catalog = "modules:recipes"; }
         pub publish(catalog, hello): std::Recipe;"#,
    );
    project.write(
        "recipes/hello.srx",
        r#"
        fn private() -> std::Recipe { std::Recipe { package = std::Package { id = "hello"; dependencies = []; }; } }
        pub fn hello() -> std::Recipe { private() }
    "#,
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages().next().unwrap().export(),
        Some("hello")
    );
    assert_eq!(plan.packages().count(), 1);
    project.write(
        "main.srx",
        r#"inputs { catalog = "modules:recipes"; }
        outputs { secret: std::Package = catalog::private(); }"#,
    );
    let result = check_project_with(&project.0, &configuration);
    assert!(
        matches!(&result,
        Err(CheckFailure::Diagnostics { errors, .. }) if errors.iter().any(|error| error.message.contains("private"))),
        "{result:?}"
    );
}

#[test]
fn catalog_files_have_distinct_modules_and_package_entrypoints() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"inputs { catalog = "modules:recipes"; }
         pub publish(catalog, recipe): std::Recipe;"#,
    );
    project.write(
        "recipes/hello/package.srx",
        r#"
        fn make() -> std::Recipe { std::Recipe { package = std::Package { id = "hello"; dependencies = []; }; } }
        pub fn recipe() -> std::Recipe { make() }
    "#,
    );
    project.write(
        "recipes/glibc/package.srx",
        r#"
        fn make() -> std::Recipe { std::Recipe { package = std::Package { id = "glibc"; dependencies = []; }; } }
        pub fn recipe() -> std::Recipe { make() }
    "#,
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages()
            .map(|pkg| pkg.export())
            .collect::<Vec<_>>(),
        [Some("glibc"), Some("hello")]
    );
    project.write(
        "main.srx",
        r#"inputs { catalog = "modules:recipes"; }
        pub publish(catalog, recipe): std::Recipe;
        outputs { private: std::Recipe = catalog::hello::make(); }"#,
    );
    let result = check_project_with(&project.0, &configuration);
    assert!(
        matches!(&result,
        Err(CheckFailure::Diagnostics { errors, .. }) if errors.iter().any(|error| error.message.contains("private"))),
        "{result:?}"
    );
    project.write(
        "recipes/hello.srx",
        "pub fn extra() -> std::Recipe { std::Recipe { package = std::Package { id = \"extra\"; dependencies = []; }; } }",
    );
    assert!(
        matches!(check_project_with(&project.0, &configuration),
        Err(CheckFailure::InvalidModuleInput { reason }) if reason.contains("share one recipe module"))
    );
}

#[test]
fn modules_locator_is_a_general_locked_input_without_catalog_marker() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"inputs { dep = "modules:dep"; }
        pub publish(dep, make): std::Recipe;"#,
    );
    for name in ["hello", "glibc"] {
        project.write(
            &format!("dep/{name}.srx"),
            &format!(
                r#"
            fn private() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "{name}"; dependencies = []; }}; }} }}
            pub fn make() -> std::Recipe {{ private() }}
        "#
            ),
        );
    }
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages()
            .map(|pkg| pkg.export())
            .collect::<Vec<_>>(),
        [Some("glibc"), Some("hello")]
    );
    project.write(
        "dep/other.srx",
        "pub fn unused() -> std::Recipe { std::Recipe { package = std::Package { id = \"other\"; dependencies = []; }; } }",
    );
    assert!(matches!(
        plan_project_with(&project.0, &configuration),
        Err(ProjectOperationError::ProjectDrift)
    ));
}

#[test]
fn authenticated_input_factory_flows_through_lock_check_and_plan() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        inputs { catalog = "path:catalog"; }
        mod published { mod package { pub fn recipe() -> std::Recipe { std::Recipe { package = catalog::zlib(); } } } } pub publish(published, recipe): std::Recipe;
        "#,
    );
    project.write(
        "catalog/package.srx",
        r#"
        fn make_zlib() -> std::Package {
            std::Package { id = "zlib"; dependencies = []; }
        }
        outputs { zlib: fn() -> std::Package = make_zlib; }
        "#,
    );
    let configuration = package_configuration();

    lock_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        check_project_lock_with(&project.0, &configuration)
            .unwrap()
            .status(),
        lock::LockStatus::Unchanged
    );
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages()
            .map(|package| package.id().as_str())
            .collect::<Vec<_>>(),
        ["zlib"]
    );
}

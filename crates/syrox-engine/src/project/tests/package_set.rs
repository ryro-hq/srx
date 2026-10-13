use super::*;

#[test]
fn recipe_without_acquisition_or_build_projects_a_package() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        mod factories { mod simple { pub fn recipe() -> std::Recipe { std::Recipe {
                package = std::Package { id = "simple"; dependencies = []; };
                acquisition = std::Option::None;
                build = std::Option::None;
                build_inputs = std::Option::None;
                commands = [];
            } } } }
        pub publish(factories, recipe): std::Recipe;
        "#,
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let plan = plan_project_with(&project.0, &config).unwrap();
    assert_eq!(plan.packages().len(), 1);
    assert_eq!(
        plan.packages().next().unwrap().id().as_str(),
        "simple"
    );
    assert_eq!(plan.acquisitions().len(), 0);
    assert_eq!(plan.builds().len(), 0);
}

const PROVIDER: &str = r#"
        mod providers { mod libc { pub fn recipe() -> std::Recipe { std::Recipe {
            package = std::Package { id = "libc"; dependencies = []; };
            acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request(
                "https://example.test/libc.tar.gz", "0000000000000000000000000000000000000000000000000000000000000000", 100
            )]; });
            build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "libc-1"; timeout_seconds = 120;  source_format = std::BuildSourceFormat::Xz; produces = ["dev", "out"]; steps = [std::BuildStep::Extract(std::BuildPath::Work("source"))]; });
            build_inputs = std::Option::None;
            commands = [];
        } } } }
        pub publish(providers, recipe): std::Recipe;
"#;

#[test]
fn mixed_build_catalog_selects_each_backend_from_one_recipe_type() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        type Entry = std::Recipe;
        pub publish(recipes, recipe): Entry;
    "#,
    );
    project.write("recipes/hello.srx", r#"
        pub fn recipe() -> std::Recipe {
            std::Recipe {
                package = std::Package { id = "hello"; dependencies = []; };
                acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request(
                    "https://example.test/hello", "0000000000000000000000000000000000000000000000000000000000000000", 100
                )]; });
                build = std::Option::Some(std::autotools(std::BuildOptions {
                    source_directory = "hello-1"; timeout_seconds = 30;
                }));
                build_inputs = std::Option::None;
                commands = [];
            }
        }
    "#);
    project.write("recipes/libc.srx", r#"
        pub fn recipe() -> std::Recipe {
            std::Recipe {
                package = std::Package { id = "libc"; dependencies = []; };
                acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request(
                    "https://example.test/libc", "0000000000000000000000000000000000000000000000000000000000000000", 100
                )]; });
                build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap;
                    source_directory = "libc-1"; timeout_seconds = 120;
                 source_format = std::BuildSourceFormat::Xz; produces = ["dev", "out"]; steps = [std::BuildStep::Extract(std::BuildPath::Work("source"))]; });
                build_inputs = std::Option::None;
                commands = [];
            }
        }
    "#);
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let catalog_plan = plan_project_with(&project.0, &config).unwrap();
    assert_eq!(catalog_plan.roots().len(), 2);
    assert_eq!(catalog_plan.packages().len(), 2);
    let user = crate::config::UserConfiguration::parse("", project.0.join("store")).unwrap();
    let selected = crate::realize::resolve_build(
        &format!("{}#hello", project.0.display()),
        &user,
        &config,
    )
    .unwrap();
    assert_eq!(selected.export(), "hello");
    let builds =
        crate::realize::resolve_builds(project.0.to_str().unwrap(), &user, &config).unwrap();
    assert_eq!(
        builds
            .iter()
            .map(crate::realize::ResolvedBuild::export)
            .collect::<Vec<_>>(),
        ["hello", "libc"]
    );
    assert!(!project.0.join("store").exists());
    let locked = open_locked_project_with(&project.0, &config).unwrap();
    for (key, format) in [
        ("hello", crate::build::BuildSourceFormat::Gzip),
        ("libc", crate::build::BuildSourceFormat::Xz),
    ] {
        let mut evaluation = locked.evaluation().unwrap();
        assert!(evaluation.select_package(key).unwrap());
        assert!(evaluation.select_package(key).unwrap());
        let plan = evaluation.into_selected_plan().unwrap();
        assert_eq!(plan.packages().len(), 1);
        assert_eq!(
            plan.packages().next().unwrap().export(),
            Some(key)
        );
        assert_eq!(
            plan.builds()
                .next()
                .unwrap()
                .program()
                .source_format,
            format
        );
    }
    project.write(
        "recipes/unused.srx",
        "pub fn recipe() -> std::Recipe { recipe() }",
    );
    lock_project_with(&project.0, &config).unwrap();
    assert!(plan_project_with(&project.0, &config).is_err());
    assert_eq!(
        crate::realize::resolve_build(
            &format!("{}#hello", project.0.display()),
            &user,
            &config
        )
        .unwrap()
        .export(),
        "hello"
    );
    let source_plan = plan_project_package_with(&project.0, &config, "hello").unwrap();
    assert_eq!(source_plan.acquisitions().len(), 1);
    assert_eq!(source_plan.packages().len(), 1);
}

#[test]
fn explicit_command_selection_ignores_unselected_failing_recipe() {
    let project = TempProject::new();
    project.write("main.srx", r#"
        mod factories {
            mod app { pub fn recipe() -> std::Recipe { std::Recipe {
                package = std::Package { id = "app"; dependencies = []; };
                acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request("https://example.test/app.tar.gz", "0000000000000000000000000000000000000000000000000000000000000000", 100)]; });
                build = std::Option::Some(std::autotools(std::BuildOptions { source_directory = "app-1"; timeout_seconds = 30; }));
                commands = [std::Command { name = "main"; output = "out"; path = "usr/bin/app"; }];
            } } }
            mod unused { pub fn recipe() -> std::Recipe { recipe() } }
        }
        pub publish(factories, recipe): std::Recipe;
    "#);
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    assert!(plan_project_with(&project.0, &config).is_err());
    let user = crate::config::UserConfiguration::parse("", project.0.join("store")).unwrap();
    let command = crate::realize::resolve_command(
        &format!("{}#app", project.0.display()),
        Some("main"),
        &user,
        &config,
    )
    .unwrap();
    assert_eq!(command.description().package().as_str(), "app");
    assert!(!project.0.join("store").exists());
}

fn recipe_source(body: &str) -> String {
    format!(
        r#"
        pub fn recipe() -> std::Recipe {{
            {body}
            std::Recipe {{
                package = std::Package {{ id = "hello"; dependencies = []; }};
                acquisition = std::Option::Some(std::Acquisition {{ sources = [
                    std::source_request("project:assets/source",
                        "ddc9e669194254cef019a29d3619a2c16592e5d52e1a81e98b01bd52319149a3", 100)
                ]; }});
                build = std::Option::Some(std::autotools(std::BuildOptions {{ source_directory = "hello-1"; timeout_seconds = 120; }}));
                build_inputs = std::Option::None;
                commands = [std::Command {{ name = "main"; output = "out"; path = "usr/bin/hello";  loader = []; libraries = []; }}];
            }}
        }}
    "#
    )
}

#[test]
fn direct_command_selection_expands_only_its_declared_runtime_provider() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        type Entry = std::Recipe;
        pub publish(recipes, recipe): Entry;
    "#,
    );
    project.write(
        "recipes/hello.srx",
        r#"
        pub fn recipe() -> std::Recipe {
            std::Recipe {
                package = std::Package { id = "hello"; dependencies = []; };
                acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request(
                    "https://example.test/hello.tar.gz",
                    "0000000000000000000000000000000000000000000000000000000000000000", 100
                )]; });
                build = std::Option::Some(std::autotools(std::BuildOptions { source_directory = "hello-1"; timeout_seconds = 120; }));
                build_inputs = std::Option::Some(std::BuildInputs { selected = [
                    std::recipe_output(project::libc, "dev")
                ]; });
                commands = [std::Command { name = "main"; output = "out"; path = "usr/bin/hello";
                    loader = [std::RuntimeFile { output = std::recipe_output(project::libc, "out"); path = "usr/lib/ld-linux-x86-64.so.2"; }];
                    libraries = [std::recipe_output(project::libc, "out")]; }];
            }
        }
    "#,
    );
    project.write(
        "recipes/unused.srx",
        "pub fn recipe() -> std::Recipe { recipe() }",
    );
    project.write(
        "recipes/libc.srx",
        r#"
        pub fn recipe() -> std::Recipe {
            std::Recipe {
                package = std::Package { id = "libc"; dependencies = []; };
                acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request(
                    "https://example.test/libc.tar.gz",
                    "0000000000000000000000000000000000000000000000000000000000000000", 100
                )]; });
                build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap;
                    source_directory = "libc-1";
                    timeout_seconds = 120;  source_format = std::BuildSourceFormat::Xz; produces = ["dev", "out"]; steps = [std::BuildStep::Extract(std::BuildPath::Work("source"))]; });
                build_inputs = std::Option::None;
                commands = [];
            }
        }
    "#,
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let locked = open_locked_project_with(&project.0, &config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    assert!(evaluation.select_package("hello").unwrap());
    let plan = evaluation.into_selected_plan().unwrap();
    assert_eq!(plan.roots().len(), 2);
    assert_eq!(plan.packages().len(), 2);
    assert_eq!(plan.builds().len(), 2);
    assert_eq!(plan.commands().len(), 1);
    assert_eq!(
        plan.commands()
            .next()
            .unwrap()
            .loader()
            .unwrap()
            .output
            .package
            .as_str(),
        "libc"
    );
    assert!(plan.roots().all(|root| root.name() != "unused"));
    let user = crate::config::UserConfiguration::parse("", project.0.join("store")).unwrap();
    let reference = format!("{}#hello", project.0.display());
    let build = crate::realize::resolve_build(&reference, &user, &config).unwrap();
    assert_eq!(
        build.description().inputs()[0].package.as_str(),
        "libc"
    );
    let application =
        crate::realize::resolve_command(&reference, Some("main"), &user, &config).unwrap();
    assert_eq!(
        application
            .description()
            .loader()
            .unwrap()
            .output
            .package
            .as_str(),
        "libc"
    );
    assert!(!project.0.join("store").exists());
    let provider = fs::read_to_string(project.0.join("recipes/libc.srx")).unwrap();
    project.write(
        "recipes/libc.srx",
        &provider.replace("id = \"libc\"", "id = \"different\""),
    );
    lock_project_with(&project.0, &config).unwrap();
    let locked = open_locked_project_with(&project.0, &config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    assert!(evaluation.select_package("hello").unwrap());
    assert_eq!(
        evaluation
            .into_selected_plan()
            .unwrap()
            .commands()
            .next()
            .unwrap()
            .loader()
            .unwrap()
            .output
            .package
            .as_str(),
        "different"
    );
    project.write(
        "recipes/libc.srx",
        "pub fn recipe() -> std::Recipe { recipe() }",
    );
    lock_project_with(&project.0, &config).unwrap();
    let locked = open_locked_project_with(&project.0, &config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    assert!(evaluation.select_package("hello").unwrap());
    assert!(matches!(
        evaluation.into_selected_plan(),
        Err(ProjectOperationError::Check(CheckFailure::Evaluation { failed_roots, .. }))
            if failed_roots == ["libc"]
    ));
}

#[test]
fn imported_publication_selects_one_composite_recipe_and_preserves_asset_origin() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    workspace.write(
        "child/main.srx",
        r#"
        inputs { recipes = "modules:recipes"; }
        pub type Entry = std::Recipe;
        pub publish(recipes, recipe): Entry;
    "#,
    );
    workspace.write("child/recipes/hello.srx", &recipe_source(""));
    workspace.write(
        "child/recipes/unused.srx",
        &recipe_source("let cycle = recipe();"),
    );
    workspace.write("child/assets/source", "child");
    workspace.write("consumer/assets/source", "consumer");
    let main = r#"
        inputs { pkgs = "path:../child"; }
        mod factories { mod hello { pub fn recipe() -> pkgs::Entry { std::recipe_value(pkgs::hello) } } } pub publish(factories, recipe): pkgs::Entry;
    "#;
    workspace.write("consumer/main.srx", &format!("{main} {PROVIDER}"));
    let config = package_configuration();
    lock_project_with(&child, &config).unwrap();
    lock_project_with(&consumer, &config).unwrap();
    let prepared = prepare_project_with(&consumer, &config).unwrap();
    let plan = prepared.plan();
    assert_eq!(plan.packages().len(), 2);
    assert!(
        plan.packages()
            .any(|package| package.export() == Some("hello"))
    );
    assert_eq!(plan.builds().len(), 2);
    assert_eq!(plan.commands().len(), 1);
    let child_locked = open_locked_project_with(&child, &config).unwrap();
    assert_eq!(
        child_locked
            .evaluation()
            .unwrap()
            .catalog_names()
            .unwrap()
            .unwrap(),
        ["hello", "unused"]
    );
    let source = plan
        .acquisitions()
        .find(|acquisition| acquisition.package().as_str() == "hello")
        .unwrap()
        .sources()
        .next()
        .unwrap();
    assert_eq!(
        fs::canonicalize(
            prepared
                .project_root(source.owner().unwrap())
                .unwrap()
        )
        .unwrap(),
        fs::canonicalize(&child).unwrap()
    );
}

#[test]
fn composite_recipe_is_evaluated_once_before_projecting_all_components() {
    use std::sync::atomic::AtomicUsize;
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn observed(_: i64) -> bool {
        CALLS.fetch_add(1, Ordering::Relaxed);
        true
    }
    let policy = CheckPolicy::new("recipe-observation")
        .unwrap()
        .with_predicate(
            "host::observed",
            syrox_lang::checker::PrimitiveType::Int,
        )
        .unwrap();
    let config = CheckConfiguration {
        environment: EvaluationEnvironment::new(&policy)
            .with_int_predicate("host::observed", observed)
            .unwrap(),
        policy,
        ..package_configuration()
    };
    let project = TempProject::new();
    let factory = format!(
        "value Observed(int) where host::observed(self); {}",
        recipe_source("let observation = Observed(1);")
    );
    project.write(
        "main.srx",
        &format!("{factory} mod factories {{ mod hello {{ pub fn recipe() -> std::Recipe {{ project::recipe() }} }} }} pub publish(factories, recipe): std::Recipe; {PROVIDER} outputs {{ selected: std::Recipe = std::recipe_value(hello); provider: std::Recipe = std::recipe_value(libc); }}"),
    );
    project.write("assets/source", "child");
    CALLS.store(0, Ordering::Relaxed);
    // Pure evaluation with an observation predicate; custom policies cannot be
    // authenticated as project locks. This tests projection, not a destination.
    let validated = validate_project_with(&project.0, &config).unwrap();
    let plan = crate::plan::Plan::from_realized(
        validated.realized(),
        [0; 32],
        config.policy.identity(),
        config.standard_library.as_ref(),
    )
    .unwrap();
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(plan.packages().len(), 2);
    assert_eq!(plan.acquisitions().len(), 2);
    assert_eq!(plan.builds().len(), 2);
    assert_eq!(plan.commands().len(), 1);
}

#[test]
fn recipe_components_reject_redundant_owner_fields() {
    for component in [
        "acquisition",
        "build",
        "build_inputs",
        "commands",
    ] {
        let project = TempProject::new();
        let source = if component == "build_inputs" {
            recipe_source("").replace(
                "build_inputs = std::Option::None;",
                "build_inputs = std::Option::Some(std::BuildInputs { selected = []; });",
            )
        } else {
            recipe_source("")
        };
        let marker = match component {
            "acquisition" => "acquisition = std::Option::Some(std::Acquisition",
            "build" => "build = std::Option::Some(std::autotools(std::BuildOptions",
            "build_inputs" => "build_inputs = std::Option::Some(std::BuildInputs",
            _ => "commands = [std::Command",
        };
        let (before, after) = source.split_once(marker).unwrap();
        project.write(
            "main.srx",
            &format!(
                "{before}{marker}{} outputs {{ hello: std::Recipe = recipe(); }}",
                after.replacen('{', "{ package = \"other\";", 1)
            ),
        );
        project.write("assets/source", "child");
        let config = package_configuration();
        assert!(
            matches!(lock_project_with(&project.0, &config), Err(ProjectOperationError::Check(CheckFailure::Diagnostics { errors, .. })) if errors.iter().any(|error| error.message.contains("unknown field `package`"))),
            "{component}"
        );
    }
}

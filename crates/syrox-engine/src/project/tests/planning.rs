use super::*;

fn build_fixture() -> String {
    format!(
        r#"mod catalog {{ mod app {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{
        package = std::Package {{ id = "internal-app"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [
            std::SourceRequest {{ url = "https://nonexistent.invalid/source"; sha256 = "{}"; maximum_bytes = 100; }}
        ]; }});
        build = std::Option::Some(std::autotools(std::BuildOptions {{
            source_directory = "app-1.0"; timeout_seconds = 30;
        }}));
        commands = [];
        }} }} }}
        mod aggregate {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "aggregate"; dependencies = []; }}; }} }} }}
        }}
        pub publish(catalog, recipe): std::Recipe;"#,
        "0".repeat(64)
    )
}

#[test]
fn project_plan_rejects_non_consumer_values_before_serialization() {
    let result = package_plan(
        "struct Holder { function: fn(std::Package) -> std::Package; } fn same(package: std::Package) -> std::Package { package } outputs { holder: Holder = Holder { function = same; }; }",
    );
    assert!(matches!(
        result,
        Err(ProjectOperationError::InvalidConsumerOutput { .. })
    ));
}

#[test]
fn development_output_is_an_explicit_validated_build_edge() {
    let config = package_configuration();
    let recipe = r#"mod catalog { mod glibc { pub fn recipe() -> std::Recipe { std::Recipe {
        package = std::Package { id = "glibc"; dependencies = []; };
        acquisition = std::Option::Some(std::Acquisition { sources = [std::SourceRequest { url = "project:glibc.tar.xz"; sha256 = "0000000000000000000000000000000000000000000000000000000000000000"; maximum_bytes = 33554432; }]; });
        build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "glibc-2.44"; timeout_seconds = 1800;  source_format = std::BuildSourceFormat::Xz; produces = ["dev", "out"]; steps = [std::BuildStep::Extract(std::BuildPath::Work("source"))]; });
    } } }
    mod hello { pub fn recipe() -> std::Recipe { std::Recipe {
            package = std::Package { id = "hello"; dependencies = []; };
            acquisition = std::Option::Some(std::Acquisition { sources = [std::SourceRequest { url = "project:hello.tar.gz"; sha256 = "0000000000000000000000000000000000000000000000000000000000000000"; maximum_bytes = 2097152; }]; });
            build = std::Option::Some(std::autotools_with_libc(std::BuildOptions { source_directory = "hello-2.12.1"; timeout_seconds = 120; }));
            commands = [std::Command { name = "main"; output = "out"; path = "usr/bin/hello";  loader = [std::RuntimeFile { output = std::recipe_output(project::glibc, "out"); path = "usr/lib/ld-linux-x86-64.so.2"; }]; libraries = [std::recipe_output(project::glibc, "out")]; }];
            build_inputs = std::Option::Some(std::BuildInputs { selected = [std::recipe_output(project::glibc, "dev"), std::recipe_output(project::glibc, "out")]; });
        } } }
    } pub publish(catalog, recipe): std::Recipe;"#;
    let plan = |source: &str| {
        let project = TempProject::new();
        project.write("main.srx", source);
        lock_project_with(&project.0, &config).unwrap();
        plan_project_with(&project.0, &config)
    };
    let valid = plan(recipe).unwrap();
    let store_directory = tempfile::tempdir().unwrap();
    fs::create_dir(store_directory.path().join("store")).unwrap();
    let store = crate::store::Store::open(&store_directory.path().join("store")).unwrap();
    let root = crate::store::RootName::new("test_build_request").unwrap();
    let glibc = valid
        .builds()
        .find(|build| build.package().as_str() == "glibc")
        .unwrap();
    let mut changed = glibc.request();
    changed.source_directory = "other-directory".into();
    assert!(matches!(
        crate::build::execute_build(
            &valid,
            &changed,
            &store,
            &root,
            Path::new("/usr"),
            Path::new("/usr/bin/false")
        ),
        Err(crate::build::BuildError::UnsupportedInputs)
    ));
    let hello = valid
        .builds()
        .find(|build| build.package().as_str() == "hello")
        .unwrap();
    assert!(matches!(
        crate::build::execute_build(
            &valid,
            &hello.request(),
            &store,
            &root,
            Path::new("/usr"),
            Path::new("/usr/bin/false")
        ),
        Err(crate::build::BuildError::UnsupportedInputs)
    ));
    assert_eq!(
        valid
            .builds()
            .find(|build| build.package().as_str() == "hello")
            .unwrap()
            .inputs()[0]
            .package
            .as_str(),
        "glibc"
    );
    assert!(
        plan(&recipe.replace(
            "(project::glibc, \"dev\")",
            "(project::glibc, \"missing\")"
        ))
        .is_err()
    );
    let additional_reference = plan(&recipe.replace(
        "std::recipe_output(project::glibc, \"dev\")",
        "std::recipe_output(std::recipe_ref(project::catalog::glibc::recipe), \"dev\")",
    ));
    assert!(
        additional_reference.is_ok(),
        "{additional_reference:?}"
    );
}

#[test]
fn plan_is_deterministic_and_projects_values() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); value Text(str); struct Pair { left: Number; right: [Text]; } outputs { pair: Pair = Pair { left = 7; right = [\"a\", \"b\"]; }; }",
    );
    lock_project(&project.0).unwrap();
    let first = value_projection_plan(&project.0, &CheckConfiguration::default())
        .unwrap()
        .to_string();
    let plan = value_projection_plan(&project.0, &CheckConfiguration::default()).unwrap();
    let second = plan.to_string();
    assert_eq!(first, second);
    assert_eq!(plan.policy_identity(), "syrox.empty");
    assert_eq!(plan.lock_digest().len(), 32);
    assert!(plan.standard_library().is_none());
    assert_eq!(plan.packages().len(), 0);
    assert!(first.contains("lock sha256 "));
    assert!(first.contains("policy syrox.empty"));
    assert!(first.contains("std absent"));
    assert!(first.contains("left = 0:Number(7)"));
    assert!(first.contains("right = [0:Text(\"a\"), 0:Text(\"b\")]"));
}

#[test]
fn plan_extracts_only_exact_authenticated_package_roots_with_explicit_ids() {
    let mut source = recipe_graph_source(&[
        ("root_name_is_not_the_id", "app", &[]),
        ("z", "z", &[]),
        ("library_root", "lib", &[]),
    ]);
    source.push_str(r#"
        value FakeId(str); struct FakeDependency { package: FakeId; }
        struct Package { id: FakeId; dependencies: [FakeDependency]; }
        mod fake { mod impostor { pub fn make() -> Package { Package { id = "ignored"; dependencies = []; } } } }
        pub publish(fake, make): Package;
    "#);
    let plan = package_plan(&source).unwrap();

    let packages: Vec<_> = plan.packages().collect();
    assert_eq!(
        packages
            .iter()
            .map(|package| package.id().as_str())
            .collect::<Vec<_>>(),
        ["app", "lib", "z"]
    );
    assert_eq!(
        packages[0]
            .dependencies()
            .map(crate::plan::PlanPackageId::as_str)
            .collect::<Vec<_>>(),
        [] as [&str; 0]
    );
    let display = plan.to_string();
    assert!(display.contains("syrox plan\n"));
    assert!(display.contains("package dependency graph\npackages 3 edges 0"));
    assert!(display.find("package \"lib\"").unwrap() < display.find("root ").unwrap());
}

#[test]
fn acquisition_roots_are_pure_explicit_and_multi_source() {
    let digest = "0".repeat(64);
    let text = format!(
        r#"
        mod catalog {{
            mod aggregate {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "aggregate"; dependencies = []; }}; }} }} }}
            mod app {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "app"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{
                sources = [
                    std::SourceRequest {{ url = "file:///tmp/pinned.tar"; sha256 = "{digest}"; maximum_bytes = 0; }},
                    std::SourceRequest {{ url = "https://example.org/pinned.tar"; sha256 = "{digest}"; maximum_bytes = 1024; }},
                ];
            }}); }} }} }}
        }} pub publish(catalog, recipe): std::Recipe;
    "#
    );
    let plan = package_plan(&text).unwrap();
    assert_eq!(plan.packages().len(), 2);
    let acquisition = plan.acquisitions().next().unwrap();
    assert_eq!(acquisition.package().as_str(), "app");
    assert_eq!(acquisition.sources().len(), 2);
    assert_eq!(
        acquisition
            .sources()
            .next()
            .unwrap()
            .maximum_bytes(),
        0
    );
    assert!(
        plan.to_string()
            .contains("acquisition \"app\" sources 2")
    );
}

#[test]
fn plan_refuses_unowned_and_invalid_source_requests() {
    let missing = package_plan(
        r"outputs {
        request: std::Acquisition = std::Acquisition { sources = []; };
    }",
    )
    .unwrap_err();
    assert!(matches!(
        missing,
        ProjectOperationError::InvalidConsumerOutput { .. }
    ));

    let invalid = package_plan(&format!(r#"mod published {{ mod package {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "app"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [
            std::SourceRequest {{ url = "http://example.org/plain"; sha256 = "{}"; maximum_bytes = 1; }}
        ]; }}); }} }} }} }} pub publish(published, recipe): std::Recipe;"#, "0".repeat(64))).unwrap_err();
    assert!(matches!(
        invalid,
        ProjectOperationError::Plan(crate::plan::PlanError::InvalidSourceRequest { .. })
    ));
    let local_project = TempProject::new();
    local_project.write("assets/runtime.tar.gz", "a");
    local_project.write("main.srx", &format!(r#"mod published {{ mod package {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "app"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [
            std::SourceRequest {{ url = "project:assets/runtime.tar.gz"; sha256 = "{}"; maximum_bytes = 2048; }}
        ]; }}); }} }} }} }} pub publish(published, recipe): std::Recipe;"#, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"));
    let configuration = package_configuration();
    lock_project_with(&local_project.0, &configuration).unwrap();
    let local = plan_project_with(&local_project.0, &configuration).unwrap();
    assert_eq!(
        local
            .acquisitions()
            .next()
            .unwrap()
            .sources()
            .next()
            .unwrap()
            .url(),
        "project:assets/runtime.tar.gz"
    );
    let traversal = package_plan(&format!(
        r#"mod published {{ mod package {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "app"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [
            std::SourceRequest {{ url = "project:../outside.tar.gz"; sha256 = "{}"; maximum_bytes = 2048; }}
        ]; }}); }} }} }} }} pub publish(published, recipe): std::Recipe;"#,
        "0".repeat(64)
    ));
    assert!(matches!(
        traversal,
        Err(ProjectOperationError::Plan(
            crate::plan::PlanError::InvalidSourceRequest { .. }
        ))
    ));
}

#[test]
fn input_domain_package_lookalike_is_not_extracted() {
    let project = TempProject::new();
    project.write("main.srx", "inputs { fake = \"path:fake\"; }");
    project.write(
        "fake/package.srx",
        "value Id(str); struct Dependency { package: Id; } struct Package { id: Id; dependencies: [Dependency]; } outputs { lookalike: Package = Package { id = \"ignored\"; dependencies = []; }; }",
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(plan.packages().len(), 0);
}

#[test]
fn recipe_build_projection_preserves_package_generality_and_public_selection() {
    let plan = package_plan(&build_fixture()).unwrap();
    assert_eq!(plan.builds().len(), 1);
    let build = plan.builds().next().unwrap();
    assert_eq!(build.package().as_str(), "internal-app");
    assert_eq!(build.source_directory(), "app-1.0");
    assert_eq!(
        plan.packages()
            .find(|package| package.id() == build.package())
            .unwrap()
            .export(),
        Some("app")
    );
    assert!(
        plan.to_string()
            .contains("build \"internal-app\" protocol program")
    );
    // An ordinary project struct with the same spelling does not request a build.
    let lookalike = package_plan(
        "value Id(str); struct Build { package: Id; } outputs { fake: Build = Build { package = \"absent\"; }; }",
    );
    assert!(matches!(
        lookalike,
        Err(ProjectOperationError::InvalidConsumerOutput { .. })
    ));
}

#[test]
fn commands_project_names_outputs_paths_and_explicit_runtime_roles() {
    let command =
        r#"commands = [std::Command { name = "main"; output = "out"; path = "usr/bin/app"; }];"#;
    let source = build_fixture().replace("commands = [];", command);
    let plan = package_plan(&source).unwrap();
    let command = plan.commands().next().unwrap();
    assert_eq!(command.name(), "main");
    assert_eq!(command.output(), "out");
    assert_eq!(command.path(), "usr/bin/app");
    assert!(command.loader().is_none());
    for (from, to) in [
        (r#"name = "main""#, r#"name = "../escape""#),
        (r#"output = "out""#, r#"output = "missing""#),
        (
            r#"path = "usr/bin/app""#,
            r#"path = "/usr/bin/app""#,
        ),
        (
            r#"path = "usr/bin/app";"#,
            r#"path = "usr/bin/app"; libraries = [std::recipe_output(project::aggregate, "out")];"#,
        ),
    ] {
        assert!(matches!(
            package_plan(&source.replace(from, to)),
            Err(ProjectOperationError::Plan(
                crate::plan::PlanError::InvalidCommand { .. }
            ))
        ));
    }
    let self_library = source.replace(
        r#"path = "usr/bin/app";"#,
        r#"path = "usr/bin/app"; libraries = [std::recipe_output(project::app, "out")];"#,
    );
    assert_eq!(
        package_plan(&self_library)
            .unwrap()
            .commands()
            .next()
            .unwrap()
            .libraries()
            .len(),
        1
    );
    let multiple = source.replace(r#"path = "usr/bin/app"; }];"#, r#"path = "usr/bin/app"; }, std::Command { name = "admin"; output = "out"; path = "usr/bin/admin"; }];"#);
    assert_eq!(
        package_plan(&multiple).unwrap().commands().len(),
        2
    );
    assert!(package_plan(&multiple.replace(r#"name = "admin""#, r#"name = "main""#)).is_err());
}

#[test]
fn cancelled_realization_has_no_store_or_host_effects() {
    let project = TempProject::new();
    project.write("main.srx", &build_fixture());
    let checks = package_configuration();
    lock_project_with(&project.0, &checks).unwrap();
    let store = project.0.join("not-created");
    let user =
        crate::config::UserConfiguration::parse("[build]\nhost-toolchain='/usr'", store.clone())
            .unwrap();
    let selected = crate::realize::resolve_build(
        &format!("{}#app", project.0.display()),
        &user,
        &checks,
    )
    .unwrap();
    let cancellation = crate::cancellation::Cancellation::default();
    cancellation.cancel();
    let result = crate::realize::realize_build(
        &selected,
        crate::realize::RealizeOptions {
            configuration: &user,
            worker: Path::new("/absent-worker"),
            offline: true,
        },
        &cancellation,
        |_| panic!("no progress after pre-cancellation"),
    );
    assert!(matches!(
        result,
        Err(crate::realize::RealizeError::Cancelled)
    ));
    assert!(!store.exists());
}

#[test]
fn invalid_build_relationships_and_paths_fail_during_pure_planning() {
    for (from, to) in [
        (
            "source_directory = \"app-1.0\"",
            "source_directory = \"../escape\"",
        ),
        ("timeout_seconds = 30", "timeout_seconds = 1801"),
    ] {
        // Only replace the first package's dependencies; avoid an unrelated cycle.
        let text = build_fixture().replacen(from, to, 1);
        assert!(
            matches!(
                package_plan(&text),
                Err(ProjectOperationError::Plan(
                    crate::plan::PlanError::InvalidBuild { .. }
                ))
            ),
            "{text}"
        );
    }
}

#[test]
fn reference_package_chain_is_planned_iteratively() {
    let names: Vec<_> = (0..512)
        .map(|index| format!("p{index}"))
        .collect();
    let nodes: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let dependencies: Vec<&str> = if index == 0 {
                Vec::new()
            } else {
                vec![names[index - 1].as_str()]
            };
            (name.as_str(), name.as_str(), dependencies)
        })
        .collect();
    let borrowed: Vec<_> = nodes
        .iter()
        .map(|(name, id, dependencies)| (*name, *id, dependencies.as_slice()))
        .collect();
    let source = recipe_graph_source(&borrowed);
    let plan = package_plan(&source).unwrap();
    assert_eq!(plan.packages().len(), 512);
    assert_eq!(
        plan.packages().next().unwrap().id().as_str(),
        "p0"
    );
    assert_eq!(
        plan.packages().last().unwrap().id().as_str(),
        "p511"
    );
}

#[test]
fn explicit_selection_rejects_unpublished_packages_and_non_consumers_before_evaluation() {
    let project = TempProject::new();
    project.write("main.srx", "value Number(int); fn forever() -> Number { forever() } outputs { invalid: Number = forever(); }");
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    assert!(matches!(
        plan_project_with(&project.0, &config),
        Err(ProjectOperationError::InvalidConsumerOutput { .. })
    ));
    assert!(matches!(
        plan_project_outputs_with(&project.0, &config, &["invalid"]),
        Err(ProjectOperationError::InvalidConsumerOutput { .. })
    ));
    assert!(matches!(
        plan_project_package_with(&project.0, &config, "invalid"),
        Err(ProjectOperationError::MissingPackageReference { .. })
    ));
}

use super::*;

#[test]
fn reachable_diamond_keeps_homonyms_distinct_and_shared_instances_unique() {
    let source = recipe_graph_source(&[
        ("root", "root", &["left", "right"]),
        ("left", "same", &["leaf"]),
        ("right", "same", &["leaf"]),
        ("leaf", "leaf", &[]),
    ]);
    let project = TempProject::new();
    project.write("main.srx", &source);
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let locked = open_locked_project_with(&project.0, &config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    assert!(evaluation.select_package("root").unwrap());
    let plan = evaluation.into_selected_plan().unwrap();
    assert_eq!(plan.packages().len(), 4);
    let leaf = plan
        .packages()
        .find(|package| package.id().as_str() == "leaf")
        .unwrap();
    let branches: Vec<_> = plan
        .packages()
        .filter(|package| package.id().as_str() == "same")
        .collect();
    assert_eq!(branches.len(), 2);
    assert_ne!(branches[0].id(), branches[1].id());
    for branch in branches {
        assert_eq!(
            branch.dependencies().collect::<Vec<_>>(),
            [leaf.id()]
        );
    }
    let root = plan
        .packages()
        .find(|package| package.has_export("root"))
        .unwrap();
    let dependencies: Vec<_> = root.dependencies().collect();
    assert_eq!(dependencies.len(), 2);
    assert_ne!(dependencies[0], dependencies[1]);
    assert!(!plan.to_string().contains("MemoId"));
}

#[test]
fn homonymous_imported_builds_preserve_runtime_aliases_and_asset_origins() {
    let workspace = TempProject::new();
    let config = package_configuration();
    for name in ["left", "right"] {
        workspace.write(&format!("{name}/assets/source"), name);
        workspace.write(&format!("{name}/main.srx"), &format!(r#"
            mod catalog {{ mod selected {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{
                package = std::Package {{ id = "same"; dependencies = []; }};
                acquisition = std::Option::Some(std::Acquisition {{ sources = [std::source_request(
                    "project:assets/source", "{}", 100
                )]; }});
                build = std::Option::Some(std::Build {{ profile = std::BuildProfile::HostBootstrap;
                    source_directory = "{name}-1"; timeout_seconds = 60;
                 source_format = std::BuildSourceFormat::Xz; produces = ["dev", "out"]; steps = [std::BuildStep::Extract(std::BuildPath::Work("source"))]; }});
            }} }} }} }}
            pub publish(catalog, recipe): std::Recipe;
        "#, crate::store::ContentDigest::sha256(name.as_bytes())));
        lock_project_with(&workspace.0.join(name), &config).unwrap();
    }
    workspace.write("consumer/main.srx", r#"
        inputs { left = "path:../left"; right = "path:../right"; }
        mod catalog { mod app { pub fn recipe() -> std::Recipe { std::Recipe {
            package = std::Package { id = "same"; dependencies = []; };
            acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request(
                "https://example.test/app", "0000000000000000000000000000000000000000000000000000000000000000", 100
            )]; });
            build = std::Option::Some(std::autotools(std::BuildOptions {
                source_directory = "app-1"; timeout_seconds = 30;
            }));
            build_inputs = std::Option::Some(std::BuildInputs { selected = [std::recipe_output(left::selected, "dev")]; });
            commands = [std::Command { name = "main"; output = "out"; path = "usr/bin/app"; 
                loader = [std::RuntimeFile { output = std::recipe_output(left::selected, "out"); path = "usr/lib/ld-linux-x86-64.so.2"; }];
                libraries = [std::recipe_output(left::selected, "out")];
            }];
        } } } }
        pub publish(catalog, recipe): std::Recipe;
        mod catalog::alias { pub use project::catalog::app::recipe; }
        pub use right::selected;
    "#);
    let consumer = workspace.0.join("consumer");
    lock_project_with(&consumer, &config).unwrap();
    let prepared = prepare_project_with(&consumer, &config).unwrap();
    let plan = prepared.plan();
    assert_eq!(plan.packages().len(), 3);
    assert_eq!(plan.builds().len(), 3);
    assert!(
        plan.packages()
            .all(|package| package.id().as_str() == "same")
    );
    let app = plan
        .packages()
        .find(|package| package.has_export("app"))
        .unwrap();
    assert!(app.has_export("alias"));
    let application = plan.commands().next().unwrap();
    let loader = &application.loader().unwrap().output.package;
    let build = plan
        .builds()
        .find(|build| build.package() == app.id())
        .unwrap();
    assert_eq!(&build.inputs()[0].package, loader);
    assert_ne!(
        loader,
        plan.packages()
            .find(|package| package.has_export("selected"))
            .unwrap()
            .id()
    );
    for (directory, expected) in [("left-1", "left"), ("right-1", "right")] {
        let build = plan
            .builds()
            .find(|build| build.source_directory() == directory)
            .unwrap();
        let source = plan
            .acquisitions()
            .find(|source| source.package() == build.package())
            .unwrap()
            .sources()
            .next()
            .unwrap();
        assert_eq!(
            source.digest(),
            crate::store::ContentDigest::sha256(expected.as_bytes())
        );
        assert_eq!(
            fs::canonicalize(
                prepared
                    .project_root(source.owner().unwrap())
                    .unwrap()
            )
            .unwrap(),
            fs::canonicalize(workspace.0.join(expected)).unwrap()
        );
    }
    let user = crate::config::UserConfiguration::parse("", workspace.0.join("store")).unwrap();
    for key in ["app", "alias"] {
        let reference = format!("{}#{key}", consumer.display());
        let selected = crate::realize::resolve_build(&reference, &user, &config).unwrap();
        assert_eq!(selected.export(), key);
        assert_eq!(selected.description().package(), app.id());
        assert_eq!(
            crate::realize::resolve_command(&reference, Some("main"), &user, &config)
                .unwrap()
                .export(),
            key
        );
    }
    assert!(matches!(
        crate::realize::resolve_build(consumer.to_str().unwrap(), &user, &config),
        Err(crate::realize::RealizeError::MissingSelection)
    ));
    assert!(
        crate::realize::resolve_command(consumer.to_str().unwrap(), None, &user, &config).is_err()
    );
}

#[test]
fn duplicate_publications_are_rejected_without_evaluating_recursive_factories() {
    let project = TempProject::new();
    let source = r"
        mod catalog { mod key { pub fn recipe() -> std::Recipe { recipe() } } }
        pub publish(catalog, recipe): std::Recipe;
    ";
    let config = package_configuration();
    project.write("main.srx", source);
    lock_project_with(&project.0, &config).unwrap();
    let locked = open_locked_project_with(&project.0, &config).unwrap();
    assert_eq!(
        locked
            .evaluation()
            .unwrap()
            .catalog_names()
            .unwrap(),
        Some(vec!["key".into()])
    );
    project.write(
        "main.srx",
        &(source.to_owned() + "pub publish(catalog, recipe): std::Recipe;"),
    );
    assert!(lock_project_with(&project.0, &config).is_err());
}

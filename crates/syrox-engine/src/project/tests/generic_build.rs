use super::*;

fn source() -> String {
    r#"
        fn base() -> std::Build { std::Build { profile = std::BuildProfile::HostBootstrap;
            source_directory = "data"; timeout_seconds = 30;
            source_format = std::BuildSourceFormat::Raw; produces = ["doc", "out"];
            steps = [std::BuildStep::Write(std::BuildFile { path = std::BuildPath::Output("out", "data"); text = std::build_text("bytes"); })];
        } }
        fn acquisition() -> std::Acquisition { std::Acquisition { sources = [std::source_request("https://example.invalid/input", "0000000000000000000000000000000000000000000000000000000000000000", 1024)]; } }
        fn make_a() -> std::Recipe { std::Recipe { package = std::Package { id = "a"; dependencies = []; }; acquisition = std::Option::Some(acquisition()); build = std::Option::Some(base()); } }
        fn make_b() -> std::Recipe { std::Recipe { package = std::Package { id = "b"; dependencies = []; }; acquisition = std::Option::Some(acquisition()); build = std::Option::Some(base()); } }
        fn make_consumer() -> std::Recipe { std::Recipe {
            package = std::Package { id = "consumer"; dependencies = []; };
            acquisition = std::Option::Some(acquisition());
            build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "data"; timeout_seconds = 30; source_format = std::BuildSourceFormat::Raw;
                steps = [std::BuildStep::Copy(std::BuildPath::Input(0, "file"), std::BuildPath::Output("out", "copied")),
                    std::BuildStep::Copy(std::BuildPath::Input(1, "file"), std::BuildPath::Output("out", "other"))]; });
            build_inputs = std::Option::Some(std::BuildInputs { selected = [std::recipe_output(a, "doc"), std::recipe_output(b, "out")]; });
        } }
        mod factories {
            mod a { pub fn recipe() -> std::Recipe { project::make_a() } }
            mod b { pub fn recipe() -> std::Recipe { project::make_b() } }
            mod selected { pub fn recipe() -> std::Recipe { project::make_consumer() } }
        }
        pub publish(factories, recipe): std::Recipe;
    "#.into()
}

#[test]
fn arbitrary_named_build_inputs_resolve_without_runtime_or_builder_kinds() {
    let plan = package_plan(&source()).unwrap();
    let build = plan
        .builds()
        .find(|build| build.package().as_str() == "consumer")
        .unwrap();
    assert_eq!(
        build
            .inputs()
            .iter()
            .map(|input| (input.package.as_str(), input.output.as_str()))
            .collect::<Vec<_>>(),
        [("a", "doc"), ("b", "out")]
    );
    assert_eq!(plan.commands().len(), 0);
    for (from, to) in [
        ("Input(1,", "Input(2,"),
        (
            "recipe_output(a, \"doc\")",
            "recipe_output(a, \"absent\")",
        ),
    ] {
        assert!(matches!(
            package_plan(&source().replace(from, to)),
            Err(ProjectOperationError::Plan(
                crate::plan::PlanError::InvalidBuild { .. }
            ))
        ));
    }
}

#[test]
fn activation_consumers_resolve_typed_outputs_and_commands_in_one_selected_preparation() {
    let project = TempProject::new();
    let config = package_configuration();
    let source = source()
        .replace("fn make_a() -> std::Recipe { std::Recipe {", r#"fn make_a() -> std::Recipe { std::Recipe { commands = [std::Command { name = "main"; output = "out"; path = "usr/bin/app"; loader = []; libraries = []; }];"#)
        .replace("id = \"b\"", "id = \"a\"")
        + r#"
            outputs { configuration: std::Shell = std::Shell {
                pkgs = [std::select_output(a, "doc"), std::select_output(a, "doc"), std::select_output(b, "out"), std::select_command(a, "out", "main")]; services = [];
            }; }
        "#;
    project.write("main.srx", &source);
    lock_project_with(&project.0, &config).unwrap();
    let locked = open_locked_project_with(&project.0, &config).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    evaluation.evaluate_root("configuration").unwrap();
    let prepared = evaluation.into_prepared_plan().unwrap();
    drop(locked);
    let plan = prepared.plan();
    assert_eq!(plan.builds().len(), 2);
    let root = plan
        .roots()
        .find(|root| root.name() == "configuration")
        .unwrap();
    let crate::plan::PlanValue::Struct {
        fields,
        ..
    } = root.value()
    else {
        panic!("configuration");
    };
    let crate::plan::PlanValue::List {
        items,
        ..
    } = &fields[0].1
    else {
        panic!("selections");
    };
    let outputs: Vec<_> = items
        .iter()
        .map(|item| {
            let crate::plan::PlanValue::Struct {
                fields,
                ..
            } = item
            else {
                panic!("selection");
            };
            fields[0].1.clone()
        })
        .collect();
    let file = plan.output_reference(&outputs[0]).unwrap();
    assert_eq!(file, plan.output_reference(&outputs[1]).unwrap());
    let other = plan.output_reference(&outputs[2]).unwrap();
    assert_eq!(file.package.as_str(), other.package.as_str());
    assert_ne!(file.package, other.package);
    let service = &file.package;
    let app = crate::realize::resolve_plan_command(
        &prepared,
        &crate::plan::PlanCommandRef {
            package: service.clone(),
            name: "main".into(),
        },
    )
    .unwrap();
    assert_eq!(app.description().package(), service);
    assert!(
        crate::realize::resolve_plan_command(
            &prepared,
            &crate::plan::PlanCommandRef {
                package: other.package.clone(),
                name: "main".into()
            }
        )
        .is_err()
    );
    let selected = crate::realize::resolve_plan_output(&prepared, &file).unwrap();
    assert_eq!(selected.reference(), &file);
    assert_eq!(
        selected.build().unwrap().description().package(),
        &file.package
    );
    let missing = crate::plan::PlanOutputRef {
        output: "missing".into(),
        ..file.clone()
    };
    assert!(matches!(
        crate::realize::resolve_plan_output(&prepared, &missing),
        Err(crate::realize::RealizeError::MissingOutput(_))
    ));
    let mut impostor = outputs[0].clone();
    let crate::plan::PlanValue::Struct {
        ty: crate::plan::PlanType::Specialization {
            domain,
            ..
        },
        ..
    } = &mut impostor
    else {
        panic!("typed output");
    };
    *domain = SourceDomainId::project().as_u32();
    assert!(plan.output_reference(&impostor).is_none());
    let pure = plan.clone();
    drop(prepared);
    // Previously resolved selections retain the preparation; a pure Plan has no
    // authority to rebind itself to whichever project happens to occupy a path.
    project.write("main.srx", "broken syntax");
    assert_eq!(selected.reference().package, file.package);
    assert_eq!(pure.builds().len(), 2);
    assert!(prepare_project_with(&project.0, &config).is_err());
}

#[test]
fn build_input_cycles_are_rejected_before_effects() {
    let source = source().replace(r#"id = "a"; dependencies = []; }; acquisition"#, r#"id = "a"; dependencies = []; }; build_inputs = std::Option::Some(std::BuildInputs { selected = [std::recipe_output(b, "out")]; }); acquisition"#)
        .replace(r#"id = "b"; dependencies = []; }; acquisition"#, r#"id = "b"; dependencies = []; }; build_inputs = std::Option::Some(std::BuildInputs { selected = [std::recipe_output(a, "out")]; }); acquisition"#);
    assert!(matches!(
        package_plan(&source),
        Err(ProjectOperationError::Plan(
            crate::plan::PlanError::InvalidBuild {
                reason: "cyclic or too deep build inputs",
                ..
            }
        ))
    ));
}

#[test]
fn build_depth_limit_includes_previously_validated_prefixes() {
    use std::fmt::Write as _;
    let prelude = source();
    let mut source = prelude
        .split("fn make_a")
        .next()
        .unwrap()
        .to_owned();
    let mut outputs = String::from("mod factories {");
    for index in 0..129 {
        let input = if index == 0 {
            String::new()
        } else {
            format!(
                "build_inputs = std::Option::Some(std::BuildInputs {{ selected = [std::recipe_output(n{:03}, \"out\")]; }});",
                index - 1
            )
        };
        write!(source, "fn make_{index}() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = \"n{index:03}\"; dependencies = []; }}; acquisition = std::Option::Some(acquisition()); build = std::Option::Some(base()); {input} }} }}").unwrap();
        write!(
            outputs,
            "mod n{index:03} {{ pub fn recipe() -> std::Recipe {{ project::make_{index}() }} }}"
        )
        .unwrap();
    }
    source.push_str(&outputs);
    source.push_str("} pub publish(factories, recipe): std::Recipe;");
    let project = TempProject::new();
    project.write("main.srx", &source);
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    assert_eq!(
        plan_project_package_with(&project.0, &config, "n127")
            .unwrap()
            .builds()
            .len(),
        128
    );
    assert!(matches!(
        plan_project_package_with(&project.0, &config, "n128"),
        Err(ProjectOperationError::Plan(
            crate::plan::PlanError::InvalidBuild {
                reason: "cyclic or too deep build inputs",
                ..
            }
        ))
    ));
}

#[test]
fn one_recipe_declares_commands_in_distinct_outputs_and_data_needs_no_entry() {
    let data = package_plan(&source()).unwrap();
    assert_eq!(data.commands().len(), 0);
    let source = source().replace(
        "fn make_a() -> std::Recipe { std::Recipe {",
        r#"fn make_a() -> std::Recipe { std::Recipe {
            commands = [
                std::Command { name = "run"; output = "out"; path = "bin/app"; },
                std::Command { name = "admin"; output = "doc"; path = "bin/admin"; }
            ];"#,
    );
    let plan = package_plan(&source).unwrap();
    assert_eq!(
        plan.commands()
            .map(|command| (command.name(), command.output(), command.path()))
            .collect::<Vec<_>>(),
        [
            ("admin", "doc", "bin/admin"),
            ("run", "out", "bin/app")
        ]
    );
    assert!(package_plan(&source.replace("output = \"doc\"", "output = \"missing\"")).is_err());
}

#[test]
fn explicit_managed_profile_projects_declared_input_paths() {
    let plan = package_plan(&source().replace(
        "BuildProfile::HostBootstrap",
        "BuildProfile::Managed",
    ))
    .unwrap();
    assert!(
        plan.builds()
            .all(|build| build.program().profile == crate::build::BuildProfile::Managed)
    );
    let consumer = plan
        .builds()
        .find(|build| build.package().as_str() == "consumer")
        .unwrap();
    assert!(matches!(
        consumer.program().steps.first(),
        Some(crate::build::BuildStep::Copy {
            source: crate::build::BuildPath::Input {
                index: 0,
                ..
            },
            ..
        })
    ));
    assert!(plan.to_string().contains("profile managed"));
    let bootstrap = package_plan(&source()).unwrap();
    assert!(
        bootstrap
            .to_string()
            .contains("profile host-bootstrap")
    );
}

#[test]
fn build_profile_is_required_in_authored_builds() {
    let missing = source().replace("profile = std::BuildProfile::HostBootstrap;", "");
    assert!(package_plan(&missing).is_err());
}

#[test]
fn managed_profile_rejects_host_paths_nested_in_process_and_write_text() {
    let marker = "std::BuildStep::Copy(std::BuildPath::Input(0, \"file\"), std::BuildPath::Output(\"out\", \"copied\"))";
    for step in [
        r#"std::BuildStep::Write(std::BuildFile { path = std::BuildPath::Output("out", "copied"); text = std::build_join([std::BuildPart::Literal("prefix"), std::BuildPart::Path(std::BuildPath::Host("/usr/share/fixture-config"))]); })"#,
        r#"std::BuildStep::Run(std::BuildProcess { executable = std::BuildPath::Input(0, "bin/tool"); directory = std::BuildPath::Work(""); arguments = [std::build_path(std::BuildPath::Host("/usr/share/fixture-config"))]; })"#,
        r#"std::BuildStep::Run(std::BuildProcess { executable = std::BuildPath::Input(0, "bin/tool"); directory = std::BuildPath::Work(""); arguments = []; environment = [std::BuildEnv { name = "CONFIG"; text = std::build_path(std::BuildPath::Host("/usr/share/fixture-config")); }]; })"#,
    ] {
        let bootstrap = source().replace(marker, step);
        assert_ne!(bootstrap, source());
        assert!(
            package_plan(&bootstrap).is_ok(),
            "explicit host bootstrap fixture must remain valid"
        );
        let managed = bootstrap.replace(
            "BuildProfile::HostBootstrap",
            "BuildProfile::Managed",
        );
        assert!(matches!(
            package_plan(&managed),
            Err(ProjectOperationError::Plan(
                crate::plan::PlanError::InvalidBuild { .. }
            ))
        ));
    }
}

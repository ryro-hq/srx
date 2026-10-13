use super::*;

fn source() -> String {
    r#"
    fn provider() -> std::Recipe { std::Recipe {
        package = std::Package { id = "provider"; dependencies = []; };
        imported = std::Option::Some(std::ImportedResult {
            root = "bootstrap";
            manifest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            entries = [std::ImportedOutput { output = "out"; key = "compiler"; }];
        });
        commands = [std::Command { name = "cc"; output = "out"; path = "bin/cc"; }];
    } }
    fn consumer() -> std::Recipe { std::Recipe {
        package = std::Package { id = "consumer"; dependencies = []; };
        acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request("https://example.invalid/source", "0000000000000000000000000000000000000000000000000000000000000000", 1024)]; });
        build = std::Option::Some(std::Build { profile = std::BuildProfile::Managed;
            source_directory = "src"; timeout_seconds = 30; source_format = std::BuildSourceFormat::Raw;
            steps = [std::BuildStep::Copy(std::BuildPath::Input(0, "data"), std::BuildPath::Output("out", "data"))]; });
        build_inputs = std::Option::Some(std::BuildInputs { selected = [std::recipe_output(tools, "out")]; });
    } }
    mod factories {
        mod tools { pub fn recipe() -> std::Recipe { project::provider() } }
        mod selected { pub fn recipe() -> std::Recipe { project::consumer() } }
    }
    pub publish(factories, recipe): std::Recipe;
    outputs {
        shell: std::Shell = std::Shell { pkgs = [std::select_command(tools, "out", "cc")]; services = []; };
    }
    "#.into()
}

#[test]
fn imported_provider_projects_build_inputs_commands_and_consumers_without_store() {
    let plan = package_plan(&source()).unwrap();
    let imported = plan.imports().next().unwrap();
    assert_eq!(plan.imports().len(), 1);
    assert_eq!(imported.root().as_str(), "bootstrap");
    assert_eq!(imported.outputs().get("out").unwrap(), "compiler");
    assert_eq!(
        imported.manifest().to_string(),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    assert_eq!(plan.builds().len(), 1);
    let output = plan
        .named_output(imported.package(), "out")
        .unwrap();
    assert_eq!(plan.builds().next().unwrap().inputs(), &[output]);
    assert!(
        plan.named_output(imported.package(), "missing")
            .is_none()
    );
    assert_eq!(
        plan.commands().next().unwrap().package(),
        imported.package()
    );
    assert_eq!(plan.consumers().count(), 1);
    let display = plan.to_string();
    assert!(display.contains("imports 1\n"));
    assert!(display.contains("root \"bootstrap\" manifest 0123456789abcdef"));
    assert!(display.contains("output \"out\" key \"compiler\""));
}

#[test]
fn imported_declarations_reject_invalid_pins_roots_and_ambiguous_mappings() {
    let base = source();
    for (old, new) in [
        ("root = \"bootstrap\"", "root = \"../bootstrap\""),
        (
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "not-a-pin",
        ),
        ("key = \"compiler\"", "key = \"../compiler\""),
        (
            "entries = [std::ImportedOutput { output = \"out\"; key = \"compiler\"; }]",
            "entries = []",
        ),
        (
            "entries = [std::ImportedOutput { output = \"out\"; key = \"compiler\"; }]",
            "entries = [std::ImportedOutput { output = \"out\"; key = \"compiler\"; }, std::ImportedOutput { output = \"out\"; key = \"other\"; }]",
        ),
        (
            "entries = [std::ImportedOutput { output = \"out\"; key = \"compiler\"; }]",
            "entries = [std::ImportedOutput { output = \"out\"; key = \"compiler\"; }, std::ImportedOutput { output = \"dev\"; key = \"compiler\"; }]",
        ),
    ] {
        let altered = base.replacen(old, new, 1);
        assert_ne!(altered, base);
        assert!(
            matches!(
                package_plan(&altered),
                Err(ProjectOperationError::Plan(_))
            ),
            "{new}"
        );
    }
}

#[test]
fn imported_provider_cannot_also_acquire_build_or_select_build_inputs() {
    for component in [
        "acquisition = std::Option::Some(std::Acquisition { sources = []; });",
        "build = std::Option::Some(std::Build { profile = std::BuildProfile::Managed; source_directory = \"src\"; timeout_seconds = 30; steps = []; });",
        "build_inputs = std::Option::Some(std::BuildInputs { selected = []; });",
    ] {
        let source = source().replacen(
            "imported =",
            &format!("{component} imported ="),
            1,
        );
        let error = package_plan(&source).unwrap_err();
        assert!(
            matches!(
                error,
                ProjectOperationError::Plan(crate::plan::PlanError::InvalidRecipe { .. })
            ),
            "{error}"
        );
    }
}

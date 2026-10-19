use super::*;

#[test]
fn configuration_assets_use_the_callers_locked_project_and_retained_bytes() {
    let workspace = TempProject::new();
    workspace.write("child/main.srx", r#"pub fn configuration() -> std::ConfigText { std::files::read_text("assets/host.toml") }"#);
    workspace.write("child/assets/host.toml", "name = 'child'\n");
    workspace.write(
        "consumer/main.srx",
        r#"inputs { child = "path:../child"; }
        value Name(str); struct Host { name: Name; }
        outputs { selected: Host = std::toml::decode<Host>(child::configuration()); }
    "#,
    );
    workspace.write("consumer/assets/host.toml", "name = 'consumer'\n");
    let configuration = package_configuration();
    lock_project_with(&workspace.0.join("child"), &configuration).unwrap();
    lock_project_with(&workspace.0.join("consumer"), &configuration).unwrap();
    let locked = open_locked_project_with(&workspace.0.join("consumer"), &configuration).unwrap();
    // Evaluation uses the bytes that were authenticated, even if a later writer changes disk.
    workspace.write("child/assets/host.toml", "name = 'changed'\n");
    let mut evaluation = locked.evaluation().unwrap();
    let root = evaluation.evaluate_root("selected").unwrap();
    assert!(
        root.diagnostics().is_empty(),
        "{:?}",
        root.diagnostics()
    );
    let Some(syrox_lang::evaluator::Value::Struct {
        fields,
        ..
    }) = root.value()
    else {
        panic!();
    };
    assert!(
        matches!(&fields[0].1, syrox_lang::evaluator::Value::Nominal { value: syrox_lang::evaluator::PrimitiveValue::Str(s), .. } if s == "child")
    );
    assert!(open_locked_project_with(&workspace.0.join("consumer"), &configuration).is_err());
}

#[test]
fn configuration_asset_paths_cannot_escape_the_authenticated_inventory() {
    for path in [
        "../outside",
        "/etc/passwd",
        "assets/../main.srx",
        "assets/missing",
    ] {
        let workspace = TempProject::new();
        workspace.write(
            "main.srx",
            &format!("outputs {{ bad: std::ConfigText = std::files::read_text(\"{path}\"); }}"),
        );
        let configuration = package_configuration();
        lock_project_with(&workspace.0, &configuration).unwrap();
        let locked = open_locked_project_with(&workspace.0, &configuration).unwrap();
        let mut evaluation = locked.evaluation().unwrap();
        let root = evaluation.evaluate_root("bad").unwrap();
        assert!(root.value().is_none());
        assert!(
            root.diagnostics()
                .iter()
                .any(|d| d.message.contains("not authenticated"))
        );
    }
}

#[test]
fn asset_type_diagnostics_include_the_file_position_and_external_field_path() {
    let workspace = TempProject::new();
    workspace.write("main.srx", r#"value Name(str); struct Host { #[key("node-name")] nodeName: Name; }
        outputs { bad: Host = std::toml::decode<Host>(std::files::read_text("assets/host.toml")); }"#);
    workspace.write("assets/host.toml", "# host\nnode-name = 42\n");
    let configuration = package_configuration();
    lock_project_with(&workspace.0, &configuration).unwrap();
    let locked = open_locked_project_with(&workspace.0, &configuration).unwrap();
    let mut evaluation = locked.evaluation().unwrap();
    let root = evaluation.evaluate_root("bad").unwrap();
    assert!(
        root.diagnostics().iter().any(|d| d
            .message
            .contains("assets/host.toml:2:1: $.node-name")),
        "{:?}",
        root.diagnostics()
    );
}

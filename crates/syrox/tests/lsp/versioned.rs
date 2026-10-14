use super::*;

#[test]
fn version_changes_refresh_configuration_completion_and_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let declaration = r#"value S(str); pub struct Old { listen: S = "old"; } pub struct New { listen: S = "new"; proxyPass: S = "http://localhost"; } pub fn nginx() -> std::PackageRef<New> package("nginx", "2", "minimal", "linux-x86_64-gnu") { std::package_ref(std::recipe_ref(recipe), "2", "minimal", "linux-x86_64-gnu", "new", render_new) } pub fn old() -> std::PackageRef<Old> package("nginx", "1", "minimal", "linux-x86_64-gnu") { std::package_ref(std::recipe_ref(recipe), "1", "minimal", "linux-x86_64-gnu", "old", render_old) } fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = "nginx"; dependencies = []; }; } } fn render_new(settings: New) -> std::ConfigText { "" } fn render_old(settings: Old) -> std::ConfigText { "" } fn configure<C>(package: std::PackageRef<C>, settings: C) -> std::ConfigText { std::package_config(package, settings) } "#;
    let path = temp.path().join("main.srx");
    let text = format!(
        r#"{declaration} fn selected() {{ configure(nginx({{version = "2";}}), {{ }}); }}"#
    );
    std::fs::write(&path, &text).unwrap();
    let document = uri(&path);
    let mut client = Client::with_options(temp.path(), "utf-16", false, "bundled");
    client.open(&document, &text);
    for (version, selected, labels) in [
        (2, "2", vec!["listen", "proxyPass"]),
        (3, "1", vec!["listen"]),
    ] {
        let text = format!(
            r#"{declaration} fn selected() {{ configure(nginx({{version = "{selected}";}}), {{ }}); }}"#
        );
        client.notify("textDocument/didChange", json!({"textDocument":{"uri":document,"version":version},"contentChanges":[{"text":text}]}));
        let diagnostics = client.diagnostics(&document, version);
        assert!(
            diagnostics["params"]["diagnostics"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{diagnostics}"
        );
        let offset = text.rfind("{ }").unwrap() + 2;
        let response = client.request("textDocument/completion", json!({"textDocument":{"uri":document},"position":{"line":0,"character":text[..offset].encode_utf16().count()}}));
        let actual: Vec<_> = response["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["label"].as_str().unwrap())
            .collect();
        assert_eq!(actual, labels, "{response}");
    }
    let text = format!(
        r#"{declaration} fn selected() {{ configure(nginx({{version = "1";}}), {{ proxyPass = "http://localhost"; }}); }}"#
    );
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":4},"contentChanges":[{"text":text}]}),
    );
    let diagnostic = client.wait(|message| {
        message["method"] == "textDocument/publishDiagnostics"
            && message["params"]["version"] == 4
            && message["params"]["diagnostics"]
                .to_string()
                .contains("proxyPass")
    });
    assert!(
        diagnostic.to_string().contains("proxyPass"),
        "{diagnostic}"
    );
    client.stop();
}

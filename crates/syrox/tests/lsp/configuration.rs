use super::*;

#[test]
fn imported_configuration_patch_has_partial_completion_and_type_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("schemas")).unwrap();
    std::fs::write(temp.path().join("schemas/host.srx"), r#"pub value Name(str); pub value Port(int); pub struct Config { #[key("node-name")] nodeName: Name; port: Port; }"#).unwrap();
    let path = temp.path().join("main.srx");
    let text = r#"inputs { schemas = "modules:schemas"; } fn update(doc: std::yaml::Document<schemas::host::Config>) { std::yaml::patch(doc, { }); }"#;
    std::fs::write(&path, text).unwrap();
    let document = uri(&path);
    let mut client = Client::with_options(temp.path(), "utf-16", false, "bundled");
    client.open(&document, text);
    let diagnostics = client.diagnostics(&document, 1);
    assert!(
        diagnostics["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{diagnostics}"
    );
    let offset = text.rfind("{ }").unwrap() + 2;
    let response = client.request(
        "textDocument/completion",
        json!({"textDocument":{"uri":document},"position":{"line":0,"character":offset}}),
    );
    let labels: Vec<_> = response["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["nodeName", "port"], "{response}");
    let text = text.replace("{ }", "{ nodeName = 1; typo = 2; }");
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":text}]}),
    );
    let diagnostics = client.wait(|message| {
        message["method"] == "textDocument/publishDiagnostics"
            && message["params"]["version"] == 2
            && message["params"]["diagnostics"]
                .to_string()
                .contains("typo")
    });
    let diagnostics = diagnostics["params"]["diagnostics"].to_string();
    assert!(diagnostics.contains("typo"), "{diagnostics}");
    assert!(
        diagnostics.contains("struct field"),
        "{diagnostics}"
    );
    client.stop();
}

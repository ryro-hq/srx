use super::*;

#[test]
fn shared_editor_fixture_covers_configuration_and_published_recipes() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/editor-compat");
    let cases: Value =
        serde_json::from_slice(&std::fs::read(fixture.join("case.json")).unwrap()).unwrap();
    let temp = tempfile::tempdir().unwrap();
    for directory in ["schemas", "recipes"] {
        std::fs::create_dir(temp.path().join(directory)).unwrap();
    }
    for file in [
        "main.srx",
        "schemas/host.srx",
        "recipes/hello.srx",
    ] {
        std::fs::copy(
            fixture.join("project").join(file),
            temp.path().join(file),
        )
        .unwrap();
    }
    let path = temp.path().join("main.srx");
    let text = std::fs::read_to_string(&path).unwrap();
    let document = uri(&path);
    let at = |case: &str| {
        let marker = &cases[case];
        let start = text
            .find(marker["needle"].as_str().unwrap())
            .unwrap();
        let offset = usize::try_from(marker["offset"].as_u64().unwrap()).unwrap();
        let mut lines = text[..start + offset].split('\n');
        let character = lines.next_back().unwrap().encode_utf16().count();
        let line = lines.count();
        json!({"textDocument":{"uri":document},"position":{"line":line,"character":character}})
    };
    let mut client = Client::with_options(temp.path(), "utf-16", false, "bundled");
    client.open(&document, &text);
    let diagnostics = client.diagnostics(&document, 1);
    assert_eq!(diagnostics["params"]["diagnostics"], json!([]));

    let response = client.request("textDocument/completion", at("completion"));
    let labels: Vec<_> = response["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["label"].clone())
        .collect();
    assert_eq!(
        json!(labels),
        cases["completion"]["labels"],
        "{response}"
    );

    let definition = client.request("textDocument/definition", at("definition"));
    let recipe = temp
        .path()
        .join(cases["definition"]["file"].as_str().unwrap());
    assert_eq!(definition["result"]["uri"], uri(&recipe));
    let virtual_definition = client.request("textDocument/definition", at("virtualSource"));
    let virtual_uri = virtual_definition["result"]["uri"]
        .as_str()
        .unwrap();
    assert!(virtual_uri.starts_with("syrox-source:"));
    let source = client.request("syrox/readSource", json!({"uri":virtual_uri}));
    assert!(
        source["result"]["text"]
            .as_str()
            .unwrap()
            .contains(cases["virtualSource"]["text"].as_str().unwrap())
    );
    let format = client.request(
        "textDocument/formatting",
        json!({"textDocument":{"uri":document},"options":{"tabSize":4,"insertSpaces":true}}),
    );
    assert!(
        format["result"][0]["newText"]
            .as_str()
            .unwrap()
            .lines()
            .any(|line| line == cases["formattedLine"].as_str().unwrap()),
        "{format}"
    );

    let marker = &cases["diagnostic"];
    let broken = text.replace(
        marker["before"].as_str().unwrap(),
        marker["after"].as_str().unwrap(),
    );
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":broken}]}),
    );
    client.wait(|message| {
        message["method"] == "textDocument/publishDiagnostics"
            && message["params"]["version"] == 2
            && message["params"]["diagnostics"]
                .as_array()
                .is_some_and(|items| {
                    items.iter().any(|item| {
                        item["code"] == "srx.type-check"
                            && item["message"]
                                .as_str()
                                .unwrap()
                                .contains(marker["text"].as_str().unwrap())
                    })
                })
    });
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":3},"contentChanges":[{"text":text}]}),
    );
    assert_eq!(
        client.diagnostics(&document, 3)["params"]["diagnostics"],
        json!([])
    );
    client.stop();
}

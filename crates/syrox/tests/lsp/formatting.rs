use super::*;

#[test]
fn formatter_uses_overlay_preserves_literals_and_reports_utf16_full_range() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("main.srx");
    std::fs::write(&path, "invalid disk contents @").unwrap();
    let document = uri(&path);
    let original = "fn text()->Missing{\"😀\\n\"}// keep  two spaces";
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, original);
    let params =
        json!({"textDocument":{"uri":document},"options":{"tabSize":2,"insertSpaces":false}});
    let result = client.request("textDocument/formatting", params.clone());
    let edits = result["result"].as_array().unwrap();
    assert_eq!(edits.len(), 1);
    assert_eq!(
        edits[0]["range"]["end"],
        json!({"line":0,"character":original.encode_utf16().count()})
    );
    let formatted = edits[0]["newText"].as_str().unwrap();
    assert!(formatted.contains("\"😀\\n\""));
    assert!(formatted.contains("// keep  two spaces"));
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":formatted}]}),
    );
    assert_eq!(
        client.request("textDocument/formatting", params)["result"],
        json!([])
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "invalid disk contents @"
    );
    client.stop();
}

#[test]
fn invalid_and_virtual_documents_never_produce_partial_edits() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("main.srx");
    std::fs::write(&path, "fn broken(").unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-8");
    client.open(&document, "fn broken(");
    for document in [&document, "syrox-source://123/4/5.srx"] {
        assert_eq!(
            client.request(
                "textDocument/formatting",
                json!({"textDocument":{"uri":document},"options":{"tabSize":4,"insertSpaces":true}})
            )["result"],
            json!([])
        );
    }
    client.stop();
}

#[test]
fn shared_formatting_contract_matches_server_and_is_idempotent() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/lsp-contract.json"
    ))
    .unwrap();
    let contract = &contract["formatting"];
    let temp = tempfile::tempdir().unwrap();
    let document = uri(&temp.path().join("main.srx"));
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(
        &document,
        contract["example"]["source"].as_str().unwrap(),
    );
    let params =
        json!({"textDocument":{"uri":document},"options":{"tabSize":4,"insertSpaces":true}});
    let method = contract["request"].as_str().unwrap();
    let reply = client.request(method, params.clone());
    assert_eq!(
        reply["result"][0]["newText"],
        contract["example"]["formatted"]
    );
    client.notify("textDocument/didChange", json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":contract["example"]["formatted"]}]}));
    assert_eq!(
        client.request(method, params)["result"],
        json!([])
    );
    client.stop();
}

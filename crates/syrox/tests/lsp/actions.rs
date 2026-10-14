use super::*;

#[test]
fn syntax_actions_are_versioned_revalidated_and_never_echo_forged_edits() {
    let temp = tempfile::tempdir().unwrap();
    let text = "value S(str); outputs { name: S = S(\"😀\") }";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, text).unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, text);
    let published = client.diagnostics(&document, 1);
    let range = published["params"]["diagnostics"][0]["range"].clone();
    let actions = client.request(
        "textDocument/codeAction",
        json!({"textDocument":{"uri":document},"range":range,"context":{"diagnostics":[]}}),
    );
    let action = actions["result"][0].clone();
    assert_eq!(action["title"], "Insert `;`");
    let change = &action["edit"]["documentChanges"][0];
    assert_eq!(change["textDocument"]["version"], 1);
    assert_eq!(change["textDocument"]["uri"], document);
    assert_eq!(
        change["edits"][0]["range"]["start"],
        cursor(text, "}")
    );
    let mut forged = action.clone();
    forged["edit"] = json!({"changes":{"file:///somewhere":[{"newText":"forged"}]}});
    let resolved = client.request("codeAction/resolve", forged);
    assert_eq!(resolved["result"]["edit"], action["edit"]);
    let fixed = text.replace(" }", "; }");
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":fixed}]}),
    );
    client.diagnostics(&document, 2);
    assert_eq!(
        client.request("codeAction/resolve", action.clone())["error"]["code"],
        -32801
    );
    client.notify(
        "textDocument/didClose",
        json!({"textDocument":{"uri":document}}),
    );
    client.open(&document, text);
    assert_eq!(
        client.request("codeAction/resolve", action)["error"]["code"],
        -32801
    );
    let excluded = client.request("textDocument/codeAction", json!({"textDocument":{"uri":document},"range":range,"context":{"diagnostics":[],"only":["source.organizeImports"]}}));
    assert_eq!(excluded["result"], json!([]));
    assert_eq!(std::fs::read_to_string(path).unwrap(), text);
    client.stop();
}

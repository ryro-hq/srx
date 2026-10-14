use super::*;

#[test]
fn github_lock_reload_switches_read_only_virtual_definitions_offline() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let main = r#"inputs { remote = "github:example/fixture"; } fn selected() -> remote::N { remote::answer() }"#;
    let first = "pub value N(int); pub fn answer() -> N { N(1) }";
    let second = "pub value N(int); pub fn answer() -> N { N(2) }";
    let first_lock = github_fixture::prepare(root, main, first, '1');
    let second_lock = github_fixture::prepare(root, main, second, '2');
    std::fs::write(root.join("main.srx"), main).unwrap();
    std::fs::write(root.join("Syrox.lock"), &first_lock).unwrap();
    let document = uri(&root.join("main.srx"));
    let mut client = Client::with_watching(root, "utf-16", true);
    let registration = client.wait(|message| message["method"] == "client/registerCapability");
    client.send(&json!({"jsonrpc":"2.0","id":registration["id"],"result":null}));
    client.open(&document, main);
    client.diagnostics(&document, 1);
    assert_eq!(
        client.diagnostics(&document, 1)["params"]["diagnostics"],
        json!([])
    );
    let position = cursor(main, "remote::answer");
    let first_definition = client.request(
        "textDocument/definition",
        json!({"textDocument":{"uri":document},"position":position}),
    );
    let remote = first_definition["result"]["uri"]
        .as_str()
        .unwrap();
    assert!(remote.starts_with("syrox-source:"));
    let text = client.request("syrox/readSource", json!({"uri":remote}));
    assert_eq!(text["result"]["text"], first);
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":remote,"version":2},"contentChanges":[{"text":"invalid"}]}),
    );
    client.wait(|message| message["method"] == "window/logMessage");
    assert_eq!(
        client.request("syrox/readSource", json!({"uri":remote}))["result"]["text"],
        first
    );
    std::fs::write(root.join("Syrox.lock"), &second_lock).unwrap();
    client.notify(
        "workspace/didChangeWatchedFiles",
        json!({"changes":[{"uri":uri(&root.join("Syrox.lock")),"type":2}]}),
    );
    client.diagnostics(&document, 1);
    assert_eq!(
        client.diagnostics(&document, 1)["params"]["diagnostics"],
        json!([])
    );
    let definition = client.request(
        "textDocument/definition",
        json!({"textDocument":{"uri":document},"position":position}),
    );
    let updated = definition["result"]["uri"].as_str().unwrap();
    assert_ne!(remote, updated);
    assert_eq!(
        client.request("syrox/readSource", json!({"uri":updated}))["result"]["text"],
        second
    );
    assert_eq!(
        std::fs::read_to_string(root.join("Syrox.lock")).unwrap(),
        second_lock
    );
    client.stop();
}

#[test]
fn watched_modules_rebuild_the_graph_and_reapply_unsaved_buffers() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir(root.join("recipes")).unwrap();
    std::fs::write(
        root.join("recipes/one.srx"),
        "pub value I(int); pub fn make() -> I { I(1) }",
    )
    .unwrap();
    let text =
        "inputs { lib = \"modules:recipes\"; } fn use_it() -> lib::one::I { lib::one::make() }";
    std::fs::write(root.join("main.srx"), text).unwrap();
    let document = uri(&root.join("main.srx"));
    let mut client = Client::with_watching(root, "utf-16", true);
    let registration = client.wait(|message| message["method"] == "client/registerCapability");
    assert_eq!(
        registration["params"]["registrations"][0]["method"],
        "workspace/didChangeWatchedFiles"
    );
    client.send(&json!({"jsonrpc":"2.0","id":registration["id"],"result":null}));
    client.open(&document, text);
    client.diagnostics(&document, 1);
    client.diagnostics(&document, 1);
    let changed = text.replace("one::make", "two::make");
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":changed}]}),
    );
    client.diagnostics(&document, 2);
    assert!(
        !client.diagnostics(&document, 2)["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let added = root.join("recipes/two.srx");
    std::fs::write(&added, "pub fn make() -> one::I { one::I(2) }").unwrap();
    client.notify(
        "workspace/didChangeWatchedFiles",
        json!({"changes":[{"uri":uri(&added),"type":1}]}),
    );
    client.diagnostics(&document, 2);
    assert_eq!(
        client.diagnostics(&document, 2)["params"]["diagnostics"],
        json!([])
    );
    let definition = client.request(
        "textDocument/definition",
        json!({"textDocument":{"uri":document},"position":cursor(&changed,"lib::two::make")}),
    );
    assert_eq!(definition["result"]["uri"], uri(&added));
    assert_eq!(
        std::fs::read_to_string(root.join("main.srx")).unwrap(),
        text
    );
    client.stop();
}

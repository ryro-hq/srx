use super::*;

fn status(client: &Client, state: &str, generation: u64) -> Value {
    client.wait(|message| {
        message["method"] == "syrox/projectStatus"
            && message["params"]["state"] == state
            && message["params"]["generation"] == generation
    })["params"]
        .clone()
}

fn document<'a>(status: &'a Value, uri: &str) -> &'a Value {
    status["documents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|document| document["uri"] == uri)
        .expect("open document in status")
}

#[test]
fn status_tracks_versions_without_confusing_errors_or_unrelated_buffers_with_coverage() {
    let directory = tempfile::tempdir().unwrap();
    let main = "value N(int); fn answer() -> N { N(1) }";
    std::fs::write(directory.path().join("main.srx"), main).unwrap();
    let uri = uri(&directory.path().join("main.srx"));
    let mut client = Client::new(directory.path(), "utf-16");
    let initial = client.request("syrox/projectStatus", Value::Null)["result"].clone();
    assert_eq!(
        initial,
        json!({"revision":1,"generation":0,"state":"pending",
        "metadataTruncated":false,"lockObservation":null,"documents":[]})
    );
    client.open(&uri, main);
    let pending = status(&client, "pending", 1);
    assert_eq!(
        document(&pending, &uri),
        &json!({"uri":uri,"version":1,"coverage":"syntax"})
    );
    let ready = status(&client, "semantic", 1);
    assert_eq!(ready["lockObservation"], "missing");
    assert_eq!(document(&ready, &uri)["coverage"], "semantic");
    assert_eq!(
        client.request("syrox/projectStatus", json!({}))["result"],
        ready
    );

    client.open("untitled:outside-project", "fn external() {}");
    let ready = status(&client, "semantic", 2);
    assert_eq!(
        document(&ready, "untitled:outside-project")["coverage"],
        "syntax"
    );
    assert_eq!(document(&ready, &uri)["coverage"], "semantic");

    let invalid = "value N(int); fn answer() -> N { N(\"wrong\") }";
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":uri,"version":2},
        "contentChanges":[{"text":invalid}]}),
    );
    let pending = status(&client, "pending", 3);
    assert_eq!(
        document(&pending, &uri),
        &json!({"uri":uri,"version":2,"coverage":"syntax"})
    );
    // Scheduling diagnostics precede pending; the next diagnostics are semantic.
    assert!(
        !client.diagnostics(&uri, 2)["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let ready = status(&client, "semantic", 3);
    assert_eq!(document(&ready, &uri)["coverage"], "semantic");
    assert_eq!(document(&ready, &uri)["version"], 2);

    client.notify(
        "textDocument/didClose",
        json!({"textDocument":{"uri":uri}}),
    );
    let ready = status(&client, "semantic", 4);
    assert_eq!(
        ready["documents"],
        json!([{ "uri":"untitled:outside-project", "version":1,"coverage":"syntax" }])
    );
    client.open(&uri, main);
    let ready = status(&client, "semantic", 5);
    assert_eq!(document(&ready, &uri)["version"], 1);
    assert_eq!(document(&ready, &uri)["coverage"], "semantic");
    client.stop();
}

#[test]
fn unavailable_graph_reports_syntax_and_recovers_after_explicit_reload() {
    let directory = tempfile::tempdir().unwrap();
    let main = "inputs { dep = \"path:./missing\"; } fn answer() {}";
    std::fs::write(directory.path().join("main.srx"), main).unwrap();
    let uri = uri(&directory.path().join("main.srx"));
    let mut client = Client::new(directory.path(), "utf-16");
    client.open(&uri, main);
    let unavailable = status(&client, "unavailable", 1);
    assert_eq!(unavailable["lockObservation"], Value::Null);
    assert_eq!(document(&unavailable, &uri)["coverage"], "syntax");
    assert_eq!(
        client.request("syrox/projectStatus", json!({}))["result"],
        unavailable
    );
    assert!(!directory.path().join("Syrox.lock").exists());
    std::fs::create_dir(directory.path().join("missing")).unwrap();
    std::fs::write(
        directory.path().join("missing/main.srx"),
        "pub fn loaded() {}",
    )
    .unwrap();
    client.notify(
        "workspace/didChangeWatchedFiles",
        json!({"changes":[{
            "uri":uri,"type":2
        }]}),
    );
    // A semantic request is the existing barrier used by the external clients.
    let symbols = client.request(
        "textDocument/documentSymbol",
        json!({"textDocument":{"uri":uri}}),
    );
    assert_eq!(symbols["result"][0]["name"], "answer");
    let ready = client.request("syrox/projectStatus", json!({}));
    assert_eq!(ready["result"]["state"], "semantic");
    assert_eq!(ready["result"]["generation"], 2);
    assert_eq!(ready["result"]["lockObservation"], "missing");
    client.stop();
}

#[test]
fn status_observes_lock_drift_without_rewriting_lock_or_rejecting_editor_analysis() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("main.srx");
    let original = "value N(int); outputs { answer: N = N(1); }";
    std::fs::write(&path, original).unwrap();
    let locked = Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(["--std", "none", "project", "lock"])
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    let lock = std::fs::read(directory.path().join("Syrox.lock")).unwrap();
    let uri = uri(&path);
    let mut client = Client::new(directory.path(), "utf-16");
    client.open(&uri, original);
    assert_eq!(
        status(&client, "semantic", 1)["lockObservation"],
        "current"
    );

    let changed = original.replace("N(1)", "N(2)");
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":uri,"version":2},
        "contentChanges":[{"text":changed}]}),
    );
    // Lock observation describes loaded disk inputs, not unsaved buffers.
    assert_eq!(
        status(&client, "semantic", 2)["lockObservation"],
        "current"
    );
    std::fs::write(&path, changed).unwrap();
    client.notify(
        "textDocument/didSave",
        json!({"textDocument":{"uri":uri}}),
    );
    let ready = status(&client, "semantic", 3);
    assert_eq!(ready["lockObservation"], "stale");
    assert_eq!(document(&ready, &uri)["coverage"], "semantic");
    assert_eq!(
        std::fs::read(directory.path().join("Syrox.lock")).unwrap(),
        lock
    );
    client.stop();
}

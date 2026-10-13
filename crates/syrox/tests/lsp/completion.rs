use super::*;

#[test]
fn project_completion_uses_the_module_owner_and_updates_after_an_edit() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("recipes")).unwrap();
    let root = "inputs { recipes = \"modules:recipes\"; } pub publish(recipes, recipe): std::Recipe; fn selected() -> std::RecipeRef<std::Recipe> { project::glibc }";
    let child = "pub fn recipe() -> std::Recipe { std::recipe_value(project::glibc) }";
    std::fs::write(temp.path().join("main.srx"), root).unwrap();
    std::fs::write(temp.path().join("recipes/hello.srx"), child).unwrap();
    std::fs::write(temp.path().join("recipes/glibc.srx"), "pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = \"glibc\"; dependencies = []; }; } }").unwrap();
    let mut client = Client::with_options(temp.path(), "utf-16", false, "bundled");
    for (file, text) in [
        ("main.srx", root),
        ("recipes/hello.srx", child),
    ] {
        let document = uri(&temp.path().join(file));
        client.open(&document, text);
        let response = client.request(
            "textDocument/completion",
            at(&document, text, "project::", "project::".len()),
        );
        let items = response["result"]["items"].as_array().unwrap();
        for expected in ["glibc", "hello"] {
            assert!(
                items.iter().any(|item| item["label"] == expected),
                "{response}"
            );
        }
        let edited = text.replace("project::glibc", "project::gl");
        client.notify(
            "textDocument/didChange",
            json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":edited}]}),
        );
        let response = client.request(
            "textDocument/completion",
            at(
                &document,
                &edited,
                "project::gl",
                "project::gl".len(),
            ),
        );
        assert!(
            response["result"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["label"] == "glibc"),
            "{response}"
        );
    }
    client.stop();
}

#[test]
fn completion_requested_immediately_after_typing_waits_for_semantic_classification() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("main.srx");
    let text = "fn example() {}";
    std::fs::write(&path, text).unwrap();
    let document = uri(&path);
    let mut client = Client::with_options(temp.path(), "utf-16", false, "bundled");
    client.open(&document, text);
    let changed = "fn example() { std::map_from_en; }";
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":changed}]}),
    );
    let result = client.request(
        "textDocument/completion",
        at(
            &document,
            changed,
            "std::map_from_en",
            "std::map_from_en".len(),
        ),
    );
    let item = result["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["label"] == "map_from_entries")
        .expect("semantic function candidate after edit");
    assert_eq!(
        item["kind"], 3,
        "Function, not a plain text completion"
    );
    assert!(item["detail"].as_str().unwrap().contains("fn("));
    client.stop();
}

fn at(document: &str, text: &str, needle: &str, delta: usize) -> Value {
    let offset = text.find(needle).unwrap() + delta;
    json!({"textDocument":{"uri":document},"position":{"line":0,"character":text[..offset].encode_utf16().count()}})
}

#[test]
fn completion_respects_interfaces_aliases_and_lexical_locals() {
    let temp = tempfile::tempdir().unwrap();
    let text = "value I(int); mod lib { outputs {} fn hidden() {} pub fn make() {} } use lib::make; fn example(arg: I) { let prior = I(1); prior; let later = I(2); lib::make(); }";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, text).unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, text);
    client.diagnostics(&document, 1);
    client.diagnostics(&document, 1);
    let qualified = client.request(
        "textDocument/completion",
        at(&document, text, "lib::make();", 5),
    );
    let labels: Vec<_> = qualified["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["make"]);
    let local = client.request(
        "textDocument/completion",
        at(&document, text, "prior;", 0),
    );
    let labels: Vec<_> = local["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["label"].as_str().unwrap())
        .collect();
    assert!(labels.contains(&"arg"), "{local}");
    assert!(labels.contains(&"prior"));
    assert!(!labels.contains(&"later"));
    assert!(labels.contains(&"make"));
    client.stop();
}

#[test]
fn signature_help_survives_incomplete_calls_and_counts_nested_arguments() {
    let temp = tempfile::tempdir().unwrap();
    let text = "value I(int); fn choose(first: I, second: I) -> I { second } fn run() -> I { choose(I(1), I(2)) }";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, text).unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, text);
    client.diagnostics(&document, 1);
    client.diagnostics(&document, 1);
    let help = client.request(
        "textDocument/signatureHelp",
        at(&document, text, "I(2)", 0),
    );
    assert_eq!(help["result"]["activeParameter"], 1, "{help}");
    assert_eq!(
        help["result"]["signatures"][0]["parameters"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        help["result"]["signatures"][0]["parameters"][1]["label"],
        "second: I"
    );
    let changed = text.replace("choose(I(1), I(2))", "choose(I(1), ");
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":changed}]}),
    );
    client.diagnostics(&document, 2);
    client.diagnostics(&document, 2);
    let help = client.request(
        "textDocument/signatureHelp",
        at(
            &document,
            &changed,
            "choose(I(1), ",
            "choose(I(1), ".len(),
        ),
    );
    assert_eq!(help["result"]["activeParameter"], 1, "{help}");
    client.stop();
}

#[test]
fn completion_handles_an_incomplete_namespace_after_unicode_text() {
    let temp = tempfile::tempdir().unwrap();
    let text = "value S(str); mod lib { pub fn make() {} } fn run() { S(\"😀\"); lib::make(); }";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, text).unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, text);
    client.diagnostics(&document, 1);
    client.diagnostics(&document, 1);
    let changed = text.replace("lib::make();", "lib::");
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":changed}]}),
    );
    client.diagnostics(&document, 2);
    client.diagnostics(&document, 2);
    let params = at(&document, &changed, "lib::", 5);
    let response = client.request("textDocument/completion", params.clone());
    let item = &response["result"]["items"][0];
    assert_eq!(item["label"], "make");
    assert_eq!(
        item["textEdit"]["range"]["start"],
        params["position"]
    );
    assert_eq!(
        item["textEdit"]["range"]["end"],
        params["position"]
    );
    client.stop();
}

#[test]
fn std_definitions_are_read_only_revisioned_virtual_sources() {
    let temp = tempfile::tempdir().unwrap();
    let text = "fn example() -> std::PackageId { std::PackageId(\"hello\") }";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, text).unwrap();
    let document = uri(&path);
    let mut client = Client::with_options(temp.path(), "utf-16", false, "bundled");
    client.open(&document, text);
    client.diagnostics(&document, 1);
    client.diagnostics(&document, 1);
    let definition = client.request(
        "textDocument/definition",
        at(&document, text, "std::PackageId", 0),
    );
    let virtual_uri = definition["result"]["uri"]
        .as_str()
        .expect("std definition URI");
    assert!(virtual_uri.starts_with("syrox-source:"));
    let content = client.request("syrox/readSource", json!({"uri":virtual_uri}));
    assert!(
        content["result"]["text"]
            .as_str()
            .unwrap()
            .contains("PackageId")
    );
    assert_eq!(
        client.request(
            "syrox/readSource",
            json!({"uri":"file:///etc/passwd"})
        )["error"]["code"],
        -32602
    );
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":text}]}),
    );
    client.diagnostics(&document, 2);
    client.diagnostics(&document, 2);
    assert_eq!(
        client.request("syrox/readSource", json!({"uri":virtual_uri}))["error"]["code"],
        -32602
    );
    client.stop();
}

#[test]
fn published_members_use_factory_navigation_and_legacy_std_is_absent() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/lsp-contract.json"
    ))
    .unwrap();
    let contract = &contract["publication"];
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("recipes")).unwrap();
    let factory = temp
        .path()
        .join(contract["factoryPath"].as_str().unwrap());
    std::fs::write(&factory, contract["factory"].as_str().unwrap()).unwrap();
    let text = contract["main"].as_str().unwrap();
    let path = temp.path().join("main.srx");
    std::fs::write(&path, text).unwrap();
    let document = uri(&path);
    let mut client = Client::with_options(temp.path(), "utf-16", false, "bundled");
    client.open(&document, text);
    client.diagnostics(&document, 1);
    client.diagnostics(&document, 1);
    let position = at(
        &document,
        text,
        contract["reference"].as_str().unwrap(),
        "project::".len(),
    );
    let definition = client.request("textDocument/definition", position.clone());
    assert_eq!(
        definition["result"]["uri"],
        uri(&factory),
        "{definition}"
    );
    let hover = client.request("textDocument/hover", position.clone());
    assert!(
        hover["result"].to_string().contains("RecipeRef"),
        "{hover}"
    );
    let completions = client.request("textDocument/completion", position);
    assert!(
        completions["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["label"] == contract["member"]),
        "{completions}"
    );
    let std = client.request(
        "textDocument/completion",
        at(&document, text, "std::Recipe;", "std::".len()),
    );
    let items = std["result"]["items"].as_array().unwrap();
    assert!(
        items.iter().any(|item| item["label"] == "Recipe"),
        "{std}"
    );
    for legacy in contract["legacyStdAbsent"].as_array().unwrap() {
        assert!(
            !items.iter().any(|item| &item["label"] == legacy),
            "{std}"
        );
    }
    client.stop();
}

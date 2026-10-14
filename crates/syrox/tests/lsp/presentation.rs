use super::*;

#[test]
fn hint_ranges_past_eof_support_editor_whole_document_requests() {
    let temp = tempfile::tempdir().unwrap();
    let text = "value S(str); fn f() { let message = S(\"é😀\"); }";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, text).unwrap();
    let document = uri(&path);
    for encoding in ["utf-8", "utf-16"] {
        let mut client = Client::new(temp.path(), encoding);
        client.open(&document, text);
        for end in [
            json!({"line":0,"character":2_147_483_647}),
            json!({"line":1,"character":0}),
        ] {
            let response = client.request("textDocument/inlayHint",json!({"textDocument":{"uri":document},"range":{"start":{"line":0,"character":0},"end":end}}));
            assert!(
                response["result"]
                    .as_array()
                    .is_some_and(|hints| hints.iter().any(|hint| hint["label"] == ": S")),
                "{response}"
            );
        }
        client.stop();
    }
}

#[test]
fn hints_negotiate_resolution_reject_old_revisions_and_hide_invalid_inference() {
    for (encoding, lazy) in [("utf-8", false), ("utf-16", true)] {
        let temp = tempfile::tempdir().unwrap();
        let text = "value I(int); fn run() { let unicode = \"é😀\"; let valid = I(1); let invalid = I(\"wrong\"); let propagated = invalid; }";
        let path = temp.path().join("main.srx");
        std::fs::write(&path, text).unwrap();
        let uri = uri(&path);
        let mut client = Client::with_hint_resolution(temp.path(), encoding, false, "none", lazy);
        client.open(&uri, text);
        let length = if encoding == "utf-8" {
            text.len()
        } else {
            text.encode_utf16().count()
        };
        let query = json!({"textDocument":{"uri":uri},"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":length}}});
        let response = client.request("textDocument/inlayHint", query.clone());
        let hints = response["result"].as_array().unwrap();
        assert_eq!(hints.len(), 2, "{response}");
        let hint = hints
            .iter()
            .find(|hint| hint["label"] == ": I")
            .unwrap();
        assert_eq!(hint.get("tooltip").is_none(), lazy);
        let byte = text.find("valid =").unwrap() + "valid".len();
        let expected = if encoding == "utf-8" {
            byte
        } else {
            text[..byte].encode_utf16().count()
        };
        assert_eq!(hint["position"]["character"], expected);
        let mut supplied = hint.clone();
        supplied["textEdits"] = json!([{"newText":"forged edit"}]);
        supplied["tooltip"] = json!("forged tooltip");
        let resolved = client.request("inlayHint/resolve", supplied);
        assert_eq!(resolved["result"]["label"], hint["label"]);
        assert!(resolved["result"]["textEdits"].is_null());
        assert!(
            resolved["result"]["tooltip"]
                .as_str()
                .unwrap()
                .contains("Reusable")
        );
        client.notify(
            "textDocument/didChange",
            json!({"textDocument":{"uri":uri,"version":2},"contentChanges":[{"text":text}]}),
        );
        assert_eq!(
            client.request("inlayHint/resolve", hint.clone())["error"]["code"],
            -32801
        );
        let refreshed = client.request("textDocument/inlayHint", query);
        assert_eq!(refreshed["result"][0]["data"]["version"], 2);
        client.stop();
    }
}

#[test]
fn hints_tokens_navigation_and_function_value_signatures_use_checked_facts() {
    let temp = tempfile::tempdir().unwrap();
    let text = "value I(int); struct Box<T> { field: T; } enum Maybe<T> { None, Some(T) } fn identity<T>(item: T) -> T { item } fn inspect(boxed: Box<I>, input: Maybe<I>) -> I { let inferred = identity(I(7)); let callback = identity<I>; callback(inferred); match input { Some(payload) => boxed.field, None => inferred } }";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, text).unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, text);
    let hints = client.request("textDocument/inlayHint",json!({"textDocument":{"uri":document},"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":text.len()}}}));
    let hints = hints["result"]
        .as_array()
        .expect("inlay hint list");
    assert!(hints.iter().any(|hint| hint["label"] == ": I"));
    assert!(
        hints
            .iter()
            .any(|hint| hint["label"] == ": fn(I) -> I")
    );
    assert!(
        hints
            .iter()
            .any(|hint| hint["label"][0]["value"] == "item:")
    );
    let tokens = client.request(
        "textDocument/semanticTokens/full",
        json!({"textDocument":{"uri":document}}),
    );
    let data = tokens["result"]["data"].as_array().unwrap();
    let mut character = 0;
    let mut typed_function = false;
    for token in data.as_chunks::<5>().0 {
        assert_eq!(token[0], 0);
        character += token[1].as_u64().unwrap();
        if usize::try_from(character).unwrap() == text.find("identity(I(7))").unwrap() {
            typed_function = token[3] == 5;
        }
    }
    assert!(
        typed_function,
        "resolved function has a function semantic token"
    );
    let mut params = json!({"textDocument":{"uri":document},"position":cursor(text,"inferred =")});
    let hover = client.request("textDocument/hover", params.clone());
    assert!(
        hover["result"]["contents"]["value"]
            .as_str()
            .unwrap()
            .contains("inferred: I")
    );
    params["context"] = json!({"includeDeclaration":true});
    assert_eq!(
        client.request("textDocument/references", params)["result"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let field = text.find("boxed.field").unwrap() + "boxed.".len();
    let definition = client.request(
        "textDocument/definition",
        json!({"textDocument":{"uri":document},"position":{"line":0,"character":field}}),
    );
    assert_eq!(
        definition["result"]["range"]["start"]["character"],
        text.find("field: T").unwrap()
    );
    let signature = client.request("textDocument/signatureHelp",json!({"textDocument":{"uri":document},"position":{"line":0,"character":text.find("callback(inferred)").unwrap()+"callback(".len()}}));
    assert_eq!(
        signature["result"]["signatures"][0]["label"],
        "callback(I) -> I"
    );
    let changed = text.replace("boxed.field", "boxed.fi");
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":changed}]}),
    );
    let field = changed.find("boxed.fi").unwrap() + "boxed.fi".len();
    let completion = client.request(
        "textDocument/completion",
        json!({"textDocument":{"uri":document},"position":{"line":0,"character":field}}),
    );
    assert!(
        completion["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["label"] == "field" && item["detail"] == "I")
    );
    client.stop();
}

#[test]
fn incomplete_bodies_keep_local_hints_and_opaque_fields_are_not_suggested() {
    let temp = tempfile::tempdir().unwrap();
    let original = "value I(int); mod vault { pub opaque struct Secret { hidden: I; } } fn run(secret: vault::Secret) { let previous = I(1); }";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, original).unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, original);
    let changed = original.replace(
        "let previous = I(1);",
        "let previous = I(1); secret.",
    );
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":changed}]}),
    );
    let result = client.request("textDocument/completion",json!({"textDocument":{"uri":document},"position":{"line":0,"character":changed.find("secret.").unwrap()+7}}));
    assert_eq!(result["result"]["items"], json!([]));
    let hints = client.request("textDocument/inlayHint",json!({"textDocument":{"uri":document},"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":changed.len()}}}));
    assert!(
        hints["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hint| hint["label"] == ": I")
    );
    client.stop();
}

use super::*;

fn complete(client: &mut Client, document: &str, text: &str, needle: &str) -> Value {
    let offset = text.find(needle).unwrap() + needle.len();
    client.request("textDocument/completion",json!({"textDocument":{"uri":document},"position":{"line":0,"character":text[..offset].encode_utf16().count()}}))["result"].clone()
}

#[test]
fn recovered_suffix_and_interpolation_complete_checked_fields_with_exact_edits() {
    let temp = tempfile::tempdir().unwrap();
    let base = "value S(str); struct Box<T> { field: T; } mod vault { pub opaque struct Secret { hidden: S; } } fn inspect(boxed: Box<S>, secret: vault::Secret) { let broken = ; let later = boxed; let text = \"é😀 ${later.fi}\"; }";
    let path = temp.path().join("main.srx");
    std::fs::write(
        &path,
        base.replace("let broken = ;", "")
            .replace("${later.fi}", "${later.field}"),
    )
    .unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, base);
    let response = complete(&mut client, &document, base, "${later.fi");
    let field = response["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["label"] == "field")
        .unwrap();
    assert_eq!(field["detail"], "S");
    let start = base.find("later.fi").unwrap() + "later.".len();
    assert_eq!(
        field["textEdit"]["range"]["start"]["character"],
        base[..start].encode_utf16().count()
    );
    assert_eq!(
        field["textEdit"]["range"]["end"]["character"],
        base[..start + 2].encode_utf16().count()
    );
    for (version, replacement, needle, expected) in [
        (2, "${lat}", "${lat", Some("later")),
        (3, "\\${later.fi}", "later.fi", None),
        (4, "${secret.hi}", "secret.hi", None),
        (5, "literal later.fi", "later.fi", None),
        (6, "${later.}", "${later.", Some("field")),
    ] {
        let changed = base.replace("${later.fi}", replacement);
        client.notify("textDocument/didChange",json!({"textDocument":{"uri":document,"version":version},"contentChanges":[{"text":changed}]}));
        let response = complete(&mut client, &document, &changed, needle);
        let items = response["items"].as_array().unwrap();
        if let Some(label) = expected {
            assert!(
                items.iter().any(|item| item["label"] == label),
                "{response}"
            );
        } else {
            assert!(items.is_empty(), "{response}");
        }
    }
    client.stop();
}

#[test]
fn projection_completion_handles_calls_and_parentheses_before_a_field_name_exists() {
    let temp = tempfile::tempdir().unwrap();
    let base = "value S(str); struct Box<T> { field: T; } fn make() -> Box<S> { Box<S> { field = S(\"ok\"); } } fn inspect(boxed: Box<S>) { make().; }";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, base.replace("make().;", "make();")).unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, base);
    for (index, receiver) in ["make()", "(boxed)"].into_iter().enumerate() {
        let changed = base.replace("make().;", &format!("{receiver}.;"));
        client.notify("textDocument/didChange",json!({"textDocument":{"uri":document,"version":index+2},"contentChanges":[{"text":changed}]}));
        let response = complete(
            &mut client,
            &document,
            &changed,
            &format!("{receiver}."),
        );
        assert!(
            response["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["label"] == "field" && item["detail"] == "S"),
            "{response}"
        );
    }
    client.stop();
}

#[test]
fn type_context_keeps_type_parameters_and_types_despite_value_shadowing() {
    let temp = tempfile::tempdir().unwrap();
    let text = "value S(str); fn helper() {} fn inspect<T>(S: S) { let chosen:  = ; }";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, text.replace("let chosen:  = ;", "")).unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, text);
    let response = complete(&mut client, &document, text, "chosen: ");
    let items = response["items"].as_array().unwrap();
    assert!(
        items
            .iter()
            .any(|item| item["label"] == "S" && item["kind"] != 6),
        "{response}"
    );
    assert!(
        items
            .iter()
            .any(|item| item["label"] == "T" && item["kind"] == 25),
        "{response}"
    );
    assert!(
        !items.iter().any(|item| item["label"] == "helper"),
        "{response}"
    );
    client.stop();
}

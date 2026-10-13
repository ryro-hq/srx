use super::*;

fn complete(client: &mut Client, uri: &str, text: &str, needle: &str) -> Value {
    let offset = text.rfind(needle).unwrap() + needle.len();
    client.request("textDocument/completion",json!({"textDocument":{"uri":uri},"position":{"line":0,"character":text[..offset].encode_utf16().count()}}))["result"].clone()
}

#[test]
fn constructors_complete_missing_specialized_fields_and_defaults_without_duplicates() {
    let temp = tempfile::tempdir().unwrap();
    let declarations = "value S(str); struct Box<T> { first: T; second: T; optional: S = S(\"default\"); } fn inspect() { ";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, format!("{declarations}}}")).unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, &format!("{declarations}}}"));
    for (index, body, needle, labels) in [
        (
            0,
            "let b = Box<S> {  }; }",
            "Box<S> { ",
            vec!["first", "second", "optional"],
        ),
        (
            1,
            "let b = Box<S> { first = S(\"é😀\"); se }; }",
            " se",
            vec!["second"],
        ),
        (
            2,
            "let b = Box<S> {  first = S(\"ok\"); }; }",
            "Box<S> { ",
            vec!["second", "optional"],
        ),
        (
            3,
            "let b = Box<S> { first = S(\"ok\"); second = S(\"ok\");  }; }",
            "second = S(\"ok\"); ",
            vec!["optional"],
        ),
        (
            4,
            "let b = Box<S> { ",
            "Box<S> { ",
            vec!["first", "second", "optional"],
        ),
        (
            5,
            "let b = Box<S> { first = ; se }; }",
            " se",
            vec!["second"],
        ),
    ] {
        let text = format!("{declarations}{body}");
        client.notify("textDocument/didChange",json!({"textDocument":{"uri":document,"version":index+2},"contentChanges":[{"text":text}]}));
        let response = complete(&mut client, &document, &text, needle);
        let items = response["items"].as_array().unwrap();
        assert_eq!(
            items
                .iter()
                .map(|item| item["label"].as_str().unwrap())
                .collect::<Vec<_>>(),
            labels,
            "case {index}: {response}"
        );
        for item in items {
            assert_eq!(item["kind"], 5);
            let default = item["label"] == "optional";
            assert_eq!(
                item["detail"],
                if default {
                    "S (default)"
                } else {
                    "S (required)"
                }
            );
            assert!(
                item["sortText"]
                    .as_str()
                    .unwrap()
                    .starts_with(if default {
                        "1:"
                    } else {
                        "0:"
                    })
            );
        }
        if index == 1 {
            let start = text.find(" se }").unwrap() + 1;
            assert_eq!(
                items[0]["textEdit"]["range"]["start"]["character"],
                text[..start].encode_utf16().count()
            );
            assert_eq!(
                items[0]["textEdit"]["range"]["end"]["character"],
                text[..start + 2].encode_utf16().count()
            );
        }
    }
    client.stop();
}

#[test]
fn constructors_use_innermost_literal_and_lexical_or_delegated_authority() {
    let temp = tempfile::tempdir().unwrap();
    let declarations = "value S(str); struct Inner { nested: S; } struct Outer { inner: Inner; outer: S; } mod vault { pub opaque struct Secret { hidden: S; } pub opaque struct Owned<owner T> { delegated: S; } } struct Key {} ";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, declarations).unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, declarations);
    for (index, body, needle, expected) in [
        (
            0,
            "fn f() { Outer { inner = Inner { ne }; outer = S(\"x\"); }; }",
            "Inner { ne",
            Some("nested"),
        ),
        (
            1,
            "fn f() { Outer { inner = Inner { nested = S(\"x\"); }; ou }; }",
            " ou",
            Some("outer"),
        ),
        (2, "fn f() { vault::Secret { hi }; }", " hi", None),
        (
            3,
            "mod vault { fn f() { Secret { hi }; } }",
            " hi",
            Some("hidden"),
        ),
        (
            4,
            "fn f() { vault::Owned<Key> { de }; }",
            " de",
            Some("delegated"),
        ),
    ] {
        let text = format!("{declarations}{body}");
        client.notify("textDocument/didChange",json!({"textDocument":{"uri":document,"version":index+2},"contentChanges":[{"text":text}]}));
        let response = complete(&mut client, &document, &text, needle);
        let items = response["items"].as_array().unwrap();
        if let Some(label) = expected {
            assert!(
                items.iter().any(|item| item["label"] == label),
                "case {index}: {response}"
            );
        } else {
            assert!(items.is_empty(), "{response}");
        }
    }
    client.stop();
}

#[test]
fn secret_authoring_uses_typed_fields_variants_and_diagnostics_without_local_grants() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("main.srx");
    // These are public logical names only. No operational configuration or
    // source file exists; editor type checking must not resolve a local grant.
    let text = "fn service() -> std::Service { std::Service { id = \"auth\"; secrets = [\"token\"]; } } fn name() -> std::SecretName { \"token\" } fn reference() -> std::CommandArgument { std::CommandArgument::SecretFile(\"token\") }";
    std::fs::write(&path, text).unwrap();
    let document = uri(&path);
    let mut client = Client::with_options(temp.path(), "utf-16", false, "bundled");
    client.open(&document, text);
    client.diagnostics(&document, 1);
    let checked = client.diagnostics(&document, 1);
    assert_eq!(
        checked["params"]["diagnostics"],
        json!([]),
        "{checked}"
    );
    let position = text.find("std::SecretName").unwrap() + "std::".len();
    let hover = client.request(
        "textDocument/hover",
        json!({"textDocument":{"uri":document},"position":{"line":0,"character":position}}),
    );
    assert!(
        hover["result"].to_string().contains("SecretName"),
        "{hover}"
    );

    let incomplete = text.replace("secrets = [\"token\"];", "se");
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":incomplete}]}),
    );
    let fields = complete(
        &mut client,
        &document,
        &incomplete,
        "\"auth\"; se",
    );
    let field = fields["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["label"] == "secrets")
        .expect("typed service secrets field");
    assert_eq!(field["kind"], 5);
    assert_eq!(
        field["detail"],
        "[std::deployment::SecretName] (default)"
    );

    let incomplete = text.replace("SecretFile(\"token\")", "SecretF");
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":3},"contentChanges":[{"text":incomplete}]}),
    );
    let variants = complete(
        &mut client,
        &document,
        &incomplete,
        "std::CommandArgument::SecretF",
    );
    assert!(
        variants["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["label"] == "SecretFile"),
        "{variants}"
    );

    let invalid = text.replace("SecretFile(\"token\")", "SecretFile(42)");
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":4},"contentChanges":[{"text":invalid}]}),
    );
    client.diagnostics(&document, 4);
    let checked = client.diagnostics(&document, 4);
    assert!(
        checked["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["message"]
                .as_str()
                .is_some_and(|message| message.contains("SecretName"))),
        "{checked}"
    );
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    assert_eq!(std::fs::read_to_string(path).unwrap(), text);
    client.stop();
}

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use serde_json::{Value, json};
use url::Url;

#[path = "lsp/actions.rs"]
mod actions;
#[path = "lsp/completion.rs"]
mod completion;
#[path = "lsp/construction.rs"]
mod construction;
#[path = "lsp/contextual.rs"]
mod contextual;
#[path = "lsp/formatting.rs"]
mod formatting;
#[path = "support/github.rs"]
mod github_fixture;
#[path = "lsp/presentation.rs"]
mod presentation;
#[path = "lsp/status.rs"]
mod status;
#[path = "lsp/versioned.rs"]
mod versioned;
#[path = "lsp/watch.rs"]
mod watch;

struct Client {
    child: Child,
    input: ChildStdin,
    messages: Receiver<Value>,
    next: u32,
}

impl Client {
    fn new(root: &std::path::Path, encoding: &str) -> Self {
        Self::with_watching(root, encoding, false)
    }

    fn with_watching(root: &std::path::Path, encoding: &str, watching: bool) -> Self {
        Self::with_options(root, encoding, watching, "none")
    }

    fn with_options(
        root: &std::path::Path,
        encoding: &str,
        watching: bool,
        standard_library: &str,
    ) -> Self {
        Self::with_hint_resolution(root, encoding, watching, standard_library, false)
    }

    fn with_hint_resolution(
        root: &std::path::Path,
        encoding: &str,
        watching: bool,
        standard_library: &str,
        resolve_hints: bool,
    ) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_srx"))
            .args(["--std", standard_library, "lsp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, messages) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
            loop {
                let mut length = None;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.strip_prefix("Content-Length: ") {
                        length = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
                let mut body = vec![0; length.expect("protocol-only stdout")];
                if reader.read_exact(&mut body).is_err() {
                    return;
                }
                if sender
                    .send(serde_json::from_slice(&body).unwrap())
                    .is_err()
                {
                    return;
                }
            }
        });
        let mut client = Self {
            child,
            input,
            messages,
            next: 0,
        };
        let response = client.request("initialize", json!({"rootUri":uri(root),"capabilities":{"textDocument":{"inlayHint":{"resolveSupport":{"properties":if resolve_hints {vec!["tooltip"]} else {vec![]}}},"codeAction":{"codeActionLiteralSupport":{"codeActionKind":{"valueSet":["quickfix"]}}}},"general":{"positionEncodings":[encoding]},"workspace":{"workspaceEdit":{"documentChanges":true},"didChangeWatchedFiles":{"dynamicRegistration":watching}}}}));
        assert_eq!(
            response["result"]["capabilities"]["documentFormattingProvider"],
            true
        );
        assert_eq!(
            response["result"]["capabilities"]["positionEncoding"],
            encoding
        );
        assert_eq!(
            response["result"]["capabilities"]["experimental"],
            serde_json::from_str::<Value>(include_str!(
                "../../../tests/fixtures/lsp-contract.json"
            ))
            .unwrap()["descriptors"]
        );
        client.notify("initialized", json!({}));
        client
    }
    fn send(&mut self, value: &Value) {
        let bytes = serde_json::to_vec(value).unwrap();
        write!(
            self.input,
            "Content-Length: {}\r\n\r\n",
            bytes.len()
        )
        .unwrap();
        self.input.write_all(&bytes).unwrap();
        self.input.flush().unwrap();
    }
    fn notify(&mut self, method: &str, params: Value) {
        let mut message = json!({"jsonrpc":"2.0","method":method});
        message["params"] = params;
        self.send(&message);
    }
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        let mut message = json!({"jsonrpc":"2.0","id":id,"method":method});
        message["params"] = params;
        self.send(&message);
        self.wait(|message| message["id"] == id)
    }
    fn wait(&self, predicate: impl Fn(&Value) -> bool) -> Value {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let value = self
                .messages
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .expect("LSP response before deadline");
            if predicate(&value) {
                return value;
            }
        }
    }
    fn diagnostics(&self, document: &str, version: i32) -> Value {
        self.wait(|message| {
            message["method"] == "textDocument/publishDiagnostics"
                && message["params"]["uri"] == document
                && message["params"]["version"] == version
        })
    }
    fn open(&mut self, document: &str, text: &str) {
        self.notify(
            "textDocument/didOpen",
            json!({"textDocument":{"uri":document,"languageId":"syrox","version":1,"text":text}}),
        );
    }
    fn stop(&mut self) {
        assert_eq!(
            self.request("shutdown", Value::Null)["result"],
            Value::Null
        );
        self.notify("exit", Value::Null);
        assert!(self.child.wait().unwrap().success());
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn uri(path: &std::path::Path) -> String {
    Url::from_file_path(path).unwrap().into()
}
fn cursor(text: &str, needle: &str) -> Value {
    json!({"line":0,"character":text[..text.find(needle).unwrap()].encode_utf16().count()})
}

#[test]
fn stdio_lsp_navigates_imports_and_reloads_saved_input_changes() {
    let temp = tempfile::Builder::new()
        .prefix("syrox lsp ")
        .tempdir()
        .unwrap();
    let root = temp.path();
    std::fs::create_dir(root.join("recipes")).unwrap();
    let recipe = "pub value I(int); pub fn make() -> I { I(1) }";
    std::fs::write(root.join("recipes/one.srx"), recipe).unwrap();
    let main =
        "inputs { lib = \"modules:recipes\"; } fn use_it() -> lib::one::I { lib::one::make() }";
    std::fs::write(root.join("main.srx"), main).unwrap();
    let document = uri(&root.join("main.srx"));
    let mut client = Client::new(root, "utf-16");
    client.open(&document, main);
    client.diagnostics(&document, 1);
    assert_eq!(
        client.diagnostics(&document, 1)["params"]["diagnostics"],
        json!([])
    );
    let params = json!({"textDocument":{"uri":document},"position":cursor(main,"lib::one::make")});
    let definition = client.request("textDocument/definition", params.clone());
    assert_eq!(
        definition["result"]["uri"],
        uri(&root.join("recipes/one.srx"))
    );
    let hover = client.request("textDocument/hover", params);
    assert!(
        hover["result"]["contents"]["value"]
            .as_str()
            .unwrap()
            .contains("fn()")
    );
    let symbols = client.request(
        "textDocument/documentSymbol",
        json!({"textDocument":{"uri":document}}),
    );
    assert_eq!(symbols["result"][0]["name"], "use_it");
    let changed = main
        .replace("modules:recipes", "modules:new")
        .replace("one::", "other::");
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"text":changed}]}),
    );
    client.wait(|message| {
        message["method"] == "window/logMessage"
            && message["params"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("input declarations changed"))
    });
    let params =
        json!({"textDocument":{"uri":document},"position":cursor(&changed,"lib::other::make")});
    assert_eq!(
        client.request("textDocument/definition", params.clone())["result"],
        Value::Null
    );
    std::fs::create_dir(root.join("new")).unwrap();
    std::fs::write(root.join("new/other.srx"), recipe).unwrap();
    std::fs::write(root.join("main.srx"), &changed).unwrap();
    client.notify(
        "textDocument/didSave",
        json!({"textDocument":{"uri":document}}),
    );
    client.diagnostics(&document, 2);
    assert_eq!(
        client.diagnostics(&document, 2)["params"]["diagnostics"],
        json!([])
    );
    assert_eq!(
        client.request("textDocument/definition", params)["result"]["uri"],
        uri(&root.join("new/other.srx"))
    );
    assert_eq!(
        client.request("unimplemented", Value::Null)["error"]["code"],
        -32601
    );
    client.stop();
}

#[test]
fn stdio_lsp_handles_unicode_edits_initially_invalid_projects_and_close() {
    let temp = tempfile::tempdir().unwrap();
    let text = "value S(str); outputs { x: S = S(\"😀\"); bad: S = ; }";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, text).unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, text);
    let diagnostics = client.diagnostics(&document, 1);
    let expected = cursor(text, "; }");
    assert!(
        diagnostics["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |diagnostic| diagnostic["code"] == "srx.syntax.expected-expression"
                    && diagnostic["range"]["start"] == expected
            )
    );
    client.notify("textDocument/didChange", json!({"textDocument":{"uri":document,"version":2},"contentChanges":[{"range":{"start":expected,"end":expected},"text":"S(\"ok\")"}]}));
    assert_eq!(
        client.diagnostics(&document, 2)["params"]["diagnostics"],
        json!([])
    );
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":1},"contentChanges":[{"text":"@"}]}),
    );
    client.wait(|message| {
        message["method"] == "window/logMessage"
            && message["params"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("version"))
    });
    let fixed = text.replace("= ;", "= S(\"ok\");");
    std::fs::write(&path, fixed).unwrap();
    client.notify(
        "textDocument/didSave",
        json!({"textDocument":{"uri":document}}),
    );
    client.diagnostics(&document, 2);
    assert_eq!(
        client.diagnostics(&document, 2)["params"]["diagnostics"],
        json!([])
    );
    client.notify(
        "textDocument/didClose",
        json!({"textDocument":{"uri":document}}),
    );
    let closed = client.wait(|message| {
        message["method"] == "textDocument/publishDiagnostics"
            && message["params"]["uri"] == document
    });
    assert_eq!(closed["params"]["diagnostics"], json!([]));
    client.stop();
}

#[test]
fn stdio_lsp_negotiates_utf8_and_keeps_unsaved_documents_useful() {
    let temp = tempfile::tempdir().unwrap();
    let mut client = Client::new(temp.path(), "utf-8");
    let document = "untitled:example";
    let text = "value S(str); fn example() -> S { S(\"😀\"). }";
    client.open(document, text);
    let diagnostics = client.diagnostics(document, 1);
    assert!(
        diagnostics["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |diagnostic| diagnostic["range"]["start"]["character"]
                    == text.find(" }").unwrap() + 1
            )
    );
    let symbols = client.request(
        "textDocument/documentSymbol",
        json!({"textDocument":{"uri":document}}),
    );
    assert_eq!(symbols["result"][0]["name"], "example");
    client.stop();
}

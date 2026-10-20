//! Editor sessions and dispatch of LSP queries.
//!
//! # Snapshots and publication
//!
//! The session owns documents, capabilities and the current generation. Parsing
//! and analysis work on snapshots; responses from another generation are discarded.
//! [`worker`] keeps one active job and one replaceable pending job so rapid edits
//! do not accumulate old analyses.
//!
//! # Formatting an open buffer
//!
//! [`formatting`] has its own queue and cancellation, independent of project
//! analysis. Before returning an edit, the session checks that the document version
//! still matches. Language parsing, checking and formatting live in `syrox-lang`;
//! the session owns the decision to publish their results.

mod actions;
mod completion;
mod features;
mod fields;
mod formatting;
mod hints;
mod interpolation;
mod navigation;
mod pending;
mod presentation;
mod status;
mod transport;
mod worker;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, mpsc};

use serde_json::{Value, json};
use syrox_engine::project::CheckConfiguration;
use syrox_lang::{
    analysis::AnalysisCancellation, analysis::AnalysisHost, line_index::LineIndex,
    line_index::PositionEncoding, line_index::TextPosition, source::Source,
};
use url::Url;

#[derive(Debug)]
enum Event {
    Message(Value),
    InvalidJson,
    End(io::Result<()>),
    Analyzed(worker::ResultSet),
    Formatted(formatting::Completed),
}

pub(super) fn run(path: Option<PathBuf>, configuration: CheckConfiguration) -> ExitCode {
    match serve(path, configuration) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("LSP: {error}");
            ExitCode::FAILURE
        }
    }
}

fn serve(path: Option<PathBuf>, configuration: CheckConfiguration) -> io::Result<bool> {
    let (events, incoming) = mpsc::sync_channel(64);
    let reader_events = events.clone();
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        loop {
            let event = match transport::read_frame(&mut reader) {
                Ok(Some(bytes)) => {
                    serde_json::from_slice(&bytes).map_or(Event::InvalidJson, Event::Message)
                }
                Ok(None) => {
                    let _ = reader_events.send(Event::End(Ok(())));
                    break;
                }
                Err(error) => {
                    let _ = reader_events.send(Event::End(Err(error)));
                    break;
                }
            };
            if reader_events.send(event).is_err() {
                break;
            }
        }
    });
    let jobs = Arc::new(worker::Jobs::default());
    worker::spawn(jobs.clone(), events.clone(), configuration);
    let formatting = formatting::Formatting::new(events);
    let mut server = Server {
        workspace_mode: worker::WorkspaceMode::Project,
        explicit_root: path.is_some(),
        root: path.unwrap_or(std::env::current_dir()?),
        lifecycle: Lifecycle::New,
        watch_registration: false,
        versioned_edits: false,
        encoding: PositionEncoding::Utf16,
        host: AnalysisHost::default(),
        generation: 0,
        reload: 0,
        cancellation: AnalysisCancellation::default(),
        jobs,
        latest: None,
        pending_semantic_requests: Vec::new(),
        formatting,
        hints: presentation::HintSettings::default(),
        hint_refresh: false,
        hint_resolve_tooltip: false,
        hint_refresh_serial: 0,
    };
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let result = (|| {
        for event in incoming {
            match event {
                Event::Message(message) => {
                    if message.get("method").and_then(Value::as_str) == Some("exit") {
                        return Ok(server.lifecycle == Lifecycle::Shutdown);
                    }
                    server.message(&message, &mut writer)?;
                }
                Event::InvalidJson => {
                    response_error(&mut writer, Value::Null, -32700, "invalid JSON")?;
                }
                Event::End(result) => {
                    result?;
                    return Ok(server.lifecycle == Lifecycle::Shutdown);
                }
                Event::Analyzed(result) => server.analyzed(result, &mut writer)?,
                Event::Formatted(result) => server.formatted(result, &mut writer)?,
            }
        }
        Ok(server.lifecycle == Lifecycle::Shutdown)
    })();
    server.cancellation.cancel();
    server.jobs.stop();
    result
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // Independent negotiated protocol capabilities.
struct Server {
    workspace_mode: worker::WorkspaceMode,
    root: PathBuf,
    explicit_root: bool,
    lifecycle: Lifecycle,
    watch_registration: bool,
    versioned_edits: bool,
    encoding: PositionEncoding,
    host: AnalysisHost,
    generation: u64,
    reload: u64,
    cancellation: AnalysisCancellation,
    jobs: Arc<worker::Jobs>,
    latest: Option<worker::ResultSet>,
    pending_semantic_requests: Vec<pending::PendingSemanticRequest>,
    formatting: formatting::Formatting,
    hints: presentation::HintSettings,
    hint_refresh: bool,
    hint_resolve_tooltip: bool,
    hint_refresh_serial: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    New,
    Initialized,
    Shutdown,
}

impl Server {
    fn message(&mut self, message: &Value, writer: &mut impl Write) -> io::Result<()> {
        let id = message.get("id").cloned();
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            if message.get("id").is_some()
                && (message.get("result").is_some() || message.get("error").is_some())
            {
                return Ok(());
            }
            return response_error(
                writer,
                id.unwrap_or(Value::Null),
                -32600,
                "expected JSON-RPC method",
            );
        };
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return response_error(
                writer,
                id.unwrap_or(Value::Null),
                -32600,
                "expected JSON-RPC 2.0",
            );
        }
        let params = &message["params"];
        if let Some(id) = id {
            if !id.is_string() && !id.is_number() && !id.is_null() {
                return response_error(writer, Value::Null, -32600, "invalid request id");
            }
            if self.lifecycle == Lifecycle::Shutdown {
                return response_error(writer, id, -32600, "server has shut down");
            }
            if method == "initialize" {
                return self.initialize(id, params, writer);
            }
            if self.lifecycle == Lifecycle::New {
                return response_error(writer, id, -32002, "server not initialized");
            }
            match method {
                "inlayHint/resolve" => match self.resolve_inlay_hint(params) {
                    Ok(result) => response(writer, id, result),
                    Err(actions::ActionError(code, message)) => {
                        response_error(writer, id, code, &message)
                    }
                },
                "textDocument/codeAction" | "codeAction/resolve" => {
                    match self.code_actions(method, params) {
                        Ok(result) => response(writer, id, result),
                        Err(actions::ActionError(code, message)) => {
                            response_error(writer, id, code, &message)
                        }
                    }
                }
                "shutdown" => {
                    self.invalidate_semantic_requests(writer)?;
                    self.formatting.invalidate(writer)?;
                    self.lifecycle = Lifecycle::Shutdown;
                    self.cancellation.cancel();
                    response(writer, id, Value::Null)
                }
                "textDocument/formatting" => self.formatting_request(id, params, writer),
                "textDocument/completion"
                | "textDocument/hover"
                | "textDocument/signatureHelp"
                | "textDocument/definition"
                | "textDocument/typeDefinition"
                | "textDocument/references"
                | "textDocument/documentHighlight"
                | "textDocument/documentSymbol"
                | "textDocument/inlayHint"
                | "textDocument/semanticTokens/full" => {
                    self.semantic_request(method, id, params, writer)
                }
                "syrox/readSource" => match self.feature(method, params) {
                    Ok(result) => response(writer, id, result),
                    Err(error) => response_error(writer, id, -32602, &error),
                },
                "syrox/projectStatus" => response(writer, id, self.project_status()),
                _ => response_error(writer, id, -32601, "method not supported"),
            }
        } else {
            self.notification(method, params, writer)
        }
    }

    fn notification(
        &mut self,
        method: &str,
        params: &Value,
        writer: &mut impl Write,
    ) -> io::Result<()> {
        if self.lifecycle != Lifecycle::Initialized {
            return Ok(());
        }
        if method == "$/cancelRequest" {
            self.formatting.cancel(&params["id"], writer)?;
            return self.cancel_semantic_request(&params["id"], writer);
        }
        if params["textDocument"]["uri"]
            .as_str()
            .is_some_and(|uri| uri.starts_with("syrox-source:"))
        {
            return if method == "textDocument/didChange" {
                log(writer, "virtual sources are read-only")
            } else {
                Ok(())
            };
        }
        let update = match method {
            "workspace/didChangeConfiguration" => {
                self.hints
                    .update(&params["settings"]["syrox"]["inlayHints"]);
                self.refresh_hints(writer)?;
                return Ok(());
            }
            "initialized" if self.watch_registration => {
                self.watch_registration = false;
                transport::write_message(
                    writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": "srx/watch",
                        "method": "client/registerCapability",
                        "params": {
                            "registrations": [{
                                "id": "syrox-sources","method": "workspace/didChangeWatchedFiles","registerOptions": {
                                    "watchers": [{
                                        "globPattern": "**/*.srx"
                                    },{
                                        "globPattern": "**/Syrox.lock"
                                    }]
                                }
                            }]
                        }
                    }),
                )?;
                return Ok(());
            }
            "textDocument/didOpen" => self.open(params).map(|()| true),
            "textDocument/didChange" => self.change(params).map(|()| false),
            "textDocument/didClose" => match document_uri(params) {
                Ok(uri) => {
                    match self
                        .host
                        .close_overlay(&uri)
                        .and_then(|_| self.host.remove_disk(&uri))
                    {
                        Ok(_) => {
                            transport::write_message(
                                writer,
                                &json!({"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{"uri":uri,"diagnostics":[]}}),
                            )?;
                            Ok(true)
                        }
                        Err(error) => Err(error.to_string()),
                    }
                }
                Err(error) => Err(error),
            },
            "textDocument/didSave" | "workspace/didChangeWatchedFiles" => Ok(true),
            _ => return Ok(()),
        };
        match update {
            Ok(reload) => self.schedule(reload, writer),
            Err(error) => log(writer, &error),
        }
    }

    fn initialize(&mut self, id: Value, params: &Value, writer: &mut impl Write) -> io::Result<()> {
        if self.lifecycle != Lifecycle::New {
            return response_error(writer, id, -32600, "already initialized");
        }
        self.workspace_mode = match params["initializationOptions"]["workspaceMode"].as_str() {
            None | Some("project") => worker::WorkspaceMode::Project,
            Some("standard-library") => worker::WorkspaceMode::StandardLibrary,
            Some(_) => return response_error(writer, id, -32602, "unknown workspaceMode"),
        };
        if !self.explicit_root {
            let uri = params["workspaceFolders"][0]["uri"]
                .as_str()
                .or_else(|| params["rootUri"].as_str());
            if let Some(path) = uri.and_then(uri_path) {
                self.root = path;
            }
        }
        if params["capabilities"]["general"]["positionEncodings"]
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value == "utf-8"))
        {
            self.encoding = PositionEncoding::Utf8;
        }
        self.lifecycle = Lifecycle::Initialized;
        self.hints
            .update(&params["initializationOptions"]["inlayHints"]);
        self.hint_resolve_tooltip =
            params["capabilities"]["textDocument"]["inlayHint"]["resolveSupport"]["properties"]
                .as_array()
                .is_some_and(|properties| {
                    properties
                        .iter()
                        .any(|property| property == "tooltip")
                });
        self.hint_refresh = params["capabilities"]["workspace"]["inlayHint"]["refreshSupport"]
            .as_bool()
            == Some(true);
        self.versioned_edits =
            params["capabilities"]["workspace"]["workspaceEdit"]["documentChanges"].as_bool()
                == Some(true)
                && params["capabilities"]["textDocument"]["codeAction"]["codeActionLiteralSupport"]
                    .is_object();
        self.watch_registration =
            params["capabilities"]["workspace"]["didChangeWatchedFiles"]["dynamicRegistration"]
                .as_bool()
                == Some(true);
        response(
            writer,
            id,
            json!({"capabilities": {
            "positionEncoding": if self.encoding == PositionEncoding::Utf8 {"utf-8"} else {"utf-16"},
            "textDocumentSync": {"openClose":true,"change":1,"save":{"includeText":false}},
            "documentFormattingProvider":true,
            "hoverProvider":true,"definitionProvider":true,"documentSymbolProvider":true,
            "typeDefinitionProvider":true,"referencesProvider":true,"documentHighlightProvider":true,
            "inlayHintProvider":{"resolveProvider":true},
            "semanticTokensProvider":{"legend":{"tokenTypes":presentation::TOKEN_TYPES,"tokenModifiers":["declaration","readonly","defaultLibrary"]},"full":true},
            "codeActionProvider": if self.versioned_edits { json!({"codeActionKinds":["quickfix"],"resolveProvider":true}) } else { json!(false) },
            "completionProvider":{"triggerCharacters":[":",".","{"],"resolveProvider":false},
            "signatureHelpProvider":{"triggerCharacters":["(","{",","],"retriggerCharacters":[",","="]},
            "experimental":{
                "syroxVirtualSource":{"revision":1,"scheme":"syrox-source","request":"syrox/readSource"},
                "syroxProjectStatus":{"revision":1,"request":"syrox/projectStatus","notification":"syrox/projectStatus"}
            }
        }, "serverInfo":{"name":"srx","version":env!("CARGO_PKG_VERSION")}}),
        )
    }

    fn open(&mut self, params: &Value) -> Result<(), String> {
        let uri = document_uri(params)?;
        if self.host.snapshot().document(&uri).is_some() {
            return Err("document is already open".into());
        }
        self.host
            .set_overlay(
                &uri,
                version(params)?,
                params["textDocument"]["text"]
                    .as_str()
                    .ok_or("missing text")?,
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn change(&mut self, params: &Value) -> Result<(), String> {
        let uri = document_uri(params)?;
        let document = self
            .host
            .snapshot()
            .document(&uri)
            .ok_or("document is not open")?;
        let mut text = document.source().text().to_owned();
        for change in params["contentChanges"]
            .as_array()
            .ok_or("missing contentChanges")?
        {
            let replacement = change["text"]
                .as_str()
                .ok_or("missing change text")?;
            if let Some(range) = change.get("range") {
                let source =
                    Source::new(&*uri, text.as_str()).map_err(|error| error.to_string())?;
                let lines = LineIndex::new(&source);
                let start = lines
                    .offset(position(&range["start"])?, self.encoding)
                    .ok_or("invalid range start")? as usize;
                let end = lines
                    .offset(position(&range["end"])?, self.encoding)
                    .ok_or("invalid range end")? as usize;
                if start > end {
                    return Err("reversed edit range".into());
                }
                if text.len() - (end - start) + replacement.len() > syrox_lang::MAX_SOURCE_BYTES {
                    return Err("document exceeds source limit".into());
                }
                text.replace_range(start..end, replacement);
            } else {
                if replacement.len() > syrox_lang::MAX_SOURCE_BYTES {
                    return Err("document exceeds source limit".into());
                }
                replacement.clone_into(&mut text);
            }
        }
        self.host
            .set_overlay(&uri, version(params)?, &text)
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn schedule(&mut self, reload: bool, writer: &mut impl Write) -> io::Result<()> {
        self.formatting.invalidate(writer)?;
        self.invalidate_semantic_requests(writer)?;
        self.cancellation.cancel();
        self.cancellation = AnalysisCancellation::default();
        self.generation += 1;
        if reload {
            self.reload += 1;
        }
        self.latest = None;
        self.publish(None, writer)?;
        self.publish_status(writer)?;
        self.jobs.submit(worker::Job {
            mode: self.workspace_mode,
            generation: self.generation,
            reload: self.reload,
            root: self.root.clone(),
            documents: self.host.snapshot(),
            cancellation: self.cancellation.clone(),
        });
        Ok(())
    }

    fn analyzed(&mut self, result: worker::ResultSet, writer: &mut impl Write) -> io::Result<()> {
        if self.lifecycle == Lifecycle::Shutdown || result.generation != self.generation {
            return Ok(());
        }
        match &result.analysis {
            Ok(_) => self.publish(Some(&result), writer)?,
            Err(error) => log(
                writer,
                &format!("Project analysis unavailable; local syntax remains active: {error}"),
            )?,
        }
        self.latest = Some(result);
        self.publish_status(writer)?;
        self.finish_semantic_requests(writer)?;
        self.refresh_hints(writer)
    }

    fn refresh_hints(&mut self, writer: &mut impl Write) -> io::Result<()> {
        if self.hint_refresh {
            self.hint_refresh_serial += 1;
            transport::write_message(
                writer,
                &json!({
                    "jsonrpc": "2.0",
                    "id": format!("srx/hints-refresh/{}",self.hint_refresh_serial),
                    "method": "workspace/inlayHint/refresh"
                }),
            )?;
        }
        Ok(())
    }
}

fn response(writer: &mut impl Write, id: Value, result: Value) -> io::Result<()> {
    let mut message = json!({"jsonrpc":"2.0"});
    message["id"] = id;
    message["result"] = result;
    transport::write_message(writer, &message)
}
fn response_error(writer: &mut impl Write, id: Value, code: i32, message: &str) -> io::Result<()> {
    let mut response = json!({"jsonrpc":"2.0","error":{"code":code,"message":message}});
    response["id"] = id;
    transport::write_message(writer, &response)
}
fn log(writer: &mut impl Write, message: &str) -> io::Result<()> {
    transport::write_message(
        writer,
        &json!({"jsonrpc":"2.0","method":"window/logMessage","params":{"type":2,"message":message}}),
    )
}
fn document_uri(params: &Value) -> Result<String, String> {
    let uri = params["textDocument"]["uri"]
        .as_str()
        .ok_or("missing document URI")?;
    let url = Url::parse(uri).map_err(|error| error.to_string())?;
    if url.scheme() != "file" && url.scheme() != "untitled" && url.scheme() != "syrox-source" {
        return Err("unsupported document URI scheme".into());
    }
    Ok(url.to_string())
}
fn uri_path(uri: &str) -> Option<PathBuf> {
    Url::parse(uri).ok()?.to_file_path().ok()
}
fn file_uri(path: &Path) -> Option<String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    Url::from_file_path(absolute).ok().map(Into::into)
}
fn version(params: &Value) -> Result<i32, String> {
    params["textDocument"]["version"]
        .as_i64()
        .and_then(|version| i32::try_from(version).ok())
        .ok_or_else(|| "missing or invalid document version".into())
}
fn position(value: &Value) -> Result<TextPosition, String> {
    Ok(TextPosition {
        line: value["line"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or("invalid line")?,
        character: value["character"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or("invalid character")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn server() -> Server {
        Server {
            workspace_mode: worker::WorkspaceMode::Project,
            root: PathBuf::new(),
            explicit_root: false,
            lifecycle: Lifecycle::Initialized,
            watch_registration: false,
            versioned_edits: false,
            encoding: PositionEncoding::Utf16,
            host: AnalysisHost::default(),
            generation: 0,
            reload: 0,
            cancellation: AnalysisCancellation::default(),
            jobs: Arc::new(worker::Jobs::default()),
            latest: None,
            pending_semantic_requests: Vec::new(),
            formatting: formatting::Formatting::new(mpsc::sync_channel(8).0),
            hints: presentation::HintSettings::default(),
            hint_refresh: false,
            hint_resolve_tooltip: false,
            hint_refresh_serial: 0,
        }
    }

    #[test]
    fn newer_edits_cancel_work_and_obsolete_results_never_publish() {
        let mut server = server();
        server
            .host
            .set_overlay("untitled:test", 1, "@")
            .unwrap();
        server.schedule(false, &mut Vec::new()).unwrap();
        let previous = server.cancellation.clone();
        server
            .host
            .set_overlay("untitled:test", 2, "fn good() {}")
            .unwrap();
        server.schedule(false, &mut Vec::new()).unwrap();
        assert!(previous.check().is_err());
        let mut output = Vec::new();
        server
            .analyzed(
                worker::ResultSet {
                    generation: 1,
                    analysis: Err("obsolete".into()),
                    paths: BTreeMap::new(),
                    lock_status: syrox_engine::project::ProjectAnalysisLockStatus::Unchecked,
                    metadata_truncated: false,
                },
                &mut output,
            )
            .unwrap();
        assert!(output.is_empty());
        assert!(server.latest.is_none());
        server.lifecycle = Lifecycle::Shutdown;
        server
            .analyzed(
                worker::ResultSet {
                    generation: 2,
                    analysis: Err("after shutdown".into()),
                    paths: BTreeMap::new(),
                    lock_status: syrox_engine::project::ProjectAnalysisLockStatus::Unchecked,
                    metadata_truncated: false,
                },
                &mut output,
            )
            .unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn deferred_completion_is_cancelled_or_invalidated_before_a_new_revision() {
        let mut server = server();
        server
            .host
            .set_overlay("untitled:test", 1, "fn good() {}")
            .unwrap();
        server.schedule(false, &mut Vec::new()).unwrap();
        let params =
            json!({"textDocument":{"uri":"untitled:test"},"position":{"line":0,"character":0}});
        let mut output = Vec::new();
        server
            .semantic_request(
                "textDocument/completion",
                json!(1),
                &params,
                &mut output,
            )
            .unwrap();
        assert!(output.is_empty());
        assert_eq!(server.pending_semantic_requests.len(), 1);
        server
            .cancel_semantic_request(&json!(1), &mut output)
            .unwrap();
        assert!(server.pending_semantic_requests.is_empty());
        let frame = transport::read_frame(&mut output.as_slice())
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&frame).unwrap()["error"]["code"],
            -32800
        );
        output.clear();
        server
            .semantic_request(
                "textDocument/completion",
                json!(2),
                &params,
                &mut output,
            )
            .unwrap();
        server
            .host
            .set_overlay("untitled:test", 2, "fn better() {}")
            .unwrap();
        server.schedule(false, &mut output).unwrap();
        assert!(server.pending_semantic_requests.is_empty());
        let frame = transport::read_frame(&mut output.as_slice())
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&frame).unwrap()["result"],
            json!({"isIncomplete":true,"items":[]})
        );
        output.clear();
        server
            .semantic_request(
                "textDocument/completion",
                json!(3),
                &params,
                &mut output,
            )
            .unwrap();
        server
            .analyzed(
                worker::ResultSet {
                    generation: 1,
                    analysis: Err("old".into()),
                    paths: BTreeMap::new(),
                    lock_status: syrox_engine::project::ProjectAnalysisLockStatus::Unchecked,
                    metadata_truncated: false,
                },
                &mut output,
            )
            .unwrap();
        assert!(output.is_empty());
        server
            .analyzed(
                worker::ResultSet {
                    generation: 2,
                    analysis: Err("syntax-only fallback".into()),
                    paths: BTreeMap::new(),
                    lock_status: syrox_engine::project::ProjectAnalysisLockStatus::Unchecked,
                    metadata_truncated: false,
                },
                &mut output,
            )
            .unwrap();
        assert!(server.pending_semantic_requests.is_empty());
        let mut frames = output.as_slice();
        transport::read_frame(&mut frames).unwrap(); // project fallback log
        let status = serde_json::from_slice::<Value>(
            &transport::read_frame(&mut frames)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(status["method"], "syrox/projectStatus");
        assert_eq!(status["params"]["state"], "unavailable");
        let response = serde_json::from_slice::<Value>(
            &transport::read_frame(&mut frames)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response["id"], 3);
        assert_eq!(response["result"]["items"], json!([]));
    }
    #[test]
    fn semantic_queries_without_cursor_share_deferral_and_cancellation() {
        let mut server = server();
        server
            .host
            .set_overlay("untitled:test", 1, "fn good() {}")
            .unwrap();
        server.schedule(false, &mut Vec::new()).unwrap();
        let params = json!({"textDocument":{"uri":"untitled:test"}});
        let methods = [
            "textDocument/documentSymbol",
            "textDocument/inlayHint",
            "textDocument/semanticTokens/full",
        ];
        let mut output = Vec::new();
        for (id, method) in methods.into_iter().enumerate() {
            server
                .semantic_request(method, json!(id), &params, &mut output)
                .unwrap();
        }
        assert!(output.is_empty());
        assert_eq!(server.pending_semantic_requests.len(), 3);
        server
            .cancel_semantic_request(&json!(1), &mut output)
            .unwrap();
        let cancelled: Value = serde_json::from_slice(
            &transport::read_frame(&mut output.as_slice())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(cancelled["id"], 1);
        assert_eq!(cancelled["error"]["code"], -32800);
        output.clear();
        server
            .invalidate_semantic_requests(&mut output)
            .unwrap();
        assert!(server.pending_semantic_requests.is_empty());
        let mut frames = output.as_slice();
        let symbols: Value = serde_json::from_slice(
            &transport::read_frame(&mut frames)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let tokens: Value = serde_json::from_slice(
            &transport::read_frame(&mut frames)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(symbols["id"], 0);
        assert_eq!(symbols["result"], json!([]));
        assert_eq!(tokens["id"], 2);
        assert_eq!(tokens["result"], json!({"data": []}));
        assert!(
            transport::read_frame(&mut frames)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn formatting_refuses_disk_document_without_open_overlay() {
        let mut server = server();
        let uri = "file:///tmp/disk-only.srx";
        server.host.set_disk(uri, "fn f()->T{x}").unwrap();
        let mut bytes = Vec::new();
        server.message(&json!({"jsonrpc":"2.0","id":700,"method":"textDocument/formatting","params":{"textDocument":{"uri":uri}}}), &mut bytes).unwrap();
        let mut frames = io::Cursor::new(bytes);
        let reply: Value = serde_json::from_slice(
            &transport::read_frame(&mut frames)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(reply["error"]["code"], -32602);
        assert!(
            transport::read_frame(&mut frames)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn formatting_cancel_and_superseded_versions_never_publish_late_edits() {
        let mut server = server();
        let (sender, receiver) = mpsc::sync_channel(8);
        server.formatting = formatting::Formatting::new(sender);
        let uri = "file:///tmp/formatting-overlay.srx";
        server
            .host
            .set_overlay(uri, 1, "fn f()->T{x}")
            .unwrap();
        let mut bytes = Vec::new();
        server.message(&json!({"jsonrpc":"2.0","id":701,"method":"textDocument/formatting","params":{"textDocument":{"uri":uri}}}), &mut bytes).unwrap();
        server
            .message(
                &json!({"jsonrpc":"2.0","method":"$/cancelRequest","params":{"id":701}}),
                &mut bytes,
            )
            .unwrap();
        let Event::Formatted(result) = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
        else {
            panic!("format result");
        };
        server.formatted(result, &mut bytes).unwrap();
        let mut frames = io::Cursor::new(&bytes);
        let cancelled: Value = serde_json::from_slice(
            &transport::read_frame(&mut frames)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(cancelled["error"]["code"], -32800);
        assert!(
            transport::read_frame(&mut frames)
                .unwrap()
                .is_none()
        );
        bytes.clear();
        server.message(&json!({"jsonrpc":"2.0","id":702,"method":"textDocument/formatting","params":{"textDocument":{"uri":uri}}}), &mut bytes).unwrap();
        server
            .message(
                &json!({
                    "jsonrpc": "2.0",
                    "method": "textDocument/didChange",
                    "params": {
                        "textDocument": {
                            "uri": uri,
                            "version": 2
                        },
                        "contentChanges": [{
                            "text": "fn f()->T{changed}"
                        }]
                    }
                }),
                &mut bytes,
            )
            .unwrap();
        let Event::Formatted(result) = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
        else {
            panic!("format result");
        };
        server.formatted(result, &mut bytes).unwrap();
        let mut frames = io::Cursor::new(&bytes);
        let mut replies = Vec::new();
        while let Some(frame) = transport::read_frame(&mut frames).unwrap() {
            let value: Value = serde_json::from_slice(&frame).unwrap();
            if value["id"] == 702 {
                replies.push(value);
            }
        }
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0]["result"], json!([]));
    }
}

use serde_json::{Value, json};
use syrox_lang::{analysis::AnalysisCancellation, analysis::DocumentSnapshot, analysis::SyntaxFix};

use super::{
    Server, document_uri,
    features::{range, text_edit},
    position,
};

pub(super) struct ActionError(pub i32, pub String);

impl From<String> for ActionError {
    fn from(message: String) -> Self {
        Self(-32602, message)
    }
}

impl Server {
    pub(super) fn code_actions(&self, method: &str, params: &Value) -> Result<Value, ActionError> {
        if method == "codeAction/resolve" {
            return self.resolve_action(params);
        }
        if !self.versioned_edits {
            return Ok(json!([]));
        }
        let uri = document_uri(params)?;
        if uri.starts_with("syrox-source:") {
            return Ok(json!([]));
        }
        if params["context"]["only"]
            .as_array()
            .is_some_and(|kinds| {
                !kinds.is_empty()
                    && !kinds
                        .iter()
                        .any(|kind| kind == "quickfix" || kind == "")
            })
        {
            return Ok(json!([]));
        }
        let document = self
            .host
            .snapshot()
            .document(&uri)
            .ok_or_else(|| ActionError(-32602, "document is not open".into()))?;
        let cancellation = AnalysisCancellation::default();
        let lines = document
            .line_index(&cancellation)
            .map_err(|error| error.to_string())?;
        let start = lines
            .offset(
                position(&params["range"]["start"])?,
                self.encoding,
            )
            .ok_or_else(|| ActionError(-32602, "invalid range start".into()))?;
        let end = lines
            .offset(position(&params["range"]["end"])?, self.encoding)
            .ok_or_else(|| ActionError(-32602, "invalid range end".into()))?;
        if start > end {
            return Err(ActionError(
                -32602,
                "reversed action range".into(),
            ));
        }
        let actions = document
            .syntax_fixes(&cancellation)
            .map_err(|error| error.to_string())?
            .iter()
            .filter(|fix| start <= fix.span.start() && fix.span.start() <= end)
            .map(|fix| self.action(&uri, &document, fix))
            .collect();
        Ok(Value::Array(actions))
    }

    fn resolve_action(&self, params: &Value) -> Result<Value, ActionError> {
        let data = &params["data"];
        let uri = data["uri"]
            .as_str()
            .ok_or_else(|| ActionError(-32602, "missing action URI".into()))?;
        let stale = || {
            ActionError(
                -32801,
                "code action is no longer current; request actions again".into(),
            )
        };
        if !self.versioned_edits
            || data["generation"].as_u64() != Some(self.generation)
            || data["process"].as_u64() != Some(u64::from(std::process::id()))
        {
            return Err(stale());
        }
        let document = self
            .host
            .snapshot()
            .document(uri)
            .ok_or_else(stale)?;
        if document.overlay_version().map(i64::from) != data["version"].as_i64() {
            return Err(stale());
        }
        let cancellation = AnalysisCancellation::default();
        let fixes = document
            .syntax_fixes(&cancellation)
            .map_err(|error| error.to_string())?;
        let fix = fixes
            .iter()
            .find(|fix| {
                data["offset"].as_u64() == Some(u64::from(fix.span.start()))
                    && data["text"].as_str() == Some(fix.text)
            })
            .ok_or_else(stale)?;
        // Rebuild the edit from current analysis; never echo client-provided edits.
        Ok(self.action(uri, &document, fix))
    }

    fn action(&self, uri: &str, document: &DocumentSnapshot, fix: &SyntaxFix) -> Value {
        let lines = document
            .line_index(&AnalysisCancellation::default())
            .expect("active document query");
        json!({"title":format!("Insert `{}`", fix.text),"kind":"quickfix",
            "edit":{"documentChanges":[{"textDocument":{"uri":uri,"version":document.overlay_version()},"edits":[text_edit(range(lines, fix.span, self.encoding).unwrap_or(Value::Null), fix.text)]}]},
            "data":{"uri":uri,"version":document.overlay_version(),"generation":self.generation,"process":std::process::id(),"offset":fix.span.start(),"text":fix.text}})
    }
}

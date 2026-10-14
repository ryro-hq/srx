use serde_json::{Value, json};
use syrox_lang::line_index::LineIndex;

use super::{Server, actions::ActionError, worker::ResultSet};

impl Server {
    pub(super) fn stamp_hints(
        &self,
        params: &Value,
        result: &ResultSet,
        hints: &mut [Value],
        resolved: bool,
    ) {
        let uri = &params["textDocument"]["uri"];
        let version = uri
            .as_str()
            .and_then(|uri| self.host.snapshot().document(uri))
            .and_then(|document| document.overlay_version());
        for hint in hints {
            hint["data"] = json!({
                "uri": uri,
                "version": version,
                "generation": result.generation,
                "process": std::process::id(),
            });
            if self.hint_resolve_tooltip && !resolved {
                hint.as_object_mut()
                    .expect("hint object")
                    .remove("tooltip");
            }
        }
    }

    pub(super) fn resolve_inlay_hint(&self, params: &Value) -> Result<Value, ActionError> {
        let data = &params["data"];
        let uri = data["uri"]
            .as_str()
            .ok_or_else(|| ActionError(-32602, "missing hint URI".into()))?;
        let stale = || {
            ActionError(
                -32801,
                "inlay hint is no longer current; request hints again".into(),
            )
        };
        if data["generation"].as_u64() != Some(self.generation)
            || data["process"].as_u64() != Some(u64::from(std::process::id()))
        {
            return Err(stale());
        }
        let result = self.latest.as_ref().ok_or_else(stale)?;
        let analysis = result.analysis.as_ref().map_err(|_| stale())?;
        let (source, text) = analysis
            .sources()
            .iter()
            .find(|(source, _)| result.uri(*source) == uri)
            .ok_or_else(stale)?;
        let version = self
            .host
            .snapshot()
            .document(uri)
            .and_then(|document| document.overlay_version());
        if data["version"] != json!(version) {
            return Err(stale());
        }
        let query = json!({
            "textDocument": { "uri": uri },
            "range": { "start": params["position"], "end": params["position"] },
        });
        let hints = self.inlay_hints(
            &query,
            result,
            analysis,
            source,
            &LineIndex::new(text),
            true,
        )?;
        // Rebuild from checked facts; client-provided tooltips/edits are never echoed.
        hints
            .as_array()
            .and_then(|hints| {
                hints.iter().find(|hint| {
                    hint["position"] == params["position"]
                        && hint["label"] == params["label"]
                        && hint["kind"] == params["kind"]
                })
            })
            .cloned()
            .ok_or_else(stale)
    }
}

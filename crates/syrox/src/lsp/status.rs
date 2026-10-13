use std::collections::BTreeSet;
use std::io::{self, Write};

use serde_json::{Value, json};
use syrox_engine::project::ProjectAnalysisLockStatus;

use super::{Server, transport};

impl Server {
    /// Observe the current editorial snapshot without scheduling analysis or
    /// authenticating buffers for package execution.
    pub(super) fn project_status(&self) -> Value {
        let latest = self
            .latest
            .as_ref()
            .filter(|result| result.generation == self.generation);
        let state = latest.map_or("pending", |result| {
            if result.analysis.is_ok() {
                "semantic"
            } else {
                "unavailable"
            }
        });
        let lock_observation = latest.and_then(|result| match result.lock_status {
            ProjectAnalysisLockStatus::Unchecked => None,
            ProjectAnalysisLockStatus::Missing => Some("missing"),
            ProjectAnalysisLockStatus::Current => Some("current"),
            ProjectAnalysisLockStatus::Drift => Some("stale"),
        });
        let snapshot = self.host.snapshot();
        let mut covered = BTreeSet::new();
        if let Some(result) = latest
            && let Ok(analysis) = &result.analysis
        {
            for (id, uri) in &result.paths {
                let Some(source) = analysis.sources().get(*id) else {
                    continue;
                };
                let Some(document) = snapshot.document(uri) else {
                    continue;
                };
                // A physical path alone does not prove that the analysis used
                // this buffer's text. Deduplicate paths shared by source domains.
                if source.text() == document.source().text() {
                    covered.insert(uri.as_str());
                }
            }
        }
        let documents: Vec<_> = snapshot
            .document_names()
            .map(|uri| {
                let document = snapshot
                    .document(uri)
                    .expect("registered document");
                json!({
                    "uri": uri,
                    "version": document.overlay_version(),
                    "coverage": if covered.contains(uri) { "semantic" } else { "syntax" },
                })
            })
            .collect();
        json!({
            "revision": 1,
            "generation": self.generation,
            "state": state,
            "metadataTruncated": latest.is_some_and(|result| result.metadata_truncated),
            "lockObservation": lock_observation,
            "documents": documents,
        })
    }

    pub(super) fn publish_status(&self, writer: &mut impl Write) -> io::Result<()> {
        transport::write_message(
            writer,
            &json!({
                "jsonrpc": "2.0",
                "method": "syrox/projectStatus",
                "params": self.project_status(),
            }),
        )
    }
}

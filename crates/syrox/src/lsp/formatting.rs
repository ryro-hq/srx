//! Formatting the open overlay in a dedicated worker.
//!
//! Its queue and cancellation are independent of project analysis. Before returning
//! the edit, the session checks that the document version still matches.

use super::{
    Event, Server, document_uri,
    features::{edit_range, text_edit},
    response, response_error,
};
use serde_json::{Value, json};
use std::io::{self, Write};
use std::sync::mpsc::{self, SyncSender};
use syrox_lang::{
    analysis::AnalysisCancellation, formatter::FormatError, line_index::LineIndex,
    line_index::PositionEncoding, source::Source,
};

const MAX_PENDING: usize = 8;
#[derive(Debug)]
struct Job {
    serial: u64,
    source: Source,
    encoding: PositionEncoding,
    cancel: AnalysisCancellation,
}
#[derive(Debug)]
pub(super) struct Completed {
    serial: u64,
    result: Result<Value, String>,
}
#[derive(Debug)]
struct Pending {
    serial: u64,
    id: Value,
    uri: String,
    version: Option<i32>,
    cancel: AnalysisCancellation,
}
#[derive(Debug)]
pub(super) struct Formatting {
    jobs: SyncSender<Job>,
    pending: Vec<Pending>,
    serial: u64,
}
impl Formatting {
    pub(super) fn new(events: SyncSender<Event>) -> Self {
        let (jobs, incoming) = mpsc::sync_channel::<Job>(MAX_PENDING);
        std::thread::spawn(move || {
            for job in incoming {
                let result = edit(&job.source, job.encoding, &job.cancel);
                if events
                    .send(Event::Formatted(Completed {
                        serial: job.serial,
                        result,
                    }))
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            jobs,
            pending: Vec::new(),
            serial: 0,
        }
    }
    pub(super) fn invalidate(&mut self, writer: &mut impl Write) -> io::Result<()> {
        for job in std::mem::take(&mut self.pending) {
            job.cancel.cancel();
            response(writer, job.id, json!([]))?;
        }
        Ok(())
    }
    pub(super) fn cancel(&mut self, id: &Value, writer: &mut impl Write) -> io::Result<()> {
        if let Some(index) = self.pending.iter().position(|p| &p.id == id) {
            let job = self.pending.remove(index);
            job.cancel.cancel();
            response_error(
                writer,
                job.id,
                -32800,
                "formatting request cancelled",
            )?;
        }
        Ok(())
    }
}
impl Drop for Formatting {
    fn drop(&mut self) {
        for job in &self.pending {
            job.cancel.cancel();
        }
    }
}
fn edit(
    source: &Source,
    encoding: PositionEncoding,
    cancel: &AnalysisCancellation,
) -> Result<Value, String> {
    let formatted = match syrox_lang::formatter::format_source_cancellable(source, cancel) {
        Ok(text) => text,
        Err(FormatError::Syntax(_)) => return Ok(json!([])),
        Err(error) => return Err(error.to_string()),
    };
    if source.text() == formatted {
        return Ok(json!([]));
    }
    let range = edit_range(
        &LineIndex::new(source),
        0,
        u32::try_from(source.text().len()).map_err(|e| e.to_string())?,
        encoding,
    )
    .ok_or("invalid document end")?;
    Ok(json!([text_edit(range, formatted)]))
}
impl Server {
    pub(super) fn formatting_request(
        &mut self,
        id: Value,
        params: &Value,
        writer: &mut impl Write,
    ) -> io::Result<()> {
        let uri = match document_uri(params) {
            Ok(uri) => uri,
            Err(e) => return response_error(writer, id, -32602, &e),
        };
        if uri.starts_with("syrox-source:") {
            return response(writer, id, json!([]));
        }
        if super::uri_path(&uri).is_none() {
            return response_error(
                writer,
                id,
                -32602,
                "formatting requires an open file document",
            );
        }
        let snapshot = self.host.snapshot();
        let Some(document) = snapshot
            .document(&uri)
            .filter(|d| d.overlay_version().is_some())
        else {
            return response_error(writer, id, -32602, "document is not open");
        };
        if self.formatting.pending.len() >= MAX_PENDING {
            return response_error(
                writer,
                id,
                -32803,
                "formatting queue full; request again",
            );
        }
        if self.formatting.pending.iter().any(|p| p.id == id) {
            return response_error(
                writer,
                id,
                -32600,
                "duplicate pending formatting id",
            );
        }
        let serial = self.formatting.serial;
        self.formatting.serial = self
            .formatting
            .serial
            .checked_add(1)
            .ok_or_else(|| io::Error::other("format request sequence exhausted"))?;
        let cancel = AnalysisCancellation::default();
        let job = Job {
            serial,
            source: document.source().clone(),
            encoding: self.encoding,
            cancel: cancel.clone(),
        };
        if self.formatting.jobs.try_send(job).is_err() {
            return response_error(
                writer,
                id,
                -32803,
                "formatting queue unavailable; request again",
            );
        }
        self.formatting.pending.push(Pending {
            serial,
            id,
            uri,
            version: document.overlay_version(),
            cancel,
        });
        Ok(())
    }
    pub(super) fn formatted(
        &mut self,
        result: Completed,
        writer: &mut impl Write,
    ) -> io::Result<()> {
        let Some(index) = self
            .formatting
            .pending
            .iter()
            .position(|p| p.serial == result.serial)
        else {
            return Ok(());
        };
        let job = self.formatting.pending.remove(index);
        if self
            .host
            .snapshot()
            .document(&job.uri)
            .is_none_or(|d| d.overlay_version() != job.version)
        {
            return response(writer, job.id, json!([]));
        }
        match result.result {
            Ok(edits) => response(writer, job.id, edits),
            Err(error) => response_error(writer, job.id, -32803, &error),
        }
    }
}

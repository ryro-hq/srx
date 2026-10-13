//! Snapshots dos documentos e consultas usadas pelo editor.
//!
//! O host recebe texto de disco e overlays. Um snapshot conserva a revisão que
//! deu origem aos spans, mesmo depois de outra edição. O documento imutável
//! guarda seu parsing; a análise do projeto reúne as fontes e passa por resolução
//! e checking antes de publicar os fatos.
//!
//! Cancelamento encerra a consulta sem virar diagnóstico. Guarde o snapshot
//! junto do resultado e confira a revisão antes de publicar uma resposta.

use std::collections::BTreeMap;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use thiserror::Error;

use crate::{
    MAX_SOURCES, diagnostic::Diagnostic, line_index::LineIndex, line_index::PositionEncoding,
    line_index::TextPosition, source::Source, source::SourceError, syntax::ParsedFile,
    syntax::SyntaxNode,
};

mod fixes;
mod interfaces;
mod relocation;
mod semantic;
mod symbols;
pub use fixes::SyntaxFix;
pub use interfaces::{InterfaceNamespaceDependency, OwnerTypeDependencies, TypeInterface};
pub use symbols::{SemanticOccurrence, SemanticSymbol, SemanticSymbolKind};
#[cfg(test)]
mod tests;
pub use semantic::{SemanticAnalysis, SemanticAnalysisError};

/// Opaque publication stamp, distinct even between independent analysis hosts.
#[derive(Clone, Debug)]
pub struct AnalysisRevision(Arc<()>);

impl PartialEq for AnalysisRevision {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for AnalysisRevision {}

#[derive(Clone, Copy, Debug)]
pub struct AnalysisLimits {
    pub max_documents: usize,
    /// Counts both disk and overlay text in the current snapshot. Old snapshots
    /// are owned by the caller, which must release obsolete work.
    pub max_source_bytes: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            max_documents: MAX_SOURCES,
            max_source_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AnalysisUpdateError {
    #[error(transparent)]
    Source(#[from] SourceError),
    #[error("editor input exceeds the configured document or source-byte limit")]
    InputLimit,
    #[error("overlay version must be newer than the open document's version")]
    StaleVersion,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("analysis query cancelled")]
pub struct AnalysisCancelled;

/// Cooperative cancellation within syntax/semantic work and between phases. Cancellation is not a
/// language diagnostic and does not poison a completed content cache.
#[derive(Clone, Debug, Default)]
pub struct AnalysisCancellation(Arc<AtomicBool>);

impl AnalysisCancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn check(&self) -> Result<(), AnalysisCancelled> {
        if self.0.load(Ordering::Acquire) {
            Err(AnalysisCancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct FileAnalysis {
    source: Source,
    parsed: OnceLock<ParsedFile>,
    lines: OnceLock<LineIndex>,
    bound: std::sync::Mutex<Option<(crate::source::SourceId, Arc<ParsedFile>)>>,
    fixes: OnceLock<Vec<SyntaxFix>>,
}

impl FileAnalysis {
    /// Parse in the caller's topology, caching only completed work for this
    /// immutable document. Source IDs are part of the parse's coordinates.
    fn parse_bound(
        &self,
        id: crate::source::SourceId,
        cancellation: &AnalysisCancellation,
    ) -> Result<Arc<ParsedFile>, AnalysisCancelled> {
        cancellation.check()?;
        let cached = self
            .bound
            .lock()
            .expect("file cache lock is not poisoned")
            .as_ref()
            .filter(|(bound, _)| *bound == id)
            .map(|(_, file)| file.clone());
        if let Some(file) = cached {
            return Ok(file);
        }
        let file = Arc::new(crate::syntax::parser::parse_file_cancellable(
            id,
            &self.source,
            Some(cancellation),
        )?);
        cancellation.check()?;
        *self
            .bound
            .lock()
            .expect("file cache lock is not poisoned") = Some((id, file.clone()));
        Ok(file)
    }

    fn new(source: Source) -> Self {
        Self {
            source,
            parsed: OnceLock::new(),
            lines: OnceLock::new(),
            bound: std::sync::Mutex::new(None),
            fixes: OnceLock::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct Overlay {
    version: i32,
    source: Source,
}

#[derive(Clone, Debug)]
struct Document {
    disk: Option<Source>,
    overlay: Option<Overlay>,
    analysis: Arc<FileAnalysis>,
}

impl Document {
    fn retained_bytes(&self) -> usize {
        self.disk
            .as_ref()
            .map_or(0, |source| source.text().len())
            + self
                .overlay
                .as_ref()
                .map_or(0, |overlay| overlay.source.text().len())
    }
}

#[derive(Clone, Debug)]
struct State {
    revision: AnalysisRevision,
    documents: BTreeMap<String, Arc<Document>>,
    source_bytes: usize,
}

/// Mutable input owner; snapshots and cached per-file results are immutable.
/// Names are caller-normalized document keys (for example paths or URIs).
#[derive(Debug)]
pub struct AnalysisHost {
    state: Arc<State>,
    limits: AnalysisLimits,
}

impl Default for AnalysisHost {
    fn default() -> Self {
        Self::new(AnalysisLimits::default())
    }
}

impl AnalysisHost {
    pub fn new(limits: AnalysisLimits) -> Self {
        Self {
            state: Arc::new(State {
                revision: AnalysisRevision(Arc::new(())),
                documents: BTreeMap::new(),
                source_bytes: 0,
            }),
            limits,
        }
    }

    pub fn snapshot(&self) -> AnalysisSnapshot {
        AnalysisSnapshot(self.state.clone())
    }

    /// Check immediately before publishing a query result. Any input update
    /// invalidates the global stamp, including edits in another document.
    pub fn is_current(&self, revision: &AnalysisRevision) -> bool {
        self.state.revision == *revision
    }

    pub fn set_disk(
        &mut self,
        name: &str,
        text: &str,
    ) -> Result<AnalysisRevision, AnalysisUpdateError> {
        let old = self.state.documents.get(name);
        if old
            .and_then(|document| document.disk.as_ref())
            .is_some_and(|source| source.text() == text)
        {
            return Ok(self.state.revision.clone());
        }
        let disk = Some(Source::new(name, text)?);
        let overlay = old.and_then(|document| document.overlay.clone());
        self.replace(name, disk, overlay)
    }

    /// Open or replace an unsaved buffer. Versions must increase until close;
    /// a reopened document may start a new editor version sequence.
    pub fn set_overlay(
        &mut self,
        name: &str,
        version: i32,
        text: &str,
    ) -> Result<AnalysisRevision, AnalysisUpdateError> {
        let old = self.state.documents.get(name);
        if old
            .and_then(|document| document.overlay.as_ref())
            .is_some_and(|overlay| version <= overlay.version)
        {
            return Err(AnalysisUpdateError::StaleVersion);
        }
        let source = Source::new(name, text)?;
        let disk = old.and_then(|document| document.disk.clone());
        self.replace(
            name,
            disk,
            Some(Overlay {
                version,
                source,
            }),
        )
    }

    pub fn remove_disk(&mut self, name: &str) -> Result<AnalysisRevision, AnalysisUpdateError> {
        let Some(document) = self.state.documents.get(name) else {
            return Ok(self.state.revision.clone());
        };
        if document.disk.is_none() {
            return Ok(self.state.revision.clone());
        }
        let overlay = document.overlay.clone();
        self.replace(name, None, overlay)
    }

    pub fn close_overlay(&mut self, name: &str) -> Result<AnalysisRevision, AnalysisUpdateError> {
        let Some(document) = self.state.documents.get(name) else {
            return Ok(self.state.revision.clone());
        };
        if document.overlay.is_none() {
            return Ok(self.state.revision.clone());
        }
        let disk = document.disk.clone();
        self.replace(name, disk, None)
    }

    fn replace(
        &mut self,
        name: &str,
        disk: Option<Source>,
        overlay: Option<Overlay>,
    ) -> Result<AnalysisRevision, AnalysisUpdateError> {
        let old = self.state.documents.get(name);
        let effective = overlay
            .as_ref()
            .map(|overlay| &overlay.source)
            .or(disk.as_ref());
        let analysis = effective.map(|source| {
            old.filter(|old| old.analysis.source.text() == source.text())
                .map_or_else(
                    || Arc::new(FileAnalysis::new(source.clone())),
                    |old| old.analysis.clone(),
                )
        });
        let next = analysis.map(|analysis| {
            Arc::new(Document {
                disk,
                overlay,
                analysis,
            })
        });
        let count =
            self.state.documents.len() - usize::from(old.is_some()) + usize::from(next.is_some());
        let bytes = self.state.source_bytes - old.map_or(0, |document| document.retained_bytes());
        let bytes = bytes
            .checked_add(
                next.as_ref()
                    .map_or(0, |document| document.retained_bytes()),
            )
            .ok_or(AnalysisUpdateError::InputLimit)?;
        if count > self.limits.max_documents.min(MAX_SOURCES)
            || bytes > self.limits.max_source_bytes
        {
            return Err(AnalysisUpdateError::InputLimit);
        }
        // Validation above is transactional: a rejected update cannot change
        // the stamp, effective text, overlay version or caches.
        let state = Arc::make_mut(&mut self.state);
        state.revision = AnalysisRevision(Arc::new(()));
        state.source_bytes = bytes;
        if let Some(document) = next {
            state.documents.insert(name.to_owned(), document);
        } else {
            state.documents.remove(name);
        }
        Ok(state.revision.clone())
    }
}

#[derive(Clone, Debug)]
pub struct AnalysisSnapshot(Arc<State>);

impl AnalysisSnapshot {
    pub fn revision(&self) -> AnalysisRevision {
        self.0.revision.clone()
    }

    pub fn document_names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.0.documents.keys().map(String::as_str)
    }

    pub fn document(&self, name: &str) -> Option<DocumentSnapshot> {
        self.0
            .documents
            .get(name)
            .map(|document| DocumentSnapshot {
                revision: self.revision(),
                document: document.clone(),
            })
    }
}

/// A document query handle includes its global publication revision and the
/// optional editor version. It remains valid after the host is edited/dropped.
#[derive(Clone, Debug)]
pub struct DocumentSnapshot {
    revision: AnalysisRevision,
    document: Arc<Document>,
}

impl DocumentSnapshot {
    pub fn revision(&self) -> AnalysisRevision {
        self.revision.clone()
    }

    pub fn overlay_version(&self) -> Option<i32> {
        self.document
            .overlay
            .as_ref()
            .map(|overlay| overlay.version)
    }

    pub fn source(&self) -> &Source {
        &self.document.analysis.source
    }

    pub fn parsed(
        &self,
        cancellation: &AnalysisCancellation,
    ) -> Result<&ParsedFile, AnalysisCancelled> {
        cancellation.check()?;
        let cache = &self.document.analysis.parsed;
        if cache.get().is_none() {
            let parsed = crate::syntax::parser::parse_file_cancellable(
                crate::source::SourceId::SINGLE,
                self.source(),
                Some(cancellation),
            )?;
            cancellation.check()?;
            let _ = cache.set(parsed);
        }
        cancellation.check()?;
        Ok(cache.get().expect("parsed cache initialized"))
    }

    pub fn line_index(
        &self,
        cancellation: &AnalysisCancellation,
    ) -> Result<&LineIndex, AnalysisCancelled> {
        cancellation.check()?;
        let lines = self
            .document
            .analysis
            .lines
            .get_or_init(|| LineIndex::new(self.source()));
        cancellation.check()?;
        Ok(lines)
    }

    pub fn diagnostics(
        &self,
        cancellation: &AnalysisCancellation,
    ) -> Result<&[Diagnostic], AnalysisCancelled> {
        Ok(self.parsed(cancellation)?.diagnostics())
    }

    pub fn function_signatures(
        &self,
        cancellation: &AnalysisCancellation,
    ) -> Result<impl ExactSizeIterator<Item = &crate::syntax::FunctionSignature>, AnalysisCancelled>
    {
        Ok(self.parsed(cancellation)?.function_signatures())
    }

    pub fn syntax_context(
        &self,
        position: TextPosition,
        encoding: PositionEncoding,
        cancellation: &AnalysisCancellation,
    ) -> Result<Option<SyntaxNode<'_>>, AnalysisCancelled> {
        let Some(offset) = self
            .line_index(cancellation)?
            .offset(position, encoding)
        else {
            return Ok(None);
        };
        Ok(self
            .parsed(cancellation)?
            .syntax()
            .context_at(offset))
    }
}

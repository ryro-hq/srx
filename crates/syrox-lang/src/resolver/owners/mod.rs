//! Fatos de resolução que podem ser comparados entre snapshots.
//!
//! As coordenadas ficam relativas ao owner para sobreviver a texto inserido
//! antes dele. Essa comparação ajuda a detectar mudanças; sozinha, não permite
//! reaproveitar o resultado da checagem de outro snapshot.

use std::{collections::BTreeMap, ops::Range, sync::Arc};

use super::{
    LocalId, LocalKind, ModuleId, ReferenceKind, ResolvedProgram, ResolvedTarget, Resolver,
};
use crate::{
    analysis::AnalysisCancellation, analysis::AnalysisCancelled, diagnostic::Diagnostic,
    diagnostic::DiagnosticCode, source::SourceDomainId, source::Span,
};

mod dependencies;
pub(crate) use dependencies::ObservedNamespace;
pub use dependencies::{
    NamespaceDependency, NamespaceExport, NamespaceOutcome, NamespaceQuery, NamespaceTarget,
};

const MAX_OWNERS: usize = 65_536;
const MAX_UNITS: usize = 262_144;
const MAX_TEXT: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResolutionOwnerPart {
    Declaration,
    Publication(String),
    FieldDefault(String),
}

/// Structural identity scoped to one project topology. Domain IDs must not be
/// compared across independently loaded projects without topology validation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolutionOwnerKey {
    pub domain: SourceDomainId,
    pub path: Vec<String>,
    pub part: ResolutionOwnerPart,
}

/// UTF-8 byte offsets from the beginning of an owner's source span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerRelativeSpan {
    pub start: u32,
    pub end: u32,
}

/// A coordinate conversion for one snapshot, not a proof of unchanged text.
#[derive(Clone, Debug)]
pub struct OwnerSourceMap {
    span: Span,
    locals: Vec<LocalId>,
}

impl OwnerSourceMap {
    pub const fn span(&self) -> Span {
        self.span
    }
    pub fn relative_span(&self, span: Span) -> Option<OwnerRelativeSpan> {
        if span.source_id() != self.span.source_id()
            || span.start() < self.span.start()
            || span.end() > self.span.end()
        {
            return None;
        }
        Some(OwnerRelativeSpan {
            start: span.start() - self.span.start(),
            end: span.end() - self.span.start(),
        })
    }
    pub fn absolute_span(&self, span: OwnerRelativeSpan) -> Option<Span> {
        if span.start > span.end || span.end > self.span.end() - self.span.start() {
            return None;
        }
        Some(Span::new(
            self.span.source_id(),
            self.span.start() + span.start,
            self.span.start() + span.end,
        ))
    }
    pub(crate) fn diagnostic(&self, diagnostic: &Diagnostic) -> Option<OwnerDiagnostic> {
        Some(OwnerDiagnostic {
            span: self.relative_span(diagnostic.span)?,
            code: diagnostic.code,
            message: diagnostic.message.clone(),
        })
    }

    pub fn local(&self, ordinal: u32) -> Option<LocalId> {
        self.locals.get(ordinal as usize).copied()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerLocal {
    pub name: String,
    pub kind: LocalKind,
    pub declaration: OwnerRelativeSpan,
    pub scopes: Vec<OwnerRelativeSpan>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerReferenceTarget {
    Local {
        owner: Arc<ResolutionOwnerKey>,
        ordinal: u32,
    },
    Item {
        domain: SourceDomainId,
        path: Vec<String>,
    },
    Module {
        domain: SourceDomainId,
        path: Vec<String>,
    },
    EnumVariant {
        domain: SourceDomainId,
        path: Vec<String>,
        /// Ordinal in the enum interface; interface changes require invalidation.
        index: u32,
    },
    ContextualEnumVariant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerReference {
    pub span: OwnerRelativeSpan,
    pub kind: ReferenceKind,
    pub target: OwnerReferenceTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerDiagnostic {
    pub span: OwnerRelativeSpan,
    pub code: DiagnosticCode,
    pub message: String,
}

/// Resolution facts with snapshot-independent coordinates. Unknown names remain
/// diagnostics. Namespace observations do not include checked type interfaces
/// or policy dependencies, so this result is not a checker cache key.
#[derive(Clone, Debug)]
pub struct OwnerResolution {
    pub key: Arc<ResolutionOwnerKey>,
    pub source_map: OwnerSourceMap,
    /// The vector index is the owner's local ordinal, independent of `LocalId`.
    pub locals: Vec<OwnerLocal>,
    pub references: Vec<OwnerReference>,
    pub diagnostics: Vec<OwnerDiagnostic>,
    /// The global resolver diagnostic cap may have hidden errors in this owner.
    pub diagnostics_truncated: bool,
    pub namespace_dependencies: Arc<Vec<NamespaceDependency>>,
    /// Coverage of namespace observations, not validity of the owner or proof
    /// that its type interfaces/policy dependencies remain unchanged.
    pub namespace_dependencies_complete: bool,
}

#[derive(Clone, Debug)]
struct Owner {
    key: Arc<ResolutionOwnerKey>,
    span: Span,
    parent: Option<usize>,
    children: Vec<usize>,
    locals: Range<usize>,
    references: Range<usize>,
    scopes: Range<usize>,
    diagnostics: Vec<OwnerDiagnostic>,
    diagnostics_truncated: bool,
    dependencies: Arc<Vec<NamespaceDependency>>,
    dependencies_complete: bool,
}

#[derive(Clone, Debug, Default)]
pub(super) struct OwnerTable {
    owners: Vec<Owner>,
    keys: BTreeMap<Arc<ResolutionOwnerKey>, Option<usize>>,
    local_owners: Vec<Option<(usize, u32)>>,
    reference_owners: Vec<Option<usize>>,
    active: Option<usize>,
    units: usize,
    text: usize,
    pub truncated: bool,
}

impl OwnerTable {
    fn reserve(&mut self, units: usize, text: usize) -> bool {
        self.units = self.units.saturating_add(units);
        self.text = self.text.saturating_add(text);
        if self.truncated
            || self.units > MAX_UNITS
            || self.text > MAX_TEXT
            || self.owners.len() >= MAX_OWNERS
        {
            *self = Self {
                truncated: true,
                ..Self::default()
            };
            return false;
        }
        true
    }

    fn unique(&self, mut index: usize) -> bool {
        loop {
            let owner = &self.owners[index];
            if self.keys.get(&owner.key) != Some(&Some(index)) {
                return false;
            }
            if let Some(parent) = owner.parent {
                index = parent;
            } else {
                return true;
            }
        }
    }
}

impl Resolver<'_> {
    pub(super) fn with_owner(
        &mut self,
        module: ModuleId,
        name: &str,
        part: ResolutionOwnerPart,
        span: Span,
        resolve: impl FnOnce(&mut Self),
    ) {
        if self.cancellation.is_none() || self.owners.truncated {
            resolve(self);
            return;
        }
        let context = &self.modules[module.index()];
        let bytes = context
            .path
            .segments
            .iter()
            .map(String::len)
            .sum::<usize>()
            + name.len()
            + match &part {
                ResolutionOwnerPart::Declaration => 0,
                ResolutionOwnerPart::FieldDefault(name)
                | ResolutionOwnerPart::Publication(name) => name.len(),
            };
        if !self.owners.reserve(1, bytes) {
            resolve(self);
            return;
        }
        let mut path = context.path.segments.clone();
        path.push(name.to_owned());
        let key = Arc::new(ResolutionOwnerKey {
            domain: context.domain,
            path,
            part,
        });
        let index = self.owners.owners.len();
        self.owners
            .keys
            .entry(key.clone())
            .and_modify(|entry| *entry = None)
            .or_insert(Some(index));
        let parent = self.owners.active.replace(index);
        let diagnostics = self.diagnostics.len();
        self.owners.owners.push(Owner {
            key,
            span,
            parent,
            children: Vec::new(),
            locals: self.locals.len()..self.locals.len(),
            references: self.references.len()..self.references.len(),
            scopes: self.editor_locals.len()..self.editor_locals.len(),
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            dependencies: Arc::default(),
            dependencies_complete: true,
        });
        if let Some(parent) = parent {
            self.owners.owners[parent].children.push(index);
        }
        resolve(self);
        if self.owners.truncated {
            return;
        }
        self.owners.active = parent;
        self.finish_owner(index, diagnostics);
    }

    fn finish_owner(&mut self, index: usize, diagnostics: usize) {
        if self
            .cancellation
            .is_some_and(|cancel| cancel.check().is_err())
        {
            self.exhausted = true;
            return;
        }
        let start = &self.owners.owners[index];
        let units = self.locals.len() - start.locals.start + self.references.len()
            - start.references.start
            + self.editor_locals.len()
            - start.scopes.start;
        let bytes = self.diagnostics[diagnostics..]
            .iter()
            .map(|diagnostic| diagnostic.message.len())
            .sum();
        if self
            .locals
            .len()
            .saturating_add(self.references.len())
            > MAX_UNITS
        {
            self.owners.reserve(MAX_UNITS + 1, 0);
            return;
        }
        if !self.owners.reserve(units, bytes) {
            return;
        }
        // IDs are contiguous in the flattened compatibility representation.
        self.owners
            .local_owners
            .resize(self.locals.len(), None);
        self.owners
            .reference_owners
            .resize(self.references.len(), None);
        let owner = &mut self.owners.owners[index];
        owner.locals.end = self.locals.len();
        owner.references.end = self.references.len();
        owner.scopes.end = self.editor_locals.len();
        owner.diagnostics_truncated = self.diagnostics.len() == crate::MAX_DIAGNOSTICS;
        owner.dependencies_complete &= !self.exhausted;
        let mut ordinal = 0;
        for entry in &mut self.owners.local_owners[owner.locals.clone()] {
            if entry.is_none() {
                *entry = Some((index, ordinal));
                ordinal += 1;
            }
        }
        for entry in &mut self.owners.reference_owners[owner.references.clone()] {
            if entry.is_none() {
                *entry = Some(index);
            }
        }
        let map = OwnerSourceMap {
            span: owner.span,
            locals: Vec::new(),
        };
        owner.diagnostics = self.diagnostics[diagnostics..]
            .iter()
            .filter_map(|diagnostic| map.diagnostic(diagnostic))
            .collect();
    }
}

impl ResolvedProgram {
    pub(crate) fn resolution_owners_truncated(&self) -> bool {
        self.editor
            .as_ref()
            .is_some_and(|editor| editor.owners.truncated)
    }
    pub(crate) fn resolution_owners(&self) -> impl Iterator<Item = (&ResolutionOwnerKey, Span)> {
        self.editor.iter().flat_map(|editor| {
            editor
                .owners
                .keys
                .values()
                .filter_map(|index| *index)
                .filter(|index| editor.owners.unique(*index))
                .map(|index| {
                    let owner = &editor.owners.owners[index];
                    (owner.key.as_ref(), owner.span)
                })
        })
    }

    pub(crate) fn owner_resolution(
        &self,
        key: &ResolutionOwnerKey,
        cancel: &AnalysisCancellation,
    ) -> Result<Option<OwnerResolution>, AnalysisCancelled> {
        cancel.check()?;
        let Some(editor) = &self.editor else {
            return Ok(None);
        };
        let table = &editor.owners;
        let Some(Some(index)) = table.keys.get(key) else {
            return Ok(None);
        };
        if !table.unique(*index) {
            return Ok(None);
        }
        let owner = &table.owners[*index];
        let mut ids = Vec::new();
        for local in owner.locals.clone() {
            cancel.check()?;
            if table.local_owners[local].is_some_and(|(id, _)| id == *index) {
                ids.push(self.locals[local].id);
            }
        }
        let map = OwnerSourceMap {
            span: owner.span,
            locals: ids,
        };
        let mut locals = Vec::new();
        for id in &map.locals {
            cancel.check()?;
            let local = &self.locals[id.index()];
            let Some(declaration) = map.relative_span(local.span) else {
                return Ok(None);
            };
            locals.push(OwnerLocal {
                name: local.name.clone(),
                kind: local.kind,
                declaration,
                scopes: Vec::new(),
            });
        }
        for (_, local, scope) in &editor.locals[owner.scopes.clone()] {
            cancel.check()?;
            if let Some((id, ordinal)) = table.local_owners[local.index()]
                && id == *index
            {
                let Some(scope) = map.relative_span(*scope) else {
                    return Ok(None);
                };
                locals[ordinal as usize].scopes.push(scope);
            }
        }
        let mut references = Vec::new();
        let mut text_budget = MAX_TEXT;
        for reference in owner
            .references
            .clone()
            .filter(|reference| table.reference_owners[*reference] == Some(*index))
        {
            cancel.check()?;
            let reference = &self.references[reference];
            let Some(span) = map.relative_span(reference.span) else {
                return Ok(None);
            };
            let Some(target) = self.owner_target(&reference.target, table, &mut text_budget) else {
                return Ok(None);
            };
            references.push(OwnerReference {
                span,
                kind: reference.kind,
                target,
            });
        }
        // A parent's diagnostic slice can include a default's diagnostics.
        let mut diagnostics = Vec::new();
        for diagnostic in &owner.diagnostics {
            cancel.check()?;
            let nested = owner.children.iter().any(|child| {
                let child = &table.owners[*child];
                map.absolute_span(diagnostic.span)
                    .is_some_and(|span| {
                        child.span.source_id() == span.source_id()
                            && child.span.start() <= span.start()
                            && span.end() <= child.span.end()
                    })
            });
            if !nested {
                diagnostics.push(diagnostic.clone());
            }
        }
        cancel.check()?;
        Ok(Some(OwnerResolution {
            key: owner.key.clone(),
            source_map: map,
            locals,
            references,
            diagnostics,
            diagnostics_truncated: owner.diagnostics_truncated,
            namespace_dependencies: owner.dependencies.clone(),
            namespace_dependencies_complete: owner.dependencies_complete
                && !owner.diagnostics_truncated,
        }))
    }

    fn owner_target(
        &self,
        target: &ResolvedTarget,
        table: &OwnerTable,
        budget: &mut usize,
    ) -> Option<OwnerReferenceTarget> {
        let path = |path: &[String], budget: &mut usize| {
            *budget = budget.checked_sub(path.iter().map(String::len).sum())?;
            Some(path.to_vec())
        };
        Some(match target {
            ResolvedTarget::Local(id) => {
                let (owner, ordinal) = table
                    .local_owners
                    .get(id.index())
                    .copied()
                    .flatten()?;
                if !table.unique(owner) {
                    return None;
                }
                OwnerReferenceTarget::Local {
                    owner: table.owners[owner].key.clone(),
                    ordinal,
                }
            }
            ResolvedTarget::Item(id) => {
                let item = &self.items[id.index()];
                OwnerReferenceTarget::Item {
                    domain: item.domain,
                    path: path(item.path.segments(), budget)?,
                }
            }
            ResolvedTarget::Module(id) => {
                let module = &self.modules[id.index()];
                OwnerReferenceTarget::Module {
                    domain: module.domain,
                    path: path(module.path.segments(), budget)?,
                }
            }
            ResolvedTarget::EnumVariant {
                enumeration,
                index,
            } => {
                let item = &self.items[enumeration.index()];
                OwnerReferenceTarget::EnumVariant {
                    domain: item.domain,
                    path: path(item.path.segments(), budget)?,
                    index: *index,
                }
            }
            ResolvedTarget::ContextualEnumVariant => OwnerReferenceTarget::ContextualEnumVariant,
        })
    }
}

#[cfg(test)]
mod tests;

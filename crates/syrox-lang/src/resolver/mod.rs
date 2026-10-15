//! Binding each name to a declaration it may access.
//!
//! The whole namespace is collected before references are resolved, so declaration
//! order does not determine visibility. An item's identity is its domain and path
//! segments, rather than the text used to display it.
//!
//! [`resolve`] returns a valid resolved program or diagnostics, ready for
//! [`crate::checker`]. Editor analysis uses partial resolution to query declarations
//! already available. [`editor`](../../src/syrox_lang/resolver/editor.rs.html) follows the same visibility rules; [`owners`](../../src/syrox_lang/resolver/owners/mod.rs.html)
//! records facts for comparison between snapshots.

mod body;
mod collections;
mod editor;
mod lookup;
mod model;
mod namespace;
mod owners;

pub use model::{
    CanonicalPath, ItemId, LocalId, LocalKind, ModuleId, PublicationId, PublishedMember,
    ReferenceKind, ResolvedItem, ResolvedItemKind, ResolvedLocal, ResolvedModule,
    ResolvedModuleExport, ResolvedProgram, ResolvedReference, ResolvedTarget,
};
pub use owners::{
    NamespaceDependency, NamespaceExport, NamespaceOutcome, NamespaceQuery, NamespaceTarget,
    OwnerDiagnostic, OwnerLocal, OwnerReference, OwnerReferenceTarget, OwnerRelativeSpan,
    OwnerResolution, OwnerSourceMap, ResolutionOwnerKey, ResolutionOwnerPart,
};

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::{
    MAX_DIAGNOSTICS, diagnostic::Diagnostic, source::SourceDomainId, source::Span, syntax::Block,
    syntax::Expression, syntax::ExpressionKind, syntax::Function, syntax::Item, syntax::ItemKind,
    syntax::Literal, syntax::MatchArm, syntax::ParsedSources, syntax::Path, syntax::Pattern,
    syntax::RefinementKind, syntax::StatementKind, syntax::StringLiteral, syntax::StringPart,
    syntax::Type, syntax::TypeKind,
};

/// Maximum namespace and reference operations performed by one resolution.
pub const MAX_RESOLUTION_WORK: usize = 4_000_000;
pub const MAX_PUBLICATION_METADATA_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub(super) struct PendingItem {
    pub(super) domain: SourceDomainId,
    pub(super) path: Vec<String>,
    pub(super) module_path: Vec<String>,
    pub(super) kind: ResolvedItemKind,
    pub(super) span: Span,
    pub(super) variants: Vec<(String, Span)>,
    pub(super) public: bool,
}

pub(super) type DomainPath = (SourceDomainId, Vec<String>);
pub(super) type BoundarySpans = (Option<Span>, Option<Span>);

#[derive(Clone, Debug, Default)]
pub(super) struct ModuleInfo {
    pub(super) declarations: BTreeMap<String, ItemId>,
    pub(super) children: BTreeMap<String, ModuleId>,
    pub(super) public_children: BTreeSet<String>,
    pub(super) imports: BTreeMap<String, ItemId>,
    pub(super) exports: BTreeMap<String, ItemId>,
    pub(super) closed: bool,
}

#[derive(Clone, Copy)]
pub(super) enum Expected {
    Any,
    Type,
    Function,
    Value,
    Struct,
}

pub(super) struct Resolver<'a> {
    implementation_modules: BTreeSet<ModuleId>,
    contract_modules: BTreeSet<ModuleId>,
    pub(super) parsed: &'a ParsedSources,
    pub(super) modules: Vec<ResolvedModule>,
    pub(super) module_ids: BTreeMap<DomainPath, ModuleId>,
    pub(super) module_info: Vec<ModuleInfo>,
    pub(super) items: Vec<ResolvedItem>,
    pub(super) item_ids: BTreeMap<DomainPath, ItemId>,
    pub(super) input_domains: BTreeMap<SourceDomainId, BTreeMap<String, SourceDomainId>>,
    pub(super) project_owners: BTreeMap<SourceDomainId, SourceDomainId>,
    pub(super) public_imports: BTreeSet<(ModuleId, String)>,
    pub(super) enum_variants: BTreeMap<ItemId, BTreeMap<String, u32>>,
    pub(super) references: Vec<ResolvedReference>,
    pub(super) module_exports: BTreeMap<(usize, u32, u32), Arc<[ResolvedModuleExport]>>,
    pub(super) inventories: BTreeSet<Arc<[ResolvedModuleExport]>>,
    pub(super) export_queries: BTreeMap<(ModuleId, ModuleId, String), Arc<[ResolvedModuleExport]>>,
    pub(super) publications: BTreeMap<PublicationId, Arc<[ResolvedModuleExport]>>,
    pub(super) publication_bytes: usize,
    pub(super) catalog_members: BTreeMap<ItemId, PublishedMember>,
    pub(super) locals: Vec<ResolvedLocal>,
    pub(super) diagnostics: Vec<Diagnostic>,
    pub(super) work: usize,
    pub(super) exhausted: bool,
    pub(super) next_local: u32,
    cancellation: Option<&'a crate::analysis::AnalysisCancellation>,
    editor_locals: Vec<(String, LocalId, Span)>,
    owners: owners::OwnerTable,
}

/// Resolve all names without changing the parsed syntax tree.
pub fn resolve(parsed: ParsedSources) -> Result<ResolvedProgram, Vec<Diagnostic>> {
    let (resolved, diagnostics, _) = resolve_partial(parsed, None);
    if diagnostics.is_empty() {
        Ok(resolved)
    } else {
        Err(diagnostics)
    }
}

pub(crate) fn resolve_partial(
    parsed: ParsedSources,
    cancellation: Option<&crate::analysis::AnalysisCancellation>,
) -> (ResolvedProgram, Vec<Diagnostic>, bool) {
    let mut resolver = Resolver::new(&parsed);
    resolver.cancellation = cancellation;
    resolver.collect();
    resolver.index_project_owners();
    if !resolver.exhausted {
        resolver.bind_interfaces();
        resolver.collect_catalog_members();
        resolver.bind_imports();
        // Imports and synthetic publication namespaces are now complete.
        resolver.export_queries.clear();
        resolver.resolve_contents();
    }
    resolver.diagnostics.sort_by_key(|diagnostic| {
        (
            diagnostic.span.source_id(),
            diagnostic.span.start(),
            diagnostic.message.clone(),
        )
    });
    {
        let visible_members = resolver.visible_publications();
        let modules = std::mem::take(&mut resolver.modules);
        let items = std::mem::take(&mut resolver.items);
        let references = std::mem::take(&mut resolver.references);
        let locals = std::mem::take(&mut resolver.locals);
        let module_exports = std::mem::take(&mut resolver.module_exports);
        let catalog_members = std::mem::take(&mut resolver.catalog_members);
        let publications = std::mem::take(&mut resolver.publications);
        let diagnostics = std::mem::take(&mut resolver.diagnostics);
        let exhausted = resolver.exhausted;
        let editor = if cancellation.is_some() && !exhausted {
            Some(Arc::new(editor::Namespace::take(&mut resolver)))
        } else {
            None
        };
        drop(resolver);
        (
            ResolvedProgram {
                ambiguous_names: std::sync::OnceLock::new(),
                parsed,
                modules,
                items,
                references,
                locals,
                module_exports,
                catalog_members,
                publications,
                visible_members,
                editor,
            },
            diagnostics,
            exhausted,
        )
    }
}

impl<'a> Resolver<'a> {
    fn index_project_owners(&mut self) {
        for (&owner, inputs) in &self.input_domains {
            for &domain in inputs.values() {
                self.work = self.work.saturating_add(1);
                if self.work > MAX_RESOLUTION_WORK {
                    self.exhausted = true;
                    return;
                }
                self.project_owners.insert(domain, owner);
            }
        }
    }

    pub(super) fn new(parsed: &'a ParsedSources) -> Self {
        Self {
            implementation_modules: BTreeSet::new(),
            contract_modules: BTreeSet::new(),
            parsed,
            modules: Vec::new(),
            module_ids: BTreeMap::new(),
            module_info: Vec::new(),
            items: Vec::new(),
            item_ids: BTreeMap::new(),
            input_domains: BTreeMap::new(),
            project_owners: BTreeMap::new(),
            public_imports: BTreeSet::new(),
            enum_variants: BTreeMap::new(),
            references: Vec::new(),
            module_exports: BTreeMap::new(),
            inventories: BTreeSet::new(),
            export_queries: BTreeMap::new(),
            publications: BTreeMap::new(),
            publication_bytes: 0,
            catalog_members: BTreeMap::new(),
            locals: Vec::new(),
            diagnostics: Vec::new(),
            work: 0,
            exhausted: false,
            next_local: 0,
            cancellation: None,
            editor_locals: Vec::new(),
            owners: owners::OwnerTable::default(),
        }
    }

    pub(super) fn charge(&mut self, span: Span) -> bool {
        if self.exhausted {
            return false;
        }
        if self
            .cancellation
            .is_some_and(|cancellation| cancellation.check().is_err())
        {
            self.exhausted = true;
            return false;
        }
        self.work = self.work.saturating_add(1);
        if self.work <= MAX_RESOLUTION_WORK {
            return true;
        }
        if !self.exhausted {
            self.exhausted = true;
            self.error("name resolution work limit reached", span);
        }
        false
    }

    pub(super) fn error(&mut self, message: impl Into<String>, span: Span) {
        if self.diagnostics.len() < MAX_DIAGNOSTICS {
            self.diagnostics.push(
                Diagnostic::error(message, span)
                    .with_code(crate::diagnostic::DiagnosticCode::Resolution),
            );
        }
    }

    pub(super) fn local(
        &mut self,
        name: &crate::syntax::Ident,
        kind: LocalKind,
    ) -> Option<LocalId> {
        let span = name.span;
        if !self.charge(span) {
            return None;
        }
        let id = LocalId(self.next_local);
        let Some(next) = self.next_local.checked_add(1) else {
            self.error("too many local declarations", span);
            return None;
        };
        self.next_local = next;
        self.locals.push(ResolvedLocal {
            id,
            span,
            name: name.text.clone(),
            kind,
        });
        Some(id)
    }

    pub(super) fn walk_items(&self) -> Vec<LocatedItem<'a>> {
        let mut result = Vec::new();
        for source in self.parsed.iter() {
            let domain = source.domain();
            let mut stack: Vec<(&Item, Vec<String>)> = source
                .program()
                .items
                .iter()
                .rev()
                .map(|item| (item, source.module().to_vec()))
                .collect();
            while let Some((item, module_path)) = stack.pop() {
                if let ItemKind::Module(module) = &item.kind {
                    let mut child = module_path.clone();
                    child.extend(
                        module
                            .path
                            .segments
                            .iter()
                            .map(|segment| segment.text.clone()),
                    );
                    for nested in module.items.iter().rev() {
                        stack.push((nested, child.clone()));
                    }
                    if module.contract.is_some() {
                        result.push(LocatedItem {
                            item,
                            domain,
                            module_path,
                        });
                    }
                } else {
                    result.push(LocatedItem {
                        item,
                        domain,
                        module_path,
                    });
                }
            }
        }
        result
    }
}

pub(super) struct LocatedItem<'a> {
    pub(super) item: &'a Item,
    pub(super) domain: SourceDomainId,
    pub(super) module_path: Vec<String>,
}

pub(super) trait SpanKey {
    fn cmp_key(&self, other: &Self) -> std::cmp::Ordering;
}

impl SpanKey for Span {
    fn cmp_key(&self, other: &Self) -> std::cmp::Ordering {
        (self.source_id(), self.start(), self.end()).cmp(&(
            other.source_id(),
            other.start(),
            other.end(),
        ))
    }
}

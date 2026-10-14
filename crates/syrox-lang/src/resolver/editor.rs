//! Editor queries over names already collected by the resolver.
//!
//! Lookup and completion follow resolution's visibility rules, including imports
//! and closed module interfaces.

use super::{
    BTreeMap, BTreeSet, DomainPath, Expected, ItemId, ItemKind, LocalId, ModuleId, ModuleInfo,
    Path, ResolvedProgram, ResolvedTarget, Resolver, SourceDomainId, Span,
};

#[derive(Clone, Debug)]
pub(super) struct Namespace {
    module_ids: BTreeMap<DomainPath, ModuleId>,
    module_info: Vec<ModuleInfo>,
    item_ids: BTreeMap<DomainPath, ItemId>,
    input_domains: BTreeMap<SourceDomainId, BTreeMap<String, SourceDomainId>>,
    pub(super) locals: Vec<(String, LocalId, Span)>,
    pub(super) owners: super::owners::OwnerTable,
}

impl Namespace {
    pub(super) fn take(resolver: &mut Resolver<'_>) -> Self {
        Self {
            module_ids: std::mem::take(&mut resolver.module_ids),
            module_info: std::mem::take(&mut resolver.module_info),
            item_ids: std::mem::take(&mut resolver.item_ids),
            input_domains: std::mem::take(&mut resolver.input_domains),
            locals: std::mem::take(&mut resolver.editor_locals),
            owners: std::mem::take(&mut resolver.owners),
        }
    }
}

impl ResolvedProgram {
    pub(crate) fn editor_module_at(
        &self,
        source: crate::source::SourceId,
        offset: u32,
    ) -> Option<ModuleId> {
        let file = self
            .parsed
            .iter()
            .find(|file| file.source_id() == source)?;
        let mut path = file.module().to_vec();
        let mut items = &file.program().items;
        while let Some(module) = items.iter().find_map(|item| {
            if item.span.start() <= offset
                && offset <= item.span.end()
                && let ItemKind::Module(module) = &item.kind
            {
                Some(module)
            } else {
                None
            }
        }) {
            path.extend(
                module
                    .path
                    .segments
                    .iter()
                    .map(|part| part.text.clone()),
            );
            items = &module.items;
        }
        self.editor
            .as_ref()?
            .module_ids
            .get(&(file.domain(), path))
            .copied()
    }
    fn query(&self) -> Option<Resolver<'_>> {
        let namespace = self.editor.as_ref()?;
        let mut resolver = Resolver::new(&self.parsed);
        resolver.modules.clone_from(&self.modules);
        resolver.items.clone_from(&self.items);
        resolver
            .module_ids
            .clone_from(&namespace.module_ids);
        resolver
            .module_info
            .clone_from(&namespace.module_info);
        resolver.item_ids.clone_from(&namespace.item_ids);
        resolver
            .input_domains
            .clone_from(&namespace.input_domains);
        resolver
            .catalog_members
            .clone_from(&self.catalog_members);
        resolver.index_project_owners();
        Some(resolver)
    }

    pub(crate) fn editor_lookup(
        &self,
        source: crate::source::SourceId,
        offset: u32,
        parts: &[String],
    ) -> Option<ResolvedTarget> {
        if parts.len() == 1
            && let Some((_, local)) = self
                .editor_locals_at(source, offset, false)
                .into_iter()
                .find(|(name, _)| name == &parts[0])
        {
            return Some(ResolvedTarget::Local(local));
        }
        let mut resolver = self.query()?;
        let module = resolver.module_at(source, offset)?;
        resolver.lookup(
            module,
            &query_path(source, offset, parts),
            Expected::Any,
        )
    }

    pub(crate) fn editor_completions(
        &self,
        source: crate::source::SourceId,
        offset: u32,
        qualifier: &[String],
        prefix: &str,
        types_only: bool,
    ) -> Vec<(String, ResolvedTarget)> {
        let Some(mut resolver) = self.query() else {
            return Vec::new();
        };
        let Some(module) = resolver.module_at(source, offset) else {
            return Vec::new();
        };
        let mut names = BTreeSet::new();
        // Enumerate the requested namespace (and parents for a bare path), then
        // validate each whole spelling. Reexports retain their exported name.
        if qualifier.first().is_some_and(|first| {
            self.editor_locals_at(source, offset, types_only)
                .contains_key(first)
        }) {
            return Vec::new();
        }
        let mut scope = resolver.completion_scope(module, &query_path(source, offset, qualifier));
        while let Some(id) = scope {
            let info = &resolver.module_info[id.index()];
            names.extend(
                info.declarations
                    .keys()
                    .chain(info.imports.keys())
                    .chain(info.exports.keys())
                    .chain(info.children.keys())
                    .filter(|name| name.starts_with(prefix))
                    .cloned(),
            );
            scope = if qualifier.is_empty() {
                resolver.parent(id)
            } else {
                None
            };
        }
        let mut found = Vec::new();
        if qualifier.is_empty() {
            found.extend(
                self.editor_locals_at(source, offset, types_only)
                    .into_iter()
                    .filter(|(name, _)| name.starts_with(prefix))
                    .map(|(name, id)| (name, ResolvedTarget::Local(id))),
            );
            if let Some(aliases) = resolver
                .input_domains
                .get(&resolver.modules[module.index()].domain)
            {
                for (name, domain) in aliases {
                    if name.starts_with(prefix)
                        && !found.iter().any(|(existing, _)| existing == name)
                        && let Some(id) = resolver.module_ids.get(&(*domain, Vec::new()))
                    {
                        found.push((name.clone(), ResolvedTarget::Module(*id)));
                    }
                }
            }
            if "std".starts_with(prefix)
                && !found.iter().any(|(name, _)| name == "std")
                && let Some(id) = resolver.module_ids.get(&(
                    SourceDomainId::STANDARD_LIBRARY,
                    vec!["std".into()],
                ))
            {
                found.push(("std".into(), ResolvedTarget::Module(*id)));
            }
            if "project".starts_with(prefix)
                && let Some(owner) = resolver.project_owner(module)
                && let Some(id) = resolver.module_ids.get(&(owner, Vec::new()))
            {
                found.push(("project".into(), ResolvedTarget::Module(*id)));
            }
        }
        for name in names {
            if found
                .iter()
                .any(|(existing, _)| existing == &name)
            {
                continue;
            }
            let mut parts = qualifier.to_vec();
            parts.push(name.clone());
            if let Some(target) = resolver.lookup(
                module,
                &query_path(source, offset, &parts),
                Expected::Any,
            ) {
                if types_only
                    && matches!(&target, ResolvedTarget::Item(item) if !resolver.items[item.index()].kind.is_type())
                {
                    continue;
                }
                if let ResolvedTarget::Module(child) = target
                    && !resolver.module_visible(module, child)
                {
                    continue;
                }
                found.push((name, target));
            }
            if found.len() >= 256 || resolver.exhausted {
                break;
            }
        }
        found.truncate(256);
        found
    }

    fn editor_locals_at(
        &self,
        source: crate::source::SourceId,
        offset: u32,
        types_only: bool,
    ) -> BTreeMap<String, LocalId> {
        let mut found = BTreeMap::new();
        if let Some(namespace) = &self.editor {
            let mut scopes: Vec<_> = namespace
                .locals
                .iter()
                .filter(|(_, id, span)| {
                    span.source_id() == source
                        && span.start() <= offset
                        && offset < span.end()
                        && (!types_only
                            || self.locals[id.index()].kind == super::LocalKind::TypeParameter)
                })
                .collect();
            scopes.sort_by_key(|(_, _, span)| (span.start(), std::cmp::Reverse(span.end())));
            for (name, id, _) in scopes {
                found.insert(name.clone(), *id);
            }
        }
        found
    }
}

impl Resolver<'_> {
    fn completion_scope(&mut self, module: ModuleId, path: &Path) -> Option<ModuleId> {
        if path.segments.is_empty() {
            return Some(module);
        }
        if path.segments.len() == 1 {
            let first = &path.segments[0].text;
            if first == "project" {
                let owner = self.project_owner(module)?;
                return self.module_ids.get(&(owner, Vec::new())).copied();
            }
            if first == "std" {
                return self
                    .module_ids
                    .get(&(
                        SourceDomainId::STANDARD_LIBRARY,
                        vec!["std".into()],
                    ))
                    .copied();
            }
            if let Some(domain) = self
                .input_domains
                .get(&self.modules[module.index()].domain)
                .and_then(|aliases| aliases.get(first))
            {
                return self
                    .module_ids
                    .get(&(*domain, Vec::new()))
                    .copied();
            }
        }
        match self.lookup(module, path, Expected::Any) {
            Some(ResolvedTarget::Module(id)) => Some(id),
            _ => None,
        }
    }

    pub(super) fn editor_local(&mut self, name: &crate::syntax::Ident, id: LocalId, scope: Span) {
        if self.cancellation.is_some() {
            self.editor_locals
                .push((name.text.clone(), id, scope));
        }
    }

    fn module_visible(&self, requester: ModuleId, child: ModuleId) -> bool {
        let mut current = child;
        while let Some(parent) = self.parent(current) {
            let boundary = &self.modules[parent.index()];
            if (self.module_info[parent.index()].closed
                || (self.modules[requester.index()].domain != boundary.domain
                    && !boundary.path.segments.is_empty()))
                && !self.is_descendant(requester, parent)
            {
                let name = self.modules[current.index()]
                    .path
                    .segments
                    .last()
                    .expect("child module name");
                if !self.module_info[parent.index()]
                    .public_children
                    .contains(name)
                {
                    return false;
                }
            }
            current = parent;
        }
        true
    }
    fn module_at(&self, source: crate::source::SourceId, offset: u32) -> Option<ModuleId> {
        let file = self
            .parsed
            .iter()
            .find(|file| file.source_id() == source)?;
        let mut path = file.module().to_vec();
        let mut items = &file.program().items;
        loop {
            let nested = items.iter().find_map(|item| {
                if item.span.start() <= offset
                    && offset < item.span.end()
                    && let ItemKind::Module(module) = &item.kind
                {
                    return Some(module);
                }
                None
            });
            let Some(nested) = nested else {
                break;
            };
            path.extend(
                nested
                    .path
                    .segments
                    .iter()
                    .map(|part| part.text.clone()),
            );
            items = &nested.items;
        }
        self.module_ids
            .get(&(file.domain(), path))
            .copied()
    }
}

fn query_path(source: crate::source::SourceId, offset: u32, parts: &[String]) -> Path {
    let span = Span::new(source, offset, offset);
    Path {
        span,
        segments: parts
            .iter()
            .map(|text| crate::syntax::Ident {
                text: text.clone(),
                span,
            })
            .collect(),
    }
}

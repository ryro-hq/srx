use super::{
    Arc, BTreeSet, CanonicalPath, Expected, ItemId, ItemKind, ModuleId, ModuleInfo, Path,
    PublishedMember, ReferenceKind, ResolvedItem, ResolvedItemKind, ResolvedModule,
    ResolvedModuleExport, ResolvedReference, ResolvedTarget, Resolver, Span,
};

impl Resolver<'_> {
    /// Inventory is structural: no output, set expression or factory is evaluated.
    pub(super) fn collect_catalog_members(&mut self) {
        let mut published_modules = BTreeSet::new();
        for source in self.parsed.iter() {
            if !self.parsed.is_project_root(source.domain()) || !source.module().is_empty() {
                continue;
            }
            for item in &source.program().items {
                let ItemKind::Publication(publication) = &item.kind else {
                    continue;
                };
                let owner = super::PublicationId(
                    u32::try_from(self.publications.len()).expect("bounded publications"),
                );
                let references = self.references.len();
                self.resolve_module_exports(
                    self.module_ids[&(source.domain(), Vec::new())],
                    &publication.namespace,
                    &publication.export,
                    item.span,
                );
                self.references.truncate(references);
                let Some(entries) = self
                    .module_exports
                    .get(&(
                        item.span.source_id().index(),
                        item.span.start(),
                        item.span.end(),
                    ))
                    .cloned()
                else {
                    continue;
                };
                if !self.reserve_publication(
                    size_of::<(super::PublicationId, Arc<[ResolvedModuleExport]>)>(),
                    item.span,
                ) {
                    return;
                }
                self.publications.insert(owner, entries.clone());
                for index in 0..entries.len() {
                    self.publish_member(
                        source.domain(),
                        owner,
                        entries.clone(),
                        index,
                        item.span,
                        &mut published_modules,
                    );
                }
                self.export_queries.clear();
            }
        }
    }

    pub(super) fn visible_publications(
        &mut self,
    ) -> std::collections::BTreeMap<
        crate::source::SourceDomainId,
        std::collections::BTreeMap<String, ItemId>,
    > {
        let mut result = std::collections::BTreeMap::new();
        for source in self.parsed.iter() {
            if !self.parsed.is_project_root(source.domain()) || !source.module().is_empty() {
                continue;
            }
            let Some(first) = source.program().items.first() else {
                continue;
            };
            let span = first.span;
            let Some(&root) = self
                .module_ids
                .get(&(source.domain(), Vec::new()))
            else {
                continue;
            };
            let mut pending = vec![(Vec::<String>::new(), root)];
            let mut entries = std::collections::BTreeMap::new();
            while let Some((path, module)) = pending.pop() {
                if !self.charge(span) {
                    return std::collections::BTreeMap::new();
                }
                let info = &self.module_info[module.index()];
                let clone_bytes = info
                    .exports
                    .keys()
                    .chain(info.public_children.iter())
                    .fold(0usize, |sum, name| {
                        sum.saturating_add(name.len() + 64)
                    });
                if !self.reserve_publication(clone_bytes, span) {
                    return std::collections::BTreeMap::new();
                }
                let exports = self.module_info[module.index()].exports.clone();
                for (name, item) in exports {
                    if !self.charge(span) {
                        return std::collections::BTreeMap::new();
                    }
                    if self.catalog_members.contains_key(&item) {
                        let bytes = path.iter().map(String::len).sum::<usize>()
                            + name.len()
                            + path.len() * 2;
                        if !self.reserve_publication(bytes + size_of::<(String, ItemId)>(), span) {
                            return std::collections::BTreeMap::new();
                        }
                        let key = if path.is_empty() {
                            name
                        } else {
                            format!("{}::{name}", path.join("::"))
                        };
                        entries.insert(key, item);
                    }
                }
                let children = self.module_info[module.index()]
                    .public_children
                    .clone();
                for name in children {
                    if !self.charge(span) {
                        return std::collections::BTreeMap::new();
                    }
                    if let Some(&child) = self.module_info[module.index()]
                        .children
                        .get(&name)
                    {
                        if !self.reserve_publication(
                            name.len()
                                + path.iter().map(String::len).sum::<usize>()
                                + (path.len() + 1) * size_of::<String>()
                                + size_of::<(Vec<String>, ModuleId)>(),
                            span,
                        ) {
                            return std::collections::BTreeMap::new();
                        }
                        let mut next = path.clone();
                        next.push(name);
                        pending.push((next, child));
                    }
                }
            }
            result.insert(source.domain(), entries);
        }
        result
    }

    // Ordered resolution keeps visibility and dependency observations aligned.
    fn publish_member(
        &mut self,
        domain: crate::source::SourceDomainId,
        publication: super::PublicationId,
        inventory: Arc<[ResolvedModuleExport]>,
        index: usize,
        span: Span,
        published_modules: &mut BTreeSet<(crate::source::SourceDomainId, Vec<String>)>,
    ) {
        if !self.charge(span) {
            return;
        }
        let key = inventory[index].key();
        // Prefix modules, symbol paths, namespace keys and index nodes are all
        // bounded before allocation, including unsuccessful collision attempts.
        let depth = key.split("::").count();
        let bytes = depth.saturating_mul(
            key.len()
                .saturating_add(depth * size_of::<String>())
                .saturating_add(256),
        );
        if !self.reserve_publication(bytes, span) {
            return;
        }
        let path = key
            .split("::")
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if path.iter().any(String::is_empty) {
            self.error("catalog member has an empty path segment", span);
            return;
        }
        if self
            .item_ids
            .contains_key(&(domain, path.clone()))
            || self
                .module_ids
                .contains_key(&(domain, path.clone()))
        {
            self.error(
                "catalog member conflicts with a declared output",
                span,
            );
            return;
        }
        let mut parent = self.module_ids[&(domain, Vec::new())];
        let mut prefix = Vec::new();
        let mut conflict = false;
        for segment in &path[..path.len() - 1] {
            if !self.charge(span) {
                return;
            }
            prefix.push(segment.clone());
            if self
                .item_ids
                .contains_key(&(domain, prefix.clone()))
                || (prefix.len() == 1
                    && self
                        .input_domains
                        .get(&domain)
                        .is_some_and(|inputs| inputs.contains_key(segment)))
                || (prefix.len() == 1
                    && (self.module_info[parent.index()]
                        .imports
                        .contains_key(segment)
                        || self.module_info[parent.index()]
                            .exports
                            .contains_key(segment)))
                || self
                    .module_ids
                    .contains_key(&(domain, prefix.clone()))
                    && !published_modules.contains(&(domain, prefix.clone()))
            {
                conflict = true;
                break;
            }
        }
        if conflict {
            self.error(
                "catalog member conflicts with a declared namespace",
                span,
            );
            return;
        }
        prefix.clear();
        for segment in &path[..path.len() - 1] {
            prefix.push(segment.clone());
            if let Some(&existing) = self.module_ids.get(&(domain, prefix.clone())) {
                parent = existing;
            } else {
                let id = ModuleId(
                    u32::try_from(self.modules.len()).expect("source limits bound modules"),
                );
                self.module_ids
                    .insert((domain, prefix.clone()), id);
                published_modules.insert((domain, prefix.clone()));
                self.modules.push(ResolvedModule {
                    id,
                    domain,
                    path: CanonicalPath {
                        segments: prefix.clone(),
                    },
                });
                self.module_info.push(ModuleInfo::default());
                self.module_info[parent.index()]
                    .children
                    .insert(segment.clone(), id);
                parent = id;
            }
            self.module_info
                [self.module_ids[&(domain, prefix[..prefix.len() - 1].to_vec())].index()]
            .public_children
            .insert(segment.clone());
        }
        let name = path
            .last()
            .expect("module export has a name")
            .clone();
        if self.module_info[parent.index()]
            .exports
            .contains_key(&name)
            || self.module_info[parent.index()]
                .imports
                .contains_key(&name)
        {
            self.error(
                "catalog member conflicts with a declared output",
                span,
            );
            return;
        }
        let id = ItemId(u32::try_from(self.items.len()).expect("source limits bound items"));
        self.item_ids.insert((domain, path.clone()), id);
        self.items.push(ResolvedItem {
            id,
            domain,
            module: parent,
            path: CanonicalPath {
                segments: path,
            },
            kind: ResolvedItemKind::PublishedMember,
            span,
        });
        self.module_info[parent.index()]
            .declarations
            .insert(name.clone(), id);
        self.module_info[parent.index()]
            .exports
            .insert(name, id);
        self.catalog_members.insert(
            id,
            PublishedMember {
                publication,
                inventory,
                index,
            },
        );
    }

    pub(super) fn resolve_module_exports(
        &mut self,
        requester: ModuleId,
        namespace: &Path,
        export: &crate::syntax::Ident,
        span: Span,
    ) {
        if self.cancellation.is_none() {
            self.resolve_module_exports_inner(requester, namespace, export, span);
            return;
        }
        let diagnostics = self.diagnostics.len();
        let reference = self.references.len();
        self.resolve_module_exports_inner(requester, namespace, export, span);
        let root = self
            .references
            .get(reference)
            .map(|reference| reference.target.clone());
        let key = (span.source_id().index(), span.start(), span.end());
        let entries = self.module_exports.remove(&key);
        self.observe_namespace(
            requester,
            namespace,
            span,
            super::NamespaceQuery::ModuleExports {
                export: export.text.clone(),
            },
            super::owners::ObservedNamespace::Exports {
                root: root.as_ref(),
                entries: entries.as_deref(),
            },
            diagnostics,
        );
        if let Some(entries) = entries {
            self.module_exports.insert(key, entries);
        }
    }

    // Ordered resolution keeps visibility and dependency observations aligned.
    fn resolve_module_exports_inner(
        &mut self,
        requester: ModuleId,
        namespace: &Path,
        export: &crate::syntax::Ident,
        span: Span,
    ) {
        let target = self.collection_namespace(requester, namespace);
        let Some(ResolvedTarget::Module(root)) = target else {
            self.error(
                "module_exports requires a module namespace",
                namespace.span,
            );
            return;
        };
        self.references.push(ResolvedReference {
            span: namespace.span,
            kind: ReferenceKind::Value,
            target: ResolvedTarget::Module(root),
        });
        let query_bytes = export
            .text
            .len()
            .saturating_add(size_of::<(ModuleId, ModuleId, String)>() + 96);
        if !self.reserve_publication(query_bytes, span) {
            return;
        }
        let query = (requester, root, export.text.clone());
        let span_key = (span.source_id().index(), span.start(), span.end());
        if let Some(shared) = self.export_queries.get(&query).cloned() {
            if !self.charge(span)
                || !self.reserve_publication(
                    size_of::<((usize, u32, u32), Arc<[ResolvedModuleExport]>)>() + 64,
                    span,
                )
            {
                return;
            }
            self.module_exports.insert(span_key, shared);
            return;
        }
        let diagnostic_count = self.diagnostics.len();
        let domain = self.modules[root.index()].domain;
        let prefix = &self.modules[root.index()].path.segments;
        let prefix_bytes =
            prefix.iter().map(String::len).sum::<usize>() + prefix.len() * size_of::<String>();
        if !self.reserve_publication(prefix_bytes, span) {
            return;
        }
        let prefix = self.modules[root.index()].path.segments.clone();
        let mut entries = Vec::new();
        let mut key_bytes = 0_usize;
        for index in 0..self.modules.len() {
            if !self.charge(span) {
                return;
            }
            let module = &self.modules[index];
            if module.domain != domain || !module.path.segments.starts_with(&prefix) {
                continue;
            }
            let Some(&item) = self.module_info[index].exports.get(&export.text) else {
                continue;
            };
            let owner = module.id;
            let bytes = module
                .path
                .segments
                .iter()
                .map(String::len)
                .sum::<usize>()
                .saturating_add(module.path.segments.len().saturating_mul(2))
                .saturating_add(export.text.len());
            for _ in 0..bytes.saturating_add(1) {
                if !self.charge(span) {
                    return;
                }
            }
            if !self.reserve_publication(
                bytes + self.modules[index].path.segments.len() * size_of::<String>(),
                span,
            ) {
                return;
            }
            let mut candidate = self.modules[index].path.segments.clone();
            candidate.push(export.text.clone());
            let Some(item) =
                self.visible_from_module(requester, owner, item, &candidate, export.span)
            else {
                continue;
            };
            if self.items[item.index()].kind != ResolvedItemKind::Function {
                self.error(
                    format!(
                        "module export `{}` must be a function",
                        candidate.join("::")
                    ),
                    export.span,
                );
                continue;
            }
            if self
                .contract_modules
                .contains(&self.items[item.index()].module)
            {
                continue;
            }
            let relative = &candidate[prefix.len()..candidate.len() - 1];
            if !self.reserve_publication(
                bytes.saturating_add(2 * size_of::<ResolvedModuleExport>()),
                span,
            ) {
                return;
            }
            let key = relative.join("::");
            key_bytes = key_bytes.saturating_add(key.len().saturating_add(1));
            entries.push(ResolvedModuleExport {
                key,
                item,
            });
        }
        // Structural path order differs from byte order when one path is a
        // prefix of another (e.g. a::x versus a0), so sort the actual keys.
        let levels = usize::try_from(entries.len().checked_ilog2().unwrap_or(0) + 1)
            .expect("logarithm fits usize");
        for _ in 0..key_bytes.saturating_mul(levels).saturating_mul(2) {
            if !self.charge(span) {
                return;
            }
        }
        entries.sort_by(|left, right| left.key.cmp(&right.key));
        let levels = self
            .inventories
            .len()
            .checked_ilog2()
            .unwrap_or(0) as usize
            + 1;
        for _ in 0..key_bytes
            .saturating_add(entries.len())
            .saturating_mul(levels)
        {
            if !self.charge(span) {
                return;
            }
        }
        let entries = if let Some(shared) = self.inventories.get(entries.as_slice()) {
            shared.clone()
        } else {
            let shared: Arc<[ResolvedModuleExport]> = entries.into();
            self.inventories.insert(shared.clone());
            shared
        };
        if !self.reserve_publication(
            size_of::<((usize, u32, u32), Arc<[ResolvedModuleExport]>)>() + 64,
            span,
        ) {
            return;
        }
        if self.diagnostics.len() == diagnostic_count {
            self.export_queries.insert(query, entries.clone());
        }
        self.module_exports.insert(
            (span.source_id().index(), span.start(), span.end()),
            entries,
        );
    }

    fn reserve_publication(&mut self, bytes: usize, span: Span) -> bool {
        self.publication_bytes = self.publication_bytes.saturating_add(bytes);
        if self.publication_bytes > super::MAX_PUBLICATION_METADATA_BYTES {
            if !self.exhausted {
                self.error("publication metadata byte limit reached", span);
            }
            self.exhausted = true;
            return false;
        }
        true
    }

    fn collection_namespace(
        &mut self,
        requester: ModuleId,
        namespace: &Path,
    ) -> Option<ResolvedTarget> {
        if namespace.segments.len() == 1 {
            let alias = &namespace.segments[0].text;
            let domain = self
                .input_domains
                .get(&self.modules[requester.index()].domain)
                .and_then(|inputs| inputs.get(alias))
                .copied();
            if let Some(root) = domain.and_then(|domain| {
                self.module_ids
                    .get(&(domain, Vec::new()))
                    .copied()
            }) {
                return Some(ResolvedTarget::Module(root));
            }
        }
        self.lookup(requester, namespace, Expected::Any)
    }
}

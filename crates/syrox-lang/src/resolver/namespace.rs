use super::{
    BTreeMap, BTreeSet, BoundarySpans, CanonicalPath, DomainPath, Expected, Item, ItemId, ItemKind,
    ModuleId, ModuleInfo, Path, PendingItem, ReferenceKind, ResolvedItem, ResolvedItemKind,
    ResolvedModule, ResolvedReference, ResolvedTarget, Resolver, Span, SpanKey, Type, TypeKind,
};

impl Resolver<'_> {
    // One collection traversal preserves registration and duplicate-diagnostic order.
    pub(super) fn collect(&mut self) {
        let mut module_paths = BTreeSet::new();
        let mut public_paths = BTreeSet::new();
        let mut contract_paths = BTreeSet::new();
        let mut pending = Vec::new();
        let mut boundaries: BTreeMap<DomainPath, BoundarySpans> = BTreeMap::new();

        for source in self.parsed.iter() {
            let domain = source.domain();
            module_paths.insert((domain, Vec::new()));
            for depth in 1..=source.module().len() {
                let prefix = source.module()[..depth].to_vec();
                module_paths.insert((domain, prefix.clone()));
                public_paths.insert((domain, prefix));
            }
            let mut stack: Vec<(&Item, Vec<String>)> = source
                .program()
                .items
                .iter()
                .rev()
                .map(|item| (item, source.module().to_vec()))
                .collect();
            while let Some((item, module_path)) = stack.pop() {
                if !self.charge(item.span) {
                    return;
                }
                match &item.kind {
                    ItemKind::Module(module) => {
                        let mut child = module_path;
                        for segment in &module.path.segments {
                            if !self.charge(segment.span) {
                                return;
                            }
                            child.push(segment.text.clone());
                            module_paths.insert((domain, child.clone()));
                            if item.public {
                                public_paths.insert((domain, child.clone()));
                            }
                        }
                        for nested in module.items.iter().rev() {
                            stack.push((nested, child.clone()));
                        }
                        if module.contract.is_some() {
                            contract_paths.insert((domain, child));
                        }
                    }
                    ItemKind::Inputs(inputs) => {
                        if !self.parsed.is_project_root(domain) || !module_path.is_empty() {
                            self.error(
                                "`inputs` blocks are only allowed at the project root",
                                item.span,
                            );
                            continue;
                        }
                        for input in &inputs.entries {
                            if input.name.text == "project" {
                                self.error(
                                    "`project` is reserved for the owning project namespace",
                                    input.name.span,
                                );
                                continue;
                            }
                            if let Some(child) = self.parsed.input_domain(domain, &input.name.text)
                            {
                                self.input_domains
                                    .entry(domain)
                                    .or_default()
                                    .insert(input.name.text.clone(), child);
                            }
                        }
                        let entry = boundaries
                            .entry((domain, module_path))
                            .or_default();
                        if entry.0.replace(item.span).is_some() {
                            self.error("duplicate `inputs` boundary in module", item.span);
                        }
                    }
                    ItemKind::Outputs(outputs) => {
                        let entry = boundaries
                            .entry((domain, module_path.clone()))
                            .or_default();
                        if let Some(first) = entry.1 {
                            if first.source_id() == item.span.source_id() {
                                self.error(
                                    "duplicate `outputs` boundary in module",
                                    item.span,
                                );
                            }
                        } else {
                            entry.1 = Some(item.span);
                        }
                        for output in &outputs.entries {
                            if !self.charge(output.span) {
                                return;
                            }
                            let crate::syntax::OutputKind::Value {
                                name,
                                ..
                            } = &output.kind
                            else {
                                continue;
                            };
                            let mut path = module_path.clone();
                            path.push(name.text.clone());
                            pending.push(PendingItem {
                                domain,
                                path,
                                module_path: module_path.clone(),
                                kind: ResolvedItemKind::OutputValue,
                                span: output.span,
                                variants: Vec::new(),
                                public: false,
                            });
                        }
                    }
                    _ => {
                        if let Some((name, kind, span)) = declaration(item) {
                            let variants = if let ItemKind::Enum(enumeration) = &item.kind {
                                let mut variants = Vec::with_capacity(enumeration.variants.len());
                                for variant in &enumeration.variants {
                                    if !self.charge(variant.name.span) {
                                        return;
                                    }
                                    variants.push((variant.name.text.clone(), variant.name.span));
                                }
                                variants
                            } else {
                                Vec::new()
                            };
                            let mut path = module_path.clone();
                            path.push(name.to_owned());
                            pending.push(PendingItem {
                                domain,
                                path,
                                module_path,
                                kind,
                                span,
                                variants,
                                public: item.public,
                            });
                        }
                    }
                }
            }
        }

        for (index, (domain, path)) in module_paths.into_iter().enumerate() {
            let id = ModuleId(u32::try_from(index).expect("source limits bound module IDs"));
            self.module_ids.insert((domain, path.clone()), id);
            self.modules.push(ResolvedModule {
                id,
                domain,
                path: CanonicalPath {
                    segments: path,
                },
            });
            self.module_info.push(ModuleInfo::default());
        }
        for module in &self.modules {
            if contract_paths.contains(&(module.domain, module.path.segments.clone())) {
                self.contract_modules.insert(module.id);
            }
            if let Some((name, parent)) = module.path.segments.split_last() {
                let parent_id = self.module_ids[&(module.domain, parent.to_vec())];
                self.module_info[parent_id.index()]
                    .children
                    .insert(name.clone(), module.id);
                if public_paths.contains(&(module.domain, module.path.segments.clone())) {
                    self.module_info[parent_id.index()]
                        .public_children
                        .insert(name.clone());
                }
            }
        }
        for ((domain, path), (_, outputs)) in boundaries {
            if outputs.is_some() {
                let id = self.module_ids[&(domain, path)];
                self.module_info[id.index()].closed = true;
            }
        }
        for module in &self.modules {
            if module.path.segments.is_empty() && self.parsed.is_input_domain(module.domain) {
                self.module_info[module.id.index()].closed = true;
            }
        }

        pending.sort_by(|left, right| {
            left.domain.cmp(&right.domain).then(
                left.path
                    .cmp(&right.path)
                    .then(left.span.cmp_key(&right.span)),
            )
        });
        for declaration in pending {
            if !self.charge(declaration.span) {
                return;
            }
            let key = (declaration.domain, declaration.path.clone());
            if let Some(&existing) = self.item_ids.get(&key) {
                let first = self.items[existing.index()].span;
                self.error(
                    "duplicate item declaration in module",
                    declaration.span,
                );
                if first == declaration.span {
                    continue;
                }
                continue;
            }
            if self.module_ids.contains_key(&key) {
                self.error(
                    "name is declared as both a module and an item",
                    declaration.span,
                );
                continue;
            }
            let id = ItemId(u32::try_from(self.items.len()).expect("source limits bound item IDs"));
            let module = self.module_ids[&(declaration.domain, declaration.module_path)];
            let name = declaration
                .path
                .last()
                .expect("items have names")
                .clone();
            self.item_ids.insert(key, id);
            self.module_info[module.index()]
                .declarations
                .insert(name.clone(), id);
            if declaration.public {
                self.module_info[module.index()]
                    .exports
                    .insert(name, id);
            }
            self.items.push(ResolvedItem {
                id,
                domain: declaration.domain,
                module,
                path: CanonicalPath {
                    segments: declaration.path,
                },
                kind: declaration.kind,
                span: declaration.span,
            });
            if !declaration.variants.is_empty() {
                let mut variants = BTreeMap::new();
                for (index, (name, span)) in declaration.variants.into_iter().enumerate() {
                    let Ok(index) = u32::try_from(index) else {
                        self.error("too many enum variants", span);
                        break;
                    };
                    self.contextual_variants
                        .entry(name.clone())
                        .or_insert((id, index));
                    if variants.insert(name, index).is_some() {
                        self.error("duplicate enum variant", span);
                    }
                }
                self.enum_variants.insert(id, variants);
            }
        }
    }

    pub(super) fn bind_interfaces(&mut self) {
        // Value outputs have synthetic declarations collected above. Install
        // them and validate names before resolving graph edges.
        let mut exported_names = BTreeSet::new();
        for module in &self.modules {
            for name in self.module_info[module.id.index()].exports.keys() {
                exported_names.insert((
                    module.domain,
                    module.path.segments.clone(),
                    name.clone(),
                ));
            }
        }
        for located in self.walk_items() {
            if !self.charge(located.item.span) {
                return;
            }
            let module = self.module_ids[&(located.domain, located.module_path.clone())];
            match &located.item.kind {
                ItemKind::Outputs(outputs) => {
                    let mut names = BTreeSet::new();
                    for output in &outputs.entries {
                        if !self.charge(output.span) {
                            return;
                        }
                        let name = match &output.kind {
                            crate::syntax::OutputKind::Value {
                                name,
                                ..
                            }
                            | crate::syntax::OutputKind::Type {
                                name,
                                ..
                            } => &name.text,
                        };
                        if !names.insert(name.clone()) {
                            self.error("duplicate output name", output.span);
                            continue;
                        }
                        if !exported_names.insert((
                            located.domain,
                            located.module_path.clone(),
                            name.clone(),
                        )) {
                            self.error("duplicate output name", output.span);
                            continue;
                        }
                        if matches!(
                            output.kind,
                            crate::syntax::OutputKind::Value { .. }
                        ) {
                            let export_path = append(&located.module_path, name);
                            if let Some(&target) = self.item_ids.get(&(located.domain, export_path))
                            {
                                self.module_info[module.index()]
                                    .exports
                                    .insert(name.clone(), target);
                            }
                        }
                    }
                }
                ItemKind::Inputs(inputs) => {
                    let mut names = BTreeSet::new();
                    for input in &inputs.entries {
                        if !self.charge(input.span) {
                            return;
                        }
                        if !names.insert(&input.name.text) {
                            self.error("duplicate input name", input.span);
                        }
                    }
                }
                _ => {}
            }
        }

        loop {
            let exports_changed = self.bind_remaining_exports(false);
            let imports_changed = self.bind_all_imports(false);
            if self.exhausted || (!exports_changed && !imports_changed) {
                break;
            }
        }
    }

    pub(super) fn bind_imports(&mut self) {
        if self.exhausted {
            return;
        }
        loop {
            let exports_changed = self.bind_remaining_exports(false);
            let imports_changed = self.bind_all_imports(false);
            if self.exhausted || (!exports_changed && !imports_changed) {
                break;
            }
        }
        if !self.exhausted {
            self.bind_remaining_exports(true);
            self.bind_all_imports(true);
        }
    }

    pub(super) fn bind_all_imports(&mut self, report_missing: bool) -> bool {
        let mut changed = false;
        for located in self.walk_items() {
            if !self.charge(located.item.span) {
                return changed;
            }
            let module = self.module_ids[&(located.domain, located.module_path.clone())];
            let ItemKind::Use(import) = &located.item.kind else {
                continue;
            };
            if let Some(names) = &import.names {
                for name in names {
                    if !self.charge(name.span) {
                        return changed;
                    }
                    let mut path = import.path.clone();
                    path.segments.push(name.clone());
                    path.span = import.path.span.join(name.span);
                    changed |= self.bind_import(
                        module,
                        &path,
                        &name.text,
                        located.item.span,
                        report_missing,
                        located.item.public,
                    );
                }
            } else if let Some(name) = import.path.segments.last() {
                changed |= self.bind_import(
                    module,
                    &import.path,
                    &name.text,
                    located.item.span,
                    report_missing,
                    located.item.public,
                );
            }
        }
        changed
    }

    pub(super) fn bind_remaining_exports(&mut self, report_missing: bool) -> bool {
        let mut changed = false;
        for located in self.walk_items() {
            if !self.charge(located.item.span) {
                return changed;
            }
            let module = self.module_ids[&(located.domain, located.module_path.clone())];
            let ItemKind::Outputs(outputs) = &located.item.kind else {
                continue;
            };
            for output in &outputs.entries {
                if !self.charge(output.span) {
                    return changed;
                }
                let (name, path, expected, kind) = match &output.kind {
                    crate::syntax::OutputKind::Value {
                        ..
                    } => continue,
                    crate::syntax::OutputKind::Type {
                        name,
                        ty,
                    } => {
                        let Some(path) = type_path(ty) else {
                            if report_missing {
                                self.error("type export requires a named type", ty.span);
                            }
                            continue;
                        };
                        (
                            &name.text,
                            path,
                            Expected::Type,
                            ReferenceKind::Type,
                        )
                    }
                };
                if self.module_info[module.index()]
                    .exports
                    .contains_key(name)
                {
                    if report_missing
                        && self
                            .public_imports
                            .contains(&(module, name.clone()))
                    {
                        self.error(
                            "public import conflicts with an output",
                            output.span,
                        );
                    }
                    continue;
                }
                let diagnostics = self.diagnostics.len();
                let Some(ResolvedTarget::Item(target)) = self.lookup(module, path, expected) else {
                    if !report_missing && !self.exhausted {
                        self.diagnostics.truncate(diagnostics);
                    } else if report_missing && self.diagnostics.len() == diagnostics {
                        self.unknown(expected.description(), path);
                    }
                    continue;
                };
                self.module_info[module.index()]
                    .exports
                    .insert(name.clone(), target);
                self.references.push(ResolvedReference {
                    span: path.span,
                    kind,
                    target: ResolvedTarget::Item(target),
                });
                changed = true;
            }
        }
        changed
    }

    pub(super) fn bind_import(
        &mut self,
        module: ModuleId,
        path: &Path,
        name: &str,
        span: Span,
        report_missing: bool,
        public: bool,
    ) -> bool {
        let diagnostics = self.diagnostics.len();
        let Some(target) = self.lookup(module, path, Expected::Any) else {
            if report_missing {
                if self.diagnostics.len() == diagnostics {
                    self.unknown("import", path);
                }
            } else if !self.exhausted {
                self.diagnostics.truncate(diagnostics);
            }
            return false;
        };
        let ResolvedTarget::Item(item) = target else {
            if report_missing {
                self.error(
                    "import path names a module, not an item",
                    path.span,
                );
            }
            return false;
        };
        if self.module_info[module.index()]
            .declarations
            .contains_key(name)
            || self.module_info[module.index()]
                .children
                .contains_key(name)
        {
            if report_missing {
                self.error("import conflicts with a declaration", span);
            }
            return false;
        }
        if let Some(&existing) = self.module_info[module.index()].imports.get(name) {
            if existing != item && report_missing {
                self.error("conflicting imports bind the same name", span);
            }
            return false;
        }
        if public
            && self.module_info[module.index()]
                .exports
                .contains_key(name)
        {
            if report_missing {
                self.error("public import conflicts with an export", span);
            }
            return false;
        }
        self.module_info[module.index()]
            .imports
            .insert(name.to_owned(), item);
        if public {
            self.module_info[module.index()]
                .exports
                .insert(name.to_owned(), item);
            self.public_imports
                .insert((module, name.to_owned()));
        }
        self.references.push(ResolvedReference {
            span: path.span,
            kind: ReferenceKind::Import,
            target: ResolvedTarget::Item(item),
        });
        true
    }
}

pub(super) fn declaration(item: &Item) -> Option<(&str, ResolvedItemKind, Span)> {
    match &item.kind {
        ItemKind::TypeAlias(declaration) => Some((
            &declaration.name.text,
            ResolvedItemKind::TypeAlias,
            declaration.name.span,
        )),
        ItemKind::Struct(declaration) => Some((
            &declaration.name.text,
            ResolvedItemKind::Struct,
            declaration.name.span,
        )),
        ItemKind::Enum(declaration) => Some((
            &declaration.name.text,
            ResolvedItemKind::Enum,
            declaration.name.span,
        )),
        ItemKind::Resource(declaration) => Some((
            &declaration.name.text,
            ResolvedItemKind::Resource,
            declaration.name.span,
        )),
        ItemKind::Value(declaration) => Some((
            &declaration.name.text,
            ResolvedItemKind::Value,
            declaration.name.span,
        )),
        ItemKind::Binding(declaration) => Some((
            &declaration.name.text,
            ResolvedItemKind::Binding,
            declaration.name.span,
        )),
        ItemKind::Function(declaration) => Some((
            &declaration.name.text,
            ResolvedItemKind::Function,
            declaration.name.span,
        )),
        ItemKind::Publication(_)
        | ItemKind::Module(_)
        | ItemKind::Use(_)
        | ItemKind::Inputs(_)
        | ItemKind::Outputs(_) => None,
    }
}

fn append(path: &[String], name: &str) -> Vec<String> {
    let mut result = path.to_vec();
    result.push(name.to_owned());
    result
}

fn type_path(ty: &Type) -> Option<&Path> {
    match &ty.kind {
        TypeKind::Named {
            path,
            ..
        } => Some(path),
        TypeKind::List(element) => type_path(element),
        TypeKind::Function {
            ..
        } => None,
    }
}

use super::{
    Expected, ItemId, ModuleId, Path, ResolvedItemKind, ResolvedTarget, Resolver, SourceDomainId,
    Span,
};

impl Resolver<'_> {
    pub(super) fn project_owner(&self, module: ModuleId) -> Option<SourceDomainId> {
        let domain = self.modules[module.index()].domain;
        if self.parsed.is_project_root(domain) {
            Some(domain)
        } else {
            self.project_owners.get(&domain).copied()
        }
    }

    pub(super) fn lookup(
        &mut self,
        module: ModuleId,
        path: &Path,
        expected: Expected,
    ) -> Option<ResolvedTarget> {
        let diagnostics = self.diagnostics.len();
        let result = self.lookup_inner(module, path, expected);
        self.observe_namespace(
            module,
            path,
            path.span,
            super::NamespaceQuery::Lookup {
                expected: expected.description(),
            },
            super::owners::ObservedNamespace::Target(result.as_ref()),
            diagnostics,
        );
        result
    }

    // One decision procedure preserves lookup precedence and visibility checks.
    fn lookup_inner(
        &mut self,
        module: ModuleId,
        path: &Path,
        expected: Expected,
    ) -> Option<ResolvedTarget> {
        for segment in &path.segments {
            if !self.charge(segment.span) {
                return None;
            }
        }
        let written: Vec<_> = path
            .segments
            .iter()
            .map(|part| part.text.clone())
            .collect();
        if written.is_empty() {
            return None;
        }
        if written.len() == 1 {
            let name = &written[0];
            let mut current = Some(module);
            while let Some(scope) = current {
                if !self.charge(path.span) {
                    return None;
                }
                if let Some(&item) = self.module_info[scope.index()].imports.get(name) {
                    return self.check_kind(item, expected, path.span);
                }
                if let Some(&item) = self.module_info[scope.index()]
                    .declarations
                    .get(name)
                {
                    return self.check_kind(item, expected, path.span);
                }
                if let Some(&child) = self.module_info[scope.index()].children.get(name) {
                    if matches!(expected, Expected::Any) {
                        return Some(ResolvedTarget::Module(child));
                    }
                    self.error("module used where an item is required", path.span);
                    return None;
                }
                current = self.parent(scope);
            }
            return None;
        }

        let mut bases = Vec::new();
        let mut consumed = 0;
        if written
            .first()
            .is_some_and(|segment| segment == "project")
        {
            if let Some(owner) = self.project_owner(module) {
                bases.push((owner, Vec::new()));
                consumed = 1;
            }
        } else if written
            .first()
            .is_some_and(|segment| segment == "std")
        {
            // Only sources explicitly assigned the authenticated standard
            // library origin participate in this reserved mapping.
            bases.push((SourceDomainId::STANDARD_LIBRARY, Vec::new()));
        } else if let Some(&domain) = self
            .input_domains
            .get(&self.modules[module.index()].domain)
            .and_then(|aliases| aliases.get(&written[0]))
        {
            bases.push((domain, Vec::new()));
            consumed = 1;
        } else {
            let mut current = Some(module);
            while let Some(scope) = current {
                if !self.charge(path.span) {
                    return None;
                }
                let first = &written[0];
                if let Some(&item) = self.module_info[scope.index()]
                    .imports
                    .get(first)
                    .or_else(|| {
                        self.module_info[scope.index()]
                            .declarations
                            .get(first)
                    })
                {
                    self.error(
                        format!(
                            "{} used as a module in a qualified path",
                            self.items[item.index()].kind.description()
                        ),
                        path.span,
                    );
                    return None;
                }
                let resolved = &self.modules[scope.index()];
                bases.push((resolved.domain, resolved.path.segments.clone()));
                if self.module_info[scope.index()]
                    .children
                    .contains_key(first)
                {
                    break;
                }
                current = self.parent(scope);
            }
        }
        for (domain, mut candidate) in bases {
            if !self.charge(path.span) {
                return None;
            }
            candidate.extend(written[consumed..].iter().cloned());
            if let Some(&item) = self.item_ids.get(&(domain, candidate.clone())) {
                if let Some(visible) = self.visible_item(module, item, &candidate, path.span) {
                    return self.check_kind(visible, expected, path.span);
                }
                self.error("item is private to a module interface", path.span);
                return None;
            }
            if let Some((name, owner_path)) = candidate.split_last()
                && let Some(&owner) = self
                    .module_ids
                    .get(&(domain, owner_path.to_vec()))
                && !self.is_descendant(module, owner)
                && let Some(&item) = self.module_info[owner.index()].exports.get(name)
            {
                if let Some(visible) =
                    self.visible_from_module(module, owner, item, &candidate, path.span)
                {
                    return self.check_kind(visible, expected, path.span);
                }
                self.error("item is private to a module interface", path.span);
                return None;
            }
            if let Some(&child) = self.module_ids.get(&(domain, candidate.clone())) {
                if matches!(expected, Expected::Any) {
                    return Some(ResolvedTarget::Module(child));
                }
                self.error("module used where an item is required", path.span);
                return None;
            }
            let base_len = candidate.len() - (written.len() - consumed);
            for end in base_len + 1..candidate.len() {
                if !self.charge(path.span) {
                    return None;
                }
                if let Some(&item) = self
                    .item_ids
                    .get(&(domain, candidate[..end].to_vec()))
                {
                    self.error(
                        format!(
                            "{} used as a module in a qualified path",
                            self.items[item.index()].kind.description()
                        ),
                        path.span,
                    );
                    return None;
                }
            }
        }
        None
    }

    pub(super) fn visible_item(
        &mut self,
        requester: ModuleId,
        item: ItemId,
        candidate: &[String],
        span: Span,
    ) -> Option<ItemId> {
        let owner = self.items[item.index()].module;
        self.visible_from_module(requester, owner, item, candidate, span)
    }

    pub(super) fn visible_from_module(
        &mut self,
        requester: ModuleId,
        owner: ModuleId,
        mut item: ItemId,
        candidate: &[String],
        span: Span,
    ) -> Option<ItemId> {
        let mut boundary = Some(owner);
        while let Some(module) = boundary {
            if !self.charge(span) {
                return None;
            }
            let boundary_module = &self.modules[module.index()];
            let crosses_domain = self.modules[requester.index()].domain != boundary_module.domain
                && !boundary_module.path.segments.is_empty();
            if (self.module_info[module.index()].closed || crosses_domain)
                && !self.is_descendant(requester, module)
            {
                let boundary_path = &boundary_module.path.segments;
                if candidate.len() != boundary_path.len() + 1 {
                    if candidate.len() > boundary_path.len() + 1
                        && candidate
                            .get(boundary_path.len())
                            .is_some_and(|name| {
                                self.module_info[module.index()]
                                    .public_children
                                    .contains(name)
                            })
                    {
                        boundary = self.parent(module);
                        continue;
                    }
                    return None;
                }
                item = self.module_info[module.index()]
                    .exports
                    .get(candidate.last().expect("item path has a name"))
                    .copied()?;
            }
            boundary = self.parent(module);
        }
        Some(item)
    }

    pub(super) fn check_kind(
        &mut self,
        item: ItemId,
        expected: Expected,
        span: Span,
    ) -> Option<ResolvedTarget> {
        let actual = self.items[item.index()].kind;
        let valid = match expected {
            Expected::Any => true,
            Expected::Type => actual.is_type(),
            Expected::Function => matches!(
                actual,
                ResolvedItemKind::Function
                    | ResolvedItemKind::Resource
                    | ResolvedItemKind::Value
                    | ResolvedItemKind::OutputValue
                    | ResolvedItemKind::PublishedMember
            ),
            Expected::Value => matches!(
                actual,
                ResolvedItemKind::Value
                    | ResolvedItemKind::Resource
                    | ResolvedItemKind::OutputValue
                    | ResolvedItemKind::PublishedMember
                    | ResolvedItemKind::Function
            ),
            Expected::Struct => matches!(actual, ResolvedItemKind::Struct),
        };
        if valid {
            Some(ResolvedTarget::Item(item))
        } else {
            self.error(
                format!(
                    "{} used where {} is required",
                    actual.description(),
                    expected.description()
                ),
                span,
            );
            None
        }
    }

    pub(super) fn lookup_variant(
        &mut self,
        module: ModuleId,
        path: &Path,
    ) -> Option<(ItemId, u32)> {
        let diagnostics = self.diagnostics.len();
        let result = self.lookup_variant_inner(module, path);
        let target = result.map(
            |(enumeration, index)| ResolvedTarget::EnumVariant {
                enumeration,
                index,
            },
        );
        self.observe_namespace(
            module,
            path,
            path.span,
            super::NamespaceQuery::Variant,
            super::owners::ObservedNamespace::Target(target.as_ref()),
            diagnostics,
        );
        result
    }

    fn lookup_variant_inner(&mut self, module: ModuleId, path: &Path) -> Option<(ItemId, u32)> {
        for segment in &path.segments {
            if !self.charge(segment.span) {
                return None;
            }
        }
        let (variant, enum_segments) = path.segments.split_last()?;
        if enum_segments.is_empty() {
            return None;
        }
        if enum_segments.len() == 1 {
            let name = &enum_segments[0].text;
            let mut current = Some(module);
            while let Some(scope) = current {
                if !self.charge(path.span) {
                    return None;
                }
                if let Some(&item) = self.module_info[scope.index()].imports.get(name)
                    && self.items[item.index()].kind == ResolvedItemKind::Enum
                {
                    return Some((
                        item,
                        self.enum_variant_index(item, &variant.text)?,
                    ));
                }
                current = self.parent(scope);
            }
        }
        let mut bases = Vec::new();
        let mut consumed = 0;
        if enum_segments
            .first()
            .is_some_and(|segment| segment.text == "std")
        {
            bases.push((SourceDomainId::STANDARD_LIBRARY, Vec::new()));
        } else if let Some(&domain) = self
            .input_domains
            .get(&self.modules[module.index()].domain)
            .and_then(|aliases| aliases.get(&enum_segments[0].text))
        {
            bases.push((domain, Vec::new()));
            consumed = 1;
        } else {
            let mut current = Some(module);
            while let Some(scope) = current {
                if !self.charge(path.span) {
                    return None;
                }
                let resolved = &self.modules[scope.index()];
                bases.push((resolved.domain, resolved.path.segments.clone()));
                current = self.parent(scope);
            }
        }
        for (domain, mut candidate) in bases {
            if !self.charge(path.span) {
                return None;
            }
            candidate.extend(
                enum_segments[consumed..]
                    .iter()
                    .map(|segment| segment.text.clone()),
            );
            if let Some(&item) = self.item_ids.get(&(domain, candidate.clone()))
                && self.items[item.index()].kind == ResolvedItemKind::Enum
                && self
                    .visible_item(module, item, &candidate, path.span)
                    .is_some()
            {
                let index = self.enum_variant_index(item, &variant.text)?;
                return Some((item, index));
            }
            if let Some((name, owner_path)) = candidate.split_last()
                && let Some(&owner) = self
                    .module_ids
                    .get(&(domain, owner_path.to_vec()))
                && let Some(&item) = self.module_info[owner.index()].exports.get(name)
                && self.items[item.index()].kind == ResolvedItemKind::Enum
            {
                let visible =
                    self.visible_from_module(module, owner, item, &candidate, path.span)?;
                return Some((
                    visible,
                    self.enum_variant_index(visible, &variant.text)?,
                ));
            }
        }
        None
    }

    pub(super) fn enum_variant_index(&self, item: ItemId, name: &str) -> Option<u32> {
        self.enum_variants.get(&item)?.get(name).copied()
    }

    pub(super) fn unknown(&mut self, expected: &str, path: &Path) {
        self.error(
            format!("unknown {expected} `{}`", path.display()),
            path.span,
        );
    }

    pub(super) fn parent(&self, module: ModuleId) -> Option<ModuleId> {
        let resolved = &self.modules[module.index()];
        let path = &resolved.path.segments;
        (!path.is_empty())
            .then(|| self.module_ids[&(resolved.domain, path[..path.len() - 1].to_vec())])
    }

    pub(super) fn is_descendant(&self, module: ModuleId, ancestor: ModuleId) -> bool {
        let module = &self.modules[module.index()];
        let ancestor = &self.modules[ancestor.index()];
        module.domain == ancestor.domain
            && module
                .path
                .segments
                .starts_with(&ancestor.path.segments)
    }
}

impl Expected {
    pub(super) const fn description(self) -> &'static str {
        match self {
            Self::Any => "item",
            Self::Type => "type",
            Self::Function => "function",
            Self::Value => "value",
            Self::Struct => "struct",
        }
    }
}

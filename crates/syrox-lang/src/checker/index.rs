use super::{
    Checker, Context, Diagnostic, FunctionInfo, Item, ItemId, ItemKind, Literal, LocalId,
    MAX_DIAGNOSTICS, ModuleId, OutputKind, ParsedSource, PrimitiveInfo, PrimitiveType,
    ReferenceKind, ResolvedTarget, Span, StructInfo, span_key,
};

impl<'a> Checker<'a> {
    pub(super) fn index_resolution_metadata(&mut self) {
        for reference in self.program.references() {
            if reference.kind() == ReferenceKind::Import {
                continue;
            }
            if !self.charge(reference.span()) {
                return;
            }
            self.references.insert(
                span_key(reference.span()),
                reference.target().clone(),
            );
        }
        for local in self.program.locals() {
            if !self.charge(local.span()) {
                return;
            }
            self.local_at
                .insert(span_key(local.span()), local.id());
        }
        for item in self.program.items() {
            if !self.charge(item.span()) {
                return;
            }
            if self.program.published_member(item.id()).is_none() {
                self.item_at
                    .insert(span_key(item.span()), item.id());
            }
        }
        let program = self.program;
        let span = program
            .parsed()
            .iter()
            .flat_map(|source| source.program().items.iter())
            .next()
            .map_or_else(
                || Span::new(crate::source::SourceId::SINGLE, 0, 0),
                |item| item.span,
            );
        for module in program.modules() {
            if !self.charge(span) {
                return;
            }
            self.module_by_path
                .entry(module.domain())
                .or_default()
                .insert(module.path().segments(), module.id());
        }
    }

    pub(super) fn charge(&mut self, span: Span) -> bool {
        self.observe_effect(span, super::bodies::EffectOperation::WorkProbe(1));
        if self
            .cancellation
            .is_some_and(|cancellation| cancellation.check().is_err())
        {
            self.exhausted = true;
            return false;
        }
        if self.exhausted {
            return false;
        }
        self.work = self.work.saturating_add(1);
        if self.work <= self.limits.max_work {
            return true;
        }
        self.exhausted = true;
        self.error("type checking work limit reached", span);
        false
    }

    pub(super) fn error(&mut self, message: impl Into<String>, span: Span) {
        self.push_diagnostic(Diagnostic::error(message, span));
    }

    pub(super) fn push_diagnostic(&mut self, diagnostic: Diagnostic) {
        self.observe_effect(
            diagnostic.span,
            super::bodies::EffectOperation::Diagnostic,
        );
        self.body.fact_errors = self.body.fact_errors.saturating_add(1);
        if self.prior_diagnostics + self.diagnostics.len() < MAX_DIAGNOSTICS {
            self.diagnostics
                .push(diagnostic.in_phase(crate::diagnostic::DiagnosticCode::TypeCheck));
        }
    }

    pub(super) fn reserve_metadata(&mut self, span: Span) -> bool {
        self.observe_effect(span, super::bodies::EffectOperation::Metadata);
        if self
            .expressions
            .len()
            .saturating_add(self.patterns.len())
            .saturating_add(self.prior_metadata)
            .saturating_add(self.collection_metadata_units)
            >= self.limits.max_metadata_units
        {
            if !self.exhausted {
                self.exhausted = true;
                self.error("checked metadata limit reached", span);
            }
            false
        } else {
            true
        }
    }

    pub(super) fn index(&mut self) {
        let program = self.program;
        for source in program.parsed().iter() {
            self.index_source(source);
            if self.exhausted {
                return;
            }
        }
    }

    // One declaration traversal keeps budget charging and registration order visible.
    pub(super) fn index_source(&mut self, source: &'a ParsedSource) {
        let root = self
            .module_by_path
            .get(&source.domain())
            .and_then(|modules| modules.get(source.module()))
            .expect("resolver records each source domain root")
            .to_owned();
        let mut stack: Vec<(&Item, Vec<String>, ModuleId)> = source
            .program()
            .items
            .iter()
            .rev()
            .map(|item| (item, source.module().to_vec(), root))
            .collect();
        while let Some((item, path, module)) = stack.pop() {
            if !self.charge(item.span) {
                return;
            }
            if let ItemKind::Module(declaration) = &item.kind {
                let mut child_path = path;
                child_path.extend(
                    declaration
                        .path
                        .segments
                        .iter()
                        .map(|segment| segment.text.clone()),
                );
                let child = self
                    .module_by_path
                    .get(&source.domain())
                    .and_then(|modules| modules.get(child_path.as_slice()))
                    .expect("resolved module")
                    .to_owned();
                for nested in declaration.items.iter().rev() {
                    stack.push((nested, child_path.clone(), child));
                }
                continue;
            }
            let context = Context {
                domain: source.domain(),
                module,
            };
            match &item.kind {
                ItemKind::TypeAlias(declaration) => {
                    if let Some(id) = self.declaration_id(declaration.name.span) {
                        self.item_context.insert(id, context);
                        let parameters = declaration
                            .type_parameters
                            .iter()
                            .filter_map(|parameter| self.local_id(parameter.name.span))
                            .collect();
                        self.aliases.insert(
                            id,
                            super::AliasInfo {
                                declaration,
                                parameters,
                            },
                        );
                    }
                }
                ItemKind::Struct(declaration) => {
                    if let Some(id) = self.declaration_id(declaration.name.span) {
                        let parameters = declaration
                            .type_parameters
                            .iter()
                            .filter_map(|parameter| self.local_id(parameter.name.span))
                            .collect();
                        self.item_context.insert(id, context);
                        self.structs.insert(
                            id,
                            StructInfo {
                                declaration,
                                context,
                                parameters,
                            },
                        );
                    }
                }
                ItemKind::Enum(declaration) => {
                    if let Some(id) = self.declaration_id(declaration.name.span) {
                        self.item_context.insert(id, context);
                        self.enums.insert(id, declaration);
                    }
                }
                ItemKind::Resource(declaration) | ItemKind::Value(declaration) => {
                    if let Some(id) = self.declaration_id(declaration.name.span) {
                        self.item_context.insert(id, context);
                        self.primitives.insert(
                            id,
                            PrimitiveInfo {
                                declaration,
                            },
                        );
                    }
                }
                ItemKind::Function(declaration) => {
                    if let Some(id) = self.declaration_id(declaration.name.span) {
                        self.item_context.insert(id, context);
                        self.functions.insert(
                            id,
                            FunctionInfo {
                                declaration,
                                context,
                            },
                        );
                    }
                }
                ItemKind::Outputs(outputs) => {
                    for output in &outputs.entries {
                        if !self.charge(output.span) {
                            return;
                        }
                        if let OutputKind::Value {
                            ty,
                            ..
                        } = &output.kind
                            && let Some(id) = self.declaration_id(output.span)
                        {
                            self.output_values.insert(id, ty);
                        }
                    }
                }
                ItemKind::Publication(_)
                | ItemKind::Module(_)
                | ItemKind::Use(_)
                | ItemKind::Inputs(_) => {}
            }
        }
    }

    pub(super) fn declaration_id(&self, span: Span) -> Option<ItemId> {
        self.item_at.get(&span_key(span)).copied()
    }

    pub(super) fn local_id(&self, span: Span) -> Option<LocalId> {
        self.local_at.get(&span_key(span)).copied()
    }

    pub(super) fn target(&self, span: Span) -> Option<&ResolvedTarget> {
        self.references.get(&span_key(span))
    }
}

pub(super) fn literal_primitive(literal: &Literal) -> PrimitiveType {
    match literal {
        Literal::Integer(_) => PrimitiveType::Int,
        Literal::String(_) => PrimitiveType::Str,
    }
}

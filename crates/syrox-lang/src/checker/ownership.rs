use super::{
    BTreeMap, BTreeSet, Checker, Diagnostic, ItemId, LocalId, RawTy, ResolvedItemKind, Span, Ty,
    VecDeque,
};

impl Checker<'_> {
    /// Join only bindings that existed before branching. A move is definite
    /// exactly when every checked branch consumes the value definitely.
    pub(super) fn join_branch(&self, merged: &mut BTreeMap<LocalId, super::Binding>, first: bool) {
        for (id, joined) in merged {
            let Some(branch) = self.body.bindings.get(id) else {
                continue;
            };
            if first {
                joined.moved = branch.moved;
                joined.conditional = branch.conditional;
                joined.ownership_unknown = branch.ownership_unknown;
            } else {
                let definite = joined.moved.is_some()
                    && !joined.conditional
                    && branch.moved.is_some()
                    && !branch.conditional;
                joined.moved = joined.moved.or(branch.moved);
                joined.conditional = joined.moved.is_some() && !definite;
                joined.ownership_unknown |= branch.ownership_unknown;
            }
        }
    }
    pub(super) fn bind_local(
        &mut self,
        local: LocalId,
        ty: Ty,
        declaration: Span,
        annotated: bool,
    ) {
        let affine = self.affine(&ty, declaration);
        let status = if ty.is_known() {
            super::TypeStatus::Known
        } else {
            super::TypeStatus::Unknown
        };
        if self.reserve_editor_metadata(declaration)
            && let Some(editor_ty) = self.retain_editor_type(&ty)
        {
            self.editor.locals.insert(
                local,
                super::CheckedLocal {
                    id: local,
                    ty: editor_ty,
                    declaration,
                    affine,
                    annotated,
                    status,
                },
            );
        }
        self.body.bindings.insert(
            local,
            super::Binding {
                constant: None,
                ty,
                affine,
                moved: None,
                declaration,
                conditional: false,
                status,
                ownership_unknown: false,
            },
        );
    }

    pub(super) fn record_use(
        &mut self,
        local: LocalId,
        span: Span,
        kind: super::OwnershipUseKind,
        closure: Option<Span>,
        permitted: bool,
    ) {
        if !self.reserve_editor_metadata(span) {
            return;
        }
        if let Some(binding) = self.body.bindings.get(&local) {
            self.editor.uses.push(super::OwnershipUse {
                local,
                span,
                kind,
                affine: binding.affine,
                status: if binding.ownership_unknown || binding.status == super::TypeStatus::Unknown
                {
                    super::OwnershipUseStatus::Unknown
                } else if permitted
                    && binding.status == super::TypeStatus::Known
                    && binding.moved.is_none()
                {
                    super::OwnershipUseStatus::Valid
                } else {
                    super::OwnershipUseStatus::Invalid
                },
                previous_move: binding.moved,
                conditional: binding.conditional,
                closure,
            });
        }
    }
    pub(super) fn propagate_carriers(&mut self) {
        let mut reverse: BTreeMap<ItemId, Vec<ItemId>> = BTreeMap::new();
        let mut queue = VecDeque::new();
        let fields: Vec<_> = self
            .struct_fields
            .iter()
            .map(|(&id, fields)| (id, fields.clone()))
            .collect();
        for (container, fields) in fields {
            let mut seeded = false;
            for (_, field, _) in &fields {
                let mut pending = vec![field];
                while let Some(field) = pending.pop() {
                    if !self.charge(self.item_span(container)) {
                        return;
                    }
                    match field {
                        RawTy::Concrete(ty) => {
                            if self.ty_directly_claims(ty) {
                                seeded = true;
                            }
                            if let Some(dependency) = Ty::nominal_head(ty) {
                                reverse
                                    .entry(dependency)
                                    .or_default()
                                    .push(container);
                            }
                        }
                        RawTy::List(element) => pending.push(element),
                        RawTy::Specialization {
                            template,
                            ..
                        } => {
                            reverse
                                .entry(*template)
                                .or_default()
                                .push(container);
                        }
                        RawTy::Function {
                            once: true,
                            ..
                        } => seeded = true,
                        RawTy::Parameter(_)
                        | RawTy::Function {
                            once: false,
                            ..
                        } => {}
                    }
                }
            }
            if seeded && self.carriers.insert(container) {
                queue.push_back(container);
            }
        }
        while let Some(carrier) = queue.pop_front() {
            if !self.charge(self.item_span(carrier)) {
                return;
            }
            if let Some(containers) = reverse.get(&carrier) {
                for &container in containers {
                    if self.carriers.insert(container) {
                        queue.push_back(container);
                    }
                }
            }
        }
    }

    pub(super) fn use_local(&mut self, local: LocalId, span: Span, consuming: bool) -> Ty {
        self.check_local_use(local, span, consuming, true)
    }

    pub(super) fn capture_local(&mut self, local: LocalId, span: Span) {
        self.check_local_use(local, span, true, false);
    }

    fn check_local_use(&mut self, local: LocalId, span: Span, consuming: bool, record: bool) -> Ty {
        match self
            .body
            .bindings
            .get(&local)
            .map(|binding| binding.status)
        {
            Some(super::TypeStatus::Unknown) => {
                self.body.fact_unknowns = self.body.fact_unknowns.saturating_add(1);
            }
            Some(super::TypeStatus::Invalid) => {
                self.body.fact_errors = self.body.fact_errors.saturating_add(1);
            }
            _ => {}
        }
        let kind = if consuming
            && self
                .body
                .bindings
                .get(&local)
                .is_some_and(|binding| binding.affine)
        {
            super::OwnershipUseKind::Consume
        } else {
            super::OwnershipUseKind::Reuse
        };
        if record {
            self.record_use(local, span, kind, None, true);
        }
        let Some(binding) = self.body.bindings.get(&local) else {
            self.error("local has no checked binding", span);
            return Ty::Error;
        };
        if binding.affine
            && !binding.ownership_unknown
            && let Some(moved) = binding.moved
        {
            let declaration = binding.declaration;
            let conditional = binding.conditional;
            self.push_diagnostic(
                Diagnostic::error("use of moved affine value", span)
                    .with_code(crate::diagnostic::DiagnosticCode::MovedValue)
                    .with_related(moved, "first moved here")
                    .with_related(declaration, "declared here")
                    .with_note(if conditional {
                        "the value may have been consumed in a preceding branch"
                    } else {
                        "affine values can be consumed at most once"
                    }),
            );
        }
        let binding = self
            .body
            .bindings
            .get_mut(&local)
            .expect("binding exists");
        if consuming && binding.affine && (binding.moved.is_none() || binding.ownership_unknown) {
            binding.moved = Some(span);
            binding.ownership_unknown = false;
            binding.conditional = false;
        }
        binding.ty.clone()
    }

    pub(super) fn recover_bindings(
        &mut self,
        binding: Option<&crate::syntax::RecoveredBinding>,
        span: Span,
    ) {
        self.body.fact_unknowns = self.body.fact_unknowns.saturating_add(1);
        for _ in 0..self.body.bindings.len() {
            if !self.charge(span) {
                return;
            }
        }
        for binding in self.body.bindings.values_mut() {
            if binding.affine {
                binding.ownership_unknown = true;
            }
        }
        if let Some(binding) = binding
            && let Some(local) = self.local_id(binding.name.span)
        {
            let ty = binding.ty.as_ref().map_or(Ty::Error, |ty| {
                self.resolve_type(ty, &self.body.type_parameters.clone(), 0)
            });
            self.bind_local(local, ty, binding.name.span, binding.ty.is_some());
            self.body
                .bindings
                .get_mut(&local)
                .expect("recovered binding")
                .status = super::TypeStatus::Unknown;
            self.body
                .bindings
                .get_mut(&local)
                .expect("recovered binding")
                .ownership_unknown = true;
            if let Some(fact) = self.editor.locals.get_mut(&local) {
                fact.status = super::TypeStatus::Unknown;
            }
        }
        if self.cancellation.is_none() {
            self.error(
                "recovered statement cannot be checked for execution",
                span,
            );
        }
    }

    pub(super) fn affine(&mut self, ty: &Ty, span: Span) -> bool {
        self.affine_inner(
            ty,
            span,
            &mut BTreeSet::new(),
            &mut BTreeMap::new(),
            0,
        )
    }

    pub(super) fn affine_inner(
        &mut self,
        ty: &Ty,
        span: Span,
        visiting: &mut BTreeSet<Ty>,
        memo: &mut BTreeMap<Ty, bool>,
        depth: usize,
    ) -> bool {
        if depth > self.limits.max_specialization_depth {
            self.error("affine classification depth limit reached", span);
            return true;
        }
        if !self.charge(span) {
            return false;
        }
        if let Some(&result) = memo.get(ty) {
            return result;
        }
        if !visiting.insert(ty.clone()) {
            return false;
        }
        let affine = match ty {
            Ty::Nominal(item) => {
                if self.item_kind(*item) == Some(ResolvedItemKind::Resource)
                    || self.carriers.contains(item)
                {
                    true
                } else {
                    let fields = self
                        .struct_fields
                        .get(item)
                        .cloned()
                        .unwrap_or_default();
                    fields.iter().any(|(_, field, _)| {
                        self.concretize(field.clone(), &BTreeMap::new(), span)
                            .is_some_and(|field| {
                                self.affine_inner(&field, span, visiting, memo, depth + 1)
                            })
                    })
                }
            }
            Ty::Specialization {
                template,
                arguments,
            } => {
                if self.carriers.contains(template) {
                    true
                } else {
                    let substitutions: BTreeMap<_, _> = self
                        .nominal_parameters(*template)
                        .into_iter()
                        .zip(arguments.iter().cloned())
                        .collect();
                    let fields = self
                        .struct_fields
                        .get(template)
                        .cloned()
                        .unwrap_or_default();
                    fields.iter().any(|(_, field, _)| {
                        self.concretize(field.clone(), &substitutions, span)
                            .is_some_and(|field| {
                                self.affine_inner(&field, span, visiting, memo, depth + 1)
                            })
                    })
                }
            }
            Ty::List(element) => self.affine_inner(element, span, visiting, memo, depth + 1),
            Ty::Parameter(_) => true,
            Ty::Function {
                once,
                ..
            } => *once,
            Ty::Unit | Ty::Int | Ty::Str | Ty::Error => false,
        };
        visiting.remove(ty);
        memo.insert(ty.clone(), affine);
        affine
    }

    pub(super) fn ty_directly_claims(&self, ty: &Ty) -> bool {
        match ty {
            Ty::Nominal(item) => self.item_kind(*item) == Some(ResolvedItemKind::Resource),
            Ty::List(element) => self.ty_directly_claims(element),
            Ty::Function {
                once: true,
                ..
            } => true,
            Ty::Unit
            | Ty::Int
            | Ty::Str
            | Ty::Parameter(_)
            | Ty::Specialization {
                ..
            }
            | Ty::Function {
                ..
            }
            | Ty::Error => false,
        }
    }

    pub(super) fn is_nominal_struct(&self, ty: &Ty) -> bool {
        Ty::nominal_head(ty).is_some_and(|item| self.structs.contains_key(&item))
    }
}

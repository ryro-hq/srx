use std::{collections::BTreeMap, mem::size_of, sync::Arc};

use super::types::type_allocation_bytes;
use super::{CanonicalType, EvaluationLimits, EvaluationSetupError, SpanKey, span_key};
use crate::{
    checker::CanonicalItemIdentity, checker::CheckPolicy, checker::CheckedProgram,
    checker::Elaboration, checker::Ty, resolver::ItemId, resolver::LocalId,
    resolver::ResolvedItemKind, resolver::ResolvedTarget, source::Span, syntax::Function,
    syntax::Item, syntax::ItemKind, syntax::PrimitiveDeclaration, syntax::RefinementKind,
    syntax::Struct,
};

pub(super) struct PrimitiveInfo<'a> {
    pub(super) declaration: &'a PrimitiveDeclaration,
    pub(super) resource: bool,
}

pub(super) struct ProgramIndex<'a> {
    items: BTreeMap<ItemId, &'a crate::resolver::ResolvedItem>,
    item_at: BTreeMap<SpanKey, ItemId>,
    identities: BTreeMap<ItemId, Arc<CanonicalItemIdentity>>,
    canonical_types: BTreeMap<Ty, Arc<CanonicalType>>,
    targets: BTreeMap<SpanKey, ResolvedTarget>,
    locals: BTreeMap<SpanKey, LocalId>,
    local_uses: BTreeMap<LocalId, usize>,
    pub(super) functions: BTreeMap<ItemId, &'a Function>,
    pub(super) output_values: BTreeMap<ItemId, &'a crate::syntax::Expression>,
    pub(super) structures: BTreeMap<ItemId, &'a Struct>,
    pub(super) primitives: BTreeMap<ItemId, PrimitiveInfo<'a>>,
    pub(super) predicate_names: BTreeMap<SpanKey, Arc<str>>,
    scope_names: BTreeMap<String, Arc<str>>,
}

impl<'a> ProgramIndex<'a> {
    pub(super) fn new(
        program: &'a CheckedProgram,
        policy: &CheckPolicy,
        budget: &mut SetupBudget,
    ) -> Result<Self, EvaluationSetupError> {
        let resolved = program.resolved();
        let mut index = Self {
            items: BTreeMap::new(),
            item_at: BTreeMap::new(),
            identities: BTreeMap::new(),
            canonical_types: BTreeMap::new(),
            targets: BTreeMap::new(),
            locals: BTreeMap::new(),
            local_uses: BTreeMap::new(),
            functions: BTreeMap::new(),
            output_values: BTreeMap::new(),
            structures: BTreeMap::new(),
            primitives: BTreeMap::new(),
            predicate_names: BTreeMap::new(),
            scope_names: BTreeMap::new(),
        };
        for (name, _) in policy.scopes() {
            budget.charge(
                name.len()
                    .saturating_mul(2)
                    .saturating_add(size_of::<(String, Arc<str>)>()),
            )?;
            index
                .scope_names
                .insert(name.clone(), Arc::from(name.as_str()));
        }
        for item in resolved.items() {
            budget.charge(
                size_of::<(ItemId, &crate::resolver::ResolvedItem)>()
                    .saturating_add(size_of::<(SpanKey, ItemId)>())
                    .saturating_add(size_of::<(ItemId, Arc<CanonicalItemIdentity>)>()),
            )?;
            budget.allocate(identity_allocation_bytes(item))?;
            let identity = Arc::new(CanonicalItemIdentity::from_resolved(item));
            if resolved.published_member(item.id()).is_none() {
                index
                    .item_at
                    .insert(span_key(item.span()), item.id());
            }
            index.identities.insert(item.id(), identity);
            index.items.insert(item.id(), item);
        }
        for source in resolved.parsed().iter() {
            let mut pending: Vec<_> = source.program().items.iter().collect();
            while let Some(item) = pending.pop() {
                budget.charge(0)?;
                match &item.kind {
                    ItemKind::Module(module) => pending.extend(&module.items),
                    ItemKind::Outputs(outputs) => {
                        for output in &outputs.entries {
                            if let crate::syntax::OutputKind::Value {
                                value,
                                ..
                            } = &output.kind
                                && let Some(&id) = index.item_at.get(&span_key(output.span))
                            {
                                budget.charge(size_of::<(ItemId, &crate::syntax::Expression)>())?;
                                index.output_values.insert(id, value);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        for reference in resolved
            .references()
            .filter(|reference| reference.kind() != crate::resolver::ReferenceKind::Import)
        {
            budget.charge(size_of::<(SpanKey, ResolvedTarget)>())?;
            index.targets.insert(
                span_key(reference.span()),
                reference.target().clone(),
            );
        }
        for local in resolved.locals() {
            budget.charge(size_of::<(SpanKey, LocalId)>())?;
            index
                .locals
                .insert(span_key(local.span()), local.id());
        }
        index.index_local_uses(budget)?;
        for source in resolved.parsed().iter() {
            index.walk_items(&source.program().items, budget)?;
        }
        for expression in program.expressions() {
            budget.charge(0)?;
            index.intern_checked_type(expression.ty(), budget)?;
            index.intern_module_collection(expression, budget)?;
            if let Some(Elaboration::Erasure {
                source,
            }) = expression.elaboration()
            {
                index.intern_checked_type(source, budget)?;
            }
            if let Some(Elaboration::FunctionSpecialization {
                substitutions,
            }) = expression.elaboration()
            {
                for ty in substitutions.values() {
                    budget.charge(0)?;
                    index.intern_checked_type(ty, budget)?;
                }
            }
        }
        for item in resolved.items() {
            if let Some(ty) = program.published_type(item.id()) {
                index.intern_checked_type(ty, budget)?;
            }
        }
        Ok(index)
    }

    fn index_local_uses(&mut self, budget: &mut SetupBudget) -> Result<(), EvaluationSetupError> {
        for target in self.targets.values() {
            budget.charge(0)?;
            if let ResolvedTarget::Local(local) = target {
                budget.allocate(size_of::<(LocalId, usize)>())?;
                *self.local_uses.entry(*local).or_default() += 1;
            }
        }
        Ok(())
    }

    fn intern_module_collection(
        &mut self,
        expression: &crate::checker::CheckedExpression,
        budget: &mut SetupBudget,
    ) -> Result<(), EvaluationSetupError> {
        if let Some(Elaboration::ModuleExports {
            function,
            ..
        }) = expression.elaboration()
        {
            self.intern_checked_type(function, budget)?;
        }
        Ok(())
    }

    fn walk_items(
        &mut self,
        items: &'a [Item],
        budget: &mut SetupBudget,
    ) -> Result<(), EvaluationSetupError> {
        for item in items {
            budget.charge(0)?;
            match &item.kind {
                ItemKind::Module(module) => self.walk_items(&module.items, budget)?,
                ItemKind::Function(declaration) => {
                    if let Some(id) = self.item_at(declaration.name.span) {
                        budget.allocate(size_of::<(ItemId, &Function)>())?;
                        self.functions.insert(id, declaration);
                    }
                }
                ItemKind::Struct(declaration) => {
                    if let Some(id) = self.item_at(declaration.name.span) {
                        budget.allocate(size_of::<(ItemId, &Struct)>())?;
                        self.structures.insert(id, declaration);
                    }
                }
                ItemKind::Resource(declaration) | ItemKind::Value(declaration) => {
                    if let Some(id) = self.item_at(declaration.name.span) {
                        let resource = self
                            .items
                            .get(&id)
                            .is_some_and(|item| item.kind() == ResolvedItemKind::Resource);
                        budget.allocate(size_of::<(ItemId, PrimitiveInfo<'_>)>())?;
                        self.primitives.insert(
                            id,
                            PrimitiveInfo {
                                declaration,
                                resource,
                            },
                        );
                        for refinement in &declaration.refinements {
                            let RefinementKind::Predicate(path) = &refinement.kind else {
                                continue;
                            };
                            budget.charge(0)?;
                            let name_len = path
                                .segments
                                .iter()
                                .map(|segment| segment.text.len())
                                .sum::<usize>()
                                .saturating_add(path.segments.len().saturating_sub(1) * 2);
                            budget.allocate(
                                name_len
                                    .saturating_add(size_of::<Arc<str>>())
                                    .saturating_add(size_of::<(SpanKey, Arc<str>)>()),
                            )?;
                            let mut name = String::with_capacity(name_len);
                            for (index, part) in path.segments.iter().enumerate() {
                                if index != 0 {
                                    name.push_str("::");
                                }
                                name.push_str(&part.text);
                            }
                            self.predicate_names
                                .insert(span_key(path.span), Arc::from(name));
                        }
                    }
                }
                ItemKind::Publication(_)
                | ItemKind::Use(_)
                | ItemKind::Inputs(_)
                | ItemKind::Outputs(_)
                | ItemKind::TypeAlias(_)
                | ItemKind::Enum(_) => {}
            }
        }
        Ok(())
    }

    pub(super) fn item_at(&self, span: Span) -> Option<ItemId> {
        self.item_at.get(&span_key(span)).copied()
    }

    pub(super) fn target(&self, span: Span) -> Option<&ResolvedTarget> {
        self.targets.get(&span_key(span))
    }

    pub(super) fn single_use(&self, local: LocalId) -> bool {
        self.local_uses.get(&local) == Some(&1)
    }

    pub(super) fn locals_referenced_in(&self, span: Span) -> impl Iterator<Item = LocalId> + '_ {
        self.targets
            .range(
                (span.source_id().index(), span.start(), 0)
                    ..=(span.source_id().index(), span.end(), u32::MAX),
            )
            .filter_map(|(_, target)| match target {
                ResolvedTarget::Local(local) => Some(*local),
                _ => None,
            })
    }

    pub(super) fn local(&self, span: Span) -> Option<LocalId> {
        self.locals.get(&span_key(span)).copied()
    }

    pub(super) fn identity(&self, item: ItemId) -> Option<Arc<CanonicalItemIdentity>> {
        self.identities.get(&item).cloned()
    }

    pub(super) fn identity_at(&self, span: Span) -> Option<Arc<CanonicalItemIdentity>> {
        self.item_at(span)
            .and_then(|item| self.identity(item))
    }

    pub(super) fn scope_name(&self, name: &str) -> Option<Arc<str>> {
        self.scope_names.get(name).cloned()
    }

    pub(super) fn canonical_type(&self, ty: &Ty) -> Option<Arc<CanonicalType>> {
        self.canonical_types.get(ty).cloned()
    }

    fn intern_checked_type(
        &mut self,
        ty: &Ty,
        budget: &mut SetupBudget,
    ) -> Result<Option<Arc<CanonicalType>>, EvaluationSetupError> {
        if let Some(canonical) = self.canonical_types.get(ty) {
            return Ok(Some(canonical.clone()));
        }
        budget.charge(0)?;
        let canonical = match ty {
            Ty::Unit => CanonicalType::Unit,
            Ty::Int => CanonicalType::Int,
            Ty::Str => CanonicalType::Str,
            Ty::Nominal(item) => {
                let Some(identity) = self.identity(*item) else {
                    return Ok(None);
                };
                CanonicalType::Nominal(identity)
            }
            Ty::Specialization {
                template,
                arguments,
            } => {
                budget.allocate(
                    arguments
                        .len()
                        .saturating_mul(size_of::<Arc<CanonicalType>>()),
                )?;
                let mut canonical = Vec::with_capacity(arguments.len());
                for argument in arguments {
                    let Some(argument) = self.intern_checked_type(argument, budget)? else {
                        return Ok(None);
                    };
                    canonical.push(argument);
                }
                let Some(template) = self.identity(*template) else {
                    return Ok(None);
                };
                CanonicalType::Specialization {
                    template,
                    arguments: canonical,
                }
            }
            Ty::List(element) => {
                let Some(element) = self.intern_checked_type(element, budget)? else {
                    return Ok(None);
                };
                CanonicalType::List(element)
            }
            Ty::Function {
                parameters,
                result,
                once,
            } => {
                budget.allocate(
                    parameters
                        .len()
                        .saturating_mul(size_of::<Arc<CanonicalType>>()),
                )?;
                let mut canonical = Vec::with_capacity(parameters.len());
                for parameter in parameters {
                    let Some(parameter) = self.intern_checked_type(parameter, budget)? else {
                        return Ok(None);
                    };
                    canonical.push(parameter);
                }
                let Some(result) = self.intern_checked_type(result, budget)? else {
                    return Ok(None);
                };
                CanonicalType::Function {
                    once: *once,
                    parameters: canonical,
                    result,
                }
            }
            Ty::Parameter(_) | Ty::Error => return Ok(None),
        };
        budget.allocate(
            size_of::<CanonicalType>()
                .saturating_add(size_of::<(Ty, Arc<CanonicalType>)>())
                .saturating_add(type_allocation_bytes(ty)),
        )?;
        let canonical = Arc::new(canonical);
        self.canonical_types
            .insert(ty.clone(), canonical.clone());
        Ok(Some(canonical))
    }
}

pub(super) struct SetupBudget {
    limits: EvaluationLimits,
    steps: usize,
    bytes: usize,
}

impl SetupBudget {
    pub(super) const fn new(limits: EvaluationLimits) -> Self {
        Self {
            limits,
            steps: 0,
            bytes: 0,
        }
    }

    pub(super) fn charge(&mut self, bytes: usize) -> Result<(), EvaluationSetupError> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.limits.max_setup_steps {
            return Err(EvaluationSetupError::SetupWorkLimit);
        }
        self.allocate(bytes)
    }

    fn allocate(&mut self, bytes: usize) -> Result<(), EvaluationSetupError> {
        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > self.limits.max_setup_bytes {
            return Err(EvaluationSetupError::SetupExpansionLimit);
        }
        Ok(())
    }
}

fn identity_allocation_bytes(item: &crate::resolver::ResolvedItem) -> usize {
    size_of::<CanonicalItemIdentity>()
        .saturating_add(
            item.path()
                .segments()
                .len()
                .saturating_mul(size_of::<String>()),
        )
        .saturating_add(
            item.path()
                .segments()
                .iter()
                .map(String::len)
                .sum::<usize>(),
        )
}

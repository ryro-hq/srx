use super::{
    BTreeMap, Block, Expected, Expression, ExpressionKind, Function, ItemKind, Literal, LocalId,
    MatchArm, ModuleId, Path, Pattern, ReferenceKind, RefinementKind, ResolvedReference,
    ResolvedTarget, Resolver, StatementKind, StringLiteral, StringPart, Type, TypeKind,
};

impl Resolver<'_> {
    fn resolve_enum(
        &mut self,
        module: ModuleId,
        enumeration: &crate::syntax::Enum,
        scope: crate::source::Span,
    ) {
        let mut types = BTreeMap::new();
        for parameter in &enumeration.type_parameters {
            if !self.charge(parameter.span) {
                return;
            }
            if parameter.owner {
                self.error(
                    "`owner` is only valid on an opaque struct",
                    parameter.span,
                );
            }
            if types.contains_key(&parameter.name.text) {
                self.error("duplicate type parameter", parameter.span);
                continue;
            }
            let Some(id) = self.local(
                &parameter.name,
                crate::resolver::LocalKind::TypeParameter,
            ) else {
                return;
            };
            types.insert(parameter.name.text.clone(), id);
            self.editor_local(&parameter.name, id, scope);
        }
        for variant in &enumeration.variants {
            for ty in &variant.payload {
                self.resolve_type(module, ty, &types);
            }
        }
    }

    fn resolve_match_arm(
        &mut self,
        module: ModuleId,
        arm: &MatchArm,
        values: &BTreeMap<String, LocalId>,
        types: &BTreeMap<String, LocalId>,
    ) {
        let path = match &arm.pattern {
            Pattern::Wildcard(_) => None,
            Pattern::Path(path)
            | Pattern::Variant {
                path,
                ..
            } => Some(path),
        };
        if let Some(path) = path {
            if path.segments.len() == 1 {
                self.references.push(ResolvedReference {
                    span: path.span,
                    kind: ReferenceKind::Pattern,
                    target: ResolvedTarget::ContextualEnumVariant,
                });
            } else {
                self.resolve_qualified_value(module, path, ReferenceKind::Pattern);
            }
        }
        if !matches!(&arm.pattern, Pattern::Variant { bindings, .. } if !bindings.is_empty()) {
            self.resolve_expression(module, &arm.value, values, types);
            return;
        }
        for _ in values.values() {
            if !self.charge(arm.span) {
                return;
            }
        }
        let mut values = values.clone();
        if let Pattern::Variant {
            bindings,
            ..
        } = &arm.pattern
        {
            let mut names = std::collections::BTreeSet::new();
            for binding in bindings {
                if binding.text == "_" {
                    continue;
                }
                if !names.insert(&binding.text) {
                    self.error("duplicate pattern binding", binding.span);
                }
                let Some(id) = self.local(binding, crate::resolver::LocalKind::Pattern) else {
                    return;
                };
                values.insert(binding.text.clone(), id);
                self.editor_local(binding, id, arm.value.span);
            }
        }
        self.resolve_expression(module, &arm.value, &values, types);
    }

    pub(super) fn resolve_contents(&mut self) {
        for located in self.walk_items() {
            if !self.charge(located.item.span) {
                return;
            }
            let module = self.module_ids[&(located.domain, located.module_path.clone())];
            if let Some((name, _, _)) = super::namespace::declaration(located.item) {
                self.with_owner(
                    module,
                    name,
                    super::ResolutionOwnerPart::Declaration,
                    located.item.span,
                    |resolver| resolver.resolve_item_contents(module, &located),
                );
            } else if let ItemKind::Publication(publication) = &located.item.kind {
                let namespace = publication
                    .namespace
                    .segments
                    .iter()
                    .map(|segment| segment.text.as_str())
                    .collect::<Vec<_>>()
                    .join("::");
                self.with_owner(
                    module,
                    &publication.export.text,
                    super::ResolutionOwnerPart::Publication(namespace),
                    located.item.span,
                    |resolver| resolver.resolve_item_contents(module, &located),
                );
            } else {
                self.resolve_item_contents(module, &located);
            }
            if self.exhausted {
                return;
            }
        }
    }

    // Exhaustive traversal keeps lexical scopes and recovery in syntax order.
    fn resolve_item_contents(&mut self, module: ModuleId, located: &super::LocatedItem<'_>) {
        match &located.item.kind {
            ItemKind::Module(_) | ItemKind::Use(_) => {}
            ItemKind::Enum(enumeration) => {
                self.resolve_enum(module, enumeration, located.item.span);
            }
            ItemKind::Inputs(inputs) => {
                for input in &inputs.entries {
                    self.resolve_string(&input.value, &BTreeMap::new());
                }
            }
            ItemKind::TypeAlias(alias) => {
                let mut type_locals = BTreeMap::new();
                for parameter in &alias.type_parameters {
                    if !self.charge(parameter.span) {
                        return;
                    }
                    if parameter.owner {
                        self.error(
                            "`owner` is only valid on an opaque struct",
                            parameter.span,
                        );
                    }
                    if type_locals.contains_key(&parameter.name.text) {
                        self.error("duplicate type parameter", parameter.span);
                        continue;
                    }
                    let Some(id) = self.local(
                        &parameter.name,
                        crate::resolver::LocalKind::TypeParameter,
                    ) else {
                        return;
                    };
                    type_locals.insert(parameter.name.text.clone(), id);
                    self.editor_local(&parameter.name, id, located.item.span);
                }
                self.resolve_type(module, &alias.ty, &type_locals);
            }
            ItemKind::Struct(structure) => {
                let mut type_locals = BTreeMap::new();
                for parameter in &structure.type_parameters {
                    if !self.charge(parameter.span) {
                        return;
                    }
                    if type_locals.contains_key(&parameter.name.text) {
                        self.error("duplicate type parameter", parameter.span);
                        continue;
                    }
                    let Some(id) = self.local(
                        &parameter.name,
                        crate::resolver::LocalKind::TypeParameter,
                    ) else {
                        return;
                    };
                    type_locals.insert(parameter.name.text.clone(), id);
                    self.editor_local(&parameter.name, id, located.item.span);
                }
                for field in &structure.fields {
                    self.resolve_type(module, &field.ty, &type_locals);
                    if let Some(default) = &field.default {
                        self.with_owner(
                            module,
                            &structure.name.text,
                            super::ResolutionOwnerPart::FieldDefault(field.name.text.clone()),
                            default.span,
                            |resolver| {
                                resolver.resolve_expression(
                                    module,
                                    default,
                                    &BTreeMap::new(),
                                    &type_locals,
                                );
                            },
                        );
                    }
                }
            }
            ItemKind::Resource(declaration) | ItemKind::Value(declaration) => {
                for refinement in &declaration.refinements {
                    if !self.charge(refinement.span) {
                        return;
                    }
                    match &refinement.kind {
                        // Predicate names are resolved by the caller's
                        // closed checking policy, not by source lookup.
                        RefinementKind::Predicate(path) => {
                            for segment in &path.segments {
                                if !self.charge(segment.span) {
                                    return;
                                }
                            }
                        }
                        RefinementKind::Set(values) => {
                            for value in values {
                                let span = match value {
                                    Literal::Integer(integer) => integer.span,
                                    Literal::String(string) => string.span,
                                };
                                if !self.charge(span) {
                                    return;
                                }
                                if let Literal::String(string) = value {
                                    self.resolve_string(string, &BTreeMap::new());
                                }
                            }
                        }
                        RefinementKind::Range {
                            ..
                        } => {}
                    }
                }
            }
            ItemKind::Function(function) => self.resolve_function(module, function),
            ItemKind::Publication(publication) => {
                self.resolve_type(module, &publication.result, &BTreeMap::new());
                self.resolve_module_exports(
                    module,
                    &publication.namespace,
                    &publication.export,
                    located.item.span,
                );
            }
            ItemKind::Outputs(outputs) => {
                for output in &outputs.entries {
                    if !self.charge(output.span) {
                        return;
                    }
                    match &output.kind {
                        crate::syntax::OutputKind::Value {
                            name,
                            ty,
                            value,
                        } => {
                            self.with_owner(
                                module,
                                &name.text,
                                super::ResolutionOwnerPart::Declaration,
                                output.span,
                                |resolver| {
                                    resolver.resolve_type(module, ty, &BTreeMap::new());
                                    resolver.resolve_expression(
                                        module,
                                        value,
                                        &BTreeMap::new(),
                                        &BTreeMap::new(),
                                    );
                                },
                            );
                        }
                        crate::syntax::OutputKind::Type {
                            ty,
                            ..
                        } => {
                            self.resolve_type(module, ty, &BTreeMap::new());
                        }
                    }
                }
            }
        }
    }

    pub(super) fn resolve_function(&mut self, module: ModuleId, function: &Function) {
        let mut locals = BTreeMap::new();
        let mut types = BTreeMap::new();
        for parameter in &function.type_parameters {
            if !self.charge(parameter.span) {
                return;
            }
            if parameter.owner {
                self.error(
                    "`owner` is only valid on an opaque struct",
                    parameter.span,
                );
            }
            if types.contains_key(&parameter.name.text) {
                self.error("duplicate type parameter", parameter.span);
                continue;
            }
            let Some(id) = self.local(
                &parameter.name,
                crate::resolver::LocalKind::TypeParameter,
            ) else {
                return;
            };
            types.insert(parameter.name.text.clone(), id);
            self.editor_local(
                &parameter.name,
                id,
                function.name.span.join(function.body.span),
            );
        }
        for parameter in &function.parameters {
            self.resolve_type(module, &parameter.ty, &types);
            if locals.contains_key(&parameter.name.text) {
                self.error("duplicate function parameter", parameter.span);
                continue;
            }
            let Some(id) = self.local(
                &parameter.name,
                crate::resolver::LocalKind::Parameter,
            ) else {
                return;
            };
            locals.insert(parameter.name.text.clone(), id);
            self.editor_local(&parameter.name, id, function.body.span);
        }
        if let Some(result) = &function.result {
            self.resolve_type(module, result, &types);
        }
        self.resolve_block(module, &function.body, &mut locals, &types);
    }

    pub(super) fn resolve_block(
        &mut self,
        module: ModuleId,
        block: &Block,
        locals: &mut BTreeMap<String, LocalId>,
        types: &BTreeMap<String, LocalId>,
    ) {
        for statement in &block.statements {
            match &statement.kind {
                StatementKind::Recovery {
                    binding,
                } => {
                    if let Some(binding) = binding {
                        if let Some(ty) = &binding.ty {
                            self.resolve_type(module, ty, types);
                        }
                        let Some(id) =
                            self.local(&binding.name, crate::resolver::LocalKind::Binding)
                        else {
                            return;
                        };
                        locals.insert(binding.name.text.clone(), id);
                        self.editor_local(
                            &binding.name,
                            id,
                            crate::source::Span::new(
                                block.span.source_id(),
                                statement.span.end(),
                                block.span.end(),
                            ),
                        );
                    }
                }
                StatementKind::Let {
                    name,
                    ty,
                    value,
                } => {
                    if let Some(ty) = ty {
                        self.resolve_type(module, ty, types);
                    }
                    self.resolve_expression(module, value, locals, types);
                    let Some(id) = self.local(name, crate::resolver::LocalKind::Binding) else {
                        return;
                    };
                    locals.insert(name.text.clone(), id);
                    self.editor_local(
                        name,
                        id,
                        crate::source::Span::new(
                            block.span.source_id(),
                            statement.span.end(),
                            block.span.end(),
                        ),
                    );
                }
                StatementKind::Expression(expression) => {
                    self.resolve_expression(module, expression, locals, types);
                }
            }
        }
        if let Some(tail) = &block.tail {
            self.resolve_expression(module, tail, locals, types);
        }
    }

    pub(super) fn resolve_type(
        &mut self,
        module: ModuleId,
        root: &Type,
        locals: &BTreeMap<String, LocalId>,
    ) {
        let mut stack = vec![root];
        while let Some(ty) = stack.pop() {
            if !self.charge(ty.span) {
                return;
            }
            match &ty.kind {
                TypeKind::Named {
                    path,
                    arguments,
                } => {
                    if let Some(local) = single_local(path, locals) {
                        self.references.push(ResolvedReference {
                            span: path.span,
                            kind: ReferenceKind::Type,
                            target: ResolvedTarget::Local(local),
                        });
                    } else {
                        self.resolve_path(module, path, Expected::Type, ReferenceKind::Type);
                    }
                    stack.extend(arguments.iter().rev());
                }
                TypeKind::List(element) => stack.push(element),
                TypeKind::Function {
                    parameters,
                    result,
                    ..
                } => {
                    stack.push(result);
                    stack.extend(parameters.iter().rev());
                }
            }
        }
    }

    // Exhaustive traversal keeps lexical scopes and recovery in syntax order.
    pub(super) fn resolve_expression(
        &mut self,
        module: ModuleId,
        root: &Expression,
        value_locals: &BTreeMap<String, LocalId>,
        type_locals: &BTreeMap<String, LocalId>,
    ) {
        let mut stack = vec![root];
        while let Some(expression) = stack.pop() {
            if !self.charge(expression.span) {
                return;
            }
            match &expression.kind {
                ExpressionKind::Integer(_) => {}
                ExpressionKind::String(string) => {
                    self.resolve_string(string, value_locals);
                }
                ExpressionKind::Path(path) => self.resolve_value_path(module, path, value_locals),
                ExpressionKind::Memoize(value) => stack.push(value),
                ExpressionKind::SortByKeys {
                    items,
                    keys,
                } => {
                    stack.extend([keys.as_ref(), items.as_ref()]);
                }
                ExpressionKind::ModuleExports {
                    namespace,
                    export,
                    mapper,
                } => {
                    self.resolve_module_exports(module, namespace, export, expression.span);
                    stack.push(mapper);
                }
                ExpressionKind::Compare {
                    left,
                    right,
                    branches,
                } => {
                    stack.push(left);
                    stack.push(right);
                    stack.extend(branches.iter().map(AsRef::as_ref));
                }
                ExpressionKind::Fold {
                    items,
                    initial,
                    step,
                } => {
                    stack.extend([
                        step.as_ref(),
                        initial.as_ref(),
                        items.as_ref(),
                    ]);
                }
                ExpressionKind::Specialize {
                    function,
                    arguments,
                } => {
                    self.resolve_callee(module, function, &BTreeMap::new());
                    for ty in arguments {
                        self.resolve_type(module, ty, type_locals);
                    }
                }
                ExpressionKind::Call {
                    callee,
                    arguments,
                } => {
                    self.resolve_callee(module, callee, value_locals);
                    stack.extend(arguments.iter().rev());
                }
                ExpressionKind::Apply {
                    callee,
                    arguments,
                } => {
                    stack.extend(arguments.iter().rev());
                    stack.push(callee);
                }
                ExpressionKind::Closure {
                    parameters,
                    result,
                    body,
                    ..
                } => self.resolve_closure(
                    module,
                    parameters,
                    result,
                    body,
                    value_locals,
                    type_locals,
                ),
                ExpressionKind::Let(block) => {
                    self.resolve_block(
                        module,
                        block,
                        &mut value_locals.clone(),
                        type_locals,
                    );
                }
                ExpressionKind::Struct {
                    path,
                    type_arguments,
                    fields,
                    ..
                } => {
                    if !path.segments.is_empty() {
                        self.resolve_path(
                            module,
                            path,
                            Expected::Struct,
                            ReferenceKind::StructConstructor,
                        );
                    }
                    for ty in type_arguments {
                        self.resolve_type(module, ty, type_locals);
                    }
                    stack.extend(fields.iter().rev().map(|field| &field.value));
                }
                ExpressionKind::List(items) | ExpressionKind::Concat(items) => {
                    stack.extend(items.iter().rev());
                }
                ExpressionKind::Erase {
                    ty,
                    value,
                } => {
                    self.resolve_type(module, ty, type_locals);
                    stack.push(value);
                }
                ExpressionKind::Match {
                    value,
                    arms,
                } => {
                    stack.push(value);
                    for arm in arms {
                        self.resolve_match_arm(module, arm, value_locals, type_locals);
                    }
                }
                ExpressionKind::Group(inner)
                | ExpressionKind::Field {
                    value: inner,
                    ..
                } => {
                    stack.push(inner);
                }
            }
        }
    }

    fn resolve_value_path(
        &mut self,
        module: ModuleId,
        path: &Path,
        locals: &BTreeMap<String, LocalId>,
    ) {
        if let Some(local) = single_local(path, locals) {
            self.references.push(ResolvedReference {
                span: path.span,
                kind: ReferenceKind::Value,
                target: ResolvedTarget::Local(local),
            });
        } else if path.segments.len() == 1 {
            if self
                .lookup(module, path, Expected::Value)
                .is_some()
            {
                self.resolve_path(
                    module,
                    path,
                    Expected::Value,
                    ReferenceKind::Value,
                );
            } else {
                self.references.push(ResolvedReference {
                    span: path.span,
                    kind: ReferenceKind::Value,
                    target: ResolvedTarget::ContextualEnumVariant,
                });
            }
        } else if path
            .segments
            .first()
            .is_some_and(|segment| locals.contains_key(&segment.text))
        {
            self.error(
                "local value cannot qualify a `::` path",
                path.span,
            );
        } else {
            self.resolve_qualified_value(module, path, ReferenceKind::Value);
        }
    }

    fn resolve_closure(
        &mut self,
        module: ModuleId,
        parameters: &[crate::syntax::Parameter],
        result: &Type,
        body: &Block,
        value_locals: &BTreeMap<String, LocalId>,
        type_locals: &BTreeMap<String, LocalId>,
    ) {
        let mut locals = value_locals.clone();
        let mut names = std::collections::BTreeSet::new();
        for parameter in parameters {
            self.resolve_type(module, &parameter.ty, type_locals);
            if !names.insert(&parameter.name.text) {
                self.error("duplicate closure parameter", parameter.span);
                continue;
            }
            let Some(id) = self.local(
                &parameter.name,
                crate::resolver::LocalKind::Parameter,
            ) else {
                return;
            };
            locals.insert(parameter.name.text.clone(), id);
            self.editor_local(&parameter.name, id, body.span);
        }
        self.resolve_type(module, result, type_locals);
        self.resolve_block(module, body, &mut locals, type_locals);
    }

    fn resolve_callee(
        &mut self,
        module: ModuleId,
        callee: &Path,
        locals: &BTreeMap<String, LocalId>,
    ) {
        if let Some(local) = single_local(callee, locals) {
            self.references.push(ResolvedReference {
                span: callee.span,
                kind: ReferenceKind::Function,
                target: ResolvedTarget::Local(local),
            });
        } else if let Some((enumeration, index)) = self.lookup_variant(module, callee) {
            self.references.push(ResolvedReference {
                span: callee.span,
                kind: ReferenceKind::Function,
                target: ResolvedTarget::EnumVariant {
                    enumeration,
                    index,
                },
            });
        } else {
            self.resolve_path(
                module,
                callee,
                Expected::Function,
                ReferenceKind::Function,
            );
        }
    }

    pub(super) fn resolve_qualified_value(
        &mut self,
        module: ModuleId,
        path: &Path,
        kind: ReferenceKind,
    ) {
        if let Some((enumeration, index)) = self.lookup_variant(module, path) {
            self.references.push(ResolvedReference {
                span: path.span,
                kind,
                target: ResolvedTarget::EnumVariant {
                    enumeration,
                    index,
                },
            });
        } else {
            self.resolve_path(module, path, Expected::Value, kind);
        }
    }

    pub(super) fn resolve_string(
        &mut self,
        string: &StringLiteral,
        locals: &BTreeMap<String, LocalId>,
    ) {
        for part in &string.parts {
            let StringPart::Interpolation {
                path,
                ..
            } = part
            else {
                continue;
            };
            if !self.charge(path.span) {
                return;
            }
            if let Some(local) = first_local(path, locals) {
                self.references.push(ResolvedReference {
                    span: path.span,
                    kind: ReferenceKind::Interpolation,
                    target: ResolvedTarget::Local(local),
                });
            } else {
                self.error("unknown local in string interpolation", path.span);
            }
        }
    }

    pub(super) fn resolve_path(
        &mut self,
        module: ModuleId,
        path: &Path,
        expected: Expected,
        kind: ReferenceKind,
    ) {
        if !self.charge(path.span) {
            return;
        }
        match self.lookup(module, path, expected) {
            Some(target) => self.references.push(ResolvedReference {
                span: path.span,
                kind,
                target,
            }),
            None => self.unknown(expected.description(), path),
        }
    }
}

fn single_local(path: &Path, locals: &BTreeMap<String, LocalId>) -> Option<LocalId> {
    (path.segments.len() == 1)
        .then(|| locals.get(&path.segments[0].text).copied())
        .flatten()
}

fn first_local(path: &Path, locals: &BTreeMap<String, LocalId>) -> Option<LocalId> {
    path.segments
        .first()
        .and_then(|segment| locals.get(&segment.text).copied())
}

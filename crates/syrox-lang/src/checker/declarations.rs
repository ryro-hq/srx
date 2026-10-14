use super::index::literal_primitive;
use super::{
    BTreeMap, BTreeSet, Checker, Context, Item, ItemId, ItemKind, ModuleId, OutputKind,
    ParsedSource, Primitive, PrimitiveDeclaration, PrimitiveType, RawTy, RefinementKind,
    ResolvedItemKind, ResolvedTarget, Span, StructInfo, Ty,
};
use crate::syntax::Type;

impl Checker<'_> {
    pub(super) fn check_defaults(&mut self) {
        let structures: Vec<_> = self
            .structs
            .iter()
            .map(|(&id, info)| (id, info.clone()))
            .collect();
        for (id, info) in structures {
            let args: BTreeMap<_, _> = info
                .parameters
                .iter()
                .copied()
                .map(|parameter| (parameter, Ty::Parameter(parameter)))
                .collect();
            self.body.type_parameters = args.clone();
            for field in &info.declaration.fields {
                if !self.charge(field.span) {
                    return;
                }
                if let Some(default) = &field.default {
                    self.with_body(default.span, |checker| {
                        checker.body.bindings.clear();
                        checker.body.type_parameters = args.clone();
                        let want = checker.resolve_type(&field.ty, &args, 0);
                        let got = checker.check_expr(default, Some(&want), info.context, true);
                        checker.expect_same(&want, &got, default.span, "struct field default");
                    });
                }
            }
            self.body.type_parameters.clear();
            let _ = id;
        }
    }

    pub(super) fn check_functions(&mut self) {
        let functions: Vec<_> = self
            .functions
            .iter()
            .map(|(&id, info)| (id, *info))
            .collect();
        for (id, info) in functions {
            self.with_body(info.declaration.name.span, |checker| {
                checker.body.bindings.clear();
                checker.body.type_parameters = checker.function_parameters(id);
                let Some((parameter_types, result)) = checker.function_types.get(&id).cloned()
                else {
                    return;
                };
                if let Some(identity) = &info.declaration.package {
                    for literal in identity.iter() {
                        let value = &literal.source[1..literal.source.len() - 1];
                        if value.is_empty()
                            || value.len() > 128
                            || !value.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                            })
                        {
                            checker.error(
                                "package identity must contain bounded literal components",
                                literal.span,
                            );
                        }
                    }
                    if !parameter_types.is_empty() || !info.declaration.type_parameters.is_empty() {
                        checker.error(
                            "versioned package factory must have no parameters",
                            info.declaration.name.span,
                        );
                    }
                    let valid = result
                        .nominal_head()
                        .and_then(|item| checker.program.item(item))
                        .is_some_and(|item| {
                            item.domain() == crate::source::SourceDomainId::standard_library()
                                && item.path().segments() == ["std", "recipe", "PackageRef"]
                        });
                    if !valid {
                        checker.error(
                            "versioned package factory must return std::PackageRef",
                            info.declaration.name.span,
                        );
                    }
                }
                for (parameter, ty) in info
                    .declaration
                    .parameters
                    .iter()
                    .zip(parameter_types)
                {
                    if let Some(local) = checker.local_id(parameter.name.span) {
                        checker.bind_local(local, ty, parameter.name.span, true);
                    }
                }
                if checker
                    .incomplete_bodies
                    .contains(&super::span_key(info.declaration.name.span))
                {
                    return;
                }
                let got = checker.check_block(
                    &info.declaration.body,
                    Some(&result),
                    info.context,
                );
                checker.expect_same(
                    &result,
                    &got,
                    info.declaration.body.span,
                    "function return",
                );
                checker.body.type_parameters.clear();
            });
        }
    }

    pub(super) fn check_outputs(&mut self) {
        let program = self.program;
        for source in program.parsed().iter() {
            self.walk_outputs(source);
        }
    }

    pub(super) fn walk_outputs(&mut self, source: &ParsedSource) {
        let root = self
            .module_by_path
            .get(&source.domain())
            .and_then(|modules| modules.get(source.module()))
            .expect("root module")
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
            } else if let ItemKind::Publication(publication) = &item.kind {
                self.with_body(item.span, |checker| {
                    let want = checker.resolve_type(&publication.result, &BTreeMap::new(), 0);
                    checker.check_publication(&want, item.span);
                });
            } else if let ItemKind::Outputs(outputs) = &item.kind {
                let context = Context {
                    domain: source.domain(),
                    module,
                };
                for output in &outputs.entries {
                    if !self.charge(output.span) {
                        return;
                    }
                    match &output.kind {
                        OutputKind::Value {
                            name,
                            ty,
                            value,
                        } => {
                            self.with_body(output.span, |checker| {
                                checker.body.bindings.clear();
                                let want = checker.resolve_type(ty, &BTreeMap::new(), 0);
                                if let Some(id) = checker
                                    .item_at
                                    .get(&super::span_key(output.span))
                                    .copied()
                                    && checker.reserve_editor_metadata(name.span)
                                    && let Some(ty) = checker.retain_editor_type(&want)
                                {
                                    checker.editor.outputs.insert(id, ty);
                                }
                                let got = checker.check_expr(value, Some(&want), context, true);
                                checker.expect_same(&want, &got, value.span, "output value");
                            });
                        }
                        OutputKind::Type {
                            ty,
                            ..
                        } => {
                            self.check_type_output(ty);
                        }
                    }
                }
            }
        }
    }

    fn check_type_output(&mut self, ty: &Type) {
        // An interface may reexport a generic template without instantiating it;
        // applications are checked at use sites.
        let template = match &ty.kind {
            crate::syntax::TypeKind::Named {
                path,
                arguments,
            } if arguments.is_empty() => match self.target(path.span) {
                Some(ResolvedTarget::Item(item)) => Some(*item),
                _ => None,
            },
            _ => None,
        };
        if !template.is_some_and(|item| {
            self.structs
                .get(&item)
                .is_some_and(|info| !info.parameters.is_empty())
                || self
                    .aliases
                    .get(&item)
                    .is_some_and(|info| !info.parameters.is_empty())
                || self
                    .enums
                    .get(&item)
                    .is_some_and(|item| !item.type_parameters.is_empty())
        }) {
            self.resolve_type(ty, &BTreeMap::new(), 0);
        }
    }

    pub(super) fn validate_declarations(&mut self) {
        let aliases: Vec<_> = self.aliases.values().cloned().collect();
        for alias in aliases {
            let params = alias
                .parameters
                .iter()
                .copied()
                .map(|id| (id, RawTy::Parameter(id)))
                .collect();
            let ty = self.resolve_raw_type(&alias.declaration.ty, &params, 0);
            if let Some(concrete) = self.concretize(ty, &BTreeMap::new(), alias.declaration.ty.span)
            {
                self.track_generic_instances(&concrete, alias.declaration.ty.span);
            }
        }
        let structures: Vec<_> = self
            .structs
            .iter()
            .map(|(&id, info)| (id, info.clone()))
            .collect();
        for (id, info) in structures {
            self.validate_struct(id, &info);
        }
        self.validate_enums();
        let primitives: Vec<_> = self
            .primitives
            .iter()
            .map(|(&id, info)| (id, *info))
            .collect();
        for (id, info) in primitives {
            self.validate_primitive(id, info.declaration);
        }
    }

    pub(super) fn validate_struct(&mut self, id: ItemId, info: &StructInfo<'_>) {
        let declaration = &info.declaration;
        let mut fields = BTreeSet::new();
        let mut scopes = BTreeSet::new();
        let mut owner_count = 0;
        for parameter in &declaration.type_parameters {
            if !self.charge(parameter.span) {
                return;
            }
            if parameter.owner {
                owner_count += 1;
                if !declaration.opaque {
                    self.error(
                        "`owner` is only valid on an opaque struct",
                        parameter.span,
                    );
                }
            }
        }
        if owner_count > 1 {
            self.error(
                "an opaque struct may delegate construction to at most one type parameter",
                declaration.name.span,
            );
        }
        for scope in &declaration.scopes {
            if !self.charge(scope.span) {
                return;
            }
            if !scopes.insert(scope.text.clone()) {
                self.error(
                    format!("duplicate struct scope `{}`", scope.text),
                    scope.span,
                );
            }
            if !self.policy.scopes.contains_key(&scope.text) {
                self.error(
                    format!("unknown scope `{}`", scope.text),
                    scope.span,
                );
            }
        }
        let params: BTreeMap<_, _> = info
            .parameters
            .iter()
            .copied()
            .map(|parameter| (parameter, RawTy::Parameter(parameter)))
            .collect();
        let mut checked_fields = Vec::new();
        for field in &declaration.fields {
            if !self.charge(field.span) {
                return;
            }
            if !fields.insert(field.name.text.clone()) {
                self.error(
                    format!("duplicate field `{}`", field.name.text),
                    field.name.span,
                );
            }
            let ty = self.resolve_raw_type(&field.ty, &params, 0);
            if let Some(concrete) = self.concretize(ty.clone(), &BTreeMap::new(), field.span) {
                self.track_generic_instances(&concrete, field.ty.span);
            }
            checked_fields.push((
                field.name.text.clone(),
                ty,
                field.default.is_some(),
            ));
        }
        self.struct_fields.insert(id, checked_fields);
    }

    pub(super) fn validate_primitive(&mut self, id: ItemId, declaration: &PrimitiveDeclaration) {
        let is_value = self.item_kind(id) == Some(ResolvedItemKind::Value);
        if let Some(scope) = &declaration.scope {
            if is_value {
                self.error(
                    "a value cannot declare an ownership scope",
                    scope.span,
                );
            } else if !self.policy.scopes.contains_key(&scope.text) {
                self.error(
                    format!("unknown scope `{}`", scope.text),
                    scope.span,
                );
            }
        }
        let primitive = match declaration.primitive {
            Primitive::Int => PrimitiveType::Int,
            Primitive::Str => PrimitiveType::Str,
        };
        for refinement in &declaration.refinements {
            if !self.charge(refinement.span) {
                return;
            }
            match &refinement.kind {
                RefinementKind::Range {
                    start,
                    end,
                    inclusive,
                } => {
                    if primitive != PrimitiveType::Int {
                        self.error("a range can only refine `int`", refinement.span);
                    }
                    if start.value > end.value || (!inclusive && start.value == end.value) {
                        self.error(
                            "this range can never be satisfied",
                            refinement.span,
                        );
                    }
                }
                RefinementKind::Set(values) => {
                    if values.is_empty() {
                        self.error(
                            "a refinement set cannot be empty",
                            refinement.span,
                        );
                        continue;
                    }
                    let first = literal_primitive(&values[0]);
                    if values
                        .iter()
                        .any(|value| literal_primitive(value) != first)
                    {
                        self.error(
                            "a refinement set must be homogeneous",
                            refinement.span,
                        );
                    } else if first != primitive {
                        self.error(
                            "refinement set values have the wrong primitive type",
                            refinement.span,
                        );
                    }
                }
                RefinementKind::Predicate(path) => {
                    let name = path.display();
                    match self.policy.predicates.get(&name) {
                        Some(input) if *input == primitive => {}
                        Some(_) => self.error(
                            format!("predicate `{name}` has the wrong primitive input"),
                            path.span,
                        ),
                        None => self.error(format!("unknown predicate `{name}`"), path.span),
                    }
                }
            }
        }
    }
    pub(super) fn check_publication(&mut self, ty: &Ty, span: Span) {
        let expected = ty;
        let Some(entries) = self.program.module_exports(span) else {
            return;
        };
        for entry in entries {
            if !self.charge(span) || !self.reserve_metadata(span) {
                return;
            }
            if !self.function_parameters(entry.item()).is_empty() {
                self.error(
                    "published factory requires explicit generic specialization",
                    span,
                );
                continue;
            }
            let Some((parameters, result)) = self.function_types.get(&entry.item()).cloned() else {
                continue;
            };
            if !parameters.is_empty() {
                self.error("published factory must take no parameters", span);
            }
            self.expect_same(
                expected,
                &result,
                span,
                "published factory result",
            );
        }
    }
}

use super::types::raw_from_ty;
use super::{
    BTreeMap, BTreeSet, Block, CheckedExpression, CheckedPattern, Checker, Context, Elaboration,
    Expression, ExpressionKind, ItemId, MatchArm, Path, Pattern, Primitive, ResolvedTarget, Span,
    StatementKind, StringLiteral, StringPart, StructField, StructInfo, Ty, Type,
};

impl Checker<'_> {
    fn check_memoize(&mut self, value: &Expression, expected: Option<&Ty>, context: Context) -> Ty {
        let ty = self.check_expr(value, expected, context, true);
        if matches!(&ty, Ty::Function { parameters, once: false, .. } if parameters.is_empty()) {
            ty
        } else {
            self.error(
                "memoize requires a reusable function with no arguments",
                value.span,
            );
            Ty::Error
        }
    }

    pub(super) fn check_block(
        &mut self,
        block: &Block,
        expected: Option<&Ty>,
        context: Context,
    ) -> Ty {
        for statement in &block.statements {
            if !self.charge(statement.span) {
                return Ty::Error;
            }
            match &statement.kind {
                StatementKind::Recovery {
                    binding,
                } => {
                    self.recover_bindings(binding.as_ref(), statement.span);
                }
                StatementKind::Let {
                    name,
                    ty: annotation,
                    value,
                } => {
                    let before = self.body.fact_errors;
                    let before_unknown = self.body.fact_unknowns;
                    let expected = annotation
                        .as_ref()
                        .map(|ty| self.resolve_type(ty, &self.body.type_parameters.clone(), 0));
                    let actual = self.check_expr(value, expected.as_ref(), context, true);
                    if let Some(want) = &expected {
                        self.expect_same(want, &actual, value.span, "let binding");
                    }
                    let ty = expected.unwrap_or(actual);
                    let constant = self.package_constant(value);
                    if let Some(local) = self.local_id(name.span) {
                        self.bind_local(local, ty, name.span, annotation.is_some());
                        self.body
                            .bindings
                            .get_mut(&local)
                            .expect("bound local")
                            .constant = constant;
                        if before != self.body.fact_errors {
                            self.body
                                .bindings
                                .get_mut(&local)
                                .expect("bound local")
                                .status = super::TypeStatus::Invalid;
                            if let Some(fact) = self.editor.locals.get_mut(&local) {
                                fact.status = super::TypeStatus::Invalid;
                            }
                        } else if before_unknown != self.body.fact_unknowns {
                            self.body
                                .bindings
                                .get_mut(&local)
                                .expect("bound local")
                                .status = super::TypeStatus::Unknown;
                            if let Some(fact) = self.editor.locals.get_mut(&local) {
                                fact.status = super::TypeStatus::Unknown;
                            }
                        }
                    }
                }
                StatementKind::Expression(expression) => {
                    self.check_expr(expression, None, context, true);
                }
            }
        }
        let result = block.tail.as_ref().map_or(Ty::Unit, |tail| {
            self.check_expr(tail, expected, context, true)
        });
        if block.incomplete {
            self.body.fact_unknowns = self.body.fact_unknowns.saturating_add(1);
            Ty::Error
        } else {
            result
        }
    }

    pub(super) fn check_expr(
        &mut self,
        expression: &Expression,
        expected: Option<&Ty>,
        context: Context,
        consuming: bool,
    ) -> Ty {
        if !self.charge(expression.span) {
            return Ty::Error;
        }
        let mut elaboration = None;
        let before = self.body.fact_errors;
        let before_unknown = self.body.fact_unknowns;
        let ty = match &expression.kind {
            ExpressionKind::Integer(_) => self.lift_literal(Ty::Int, expected, &mut elaboration),
            ExpressionKind::String(string) => {
                self.check_string(string, context);
                self.lift_literal(Ty::Str, expected, &mut elaboration)
            }
            ExpressionKind::Path(path) => {
                self.check_path_value(path, expected, consuming, &mut elaboration)
            }
            ExpressionKind::Call {
                callee,
                arguments,
            } => self.check_call(
                callee,
                arguments,
                expected,
                context,
                &mut elaboration,
            ),
            ExpressionKind::Specialize {
                function,
                arguments,
            } => self.check_function_specialization(function, arguments, &mut elaboration),
            ExpressionKind::ModuleExports {
                mapper,
                ..
            } => self.check_module_exports(mapper, context, expression.span, &mut elaboration),
            ExpressionKind::Memoize(value) => self.check_memoize(value, expected, context),
            ExpressionKind::SortByKeys {
                items,
                keys,
            } => self.check_sort_by_keys(items, keys, expected, context),
            ExpressionKind::Compare {
                left,
                right,
                branches,
            } => self.check_compare(left, right, branches, expected, context),
            ExpressionKind::Fold {
                items,
                initial,
                step,
            } => self.check_fold(items, initial, step, expected, context),
            ExpressionKind::Apply {
                callee,
                arguments,
            } => {
                let ty = self.check_expr(callee, None, context, true);
                if let Ty::Function {
                    parameters,
                    result,
                    ..
                } = ty
                {
                    self.check_arguments(arguments, &parameters, context, callee.span);
                    *result
                } else {
                    self.error("callee is not a function value", callee.span);
                    Ty::Error
                }
            }
            ExpressionKind::Closure {
                parameters,
                result,
                body,
                once,
            } => self.check_closure(
                parameters,
                result,
                body,
                *once,
                context,
                expression.span,
            ),
            ExpressionKind::Let(block) => {
                let bindings = self.body.bindings.clone();
                let result = self.check_block(block, expected, context);
                // Preserve moves of enclosing affine values, discard lexical locals.
                self.body
                    .bindings
                    .retain(|local, _| bindings.contains_key(local));
                result
            }
            ExpressionKind::Struct {
                path,
                type_arguments,
                fields,
                recovery,
            } => self.check_struct_literal(
                path,
                type_arguments,
                fields,
                recovery,
                expected,
                context,
            ),
            ExpressionKind::List(items) => {
                self.check_list(items, expected, context, expression.span)
            }
            ExpressionKind::Erase {
                ty,
                value,
            } => {
                let result = self.check_erase(ty, value, context);
                if !matches!(result, Ty::Error) {
                    elaboration = Some(Elaboration::Erasure {
                        source: self.expression_ty(value.span),
                    });
                }
                result
            }
            ExpressionKind::Match {
                value,
                arms,
            } => self.check_match(value, arms, expected, context),
            ExpressionKind::Group(inner) => self.check_expr(inner, expected, context, consuming),
            ExpressionKind::Field {
                value,
                fields,
            } => {
                let mut ty = self.check_expr(value, None, context, true);
                for field in fields {
                    ty = self.project(&ty, &field.text, context, field.span);
                }
                ty
            }
            ExpressionKind::Concat(parts) => self.check_concat(parts, expected, context),
        };
        if self.reserve_metadata(expression.span) {
            self.expressions.push(CheckedExpression {
                span: expression.span,
                ty: ty.clone(),
                elaboration,
                expected: expected.cloned(),
                status: self.fact_status(&ty, before, before_unknown),
            });
        }
        ty
    }

    fn fact_status(&self, ty: &Ty, errors: u64, unknowns: u64) -> super::TypeStatus {
        if errors != self.body.fact_errors {
            super::TypeStatus::Invalid
        } else if unknowns == self.body.fact_unknowns && ty.is_known() {
            super::TypeStatus::Known
        } else {
            super::TypeStatus::Unknown
        }
    }

    fn check_concat(
        &mut self,
        parts: &[Expression],
        expected: Option<&Ty>,
        context: Context,
    ) -> Ty {
        let mut result: Option<Ty> = None;
        for part in parts {
            let got = self.check_expr(part, expected.or(result.as_ref()), context, true);
            if !matches!(got, Ty::List(_)) {
                self.error("`++` operands must be lists", part.span);
            }
            if let Some(want) = &result {
                self.expect_same(want, &got, part.span, "list concatenation");
            } else {
                result = Some(got);
            }
        }
        result.unwrap_or(Ty::Error)
    }

    // Contextual type, scope, consumption and recovery are independent checker inputs.
    #[allow(clippy::too_many_arguments)]
    fn check_closure(
        &mut self,
        parameters: &[crate::syntax::Parameter],
        result: &Type,
        body: &Block,
        once: bool,
        context: Context,
        span: Span,
    ) -> Ty {
        let mut outer = self.body.bindings.clone();
        let mut captures = BTreeSet::new();
        let mut recorded = BTreeSet::new();
        self.observe_reference_scan(span);
        for reference in self.program.references() {
            if !self.charge(reference.span()) {
                break;
            }
            let location = reference.span();
            if location.source_id() != span.source_id()
                || location.start() < span.start()
                || location.end() > span.end()
            {
                continue;
            }
            if let ResolvedTarget::Local(local) = reference.target()
                && let Some(binding) = outer.get(local)
            {
                if recorded.insert(*local) {
                    self.record_use(
                        *local,
                        location,
                        super::OwnershipUseKind::Capture,
                        Some(span),
                        once || !binding.affine,
                    );
                }
                if !binding.affine {
                    continue;
                }
                if !once {
                    self.error("closure cannot capture an affine value", location);
                } else if captures.insert(*local) {
                    self.capture_local(*local, location);
                    outer.get_mut(local).expect("outer capture").moved = Some(location);
                }
            }
        }
        for local in captures {
            self.body
                .bindings
                .get_mut(&local)
                .expect("capture binding")
                .moved = None;
        }
        let arguments: Vec<_> = parameters
            .iter()
            .map(|parameter| {
                self.resolve_type(
                    &parameter.ty,
                    &self.body.type_parameters.clone(),
                    0,
                )
            })
            .collect();
        let return_type = self.resolve_type(result, &self.body.type_parameters.clone(), 0);
        for (parameter, ty) in parameters.iter().zip(&arguments) {
            if let Some(local) = self.local_id(parameter.name.span) {
                self.bind_local(local, ty.clone(), parameter.name.span, true);
            }
        }
        let got = self.check_block(body, Some(&return_type), context);
        self.expect_same(&return_type, &got, body.span, "closure return");
        if body.incomplete {
            for binding in outer.values_mut() {
                if binding.affine {
                    binding.ownership_unknown = true;
                }
            }
        }
        self.body.bindings = outer;
        Ty::Function {
            parameters: arguments,
            result: Box::new(return_type),
            once,
        }
    }

    pub(super) fn check_path_value(
        &mut self,
        path: &Path,
        expected: Option<&Ty>,
        consuming: bool,
        elaboration: &mut Option<Elaboration>,
    ) -> Ty {
        match self.target(path.span).cloned() {
            Some(ResolvedTarget::Item(item)) if self.program.published_member(item).is_some() => {
                let factory = self
                    .program
                    .published_member(item)
                    .expect("checked above")
                    .factory();
                self.published_member_type(factory, path.span)
            }
            Some(ResolvedTarget::Local(local)) => self.use_local(local, path.span, consuming),
            Some(ResolvedTarget::EnumVariant {
                enumeration,
                index,
            }) => {
                if !self.variant_exists(enumeration, index, path.span) {
                    return Ty::Error;
                }
                self.empty_variant(enumeration, index, expected, path.span)
            }
            Some(ResolvedTarget::ContextualEnumVariant) => {
                let Some(enumeration) = expected.and_then(Ty::nominal_head) else {
                    self.error(
                        "bare enum variant requires an expected enum type",
                        path.span,
                    );
                    return Ty::Error;
                };
                let name = path
                    .segments
                    .last()
                    .map_or("", |segment| &segment.text);
                let Some(index) = self.variant_index(enumeration, name) else {
                    self.error(format!("enum has no variant `{name}`"), path.span);
                    return Ty::Error;
                };
                *elaboration = Some(Elaboration::ContextualVariant {
                    enumeration,
                    index,
                });
                self.empty_variant(enumeration, index, expected, path.span)
            }
            Some(ResolvedTarget::Item(item)) => {
                if let Some(ty) = self.output_values.get(&item).copied() {
                    let resolved = self.resolve_type(ty, &BTreeMap::new(), 0);
                    if self.affine(&resolved, path.span) {
                        self.error(
                            "an imported value output cannot carry an affine resource",
                            path.span,
                        );
                    }
                    return resolved;
                }
                if let Some((parameters, result)) = self.function_types.get(&item) {
                    if !self.function_parameters(item).is_empty() {
                        return self.infer_function_value(item, expected, path.span, elaboration);
                    }
                    return Ty::Function {
                        parameters: parameters.clone(),
                        result: Box::new(result.clone()),
                        once: false,
                    };
                }
                self.error(
                    "a declaration is not a value; call its constructor",
                    path.span,
                );
                Ty::Nominal(item)
            }
            _ => Ty::Error,
        }
    }

    pub(super) fn published_member_type(&mut self, factory: ItemId, span: Span) -> Ty {
        if !self.function_parameters(factory).is_empty() {
            self.error(
                "published factory requires explicit generic specialization",
                span,
            );
            return Ty::Error;
        }
        let Some((parameters, result)) = self.function_types.get(&factory) else {
            return Ty::Error;
        };
        if !parameters.is_empty() {
            self.error("catalog factory must not take parameters", span);
            return Ty::Error;
        }
        let Some(reference) = self.program.items().find(|item| {
            item.domain() == crate::source::SourceDomainId::standard_library()
                && item
                    .path()
                    .segments()
                    .iter()
                    .map(String::as_str)
                    .eq(["std", "recipe", "RecipeRef"])
        }) else {
            return Ty::Error;
        };
        Ty::Specialization {
            template: reference.id(),
            arguments: vec![result.clone()],
        }
    }

    pub(super) fn check_call(
        &mut self,
        callee: &Path,
        arguments: &[Expression],
        expected: Option<&Ty>,
        context: Context,
        elaboration: &mut Option<Elaboration>,
    ) -> Ty {
        if let Some(ResolvedTarget::EnumVariant {
            enumeration,
            index,
        }) = self.target(callee.span).cloned()
        {
            if !self.nominal_parameters(enumeration).is_empty() {
                let result = Ty::Specialization {
                    template: enumeration,
                    arguments: self
                        .nominal_parameters(enumeration)
                        .into_iter()
                        .map(Ty::Parameter)
                        .collect(),
                };
                let parameters = self.variant_payload(&result, index);
                return self
                    .infer_call(
                        enumeration,
                        &parameters,
                        &result,
                        arguments,
                        expected,
                        context,
                        callee.span,
                    )
                    .0;
            }
            let Ty::Function {
                parameters,
                result,
                ..
            } = self.variant_constructor(enumeration, index, &[], callee.span, &mut None)
            else {
                return Ty::Error;
            };
            self.check_arguments(arguments, &parameters, context, callee.span);
            return *result;
        }
        if let Some(ResolvedTarget::Local(local)) = self.target(callee.span).cloned() {
            let ty = self.use_local(local, callee.span, true);
            if let Ty::Function {
                parameters,
                result,
                ..
            } = ty
            {
                self.check_arguments(arguments, &parameters, context, callee.span);
                return *result;
            }
            self.error("callee is not a function value", callee.span);
            return Ty::Error;
        }
        let Some(ResolvedTarget::Item(item)) = self.target(callee.span).cloned() else {
            for argument in arguments {
                self.check_expr(argument, None, context, true);
            }
            return Ty::Error;
        };
        if self.output_values.contains_key(&item) {
            let ty = self.check_path_value(callee, None, true, &mut None);
            if let Ty::Function {
                parameters,
                result,
                ..
            } = ty
            {
                self.check_arguments(arguments, &parameters, context, callee.span);
                return *result;
            }
            self.error("callee is not a function value", callee.span);
            return Ty::Error;
        }
        if let Some((parameters, result)) = self.function_types.get(&item).cloned() {
            if self
                .functions
                .get(&item)
                .is_some_and(|info| info.declaration.package.is_some())
                && !arguments.is_empty()
            {
                return self.check_package_selection(item, arguments, elaboration, context);
            }
            self.record_arguments(item, arguments);
            if !self.function_parameters(item).is_empty() {
                let (result, substitutions) = self.infer_call(
                    item,
                    &parameters,
                    &result,
                    arguments,
                    expected,
                    context,
                    callee.span,
                );
                *elaboration = Some(Elaboration::FunctionSpecialization {
                    substitutions,
                });
                return result;
            }
            self.check_arguments(arguments, &parameters, context, callee.span);
            return result;
        }
        let Some(primitive) = self.primitives.get(&item).copied() else {
            self.error("callee is not callable", callee.span);
            return Ty::Error;
        };
        let inner = match primitive.declaration.primitive {
            Primitive::Int => Ty::Int,
            Primitive::Str => Ty::Str,
        };
        self.check_arguments(arguments, &[inner], context, callee.span);
        Ty::Nominal(item)
    }

    pub(super) fn check_arguments(
        &mut self,
        arguments: &[Expression],
        parameters: &[Ty],
        context: Context,
        span: Span,
    ) {
        if arguments.len() != parameters.len() {
            self.error(
                format!(
                    "expected {} argument(s), found {}",
                    parameters.len(),
                    arguments.len()
                ),
                span,
            );
        }
        for (index, argument) in arguments.iter().enumerate() {
            let expected = parameters.get(index);
            let got = self.check_expr(argument, expected, context, true);
            if let Some(want) = expected {
                self.expect_same(want, &got, argument.span, "call argument");
            }
        }
    }

    pub(super) fn check_struct_literal(
        &mut self,
        path: &Path,
        type_arguments: &[Type],
        fields: &[StructField],
        recovery: &[Span],
        expected: Option<&Ty>,
        context: Context,
    ) -> Ty {
        let item = if path.segments.is_empty() {
            let Some(item) = expected.and_then(Ty::nominal_head) else {
                self.error(
                    "attribute set requires an expected configuration type",
                    path.span,
                );
                return Ty::Error;
            };
            item
        } else if let Some(ResolvedTarget::Item(item)) = self.target(path.span).cloned() {
            item
        } else {
            return Ty::Error;
        };
        let raw_parameters: BTreeMap<_, _> = self
            .body
            .type_parameters
            .iter()
            .map(|(&parameter, ty)| (parameter, raw_from_ty(ty.clone())))
            .collect();
        let raw = if path.segments.is_empty() {
            raw_from_ty(expected.cloned().unwrap_or(Ty::Error))
        } else {
            self.expand_item_type(
                item,
                type_arguments,
                &raw_parameters,
                0,
                path.span,
            )
        };
        let ty = if path.segments.is_empty() {
            expected.cloned().unwrap_or(Ty::Error)
        } else {
            self.concretize(raw, &self.body.type_parameters.clone(), path.span)
                .unwrap_or(Ty::Error)
        };
        self.validate_concrete_type(&ty, path.span);
        self.track_generic_instances(&ty, path.span);
        let Some(info) = self.structs.get(&item).cloned() else {
            return Ty::Error;
        };
        if !self.has_representation_authority(&ty, &info, context) {
            self.error(
                "opaque struct constructor is private in this source domain",
                path.span,
            );
        }
        let canonical = self.item_identity(item);
        if self
            .policy
            .erasures
            .iter()
            .any(|rule| rule.target == canonical)
        {
            self.error(
                "an erasure target has no public literal constructor",
                path.span,
            );
        }
        let substitutions = self.specialization_substitutions(item, &ty);
        let declared: BTreeMap<_, _> = info
            .declaration
            .fields
            .iter()
            .map(|field| {
                (
                    field.name.text.clone(),
                    (
                        field.clone(),
                        self.resolve_type(&field.ty, &substitutions, 1),
                    ),
                )
            })
            .collect();
        let mut seen = BTreeSet::new();
        let mut gaps = recovery.iter().peekable();
        for field in fields {
            while gaps
                .peek()
                .is_some_and(|gap| gap.start() < field.span.start())
            {
                self.recover_bindings(None, *gaps.next().expect("recovery gap"));
            }
            if !seen.insert(field.name.text.clone()) {
                self.error(
                    format!("field `{}` is given twice", field.name.text),
                    field.name.span,
                );
            }
            if let Some((declaration, want)) = declared.get(&field.name.text) {
                self.record_field(field.name.span, declaration.name.span, want);
                let got = self.check_expr(&field.value, Some(want), context, true);
                self.expect_same(want, &got, field.value.span, "struct field");
                let _ = declaration;
            } else {
                self.check_expr(&field.value, None, context, true);
                self.error(
                    format!("unknown field `{}`", field.name.text),
                    field.name.span,
                );
            }
        }
        for gap in gaps {
            self.recover_bindings(None, *gap);
        }
        for (name, (field, _)) in declared {
            if recovery.is_empty() && field.default.is_none() && !seen.contains(&name) {
                self.error(format!("missing field `{name}`"), path.span);
            }
        }
        ty
    }

    pub(super) fn has_representation_authority(
        &self,
        ty: &Ty,
        info: &StructInfo<'_>,
        context: Context,
    ) -> bool {
        super::RepresentationAuthority::for_struct(info).permits(self.program, ty, context.module)
    }

    pub(super) fn check_list(
        &mut self,
        items: &[Expression],
        expected: Option<&Ty>,
        context: Context,
        span: Span,
    ) -> Ty {
        let expected_element = match expected {
            Some(Ty::List(element)) => Some(element.as_ref()),
            _ => None,
        };
        if items.is_empty() {
            return expected
                .cloned()
                .filter(|ty| matches!(ty, Ty::List(_)))
                .unwrap_or_else(|| {
                    self.error(
                        "an empty list requires a contextual list type",
                        span,
                    );
                    Ty::Error
                });
        }
        let mut element: Option<Ty> = expected_element.cloned();
        for item in items {
            let got = self.check_expr(item, element.as_ref(), context, true);
            if matches!(got, Ty::Unit) {
                self.error("lists cannot contain `unit`", item.span);
            }
            if let Some(want) = &element {
                self.expect_same(want, &got, item.span, "list element");
            } else {
                element = Some(got);
            }
        }
        Ty::List(Box::new(element.unwrap_or(Ty::Error)))
    }

    pub(super) fn check_erase(
        &mut self,
        target: &Type,
        value: &Expression,
        context: Context,
    ) -> Ty {
        let target_ty = self.resolve_type(target, &BTreeMap::new(), 0);
        let source_ty = self.check_expr(value, None, context, true);
        let Ty::Specialization {
            template,
            ..
        } = &source_ty
        else {
            self.error(
                "only a generic struct specialization can be erased",
                value.span,
            );
            return Ty::Error;
        };
        let Some(target_item) = Ty::nominal_head(&target_ty) else {
            self.error(
                "erasure target must be a non-generic struct",
                target.span,
            );
            return Ty::Error;
        };
        let source_name = self.item_identity(*template);
        let target_name = self.item_identity(target_item);
        if !self
            .policy
            .erasures
            .iter()
            .any(|rule| rule.source == source_name && rule.target == target_name)
        {
            self.error(
                "erasure is not allowed by the checking policy",
                target.span,
            );
            return Ty::Error;
        }
        if !matches!(target_ty, Ty::Nominal(_)) {
            self.error("erasure target must be non-generic", target.span);
            return Ty::Error;
        }
        let Some(target_info) = self.structs.get(&target_item).cloned() else {
            self.error("erasure target must be a struct", target.span);
            return Ty::Error;
        };
        if !target_info.declaration.scopes.is_empty()
            || target_info
                .declaration
                .fields
                .iter()
                .any(|field| field.default.is_some())
        {
            self.error(
                "erasure target cannot have scopes or defaults",
                target.span,
            );
        }
        let source_fields = self.fields_of(&source_ty);
        for field in &target_info.declaration.fields {
            let wanted = self.resolve_type(&field.ty, &BTreeMap::new(), 0);
            if !source_fields
                .iter()
                .any(|(name, ty)| name == &field.name.text && ty == &wanted)
            {
                self.error(
                    format!(
                        "erasure target field `{}` is not an exact source field",
                        field.name.text
                    ),
                    field.name.span,
                );
            }
        }
        target_ty
    }

    pub(super) fn check_match(
        &mut self,
        value: &Expression,
        arms: &[MatchArm],
        expected: Option<&Ty>,
        context: Context,
    ) -> Ty {
        let scrutinee = self.check_expr(value, None, context, true);
        let Some(enumeration) = Ty::nominal_head(&scrutinee) else {
            self.error("only an enum can be matched", value.span);
            return Ty::Error;
        };
        if !self.enums.contains_key(&enumeration) {
            self.error("only an enum can be matched", value.span);
            return Ty::Error;
        }
        let mut covered = BTreeSet::new();
        let mut wildcard = false;
        let baseline = self.body.bindings.clone();
        let mut merged = baseline.clone();
        let mut result = expected.cloned();
        for (arm_index, arm) in arms.iter().enumerate() {
            if !self.charge(arm.span) {
                return Ty::Error;
            }
            if wildcard {
                self.error(
                    "match arm is unreachable after wildcard",
                    arm.span,
                );
            }
            self.body.bindings = baseline.clone();
            match &arm.pattern {
                Pattern::Wildcard(_) => wildcard = true,
                Pattern::Path(path)
                | Pattern::Variant {
                    path,
                    ..
                } => {
                    let index = match self.target(path.span).cloned() {
                        Some(ResolvedTarget::EnumVariant {
                            enumeration: actual,
                            index,
                        }) if actual == enumeration => Some(index),
                        Some(ResolvedTarget::ContextualEnumVariant) => path
                            .segments
                            .last()
                            .and_then(|name| self.variant_index(enumeration, &name.text)),
                        Some(ResolvedTarget::EnumVariant {
                            ..
                        }) => {
                            self.error(
                                "match pattern belongs to a different enum",
                                path.span,
                            );
                            None
                        }
                        _ => None,
                    };
                    if let Some(index) = index {
                        self.bind_variant_pattern(&arm.pattern, &scrutinee, index, path.span);
                        if self.reserve_metadata(path.span) {
                            self.patterns.push(CheckedPattern {
                                span: path.span,
                                enumeration,
                                index,
                            });
                        }
                        if !covered.insert(index) {
                            self.error(
                                "enum variant is covered more than once",
                                path.span,
                            );
                        }
                    } else {
                        let name = path.segments.last().map_or("", |name| &name.text);
                        self.error(format!("enum has no variant `{name}`"), path.span);
                    }
                }
            }
            let got = self.check_expr(&arm.value, result.as_ref(), context, true);
            if let Some(want) = &result {
                self.expect_same(want, &got, arm.value.span, "match arm");
            } else {
                result = Some(got);
            }
            self.join_branch(&mut merged, arm_index == 0);
        }
        self.body.bindings = merged;
        if !wildcard {
            let count = self
                .enums
                .get(&enumeration)
                .map_or(0, |item| item.variants.len());
            if covered.len() != count {
                self.error("match is not exhaustive", value.span);
            }
        }
        result.unwrap_or(Ty::Error)
    }

    pub(super) fn check_string(&mut self, string: &StringLiteral, context: Context) {
        for part in &string.parts {
            let StringPart::Interpolation {
                path,
                ..
            } = part
            else {
                continue;
            };
            let Some(ResolvedTarget::Local(local)) = self.target(path.span).cloned() else {
                continue;
            };
            let mut ty = self.use_local(local, path.span, true);
            for field in path.segments.iter().skip(1) {
                ty = self.project(&ty, &field.text, context, field.span);
            }
            let wrapper = match ty {
                Ty::Nominal(item) => self.primitives.contains_key(&item),
                _ => false,
            };
            if !matches!(ty, Ty::Int | Ty::Str | Ty::Error) && !wrapper {
                self.error(
                    "interpolation requires a primitive or primitive wrapper",
                    path.span,
                );
            }
        }
    }
}

use super::types::raw_from_ty;
use super::{
    BTreeMap, Checker, Context, Elaboration, Expression, Path, Primitive, ResolvedItemKind,
    ResolvedTarget, Span, Ty, Type,
};

impl Checker<'_> {
    pub(super) fn check_sort_by_keys(
        &mut self,
        items: &Expression,
        keys: &Expression,
        expected: Option<&Ty>,
        context: Context,
    ) -> Ty {
        let items_ty = self.check_expr(items, expected, context, true);
        let keys_ty = self.check_expr(keys, None, context, true);
        if !matches!(items_ty, Ty::List(_) | Ty::Error) {
            self.error("sort_by_keys requires an item list", items.span);
        }
        if !matches!(&keys_ty, Ty::List(key) if self.ordered_type(key)) {
            self.error(
                "sort keys must be a list of reusable primitive values",
                keys.span,
            );
        }
        items_ty
    }

    fn ordered_type(&self, ty: &Ty) -> bool {
        match ty {
            Ty::Int | Ty::Str | Ty::Error => true,
            Ty::Nominal(item) => {
                self.primitives.contains_key(item)
                    && self.item_kind(*item) == Some(ResolvedItemKind::Value)
            }
            _ => false,
        }
    }

    pub(super) fn check_compare(
        &mut self,
        left: &Expression,
        right: &Expression,
        branches: &[Box<Expression>; 3],
        expected: Option<&Ty>,
        context: Context,
    ) -> Ty {
        let operand = self.check_expr(left, None, context, true);
        let right_ty = self.check_expr(right, Some(&operand), context, true);
        self.expect_same(
            &operand,
            &right_ty,
            right.span,
            "comparison operand",
        );
        if !self.ordered_type(&operand) {
            self.error(
                "comparison requires integers, strings or reusable primitive values",
                left.span,
            );
        }
        let baseline = self.body.bindings.clone();
        let mut merged = baseline.clone();
        let mut result = expected.cloned();
        for (index, branch) in branches.iter().enumerate() {
            for _ in baseline.values() {
                if !self.charge(branch.span) {
                    return Ty::Error;
                }
            }
            self.body.bindings = baseline.clone();
            let actual = self.check_expr(branch, result.as_ref(), context, true);
            if let Some(expected) = &result {
                self.expect_same(
                    expected,
                    &actual,
                    branch.span,
                    "comparison branch",
                );
            } else {
                result = Some(actual);
            }
            self.join_branch(&mut merged, index == 0);
        }
        self.body.bindings = merged;
        result.unwrap_or(Ty::Error)
    }

    pub(super) fn check_fold(
        &mut self,
        items: &Expression,
        initial: &Expression,
        step: &Expression,
        expected: Option<&Ty>,
        context: Context,
    ) -> Ty {
        let items_ty = self.check_expr(items, None, context, true);
        let accumulator = self.check_expr(initial, expected, context, true);
        let Ty::List(element) = items_ty else {
            self.error("fold requires a list", items.span);
            return Ty::Error;
        };
        let signature = Ty::Function {
            once: false,
            parameters: vec![accumulator.clone(), *element],
            result: Box::new(accumulator.clone()),
        };
        let got = self.check_expr(step, Some(&signature), context, true);
        self.expect_same(&signature, &got, step.span, "fold step");
        accumulator
    }

    pub(super) fn check_function_specialization(
        &mut self,
        function: &Path,
        arguments: &[Type],
        elaboration: &mut Option<Elaboration>,
    ) -> Ty {
        if let Some(ResolvedTarget::EnumVariant {
            enumeration,
            index,
        }) = self.target(function.span).cloned()
        {
            return self.variant_constructor(
                enumeration,
                index,
                arguments,
                function.span,
                elaboration,
            );
        }
        let Some(ResolvedTarget::Item(item)) = self.target(function.span).cloned() else {
            return Ty::Error;
        };
        let Some(info) = self.functions.get(&item).copied() else {
            self.error(
                "type arguments require a generic function",
                function.span,
            );
            return Ty::Error;
        };
        let parameters = &info.declaration.type_parameters;
        if parameters.is_empty() || parameters.len() != arguments.len() {
            self.error(
                "generic function type argument count mismatch",
                function.span,
            );
            return Ty::Error;
        }
        let outer = self.body.type_parameters.clone();
        let mut substitutions = BTreeMap::new();
        let mut instance = Vec::with_capacity(arguments.len());
        for (parameter, argument) in parameters.iter().zip(arguments) {
            let ty = self.resolve_type(argument, &outer, 0);
            instance.push(ty.clone());
            let Some(local) = self.local_id(parameter.name.span) else {
                return Ty::Error;
            };
            substitutions.insert(local, ty);
        }
        self.track_generic_instances(
            &Ty::Specialization {
                template: item,
                arguments: instance,
            },
            function.span,
        );
        let Some((parameters, result)) = self.function_types.get(&item).cloned() else {
            return Ty::Error;
        };
        let signature = Ty::Function {
            once: false,
            parameters,
            result: Box::new(result),
        };
        let ty = self
            .concretize(
                raw_from_ty(signature),
                &substitutions,
                function.span,
            )
            .unwrap_or(Ty::Error);
        self.validate_concrete_type(&ty, function.span);
        self.track_generic_instances(&ty, function.span);
        *elaboration = Some(Elaboration::FunctionSpecialization {
            substitutions,
        });
        ty
    }
}

impl Checker<'_> {
    pub(super) fn check_module_exports(
        &mut self,
        mapper: &Expression,
        context: Context,
        span: Span,
        elaboration: &mut Option<Elaboration>,
    ) -> Ty {
        let mapper_ty = self.check_expr(mapper, None, context, true);
        let Ty::Function {
            parameters,
            result,
            once: false,
        } = mapper_ty
        else {
            self.error(
                "module mapper must be a reusable function",
                mapper.span,
            );
            return Ty::Error;
        };
        let [
            Ty::Nominal(key),
            function @ Ty::Function {
                once: false,
                ..
            },
        ] = parameters.as_slice()
        else {
            self.error(
                "module mapper requires a string value key and a reusable function parameter",
                mapper.span,
            );
            return Ty::Error;
        };
        if self.item_kind(*key) != Some(ResolvedItemKind::Value)
            || !self
                .primitives
                .get(key)
                .is_some_and(|info| info.declaration.primitive == Primitive::Str)
        {
            self.error(
                "module key must be a reusable value(str) type",
                mapper.span,
            );
        }
        if matches!(result.as_ref(), Ty::Unit) {
            self.error(
                "module mapper cannot produce unit list elements",
                mapper.span,
            );
        }
        let Some(entries) = self.program.module_exports(span) else {
            return Ty::Error;
        };
        for entry in entries {
            if !self.charge(span) || !self.reserve_metadata(span) {
                return Ty::Error;
            }
            self.collection_metadata_units += 1;
            if !self.function_parameters(entry.item()).is_empty() {
                self.error(
                    format!(
                        "module export `{}` requires explicit generic specialization",
                        entry.key()
                    ),
                    mapper.span,
                );
                continue;
            }
            let Some((parameters, result)) = self.function_types.get(&entry.item()).cloned() else {
                continue;
            };
            let signature = Ty::Function {
                parameters,
                result: Box::new(result),
                once: false,
            };
            let Some(signature) = self.concretize(raw_from_ty(signature), &BTreeMap::new(), span)
            else {
                return Ty::Error;
            };
            self.expect_same(
                function,
                &signature,
                mapper.span,
                &format!("module export `{}`", entry.key()),
            );
        }
        *elaboration = Some(Elaboration::ModuleExports {
            key: *key,
            function: function.clone(),
        });
        Ty::List(result)
    }
}

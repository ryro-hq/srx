use super::types::raw_from_ty;
use super::{BTreeMap, Checker, Context, Expression, ItemId, LocalId, Span, Ty};

impl Checker<'_> {
    // Inference is local and directed: result context first, then arguments in
    // source order. Expressions are checked exactly once, including affine moves.
    // Context, substitutions and argument positions are distinct inference inputs.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn infer_call(
        &mut self,
        item: ItemId,
        parameters: &[Ty],
        result: &Ty,
        arguments: &[Expression],
        expected: Option<&Ty>,
        context: Context,
        span: Span,
    ) -> (Ty, BTreeMap<LocalId, Ty>) {
        let mut substitutions = BTreeMap::new();
        if let Some(expected) = expected {
            self.infer_type(result, expected, &mut substitutions, span);
        }
        if parameters.len() != arguments.len() {
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
            let parameter = parameters.get(index);
            let contextual = parameter.and_then(|ty| {
                self.concretize(
                    raw_from_ty(ty.clone()),
                    &substitutions,
                    argument.span,
                )
            });
            let actual = self.check_expr(argument, contextual.as_ref(), context, true);
            if let Some(parameter) = parameter {
                self.infer_type(
                    parameter,
                    &actual,
                    &mut substitutions,
                    argument.span,
                );
            }
        }
        self.finish_inference(item, &substitutions, span);
        let result = self
            .concretize(raw_from_ty(result.clone()), &substitutions, span)
            .unwrap_or(Ty::Error);
        self.validate_concrete_type(&result, span);
        self.track_generic_instances(&result, span);
        (result, substitutions)
    }

    pub(super) fn infer_function_value(
        &mut self,
        item: ItemId,
        expected: Option<&Ty>,
        span: Span,
        elaboration: &mut Option<super::Elaboration>,
    ) -> Ty {
        let Some(
            expected @ Ty::Function {
                ..
            },
        ) = expected
        else {
            self.error(
                "generic function requires explicit type arguments or a contextual function type",
                span,
            );
            return Ty::Error;
        };
        let (parameters, result) = self.function_types[&item].clone();
        let signature = Ty::Function {
            parameters,
            result: Box::new(result),
            once: false,
        };
        let mut substitutions = BTreeMap::new();
        self.infer_type(&signature, expected, &mut substitutions, span);
        self.finish_inference(item, &substitutions, span);
        let ty = self
            .concretize(raw_from_ty(signature), &substitutions, span)
            .unwrap_or(Ty::Error);
        self.validate_concrete_type(&ty, span);
        self.track_generic_instances(&ty, span);
        *elaboration = Some(super::Elaboration::FunctionSpecialization {
            substitutions,
        });
        ty
    }

    fn finish_inference(
        &mut self,
        item: ItemId,
        substitutions: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) {
        let parameters: Vec<_> = if self.functions.contains_key(&item) {
            self.functions[&item]
                .declaration
                .type_parameters
                .iter()
                .filter_map(|parameter| self.local_id(parameter.name.span))
                .collect()
        } else {
            self.nominal_parameters(item)
        };
        let Some(arguments) = parameters
            .iter()
            .map(|id| substitutions.get(id).cloned())
            .collect::<Option<Vec<_>>>()
        else {
            self.error(
                "cannot infer all generic arguments; supply explicit type arguments",
                span,
            );
            return;
        };
        self.track_generic_instances(
            &Ty::Specialization {
                template: item,
                arguments,
            },
            span,
        );
    }

    fn infer_type(
        &mut self,
        pattern: &Ty,
        actual: &Ty,
        substitutions: &mut BTreeMap<LocalId, Ty>,
        span: Span,
    ) {
        let mut pending = vec![(pattern, actual)];
        while let Some((pattern, actual)) = pending.pop() {
            if !self.charge(span) {
                return;
            }
            match (pattern, actual) {
                (_, Ty::Error) | (Ty::Error, _) => {}
                (Ty::Parameter(id), actual) => {
                    if let Some(previous) = substitutions.get(id) {
                        self.expect_same(
                            previous,
                            actual,
                            span,
                            "inferred generic argument",
                        );
                    } else {
                        substitutions.insert(*id, actual.clone());
                    }
                }
                (Ty::List(pattern), Ty::List(actual)) => pending.push((pattern, actual)),
                (
                    Ty::Specialization {
                        template: left,
                        arguments: patterns,
                    },
                    Ty::Specialization {
                        template: right,
                        arguments: actuals,
                    },
                ) if left == right && patterns.len() == actuals.len() => {
                    pending.extend(patterns.iter().zip(actuals));
                }
                (
                    Ty::Function {
                        parameters: patterns,
                        result: left,
                        once: left_once,
                    },
                    Ty::Function {
                        parameters: actuals,
                        result: right,
                        once: right_once,
                    },
                ) if left_once == right_once && patterns.len() == actuals.len() => {
                    pending.push((left, right));
                    pending.extend(patterns.iter().zip(actuals));
                }
                _ => self.expect_same(pattern, actual, span, "generic inference"),
            }
        }
    }
}

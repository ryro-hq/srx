//! Known arguments specialize a body under the ordinary checking budget.
use super::{
    Checker, Constant, Context, Elaboration, Expression, ExpressionKind, ItemId, Pattern,
    ResolvedTarget, Span, StaticFacts, Ty,
};
use std::{collections::BTreeMap, sync::Arc};

impl Checker<'_> {
    pub(super) fn constant_value(
        &mut self,
        expression: &Expression,
        depth: usize,
    ) -> Option<Constant> {
        if depth >= self.limits.max_specialization_depth || !self.charge(expression.span) {
            return None;
        }
        match &expression.kind {
            ExpressionKind::List(items) => items
                .iter()
                .map(|item| self.constant_value(item, depth + 1))
                .collect::<Option<Vec<_>>>()
                .map(|items| Constant::List(items.into())),
            ExpressionKind::If {
                condition,
                branches,
            } => {
                let Constant::Boolean(value) = self.constant_value(condition, depth + 1)? else {
                    return None;
                };
                self.constant_value(&branches[usize::from(!value)], depth + 1)
            }
            ExpressionKind::Match {
                value,
                arms,
            } => {
                let value = self.constant_value(value, depth + 1)?;
                for arm in arms {
                    if self.static_pattern_matches(&arm.pattern, &value, arm.span) {
                        return self.constant_value(&arm.value, depth + 1);
                    }
                }
                None
            }
            ExpressionKind::Let(block) => {
                let bindings = self.body.bindings.clone();
                let result = (|| {
                    for statement in &block.statements {
                        if let super::StatementKind::Let {
                            name,
                            value,
                            ..
                        } = &statement.kind
                        {
                            let constant = self.constant_value(value, depth + 1)?;
                            let local = self.local_id(name.span)?;
                            self.bind_local(
                                local,
                                self.expression_ty(value.span),
                                name.span,
                                false,
                            );
                            self.body.bindings.get_mut(&local)?.constant = Some(constant);
                        } else {
                            return None;
                        }
                    }
                    self.constant_value(block.tail.as_ref()?, depth + 1)
                })();
                self.body.bindings = bindings;
                result
            }
            ExpressionKind::Integer(value) => Some(Constant::Integer(value.value)),
            ExpressionKind::String(_) => self
                .string_constant(expression)
                .map(Constant::String),
            ExpressionKind::Group(value) => self.constant_value(value, depth + 1),
            ExpressionKind::Path(path) => match self.target(path.span) {
                Some(ResolvedTarget::Local(local)) => {
                    self.body.bindings.get(local)?.constant.clone()
                }
                Some(ResolvedTarget::EnumVariant {
                    enumeration,
                    index,
                }) if self.program.item(*enumeration)?.path().segments() == ["std", "Bool"] => {
                    Some(Constant::Boolean(*index == 1))
                }
                _ => None,
            },
            ExpressionKind::Equality {
                left,
                right,
                negated,
            } => {
                let left = self.constant_value(left, depth + 1)?;
                let right = self.constant_value(right, depth + 1)?;
                let equal = match (&left, &right) {
                    (Constant::String(left), Constant::String(right)) => left == right,
                    (Constant::Integer(left), Constant::Integer(right)) => left == right,
                    (Constant::Boolean(left), Constant::Boolean(right)) => left == right,
                    _ => return None,
                };
                Some(Constant::Boolean(equal != *negated))
            }
            ExpressionKind::Field {
                value,
                fields,
            } => {
                let mut value = self.constant_value(value, depth + 1)?;
                for field in fields {
                    let Constant::Struct(fields) = value else {
                        return None;
                    };
                    value = fields.get(&field.text)?.clone();
                }
                Some(value)
            }
            ExpressionKind::Struct {
                fields,
                ..
            } => {
                let ty = self.expression_ty(expression.span);
                let item = ty.nominal_head()?;
                let declaration = self.structs.get(&item)?.declaration;
                let mut values = BTreeMap::new();
                for field in &declaration.fields {
                    let expression = fields
                        .iter()
                        .find(|given| given.name.text == field.name.text)
                        .map(|given| &given.value)
                        .or(field.default.as_ref())?;
                    values.insert(
                        field.name.text.clone(),
                        self.constant_value(expression, depth + 1)?,
                    );
                }
                Some(Constant::Struct(Arc::new(values)))
            }
            ExpressionKind::Call {
                ..
            }
            | ExpressionKind::MethodCall {
                ..
            } => self
                .expressions
                .iter()
                .rev()
                .find(|fact| fact.span == expression.span)
                .and_then(|fact| match &fact.elaboration {
                    Some(Elaboration::StaticCall {
                        constant,
                        ..
                    }) => constant.clone(),
                    _ => None,
                }),
            _ => None,
        }
    }

    pub(super) fn static_pattern_matches(
        &mut self,
        pattern: &Pattern,
        value: &Constant,
        span: Span,
    ) -> bool {
        match pattern {
            Pattern::Wildcard(_) => true,
            Pattern::Literal(literal) => {
                let expression = Expression {
                    span,
                    kind: match literal {
                        super::Literal::Integer(value) => ExpressionKind::Integer(value.clone()),
                        super::Literal::String(value) => ExpressionKind::String(value.clone()),
                    },
                };
                self.constant_value(&expression, 0).as_ref() == Some(value)
            }
            _ => false,
        }
    }

    pub(super) fn check_static_call(
        &mut self,
        item: ItemId,
        arguments: &[Expression],
        context: Context,
        span: Span,
        elaboration: &mut Option<Elaboration>,
    ) -> Ty {
        self.observe_effect(
            span,
            super::bodies::EffectOperation::Specialization,
        );
        if self.static_calls.len() >= self.limits.max_specialization_depth
            || self.static_instances >= self.limits.max_generic_instances
        {
            self.error("constant specialization limit reached", span);
            return Ty::Error;
        }
        self.static_instances += 1;
        let info = self.functions[&item];
        let (mut parameters, _) = self.function_types[&item].clone();
        let mut supplied = BTreeMap::new();
        if info.declaration.type_parameters.is_empty() {
            self.check_arguments(arguments, &parameters, context, span);
        } else {
            supplied = self
                .infer_call(
                    item,
                    &parameters,
                    &Ty::Error,
                    arguments,
                    None,
                    context,
                    span,
                )
                .1;
            self.validate_bounds(&supplied, span);
            parameters = info
                .declaration
                .parameters
                .iter()
                .map(|parameter| self.resolve_type(&parameter.ty, &supplied, 0))
                .collect();
            for (want, argument) in parameters.iter().zip(arguments) {
                self.expect_same(
                    want,
                    &self.expression_ty(argument.span),
                    argument.span,
                    "specialized call argument",
                );
            }
        }
        if arguments.len() != parameters.len() {
            return Ty::Error;
        }
        let mut constants = Vec::with_capacity(arguments.len());
        for (parameter, argument) in info.declaration.parameters.iter().zip(arguments) {
            let constant = self.constant_value(argument, 0);
            if parameter.constant && constant.is_none() {
                self.error(
                    "const argument must be a known literal or constant",
                    argument.span,
                );
                return Ty::Error;
            }
            constants.push(constant);
        }
        let bindings = std::mem::take(&mut self.body.bindings);
        let substitutions = std::mem::take(&mut self.body.type_parameters);
        self.body.type_parameters = supplied.clone();
        let previous_mode = std::mem::replace(
            &mut self.static_mode,
            info.declaration.is_static(),
        );
        let result = info
            .declaration
            .result
            .as_ref()
            .map_or(Ty::Unit, |result| {
                if info.declaration.inferred_result() {
                    Ty::Error
                } else {
                    self.resolve_type(result, &supplied, 0)
                }
            });
        self.static_calls.push(span);
        let expression_start = self.expressions.len();
        let pattern_start = self.patterns.len();
        for ((parameter, ty), constant) in info
            .declaration
            .parameters
            .iter()
            .zip(parameters)
            .zip(constants)
        {
            if let Some(local) = self.local_id(parameter.name.span) {
                self.bind_local(local, ty, parameter.name.span, true);
                self.body
                    .bindings
                    .get_mut(&local)
                    .expect("bound parameter")
                    .constant = constant;
            }
        }
        let inferred = info.declaration.inferred_result();
        let actual = self.check_block(
            &info.declaration.body,
            if inferred {
                None
            } else {
                Some(&result)
            },
            info.context,
        );
        if !inferred {
            self.expect_same(
                &result,
                &actual,
                span,
                "specialized function return",
            );
        }
        let constant = info
            .declaration
            .body
            .tail
            .as_ref()
            .and_then(|tail| self.constant_value(tail, 0));
        let facts = StaticFacts {
            substitutions: supplied,
            expressions: self
                .expressions
                .drain(expression_start..)
                .map(|fact| (super::span_key(fact.span), fact))
                .collect(),
            patterns: self
                .patterns
                .drain(pattern_start..)
                .map(|fact| (super::span_key(fact.span), fact))
                .collect(),
        };
        self.collection_metadata_units += facts.expressions.len() + facts.patterns.len();
        self.static_calls.pop();
        self.static_mode = previous_mode;
        self.body.bindings = bindings;
        self.body.type_parameters = substitutions;
        *elaboration = Some(Elaboration::StaticCall {
            function: item,
            facts: Arc::new(facts),
            constant,
        });
        if inferred {
            actual
        } else {
            result
        }
    }
}

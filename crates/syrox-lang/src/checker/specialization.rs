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
                let scrutinee = self.expression_ty(value.span);
                let value = self.constant_value(value, depth + 1)?;
                for arm in arms {
                    if self.static_pattern_matches(&arm.pattern, &value, arm.span) {
                        let bindings = self.body.bindings.clone();
                        if let Constant::Variant {
                            index,
                            ..
                        } = &value
                        {
                            self.bind_variant_pattern(
                                &arm.pattern,
                                &scrutinee,
                                *index,
                                Some(&value),
                            );
                        }
                        let result = self.constant_value(&arm.value, depth + 1);
                        self.body.bindings = bindings;
                        return result;
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
                Some(ResolvedTarget::Item(item)) if self.global_values.contains_key(item) => {
                    let item = *item;
                    self.check_global(item, path.span);
                    self.global_constants.get(&item).cloned()
                }
                Some(ResolvedTarget::Local(local)) => {
                    self.body.bindings.get(local)?.constant.clone()
                }
                Some(ResolvedTarget::EnumVariant {
                    enumeration,
                    index,
                }) => Some(self.variant_constant(*enumeration, *index, Vec::new())),
                Some(ResolvedTarget::ContextualEnumVariant) => {
                    let fact = self
                        .expressions
                        .iter()
                        .rev()
                        .find(|fact| fact.span == expression.span)?;
                    let Some(Elaboration::ContextualVariant {
                        enumeration,
                        index,
                    }) = fact.elaboration
                    else {
                        return None;
                    };
                    Some(self.variant_constant(enumeration, index, Vec::new()))
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
            } => {
                if let ExpressionKind::Call {
                    callee,
                    arguments,
                } = &expression.kind
                    && let Some(ResolvedTarget::EnumVariant {
                        enumeration,
                        index,
                    }) = self.target(callee.span).cloned()
                {
                    let payload = arguments
                        .iter()
                        .map(|argument| self.constant_value(argument, depth + 1))
                        .collect();
                    return Some(self.variant_constant(enumeration, index, payload));
                }
                if let ExpressionKind::Call {
                    callee,
                    arguments,
                } = &expression.kind
                    && let Some(ResolvedTarget::Item(item)) = self.target(callee.span)
                    && self.item_kind(*item) == Some(super::ResolvedItemKind::Value)
                    && self.primitives.contains_key(item)
                    && arguments.len() == 1
                {
                    return self.constant_value(&arguments[0], depth + 1);
                }
                self.expressions
                    .iter()
                    .rev()
                    .find(|fact| fact.span == expression.span)
                    .and_then(|fact| match &fact.elaboration {
                        Some(Elaboration::StaticCall {
                            constant,
                            ..
                        }) => constant.clone(),
                        _ => None,
                    })
            }
            ExpressionKind::Apply {
                callee,
                arguments,
            } => {
                let mut callee = callee.as_ref();
                while let ExpressionKind::Group(inner) = &callee.kind {
                    callee = inner;
                }
                let fact = self
                    .expressions
                    .iter()
                    .rev()
                    .find(|fact| fact.span == callee.span)?;
                let Some(Elaboration::VariantConstructor {
                    index,
                }) = fact.elaboration
                else {
                    return None;
                };
                let enumeration = self
                    .expression_ty(expression.span)
                    .nominal_head()?;
                let payload = arguments
                    .iter()
                    .map(|argument| self.constant_value(argument, depth + 1))
                    .collect();
                Some(self.variant_constant(enumeration, index, payload))
            }
            _ => None,
        }
    }

    fn variant_constant(
        &self,
        enumeration: ItemId,
        index: u32,
        payload: Vec<Option<Constant>>,
    ) -> Constant {
        if self
            .program
            .item(enumeration)
            .is_some_and(|item| {
                item.domain() == crate::source::SourceDomainId::standard_library()
                    && item.path().segments() == ["std", "Bool"]
            })
        {
            Constant::Boolean(index == 1)
        } else {
            Constant::Variant {
                enumeration,
                index,
                payload: payload.into(),
            }
        }
    }

    // A known discriminant may carry lazy/unknown values. It can select a
    // match arm, but a const parameter still requires every payload to be known.
    // Visit shared constant nodes once instead of expanding their graph.
    fn complete_constant(&mut self, constant: &Constant, span: Span) -> bool {
        let mut pending = vec![(constant, 0)];
        let mut visited = std::collections::BTreeSet::new();
        while let Some((value, depth)) = pending.pop() {
            if !self.charge(span) || depth >= self.limits.max_specialization_depth {
                return false;
            }
            if !visited.insert(std::ptr::from_ref(value)) {
                continue;
            }
            match value {
                Constant::Variant {
                    payload,
                    ..
                } => {
                    for value in payload.iter() {
                        let Some(value) = value else {
                            return false;
                        };
                        pending.push((value, depth + 1));
                    }
                }
                Constant::List(values) => {
                    pending.extend(values.iter().map(|value| (value, depth + 1)));
                }
                Constant::Struct(fields) => {
                    pending.extend(fields.values().map(|value| (value, depth + 1)));
                }
                Constant::Integer(_) | Constant::String(_) | Constant::Boolean(_) => {}
            }
        }
        true
    }

    pub(super) fn static_pattern_matches(
        &mut self,
        pattern: &Pattern,
        value: &Constant,
        span: Span,
    ) -> bool {
        match pattern {
            Pattern::Wildcard(_) => true,
            Pattern::Path(path)
            | Pattern::Variant {
                path,
                ..
            } => {
                let pattern = self
                    .patterns
                    .iter()
                    .rev()
                    .find(|pattern| pattern.span == path.span);
                match (pattern, value) {
                    (Some(pattern), Constant::Boolean(value)) => {
                        self.program
                            .item(pattern.enumeration)
                            .is_some_and(|item| {
                                item.domain() == crate::source::SourceDomainId::standard_library()
                                    && item.path().segments() == ["std", "Bool"]
                            })
                            && pattern.index == u32::from(*value)
                    }
                    (
                        Some(pattern),
                        Constant::Variant {
                            enumeration,
                            index,
                            ..
                        },
                    ) => pattern.enumeration == *enumeration && pattern.index == *index,
                    _ => false,
                }
            }
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
            if parameter.constant
                && constant
                    .as_ref()
                    .is_none_or(|constant| !self.complete_constant(constant, argument.span))
            {
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
        let name = self
            .program
            .item(item)
            .expect("function")
            .path()
            .segments()
            .join("::");
        let arguments = constants
            .iter()
            .map(|value| {
                value.as_ref().map_or_else(
                    || "?".into(),
                    |value| constant_description(value, self),
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        self.static_descriptions
            .push(format!("{name}({arguments})"));
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
        self.static_descriptions.pop();
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

/// Diagnostics must not expand shared constant graphs without a bound.
pub(super) fn constant_description(value: &Constant, checker: &Checker<'_>) -> String {
    fn render(value: &Constant, checker: &Checker<'_>, left: &mut usize, depth: usize) -> String {
        if *left == 0 || depth >= 8 {
            return "…".into();
        }
        *left -= 1;
        match value {
            Constant::Integer(value) => value.to_string(),
            Constant::Boolean(value) => value.to_string(),
            Constant::Variant {
                enumeration,
                index,
                payload,
            } => {
                let name = checker
                    .program
                    .item(*enumeration)
                    .expect("constant enum")
                    .path()
                    .segments()
                    .join("::");
                let variant = &checker.enums[enumeration].variants[*index as usize]
                    .name
                    .text;
                let name = format!("{name}::{variant}");
                if payload.is_empty() {
                    name
                } else {
                    format!(
                        "{name}({})",
                        payload
                            .iter()
                            .take(16)
                            .map(|value| value.as_ref().map_or_else(
                                || "?".into(),
                                |value| render(value, checker, left, depth + 1)
                            ))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            }
            Constant::String(value) => {
                let mut text: String = value.chars().take(160).collect();
                if text.len() < value.len() {
                    text.push('…');
                }
                format!("{text:?}")
            }
            Constant::List(values) => format!(
                "[{}]",
                values
                    .iter()
                    .take(16)
                    .map(|value| render(value, checker, left, depth + 1))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Constant::Struct(fields) => format!(
                "{{{}}}",
                fields
                    .iter()
                    .take(16)
                    .map(|(key, value)| format!(
                        "{key} = {}",
                        render(value, checker, left, depth + 1)
                    ))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        }
    }
    render(value, checker, &mut 64, 0)
}

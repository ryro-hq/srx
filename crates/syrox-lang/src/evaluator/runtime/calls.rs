//! Function calls and their local bindings.
//!
//! Leaving a call must restore the previous frame even after evaluation, depth
//! or expansion errors.

use super::{
    BTreeMap, Block, CanonicalType, Elaboration, Eval, Evaluator, Expression, Halt, ItemId,
    LocalId, PrimitiveValue, ResolvedTarget, Span, StatementKind, Ty, Value, size_of,
};

impl Evaluator<'_> {
    pub(super) fn call(
        &mut self,
        callee_span: Span,
        arguments: &[Expression],
        substitutions: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) -> Eval<Value> {
        if let Some(Elaboration::PackageSelection {
            factory,
        }) = self
            .checked
            .expression(span)
            .and_then(|metadata| metadata.elaboration())
        {
            return self.invoke_item(*factory, Vec::new(), &BTreeMap::new(), span);
        }
        let item = match self.index.target(callee_span).cloned() {
            Some(ResolvedTarget::EnumVariant {
                index,
                ..
            }) => {
                let payload = self.evaluate_arguments(arguments, substitutions, span)?;
                let ty = self.checked.expression(span).ok_or(Halt)?.ty();
                let ty = self.canonical_ty(ty, substitutions, span)?;
                return self.construct_variant(ty, index, payload, span);
            }
            Some(ResolvedTarget::Item(item)) if self.index.output_values.contains_key(&item) => {
                let callable = self.output_value(item, callee_span)?;
                return self.call_value(
                    callable,
                    callee_span,
                    arguments,
                    substitutions,
                    span,
                );
            }
            Some(ResolvedTarget::Item(item)) => item,
            Some(ResolvedTarget::Local(local)) => {
                let callable = self.local_value(local, callee_span)?;
                return self.call_value(
                    callable,
                    callee_span,
                    arguments,
                    substitutions,
                    span,
                );
            }
            _ => return self.fail(callee_span, "checked call has no item target"),
        };
        let supplied = match self
            .checked
            .expression(span)
            .and_then(|metadata| metadata.elaboration())
        {
            Some(Elaboration::FunctionSpecialization {
                substitutions: supplied,
            }) => self.substitute_bindings(supplied, substitutions, span)?,
            _ => BTreeMap::new(),
        };
        let values = self.evaluate_arguments(arguments, substitutions, span)?;
        self.invoke_item(item, values, &supplied, callee_span)
    }

    pub(super) fn call_value(
        &mut self,
        callable: Value,
        callee_span: Span,
        arguments: &[Expression],
        substitutions: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) -> Eval<Value> {
        let values = self.evaluate_arguments(arguments, substitutions, span)?;
        self.invoke_value(callable, values, callee_span)
    }

    fn evaluate_arguments(
        &mut self,
        arguments: &[Expression],
        substitutions: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) -> Eval<Vec<Value>> {
        self.expand(
            arguments.len().saturating_mul(size_of::<Value>()),
            span,
        )?;
        arguments
            .iter()
            .map(|argument| self.expression(argument, substitutions))
            .collect()
    }

    pub(super) fn invoke_value(
        &mut self,
        callable: Value,
        values: Vec<Value>,
        span: Span,
    ) -> Eval<Value> {
        match callable {
            Value::MemoizedFunction {
                id,
                ..
            } => {
                if !values.is_empty() {
                    return self.fail(span, "memoized function received arguments");
                }
                self.force_memo(&id, span)
            }
            Value::VariantConstructor {
                ty,
                index,
            } => {
                let CanonicalType::Function {
                    parameters,
                    result,
                    ..
                } = ty.as_ref()
                else {
                    return self.fail(span, "variant constructor has no function type");
                };
                if values.len() != parameters.len() {
                    return self.fail(span, "variant constructor arity mismatch");
                }
                self.construct_variant(result.clone(), index, values, span)
            }
            Value::Function {
                item,
                substitutions: supplied,
                ..
            } => self.invoke_item(item, values, &supplied, span),
            Value::Closure {
                body,
                owner,
                parameters,
                captures,
                substitutions: supplied,
                ..
            } => {
                if values.len() != parameters.len() {
                    return self.fail(span, "closure call has invalid checked arity");
                }
                self.expand(
                    captures
                        .len()
                        .saturating_add(values.len())
                        .saturating_mul(size_of::<(LocalId, Option<Value>)>()),
                    span,
                )?;
                self.with_local_bindings(0, |evaluator, bound| {
                    for (local, value) in captures
                        .into_iter()
                        .chain(parameters.into_iter().zip(values))
                    {
                        bound.push((local, evaluator.locals.insert(local, value)));
                    }
                    evaluator.enter_call(span)?;
                    let previous_context = std::mem::replace(&mut evaluator.project_context, owner);
                    let result = evaluator.block(&body, &supplied);
                    evaluator.call_depth -= 1;
                    evaluator.project_context = previous_context;
                    result
                })
            }
            _ => self.fail(span, "checked callee is not a function value"),
        }
    }

    pub(super) fn invoke_item(
        &mut self,
        item: ItemId,
        values: Vec<Value>,
        supplied: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) -> Eval<Value> {
        self.enter_call(span)?;
        let result = self.invoke_item_inner(item, values, supplied, span);
        self.call_depth -= 1;
        result
    }

    fn invoke_item_inner(
        &mut self,
        item: ItemId,
        mut values: Vec<Value>,
        supplied: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) -> Eval<Value> {
        if self.index.primitives.contains_key(&item) {
            if values.len() != 1 {
                return self.fail(
                    span,
                    "primitive constructor has invalid checked arity",
                );
            }
            let primitive = match values.pop().expect("one value") {
                Value::Int(value) => PrimitiveValue::Int(value),
                Value::Str(value) => PrimitiveValue::Str(value),
                _ => {
                    return self.fail(
                        span,
                        "primitive constructor received a non-primitive value",
                    );
                }
            };
            return self.construct_primitive(item, primitive, span, true);
        }
        let Some(function) = self.index.functions.get(&item).copied() else {
            return self.fail(span, "checked function target is unavailable");
        };
        if values.len() != function.parameters.len() {
            return self.fail(span, "function call has invalid checked arity");
        }
        self.expand(
            values.len().saturating_mul(
                size_of::<(LocalId, Option<Value>)>().saturating_add(size_of::<(LocalId, Value)>()),
            ),
            span,
        )?;
        self.with_local_bindings(values.len(), |evaluator, bound| {
            for (parameter, value) in function.parameters.iter().zip(values) {
                let Some(local) = evaluator.index.local(parameter.name.span) else {
                    return evaluator.fail(
                        parameter.name.span,
                        "missing checked function parameter identity",
                    );
                };
                bound.push((local, evaluator.locals.insert(local, value)));
            }
            let previous_context = evaluator.enter_project_context(function.body.span);
            let result = evaluator.block(&function.body, supplied).and_then(|value| {
                if let Some(identity) = &function.package {
                    let Value::Struct { fields, .. } = &value else {
                        return evaluator.fail(span, "package factory did not return a package reference");
                    };
                    for (name, literal) in ["version", "variant", "system"].into_iter().zip(&identity[1..]) {
                        let expected = evaluator.string(literal, supplied)?;
                        if !fields.iter().any(|(field, value)| field == name && matches!(value, Value::Nominal { value: PrimitiveValue::Str(actual), .. } if *actual == expected)) {
                            return evaluator.fail(span, "package reference identity differs from its declared selection");
                        }
                    }
                }
                Ok(value)
            });
            evaluator.project_context = previous_context;
            result
        })
    }

    pub(super) fn block(
        &mut self,
        block: &Block,
        substitutions: &BTreeMap<LocalId, Ty>,
    ) -> Eval<Value> {
        self.with_local_bindings(0, |evaluator, declared| {
            for statement in &block.statements {
                evaluator.tick(statement.span)?;
                match &statement.kind {
                    StatementKind::Recovery {
                        ..
                    } => {
                        return evaluator.fail(
                            statement.span,
                            "recovered statement cannot be evaluated",
                        );
                    }
                    StatementKind::Let {
                        name,
                        value,
                        ..
                    } => {
                        let value = evaluator.expression(value, substitutions)?;
                        let Some(local) = evaluator.index.local(name.span) else {
                            return evaluator.fail(name.span, "missing checked let identity");
                        };
                        evaluator.expand(
                            size_of::<(LocalId, Option<Value>)>().saturating_add(size_of::<(
                                LocalId,
                                Value,
                            )>(
                            )),
                            name.span,
                        )?;
                        declared.push((local, evaluator.locals.insert(local, value)));
                    }
                    StatementKind::Expression(expression) => {
                        let _ = evaluator.expression(expression, substitutions)?;
                    }
                }
            }
            block
                .tail
                .as_ref()
                .map_or(Ok(Value::Unit), |tail| {
                    evaluator.expression(tail, substitutions)
                })
        })
    }

    // Restore in reverse binding order on every fallible exit. Nested calls and
    // pattern arms can temporarily reuse the same resolved local identity.
    pub(super) fn with_local_bindings<T>(
        &mut self,
        capacity: usize,
        evaluate: impl FnOnce(&mut Self, &mut Vec<(LocalId, Option<Value>)>) -> Eval<T>,
    ) -> Eval<T> {
        let mut bound = Vec::with_capacity(capacity);
        let result = evaluate(self, &mut bound);
        for (local, previous) in bound.into_iter().rev() {
            if let Some(previous) = previous {
                self.locals.insert(local, previous);
            } else {
                self.locals.remove(&local);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        checker::{CanonicalItemIdentity, CheckPolicy, ScopeRule, check},
        evaluator::{EvaluationEnvironment, EvaluationLimits, index::SetupBudget},
        resolver::resolve,
        source::{SourceDomainId, SourceSet},
        syntax::parse_sources,
    };

    fn with_evaluator(
        text: &str,
        policy: &CheckPolicy,
        verify: impl FnOnce(&mut Evaluator<'_>, &Expression),
    ) {
        let mut sources = SourceSet::new();
        sources.add("main.srx", text).unwrap();
        let checked = check(
            resolve(parse_sources(&sources).unwrap()).unwrap(),
            policy,
        )
        .unwrap();
        let limits = EvaluationLimits::default();
        let index =
            super::super::ProgramIndex::new(&checked, policy, &mut SetupBudget::new(limits))
                .unwrap();
        let expression = index.output_values.values().next().unwrap();
        let environment = EvaluationEnvironment::new(policy);
        let root = std::sync::Arc::new(
            CanonicalItemIdentity::new(SourceDomainId::project(), ["test"]).unwrap(),
        );
        let mut evaluator = Evaluator::new(
            &checked,
            policy,
            &environment,
            &index,
            limits,
            expression.span,
            root,
        );
        verify(&mut evaluator, expression);
    }

    #[test]
    fn closure_depth_failure_restores_shadowed_parameter_and_keeps_budget_charge() {
        with_evaluator(
            "value I(int); outputs { f: fn(I) -> I = fn(n: I) -> I { n }; }",
            &CheckPolicy::default(),
            |evaluator, expression| {
                let callable = evaluator
                    .expression(expression, &BTreeMap::new())
                    .unwrap_or_else(|_| panic!("closure construction failed"));
                let Value::Closure {
                    parameters,
                    ..
                } = &callable
                else {
                    panic!("expected closure");
                };
                let local = parameters[0];
                evaluator.locals.insert(local, Value::Int(99));
                evaluator.call_depth = super::super::MAX_CALL_DEPTH;
                let expansion = evaluator.expansion;
                assert!(
                    evaluator
                        .invoke_value(callable, vec![Value::Int(1)], expression.span)
                        .is_err()
                );
                assert!(matches!(
                    evaluator.locals.get(&local),
                    Some(Value::Int(99))
                ));
                assert_eq!(evaluator.call_depth, super::super::MAX_CALL_DEPTH);
                assert_eq!(
                    evaluator.expansion - expansion,
                    size_of::<(LocalId, Option<Value>)>()
                );
                assert!(
                    evaluator.diagnostics[0]
                        .message
                        .contains("call depth limit")
                );
            },
        );
    }

    #[test]
    fn body_work_failure_restores_parameters_and_removes_let_binding() {
        with_evaluator(
            "value I(int); fn f(n: I, m: I) -> I { let k = n; I(1) } outputs { out: I = f(I(4), I(5)); }",
            &CheckPolicy::default(),
            |evaluator, expression| {
                let (&item, function) = evaluator.index.functions.iter().next().unwrap();
                let local = |span| evaluator.index.local(span).unwrap();
                let n = local(function.parameters[0].name.span);
                let m = local(function.parameters[1].name.span);
                let StatementKind::Let {
                    name,
                    ..
                } = &function.body.statements[0].kind
                else {
                    panic!("expected let binding");
                };
                let k = local(name.span);
                evaluator.locals.insert(n, Value::Int(99));
                evaluator.locals.insert(m, Value::Int(88));
                // Spend one step on the let statement and one on its value;
                // fail on the body tail after the new local has been installed.
                evaluator.limits.max_total_steps = evaluator.steps + 2;
                let steps = evaluator.steps;
                let result = evaluator.invoke_item(
                    item,
                    vec![Value::Int(4), Value::Int(5)],
                    &BTreeMap::new(),
                    expression.span,
                );
                assert!(result.is_err());
                assert!(matches!(
                    evaluator.locals.get(&n),
                    Some(Value::Int(99))
                ));
                assert!(matches!(
                    evaluator.locals.get(&m),
                    Some(Value::Int(88))
                ));
                assert!(!evaluator.locals.contains_key(&k));
                assert_eq!(evaluator.call_depth, 0);
                assert_eq!(evaluator.steps, steps + 3);
                assert_eq!(
                    evaluator.operation_error,
                    Some(crate::evaluator::EvaluationSetupError::EvaluationWorkLimit)
                );
            },
        );
    }

    #[test]
    fn struct_expansion_failure_closes_private_scope_and_keeps_budget_charge() {
        let policy = CheckPolicy::new("private")
            .unwrap()
            .with_scope_rule("net", ScopeRule::Private)
            .unwrap();
        with_evaluator(
            "value I(int); struct Box in [net] { n: I; } outputs { b: Box = Box { n = I(1); }; }",
            &policy,
            |evaluator, expression| {
                let scope_count = evaluator.scopes.len();
                let expansion = evaluator.expansion;
                // Allow the expression frame; fail at allocation of the fields,
                // after the structure has opened its private ownership scope.
                evaluator.limits.max_expansion_bytes = expansion + size_of::<Value>();
                assert!(
                    evaluator
                        .expression(expression, &BTreeMap::new())
                        .is_err()
                );
                assert_eq!(evaluator.scopes.len(), scope_count);
                assert_eq!(
                    evaluator.expansion - expansion,
                    size_of::<Value>() + size_of::<(String, Value)>()
                );
                assert_eq!(evaluator.depth, 0);
                assert!(
                    evaluator.diagnostics[0]
                        .message
                        .contains("expansion byte limit")
                );
            },
        );
    }
}

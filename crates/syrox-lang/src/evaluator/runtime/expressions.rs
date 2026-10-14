use super::{
    Arc, BTreeMap, BTreeSet, CanonicalType, Elaboration, Eval, Evaluator, Expression,
    ExpressionKind, Halt, LocalId, MatchArm, Pattern, PrimitiveValue, ResolvedTarget, Ty, Value,
    size_of,
};

impl Evaluator<'_> {
    pub(in crate::evaluator) fn expression(
        &mut self,
        expression: &Expression,
        substitutions: &BTreeMap<LocalId, Ty>,
    ) -> Eval<Value> {
        self.tick(expression.span)?;
        if self.depth >= self.limits.max_depth {
            return self.fail(
                expression.span,
                "evaluation/value depth limit reached",
            );
        }
        self.expand(size_of::<Value>(), expression.span)?;
        self.depth += 1;
        let result = self.expression_inner(expression, substitutions);
        self.depth -= 1;
        result
    }

    // Exhaustive dispatch keeps shared evaluation state and failure handling visible.
    pub(super) fn expression_inner(
        &mut self,
        expression: &Expression,
        substitutions: &BTreeMap<LocalId, Ty>,
    ) -> Eval<Value> {
        let metadata = self
            .checked
            .expression(expression.span)
            .ok_or_else(|| {
                self.error(
                    expression.span,
                    "missing checked expression metadata",
                );
                Halt
            })?;
        match &expression.kind {
            ExpressionKind::Let(block) => self.block(block, substitutions),
            ExpressionKind::Integer(integer) => {
                let value = PrimitiveValue::Int(integer.value);
                if let Some(Elaboration::ValueLiteral(item)) = metadata.elaboration() {
                    self.construct_primitive(*item, value, expression.span, false)
                } else {
                    Ok(Value::Int(integer.value))
                }
            }
            ExpressionKind::String(string) => {
                let text = self.string(string, substitutions)?;
                if let Some(Elaboration::ValueLiteral(item)) = metadata.elaboration() {
                    self.construct_primitive(
                        *item,
                        PrimitiveValue::Str(text),
                        expression.span,
                        false,
                    )
                } else {
                    Ok(Value::Str(text))
                }
            }
            ExpressionKind::Path(path) => match metadata.elaboration() {
                Some(Elaboration::ContextualVariant {
                    index,
                    ..
                }) => Ok(Value::Variant {
                    ty: self.canonical_ty(metadata.ty(), substitutions, path.span)?,
                    index: *index,
                    payload: Vec::new(),
                }),
                _ => match self.index.target(path.span) {
                    Some(ResolvedTarget::Local(local)) => self.local_value(*local, path.span),
                    Some(ResolvedTarget::Item(item))
                        if self
                            .checked
                            .resolved()
                            .published_member(*item)
                            .is_some() =>
                    {
                        self.published_value(*item, path.span)
                    }
                    Some(ResolvedTarget::Item(item)) if self.index.functions.contains_key(item) => {
                        let supplied = match metadata.elaboration() {
                            Some(Elaboration::FunctionSpecialization {
                                substitutions: supplied,
                            }) => self.substitute_bindings(supplied, substitutions, path.span)?,
                            _ => BTreeMap::new(),
                        };
                        Ok(Value::Function {
                            item: *item,
                            substitutions: supplied,
                            ty: self.canonical_ty(metadata.ty(), substitutions, path.span)?,
                        })
                    }
                    Some(ResolvedTarget::Item(item))
                        if self.index.output_values.contains_key(item) =>
                    {
                        self.output_value(*item, path.span)
                    }
                    Some(ResolvedTarget::EnumVariant {
                        index,
                        ..
                    }) => Ok(Value::Variant {
                        ty: self.canonical_ty(metadata.ty(), substitutions, path.span)?,
                        index: *index,
                        payload: Vec::new(),
                    }),
                    _ => self.fail(
                        path.span,
                        "checked value path has no evaluable target",
                    ),
                },
            },
            ExpressionKind::Call {
                callee,
                arguments,
            } => self.call(
                callee.span,
                arguments,
                substitutions,
                expression.span,
            ),
            ExpressionKind::Specialize {
                function,
                ..
            } => {
                if let Some(Elaboration::VariantConstructor {
                    index,
                }) = metadata.elaboration()
                {
                    return Ok(Value::VariantConstructor {
                        ty: self.canonical_ty(metadata.ty(), substitutions, expression.span)?,
                        index: *index,
                    });
                }
                let Some(ResolvedTarget::Item(item)) = self.index.target(function.span).cloned()
                else {
                    return self.fail(expression.span, "missing generic function target");
                };
                let Some(Elaboration::FunctionSpecialization {
                    substitutions: supplied,
                }) = metadata.elaboration()
                else {
                    return self.fail(
                        expression.span,
                        "missing function specialization metadata",
                    );
                };
                let specialized =
                    self.substitute_bindings(supplied, substitutions, expression.span)?;
                Ok(Value::Function {
                    item,
                    ty: self.canonical_ty(metadata.ty(), substitutions, expression.span)?,
                    substitutions: specialized,
                })
            }
            ExpressionKind::Apply {
                callee,
                arguments,
            } => {
                let callable = self.expression(callee, substitutions)?;
                self.call_value(
                    callable,
                    callee.span,
                    arguments,
                    substitutions,
                    expression.span,
                )
            }
            ExpressionKind::ModuleExports {
                mapper,
                ..
            } => self.module_exports(mapper, substitutions, expression.span),
            ExpressionKind::Memoize(value) => {
                let callable = self.expression(value, substitutions)?;
                self.memoize(callable, expression.span)
            }
            ExpressionKind::SortByKeys {
                items,
                keys,
            } => {
                let items = self.expression(items, substitutions)?;
                let keys = self.expression(keys, substitutions)?;
                self.sort_by_keys(items, keys, expression.span)
            }
            ExpressionKind::Compare {
                left,
                right,
                branches,
            } => {
                let left = self.expression(left, substitutions)?;
                let right = self.expression(right, substitutions)?;
                let index = self.compare_values(left, right, expression.span)?;
                self.expression(&branches[index], substitutions)
            }
            ExpressionKind::Fold {
                items,
                initial,
                step,
            } => {
                let Value::List {
                    items,
                    ..
                } = self.expression(items, substitutions)?
                else {
                    return self.fail(
                        expression.span,
                        "checked fold input is not a list",
                    );
                };
                let mut accumulator = self.expression(initial, substitutions)?;
                let callback = self.expression(step, substitutions)?;
                for item in items {
                    self.tick(expression.span)?;
                    self.expand(2 * size_of::<Value>(), expression.span)?;
                    let callable = Self::copy_value_ref(self, &callback, step.span, 0)?;
                    accumulator =
                        self.invoke_value(callable, vec![accumulator, item], expression.span)?;
                }
                Ok(accumulator)
            }
            ExpressionKind::Closure {
                parameters,
                body,
                once,
                ..
            } => {
                let referenced = self
                    .index
                    .locals_referenced_in(expression.span)
                    .count();
                self.charge_steps(referenced, expression.span)?;
                self.expand(
                    referenced.saturating_mul(size_of::<LocalId>()),
                    expression.span,
                )?;
                let referenced: BTreeSet<_> = self
                    .index
                    .locals_referenced_in(expression.span)
                    .collect();
                self.expand(
                    body.span.end().saturating_sub(body.span.start()) as usize * 32,
                    expression.span,
                )?;
                let mut captures = Vec::new();
                for local in referenced {
                    if self.locals.contains_key(&local) {
                        self.expand(size_of::<(LocalId, Value)>(), expression.span)?;
                        let value = if *once || self.index.single_use(local) {
                            self.local_value(local, expression.span)?
                        } else {
                            self.copy_value(local, expression.span)?
                        };
                        captures.push((local, value));
                    }
                }
                self.expand(
                    parameters
                        .len()
                        .saturating_mul(size_of::<LocalId>()),
                    expression.span,
                )?;
                let parameters = parameters
                    .iter()
                    .map(|parameter| self.index.local(parameter.name.span).ok_or(Halt))
                    .collect::<Eval<Vec<_>>>()?;
                Ok(Value::Closure {
                    once: *once,
                    owner: self
                        .checked
                        .resolved()
                        .parsed()
                        .owner(expression.span.source_id())
                        .unwrap_or(self.project_context),
                    substitutions: self.substitute_bindings(
                        substitutions,
                        &BTreeMap::new(),
                        expression.span,
                    )?,
                    ty: self.canonical_ty(metadata.ty(), substitutions, expression.span)?,
                    body: Arc::new(body.clone()),
                    parameters,
                    captures,
                })
            }
            ExpressionKind::Struct {
                fields,
                recovery,
                ..
            } => {
                if !recovery.is_empty() {
                    return self.fail(
                        expression.span,
                        "recovered struct cannot be evaluated",
                    );
                }
                let checked_ty =
                    self.substitute_ty(metadata.ty(), substitutions, expression.span)?;
                let item = Ty::nominal_head(&checked_ty).ok_or_else(|| {
                    self.error(
                        expression.span,
                        "checked struct expression has no nominal type",
                    );
                    Halt
                })?;
                self.structure(
                    item,
                    &checked_ty,
                    fields,
                    substitutions,
                    expression.span,
                )
            }
            ExpressionKind::List(items) => {
                self.expand(
                    items.len().saturating_mul(size_of::<Value>()),
                    expression.span,
                )?;
                let mut values = Vec::with_capacity(items.len());
                for item in items {
                    values.push(self.expression(item, substitutions)?);
                }
                Ok(Value::List {
                    ty: self.canonical_ty(metadata.ty(), substitutions, expression.span)?,
                    items: values,
                })
            }
            ExpressionKind::Erase {
                value,
                ..
            } => {
                let Some(Elaboration::Erasure {
                    source,
                }) = metadata.elaboration()
                else {
                    return self.fail(
                        expression.span,
                        "missing checked erasure metadata",
                    );
                };
                let source_ty = self.canonical_ty(source, substitutions, expression.span)?;
                let target_ty = self.canonical_ty(metadata.ty(), substitutions, expression.span)?;
                let target_item = Ty::nominal_head(metadata.ty()).ok_or_else(|| {
                    self.error(
                        expression.span,
                        "checked erasure target is not nominal",
                    );
                    Halt
                })?;
                let inner = self.expression(value, substitutions)?;
                self.erase(
                    inner,
                    &source_ty,
                    target_ty,
                    target_item,
                    expression.span,
                )
            }
            ExpressionKind::Match {
                value,
                arms,
            } => {
                let scrutinee = self.expression(value, substitutions)?;
                let Value::Variant {
                    ty,
                    index,
                    payload,
                } = scrutinee
                else {
                    return self.fail(
                        value.span,
                        "checked match produced a non-variant value",
                    );
                };
                for arm in arms {
                    if self.pattern_matches(arm, &ty, index)? {
                        return self.match_payload(arm, payload, substitutions);
                    }
                }
                self.fail(expression.span, "checked match selected no arm")
            }
            ExpressionKind::Group(inner) => self.expression(inner, substitutions),
            ExpressionKind::Field {
                value,
                fields,
            } => {
                let mut current = self.expression(value, substitutions)?;
                for field in fields {
                    current = self.project(current, &field.text, field.span)?;
                }
                Ok(current)
            }
            ExpressionKind::Concat(parts) => {
                let mut result = Vec::new();
                for part in parts {
                    let Value::List {
                        items: mut values,
                        ..
                    } = self.expression(part, substitutions)?
                    else {
                        return self.fail(
                            part.span,
                            "checked concatenation produced a non-list",
                        );
                    };
                    if result.is_empty() {
                        result = values;
                    } else {
                        let needed = result.len().saturating_add(values.len());
                        if needed > result.capacity() {
                            let capacity = needed.max(result.capacity().saturating_mul(2));
                            self.expand(
                                capacity
                                    .saturating_sub(result.capacity())
                                    .saturating_mul(size_of::<Value>()),
                                part.span,
                            )?;
                            result.reserve_exact(capacity - result.len());
                        }
                        result.append(&mut values);
                    }
                }
                Ok(Value::List {
                    ty: self.canonical_ty(metadata.ty(), substitutions, expression.span)?,
                    items: result,
                })
            }
        }
    }

    fn match_payload(
        &mut self,
        arm: &MatchArm,
        payload: Vec<Value>,
        substitutions: &BTreeMap<LocalId, Ty>,
    ) -> Eval<Value> {
        self.with_local_bindings(0, |evaluator, bound| {
            if let Pattern::Variant {
                bindings,
                ..
            } = &arm.pattern
            {
                if bindings.len() != payload.len() {
                    return evaluator.fail(arm.span, "checked pattern payload arity mismatch");
                }
                evaluator.expand(
                    bindings
                        .len()
                        .saturating_mul(size_of::<(LocalId, Option<Value>)>()),
                    arm.span,
                )?;
                for (binding, value) in bindings.iter().zip(payload) {
                    if binding.text == "_" {
                        continue;
                    }
                    let local = evaluator.index.local(binding.span).ok_or(Halt)?;
                    bound.push((local, evaluator.locals.insert(local, value)));
                }
            }
            evaluator.expression(&arm.value, substitutions)
        })
    }

    fn pattern_matches(
        &mut self,
        arm: &MatchArm,
        ty: &Arc<CanonicalType>,
        index: u32,
    ) -> Eval<bool> {
        match &arm.pattern {
            Pattern::Wildcard(_) => Ok(true),
            Pattern::Path(path)
            | Pattern::Variant {
                path,
                ..
            } => {
                let checked = self.checked.pattern(path.span).ok_or_else(|| {
                    self.error(path.span, "missing checked pattern metadata");
                    Halt
                })?;
                let pattern_ty = self.canonical_ty(
                    &Ty::Nominal(checked.enumeration()),
                    &BTreeMap::new(),
                    path.span,
                )?;
                let same_enum = match (pattern_ty.as_ref(), ty.as_ref()) {
                    (
                        CanonicalType::Nominal(expected),
                        CanonicalType::Specialization {
                            template,
                            ..
                        },
                    ) => expected == template,
                    _ => &pattern_ty == ty,
                };
                Ok(same_enum && checked.index() == index)
            }
        }
    }
}

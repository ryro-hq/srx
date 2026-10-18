use super::*;

impl Evaluator<'_> {
    pub(super) fn structure(
        &mut self,
        item: ItemId,
        checked_ty: &Ty,
        fields: &[crate::syntax::StructField],
        substitutions: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) -> Eval<Value> {
        let Some(declaration) = self.index.structures.get(&item).copied() else {
            return self.fail(span, "checked struct declaration is unavailable");
        };
        let concrete = self.canonical_ty(checked_ty, substitutions, span)?;
        let type_substitutions =
            self.specialization_substitutions(item, checked_ty, substitutions, span)?;
        let mark = self.scopes.len();
        for scope in &declaration.scopes {
            match self.policy.scope_rule(&scope.text) {
                Some(ScopeRule::Private) => {
                    let Some(name) = self.index.scope_name(&scope.text) else {
                        self.scopes.truncate(mark);
                        return self.fail(scope.span, "policy scope identity is unavailable");
                    };
                    self.push_scope(Some(name), scope.span);
                }
                Some(ScopeRule::Inherited) => {}
                None => {
                    self.scopes.truncate(mark);
                    return self.fail(
                        scope.span,
                        "checked structure uses an unsupported scope",
                    );
                }
            }
        }
        let result = (|| {
            self.expand(
                declaration
                    .fields
                    .len()
                    .saturating_mul(size_of::<(String, Value)>()),
                span,
            )?;
            let mut supplied = BTreeMap::new();
            self.expand(
                fields
                    .len()
                    .saturating_mul(size_of::<(&str, Value)>()),
                span,
            )?;
            for field in fields {
                let value = self.expression(&field.value, substitutions)?;
                supplied.insert(field.name.text.as_str(), value);
            }
            let mut realized = Vec::with_capacity(declaration.fields.len());
            for field in &declaration.fields {
                self.expand(field.name.text.len(), field.span)?;
                let value = if let Some(value) = supplied.remove(field.name.text.as_str()) {
                    value
                } else if let Some(default) = &field.default {
                    self.expression(default, &type_substitutions)?
                } else {
                    return self.fail(
                        field.span,
                        "checked struct is missing a field value",
                    );
                };
                realized.push((field.name.text.clone(), value));
            }
            Ok(Value::Struct {
                ty: concrete,
                fields: realized,
                owner: Some(
                    self.checked
                        .resolved()
                        .parsed()
                        .owner(span.source_id())
                        .unwrap_or(self.project_context),
                ),
            })
        })();
        self.scopes.truncate(mark);
        result
    }

    pub(super) fn construct_primitive(
        &mut self,
        item: ItemId,
        value: PrimitiveValue,
        span: Span,
        allow_resource: bool,
    ) -> Eval<Value> {
        let Some(info) = self.index.primitives.get(&item) else {
            return self.fail(
                span,
                "checked primitive declaration is unavailable",
            );
        };
        if info.resource && !allow_resource {
            return self.fail(span, "resource literal lifting is not permitted");
        }
        self.refinements(info.declaration, &value, span)?;
        let ty = self.canonical_ty(&Ty::Nominal(item), &BTreeMap::new(), span)?;
        if let PrimitiveValue::Str(text) = &value {
            self.expand(text.len(), span)?;
        }
        if info.resource {
            let scope_index = if let Some(name) = &info.declaration.scope {
                self.scopes
                    .iter()
                    .rposition(|scope| scope.name.as_deref() == Some(&name.text))
            } else {
                self.scopes
                    .iter()
                    .position(|scope| scope.name.is_none())
            };
            let Some(scope_index) = scope_index else {
                return self.fail(span, "resource governing scope is not open");
            };
            let scope = &self.scopes[scope_index];
            let scope_name_len = scope.name.as_ref().map_or(0, |name| name.len());
            let boundary = scope.boundary;
            self.expand(
                size_of::<ResourceClaimKey>()
                    .saturating_add(size_of::<ResourceClaim>())
                    .saturating_add(scope_name_len),
                span,
            )?;
            let scope_name = self.scopes[scope_index].name.clone();
            let key = ResourceClaimKey {
                ty: ty.clone(),
                value: value.clone(),
                scope: GoverningScope {
                    root: self.root.clone(),
                    name: scope_name.map(|name| name.to_string()),
                    boundary,
                },
            };
            if let Some(previous_span) = self.claims.get(&key).copied() {
                self.error(
                    span,
                    "resource claim conflicts with an earlier claim in this root",
                );
                if let Some(diagnostic) = self.diagnostics.last_mut() {
                    diagnostic.note = Some(format!(
                        "first claimed at byte {}",
                        previous_span.start()
                    ));
                }
                return Err(Halt);
            }
            self.claims.insert(key, span);
            self.claim_effects = self.claim_effects.saturating_add(1);
        }
        Ok(Value::Nominal {
            ty,
            value,
            resource: info.resource,
        })
    }

    pub(super) fn refinements(
        &mut self,
        declaration: &PrimitiveDeclaration,
        value: &PrimitiveValue,
        span: Span,
    ) -> Eval<()> {
        for refinement in &declaration.refinements {
            self.tick(refinement.span)?;
            let accepted = match &refinement.kind {
                RefinementKind::Range {
                    start,
                    end,
                    inclusive,
                } => match value {
                    PrimitiveValue::Int(value) => {
                        *value >= start.value
                            && if *inclusive {
                                *value <= end.value
                            } else {
                                *value < end.value
                            }
                    }
                    PrimitiveValue::Str(_) => false,
                },
                RefinementKind::Set(values) => {
                    let mut found = false;
                    for candidate in values {
                        self.tick(span)?;
                        if let (Literal::String(literal), PrimitiveValue::Str(_)) =
                            (candidate, value)
                        {
                            // Charge the maximum byte comparisons before walking
                            // the literal; an early mismatch remains conservative.
                            self.charge_steps(literal.source.len().div_ceil(64), span)?;
                        }
                        if literal_equals(candidate, value) {
                            found = true;
                            break;
                        }
                    }
                    found
                }
                RefinementKind::Predicate(path) => {
                    let Some(name) = self
                        .index
                        .predicate_names
                        .get(&span_key(path.span))
                    else {
                        return self.fail(
                            path.span,
                            "predicate name metadata is unavailable",
                        );
                    };
                    let accepted = match (
                        self.environment.predicates.get(name.as_ref()),
                        value,
                    ) {
                        (Some(PredicateCallback::Int(callback)), PrimitiveValue::Int(value)) => {
                            catch_unwind(AssertUnwindSafe(|| callback(*value)))
                        }
                        (Some(PredicateCallback::Str(callback)), PrimitiveValue::Str(value)) => {
                            catch_unwind(AssertUnwindSafe(|| callback(value)))
                        }
                        _ => {
                            return self.fail(
                                path.span,
                                "predicate callback does not match checked metadata",
                            );
                        }
                    };
                    match accepted {
                        Ok(accepted) => accepted,
                        Err(_) => {
                            return self.fail(path.span, "predicate callback panicked");
                        }
                    }
                }
            };
            if !accepted {
                return self.fail(
                    span,
                    format!(
                        "value does not satisfy refinement on `{}`",
                        declaration.name.text
                    ),
                );
            }
        }
        Ok(())
    }

    pub(super) fn string(
        &mut self,
        literal: &StringLiteral,
        substitutions: &BTreeMap<LocalId, Ty>,
    ) -> Eval<String> {
        self.expand(literal.source.len(), literal.span)?;
        let mut result = String::with_capacity(literal.source.len());
        for part in &literal.parts {
            match part {
                StringPart::Text {
                    source,
                    span,
                } => {
                    decode_text_into(source, &mut result).ok_or_else(|| {
                        self.error(*span, "checked string contains an invalid escape");
                        Halt
                    })?;
                }
                StringPart::Interpolation {
                    path,
                    span,
                } => {
                    let mut value = match self.index.target(path.span).cloned() {
                        Some(ResolvedTarget::Local(local)) => self.local_value(local, *span)?,
                        Some(ResolvedTarget::Item(item))
                            if self.index.output_values.contains_key(&item) =>
                        {
                            self.output_value(item, *span)?
                        }
                        _ => return self.fail(*span, "checked interpolation has no value target"),
                    };
                    for field in path.segments.iter().skip(1) {
                        value = self.project(value, &field.text, field.span)?;
                    }
                    match value {
                        Value::Int(value)
                        | Value::Nominal {
                            value: PrimitiveValue::Int(value),
                            ..
                        } => {
                            let length = decimal_len(value);
                            self.expand(length, *span)?;
                            result.reserve(length);
                            if write!(result, "{value}").is_err() {
                                return self.fail(*span, "integer interpolation formatting failed");
                            }
                        }
                        Value::Str(value)
                        | Value::Nominal {
                            value: PrimitiveValue::Str(value),
                            ..
                        } => {
                            self.expand(value.len(), *span)?;
                            result.reserve(value.len());
                            result.push_str(&value);
                        }
                        _ => {
                            return self.fail(
                                *span,
                                "checked interpolation produced a non-primitive value",
                            );
                        }
                    }
                }
            }
        }
        let _ = substitutions;
        Ok(result)
    }

    pub(super) fn project(&mut self, value: Value, field: &str, span: Span) -> Eval<Value> {
        let Value::Struct {
            fields,
            ..
        } = value
        else {
            return self.fail(
                span,
                "checked field projection produced a non-struct value",
            );
        };
        fields
            .into_iter()
            .find(|(name, _)| name == field)
            .map(|(_, value)| value)
            .ok_or_else(|| {
                self.error(
                    span,
                    "checked field projection could not find its field",
                );
                Halt
            })
    }

    pub(super) fn erase(
        &mut self,
        value: Value,
        source_ty: &Arc<CanonicalType>,
        target_ty: Arc<CanonicalType>,
        target_item: ItemId,
        span: Span,
    ) -> Eval<Value> {
        let Value::Struct {
            ty,
            fields,
            owner,
        } = value
        else {
            return self.fail(
                span,
                "checked erasure produced a non-struct source",
            );
        };
        if &ty != source_ty {
            return self.fail(span, "checked erasure source identity mismatch");
        }
        let Some(target) = self.index.structures.get(&target_item).copied() else {
            return self.fail(
                span,
                "checked erasure target declaration is unavailable",
            );
        };
        self.expand(
            target
                .fields
                .len()
                .saturating_mul(size_of::<(String, Value)>()),
            span,
        )?;
        let mut source: BTreeMap<_, _> = fields.into_iter().collect();
        let mut projected = Vec::with_capacity(target.fields.len());
        for field in &target.fields {
            let Some(value) = source.remove(&field.name.text) else {
                return self.fail(
                    field.span,
                    "checked erasure source is missing a projected field",
                );
            };
            projected.push((field.name.text.clone(), value));
        }
        Ok(Value::Struct {
            ty: target_ty,
            fields: projected,
            owner,
        })
    }

    pub(super) fn module_exports(
        &mut self,
        mapper: &Expression,
        substitutions: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) -> Eval<Value> {
        let metadata = self.expression_metadata(span).ok_or(Halt)?;
        let Some(Elaboration::ModuleExports {
            key,
            function,
        }) = metadata.elaboration()
        else {
            return self.fail(span, "missing checked module collection metadata");
        };
        let entries = self
            .checked
            .resolved()
            .module_exports(span)
            .ok_or(Halt)?;
        self.expand(
            entries.len().saturating_mul(size_of::<Value>()),
            span,
        )?;
        let callback = self.expression(mapper, substitutions)?;
        let function = self.canonical_ty(function, substitutions, span)?;
        let mut items = Vec::with_capacity(entries.len());
        for entry in entries {
            self.tick(span)?;
            self.expand(
                entry
                    .key()
                    .len()
                    .saturating_add(2 * size_of::<Value>()),
                span,
            )?;
            let key = self.construct_primitive(
                *key,
                PrimitiveValue::Str(entry.key().to_owned()),
                span,
                true,
            )?;
            let factory = Value::Function {
                item: entry.item(),
                ty: function.clone(),
                substitutions: BTreeMap::new(),
            };
            let callable = Self::copy_value_ref(self, &callback, mapper.span, 0)?;
            items.push(self.invoke_value(callable, vec![key, factory], span)?);
        }
        Ok(Value::List {
            ty: self.canonical_ty(metadata.ty(), substitutions, span)?,
            items,
        })
    }
}

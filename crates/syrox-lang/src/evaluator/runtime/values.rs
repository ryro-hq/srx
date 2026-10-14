use super::{
    Arc, BTreeMap, CanonicalType, Eval, Evaluator, Halt, LocalId, PrimitiveValue, Span, Value,
    primitive_value, size_of,
};

impl Evaluator<'_> {
    pub(super) fn local_value(&mut self, local: LocalId, span: Span) -> Eval<Value> {
        let Some(value) = self.locals.get(&local) else {
            return self.fail(span, "checked local has no runtime value");
        };
        if self.index.single_use(local) || value.affine() {
            return self.locals.remove(&local).ok_or(Halt);
        }
        self.copy_value(local, span)
    }

    // Exhaustive comparison keeps affine checks and value ordering consistent.
    pub(super) fn copy_value_ref(
        ev: &mut Evaluator<'_>,
        value: &Value,
        span: Span,
        depth: usize,
    ) -> Eval<Value> {
        if depth >= ev.limits.max_depth {
            return ev.fail(span, "value copy depth limit reached");
        }
        ev.expand(size_of::<Value>(), span)?;
        match value {
            Value::MemoizedFunction {
                ty,
                id,
            } => Ok(Value::MemoizedFunction {
                ty: ty.clone(),
                id: id.clone(),
            }),
            Value::VariantConstructor {
                ty,
                index,
            } => Ok(Value::VariantConstructor {
                ty: ty.clone(),
                index: *index,
            }),
            Value::Function {
                item,
                ty,
                substitutions,
            } => Ok(Value::Function {
                item: *item,
                ty: ty.clone(),
                substitutions: ev.substitute_bindings(substitutions, &BTreeMap::new(), span)?,
            }),
            Value::Closure {
                ty,
                once,
                owner,
                body,
                parameters,
                captures,
                substitutions,
            } => {
                if *once {
                    return ev.fail(span, "cannot copy a consumable closure");
                }
                let parameter_bytes = parameters
                    .len()
                    .saturating_mul(size_of::<LocalId>());
                let capture_bytes = captures
                    .len()
                    .saturating_mul(size_of::<(LocalId, Value)>());
                ev.expand(
                    parameter_bytes.saturating_add(capture_bytes),
                    span,
                )?;
                let mut copied = Vec::with_capacity(captures.len());
                for (local, value) in captures {
                    copied.push((
                        *local,
                        Self::copy_value_ref(ev, value, span, depth + 1)?,
                    ));
                }
                Ok(Value::Closure {
                    once: false,
                    owner: *owner,
                    substitutions: ev.substitute_bindings(substitutions, &BTreeMap::new(), span)?,
                    ty: ty.clone(),
                    body: body.clone(),
                    parameters: parameters.clone(),
                    captures: copied,
                })
            }
            Value::Unit => Ok(Value::Unit),
            Value::Int(value) => Ok(Value::Int(*value)),
            Value::Str(value) => {
                ev.expand(value.len(), span)?;
                Ok(Value::Str(value.clone()))
            }
            Value::Nominal {
                ty,
                value,
                resource,
            } => {
                if *resource {
                    return ev.fail(span, "cannot copy an affine resource value");
                }
                if let PrimitiveValue::Str(text) = value {
                    ev.expand(text.len(), span)?;
                }
                Ok(Value::Nominal {
                    ty: ty.clone(),
                    value: value.clone(),
                    resource: false,
                })
            }
            Value::List {
                ty,
                items,
            } => {
                ev.expand(
                    items.len().saturating_mul(size_of::<Value>()),
                    span,
                )?;
                let mut copied = Vec::with_capacity(items.len());
                for item in items {
                    copied.push(Self::copy_value_ref(ev, item, span, depth + 1)?);
                }
                Ok(Value::List {
                    ty: ty.clone(),
                    items: copied,
                })
            }
            Value::Struct {
                ty,
                fields,
                owner,
            } => {
                ev.expand(
                    fields
                        .len()
                        .saturating_mul(size_of::<(String, Value)>()),
                    span,
                )?;
                let mut copied = Vec::with_capacity(fields.len());
                for (name, value) in fields {
                    ev.expand(name.len(), span)?;
                    copied.push((
                        name.clone(),
                        Self::copy_value_ref(ev, value, span, depth + 1)?,
                    ));
                }
                Ok(Value::Struct {
                    ty: ty.clone(),
                    fields: copied,
                    owner: *owner,
                })
            }
            Value::Variant {
                ty,
                index,
                payload,
            } => {
                ev.expand(
                    payload.len().saturating_mul(size_of::<Value>()),
                    span,
                )?;
                let payload = payload
                    .iter()
                    .map(|value| Self::copy_value_ref(ev, value, span, depth + 1))
                    .collect::<Eval<Vec<_>>>()?;
                Ok(Value::Variant {
                    ty: ty.clone(),
                    index: *index,
                    payload,
                })
            }
        }
    }

    pub(super) fn copy_value(&mut self, local: LocalId, span: Span) -> Eval<Value> {
        let value = self.locals.remove(&local).ok_or(Halt)?;
        let result = Self::copy_value_ref(self, &value, span, 0);
        self.locals.insert(local, value);
        result
    }

    pub(super) fn construct_variant(
        &mut self,
        ty: Arc<CanonicalType>,
        index: u32,
        payload: Vec<Value>,
        span: Span,
    ) -> Eval<Value> {
        let value = Value::Variant {
            ty,
            index,
            payload,
        };
        self.check_payload_depth(&value, span, 0)?;
        Ok(value)
    }

    // An iterative fold can grow a recursive payload without increasing call
    // depth. Bound the retained tree before later copying, affine inspection or
    // destruction can recurse through it. Traversal itself consumes work budget.
    fn check_payload_depth(&mut self, value: &Value, span: Span, depth: usize) -> Eval<()> {
        self.tick(span)?;
        if depth >= self.limits.max_depth {
            return self.fail(span, "enum payload value depth limit reached");
        }
        match value {
            Value::Variant {
                payload: items,
                ..
            }
            | Value::List {
                items,
                ..
            } => {
                for item in items {
                    self.check_payload_depth(item, span, depth + 1)?;
                }
            }
            Value::Struct {
                fields,
                ..
            } => {
                for (_, item) in fields {
                    self.check_payload_depth(item, span, depth + 1)?;
                }
            }
            Value::Closure {
                captures,
                ..
            } => {
                for (_, item) in captures {
                    self.check_payload_depth(item, span, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn sort_by_keys(&mut self, items: Value, keys: Value, span: Span) -> Eval<Value> {
        let (
            Value::List {
                ty,
                items,
            },
            Value::List {
                items: keys,
                ..
            },
        ) = (items, keys)
        else {
            return self.fail(span, "sort_by_keys requires two lists");
        };
        if items.len() != keys.len() {
            return self.fail(span, "sort_by_keys lists must have equal lengths");
        }
        self.expand(
            items
                .len()
                .saturating_mul(size_of::<(PrimitiveValue, usize, Value)>() + size_of::<Value>()),
            span,
        )?;
        let mut keyed = Vec::with_capacity(items.len());
        for (index, (key, item)) in keys.into_iter().zip(items).enumerate() {
            self.tick(span)?;
            let Some(key) = primitive_value(key) else {
                return self.fail(span, "invalid sort key");
            };
            keyed.push((key, index, item));
        }
        // Fallible in-place heapsort: every comparison spends work before it
        // runs, and a budget failure stops immediately. The original position
        // breaks equal-key ties, preserving stable ordering without cloning T.
        for root in (0..keyed.len() / 2).rev() {
            self.sift_keys(&mut keyed, root, span)?;
        }
        for end in (1..keyed.len()).rev() {
            keyed.swap(0, end);
            self.sift_keys(&mut keyed[..end], 0, span)?;
        }
        Ok(Value::List {
            ty,
            items: keyed
                .into_iter()
                .map(|(_, _, item)| item)
                .collect(),
        })
    }

    fn sift_keys(
        &mut self,
        values: &mut [(PrimitiveValue, usize, Value)],
        mut root: usize,
        span: Span,
    ) -> Eval<()> {
        while root * 2 + 1 < values.len() {
            let mut child = root * 2 + 1;
            if child + 1 < values.len()
                && self.key_less(&values[child], &values[child + 1], span)?
            {
                child += 1;
            }
            if !self.key_less(&values[root], &values[child], span)? {
                break;
            }
            values.swap(root, child);
            root = child;
        }
        Ok(())
    }

    fn key_less(
        &mut self,
        left: &(PrimitiveValue, usize, Value),
        right: &(PrimitiveValue, usize, Value),
        span: Span,
    ) -> Eval<bool> {
        let work = match (&left.0, &right.0) {
            (PrimitiveValue::Str(left), PrimitiveValue::Str(right)) => {
                left.len().min(right.len()).saturating_add(1)
            }
            _ => 1,
        };
        self.charge_steps(work, span)?;
        Ok((&left.0, left.1) < (&right.0, right.1))
    }

    pub(super) fn compare_values(&mut self, left: Value, right: Value, span: Span) -> Eval<usize> {
        let ordering = match (primitive_value(left), primitive_value(right)) {
            (Some(PrimitiveValue::Int(left)), Some(PrimitiveValue::Int(right))) => left.cmp(&right),
            (Some(PrimitiveValue::Str(left)), Some(PrimitiveValue::Str(right))) => {
                self.charge_steps(
                    left.len().min(right.len()).saturating_add(1),
                    span,
                )?;
                left.as_bytes().cmp(right.as_bytes())
            }
            _ => return self.fail(span, "checked comparison has invalid operands"),
        };
        Ok(match ordering {
            std::cmp::Ordering::Less => 0,
            std::cmp::Ordering::Equal => 1,
            std::cmp::Ordering::Greater => 2,
        })
    }
}

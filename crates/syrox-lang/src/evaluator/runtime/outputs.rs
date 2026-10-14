use super::{
    Arc, BTreeMap, CachedOutput, CanonicalType, Eval, Evaluator, Expression, Halt, ItemId, MemoId,
    Span, Value, size_of,
};

impl Evaluator<'_> {
    pub(in crate::evaluator) fn root_value(
        &mut self,
        item: ItemId,
        expression: &Expression,
    ) -> Eval<Value> {
        if self.memo_outputs.contains_key(&item) {
            return self.output_value(item, expression.span);
        }
        self.expand(size_of::<ItemId>(), expression.span)?;
        self.active_outputs.insert(item);
        let claim_effects = self.claim_effects;
        let result = self.expression(expression, &BTreeMap::new());
        self.active_outputs.remove(&item);
        let value = result?;
        if !value.affine() && self.claim_effects == claim_effects && self.diagnostics.is_empty() {
            self.expand(
                size_of::<(ItemId, CachedOutput)>(),
                expression.span,
            )?;
            let copy = Self::copy_value_ref(self, &value, expression.span, 0)?;
            self.memo_outputs.insert(
                item,
                CachedOutput {
                    value: copy,
                    shareable: true,
                },
            );
        }
        Ok(value)
    }

    pub(super) fn output_value(&mut self, item: ItemId, span: Span) -> Eval<Value> {
        self.ensure_output_cached(item, span)?;
        let output = self.memo_outputs.remove(&item).ok_or(Halt)?;
        if !output.shareable {
            self.claim_effects = self.claim_effects.saturating_add(1);
        }
        let result = Self::copy_value_ref(self, &output.value, span, 0);
        self.memo_outputs.insert(item, output);
        result
    }

    pub(super) fn ensure_output_cached(&mut self, item: ItemId, span: Span) -> Eval<()> {
        if self.memo_outputs.contains_key(&item) {
            return Ok(());
        }
        if self.active_outputs.contains(&item) {
            return self.fail(span, "cycle in imported value outputs");
        }
        self.expand(size_of::<ItemId>(), span)?;
        self.active_outputs.insert(item);
        let value = self
            .index
            .output_values
            .get(&item)
            .copied()
            .ok_or(Halt)?;
        let previous = self.enter_project_context(value.span);
        let claim_effects = self.claim_effects;
        let result = self.expression(value, &BTreeMap::new());
        self.project_context = previous;
        self.active_outputs.remove(&item);
        let value = result?;
        if value.affine() {
            return self.fail(
                span,
                "imported value output cannot carry an affine resource",
            );
        }
        self.expand(size_of::<(ItemId, CachedOutput)>(), span)?;
        let shareable = self.claim_effects == claim_effects && self.diagnostics.is_empty();
        self.memo_outputs.insert(
            item,
            CachedOutput {
                value,
                shareable,
            },
        );
        Ok(())
    }

    pub(in crate::evaluator) fn published_value(
        &mut self,
        item: ItemId,
        span: Span,
    ) -> Eval<Value> {
        self.tick(span)?;
        let member = self
            .checked
            .resolved()
            .published_member(item)
            .ok_or(Halt)?;
        let key = (member.publication, member.factory());
        let ty = self
            .checked
            .published_type(item)
            .and_then(|ty| self.index.canonical_type(ty))
            .ok_or(Halt)?;
        let CanonicalType::Specialization {
            arguments,
            ..
        } = ty.as_ref()
        else {
            return Err(Halt);
        };
        let [result] = arguments.as_slice() else {
            return Err(Halt);
        };
        self.expand(
            3 * size_of::<Value>()
                + size_of::<CanonicalType>()
                + size_of::<(String, Value)>()
                + size_of::<(crate::resolver::PublicationId, ItemId, MemoId)>()
                + "factory".len(),
            span,
        )?;
        let factory_ty = Arc::new(CanonicalType::Function {
            parameters: Vec::new(),
            result: result.clone(),
            once: false,
        });
        let id = if let Some(id) = self.memos.published.get(&key) {
            id.clone()
        } else {
            let declaration = self
                .checked
                .resolved()
                .item(item)
                .ok_or(Halt)?
                .span();
            let previous = self.enter_project_context(declaration);
            let value = self.memoize(
                Value::Function {
                    item: key.1,
                    substitutions: BTreeMap::new(),
                    ty: factory_ty.clone(),
                },
                declaration,
            );
            self.project_context = previous;
            let Value::MemoizedFunction {
                id,
                ..
            } = value?
            else {
                return Err(Halt);
            };
            self.memos.published.insert(key, id.clone());
            id
        };
        let owner = self.checked.resolved().parsed().owner(
            self.checked
                .resolved()
                .item(item)
                .ok_or(Halt)?
                .span()
                .source_id(),
        );
        Ok(Value::Struct {
            ty,
            fields: vec![(
                "factory".into(),
                Value::MemoizedFunction {
                    ty: factory_ty,
                    id,
                },
            )],
            owner,
        })
    }
}

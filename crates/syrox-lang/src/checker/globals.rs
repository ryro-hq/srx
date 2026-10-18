//! Immutable module values are inferred once, in dependency order.
use super::{BTreeMap, Checker, ItemId, Span, Ty};

impl Checker<'_> {
    pub(super) fn check_globals(&mut self) {
        let globals: Vec<_> = self.global_values.keys().copied().collect();
        for id in globals {
            let span = self.global_values[&id].0.name.span;
            self.with_body(span, |checker| {
                checker.check_global(id, span);
            });
        }
    }

    pub(super) fn check_global(&mut self, id: ItemId, span: Span) -> Ty {
        if let Some(ty) = self.global_types.get(&id) {
            return ty.clone();
        }
        if !self.charge(span) {
            return Ty::Error;
        }
        if self.active_globals.contains(&id) {
            let mut cycle: Vec<_> = self
                .active_globals
                .iter()
                .filter_map(|id| self.program.item(*id))
                .map(|item| item.path().segments().join("::"))
                .collect();
            cycle.push(
                self.program
                    .item(id)
                    .expect("global")
                    .path()
                    .segments()
                    .join("::"),
            );
            self.error(
                format!("cycle in global bindings: {}", cycle.join(" -> ")),
                span,
            );
            return Ty::Error;
        }
        if self.active_globals.len() >= self.limits.max_specialization_depth {
            self.error(
                "global binding dependency depth limit reached",
                span,
            );
            return Ty::Error;
        }
        self.active_globals.push(id);
        let (binding, context) = self.global_values[&id];
        let previous_body = std::mem::take(&mut self.body.bindings);
        let substitutions = std::mem::take(&mut self.body.type_parameters);
        let previous_global = self.global_initializer.replace(id);
        let expression_start = self.expressions.len();
        let pattern_start = self.patterns.len();
        let previous_mode = std::mem::replace(&mut self.static_mode, true);
        let want = binding
            .ty
            .as_ref()
            .map(|ty| self.resolve_type(ty, &BTreeMap::new(), 0));
        let before = self.body.fact_errors;
        let actual = self.check_expr(&binding.value, want.as_ref(), context, true);
        if let Some(want) = &want {
            self.expect_same(
                want,
                &actual,
                binding.value.span,
                "global binding",
            );
        }
        let ty = want.unwrap_or({
            if self.body.fact_errors == before {
                actual
            } else {
                Ty::Error
            }
        });
        if self.affine(&ty, binding.name.span) {
            self.error(
                "global binding cannot carry an affine resource",
                binding.name.span,
            );
        }
        if self.body.fact_errors == before
            && let Some(constant) = self.constant_value(&binding.value, 0)
        {
            self.global_constants.insert(id, constant);
        }
        if !self.static_calls.is_empty() {
            let facts = self.expressions[expression_start..].to_vec();
            for fact in facts {
                let key = super::span_key(fact.span);
                if !self.global_facts.contains_key(&key) && self.reserve_metadata(fact.span) {
                    self.collection_metadata_units += 1;
                    self.global_facts.insert(key, fact);
                }
            }
        }
        if !self.static_calls.is_empty() {
            let patterns = self.patterns[pattern_start..].to_vec();
            for pattern in patterns {
                let key = super::span_key(pattern.span);
                if !self.global_patterns.contains_key(&key) && self.reserve_metadata(pattern.span) {
                    self.collection_metadata_units += 1;
                    self.global_patterns.insert(key, pattern);
                }
            }
        }
        self.global_initializer = previous_global;
        self.body.bindings = previous_body;
        self.body.type_parameters = substitutions;
        self.static_mode = previous_mode;
        self.active_globals.pop();
        self.global_types.insert(id, ty.clone());
        if self.reserve_editor_metadata(binding.name.span)
            && let Some(retained) = self.retain_editor_type(&ty)
        {
            self.editor.outputs.insert(id, retained);
        }
        ty
    }
}

//! Checking one body without mixing its facts with the next body's facts.
//!
//! Each result keeps its facts and observed cost. Limits and generic-instance
//! deduplication still apply to the whole checking run. Publishing these facts
//! does not create a cache entry across revisions. [`effects`] records the work
//! and decisions used to compare a body against another checking state.

use super::{
    BTreeMap, BTreeSet, Binding, CheckedExpression, CheckedLocal, CheckedPattern, Checker,
    Diagnostic, LocalId, OwnershipUse, ParameterHint, Span, Ty,
};
use crate::resolver::ItemId;
use std::ops::Range;
use std::sync::Arc;

mod effects;
pub use effects::{BodyEffects, BodyReplayState};
pub(super) use effects::{EffectOperation, EffectRetention};

/// Ranges into the original checker publication order, before diagnostic sorting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BodyPublication {
    pub anchor: Span,
    pub diagnostics: Range<usize>,
    pub expressions: Range<usize>,
    pub patterns: Range<usize>,
    pub uses: Range<usize>,
    pub fields: Range<usize>,
    pub arguments: Range<usize>,
    pub locals: Vec<LocalId>,
    pub outputs: Vec<ItemId>,
    pub complete: bool,
    pub effects: Option<Arc<BodyEffects>>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct BodyPublications {
    pub entries: Vec<BodyPublication>,
    pub truncated: bool,
    pub(crate) units: usize,
}

#[derive(Default)]
pub(super) struct BodyState {
    pub bindings: BTreeMap<LocalId, Binding>,
    pub type_parameters: BTreeMap<LocalId, Ty>,
    pub fact_errors: u64,
    pub fact_unknowns: u64,
    pub active: bool,
    /// Includes instances already registered by another body. A count delta
    /// alone cannot describe this body's dependence on shared deduplication.
    pub instances: BTreeSet<Ty>,
    pub effects: Vec<effects::EffectObservation>,
    pub effect_anchor: Option<Span>,
}

#[derive(Default)]
struct BodyFacts {
    diagnostics: Vec<Diagnostic>,
    expressions: Vec<CheckedExpression>,
    patterns: Vec<CheckedPattern>,
    locals: BTreeMap<LocalId, CheckedLocal>,
    uses: Vec<OwnershipUse>,
    fields: Vec<(Span, Span, Ty)>,
    arguments: Vec<ParameterHint>,
    outputs: BTreeMap<ItemId, Ty>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyBudget {
    pub work: usize,
    pub metadata: usize,
    pub editor_metadata: usize,
    pub generic_instances: usize,
    pub specializations: usize,
    pub diagnostics: usize,
    pub exhausted: bool,
    pub editor_truncated: bool,
}

struct BodyResult {
    facts: BodyFacts,
    before: BodyBudget,
    after: BodyBudget,
    instances: BTreeSet<Ty>,
    cancelled: bool,
    effects: Option<Arc<BodyEffects>>,
}

impl BodyFacts {
    fn take(checker: &mut Checker<'_>) -> Self {
        Self {
            diagnostics: std::mem::take(&mut checker.diagnostics),
            expressions: std::mem::take(&mut checker.expressions),
            patterns: std::mem::take(&mut checker.patterns),
            locals: std::mem::take(&mut checker.editor.locals),
            uses: std::mem::take(&mut checker.editor.uses),
            fields: std::mem::take(&mut checker.editor.fields),
            arguments: std::mem::take(&mut checker.editor.arguments),
            outputs: std::mem::take(&mut checker.editor.outputs),
        }
    }

    fn append(mut self, checker: &mut Checker<'_>) {
        checker.diagnostics.append(&mut self.diagnostics);
        checker.expressions.append(&mut self.expressions);
        checker.patterns.append(&mut self.patterns);
        checker.editor.locals.extend(self.locals);
        checker.editor.uses.append(&mut self.uses);
        checker.editor.fields.append(&mut self.fields);
        checker
            .editor
            .arguments
            .append(&mut self.arguments);
        checker.editor.outputs.extend(self.outputs);
    }

    fn restore(self, checker: &mut Checker<'_>) {
        checker.diagnostics = self.diagnostics;
        checker.expressions = self.expressions;
        checker.patterns = self.patterns;
        checker.editor.locals = self.locals;
        checker.editor.uses = self.uses;
        checker.editor.fields = self.fields;
        checker.editor.arguments = self.arguments;
        checker.editor.outputs = self.outputs;
    }
}

impl Checker<'_> {
    pub(super) fn budget_position(&self) -> BodyBudget {
        BodyBudget {
            work: self.work,
            metadata: self.prior_metadata
                + self.expressions.len()
                + self.patterns.len()
                + self.collection_metadata_units,
            editor_metadata: self.editor.units,
            generic_instances: self.generic_instances.len(),
            specializations: self.static_instances,
            diagnostics: self.prior_diagnostics + self.diagnostics.len(),
            exhausted: self.exhausted,
            editor_truncated: self.editor.truncated,
        }
    }

    pub(super) fn with_body(&mut self, anchor: Span, check: impl FnOnce(&mut Self)) {
        // Differential tests retain the old flat accumulation as an oracle.
        #[cfg(test)]
        if self.unpartitioned_bodies {
            check(self);
            return;
        }
        let result = self.evaluate_body(|checker| {
            checker.body.effect_anchor = Some(anchor);
            check(checker);
        });
        self.record_body(anchor, &result);
        self.publish_body(result);
    }

    fn record_body(&mut self, anchor: Span, result: &BodyResult) {
        if self.cancellation.is_none() || result.cancelled || self.publications.truncated {
            return;
        }
        let facts = &result.facts;
        let units = 1 + facts.locals.len() + facts.outputs.len();
        if units > 262_144_usize.saturating_sub(self.publications.units) {
            self.publications = BodyPublications {
                truncated: true,
                ..BodyPublications::default()
            };
            return;
        }
        self.publications.units += units;
        self.publications.entries.push(BodyPublication {
            anchor,
            diagnostics: self.diagnostics.len()..self.diagnostics.len() + facts.diagnostics.len(),
            expressions: self.expressions.len()..self.expressions.len() + facts.expressions.len(),
            patterns: self.patterns.len()..self.patterns.len() + facts.patterns.len(),
            uses: self.editor.uses.len()..self.editor.uses.len() + facts.uses.len(),
            fields: self.editor.fields.len()..self.editor.fields.len() + facts.fields.len(),
            arguments: self.editor.arguments.len()
                ..self.editor.arguments.len() + facts.arguments.len(),
            locals: facts.locals.keys().copied().collect(),
            outputs: facts.outputs.keys().copied().collect(),
            complete: !result.after.exhausted
                && !result.after.editor_truncated
                && result.after.diagnostics < crate::MAX_DIAGNOSTICS,
            effects: result.effects.clone(),
        });
    }

    fn evaluate_body(&mut self, check: impl FnOnce(&mut Self)) -> BodyResult {
        assert!(
            !self.body.active,
            "closures belong to their enclosing body query"
        );
        let before = self.budget_position();
        let previous = std::mem::replace(
            &mut self.body,
            BodyState {
                active: true,
                ..BodyState::default()
            },
        );
        let prefix = BodyFacts::take(self);
        self.prior_diagnostics += prefix.diagnostics.len();
        self.prior_metadata += prefix.expressions.len() + prefix.patterns.len();
        check(self);
        let after = self.budget_position();
        let facts = BodyFacts::take(self);
        self.prior_diagnostics -= prefix.diagnostics.len();
        self.prior_metadata -= prefix.expressions.len() + prefix.patterns.len();
        prefix.restore(self);
        let state = std::mem::replace(&mut self.body, previous);
        BodyResult {
            facts,
            before,
            after,
            instances: state.instances,
            effects: (self.cancellation.is_some() && !self.effect_retention.truncated).then(|| {
                Arc::new(BodyEffects::new(
                    before,
                    after,
                    self.limits,
                    state.effects,
                ))
            }),
            cancelled: self
                .cancellation
                .is_some_and(|cancel| cancel.check().is_err()),
        }
    }

    fn publish_body(&mut self, result: BodyResult) {
        if result.cancelled
            || self
                .cancellation
                .is_some_and(|cancel| cancel.check().is_err())
        {
            return;
        }
        // Budget effects were charged in their original order while checking.
        // Publication neither charges them again nor resets a global limit.
        debug_assert!(result.before.work <= result.after.work);
        debug_assert!(
            result
                .instances
                .iter()
                .all(|ty| self.generic_instances.contains(ty))
        );
        result.facts.append(self);
        debug_assert_eq!(self.budget_position(), result.after);
    }
}

#[cfg(test)]
mod tests;

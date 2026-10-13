//! Recording work and decisions observed while checking a body.
//!
//! Replay compares these observations with another budget and instance state.
//! If any limit or decision changes, replay rejects the result. The record does
//! not install facts in the checker or cause a body's evaluation to be skipped.

use super::{BodyBudget, Checker};
use crate::{
    analysis::AnalysisCancellation, analysis::AnalysisCancelled, checker::CheckLimits, checker::Ty,
    source::Span,
};
use std::collections::BTreeSet;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyReplayState {
    pub budget: BodyBudget,
    /// Snapshot-local types, in the same coordinates as the journal.
    pub instances: BTreeSet<Ty>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::checker) enum EffectOperation {
    WorkProbe(usize),
    Metadata,
    EditorUnit,
    EditorType(usize),
    Diagnostic,
    Instance {
        ty: Ty,
        already_present: bool,
    },
    ReferenceScan(Arc<[Span]>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::checker) struct EffectObservation {
    position: BodyBudget,
    span: Span,
    operation: EffectOperation,
}

/// Inspection-only journal. Replay does not install facts or construct a program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyEffects {
    entry: BodyBudget,
    exit: BodyBudget,
    limits: CheckLimits,
    observations: Vec<EffectObservation>,
}

impl BodyEffects {
    pub(super) fn new(
        entry: BodyBudget,
        exit: BodyBudget,
        limits: CheckLimits,
        observations: Vec<EffectObservation>,
    ) -> Self {
        Self {
            entry,
            exit,
            limits,
            observations,
        }
    }
    pub const fn entry(&self) -> BodyBudget {
        self.entry
    }
    pub const fn exit(&self) -> BodyBudget {
        self.exit
    }
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    /// Simulate unchanged decisions against a different prefix. A failed replay
    /// never mutates `input`; callers must cold-check instead of publishing it.
    /// Across snapshots, first remap the journal and validate its dependencies;
    /// this scalar simulation cannot inspect the target reference inventory.
    pub fn replay(
        &self,
        input: &BodyReplayState,
        limits: CheckLimits,
        cancel: &AnalysisCancellation,
    ) -> Result<Option<BodyReplayState>, AnalysisCancelled> {
        cancel.check()?;
        if limits != self.limits
            || !usable(self.entry)
            || !usable(self.exit)
            || !usable(input.budget)
            || input.instances.len() != input.budget.generic_instances
            || input.instances.len() > limits.max_generic_instances
        {
            return Ok(None);
        }
        let mut state = BodyReplayState {
            budget: input.budget,
            instances: BTreeSet::new(),
        };
        let mut units = 262_144;
        for ty in &input.instances {
            if !type_fits(ty, &mut units, cancel) {
                cancel.check()?;
                return Ok(None);
            }
            state.instances.insert(ty.clone());
        }
        let result = (|| {
            let mut previous = self.entry;
            for observation in &self.observations {
                cancel.check().ok()?;
                advance(
                    &mut state.budget,
                    previous,
                    observation.position,
                    limits,
                )?;
                let position = state.budget;
                match &observation.operation {
                    EffectOperation::WorkProbe(cost) => {
                        if position.work.checked_add(*cost)? > limits.max_work {
                            return None;
                        }
                    }
                    EffectOperation::Metadata => {
                        if position.metadata >= limits.max_metadata_units {
                            return None;
                        }
                    }
                    EffectOperation::EditorUnit => {
                        if position.editor_metadata >= limits.max_metadata_units {
                            return None;
                        }
                    }
                    EffectOperation::EditorType(cost) => {
                        if position.editor_metadata.checked_add(*cost)? > limits.max_metadata_units
                        {
                            return None;
                        }
                    }
                    EffectOperation::Diagnostic => {
                        if position.diagnostics >= crate::MAX_DIAGNOSTICS {
                            return None;
                        }
                    }
                    EffectOperation::Instance {
                        ty,
                        ..
                    } => {
                        if !state.instances.contains(ty) {
                            if state.instances.len() >= limits.max_generic_instances
                                || !type_fits(ty, &mut units, cancel)
                            {
                                return None;
                            }
                            state.instances.insert(ty.clone());
                            state.budget.generic_instances = state.instances.len();
                        }
                    }
                    EffectOperation::ReferenceScan(_) => {}
                }
                previous = observation.position;
            }
            advance(&mut state.budget, previous, self.exit, limits)?;
            usable(state.budget).then_some(state)
        })();
        cancel.check()?;
        Ok(result)
    }

    pub(crate) fn remap(&self, mapper: &mut impl crate::checker::FactMapper) -> Option<Self> {
        let observations = self
            .observations
            .iter()
            .map(|observation| {
                mapper.reserve(0)?;
                Some(EffectObservation {
                    position: observation.position,
                    span: mapper.span(observation.span)?,
                    operation: match &observation.operation {
                        EffectOperation::ReferenceScan(references) => {
                            EffectOperation::ReferenceScan(mapper.reference_scan(references)?)
                        }
                        EffectOperation::Instance {
                            ty,
                            already_present,
                        } => EffectOperation::Instance {
                            ty: mapper.ty(ty)?,
                            already_present: *already_present,
                        },
                        other => other.clone(),
                    },
                })
            })
            .collect::<Option<_>>()?;
        Some(Self {
            entry: self.entry,
            exit: self.exit,
            limits: self.limits,
            observations,
        })
    }
}

fn usable(position: BodyBudget) -> bool {
    !position.exhausted
        && !position.editor_truncated
        && position.diagnostics < crate::MAX_DIAGNOSTICS
}

fn advance(
    position: &mut BodyBudget,
    before: BodyBudget,
    after: BodyBudget,
    limits: CheckLimits,
) -> Option<()> {
    if !usable(before) || !usable(after) {
        return None;
    }
    position.work = position
        .work
        .checked_add(after.work.checked_sub(before.work)?)?;
    position.metadata = position
        .metadata
        .checked_add(after.metadata.checked_sub(before.metadata)?)?;
    position.editor_metadata = position.editor_metadata.checked_add(
        after
            .editor_metadata
            .checked_sub(before.editor_metadata)?,
    )?;
    position.diagnostics = position.diagnostics.checked_add(
        after
            .diagnostics
            .checked_sub(before.diagnostics)?,
    )?;
    (position.work <= limits.max_work
        && position.metadata <= limits.max_metadata_units
        && position.editor_metadata <= limits.max_metadata_units
        && position.diagnostics < crate::MAX_DIAGNOSTICS)
        .then_some(())
}

#[derive(Debug, PartialEq, Eq)]
pub(in crate::checker) struct EffectRetention {
    remaining: usize,
    pub truncated: bool,
}
impl Default for EffectRetention {
    fn default() -> Self {
        Self {
            remaining: 262_144,
            truncated: false,
        }
    }
}

impl Checker<'_> {
    pub(in crate::checker) fn observe_reference_scan(&mut self, span: Span) {
        if !self.body.active || self.cancellation.is_none() || self.effect_retention.truncated {
            return;
        }
        if self.reference_inventory.is_none() {
            let count = self.program.references().len();
            if count > self.effect_retention.remaining {
                self.discard_effects();
                return;
            }
            self.effect_retention.remaining -= count;
            let cancel = self
                .cancellation
                .expect("editor observation requires cancellation");
            let mut inventory = Vec::with_capacity(count);
            for reference in self.program.references() {
                if cancel.check().is_err() {
                    self.discard_effects();
                    return;
                }
                inventory.push(reference.span());
            }
            self.reference_inventory = Some(inventory.into());
        }
        self.observe_effect(
            span,
            EffectOperation::ReferenceScan(self.reference_inventory.as_ref().unwrap().clone()),
        );
    }
    pub(in crate::checker) fn observe_effect(&mut self, span: Span, operation: EffectOperation) {
        if !self.body.active || self.cancellation.is_none() || self.effect_retention.truncated {
            return;
        }
        let before = self.budget_position();
        self.observe_effect_at(before, span, operation);
    }

    pub(in crate::checker) fn observe_effect_at(
        &mut self,
        position: BodyBudget,
        span: Span,
        operation: EffectOperation,
    ) {
        if !self.body.active || self.cancellation.is_none() || self.effect_retention.truncated {
            return;
        }
        if self.effect_retention.remaining == 0 {
            self.discard_effects();
            return;
        }
        self.effect_retention.remaining -= 1;
        self.body.effects.push(EffectObservation {
            position,
            span,
            operation,
        });
    }

    pub(in crate::checker) fn observe_instance(&mut self, span: Span, ty: &Ty) {
        if !self.body.active || self.effect_retention.truncated {
            return;
        }
        let Some(cancel) = self.cancellation else {
            return;
        };
        if !type_fits(ty, &mut self.effect_retention.remaining, cancel) {
            self.discard_effects();
            return;
        }
        self.observe_effect(
            span,
            EffectOperation::Instance {
                ty: ty.clone(),
                already_present: self.generic_instances.contains(ty),
            },
        );
    }

    fn discard_effects(&mut self) {
        self.reference_inventory = None;
        self.effect_retention.truncated = true;
        self.body.effects.clear();
        for publication in &mut self.publications.entries {
            publication.effects = None;
        }
    }
}

fn type_fits(ty: &Ty, remaining: &mut usize, cancel: &AnalysisCancellation) -> bool {
    type_fits_at(ty, remaining, cancel, 0)
}

fn type_fits_at(
    ty: &Ty,
    remaining: &mut usize,
    cancel: &AnalysisCancellation,
    depth: usize,
) -> bool {
    if *remaining == 0 || depth > crate::MAX_DEPTH || cancel.check().is_err() {
        return false;
    }
    *remaining -= 1;
    match ty {
        Ty::Specialization {
            arguments,
            ..
        } => arguments
            .iter()
            .all(|ty| type_fits_at(ty, remaining, cancel, depth + 1)),
        Ty::Function {
            parameters,
            result,
            ..
        } => {
            parameters
                .iter()
                .all(|ty| type_fits_at(ty, remaining, cancel, depth + 1))
                && type_fits_at(result, remaining, cancel, depth + 1)
        }
        Ty::List(inner) => type_fits_at(inner, remaining, cancel, depth + 1),
        Ty::Unit | Ty::Int | Ty::Str | Ty::Parameter(_) | Ty::Nominal(_) | Ty::Error => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        checker::CheckPolicy, resolver::resolve, source::SourceSet, syntax::parse_sources,
    };
    use std::collections::BTreeMap;

    fn program() -> crate::resolver::ResolvedProgram {
        let mut sources = SourceSet::new();
        sources.add("main.srx","value I(int); struct Box<T> { payload: T; } fn inspect() { let x=Box<I> { payload = I(1); }; let y=Box<I> { payload = I(2); }; }").unwrap();
        resolve(parse_sources(&sources).unwrap()).unwrap()
    }

    fn prepare<'a>(
        program: &'a crate::resolver::ResolvedProgram,
        policy: &'a CheckPolicy,
        cancel: &'a AnalysisCancellation,
        limits: CheckLimits,
    ) -> Checker<'a> {
        let mut checker = Checker::new(program, policy, limits);
        checker.cancellation = Some(cancel);
        checker.index_resolution_metadata();
        checker.index();
        checker.validate_declarations();
        checker.propagate_carriers();
        checker.collect_function_types();
        checker.collect_editor_types();
        checker
    }

    fn run(checker: &mut Checker<'_>) -> super::super::BodyResult {
        let info = *checker.functions.values().next().unwrap();
        checker.evaluate_body(|checker| {
            checker.body.effect_anchor = Some(info.declaration.name.span);
            checker.check_block(&info.declaration.body, None, info.context);
        })
    }

    #[test]
    fn replay_matches_cold_prefix_changes_and_both_deduplication_directions() {
        let program = program();
        let policy = CheckPolicy::default();
        let cancel = AnalysisCancellation::default();
        let limits = CheckLimits::default();
        let mut original = prepare(&program, &policy, &cancel, limits);
        let original_input = BodyReplayState {
            budget: original.budget_position(),
            instances: original.generic_instances.clone(),
        };
        let result = run(&mut original);
        let journal = result.effects.unwrap();
        assert!(journal.observation_count() > 0);
        assert_eq!(
            journal
                .replay(&original_input, limits, &cancel)
                .unwrap()
                .unwrap(),
            BodyReplayState {
                budget: result.after,
                instances: original.generic_instances.clone()
            }
        );
        let requested = original.generic_instances.clone();
        for seeded in [false, true] {
            let mut cold = prepare(&program, &policy, &cancel, limits);
            cold.work += 17;
            cold.prior_metadata += 5;
            cold.editor.units += 3;
            cold.prior_diagnostics += 2;
            if seeded {
                cold.generic_instances = requested.clone();
            }
            let input = BodyReplayState {
                budget: cold.budget_position(),
                instances: cold.generic_instances.clone(),
            };
            let expected = run(&mut cold);
            let replayed = journal
                .replay(&input, limits, &cancel)
                .unwrap()
                .unwrap();
            assert_eq!(
                replayed,
                BodyReplayState {
                    budget: expected.after,
                    instances: cold.generic_instances.clone()
                }
            );
            // Replay the journal recorded with the new prefix back at the old prefix.
            let other = expected.effects.unwrap();
            assert_eq!(
                other
                    .replay(&original_input, limits, &cancel)
                    .unwrap()
                    .unwrap()
                    .budget,
                result.after
            );
        }
    }

    #[test]
    fn sequential_body_journals_compose_with_shared_specializations() {
        let mut sources = SourceSet::new();
        sources.add("main.srx","value I(int); struct Box<T> { payload: T; } fn first() { let x=Box<I> { payload=I(1); }; } fn second() { let x=Box<I> { payload=I(2); }; let y=Box<Box<I>> { payload=x; }; }").unwrap();
        let program = resolve(parse_sources(&sources).unwrap()).unwrap();
        let policy = CheckPolicy::default();
        let cancel = AnalysisCancellation::default();
        let limits = CheckLimits::default();
        let mut checker = prepare(&program, &policy, &cancel, limits);
        let mut simulated = BodyReplayState {
            budget: checker.budget_position(),
            instances: checker.generic_instances.clone(),
        };
        let functions: Vec<_> = checker.functions.values().copied().collect();
        for info in functions {
            let result = checker.evaluate_body(|checker| {
                checker.body.effect_anchor = Some(info.declaration.name.span);
                checker.check_block(&info.declaration.body, None, info.context);
            });
            let journal = result.effects.as_ref().unwrap();
            simulated = journal
                .replay(&simulated, limits, &cancel)
                .unwrap()
                .unwrap();
            assert_eq!(
                simulated,
                BodyReplayState {
                    budget: result.after,
                    instances: checker.generic_instances.clone()
                }
            );
            checker.publish_body(result);
            assert_eq!(simulated.budget, checker.budget_position());
        }
        assert_eq!(simulated.instances.len(), 2);
    }

    #[test]
    fn exact_work_boundary_and_ordered_instance_limit_match_cold_runs() {
        let program = program();
        let policy = CheckPolicy::default();
        let cancel = AnalysisCancellation::default();
        let limits = CheckLimits {
            max_generic_instances: 1,
            ..CheckLimits::default()
        };
        let mut original = prepare(&program, &policy, &cancel, limits);
        let result = run(&mut original);
        let journal = result.effects.unwrap();
        let delta = result.after.work - result.before.work;
        for extra in [0, 1] {
            let mut cold = prepare(&program, &policy, &cancel, limits);
            cold.work = limits.max_work - delta + extra;
            let input = BodyReplayState {
                budget: cold.budget_position(),
                instances: cold.generic_instances.clone(),
            };
            let result = run(&mut cold);
            let replay = journal.replay(&input, limits, &cancel).unwrap();
            if extra == 0 {
                assert_eq!(replay.unwrap().budget, result.after);
            } else {
                assert!(replay.is_none() && result.after.exhausted);
            }
        }
        let requested = original
            .generic_instances
            .iter()
            .next()
            .unwrap()
            .clone();
        let Ty::Specialization {
            template,
            ..
        } = requested
        else {
            panic!("specialization");
        };
        for instance in [
            requested,
            Ty::Specialization {
                template,
                arguments: vec![Ty::Str],
            },
        ] {
            let mut cold = prepare(&program, &policy, &cancel, limits);
            cold.generic_instances.insert(instance);
            let input = BodyReplayState {
                budget: cold.budget_position(),
                instances: cold.generic_instances.clone(),
            };
            let result = run(&mut cold);
            let replay = journal.replay(&input, limits, &cancel).unwrap();
            if result.after.exhausted {
                assert!(replay.is_none());
            } else {
                assert_eq!(
                    replay.unwrap(),
                    BodyReplayState {
                        budget: result.after,
                        instances: cold.generic_instances.clone()
                    }
                );
            }
        }
    }

    #[test]
    fn uncommitted_concretization_probes_are_not_lost_in_final_deltas() {
        use crate::checker::RawTy;
        let program = program();
        let policy = CheckPolicy::default();
        let cancel = AnalysisCancellation::default();
        let limits = CheckLimits::default();
        let mut checker = prepare(&program, &policy, &cancel, limits);
        let info = *checker.functions.values().next().unwrap();
        let span = info.declaration.name.span;
        let missing = program.locals().next().unwrap().id();
        let before = checker.budget_position();
        let result = checker.evaluate_body(|checker| {
            assert!(
                checker
                    .concretize(
                        RawTy::List(Box::new(RawTy::Parameter(missing))),
                        &BTreeMap::default(),
                        span
                    )
                    .is_none()
            );
        });
        assert_eq!(before.work, result.after.work);
        let journal = result.effects.unwrap();
        assert!(journal.observation_count() >= 2);
        let input = BodyReplayState {
            budget: BodyBudget {
                work: limits.max_work - 1,
                ..before
            },
            instances: checker.generic_instances.clone(),
        };
        assert!(
            journal
                .replay(&input, limits, &cancel)
                .unwrap()
                .is_none()
        );
        let mut cold = prepare(&program, &policy, &cancel, limits);
        cold.work = input.budget.work;
        let rejected = cold.evaluate_body(|checker| {
            checker.concretize(
                RawTy::List(Box::new(RawTy::Parameter(missing))),
                &BTreeMap::default(),
                span,
            );
        });
        assert!(rejected.after.exhausted);
        assert!(
            rejected
                .effects
                .unwrap()
                .replay(&input, limits, &cancel)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn diagnostics_near_the_cap_reject_changed_publication() {
        let mut sources = SourceSet::new();
        sources
            .add(
                "main.srx",
                "resource R(int); fn inspect() { let x=R(1); x; x; x; }",
            )
            .unwrap();
        let program = resolve(parse_sources(&sources).unwrap()).unwrap();
        let policy = CheckPolicy::default();
        let cancel = AnalysisCancellation::default();
        let limits = CheckLimits::default();
        let mut original = prepare(&program, &policy, &cancel, limits);
        let result = run(&mut original);
        assert_eq!(result.facts.diagnostics.len(), 2);
        let journal = result.effects.unwrap();
        for diagnostics in [
            crate::MAX_DIAGNOSTICS - 3,
            crate::MAX_DIAGNOSTICS - 2,
            crate::MAX_DIAGNOSTICS - 1,
        ] {
            let mut cold = prepare(&program, &policy, &cancel, limits);
            cold.prior_diagnostics = diagnostics;
            let input = BodyReplayState {
                budget: cold.budget_position(),
                instances: cold.generic_instances.clone(),
            };
            let result = run(&mut cold);
            let replay = journal.replay(&input, limits, &cancel).unwrap();
            if result.after.diagnostics < crate::MAX_DIAGNOSTICS {
                assert_eq!(replay.unwrap().budget, result.after);
            } else {
                assert!(replay.is_none());
            }
        }
    }

    #[test]
    fn limits_cancel_and_journal_retention_are_transactional() {
        let program = program();
        let policy = CheckPolicy::default();
        let cancel = AnalysisCancellation::default();
        let limits = CheckLimits::default();
        let mut checker = prepare(&program, &policy, &cancel, limits);
        let input = BodyReplayState {
            budget: checker.budget_position(),
            instances: checker.generic_instances.clone(),
        };
        let expected = run(&mut checker);
        let journal = expected.effects.unwrap();
        for category in 0..4 {
            let mut saturated = input.clone();
            match category {
                0 => saturated.budget.work = limits.max_work,
                1 => saturated.budget.metadata = limits.max_metadata_units,
                2 => saturated.budget.editor_metadata = limits.max_metadata_units,
                _ => saturated.budget.diagnostics = crate::MAX_DIAGNOSTICS,
            }
            let untouched = saturated.clone();
            assert!(
                journal
                    .replay(&saturated, limits, &cancel)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(saturated, untouched);
        }
        let mut bounded = prepare(&program, &policy, &cancel, limits);
        bounded.effect_retention.remaining = 1;
        let result = run(&mut bounded);
        assert!(result.effects.is_none());
        assert_eq!(result.after, expected.after);
        assert_eq!(
            result.facts.expressions,
            expected.facts.expressions
        );
        assert_eq!(result.facts.locals, expected.facts.locals);
        assert_eq!(result.facts.uses, expected.facts.uses);
        assert_eq!(
            result.facts.diagnostics,
            expected.facts.diagnostics
        );
        cancel.cancel();
        assert!(journal.replay(&input, limits, &cancel).is_err());
    }
}

use std::{cmp::Ordering, fmt, mem::size_of, sync::Arc};

use super::{CanonicalType, Eval, Evaluator, Value};
use crate::{checker::CanonicalItemIdentity, source::SourceDomainId, source::Span};

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::{
        checker::CheckPolicy, checker::CheckedProgram, checker::PrimitiveType, checker::check,
        evaluator::EvaluationEnvironment, evaluator::EvaluationLimits,
        evaluator::EvaluationSession, evaluator::PrimitiveValue, resolver::resolve,
        source::SourceSet, syntax::parse_sources,
    };

    fn checked(text: &str, policy: &CheckPolicy) -> CheckedProgram {
        let mut sources = SourceSet::new();
        sources.add("main.srx", text).unwrap();
        check(
            resolve(parse_sources(&sources).unwrap()).unwrap(),
            policy,
        )
        .unwrap()
    }

    fn memo_id(value: &Value) -> &MemoId {
        let Value::MemoizedFunction {
            id,
            ..
        } = value
        else {
            panic!("expected memoized reference");
        };
        id
    }

    #[test]
    fn aliases_share_instances_but_parameterized_constructions_and_operations_are_distinct() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn observe(_: i64) -> bool {
            CALLS.fetch_add(1, Ordering::Relaxed);
            true
        }
        let policy = CheckPolicy::new("memo-observation")
            .unwrap()
            .with_predicate("observe", PrimitiveType::Int)
            .unwrap();
        let environment = EvaluationEnvironment::new(&policy)
            .with_int_predicate("observe", observe)
            .unwrap();
        let program = checked(
            r"
        value I(int); value Probe(int) where observe(self); type Factory = fn() -> I;
        fn invoke(f: Factory) -> I { f() }
        fn create(n: I) -> fn() -> I {
            memoize(fn() -> I { let probe = Probe(1); n })
        }
        fn unused() -> I { unused() }
        outputs {
            a: Factory = create(I(1)); b: Factory = create(I(2));
            alias: Factory = memoize(a); dormant: Factory = memoize(unused);
            first: I = invoke(a); again: I = invoke(alias); second: I = invoke(b);
        }
    ",
            &policy,
        );
        let mut session = EvaluationSession::new(
            &program,
            &policy,
            &environment,
            EvaluationLimits::default(),
        )
        .unwrap();
        let a = memo_id(
            session
                .evaluate_root("a")
                .unwrap()
                .value()
                .unwrap(),
        )
        .clone();
        let b = memo_id(
            session
                .evaluate_root("b")
                .unwrap()
                .value()
                .unwrap(),
        )
        .clone();
        let alias = memo_id(
            session
                .evaluate_root("alias")
                .unwrap()
                .value()
                .unwrap(),
        )
        .clone();
        assert_eq!(a, alias);
        assert_ne!(a, b);
        session.evaluate_root("dormant").unwrap();
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
        for name in ["first", "again", "second"] {
            session.evaluate_root(name).unwrap();
        }
        assert_eq!(CALLS.load(Ordering::Relaxed), 2);
        assert!(matches!(
            session.evaluate_root("second").unwrap().value(),
            Some(Value::Nominal {
                value: PrimitiveValue::Int(2),
                ..
            })
        ));
        let mut other = EvaluationSession::new(
            &program,
            &policy,
            &environment,
            EvaluationLimits::default(),
        )
        .unwrap();
        assert_ne!(
            &a,
            memo_id(other.evaluate_root("a").unwrap().value().unwrap())
        );
    }

    #[test]
    fn memo_failures_are_retained_even_when_the_reference_was_loaded_by_the_failed_root() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn observe(_: i64) -> bool {
            CALLS.fetch_add(1, Ordering::Relaxed);
            true
        }
        let policy = CheckPolicy::new("memo-failure")
            .unwrap()
            .with_predicate("observe", PrimitiveType::Int)
            .unwrap();
        let environment = EvaluationEnvironment::new(&policy)
            .with_int_predicate("observe", observe)
            .unwrap();
        let program = checked(
            r"
        value I(int) where in [1]; value Probe(int) where observe(self); type Factory = fn() -> I;
        fn invoke(f: Factory) -> I { f() }
        fn bad() -> I { let probe = Probe(1); I(2) }
        outputs { lazy: Factory = memoize(bad); first: I = invoke(lazy); second: I = invoke(lazy); }
    ",
            &policy,
        );
        let mut session = EvaluationSession::new(
            &program,
            &policy,
            &environment,
            EvaluationLimits::default(),
        )
        .unwrap();
        assert!(
            session
                .evaluate_root("first")
                .unwrap()
                .value()
                .is_none()
        );
        assert!(
            session
                .evaluate_root("second")
                .unwrap()
                .diagnostics()
                .iter()
                .any(|error| error.message.contains("previously failed"))
        );
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cycles_report_the_named_factory_chain() {
        let policy = CheckPolicy::default();
        let environment = EvaluationEnvironment::new(&policy);
        let program = checked(
            r"
        value I(int); type Factory = fn() -> I;
        fn invoke(f: Factory) -> I { f() }
        fn left() -> I { invoke(b) } fn right() -> I { invoke(a) }
        outputs { a: Factory = memoize(left); b: Factory = memoize(right); selected: I = invoke(a); }
    ",
            &policy,
        );
        let mut session = EvaluationSession::new(
            &program,
            &policy,
            &environment,
            EvaluationLimits::default(),
        )
        .unwrap();
        let errors = session
            .evaluate_root("selected")
            .unwrap()
            .diagnostics();
        assert!(
            errors.iter().any(|error| error
                .message
                .contains("cycle in memoized computation")
                && error.message.contains("left")
                && error.message.contains("right")
                && error.message.contains(" -> ")),
            "{errors:?}"
        );
    }

    #[test]
    fn memoization_refuses_affine_results_and_claimful_computations() {
        let policy = CheckPolicy::default();
        let environment = EvaluationEnvironment::new(&policy);
        for source in [
            "resource R(int); outputs { selected: R = memoize(fn() -> R { R(1) })(); }",
            "resource R(int); value I(int); outputs { selected: I = memoize(fn() -> I { let claim = R(1); I(1) })(); }",
        ] {
            let program = checked(source, &policy);
            let mut session = EvaluationSession::new(
                &program,
                &policy,
                &environment,
                EvaluationLimits::default(),
            )
            .unwrap();
            assert!(
                session
                    .evaluate_root("selected")
                    .unwrap()
                    .value()
                    .is_none(),
                "{source}"
            );
        }
    }

    #[test]
    fn memoize_rejects_consumable_and_non_nullary_functions_statically() {
        for value in [
            "once fn() -> I { I(1) }",
            "fn(n: I) -> I { n }",
            "I(1)",
        ] {
            let mut sources = SourceSet::new();
            sources.add("main.srx", format!("value I(int); type Factory = fn() -> I; outputs {{ selected: Factory = memoize({value}); }}")).unwrap();
            let errors = check(
                resolve(parse_sources(&sources).unwrap()).unwrap(),
                &CheckPolicy::default(),
            )
            .unwrap_err();
            assert!(
                errors.iter().any(|error| error
                    .message
                    .contains("memoize requires a reusable function with no arguments")),
                "{errors:?}"
            );
        }
    }

    #[test]
    fn pure_memos_work_after_unrelated_claims_but_cached_claims_cannot_be_laundered() {
        let policy = CheckPolicy::default();
        let environment = EvaluationEnvironment::new(&policy);
        let program = checked(
            r"
        resource R(int); value I(int); type Factory = fn() -> I;
        fn invoke(f: Factory) -> I { f() }
        fn claim() -> I { let acquired = R(1); I(7) }
        fn pure_after_claim() -> I { let acquired = R(2); invoke(pure) }
        fn launder() -> I { let cached = claimful; invoke(impure) }
        outputs {
            pure: Factory = memoize(fn() -> I { I(1) });
            impure: Factory = memoize(fn() -> I { claimful });
            claimful: I = claim();
            selected: I = pure_after_claim();
            again: I = invoke(pure);
            rejected: I = launder();
            retry: I = invoke(impure);
        }
    ",
            &policy,
        );
        let mut session = EvaluationSession::new(
            &program,
            &policy,
            &environment,
            EvaluationLimits::default(),
        )
        .unwrap();
        let selected = session.evaluate_root("selected").unwrap();
        assert!(selected.value().is_some());
        assert_eq!(selected.claims().len(), 1);
        let again = session.evaluate_root("again").unwrap();
        assert!(again.value().is_some());
        assert_eq!(again.claims().len(), 0);
        assert!(
            session
                .evaluate_root("rejected")
                .unwrap()
                .diagnostics()
                .iter()
                .any(|error| error.message.contains("without resource claims"))
        );
        assert!(
            session
                .evaluate_root("retry")
                .unwrap()
                .diagnostics()
                .iter()
                .any(|error| error.message.contains("previously failed"))
        );
    }

    #[test]
    fn creating_lazy_instances_charges_the_expansion_budget() {
        let policy = CheckPolicy::default();
        let environment = EvaluationEnvironment::new(&policy);
        let program = checked(
            r"
        value I(int); fn unused() -> I { unused() }
        outputs { instances: [fn() -> I] = fold([I(1), I(2), I(3), I(4)], [],
            fn(acc: [fn() -> I], n: I) -> [fn() -> I] { acc ++ [memoize(unused)] }); }
    ",
            &policy,
        );
        let mut session = EvaluationSession::new(
            &program,
            &policy,
            &environment,
            EvaluationLimits {
                max_expansion_bytes: 1024,
                ..EvaluationLimits::default()
            },
        )
        .unwrap();
        assert!(
            session
                .evaluate_root("instances")
                .unwrap()
                .diagnostics()
                .iter()
                .any(|error| error.message.contains("expansion byte limit"))
        );
    }
}

/// An opaque identity within one evaluation operation. Copies retain identity;
/// distinct constructions and distinct operations never compare equal. This
/// token is not a persistent recipe identity or an Action digest.
#[derive(Clone)]
pub struct MemoId {
    operation: Arc<()>,
    index: usize,
}

impl PartialEq for MemoId {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && Arc::ptr_eq(&self.operation, &other.operation)
    }
}
impl Eq for MemoId {}
impl PartialOrd for MemoId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for MemoId {
    fn cmp(&self, other: &Self) -> Ordering {
        (Arc::as_ptr(&self.operation), self.index)
            .cmp(&(Arc::as_ptr(&other.operation), other.index))
    }
}
impl fmt::Debug for MemoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MemoId")
            .field(&self.index)
            .finish()
    }
}

#[derive(Default)]
pub(in crate::evaluator) struct MemoArena {
    operation: Arc<()>,
    entries: Vec<Entry>,
    pub(super) published: std::collections::BTreeMap<
        (
            crate::resolver::PublicationId,
            crate::resolver::ItemId,
        ),
        MemoId,
    >,
    active: Vec<usize>,
}

struct Entry {
    owner: SourceDomainId,
    origin: Span,
    label: Arc<CanonicalItemIdentity>,
    state: State,
}

enum State {
    Pending(Value),
    Evaluating,
    Ready(Value),
    Failed,
}

impl MemoArena {
    pub(in crate::evaluator) fn owner(&self, id: &MemoId) -> Option<SourceDomainId> {
        if !Arc::ptr_eq(&id.operation, &self.operation) {
            return None;
        }
        self.entries
            .get(id.index)
            .map(|entry| entry.owner)
    }

    pub(in crate::evaluator) fn origin(
        &self,
        id: &MemoId,
    ) -> Option<(Span, &CanonicalItemIdentity)> {
        if !Arc::ptr_eq(&id.operation, &self.operation) {
            return None;
        }
        self.entries
            .get(id.index)
            .map(|entry| (entry.origin, entry.label.as_ref()))
    }
}

impl Evaluator<'_> {
    pub(super) fn memoize(&mut self, callable: Value, span: Span) -> Eval<Value> {
        if matches!(callable, Value::MemoizedFunction { .. }) {
            return Ok(callable);
        }
        let ty = callable.canonical_type();
        if !matches!(ty.as_ref(), CanonicalType::Function { parameters, once: false, .. } if parameters.is_empty())
            || callable.affine()
        {
            return self.fail(
                span,
                "memoize requires a reusable function with no arguments",
            );
        }
        self.expand(2 * size_of::<Entry>() + size_of::<MemoId>(), span)?;
        let (origin, label) = match &callable {
            Value::Function {
                item,
                ..
            } => (
                span,
                self.index
                    .identity(*item)
                    .unwrap_or_else(|| self.root.clone()),
            ),
            Value::Closure {
                body,
                ..
            } => (body.span, self.root.clone()),
            _ => (span, self.root.clone()),
        };
        let id = MemoId {
            operation: self.memos.operation.clone(),
            index: self.memos.entries.len(),
        };
        self.memos.entries.push(Entry {
            owner: self.project_context,
            origin,
            label,
            state: State::Pending(callable),
        });
        Ok(Value::MemoizedFunction {
            ty,
            id,
        })
    }

    pub(in crate::evaluator) fn force_memo(&mut self, id: &MemoId, span: Span) -> Eval<Value> {
        self.tick(span)?;
        if !Arc::ptr_eq(&id.operation, &self.memos.operation)
            || id.index >= self.memos.entries.len()
        {
            return self.fail(
                span,
                "memoized reference belongs to another evaluation operation",
            );
        }
        let state = std::mem::replace(
            &mut self.memos.entries[id.index].state,
            State::Evaluating,
        );
        match state {
            State::Ready(value) => {
                let result = Self::copy_value_ref(self, &value, span, 0);
                self.memos.entries[id.index].state = State::Ready(value);
                result
            }
            State::Failed => {
                self.memos.entries[id.index].state = State::Failed;
                self.fail(span, "memoized computation previously failed")
            }
            State::Evaluating => {
                let mut path = String::new();
                for offset in 0..=self.memos.active.len() {
                    use std::fmt::Write as _;
                    let index = self
                        .memos
                        .active
                        .get(offset)
                        .copied()
                        .unwrap_or(id.index);
                    let bytes = self.memos.entries[index]
                        .label
                        .path()
                        .iter()
                        .map(String::len)
                        .sum::<usize>()
                        .saturating_add(
                            self.memos.entries[index]
                                .label
                                .path()
                                .len()
                                .saturating_mul(2),
                        )
                        .saturating_add(64);
                    self.tick(span)?;
                    self.expand(bytes.saturating_mul(2), span)?;
                    let entry = &self.memos.entries[index];
                    if !path.is_empty() {
                        path.push_str(" -> ");
                    }
                    write!(
                        path,
                        "{}:{}@{}:{}",
                        entry.label.domain().as_u32(),
                        entry.label.path().join("::"),
                        entry.origin.source_id().index(),
                        entry.origin.start()
                    )
                    .expect("String write");
                }
                self.fail(
                    span,
                    format!("cycle in memoized computation: {path}"),
                )
            }
            State::Pending(callable) => {
                let result = self.compute_memo(id.index, callable, span);
                if result.is_err() {
                    self.memos.entries[id.index].state = State::Failed;
                }
                result
            }
        }
    }

    fn compute_memo(&mut self, index: usize, callable: Value, span: Span) -> Eval<Value> {
        // Effects include reads of claimful cached outputs, preventing a memo
        // from laundering a root-scoped claim into a shareable plain payload.
        let claim_effects = self.claim_effects;
        self.expand(size_of::<usize>(), span)?;
        self.memos.active.push(index);
        let previous = std::mem::replace(
            &mut self.project_context,
            self.memos.entries[index].owner,
        );
        let result = self.invoke_value(callable, Vec::new(), span);
        self.project_context = previous;
        self.memos.active.pop();
        let value = result?;
        if value.affine() || self.claim_effects != claim_effects {
            return self.fail(
                span,
                "memoized computation must return a reusable value without resource claims",
            );
        }
        let copy = Self::copy_value_ref(self, &value, span, 0)?;
        self.memos.entries[index].state = State::Ready(value);
        Ok(copy)
    }
}

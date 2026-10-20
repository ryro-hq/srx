#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        checker::CheckPolicy, checker::PrimitiveType, checker::check,
        evaluator::EvaluationEnvironment, evaluator::EvaluationLimits, resolver::resolve,
        source::SourceSet, syntax::parse_sources,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    fn std(sources: &mut SourceSet) {
        sources
            .add_standard_library(
                "std/recipe.srx",
                "mod std::recipe { pub struct RecipeRef<R> { factory: fn() -> R; } }",
            )
            .unwrap();
    }
    fn checked(text: &str, policy: &CheckPolicy) -> CheckedProgram {
        let mut sources = SourceSet::new();
        std(&mut sources);
        sources.add("main.srx", text).unwrap();
        check(
            resolve(parse_sources(&sources).unwrap()).unwrap(),
            policy,
        )
        .unwrap()
    }
    fn reference(value: Value) -> crate::evaluator::MemoId {
        let Value::Struct {
            fields,
            ..
        } = value
        else {
            panic!("expected ref")
        };
        let (
            _,
            Value::MemoizedFunction {
                id,
                ..
            },
        ) = fields.into_iter().next().unwrap()
        else {
            panic!("expected memo")
        };
        id
    }
    #[test]
    fn inventory_without_outputs_is_lazy_and_aliases_force_once() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn observe(_: i64) -> bool {
            CALLS.fetch_add(1, Ordering::SeqCst);
            true
        }
        let policy = CheckPolicy::new("public-lazy")
            .unwrap()
            .with_predicate("observe", PrimitiveType::Int)
            .unwrap();
        let environment = EvaluationEnvironment::new(&policy)
            .with_int_predicate("observe", observe)
            .unwrap();
        let program = checked(
            r"
        value I(int); value Probe(int) where observe(self);
        mod collection::one { pub fn make()->I {let probe=Probe(1); I(7)} }
        mod collection::alias { pub use project::collection::one::make; }
        mod collection::dormant { pub fn make()->I { make() } }
        pub publish(collection, make): I;
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
        assert_eq!(session.root_names().len(), 0);
        assert_eq!(
            session
                .published_members()
                .map(PublishedRoot::name)
                .collect::<Vec<_>>(),
            ["alias", "dormant", "one"]
        );
        let one = reference(session.select_published("one").unwrap());
        assert_eq!(
            one,
            reference(session.select_published("alias").unwrap())
        );
        session.select_published("dormant").unwrap();
        assert_eq!(CALLS.load(Ordering::SeqCst), 0);
        assert!(
            session
                .force_published("one")
                .unwrap()
                .value()
                .is_some()
        );
        let aliases = session
            .force_published("alias")
            .unwrap()
            .aliases()
            .collect::<Vec<_>>();
        assert_eq!(aliases, ["alias", "one"]);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn imported_members_are_visible_only_when_reexported_and_keep_canonical_identity() {
        let policy = CheckPolicy::default();
        let environment = EvaluationEnvironment::new(&policy);
        for exported in [false, true] {
            let mut sources = SourceSet::new();
            std(&mut sources);
            sources
                .add(
                    "main.srx",
                    if exported {
                        "inputs {lib=\"path:lib\";} pub use lib::one;"
                    } else {
                        "inputs {lib=\"path:lib\";}"
                    },
                )
                .unwrap();
            let domain = sources
                .create_project_domain(SourceDomainId::project(), "lib")
                .unwrap();
            sources.add_to_project_domain(domain,"lib/main.srx","pub value I(int); mod factories::one {pub fn make()->I{I(7)}} pub publish(factories,make):I;").unwrap();
            let program = check(
                resolve(parse_sources(&sources).unwrap()).unwrap(),
                &policy,
            )
            .unwrap();
            let mut session = EvaluationSession::new(
                &program,
                &policy,
                &environment,
                EvaluationLimits::default(),
            )
            .unwrap();
            assert_eq!(
                session.published_members().len(),
                usize::from(exported)
            );
            if exported {
                let identity = session
                    .published_members()
                    .next()
                    .unwrap()
                    .identity()
                    .clone();
                assert_eq!(identity.domain(), domain);
                assert_eq!(
                    reference(session.select_published("one").unwrap()),
                    reference(
                        session
                            .select_canonical_member(&identity)
                            .unwrap()
                    )
                );
                assert!(
                    session
                        .force_published("one")
                        .unwrap()
                        .value()
                        .is_some()
                );
            }
        }
    }
    #[test]
    fn obsolete_output_publication_is_rejected_by_parser() {
        let mut sources = SourceSet::new();
        sources
            .add(
                "main.srx",
                "outputs {publish(x,recipe) packages:T = x;}",
            )
            .unwrap();
        assert!(parse_sources(&sources).is_err());
    }

    #[test]
    fn separate_publications_do_not_merge_the_same_factory() {
        let policy = CheckPolicy::default();
        let environment = EvaluationEnvironment::new(&policy);
        let program = checked(
            "value I(int); pub fn make()->I{I(1)}\n\
         mod left::alpha {pub use project::make;}\n\
         mod right::beta {pub use project::make;}\n\
         pub publish(left,make):I; pub publish(right,make):I;",
            &policy,
        );
        let mut session = EvaluationSession::new(
            &program,
            &policy,
            &environment,
            EvaluationLimits::default(),
        )
        .unwrap();
        assert_ne!(
            reference(session.select_published("alpha").unwrap()),
            reference(session.select_published("beta").unwrap())
        );
        assert_ne!(
            session
                .published_members()
                .next()
                .unwrap()
                .publication(),
            session
                .published_members()
                .last()
                .unwrap()
                .publication()
        );
    }

    #[test]
    fn declaration_result_and_factory_signature_are_checked_without_selection() {
        let policy = CheckPolicy::default();
        for declaration in [
            "pub fn make()->Other{Other(1)}",
            "pub fn make(x:I)->I{x}",
        ] {
            let mut sources = SourceSet::new();
            std(&mut sources);
            sources.add("main.srx", format!("value I(int); value Other(int); mod factories::one {{{declaration}}} pub publish(factories,make):I;")).unwrap();
            let resolved = resolve(parse_sources(&sources).unwrap()).unwrap();
            assert!(check(resolved, &policy).is_err());
        }
    }
}
use super::{
    EvaluationQueryError, EvaluationSession, EvaluationSetupError, ProgramIndex, SetupBudget,
};
use crate::evaluator::runtime::Evaluator;
use crate::evaluator::{CanonicalType, RealizedRoot, Value};
use crate::{
    checker::CanonicalItemIdentity, checker::CheckedProgram, resolver::ItemId,
    resolver::PublicationId, source::SourceDomainId, source::Span,
};
use std::{collections::BTreeMap, mem::size_of, sync::Arc};

#[derive(Clone, Debug)]
pub struct PublishedRoot {
    name: String,
    identity: Arc<CanonicalItemIdentity>,
    result: Arc<CanonicalType>,
    item: ItemId,
    span: Span,
    publication: PublicationId,
}
impl PublishedRoot {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn identity(&self) -> &CanonicalItemIdentity {
        &self.identity
    }
    pub const fn result_type(&self) -> &Arc<CanonicalType> {
        &self.result
    }
    pub const fn span(&self) -> Span {
        self.span
    }
    pub const fn publication(&self) -> PublicationId {
        self.publication
    }
}

/// A public global whose checked type is the authenticated `RecipeRef<R>`.
/// Its initializer is evaluated only when selected, using the session's shared
/// global cache. Enumerating bindings does not invoke their factories.
#[derive(Clone, Debug)]
pub struct ReferenceBinding {
    name: String,
    identity: Arc<CanonicalItemIdentity>,
    result: Arc<CanonicalType>,
    item: ItemId,
    span: Span,
}

impl ReferenceBinding {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub const fn result_type(&self) -> &Arc<CanonicalType> {
        &self.result
    }
}

pub(super) fn binding_inventory(
    program: &CheckedProgram,
    index: &ProgramIndex<'_>,
    budget: &mut SetupBudget,
) -> Result<BTreeMap<String, ReferenceBinding>, EvaluationSetupError> {
    let mut bindings = BTreeMap::new();
    for (name, item) in program
        .resolved()
        .visible_bindings(SourceDomainId::project())
    {
        budget.charge(0)?;
        let expression = index
            .output_values
            .get(&item)
            .ok_or(EvaluationSetupError::MissingRootIdentity)?;
        let reference = program
            .expression(expression.span)
            .and_then(|expression| index.canonical_type(expression.ty()))
            .ok_or(EvaluationSetupError::MissingRootIdentity)?;
        let CanonicalType::Specialization {
            template,
            arguments,
        } = reference.as_ref()
        else {
            continue;
        };
        if template.domain() != SourceDomainId::standard_library()
            || template.path() != ["std", "recipe", "RecipeRef"]
        {
            continue;
        }
        let [result] = arguments.as_slice() else {
            return Err(EvaluationSetupError::MissingRootIdentity);
        };
        budget.charge(2 * name.len() + size_of::<(String, ReferenceBinding)>())?;
        bindings.insert(
            name.into(),
            ReferenceBinding {
                name: name.into(),
                identity: index
                    .identity(item)
                    .ok_or(EvaluationSetupError::MissingRootIdentity)?,
                result: result.clone(),
                item,
                span: expression.span,
            },
        );
    }
    Ok(bindings)
}

pub(super) fn inventory(
    program: &CheckedProgram,
    index: &ProgramIndex<'_>,
    budget: &mut SetupBudget,
) -> Result<BTreeMap<String, PublishedRoot>, EvaluationSetupError> {
    let mut members = BTreeMap::new();
    for (name, item) in program
        .resolved()
        .visible_published_members(SourceDomainId::project())
    {
        budget.charge(2 * name.len() + size_of::<(String, PublishedRoot)>())?;
        let reference = program
            .published_type(item)
            .and_then(|ty| index.canonical_type(ty))
            .ok_or(EvaluationSetupError::MissingRootIdentity)?;
        let CanonicalType::Specialization {
            arguments,
            ..
        } = reference.as_ref()
        else {
            return Err(EvaluationSetupError::MissingRootIdentity);
        };
        let [result] = arguments.as_slice() else {
            return Err(EvaluationSetupError::MissingRootIdentity);
        };
        let resolved = program
            .resolved()
            .item(item)
            .ok_or(EvaluationSetupError::MissingRootIdentity)?;
        members.insert(
            name.into(),
            PublishedRoot {
                name: name.into(),
                identity: index
                    .identity(item)
                    .ok_or(EvaluationSetupError::MissingRootIdentity)?,
                result: result.clone(),
                item,
                span: resolved.span(),
                publication: program
                    .resolved()
                    .published_member(item)
                    .ok_or(EvaluationSetupError::MissingRootIdentity)?
                    .publication,
            },
        );
    }
    Ok(members)
}
impl EvaluationSession<'_> {
    pub fn reference_bindings(&self) -> impl ExactSizeIterator<Item = &ReferenceBinding> {
        self.reference_bindings.values()
    }

    /// Evaluate a public reference initializer while preserving global and memo
    /// identity across named lookups, aliases and ordinary output evaluation.
    pub fn select_reference_binding(&mut self, name: &str) -> Result<Value, EvaluationQueryError> {
        self.reserve_metadata_work(1)?;
        let binding = self
            .reference_bindings
            .get(name)
            .ok_or(EvaluationQueryError::UnknownRoot)?;
        let (item, span, identity) = (
            binding.item,
            binding.span,
            binding.identity.clone(),
        );
        self.select_reference_value(item, span, identity, false)
    }

    pub fn force_reference_binding(
        &mut self,
        name: &str,
    ) -> Result<&RealizedRoot, EvaluationQueryError> {
        let value = self.select_reference_binding(name)?;
        let binding = self
            .reference_bindings
            .get(name)
            .ok_or(EvaluationQueryError::UnknownRoot)?;
        let (result, identity, span) = (
            binding.result.clone(),
            binding.identity.clone(),
            binding.span,
        );
        self.force_reference_value(value, result, name, identity, span)
    }

    /// Enumerate only root-domain public members, without evaluating any factory.
    pub fn published_members(&self) -> impl ExactSizeIterator<Item = &PublishedRoot> {
        self.published.values()
    }

    /// Return the authenticated lazy reference. No factory is forced by this query.
    pub fn select_published(&mut self, name: &str) -> Result<Value, EvaluationQueryError> {
        self.reserve_metadata_work(1)?;
        let member = self
            .published
            .get(name)
            .ok_or(EvaluationQueryError::UnknownRoot)?;
        let (item, span, identity) = (member.item, member.span, member.identity.clone());
        self.select_reference_value(item, span, identity, true)
    }

    fn select_reference_value(
        &mut self,
        item: ItemId,
        span: Span,
        identity: Arc<CanonicalItemIdentity>,
        published: bool,
    ) -> Result<Value, EvaluationQueryError> {
        let mut evaluator = Evaluator::new(
            self.program,
            self.policy,
            self.environment,
            &self.index,
            self.remaining_limits(),
            span,
            identity,
        );
        evaluator.inherit_outputs(std::mem::take(&mut self.shared_outputs));
        evaluator.memos = std::mem::take(&mut self.memos);
        let value = if published {
            evaluator.published_value(item, span)
        } else {
            evaluator.output_value(item, span)
        };
        let error = evaluator.operation_error;
        self.shared_outputs = evaluator.take_shareable_outputs();
        self.memos = std::mem::take(&mut evaluator.memos);
        let steps = evaluator.steps;
        let expansion = evaluator.expansion;
        let diagnostics = std::mem::take(&mut evaluator.diagnostics);
        self.diagnostics_used = self
            .diagnostics_used
            .saturating_add(diagnostics.len());
        drop(evaluator);
        if let Some(error) = error {
            self.failure = Some(error);
            return Err(error.into());
        }
        self.reserve_metadata_work(steps)?;
        self.reserve_metadata_bytes(expansion)?;
        if !diagnostics.is_empty() {
            return Err(EvaluationQueryError::Evaluation(diagnostics));
        }
        value.map_err(|_| EvaluationQueryError::InvalidSelection)
    }

    /// Canonical lookup is constrained to the same visible root inventory.
    pub fn select_canonical_member(
        &mut self,
        identity: &CanonicalItemIdentity,
    ) -> Result<Value, EvaluationQueryError> {
        self.reserve_metadata_work(self.published.len())?;
        let member = self
            .published
            .values()
            .find(|member| member.identity() == identity)
            .ok_or(EvaluationQueryError::UnknownRoot)?;
        let size = member.name.len();
        self.reserve_metadata_bytes(size)?;
        let name = self
            .published
            .values()
            .find(|member| member.identity() == identity)
            .ok_or(EvaluationQueryError::UnknownRoot)?
            .name
            .clone();
        self.select_published(&name)
    }

    /// Force exactly one selected public member, preserving aliases and its own origin.
    pub fn force_published(&mut self, name: &str) -> Result<&RealizedRoot, EvaluationQueryError> {
        let value = self.select_published(name)?;
        let member = self
            .published
            .get(name)
            .ok_or(EvaluationQueryError::UnknownRoot)?;
        let (result, identity, span) = (
            member.result.clone(),
            member.identity.clone(),
            member.span,
        );
        self.force_reference_value(value, result, name, identity, span)
    }

    fn force_reference_value(
        &mut self,
        value: Value,
        result: Arc<CanonicalType>,
        name: &str,
        identity: Arc<CanonicalItemIdentity>,
        span: Span,
    ) -> Result<&RealizedRoot, EvaluationQueryError> {
        let Value::Struct {
            fields,
            ..
        } = value
        else {
            return Err(EvaluationQueryError::InvalidSelection);
        };
        let mut fields = fields.into_iter();
        let Some((
            _,
            Value::MemoizedFunction {
                id,
                ..
            },
        )) = fields.next()
        else {
            return Err(EvaluationQueryError::InvalidSelection);
        };
        if let Some(&existing) = self.selected_memos.get(&id) {
            if !self.selected[existing]
                .aliases
                .iter()
                .any(|alias| alias == name)
            {
                self.reserve_metadata_bytes(size_of::<String>() + name.len())?;
                self.selected[existing].aliases.push(name.into());
                self.selected[existing].aliases.sort();
            }
            return Ok(&self.selected[existing]);
        }
        self.force_selected(&id, result, name, identity, span, true)
    }
}

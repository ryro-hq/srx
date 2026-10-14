use std::collections::BTreeMap;

use crate::{
    diagnostic::Diagnostic, resolver::ItemId, resolver::LocalId, resolver::ResolvedProgram,
    source::Span,
};

use super::{
    CheckPolicy, Checker, MAX_ALIAS_DEPTH, MAX_CHECK_WORK, MAX_GENERIC_INSTANCES,
    MAX_METADATA_UNITS, MAX_SPECIALIZATION_DEPTH, PolicyFingerprint, span_key,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckLimits {
    pub max_work: usize,
    pub max_alias_depth: usize,
    pub max_specialization_depth: usize,
    pub max_generic_instances: usize,
    pub max_metadata_units: usize,
}

impl Default for CheckLimits {
    fn default() -> Self {
        Self {
            max_work: MAX_CHECK_WORK,
            max_alias_depth: MAX_ALIAS_DEPTH,
            max_specialization_depth: MAX_SPECIALIZATION_DEPTH,
            max_generic_instances: MAX_GENERIC_INSTANCES,
            max_metadata_units: MAX_METADATA_UNITS,
        }
    }
}

/// A checked type. Aliases never appear; parameters occur only in generic defaults.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ty {
    Unit,
    Int,
    Str,
    Parameter(LocalId),
    Nominal(ItemId),
    Specialization {
        template: ItemId,
        arguments: Vec<Ty>,
    },
    List(Box<Ty>),
    Function {
        parameters: Vec<Ty>,
        result: Box<Ty>,
        once: bool,
    },
    Error,
}

impl Ty {
    /// Project nominal identity without changing checked arguments or authority.
    pub(crate) const fn nominal_head(&self) -> Option<ItemId> {
        match self {
            Self::Nominal(item) => Some(*item),
            Self::Specialization {
                template,
                ..
            } => Some(*template),
            _ => None,
        }
    }

    pub(super) fn compatible(&self, other: &Self) -> bool {
        self == other || matches!(self, Self::Error) || matches!(other, Self::Error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Elaboration {
    PackageSelection {
        factory: ItemId,
    },
    ModuleExports {
        key: ItemId,
        function: Ty,
    },
    VariantConstructor {
        index: u32,
    },
    FunctionSpecialization {
        substitutions: BTreeMap<LocalId, Ty>,
    },
    ContextualVariant {
        enumeration: ItemId,
        index: u32,
    },
    ValueLiteral(ItemId),
    Erasure {
        source: Ty,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedExpression {
    pub(super) span: Span,
    pub(super) ty: Ty,
    pub(super) elaboration: Option<Elaboration>,
    pub(super) expected: Option<Ty>,
    pub(super) status: TypeStatus,
}

/// Confidence in an editor fact, independent of the contextual expected type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeStatus {
    Known,
    Unknown,
    Invalid,
}

impl Ty {
    pub fn is_known(&self) -> bool {
        match self {
            Self::Error => false,
            Self::List(inner) => inner.is_known(),
            Self::Specialization {
                arguments,
                ..
            } => arguments.iter().all(Self::is_known),
            Self::Function {
                parameters,
                result,
                ..
            } => parameters.iter().all(Self::is_known) && result.is_known(),
            _ => true,
        }
    }
}

/// Snapshot-local binding facts. No evaluation or resource claims are performed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedLocal {
    pub id: LocalId,
    pub declaration: Span,
    pub ty: Ty,
    pub affine: bool,
    pub annotated: bool,
    pub status: TypeStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnershipUseKind {
    Consume,
    Capture,
    Reuse,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnershipUse {
    pub local: LocalId,
    pub span: Span,
    pub kind: OwnershipUseKind,
    pub affine: bool,
    pub status: OwnershipUseStatus,
    pub previous_move: Option<Span>,
    pub conditional: bool,
    /// Closure expression for capture events; the reference span remains exact.
    pub closure: Option<Span>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnershipUseStatus {
    Valid,
    Invalid,
    Unknown,
}

impl OwnershipUse {
    pub const fn is_valid(&self) -> bool {
        matches!(self.status, OwnershipUseStatus::Valid)
    }
    /// A recovered syntax fragment prevents a precise availability conclusion.
    pub const fn is_uncertain(&self) -> bool {
        matches!(self.status, OwnershipUseStatus::Unknown)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParameterHint {
    pub argument: Span,
    pub parameter: Span,
    pub name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct EditorFacts {
    pub locals: BTreeMap<LocalId, CheckedLocal>,
    pub uses: Vec<OwnershipUse>,
    pub patterns: Vec<CheckedPattern>,
    pub shapes: BTreeMap<ItemId, super::NominalShape>,
    pub outputs: BTreeMap<ItemId, Ty>,
    pub fields: Vec<(Span, Span, Ty)>,
    pub units: usize,
    pub arguments: Vec<ParameterHint>,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedPattern {
    pub(super) span: Span,
    pub(super) enumeration: ItemId,
    pub(super) index: u32,
}

impl CheckedPattern {
    pub const fn span(self) -> Span {
        self.span
    }

    pub const fn enumeration(self) -> ItemId {
        self.enumeration
    }

    pub const fn index(self) -> u32 {
        self.index
    }
}

impl CheckedExpression {
    pub const fn type_status(&self) -> TypeStatus {
        self.status
    }
    pub fn expected_type(&self) -> Option<&Ty> {
        self.expected.as_ref()
    }
    pub const fn span(&self) -> Span {
        self.span
    }

    pub const fn ty(&self) -> &Ty {
        &self.ty
    }

    pub const fn elaboration(&self) -> Option<&Elaboration> {
        self.elaboration.as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyMismatch {
    pub checked: PolicyFingerprint,
    pub supplied: PolicyFingerprint,
}

/// Successful checking output. Its constructor is private to this crate.
#[derive(Clone, Debug)]
pub struct CheckedProgram {
    pub(super) published_types: BTreeMap<ItemId, Ty>,
    pub(super) resolved: ResolvedProgram,
    pub(super) policy: CheckPolicy,
    pub(super) policy_identity: String,
    pub(super) policy_fingerprint: PolicyFingerprint,
    pub(super) expressions: Vec<CheckedExpression>,
    pub(super) patterns: Vec<CheckedPattern>,
    pub(super) expression_index: BTreeMap<(u32, u32, u32), usize>,
    pub(super) pattern_index: BTreeMap<(u32, u32, u32), usize>,
}

impl CheckedProgram {
    pub fn published_type(&self, item: ItemId) -> Option<&Ty> {
        self.resolved.published_member(item)?;
        self.published_types.get(&item)
    }
    pub const fn resolved(&self) -> &ResolvedProgram {
        &self.resolved
    }

    pub fn policy_identity(&self) -> &str {
        &self.policy_identity
    }

    pub const fn policy_fingerprint(&self) -> PolicyFingerprint {
        self.policy_fingerprint
    }

    pub fn expressions(&self) -> impl ExactSizeIterator<Item = &CheckedExpression> {
        self.expressions.iter()
    }

    pub fn patterns(&self) -> impl ExactSizeIterator<Item = CheckedPattern> + '_ {
        self.patterns.iter().copied()
    }

    pub fn require_policy(&self, policy: &CheckPolicy) -> Result<(), PolicyMismatch> {
        if policy == &self.policy {
            Ok(())
        } else {
            let supplied = policy.fingerprint();
            Err(PolicyMismatch {
                checked: self.policy_fingerprint,
                supplied,
            })
        }
    }

    pub(crate) fn expression(&self, span: Span) -> Option<&CheckedExpression> {
        self.expression_index
            .get(&span_key(span))
            .map(|&index| &self.expressions[index])
    }

    pub(crate) fn pattern(&self, span: Span) -> Option<CheckedPattern> {
        self.pattern_index
            .get(&span_key(span))
            .map(|&index| self.patterns[index])
    }
}

pub fn check(
    resolved: ResolvedProgram,
    policy: &CheckPolicy,
) -> Result<CheckedProgram, Vec<Diagnostic>> {
    check_with_limits(resolved, policy, CheckLimits::default())
}

pub fn check_with_limits(
    resolved: ResolvedProgram,
    policy: &CheckPolicy,
    limits: CheckLimits,
) -> Result<CheckedProgram, Vec<Diagnostic>> {
    let mut checker = Checker::new(&resolved, policy, limits);
    checker.run();
    checker.diagnostics.sort_by_key(|diagnostic| {
        (
            diagnostic.span.source_id(),
            diagnostic.span.start(),
            diagnostic.message.clone(),
        )
    });
    if checker.diagnostics.is_empty() {
        let expressions = std::mem::take(&mut checker.expressions);
        let patterns = std::mem::take(&mut checker.patterns);
        let expression_index = expressions
            .iter()
            .enumerate()
            .map(|(index, expression)| (span_key(expression.span), index))
            .collect();
        let pattern_index = patterns
            .iter()
            .enumerate()
            .map(|(index, pattern)| (span_key(pattern.span), index))
            .collect();
        let published_types = std::mem::take(&mut checker.published_types);
        Ok(CheckedProgram {
            published_types,
            resolved,
            policy: policy.clone(),
            policy_identity: policy.identity.clone(),
            policy_fingerprint: policy.fingerprint(),
            expressions,
            patterns,
            expression_index,
            pattern_index,
        })
    } else {
        Err(std::mem::take(&mut checker.diagnostics))
    }
}

use std::sync::Arc;

use crate::{checker::CanonicalItemIdentity, diagnostic::Diagnostic, source::Span};

pub const MAX_EVALUATION_STEPS: usize = 5_000_000;
pub const MAX_EVALUATION_TOTAL_STEPS: usize = 5_000_000;
pub const MAX_EVALUATION_DEPTH: usize = 128;
pub const MAX_EVALUATION_EXPANSION: usize = 64 * 1024 * 1024;
pub const MAX_EVALUATION_RETAINED_EXPANSION: usize = 64 * 1024 * 1024;
pub const MAX_EVALUATION_SETUP_STEPS: usize = 4_000_000;
pub const MAX_EVALUATION_SETUP_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationLimit {
    SetupSteps,
    SetupBytes,
    TotalSteps,
    StepsPerRoot,
    Depth,
    ExpansionBytes,
    RetainedExpansionBytes,
    Diagnostics,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvaluationLimits {
    pub max_setup_steps: usize,
    pub max_setup_bytes: usize,
    pub max_total_steps: usize,
    pub max_steps_per_root: usize,
    pub max_depth: usize,
    pub max_expansion_bytes: usize,
    pub max_retained_expansion_bytes: usize,
    pub max_diagnostics: usize,
}

impl Default for EvaluationLimits {
    fn default() -> Self {
        Self {
            max_setup_steps: MAX_EVALUATION_SETUP_STEPS,
            max_setup_bytes: MAX_EVALUATION_SETUP_BYTES,
            max_total_steps: MAX_EVALUATION_TOTAL_STEPS,
            max_steps_per_root: MAX_EVALUATION_STEPS,
            max_depth: MAX_EVALUATION_DEPTH,
            max_expansion_bytes: MAX_EVALUATION_EXPANSION,
            max_retained_expansion_bytes: MAX_EVALUATION_RETAINED_EXPANSION,
            max_diagnostics: crate::MAX_DIAGNOSTICS,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CanonicalType {
    Unit,
    Int,
    Str,
    Nominal(Arc<CanonicalItemIdentity>),
    Specialization {
        template: Arc<CanonicalItemIdentity>,
        arguments: Vec<Arc<CanonicalType>>,
    },
    List(Arc<CanonicalType>),
    Function {
        parameters: Vec<Arc<CanonicalType>>,
        result: Arc<CanonicalType>,
        once: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrimitiveValue {
    Int(i64),
    Str(String),
}

/// An evaluated value. It deliberately does not implement `Clone`: evaluator
/// copies are explicit and reject resource-bearing values.
#[derive(Debug, PartialEq, Eq)]
pub enum Value {
    MemoizedFunction {
        ty: Arc<CanonicalType>,
        id: super::MemoId,
    },
    VariantConstructor {
        ty: Arc<CanonicalType>,
        index: u32,
    },
    Function {
        item: crate::resolver::ItemId,
        ty: Arc<CanonicalType>,
        substitutions: std::collections::BTreeMap<crate::resolver::LocalId, crate::checker::Ty>,
    },
    Closure {
        ty: Arc<CanonicalType>,
        once: bool,
        owner: crate::source::SourceDomainId,
        body: Arc<crate::syntax::Block>,
        parameters: Vec<crate::resolver::LocalId>,
        captures: Vec<(crate::resolver::LocalId, Value)>,
        substitutions: std::collections::BTreeMap<crate::resolver::LocalId, crate::checker::Ty>,
    },
    Unit,
    Int(i64),
    Str(String),
    Nominal {
        ty: Arc<CanonicalType>,
        value: PrimitiveValue,
        resource: bool,
    },
    List {
        ty: Arc<CanonicalType>,
        items: Vec<Value>,
    },
    Struct {
        ty: Arc<CanonicalType>,
        fields: Vec<(String, Value)>,
        owner: Option<crate::source::SourceDomainId>,
    },
    Variant {
        ty: Arc<CanonicalType>,
        index: u32,
        payload: Vec<Value>,
    },
}

impl Value {
    pub fn canonical_type(&self) -> Arc<CanonicalType> {
        match self {
            Self::Unit => Arc::new(CanonicalType::Unit),
            Self::Int(_) => Arc::new(CanonicalType::Int),
            Self::Str(_) => Arc::new(CanonicalType::Str),
            Self::Nominal {
                ty,
                ..
            }
            | Self::Struct {
                ty,
                ..
            }
            | Self::Variant {
                ty,
                ..
            }
            | Self::List {
                ty,
                ..
            }
            | Self::Function {
                ty,
                ..
            }
            | Self::MemoizedFunction {
                ty,
                ..
            }
            | Self::VariantConstructor {
                ty,
                ..
            }
            | Self::Closure {
                ty,
                ..
            } => ty.clone(),
        }
    }

    pub(super) fn affine(&self) -> bool {
        match self {
            Self::Nominal {
                resource,
                ..
            } => *resource,
            Self::List {
                items,
                ..
            } => items.iter().any(Self::affine),
            Self::Struct {
                fields,
                ..
            } => fields.iter().any(|(_, value)| value.affine()),
            Self::Variant {
                payload,
                ..
            } => payload.iter().any(Self::affine),
            Self::Closure {
                once,
                captures,
                ..
            } => *once || captures.iter().any(|(_, value)| value.affine()),
            Self::Unit
            | Self::Int(_)
            | Self::Str(_)
            | Self::VariantConstructor {
                ..
            }
            | Self::Function {
                ..
            }
            | Self::MemoizedFunction {
                ..
            } => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GoverningScope {
    pub root: Arc<CanonicalItemIdentity>,
    pub name: Option<String>,
    pub boundary: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourceClaimKey {
    pub ty: Arc<CanonicalType>,
    pub value: PrimitiveValue,
    pub scope: GoverningScope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceClaim {
    pub key: ResourceClaimKey,
    pub span: Span,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RealizedRootOutcome {
    Value(Value),
    Failed(Vec<Diagnostic>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct RealizedRoot {
    pub(super) name: String,
    pub(super) identity: Arc<CanonicalItemIdentity>,
    pub(super) ty: Option<Arc<CanonicalType>>,
    pub(super) outcome: RealizedRootOutcome,
    pub(super) claims: Vec<ResourceClaim>,
    pub(super) selected: bool,
    pub(super) reference: Option<super::MemoId>,
    pub(super) aliases: Vec<String>,
}

impl RealizedRoot {
    pub fn aliases(&self) -> impl ExactSizeIterator<Item = &str> {
        self.aliases.iter().map(String::as_str)
    }

    pub fn selected_reference(&self) -> Option<&super::MemoId> {
        self.reference.as_ref()
    }
    pub fn is_selected(&self) -> bool {
        self.selected
    }
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn identity(&self) -> &CanonicalItemIdentity {
        &self.identity
    }

    pub fn ty(&self) -> Option<&CanonicalType> {
        self.ty.as_deref()
    }

    pub const fn outcome(&self) -> &RealizedRootOutcome {
        &self.outcome
    }

    pub fn claims(&self) -> impl ExactSizeIterator<Item = &ResourceClaim> {
        self.claims.iter()
    }

    pub const fn value(&self) -> Option<&Value> {
        match &self.outcome {
            RealizedRootOutcome::Value(value) => Some(value),
            RealizedRootOutcome::Failed(_) => None,
        }
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        match &self.outcome {
            RealizedRootOutcome::Value(_) => &[],
            RealizedRootOutcome::Failed(diagnostics) => diagnostics,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RealizedProgram {
    pub(super) roots: Vec<RealizedRoot>,
}

impl RealizedProgram {
    pub fn roots(&self) -> impl ExactSizeIterator<Item = &RealizedRoot> {
        self.roots.iter()
    }

    pub fn diagnostics(&self) -> impl Iterator<Item = &Diagnostic> {
        self.roots
            .iter()
            .flat_map(RealizedRoot::diagnostics)
    }

    pub fn is_success(&self) -> bool {
        self.roots
            .iter()
            .all(|root| matches!(root.outcome, RealizedRootOutcome::Value(_)))
    }
}

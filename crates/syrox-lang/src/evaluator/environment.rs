use std::{collections::BTreeMap, fmt};

use crate::{
    checker::CheckPolicy, checker::PolicyFingerprint, checker::PrimitiveType,
    evaluator::EvaluationLimit,
};

#[derive(Clone, Copy)]
pub(super) enum PredicateCallback {
    Int(fn(i64) -> bool),
    Str(fn(&str) -> bool),
}

impl fmt::Debug for PredicateCallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<pure predicate callback>")
    }
}

/// Caller-owned predicate callbacks are a trusted host boundary. Callers must
/// make them deterministic and free of externally visible effects. Panics are
/// caught and reported as failed-root diagnostics. The retained policy proves
/// the implemented vocabulary without treating function addresses as policy data.
#[derive(Clone, Debug)]
pub struct EvaluationEnvironment {
    pub(super) policy: CheckPolicy,
    pub(super) assets: BTreeMap<(crate::source::SourceDomainId, String), std::sync::Arc<[u8]>>,
    pub(super) predicates: BTreeMap<String, PredicateCallback>,
}

impl EvaluationEnvironment {
    pub fn new(policy: &CheckPolicy) -> Self {
        Self {
            policy: policy.clone(),
            predicates: BTreeMap::new(),
            assets: BTreeMap::new(),
        }
    }

    /// Retained bytes supplied by the engine after authenticating a project graph.
    /// No filesystem access takes place during language evaluation.
    #[must_use]
    pub fn with_authenticated_asset(
        mut self,
        domain: crate::source::SourceDomainId,
        path: String,
        bytes: std::sync::Arc<[u8]>,
    ) -> Self {
        self.assets.insert((domain, path), bytes);
        self
    }

    pub const fn policy(&self) -> &CheckPolicy {
        &self.policy
    }

    pub fn with_int_predicate(
        mut self,
        name: impl Into<String>,
        callback: fn(i64) -> bool,
    ) -> Result<Self, EnvironmentError> {
        self.insert_predicate(
            name.into(),
            PrimitiveType::Int,
            PredicateCallback::Int(callback),
        )?;
        Ok(self)
    }

    pub fn with_str_predicate(
        mut self,
        name: impl Into<String>,
        callback: fn(&str) -> bool,
    ) -> Result<Self, EnvironmentError> {
        self.insert_predicate(
            name.into(),
            PrimitiveType::Str,
            PredicateCallback::Str(callback),
        )?;
        Ok(self)
    }

    fn insert_predicate(
        &mut self,
        name: String,
        kind: PrimitiveType,
        callback: PredicateCallback,
    ) -> Result<(), EnvironmentError> {
        let declared = self
            .policy
            .predicates()
            .find(|rule| rule.name == name)
            .map(|rule| rule.input);
        if declared != Some(kind) {
            return Err(EnvironmentError::UnknownOrWrongPredicate {
                name,
            });
        }
        self.predicates.insert(name, callback);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvironmentError {
    UnknownOrWrongPredicate {
        name: String,
    },
}

impl fmt::Display for EnvironmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOrWrongPredicate {
                name,
            } => {
                write!(
                    formatter,
                    "predicate `{name}` is absent or has a different input type"
                )
            }
        }
    }
}

impl std::error::Error for EnvironmentError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationSetupError {
    LimitExceedsMaximum {
        limit: EvaluationLimit,
        configured: usize,
        maximum: usize,
    },
    PolicyMismatch {
        checked: PolicyFingerprint,
        supplied: PolicyFingerprint,
    },
    EnvironmentPolicyMismatch,
    MissingPredicateCallback,
    SetupWorkLimit,
    SetupExpansionLimit,
    EvaluationWorkLimit,
    EvaluationRetainedExpansionLimit,
    MissingRootIdentity,
}

impl fmt::Display for EvaluationSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceedsMaximum {
                limit,
                configured,
                maximum,
            } => write!(
                formatter,
                "evaluation limit {limit:?} is {configured}, above the hard maximum of {maximum}"
            ),
            Self::PolicyMismatch {
                ..
            } => formatter.write_str("evaluation policy does not match checking policy"),
            Self::EnvironmentPolicyMismatch => {
                formatter.write_str("evaluation environment does not match the supplied policy")
            }
            Self::MissingPredicateCallback => formatter.write_str(
                "evaluation environment does not implement the complete predicate vocabulary",
            ),
            Self::SetupWorkLimit => formatter.write_str("evaluation setup work limit reached"),
            Self::SetupExpansionLimit => {
                formatter.write_str("evaluation setup expansion byte limit reached")
            }
            Self::EvaluationWorkLimit => {
                formatter.write_str("operation-wide evaluation work limit reached")
            }
            Self::EvaluationRetainedExpansionLimit => formatter
                .write_str("operation-wide evaluation retained expansion byte limit reached"),
            Self::MissingRootIdentity => {
                formatter.write_str("evaluation root identity is unavailable")
            }
        }
    }
}

impl std::error::Error for EvaluationSetupError {}

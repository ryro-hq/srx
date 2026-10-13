//! Avalia o programa que passou pela checagem.
//!
//! A avaliação usa a mesma política e um ambiente explícito. Trabalho, expansão
//! e dados retidos têm limites próprios. Os valores descrevem receitas e seus
//! recursos; adquirir arquivos e executar builds ficam na engine.
//!
//! [`evaluate`] avalia tudo. [`EvaluationSession`] permite selecionar publicações
//! sob demanda, mantendo o ambiente e os valores compartilhados entre consultas.

mod environment;
mod index;
mod model;
mod runtime;
mod session;
mod types;

#[cfg(test)]
mod tests;

use crate::{checker::CheckPolicy, checker::CheckedProgram, source::Span};

pub use environment::{EnvironmentError, EvaluationEnvironment, EvaluationSetupError};
pub use model::{
    CanonicalType, EvaluationLimit, EvaluationLimits, GoverningScope, MAX_EVALUATION_DEPTH,
    MAX_EVALUATION_EXPANSION, MAX_EVALUATION_RETAINED_EXPANSION, MAX_EVALUATION_SETUP_BYTES,
    MAX_EVALUATION_SETUP_STEPS, MAX_EVALUATION_STEPS, MAX_EVALUATION_TOTAL_STEPS, PrimitiveValue,
    RealizedProgram, RealizedRoot, RealizedRootOutcome, ResourceClaim, ResourceClaimKey, Value,
};

pub use runtime::MemoId;
pub use session::{EvaluationQueryError, EvaluationSession, PublishedRoot};

pub fn evaluate(
    program: &CheckedProgram,
    policy: &CheckPolicy,
    environment: &EvaluationEnvironment,
) -> Result<RealizedProgram, EvaluationSetupError> {
    evaluate_with_limits(
        program,
        policy,
        environment,
        EvaluationLimits::default(),
    )
}

pub fn evaluate_with_limits(
    program: &CheckedProgram,
    policy: &CheckPolicy,
    environment: &EvaluationEnvironment,
    limits: EvaluationLimits,
) -> Result<RealizedProgram, EvaluationSetupError> {
    let mut session = EvaluationSession::new(program, policy, environment, limits)?;
    session.evaluate_all()?;
    session.into_realized()
}

fn validate_limits(limits: EvaluationLimits) -> Result<(), EvaluationSetupError> {
    let limits_and_maxima = [
        (
            EvaluationLimit::SetupSteps,
            limits.max_setup_steps,
            MAX_EVALUATION_SETUP_STEPS,
        ),
        (
            EvaluationLimit::SetupBytes,
            limits.max_setup_bytes,
            MAX_EVALUATION_SETUP_BYTES,
        ),
        (
            EvaluationLimit::TotalSteps,
            limits.max_total_steps,
            MAX_EVALUATION_TOTAL_STEPS,
        ),
        (
            EvaluationLimit::StepsPerRoot,
            limits.max_steps_per_root,
            MAX_EVALUATION_STEPS,
        ),
        (
            EvaluationLimit::Depth,
            limits.max_depth,
            MAX_EVALUATION_DEPTH,
        ),
        (
            EvaluationLimit::ExpansionBytes,
            limits.max_expansion_bytes,
            MAX_EVALUATION_EXPANSION,
        ),
        (
            EvaluationLimit::RetainedExpansionBytes,
            limits.max_retained_expansion_bytes,
            MAX_EVALUATION_RETAINED_EXPANSION,
        ),
        (
            EvaluationLimit::Diagnostics,
            limits.max_diagnostics,
            crate::MAX_DIAGNOSTICS,
        ),
    ];
    for (limit, configured, maximum) in limits_and_maxima {
        if configured > maximum {
            return Err(EvaluationSetupError::LimitExceedsMaximum {
                limit,
                configured,
                maximum,
            });
        }
    }
    Ok(())
}

type SpanKey = (usize, u32, u32);

fn span_key(span: Span) -> SpanKey {
    (span.source_id().index(), span.start(), span.end())
}

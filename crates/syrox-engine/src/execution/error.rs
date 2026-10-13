use crate::{result::MaterializationError, store::StoreError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("runtime cancelled")]
    Cancelled,
    #[error("invalid runtime closure: {0}")]
    Invalid(String),
    #[error(transparent)]
    Materialization(#[from] MaterializationError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub(super) fn invalid(reason: &str) -> RuntimeError {
    RuntimeError::Invalid(reason.into())
}

//! Building with a worker pinned by hash and inputs already verified.
//!
//! Preparation, handoff, execution and settlement require different evidence.
//! Receiving a packet or descriptor does not release the payload. Authorization
//! depends on verifying the worker, manager invocation, namespace and input
//! retention. [`namespace_identity`](../../../src/syrox_engine/build/managed/namespace_identity.rs.html) owns the process and namespace comparisons;
//! [`journal`](../../../src/syrox_engine/build/journal/mod.rs.html) preserves recovery state.

pub(crate) mod cgroup;
pub(crate) mod entry;
pub(crate) mod execution;
pub(crate) mod handshake;
pub(crate) mod namespace;
pub(crate) mod namespace_identity;
pub(crate) mod namespace_protocol;
pub(crate) mod preparation;
pub(crate) mod resources;
pub(crate) mod retention_protocol;
pub(crate) mod supervision;
pub(crate) mod transfer;
pub(crate) mod worker;
pub(crate) use super::bootstrap::linux;
pub(crate) use super::{
    BuildError, BuildProfile, BuildResources, BuildResult, BuildSpecification, cancellation,
    journal, publication, records,
};
pub(crate) use handshake::{ManagedBuildHandshake, ManagedBuildResourcesSent};
pub(crate) use namespace::PreparedManagedBuildNamespace;
pub(crate) use namespace_protocol::{
    CapturedManagedBuildOutput, CommittedManagedBuild, ObservedManagedBuildNamespace,
    PublishedManagedBuildNamespace,
};
pub use preparation::{
    ManagedBuildInputs, ManagedBuildLayout, PreparedManagedBuild, prepare_managed_build,
    prepare_managed_build_inputs,
};
pub(crate) use resources::ManagedBuildResources;
pub(crate) use retention_protocol::ObservedManagedBuildRetention;
pub(crate) use supervision::{ManagedBuildServiceSpecification, ObservedManagedBuildBinding};
pub(crate) use worker::ManagedBuildWorkerInspection;

pub(crate) use super::{MAX_BUILD_PROGRAM_BYTES, MAX_OUTPUT_BYTES};

// Observation errors remain errors; this mapping cannot certify resource settlement.
fn manager_error(error: &crate::systemd::SystemdError) -> BuildError {
    match error {
        crate::systemd::SystemdError::Cancelled => BuildError::Cancelled,
        _ => BuildError::Cache(error.to_string()),
    }
}

// Timeout family allows a zero remaining duration, as its original callers did.
fn remaining_timeout(
    cancel: &crate::cancellation::Cancellation,
    deadline: std::time::Instant,
) -> Result<std::time::Duration, BuildError> {
    cancel.check()?;
    deadline
        .checked_duration_since(std::time::Instant::now())
        .ok_or(BuildError::Timeout)
}
// Request validation rejects expired and zero durations; cancellation has priority.
fn remaining_request(
    cancel: &crate::cancellation::Cancellation,
    deadline: std::time::Instant,
) -> Result<std::time::Duration, BuildError> {
    cancel.check()?;
    remaining_request_duration(deadline)
}
fn remaining_request_duration(
    deadline: std::time::Instant,
) -> Result<std::time::Duration, BuildError> {
    deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(BuildError::InvalidRequest)
}

// Framing only: callers still own semantic validation, canonical equality and phase authority.
fn encode_json(
    domain: &[u8],
    value: &impl serde::Serialize,
    limit: usize,
) -> Result<Vec<u8>, BuildError> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(value).map_err(|_| BuildError::InvalidRequest)?);
    if bytes.len() > limit {
        return Err(BuildError::InvalidRequest);
    }
    Ok(bytes)
}
fn decode_json<T: serde::de::DeserializeOwned>(
    domain: &[u8],
    bytes: &[u8],
    limit: usize,
) -> Result<T, BuildError> {
    if bytes.len() > limit {
        return Err(BuildError::InvalidRequest);
    }
    serde_json::from_slice(
        bytes
            .strip_prefix(domain)
            .ok_or(BuildError::InvalidRequest)?,
    )
    .map_err(|_| BuildError::InvalidRequest)
}

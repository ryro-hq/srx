use super::{BuildError, SystemBuildInputs};
use crate::{
    cancellation::Cancellation, result::MaterializedArtifact, store::chunked::ChunkedDescriptorSet,
};

impl SystemBuildInputs {
    /// Prepare one already-authorized v3 input for a descriptor-only worker.
    /// Slots are manifest first and unique chunks sorted by digest. The explicit
    /// remaining slot ceiling must exclude all other worker/control roles; it
    /// cannot exceed the action's descriptor budget. No legacy resource packet,
    /// worker handshake, execution gate or receipt is produced here.
    pub fn chunked_input_descriptors(
        &self,
        index: usize,
        maximum_slots: u32,
        cancellation: &Cancellation,
    ) -> Result<ChunkedDescriptorSet, BuildError> {
        cancellation.check()?;
        if maximum_slots == 0 || maximum_slots > self.action.budget().request().descriptors {
            return Err(BuildError::InvalidRequest);
        }
        let input = self
            .inputs
            .get(index)
            .ok_or(BuildError::UnsupportedInputs)?;
        let expected = input
            .chunked()
            .ok_or(BuildError::UnsupportedInputs)?
            .decoded()
            .map_err(|_| BuildError::InputChanged)?;
        let chunks = expected
            .chunks()
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if chunks.len() + 1 > usize::try_from(maximum_slots).unwrap_or(usize::MAX) {
            return Err(BuildError::UnsupportedInputs);
        }
        self.revalidate(cancellation)?;
        capture(input, maximum_slots, cancellation)
    }
}

/// The aggregate exporter validates the entire preparation once at each end.
/// Reopening each selected artifact still authenticates its complete closure;
/// it must not rescan every unrelated input for each individual input role.
pub(super) fn capture(
    input: &MaterializedArtifact,
    maximum_slots: u32,
    cancellation: &Cancellation,
) -> Result<ChunkedDescriptorSet, BuildError> {
    cancellation.check()?;
    let expected = input
        .chunked()
        .ok_or(BuildError::UnsupportedInputs)?
        .decoded()
        .map_err(|_| BuildError::InputChanged)?;
    let operation = input.object_lease().operation()?;
    let artifact = operation
        .open_chunked(
            input.artifact(),
            input.artifact_limits().bytes,
            cancellation,
        )
        .map_err(|error| map_error(&error, cancellation))?
        .ok_or(BuildError::InputChanged)?;
    drop(operation);
    if artifact.manifest() != &expected {
        return Err(BuildError::InputChanged);
    }
    artifact
        .prepare_descriptors(maximum_slots, cancellation)
        .map_err(|error| map_error(&error, cancellation))
}

fn map_error(
    error: &crate::store::chunked::ChunkedArtifactError,
    cancellation: &Cancellation,
) -> BuildError {
    if cancellation.is_cancelled() {
        BuildError::Cancelled
    } else {
        BuildError::Cache(error.to_string())
    }
}

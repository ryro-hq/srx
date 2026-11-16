//! A prepared component retains its source/input custody throughout both mounts.

use super::{
    BuildError, SystemBuildInputs,
    scratch::{check, check_io, io_error},
};
use crate::{
    cancellation::Cancellation,
    store::ContentDigest,
    system::{
        budget::BuilderCapacity,
        helper_client::{HelperClient, WorkspaceLease},
        workspace::{ReceivedWorkspace, WorkspaceLayout, WorkspaceObservation},
    },
};
use std::{fs::File, time::Instant};

/// Drop closes descriptions/control and leaves uncertain helper evidence. It
/// never releases a live worker, repeats formatting or creates a build receipt.
pub struct SystemBuildWorkspace<'a> {
    inputs: &'a SystemBuildInputs,
    scratch: File,
    output: File,
    observation: WorkspaceObservation,
    lease: WorkspaceLease,
}
impl std::fmt::Debug for SystemBuildWorkspace<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemBuildWorkspace")
            .field("action", &self.action_digest())
            .field("observation", &self.observation)
            .finish_non_exhaustive()
    }
}
impl SystemBuildInputs {
    /// Explicit allocation via the snapshotted root endpoint. Capacity is
    /// independently checked here and reobserved by the helper; no worker starts.
    pub fn prepare_workspace(
        &self,
        id: &str,
        capacity: BuilderCapacity,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<SystemBuildWorkspace<'_>, BuildError> {
        check(cancellation, deadline)?;
        if id.len() != 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(BuildError::InvalidRequest);
        }
        let layout = self.action.workspace_layout()?;
        layout.budget().check_capacity(capacity)?;
        self.revalidate(cancellation)?;
        check(cancellation, deadline)?;
        let check_io = || check_io(cancellation, deadline);
        let grant = HelperClient::connect(
            self.configuration.helper_socket(),
            check_io,
            deadline,
        )
        .and_then(|client| client.prepare_workspace(id, &layout, check_io, deadline))
        .map_err(|error| io_error(error, cancellation, deadline))?;
        check(cancellation, deadline)?;
        let observation = *grant.observation();
        let (scratch, output, lease) = grant.into_parts();
        let workspace = SystemBuildWorkspace {
            inputs: self,
            scratch,
            output,
            observation,
            lease,
        };
        workspace.verify_roots()?;
        check(cancellation, deadline)?;
        Ok(workspace)
    }
}
impl SystemBuildWorkspace<'_> {
    pub(super) const fn inputs(&self) -> &SystemBuildInputs {
        self.inputs
    }
    pub fn action_digest(&self) -> ContentDigest {
        self.inputs.action.digest()
    }
    pub const fn layout(&self) -> &WorkspaceLayout {
        self.lease.layout()
    }
    pub const fn observation(&self) -> &WorkspaceObservation {
        &self.observation
    }
    fn verify_roots(&self) -> Result<(), BuildError> {
        if self.layout().budget() != self.inputs.action.budget() {
            return Err(BuildError::InputChanged);
        }
        ReceivedWorkspace::from_authorized_roots(
            self.layout(),
            &self.observation,
            self.scratch.try_clone()?,
            self.output.try_clone()?,
        )?
        .revalidate()?;
        Ok(())
    }
    /// Role order and observation are authenticated through this owner; the
    /// receiver still needs the selected action's authenticated worker handoff.
    /// The helper control description never crosses this boundary.
    pub fn root_descriptors(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(File, File), BuildError> {
        check(cancellation, deadline)?;
        self.inputs.revalidate(cancellation)?;
        self.verify_roots()?;
        let roots = (
            self.scratch.try_clone()?,
            self.output.try_clone()?,
        );
        check(cancellation, deadline)?;
        Ok(roots)
    }
    /// End every worker namespace and close all external root/files first.
    /// Helper confirmation requires both loops gone and both final checks.
    pub fn release(
        self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<serde_json::Value, BuildError> {
        check(cancellation, deadline)?;
        let Self {
            inputs: _inputs,
            scratch,
            output,
            observation: _,
            lease,
        } = self;
        drop(scratch);
        drop(output);
        lease
            .release(|| check_io(cancellation, deadline), deadline)
            .map_err(|error| io_error(error, cancellation, deadline))
    }
}

//! Bind private helper scratch to a prepared System component and its custody.
//!
//! Only the root directory can cross the worker boundary. The coordinator keeps
//! the control lease in its original identity namespace until explicit release.

use super::{BuildError, SystemBuildInputs};
use crate::{
    cancellation::{Cancellation, cancellation_io},
    store::ContentDigest,
    system::{
        budget::BuilderCapacity,
        helper_client::{HelperClient, ScratchLease},
        scratch::{ReceivedScratch, ScratchCapacity},
    },
};
use std::{fs::File, io, time::Instant};

#[cfg(target_arch = "x86_64")]
impl super::SystemBuildAction {
    /// Pure geometry/inode planning for both writable roles, derived from this
    /// action's exact admitted budget. This neither contacts the scratch helper
    /// nor authorizes formatting/mounting. The current one-volume helper API
    /// remains separate until the complete workspace protocol is implemented.
    pub fn workspace_layout(
        &self,
    ) -> Result<crate::system::workspace::WorkspaceLayout, BuildError> {
        Ok(crate::system::workspace::WorkspaceLayout::from_budget(self.budget())?)
    }
}

/// Owns a root-authenticated private scratch grant while borrowing source/input
/// custody. Drop closes handles and leaves uncertain helper work for explicit
/// recovery; it never sends RELEASE, repeats formatting or authorizes execution.
pub struct SystemBuildScratch<'a> {
    inputs: &'a SystemBuildInputs,
    root: File,
    lease: ScratchLease,
    capacity: ScratchCapacity,
}

impl std::fmt::Debug for SystemBuildScratch<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemBuildScratch")
            .field("action", &self.action_digest())
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl SystemBuildInputs {
    /// Allocate scratch only through the endpoint snapshotted during preparation.
    /// This explicit effect does not create a build attempt or start a worker.
    /// Root policy independently admits the exact System budget and peer. The
    /// helper owns the image/loop/journal; no physical device is selected here.
    pub fn prepare_scratch(
        &self,
        id: &str,
        capacity: BuilderCapacity,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<SystemBuildScratch<'_>, BuildError> {
        check(cancellation, deadline)?;
        if id.len() != 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(BuildError::InvalidRequest);
        }
        self.action.budget().check_capacity(capacity)?;
        self.revalidate(cancellation)?;
        check(cancellation, deadline)?;
        let check_io = || check_io(cancellation, deadline);
        let grant = HelperClient::connect(
            self.configuration.helper_socket(),
            check_io,
            deadline,
        )
        .and_then(|client| client.prepare(id, self.action.budget(), check_io, deadline))
        .map_err(|error| io_error(error, cancellation, deadline))?;
        check(cancellation, deadline)?;
        let capacity = grant.capacity();
        let (root, lease) = grant.into_parts();
        let scratch = SystemBuildScratch {
            inputs: self,
            root,
            lease,
            capacity,
        };
        scratch.verify_root()?;
        check(cancellation, deadline)?;
        Ok(scratch)
    }
}

impl SystemBuildScratch<'_> {
    pub fn action_digest(&self) -> ContentDigest {
        self.inputs.action.digest()
    }

    pub const fn capacity(&self) -> ScratchCapacity {
        self.capacity
    }

    fn verify_root(&self) -> Result<(), BuildError> {
        let verified = ReceivedScratch::from_authorized_root(
            self.root.try_clone()?,
            self.inputs.action.budget(),
        )?;
        if verified.capacity() != self.capacity
            || self.lease.budget() != self.inputs.action.budget().request()
        {
            return Err(BuildError::InputChanged);
        }
        Ok(())
    }

    /// Revalidate the held inputs and genuine root before duplicating only its
    /// readonly directory description. The receiver still owes an authenticated
    /// action/handoff and a private namespace. No control socket is transferred.
    pub fn root_descriptor(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<File, BuildError> {
        check(cancellation, deadline)?;
        self.inputs.revalidate(cancellation)?;
        self.verify_root()?;
        check(cancellation, deadline)?;
        Ok(self.root.try_clone()?)
    }

    /// Call only after closing all transferred root/files and ending worker
    /// namespaces. Drop this coordinator root before requesting the helper's
    /// independent loop/filesystem checks. Rejection or lost replies stay
    /// uncertain, without retry, reformat or automatic reconciliation.
    pub fn release(
        self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<serde_json::Value, BuildError> {
        check(cancellation, deadline)?;
        let Self {
            inputs: _inputs,
            root,
            lease,
            capacity: _,
        } = self;
        drop(root);
        lease
            .release(|| check_io(cancellation, deadline), deadline)
            .map_err(|error| io_error(error, cancellation, deadline))
    }
}

pub(super) fn check(cancellation: &Cancellation, deadline: Instant) -> Result<(), BuildError> {
    cancellation.check()?;
    if Instant::now() >= deadline {
        return Err(BuildError::Timeout);
    }
    Ok(())
}

pub(super) fn check_io(cancellation: &Cancellation, deadline: Instant) -> io::Result<()> {
    if cancellation.is_cancelled() {
        return Err(cancellation_io());
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "System scratch deadline exceeded",
        ));
    }
    Ok(())
}

pub(super) fn io_error(
    error: io::Error,
    cancellation: &Cancellation,
    deadline: Instant,
) -> BuildError {
    if cancellation.is_cancelled() {
        BuildError::Cancelled
    } else if Instant::now() >= deadline {
        BuildError::Timeout
    } else {
        BuildError::Io(error)
    }
}

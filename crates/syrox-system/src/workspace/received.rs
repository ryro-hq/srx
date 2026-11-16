use super::{WorkspaceLayout, WorkspaceObservation, WorkspaceVolumeObservation, refused};
use crate::scratch::{AttachedScratch, ReceivedScratch};
use std::{
    fs::File,
    io,
    os::{fd::BorrowedFd, unix::fs::MetadataExt as _},
};

/// Descriptor-only pair after the caller authenticates the helper's observation
/// and role order. No control socket, namespace mutation or execution authority
/// is acquired by validating geometry/identity here.
#[derive(Debug)]
pub struct ReceivedWorkspace {
    layout: WorkspaceLayout,
    observation: WorkspaceObservation,
    scratch: ReceivedScratch,
    output: ReceivedScratch,
}

impl ReceivedWorkspace {
    pub fn from_authorized_roots(
        layout: &WorkspaceLayout,
        observation: &WorkspaceObservation,
        scratch: File,
        output: File,
    ) -> io::Result<Self> {
        observation.validate(layout)?;
        let scratch = ReceivedScratch::from_authorized_root_with_limits(
            scratch,
            layout.scratch.image_bytes(),
            layout.scratch.requested_inodes(),
        )?;
        let output = ReceivedScratch::from_authorized_root_with_limits(
            output,
            layout.output.image_bytes(),
            layout.output.requested_inodes(),
        )?;
        let received = Self {
            layout: *layout,
            observation: *observation,
            scratch,
            output,
        };
        received.revalidate()?;
        Ok(received)
    }
    pub const fn layout(&self) -> &WorkspaceLayout {
        &self.layout
    }
    pub const fn observation(&self) -> &WorkspaceObservation {
        &self.observation
    }
    pub fn revalidate(&self) -> io::Result<()> {
        self.scratch.revalidate()?;
        self.output.revalidate()?;
        self.observation.validate(&self.layout)?;
        for (received, expected) in [
            (&self.scratch, self.observation.scratch),
            (&self.output, self.observation.output),
        ] {
            if received.root_identity() != (expected.device, expected.inode)
                || received.capacity().filesystem_bytes != expected.filesystem_bytes
                || received.capacity().inodes != expected.inodes
            {
                return Err(refused(
                    "workspace root differs from its authenticated role observation",
                ));
            }
        }
        Ok(())
    }

    /// Move both roots to distinct pinned empty targets in this worker's private
    /// namespace, after validating both targets before the first move.
    ///
    /// # Safety
    /// Caller is a dedicated single-threaded non-root worker in its own private
    /// user/mount namespaces, preserving the mapped builder identity. On ANY
    /// error discard the entire namespace, including a possible first mount;
    /// no retry/fallback is permitted. All roots/files and the namespace must
    /// end before the coordinator requests helper loop/filesystem release.
    #[allow(unsafe_code)]
    pub unsafe fn attach(
        self,
        scratch_target: File,
        output_target: File,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<AttachedWorkspace> {
        check()?;
        self.revalidate()?;
        self.scratch.validate_target(&scratch_target)?;
        self.output.validate_target(&output_target)?;
        let scratch_identity = identity(&scratch_target)?;
        let output_identity = identity(&output_target)?;
        if scratch_identity == output_identity
            || [scratch_identity, output_identity]
                .iter()
                .any(|target| {
                    *target == self.scratch.root_identity()
                        || *target == self.output.root_identity()
                })
        {
            return Err(refused(
                "workspace targets must be distinct from each other and both sources",
            ));
        }
        check()?;
        // SAFETY: caller guarantees the dedicated namespace lifecycle above;
        // failure after either move is handled by discarding that namespace.
        let scratch = unsafe { self.scratch.attach(scratch_target, &mut check) }?;
        // SAFETY: the same prevalidated dedicated namespace/target contract.
        let output = unsafe { self.output.attach(output_target, &mut check) }?;
        check()?;
        let attached = AttachedWorkspace {
            layout: self.layout,
            observation: self.observation,
            scratch,
            output,
        };
        attached.revalidate()?;
        Ok(attached)
    }
}

#[derive(Debug)]
pub struct AttachedWorkspace {
    layout: WorkspaceLayout,
    observation: WorkspaceObservation,
    scratch: AttachedScratch,
    output: AttachedScratch,
}

impl AttachedWorkspace {
    pub const fn layout(&self) -> &WorkspaceLayout {
        &self.layout
    }
    pub const fn observation(&self) -> &WorkspaceObservation {
        &self.observation
    }
    pub fn scratch_root(&self) -> BorrowedFd<'_> {
        self.scratch.root()
    }
    pub fn output_root(&self) -> BorrowedFd<'_> {
        self.output.root()
    }
    pub fn revalidate(&self) -> io::Result<()> {
        self.scratch.revalidate()?;
        self.output.revalidate()?;
        self.observation.validate(&self.layout)?;
        for (root, capacity, expected) in [
            (
                self.scratch.root(),
                self.scratch.capacity(),
                self.observation.scratch,
            ),
            (
                self.output.root(),
                self.output.capacity(),
                self.observation.output,
            ),
        ] {
            let actual: WorkspaceVolumeObservation = super::observe_root(root, capacity)?;
            if actual != expected {
                return Err(refused(
                    "attached workspace role identity changed",
                ));
            }
        }
        Ok(())
    }
}

fn identity(file: &File) -> io::Result<(u64, u64)> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino()))
}

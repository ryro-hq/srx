//! Distinct private ext4 areas for System intermediates and final outputs.
//!
//! Layout is derived solely from an independently admitted budget. Formatting,
//! peer authority, journals, release/recovery and execution supervision remain
//! caller responsibilities. Filesystem ceilings cover allocated storage/inodes;
//! sparse logical lengths still require file-size/output admission enforcement.

use crate::{
    budget::AdmittedBudget,
    ext4_tool::Geometry,
    loop_device::ScratchLoop,
    scratch::{DetachedScratch, ScratchCapacity},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::File,
    io,
    os::{fd::BorrowedFd, unix::fs::MetadataExt as _},
};
use syrox_encoding::formats;

mod received;
pub use received::{AttachedWorkspace, ReceivedWorkspace};

const HEADER: &[u8] = formats::SYSTEM_WORKSPACE_LAYOUT_LINE.as_bytes();

/// Deterministic geometry for two separately bounded filesystems. The global
/// inode ceiling is split in proportion to scratch/output byte ceilings, then
/// each share rounds down to the existing ext4 table/group granularity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkspaceLayout {
    budget: AdmittedBudget,
    scratch: Geometry,
    output: Geometry,
}

impl WorkspaceLayout {
    /// Pure preflight, with no object/device open or image allocation. Both
    /// volumes must satisfy the fixed ext4 geometry contract independently.
    pub fn from_budget(budget: &AdmittedBudget) -> io::Result<Self> {
        let request = budget.request();
        let total = request
            .storage_bytes()
            .map_err(io::Error::other)?;
        let scratch_inodes = u64::try_from(
            u128::from(request.files) * u128::from(request.scratch_bytes) / u128::from(total),
        )
        .map_err(|_| refused("workspace inode allocation overflow"))?;
        let output_inodes = request.files - scratch_inodes;
        let scratch = Geometry::new(request.scratch_bytes, scratch_inodes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("workspace scratch geometry: {e}"),
            )
        })?;
        let output = Geometry::new(request.output_bytes, output_inodes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("workspace output geometry: {e}"),
            )
        })?;
        Ok(Self {
            budget: *budget,
            scratch,
            output,
        })
    }
    pub const fn budget(&self) -> &AdmittedBudget {
        &self.budget
    }
    pub const fn scratch_geometry(&self) -> Geometry {
        self.scratch
    }
    pub const fn output_geometry(&self) -> Geometry {
        self.output
    }
    pub fn storage_bytes(&self) -> u64 {
        self.scratch.image_bytes() + self.output.image_bytes()
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let request = self.budget.request();
        let mut bytes = HEADER.to_vec();
        bytes.extend(self.budget.policy_fingerprint());
        for value in [
            request.memory_bytes,
            u64::from(request.cpu_percent),
            u64::from(request.processes),
            u64::from(request.descriptors),
            request.scratch_bytes,
            request.files,
            request.output_bytes,
            u64::from(request.duration_seconds),
            self.scratch.image_bytes(),
            self.scratch.requested_inodes(),
            self.output.image_bytes(),
            self.output.requested_inodes(),
        ] {
            bytes.extend(value.to_le_bytes());
        }
        bytes
    }
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

/// Observed filesystem identity and total geometry, never producer authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceVolumeObservation {
    pub device: u64,
    pub inode: u64,
    pub filesystem_bytes: u64,
    pub inodes: u64,
}

/// Role order must be authenticated by a helper receipt/handoff independently;
/// geometry alone cannot distinguish two equal-size swapped filesystems.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceObservation {
    pub layout_sha256: [u8; 32],
    pub scratch: WorkspaceVolumeObservation,
    pub output: WorkspaceVolumeObservation,
}

impl WorkspaceObservation {
    fn validate(&self, layout: &WorkspaceLayout) -> io::Result<()> {
        if self.layout_sha256 != layout.digest() || self.scratch.device == self.output.device {
            return Err(refused(
                "workspace layout or distinct filesystem roles disagree",
            ));
        }
        for (observed, geometry) in [
            (self.scratch, layout.scratch),
            (self.output, layout.output),
        ] {
            if observed.inode != 2
                || observed.filesystem_bytes == 0
                || observed.filesystem_bytes > geometry.image_bytes()
                || observed.inodes == 0
                || observed.inodes > geometry.requested_inodes()
            {
                return Err(refused(
                    "workspace filesystem exceeds its exact role geometry",
                ));
            }
        }
        if self
            .scratch
            .inodes
            .checked_add(self.output.inodes)
            .is_none_or(|total| total > layout.budget.request().files)
        {
            return Err(refused(
                "workspace aggregate inode ceiling exceeded",
            ));
        }
        Ok(())
    }
}

/// Two detached mounts, borrowing their independently owned loop bindings.
/// On any error retain journal evidence; neither Drop nor this type releases a
/// loop, reformats an image or proves that transferred roots/namespaces ended.
#[derive(Debug)]
pub struct DetachedWorkspace<'a> {
    layout: WorkspaceLayout,
    scratch: DetachedScratch<'a>,
    output: DetachedScratch<'a>,
}

impl<'a> DetachedWorkspace<'a> {
    /// Caller formats/checks both NEW private images with authenticated tools
    /// and journals intent first. Aliased images/devices and incorrect sizes
    /// fail before either mount. A later error may follow the first mount.
    pub fn mount(
        layout: &WorkspaceLayout,
        scratch: &'a ScratchLoop,
        output: &'a ScratchLoop,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        check()?;
        check_devices(layout, scratch, output)?;
        let scratch = DetachedScratch::mount_with_limits(
            scratch,
            layout.scratch.image_bytes(),
            layout.scratch.requested_inodes(),
            &mut check,
        )?;
        let output = DetachedScratch::mount_with_limits(
            output,
            layout.output.image_bytes(),
            layout.output.requested_inodes(),
            &mut check,
        )?;
        let workspace = Self {
            layout: *layout,
            scratch,
            output,
        };
        workspace.observation()?;
        check()?;
        Ok(workspace)
    }
    pub const fn layout(&self) -> &WorkspaceLayout {
        &self.layout
    }
    pub fn scratch_root(&self) -> io::Result<BorrowedFd<'_>> {
        self.scratch.root()
    }
    pub fn output_root(&self) -> io::Result<BorrowedFd<'_>> {
        self.output.root()
    }
    pub fn observation(&self) -> io::Result<WorkspaceObservation> {
        let observed = WorkspaceObservation {
            layout_sha256: self.layout.digest(),
            scratch: observe_root(self.scratch.root()?, self.scratch.capacity())?,
            output: observe_root(self.output.root()?, self.output.capacity())?,
        };
        observed.validate(&self.layout)?;
        Ok(observed)
    }
    /// Only this pair's fresh roots change ownership. The operation is not
    /// atomic across roots; a failure requires preserving intent/evidence.
    pub fn assign_owner(&self, uid: u32, gid: u32) -> io::Result<()> {
        if uid == 0 {
            return Err(refused(
                "workspace requires an explicit non-root builder",
            ));
        }
        self.scratch.assign_owner(uid, gid)?;
        self.output.assign_owner(uid, gid)?;
        self.observation()?;
        Ok(())
    }
}

fn check_devices(
    layout: &WorkspaceLayout,
    scratch: &ScratchLoop,
    output: &ScratchLoop,
) -> io::Result<()> {
    if scratch.image_bytes() != layout.scratch.image_bytes()
        || output.image_bytes() != layout.output.image_bytes()
        || scratch.backing_identity()? == output.backing_identity()?
    {
        return Err(refused(
            "workspace requires distinct images of the planned exact sizes",
        ));
    }
    let left = File::from(scratch.verified_device()?.try_clone_to_owned()?)
        .metadata()?
        .rdev();
    let right = File::from(output.verified_device()?.try_clone_to_owned()?)
        .metadata()?
        .rdev();
    if left == right {
        return Err(refused("workspace loop devices are aliased"));
    }
    Ok(())
}

fn observe_root(
    root: BorrowedFd<'_>,
    capacity: ScratchCapacity,
) -> io::Result<WorkspaceVolumeObservation> {
    let metadata = File::from(root.try_clone_to_owned()?).metadata()?;
    Ok(WorkspaceVolumeObservation {
        device: metadata.dev(),
        inode: metadata.ino(),
        filesystem_bytes: capacity.filesystem_bytes,
        inodes: capacity.inodes,
    })
}

fn refused(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

#[cfg(test)]
mod tests;

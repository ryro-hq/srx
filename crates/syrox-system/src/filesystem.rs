//! Read-only filesystem and project-quota observations from an already open
//! directory. No path discovery, quota changes, mounts or provisioning occurs.
//!
//! A capacity report is not an execution lease: a builder must independently
//! authorize its directory, establish exclusive use, enforce its limits and
//! revalidate the observed identity and quota state immediately before work.

use serde::Serialize;
use std::{
    fs::File,
    io,
    os::{fd::AsFd as _, unix::fs::MetadataExt as _},
};

#[allow(unsafe_code)]
mod kernel;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Observation<T> {
    Available {
        value: T,
    },
    Unavailable {
        errno: Option<i32>,
        reason: String,
    },
}

impl<T> Observation<T> {
    fn from_result(result: io::Result<T>) -> Self {
        match result {
            Ok(value) => Self::Available {
                value,
            },
            Err(error) => Self::Unavailable {
                errno: error.raw_os_error(),
                reason: error.to_string(),
            },
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FilesystemObservation {
    pub device: u64,
    pub inode: u64,
    pub filesystem_type: i64,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub total_inodes: u64,
    pub available_inodes: u64,
    pub project: Observation<ProjectObservation>,
}

/// External filesystem UUID bytes, as returned by the kernel, bounded to 16.
/// Cloned filesystems can share a UUID; this is not exclusive device authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct FilesystemUuid(Vec<u8>);

impl FilesystemUuid {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for FilesystemUuid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Read the external filesystem UUID through a fixed read-only ioctl on this
/// existing directory. Unsupported kernels/filesystems return their actual
/// error; there is no pathname/device discovery or fabricated identity.
pub fn external_uuid(directory: &File) -> io::Result<FilesystemUuid> {
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesystem UUID requires a directory descriptor",
        ));
    }
    kernel::uuid(directory.as_fd()).map(FilesystemUuid)
}

#[derive(Clone, Debug, Serialize)]
pub struct ProjectObservation {
    pub id: u32,
    pub children_inherit_project: bool,
    pub state: Observation<ProjectQuotaState>,
    pub limits: Observation<ProjectQuotaLimits>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ProjectQuotaState {
    pub accounting: bool,
    pub enforcement: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectQuotaLimits {
    /// A zero kernel hard limit means unlimited, never zero available capacity.
    pub hard_bytes: Option<u64>,
    pub hard_inodes: Option<u64>,
    pub used_bytes: u64,
    pub used_inodes: u64,
}

impl FilesystemObservation {
    /// Identity of this exact observation, including capacity/usage. It is not
    /// a filesystem lock or proof that the observed values remain current.
    pub fn fingerprint(&self) -> Result<String, serde_json::Error> {
        use sha2::{Digest as _, Sha256};
        use std::fmt::Write as _;
        let mut hasher = Sha256::new();
        hasher.update(b"syrox-filesystem-observation-v1\n");
        hasher.update(serde_json::to_vec(self)?);
        let mut text = String::with_capacity(64);
        for byte in hasher.finalize() {
            write!(text, "{byte:02x}").expect("String writes cannot fail");
        }
        Ok(text)
    }
}

/// Query only the supplied descriptor. Unsupported filesystem operations and
/// insufficient privilege remain explicit unavailable observations, never proof
/// that quota enforcement is active. The input must refer to a directory.
pub fn observe(directory: &File) -> io::Result<FilesystemObservation> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesystem observation requires a directory descriptor",
        ));
    }
    let capacity = kernel::capacity(directory.as_fd())?;
    let project = kernel::project(directory.as_fd()).map(|(id, inherit)| ProjectObservation {
        id,
        children_inherit_project: inherit,
        state: Observation::from_result(kernel::quota_state(directory.as_fd())),
        limits: Observation::from_result(kernel::quota_limits(directory.as_fd(), id)),
    });
    Ok(FilesystemObservation {
        device: metadata.dev(),
        inode: metadata.ino(),
        filesystem_type: capacity.filesystem_type,
        total_bytes: capacity.total_bytes,
        available_bytes: capacity.available_bytes,
        total_inodes: capacity.total_inodes,
        available_inodes: capacity.available_inodes,
        project: Observation::from_result(project),
    })
}

#[cfg(test)]
mod tests;

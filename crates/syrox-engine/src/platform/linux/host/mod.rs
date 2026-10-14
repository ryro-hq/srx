use std::path::{Path, PathBuf};

use thiserror::Error;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
#[path = "linux.rs"]
mod linux;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCapabilityStatus {
    Available(String),
    Unavailable(String),
    NeedsActiveProbe(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapability {
    pub name: &'static str,
    pub status: HostCapabilityStatus,
}

#[derive(Debug, Clone)]
pub struct HostInspection {
    pub cgroup_parent: PathBuf,
    pub capabilities: Vec<HostCapability>,
}

#[derive(Debug, Error)]
pub enum HostInspectError {
    #[error("cgroup parent must resolve beneath /sys/fs/cgroup")]
    InvalidCgroupParent,
}

/// With `probe_cgroup`, briefly create a child, verify its cpu/memory/pids
/// controls and attempt migration of a gated copy of the running `srx` into
/// that child. This tests this caller's source cgroup only; future callers
/// elsewhere still require an executor placed within the delegated subtree.
pub fn inspect_host_with_probe(
    parent: Option<&Path>,
    probe_cgroup: bool,
) -> Result<HostInspection, HostInspectError> {
    #[cfg(target_os = "linux")]
    {
        linux::inspect(parent, probe_cgroup)
    }
}

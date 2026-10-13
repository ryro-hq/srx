use super::BuildError;
use crate::store::{ContentDigest, Store};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildRecoveryState {
    /// The coordinator still owns its operation; nothing was changed.
    Active,
    /// Launch was revoked, resource quiescence proved, and private state removed.
    Recovered,
    /// Evidence is incomplete or cleanup failed; the record was retained.
    Retained(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildRecoveryEntry {
    pub operation: String,
    pub state: BuildRecoveryState,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuildRecoveryReport {
    pub entries: Vec<BuildRecoveryEntry>,
}

/// Recover executor journals in this Store. Live coordinators are skipped;
/// uncertain operations are retained and reported individually. Recovery never
/// publishes, resumes or labels a build result as successful, nor deletes CAS roots.
pub fn recover_builds(store: &Store) -> Result<BuildRecoveryReport, BuildError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        super::journal::recover(store)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = store;
        Err(BuildError::UnsupportedPlatform)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuildIndexReport {
    pub indexed: usize,
    pub skipped: usize,
    pub removed_stale: usize,
    pub conflicts: Vec<ContentDigest>,
}

/// Reconstruct the local action index from managed build roots. Referenced bytes
/// and receipt semantics are verified and retention durability is re-confirmed.
/// Journals and unrooted CAS objects never supply reconstruction authority.
pub fn rebuild_build_index(store: &Store) -> Result<BuildIndexReport, BuildError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        super::cache::rebuild(store)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = store;
        Err(BuildError::UnsupportedPlatform)
    }
}

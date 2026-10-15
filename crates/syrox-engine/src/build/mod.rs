//! Executing builds and publishing their outputs.
//!
//! # Choosing an execution backend
//!
//! [`BuildProfile::HostBootstrap`] uses the host toolchain selected by the user.
//! [`BuildProfile::Managed`] receives inputs and a worker verified through
//! descriptors. Each backend performs preflight, consults the cache and prepares
//! execution. See [`bootstrap`] for toolchain identity and [`managed`] for worker
//! admission.
//!
//! # Publishing after settlement
//!
//! Results are published only after the execution that could still modify them
//! has ended. Cancellation also passes through settlement before releasing files
//! retained by the build. [`publication`](../../src/syrox_engine/build/publication.rs.html) validates outputs after the backend has
//! checked settlement; [`journal`](../../src/syrox_engine/build/journal/mod.rs.html) retains the state needed for recovery.
//!
//! [`shared`](../../src/syrox_engine/build/shared.rs.html) coordinates requests for the same producer. [`cancellation`](../../src/syrox_engine/build/cancellation/mod.rs.html) tracks
//! each consumer's interest, and [`records`](../../src/syrox_engine/build/records.rs.html) owns the bytes used for build identity.

use crate::{
    plan::Plan,
    store::{ContentDigest, RootName, Store, StoreError},
};
use std::path::{Path, PathBuf};
use thiserror::Error;
pub mod bootstrap;
pub(crate) mod cache;
pub(crate) mod cancellation;
pub(crate) mod journal;
pub mod maintenance;
pub mod managed;
pub(crate) mod policy;
#[allow(unsafe_code)]
pub(crate) mod profile;
mod program;
pub(crate) mod publication;
pub(crate) mod records;
pub(crate) mod shared;
use crate::cancellation::Cancellation;
pub(crate) use bootstrap::linux::retained_build_with_inputs;
#[cfg(target_arch = "x86_64")]
pub(crate) use bootstrap::linux::{PreparedLookup, build_prepared, prepare_managed};
use bootstrap::{linux, sandbox};
pub use maintenance::{
    BuildIndexReport, BuildRecoveryEntry, BuildRecoveryReport, BuildRecoveryState,
    rebuild_build_index, recover_builds,
};
pub use program::{
    BuildPart, BuildPath, BuildProcess, BuildProfile, BuildProgram, BuildSourceFormat, BuildStep,
    BuildText, MAX_BUILD_PROGRAM_BYTES,
};

pub(crate) use crate::result::artifact::MAX_OUTPUT_BYTES;
pub(crate) const MAX_STANDARD_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_LARGE_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
pub(crate) const MANAGED_PROFILE: &str = "syrox-managed-program-x86_64-v2";
pub(crate) const PROFILE: &str = "syrox-host-program-x86_64-v3";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildResources {
    Standard,
    Large,
}

#[derive(Clone, Copy, Debug)]
struct ResourceEnvelope {
    memory: u64,
    tasks: u32,
    cpu_percent: u32,
    nofile: u32,
    output_bytes: u64,
    work_tmpfs: u64,
    output_tmpfs: u64,
}

impl BuildResources {
    pub(crate) const fn output_limit(self) -> u64 {
        self.envelope().output_bytes
    }
    const fn envelope(self) -> ResourceEnvelope {
        match self {
            Self::Standard => ResourceEnvelope {
                memory: 805_306_368,
                tasks: 64,
                cpu_percent: 100,
                nofile: 256,
                output_bytes: MAX_STANDARD_OUTPUT_BYTES,
                work_tmpfs: 402_653_184,
                output_tmpfs: 67_108_864,
            },
            Self::Large => ResourceEnvelope {
                memory: 1_610_612_736,
                tasks: 256,
                cpu_percent: 100,
                nofile: 4096,
                output_bytes: MAX_OUTPUT_BYTES,
                // glibc's source and intermediate archives coexist in /work.
                work_tmpfs: 1_073_741_824,
                output_tmpfs: 134_217_728,
            },
        }
    }
}

/// A selected build with its declared inputs. Caller selections are checked
/// against the locked Plan before any effects.
#[derive(Clone, Debug)]
pub struct BuildSpecification {
    pub package: crate::plan::PlanPackageId,
    pub source_directory: String,
    pub timeout_seconds: u32,
    pub program: BuildProgram,
    pub inputs: Vec<BuildInput>,
}

#[derive(Clone, Debug)]
pub struct BuildInput {
    pub output: crate::result::RetainedOutput,
}

impl BuildSpecification {
    pub const fn resources(&self) -> BuildResources {
        self.program.resources
    }

    fn validate(&self) -> Result<(), BuildError> {
        self.program.validate()?;
        if !relative_path(&self.source_directory)
            || self.source_directory.contains('/')
            || !(1..=1800).contains(&self.timeout_seconds)
        {
            return Err(BuildError::InvalidRequest);
        }
        Ok(())
    }
}

pub(crate) use crate::result::artifact::relative_path;

#[derive(Clone, Debug)]
pub enum BuildExecution {
    Built {
        operation: String,
    },
    Shared {
        operation: String,
    },
    Cached,
}

/// An admitted result with live custody of its authenticated object closure.
/// Clones share granular retention without holding a global Store barrier.
/// Removing a durable root does not collect these bytes while a handle lives;
/// the handle does not grant new execution or publication authority.
#[derive(Clone, Debug)]
pub struct BuildResult {
    /// Complete authenticated object closure, held independently of durable roots.
    pub(crate) retention: crate::store::ObjectLease,
    /// Cache hits have no new operation. Shared consumers name their producer.
    pub execution: BuildExecution,
    pub action: ContentDigest,
    pub artifact: ContentDigest,
    pub receipt: ContentDigest,
    pub toolchain: Option<ContentDigest>,
    pub files: usize,
    pub root: RootName,
}

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("managed build executor is unavailable")]
    UnsupportedProfile,
    #[error(
        "build requires Linux x86_64 with systemd user services, Bubblewrap and setpriv Landlock support"
    )]
    UnsupportedPlatform,
    #[error(
        "invalid build request: a bounded program, declared paths and a valid deadline are required"
    )]
    InvalidRequest,
    #[error("build inputs or instruction program do not match the selected Plan")]
    UnsupportedInputs,
    #[error("build source is absent or exceeds the selected resource limit")]
    MissingSource,
    #[error("host build requires the explicitly selected /usr toolchain")]
    Toolchain,
    #[error("build host capability unavailable: {0}")]
    Capability(&'static str),
    #[error("toolchain inventory refused: {0}")]
    Inventory(String),
    #[error("build input changed during the operation")]
    InputChanged,
    #[error("build deadline elapsed")]
    Timeout,
    #[error("build cancelled")]
    Cancelled,
    #[error("build payload or sandbox failed: {0}")]
    Execution(String),
    #[error("build resource settlement is unconfirmed ({reason}); private staging retained at {}{}", stage.display(), primary.as_ref().map_or_else(String::new, |error| format!("; original failure: {error}")))]
    Settlement {
        stage: PathBuf,
        reason: &'static str,
        #[source]
        primary: Option<Box<BuildError>>,
    },
    #[error("invalid, missing, or oversized build output")]
    Output,
    #[error("build cleanup failed: {0}")]
    Cleanup(std::io::Error),
    #[error("build failed ({primary}) and private staging cleanup also failed: {cleanup}")]
    FailureAndCleanup {
        #[source]
        primary: Box<BuildError>,
        cleanup: std::io::Error,
    },
    #[error("build operation journal failed: {0}")]
    Journal(String),
    #[error("build failed ({primary}); operation journal also failed: {journal}")]
    FailureAndJournal {
        #[source]
        primary: Box<BuildError>,
        journal: String,
    },
    #[error(
        "build result was published under {root}, but its operation journal update failed: {journal}"
    )]
    PublishedAndJournal {
        root: RootName,
        journal: String,
    },
    #[error("build action index refused: {0}")]
    Cache(String),
    #[error("divergent build results for action {action}: receipts {first} and {second}")]
    DivergentResults {
        action: ContentDigest,
        first: ContentDigest,
        second: ContentDigest,
    },
    #[error("build result was published under {root}, but action indexing failed: {source}")]
    PublishedAndCache {
        root: RootName,
        #[source]
        source: Box<BuildError>,
    },
    #[error("build result was published under {root}, but live retention failed: {source}")]
    PublishedAndRetention {
        root: RootName,
        #[source]
        source: StoreError,
    },
    #[error("shared build producer {operation}: {reason}")]
    SharedProducer {
        operation: String,
        reason: String,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Archive(#[from] crate::acquire::archive::ArchiveError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Builds with a caller-authorized host toolchain. `worker` must be the trusted
/// srx executable implementing the internal worker dispatch. Publication is last,
/// after payload quiescence, unit finalization, artifact validation, input recheck
/// and staging cleanup.
pub fn execute_build(
    plan: &Plan,
    request: &BuildSpecification,
    store: &Store,
    root: &RootName,
    toolchain: &Path,
    worker: &Path,
) -> Result<BuildResult, BuildError> {
    execute_build_with_cancellation(
        plan,
        request,
        store,
        root,
        toolchain,
        worker,
        &Cancellation::default(),
    )
}

/// Cancellable form of [`execute_build`]. Concurrent consumers share a producer
/// with independent interests. A cancelled caller gets no new custom root, while
/// the shared managed result may still be published for another caller. The first
/// caller continues coordinating that producer until completion. Cancellation of
/// the last interest before commit prevents publication; a commit already in
/// progress finishes with its actual durable/uncertain outcome.
pub fn execute_build_with_cancellation(
    plan: &Plan,
    request: &BuildSpecification,
    store: &Store,
    root: &RootName,
    toolchain: &Path,
    worker: &Path,
    cancellation: &Cancellation,
) -> Result<BuildResult, BuildError> {
    request.validate()?;
    cancellation.check()?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        linux::build(
            plan,
            request,
            store,
            Some(root),
            toolchain,
            worker,
            cancellation,
        )
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (plan, request, store, root, toolchain, worker);
        Err(BuildError::UnsupportedPlatform)
    }
}

/// Check whether this host can start a new build with the configured bootstrap
/// toolchain. Existing cached results can remain usable when this check fails.
pub fn check_build_host(toolchain: &Path) -> Result<(), BuildError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        if toolchain != Path::new("/usr") {
            return Err(BuildError::Toolchain);
        }
        crate::platform::linux::fd::require_build_landlock()?;
        sandbox::preflight()
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = toolchain;
        Err(BuildError::UnsupportedPlatform)
    }
}

pub(crate) fn build_managed(
    plan: &Plan,
    request: &BuildSpecification,
    store: &Store,
    toolchain: &Path,
    worker: &Path,
    cancellation: &Cancellation,
) -> Result<BuildResult, BuildError> {
    request.validate()?;
    cancellation.check()?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        linux::build(
            plan,
            request,
            store,
            None,
            toolchain,
            worker,
            cancellation,
        )
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (plan, request, store, toolchain, worker);
        Err(BuildError::UnsupportedPlatform)
    }
}

impl From<crate::result::artifact::ArtifactError> for BuildError {
    fn from(error: crate::result::artifact::ArtifactError) -> Self {
        match error {
            crate::result::artifact::ArtifactError::Output => Self::Output,
            crate::result::artifact::ArtifactError::Cancelled => Self::Cancelled,
            crate::result::artifact::ArtifactError::Io(error) => Self::Io(error),
        }
    }
}

// Cancellation remains distinguishable; materialization failures do not imply settlement.
fn materialization_error(error: &crate::result::MaterializationError) -> BuildError {
    if matches!(
        error,
        crate::result::MaterializationError::Cancelled
    ) {
        BuildError::Cancelled
    } else {
        BuildError::Cache(error.to_string())
    }
}

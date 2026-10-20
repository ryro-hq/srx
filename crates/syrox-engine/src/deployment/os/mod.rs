//! Persistent generations and application of Os configuration.
//!
//! # Preparing and applying a generation
//!
//! The manifest describes a generation; it does not by itself authorize a start.
//! [`installation`](../../../src/syrox_engine/deployment/os/installation/mod.rs.html) associates its objects with the Store. [`apply`](../../../src/syrox_engine/deployment/os/apply/mod.rs.html) records
//! effects in [`activation`](../../../src/syrox_engine/deployment/os/activation/mod.rs.html) before executing them. [`launch_binding`](../../../src/syrox_engine/deployment/os/launch_binding/mod.rs.html) binds an
//! invocation to the selected generation, process and context.
//!
//! # Recovering interrupted effects
//!
//! [`recovery`](../../../src/syrox_engine/deployment/os/apply/recovery/mod.rs.html) checks records and observed execution to continue settlement
//! without accidentally starting a generation. A partial apply does not make the
//! whole generation applied or permit collection of old resources.

pub(crate) mod abandon;
pub(crate) mod activation;
pub(crate) mod apply;
pub(crate) mod diff;
pub(crate) mod installation;
pub(crate) mod launch_binding;
pub(crate) mod paths;
pub mod profile;
pub(crate) mod public;
pub(crate) mod runtime;
pub(crate) mod status;
pub(crate) mod unit_files;

pub(crate) use crate::deployment::manifest::encoding as manifest;
pub(crate) use crate::deployment::manifest::encoding::{
    GenerationManifest, LauncherIdentity, ShellSessionManifest,
};
pub(crate) use crate::deployment::manifest::{GenerationError, PreparedGeneration, shell_snapshot};

pub use abandon::{OsAbandonment, OsAbandonmentError, abandon_os_operation};
pub use apply::recovery::{
    OsRecoveryEffect, OsRecoveryError, OsRecoveryReport, OsRecoveryRequest, OsRecoveryState,
    recover_os_generation, recover_os_generation_with_identity,
};
pub use apply::{
    OsApplyError, OsApplyReport, OsApplyRequest, OsApplyResource, OsApplyResourceState,
    OsRollbackRequest, OsSelectionAuthority, apply_os_generation,
    apply_os_generation_with_authority, rollback_os_generation,
};
pub use public::{
    OsCandidateEntry, OsCandidatePhase, OsGenerationError, OsGenerationSummary, OsInstallation,
    OsPreparation, diff_os_generations, initialize_os_installation, inspect_os_generation,
    list_os_generations, open_os_installation, prepare_empty_os_generation, prepare_os_generation,
};
pub use status::{
    OsStatus, OsStatusBinding, OsStatusBootFence, OsStatusEffect, OsStatusEpoch, OsStatusError,
    inspect_os_status,
};

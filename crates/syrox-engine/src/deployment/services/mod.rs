//! Persistent generations and application of Services configuration.
//!
//! # Preparing and applying a generation
//!
//! The manifest describes a generation; it does not by itself authorize a start.
//! [`installation`](../../../src/syrox_engine/deployment/services/installation/mod.rs.html) associates its objects with the Store. [`apply`](../../../src/syrox_engine/deployment/services/apply/mod.rs.html) records
//! effects in [`activation`](../../../src/syrox_engine/deployment/services/activation/mod.rs.html) before executing them. [`launch_binding`](../../../src/syrox_engine/deployment/services/launch_binding/mod.rs.html) binds an
//! invocation to the selected generation, process and context.
//!
//! # Recovering interrupted effects
//!
//! [`recovery`](../../../src/syrox_engine/deployment/services/apply/recovery/mod.rs.html) checks records and observed execution to continue settlement
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

pub use abandon::{ServicesAbandonment, ServicesAbandonmentError, abandon_services_operation};
pub use apply::recovery::{
    ServicesRecoveryEffect, ServicesRecoveryError, ServicesRecoveryReport, ServicesRecoveryRequest,
    ServicesRecoveryState, recover_services_generation, recover_services_generation_with_identity,
};
pub use apply::{
    ServicesApplyError, ServicesApplyReport, ServicesApplyRequest, ServicesApplyResource,
    ServicesApplyResourceState, ServicesRollbackRequest, ServicesSelectionAuthority,
    apply_services_generation, apply_services_generation_with_authority,
    rollback_services_generation,
};
pub use public::{
    ServicesCandidateEntry, ServicesCandidatePhase, ServicesGenerationError,
    ServicesGenerationSummary, ServicesInstallation, ServicesPreparation,
    diff_services_generations, initialize_services_installation, inspect_services_generation,
    list_services_generations, open_services_installation, prepare_empty_services_generation,
    prepare_services_generation,
};
pub use status::{
    ServicesStatus, ServicesStatusBinding, ServicesStatusBootFence, ServicesStatusEffect,
    ServicesStatusEpoch, ServicesStatusError, inspect_services_status,
};

//! Gerações persistentes e aplicação da configuração Os.
//!
//! O manifesto descreve a geração; sozinho, não autoriza um start. A instalação
//! associa seus objetos à Store e o apply registra os efeitos antes de executá-los.
//! A recuperação confere esses registros e a execução observada para continuar
//! o fechamento sem iniciar uma geração por acidente.

pub(crate) mod abandon;
pub(crate) mod activation;
pub(crate) mod apply;
pub(crate) mod diff;
pub(crate) mod installation;
pub(crate) mod launch_binding;
pub(crate) mod paths;
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
    recover_os_generation,
};
pub use apply::{
    OsApplyError, OsApplyReport, OsApplyRequest, OsApplyResource, OsApplyResourceState,
    OsRollbackRequest, apply_os_generation, rollback_os_generation,
};
pub use public::{
    OsCandidateEntry, OsCandidatePhase, OsGenerationError, OsGenerationSummary, OsInstallation,
    OsPreparation, diff_os_generations, initialize_os_installation, inspect_os_generation,
    list_os_generations, prepare_os_generation,
};
pub use status::{
    OsStatus, OsStatusBinding, OsStatusBootFence, OsStatusEffect, OsStatusEpoch, OsStatusError,
    inspect_os_status,
};

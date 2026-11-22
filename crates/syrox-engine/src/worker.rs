pub use crate::build::managed::entry::run_managed_build_entry;
#[cfg(target_arch = "x86_64")]
pub use crate::build::system::namespace::run_payload as run_system_build_payload;
pub use crate::execution::launcher::owner::{SessionOwnerError, run_session_owner};
pub use crate::execution::launcher::service::{ServiceWorkerError, run_session_service};
pub use crate::execution::launcher::services::{ServicesWorkerError, run_services_worker};
pub use crate::execution::native::{
    managed_command_runtime_helper, managed_runtime_helper, reraise_shell_command_signal,
    runtime_helper,
};
pub use crate::runtime::command_proxy::frontend::{ShellCommandExit, run_shell_command};

use crate::build::{
    BuildError,
    bootstrap::{sandbox, worker},
};
use std::path::{Path, PathBuf};

/// System IR execution only after namespace/manager/resource admission; this
/// grants neither execution admission nor Store/result-publication authority.
///
/// # Safety
/// Dedicated single-threaded payload child; exit after return, including errors.
/// Caller authenticates the action, budget, helper observation, immutable input
/// mounts and namespace lifecycle. Policy installation closes descriptors >=3.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub unsafe fn run_system_build_worker(
    action: &crate::build::system::SystemBuildAction,
    observation: &crate::system::workspace::WorkspaceObservation,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<(), BuildError> {
    // SAFETY: delegated dedicated-process and authenticated admission contract.
    unsafe { worker::run_system(action, observation, cancellation) }
}

/// Internal subprocess entry; requires the sandbox's private mount layout.
/// Calling this function does not confer build or Store publication authority.
pub fn run_build_worker(source_directory: &str, action: &str) -> Result<(), BuildError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        worker::run(source_directory, action)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (source_directory, action);
        Err(BuildError::UnsupportedPlatform)
    }
}

/// Internal Managed IR subprocess entry; no Store or journal authority is granted.
///
/// # Safety
/// The caller must be a dedicated single-threaded process and exit after return.
#[allow(unsafe_code)]
pub unsafe fn run_managed_build_worker(
    source_directory: &str,
    action: &str,
) -> Result<(), BuildError> {
    // SAFETY: the caller establishes the dedicated process contract; the helper
    // validates its private namespace before installing process-wide policy.
    unsafe { worker::run_managed(source_directory, action) }
}

/// Internal trusted service entry. The persistent launch authorization is checked
/// under its own lock before any payload is started. This is not a recipe API.
pub fn run_build_gate(
    operation: &Path,
    source_directory: &str,
    blocked: &[PathBuf],
) -> Result<(), BuildError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        sandbox::run_gate(operation, source_directory, blocked)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (operation, source_directory, blocked);
        Err(BuildError::UnsupportedPlatform)
    }
}

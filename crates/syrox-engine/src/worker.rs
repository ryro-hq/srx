pub use crate::build::managed::entry::run_managed_build_entry;
pub use crate::execution::launcher::os::{OsWorkerError, run_os_service};
pub use crate::execution::launcher::owner::{SessionOwnerError, run_session_owner};
pub use crate::execution::launcher::service::{ServiceWorkerError, run_session_service};
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

//! Configuration and commands for a Shell session.
//!
//! The session keeps its outputs, secrets and files alive while commands can use
//! them. In Managed mode, the owner coordinates services and closes the session
//! after settlement. Persistent installation belongs to [`super::os`].
//!
//! See [`commands`](../../../src/syrox_engine/deployment/shell/commands.rs.html) for the public alias directory and its broker checks, and
//! [`managed`](../../../src/syrox_engine/deployment/shell/managed/mod.rs.html) for service supervision, retained state and recovery.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitStatus;

use crate::{
    cancellation::Cancellation, deployment::manifest::PreparedConsumer, plan::PlanCommandArgument,
    plan::PlanConsumerKind, project::PreparedPlan, runtime::RuntimeConfiguration,
};
use thiserror::Error;

pub(crate) mod command_broker;
pub(crate) mod commands;
pub(crate) mod files;
pub(crate) mod managed;
pub(crate) use crate::execution::journal as ownership;
mod secrets;
mod state;
mod terminal;
pub use terminal::PreparedShellTerminal;
#[cfg(test)]
mod tests;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("the selected consumer is not a Shell")]
    NotShell,
    #[error(
        "Shell service processes require session supervision and explicit managed-session configuration"
    )]
    ProcessesUnsupported,
    #[error("session state requires managed Shell supervision")]
    StateUnsupported,
    #[error("managed Shell supervision failed: {0}")]
    Supervision(String),
    #[error("Shell has no exposed command `{0}`")]
    MissingCommand(String),
    #[error("configuration reference requires a service namespace")]
    MissingNamespace,
    #[error("session cancelled")]
    Cancelled,
    #[error(transparent)]
    Deployment(Box<crate::deployment::manifest::DeploymentError>),
    #[error(transparent)]
    Runtime(#[from] crate::runtime::RuntimeError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
impl From<crate::deployment::manifest::DeploymentError> for SessionError {
    fn from(error: crate::deployment::manifest::DeploymentError) -> Self {
        Self::Deployment(Box::new(error))
    }
}

/// Reject unsupported destinations, missing entries and unimplemented service
/// supervision before Store initialization, construction or file materialization.
pub fn validate_shell_command(
    prepared: &PreparedPlan,
    consumer: &str,
    command: &str,
) -> Result<(), SessionError> {
    let selected = crate::deployment::manifest::select_consumer(prepared, consumer)?;
    validate_consumer(selected.consumer())?;
    if !selected.exposures().contains_key(command) {
        return Err(SessionError::MissingCommand(command.into()));
    }
    Ok(())
}

/// Pure managed-profile selection before Store or manager effects.
pub fn validate_managed_shell_command(
    prepared: &PreparedPlan,
    consumer: &str,
    command: &str,
) -> Result<(), SessionError> {
    let selected = crate::deployment::manifest::select_consumer(prepared, consumer)?;
    if selected.consumer().kind() != PlanConsumerKind::Shell {
        return Err(SessionError::NotShell);
    }
    if !selected.exposures().contains_key(command) {
        return Err(SessionError::MissingCommand(command.into()));
    }
    if selected
        .consumer()
        .services()
        .iter()
        .map(|service| service.processes().len())
        .sum::<usize>()
        >= ownership::MAX_SESSION_ATTEMPTS
    {
        return Err(SessionError::Supervision(
            "Shell exceeds session attempt capacity".into(),
        ));
    }
    Ok(())
}

fn validate_consumer(consumer: &crate::plan::PlanConsumer) -> Result<(), SessionError> {
    if consumer
        .services()
        .iter()
        .any(|s| !s.secrets().is_empty())
    {
        return Err(SessionError::Supervision(
            "secrets require managed Shell supervision".into(),
        ));
    }
    if consumer
        .services()
        .iter()
        .any(|service| service.state() == crate::plan::PlanServiceState::Session)
    {
        return Err(SessionError::StateUnsupported);
    }
    if consumer.kind() != PlanConsumerKind::Shell {
        return Err(SessionError::NotShell);
    }
    if consumer
        .services()
        .iter()
        .any(|service| !service.processes().is_empty())
    {
        return Err(SessionError::ProcessesUnsupported);
    }
    Ok(())
}

/// Owns the prepared outputs and private configuration until namespace settlement.
/// This first execution mode is noninteractive; it does not claim PTY/job control
/// or a durable session supervisor. Explicit close reports configuration cleanup.
pub struct ShellSession {
    prepared: PreparedConsumer,
    files: files::SessionFiles,
    state: Option<state::SessionState>,
    secrets: secrets::SessionSecrets,
}

impl std::fmt::Debug for ShellSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ShellSession")
            .finish_non_exhaustive()
    }
}

impl ShellSession {
    pub fn new(
        prepared: PreparedConsumer,
        cancellation: &Cancellation,
    ) -> Result<Self, SessionError> {
        validate_consumer(prepared.consumer())?;
        if cancellation.is_cancelled() {
            return Err(SessionError::Cancelled);
        }
        let files =
            files::SessionFiles::new(prepared.consumer(), cancellation).map_err(|error| {
                if crate::cancellation::is_cancellation_io(&error) {
                    SessionError::Cancelled
                } else {
                    SessionError::Io(error)
                }
            })?;
        Ok(Self {
            prepared,
            files,
            state: None,
            secrets: secrets::SessionSecrets::default(),
        })
    }

    pub fn run_command(
        &self,
        name: &str,
        extra_arguments: &[OsString],
        cwd: &Path,
        cancellation: &Cancellation,
    ) -> Result<ExitStatus, SessionError> {
        self.run_attached(name, extra_arguments, cwd, None, cancellation)
    }

    /// Execute on a caller-owned dedicated PTY slave. Relay, terminal recovery
    /// and the master endpoint belong to the caller. This does not activate
    /// service processes or compose a PATH for other managed commands.
    pub fn run_command_with_terminal(
        &self,
        name: &str,
        extra_arguments: &[OsString],
        cwd: &Path,
        terminal: std::os::fd::BorrowedFd<'_>,
        cancellation: &Cancellation,
    ) -> Result<ExitStatus, SessionError> {
        if cancellation.is_cancelled() {
            return Err(SessionError::Cancelled);
        }
        crate::platform::linux::fd::terminal::validate_slave(terminal)?;
        self.run_attached(
            name,
            extra_arguments,
            cwd,
            Some(terminal),
            cancellation,
        )
    }

    fn run_attached(
        &self,
        name: &str,
        extra_arguments: &[OsString],
        cwd: &Path,
        terminal: Option<std::os::fd::BorrowedFd<'_>>,
        cancellation: &Cancellation,
    ) -> Result<ExitStatus, SessionError> {
        if cancellation.is_cancelled() {
            return Err(SessionError::Cancelled);
        }
        let key = self
            .prepared
            .exposures()
            .get(name)
            .ok_or_else(|| SessionError::MissingCommand(name.into()))?;
        let invocation = &self.prepared.invocations()[key];
        let service = key.0.as_deref();
        let mut arguments = invocation
            .arguments()
            .iter()
            .map(|argument| render(argument, service).map(OsString::from))
            .collect::<Result<Vec<_>, _>>()?;
        arguments.extend_from_slice(extra_arguments);
        let environment = invocation
            .environment()
            .iter()
            .map(|entry| Ok((entry.name.clone(), render(&entry.value, service)?)))
            .collect::<Result<BTreeMap<_, _>, SessionError>>()?;
        let configuration = if let Some(service) = service {
            RuntimeConfiguration::new(
                service.to_owned(),
                self.files.service(service)?,
                environment,
            )?
        } else {
            RuntimeConfiguration::default()
        };
        let configuration = match service {
            Some(service) => self.secrets.configure(service, configuration)?,
            None => configuration,
        };
        let configuration = match (self.state.as_ref(), service) {
            (Some(state), Some(service)) => state.configure(service, configuration)?,
            _ => configuration,
        };
        if let Some(terminal) = terminal {
            return Ok(crate::runtime::run_runtime_with_terminal(
                invocation.closure(),
                &arguments,
                cwd,
                &configuration,
                terminal,
                cancellation,
            )?);
        }
        Ok(
            crate::runtime::run_runtime_configured_with_cancellation(
                invocation.closure(),
                &arguments,
                cwd,
                &configuration,
                cancellation,
            )?,
        )
    }

    pub fn close(self) -> Result<(), SessionError> {
        self.files.close().map_err(Into::into)
    }
}

fn render(argument: &PlanCommandArgument, service: Option<&str>) -> Result<String, SessionError> {
    match argument {
        PlanCommandArgument::SecretFile(name) => Ok(format!(
            "/syrox/secrets/{}/{name}",
            service.ok_or(SessionError::MissingNamespace)?
        )),
        PlanCommandArgument::StateDirectory => Ok(format!(
            "/syrox/state/{}",
            service.ok_or(SessionError::MissingNamespace)?
        )),
        PlanCommandArgument::Literal(value) => Ok(value.clone()),
        PlanCommandArgument::File(path) => Ok(format!(
            "/syrox/config/{}/{}",
            service.ok_or(SessionError::MissingNamespace)?,
            path
        )),
    }
}

pub use managed::inspection::{
    ManagedSessionEntry, ManagedSessionEvidence, list_managed_shell_sessions,
    recover_managed_shell_session,
};
pub use managed::public::{ManagedShell, ManagedShellConfiguration};
pub use managed::recovery::{
    AttemptRecovery as ShellAttemptRecovery, AttemptRecoveryOutcome as ShellAttemptOutcome,
    RecoveryStage as ShellRecoveryStage, RoleRetentionRecovery, RoleRetentionRecoveryOutcome,
    ShellRecoveryReport,
};

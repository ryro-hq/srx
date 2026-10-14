use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::Instant;

use crate::deployment::os::{LauncherIdentity, shell_snapshot};
use crate::execution::launcher::coordinator::{OwnerHandle, OwnerStart, start_owner};
use crate::execution::launcher::service_coordinator::{ServiceGroup, ServiceRoleStart};
use crate::platform::linux::boot::BootId;
use crate::runtime::launch_preparation::prepare_runtime_launch;
use crate::{
    cancellation::Cancellation, deployment::manifest::PreparedConsumer, plan::PlanConsumerKind,
    store::ContentDigest, store::ObjectLease,
};

use super::ownership::SessionJournal;
use super::{SessionError, ShellSession, files::SessionFiles};

pub(crate) mod inspection;
mod proxy;
pub(crate) mod public;
mod record;
pub(crate) mod recovery;
mod supervision;

pub(crate) struct ManagedShellStart<'a> {
    pub worker: &'a Path,
    pub worker_digest: ContentDigest,
    pub bus_socket: &'a Path,
    /// Existing owned mode-0700 directory, retained for recovery.
    pub private_directory: &'a Path,
    pub journal: &'a Arc<SessionJournal>,
    pub retention: &'a ObjectLease,
    pub cwd: &'a Path,
    pub secrets: &'a crate::config::ShellSecretSources,
}

pub(crate) struct ManagedShellSession {
    shell: ShellSession,
    owner: OwnerHandle,
    services: ServiceGroup,
    cwd: PathBuf,
    journal: Arc<SessionJournal>,
    worker_digest: ContentDigest,
}

impl ManagedShellSession {
    pub(crate) fn start(
        prepared: PreparedConsumer,
        start: &ManagedShellStart<'_>,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Self, SessionError> {
        if prepared.consumer().kind() != PlanConsumerKind::Shell {
            return Err(SessionError::NotShell);
        }
        let cwd = std::path::absolute(start.cwd)?;
        let private = std::path::absolute(start.private_directory)?;
        if cwd.starts_with(&private) || private.starts_with(&cwd) {
            return Err(SessionError::Supervision(
                "working directory overlaps managed session state".into(),
            ));
        }
        if cwd.to_str().is_none()
            || !crate::execution::resources::valid_managed_working_directory(&cwd)
        {
            return Err(SessionError::Supervision(
                "invalid managed Shell working directory".into(),
            ));
        }
        let process_count = prepared
            .consumer()
            .services()
            .iter()
            .map(|service| service.processes().len())
            .sum::<usize>();
        if process_count >= super::ownership::MAX_SESSION_ATTEMPTS {
            return Err(SessionError::Supervision(
                "Shell exceeds session attempt capacity".into(),
            ));
        }
        let (shell, launches, manifest) =
            prepare_shell(prepared, start, &cwd, cancellation, deadline)?;
        let pin = ContentDigest::sha256(&manifest);
        let mut owner = start_owner(
            OwnerStart {
                worker: start.worker,
                worker_digest: start.worker_digest,
                bus_socket: start.bus_socket,
                private_directory: start.private_directory,
                manifest: &manifest,
                pin,
                retention: start.retention,
            },
            start.journal,
            cancellation,
            deadline,
        )
        .map_err(supervision)?;
        let services = match ServiceGroup::start(
            &owner,
            launches,
            start.private_directory,
            Arc::clone(start.journal),
            cancellation,
            deadline,
        ) {
            Ok(services) => services,
            Err(error) => {
                // The group's admission thread retains uncertain attempts and
                // closes admission before returning an unsuccessful start.
                let cleanup = Cancellation::default();
                let until = Instant::now() + std::time::Duration::from_secs(10);
                let _ = start.journal.begin_closing(
                    &owner.session,
                    "Shell startup failed",
                    &cleanup,
                    until,
                );
                let _ = owner.close(start.journal, &cleanup, until);
                return Err(SessionError::Supervision(format!(
                    "{error}; configuration retained at {}",
                    shell.files.path().display(),
                )));
            }
        };
        Ok(Self {
            shell,
            owner,
            services,
            cwd,
            journal: Arc::clone(start.journal),
            worker_digest: start.worker_digest,
        })
    }

    pub(crate) fn run_command(
        &self,
        name: &str,
        arguments: &[OsString],
        cancellation: &Cancellation,
    ) -> Result<ExitStatus, SessionError> {
        self.run_attached(name, arguments, None, cancellation)
    }

    pub(crate) fn run_command_with_terminal(
        &self,
        name: &str,
        arguments: &[OsString],
        terminal: std::os::fd::BorrowedFd<'_>,
        cancellation: &Cancellation,
    ) -> Result<ExitStatus, SessionError> {
        if cancellation.is_cancelled() {
            return Err(SessionError::Cancelled);
        }
        crate::platform::linux::fd::terminal::validate_slave(terminal)?;
        self.run_attached(name, arguments, Some(terminal), cancellation)
    }

    fn run_attached(
        &self,
        name: &str,
        arguments: &[OsString],
        terminal: Option<std::os::fd::BorrowedFd<'_>>,
        cancellation: &Cancellation,
    ) -> Result<ExitStatus, SessionError> {
        supervision::supervise(
            self.foreground_authority(),
            cancellation,
            |local| {
                self.run_proxy(
                    name,
                    arguments,
                    crate::runtime::command_proxy::launch::Attachment::Borrowed(terminal),
                    local,
                )
            },
        )
        .map_err(supervision)
    }

    /// The existing authority monitor spans negotiation, execution, drain and
    /// restoration. Its cancellation reaches the runtime through the frontend's
    /// operation token, without treating ordinary PTY EOF as session completion.
    pub(crate) fn run_prepared_terminal(
        &self,
        name: &str,
        arguments: &[OsString],
        terminal: super::terminal::PreparedShellTerminal,
        cancellation: &Cancellation,
    ) -> Result<ExitStatus, SessionError> {
        supervision::supervise(
            self.foreground_authority(),
            cancellation,
            |local| {
                terminal.run_with(local, |request, frontend, operation| {
                    self.run_proxy(
                        name,
                        arguments,
                        crate::runtime::command_proxy::launch::Attachment::Owned(
                            Box::new(request),
                            frontend,
                        ),
                        operation,
                    )
                })
            },
        )
        .map_err(supervision)
    }

    fn foreground_authority(&self) -> supervision::ForegroundAuthority {
        supervision::ForegroundAuthority {
            journal: Arc::clone(&self.journal),
            session: self.owner.session.clone(),
            pin: self.owner.manifest_pin(),
            owner: self.owner.binding.clone(),
            services: self.services.authority(),
            bus_socket: self.owner.bus_socket().to_path_buf(),
        }
    }

    /// Attempt every shutdown even when another fails. The retained directory
    /// is removed only after all service namespaces and the owner have settled.
    pub(crate) fn close(
        mut self,
        journal: &SessionJournal,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), SessionError> {
        journal
            .begin_closing(
                &self.owner.session,
                "Shell close",
                cancellation,
                deadline,
            )
            .map_err(supervision)?;
        let services_closed = self.services.close(cancellation, deadline);
        let completion = self
            .owner
            .close(journal, cancellation, deadline)
            .map_err(supervision)?;
        if !matches!(
            completion,
            crate::systemd::SystemdJobCompletion::Observed {
                result: crate::systemd::SystemdJobResult::Done
            }
        ) {
            return Err(SessionError::Supervision(format!(
                "owner stop unconfirmed; configuration retained at {}",
                self.shell.files.path().display(),
            )));
        }
        if services_closed.is_err() {
            self.services
                .settle_after_owner_stop(&self.owner, &completion, cancellation, deadline)
                .map_err(supervision)?;
        }
        if let Some(state) = self.shell.state.take() {
            state.close(cancellation, deadline)?;
        }
        self.shell.close()
    }
}

type PreparedServices = Vec<ServiceRoleStart>;

fn prepare_shell(
    prepared: PreparedConsumer,
    start: &ManagedShellStart<'_>,
    cwd: &Path,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(ShellSession, PreparedServices, Vec<u8>), SessionError> {
    let secrets = super::secrets::SessionSecrets::snapshot(
        prepared.consumer(),
        start.secrets,
        cwd,
        cancellation,
    )?;
    let boot = BootId::current(cancellation, deadline).map_err(supervision)?;
    let identity = LauncherIdentity::new(start.worker_digest, 1).map_err(supervision)?;
    let (snapshot, _) = shell_snapshot(&prepared, identity).map_err(supervision)?;
    let files = SessionFiles::new_retained_in(
        prepared.consumer(),
        start.private_directory,
        cancellation,
    )?;
    let state = super::state::SessionState::create(
        prepared.consumer(),
        start.private_directory,
        cancellation,
    )?;
    let shell = ShellSession {
        prepared,
        files,
        state,
        secrets,
    };
    // Validate and retain every launch before any manager mutation.
    let launches = prepare_services(&shell, cwd, cancellation)?;
    let manifest = record::encode_with_state(
        &boot,
        &snapshot,
        shell.files.path(),
        cwd,
        shell
            .state
            .as_ref()
            .map(super::state::SessionState::path),
    )
    .map_err(supervision)?;
    let pin = ContentDigest::sha256(&manifest);
    super::ownership::validate_manifest(&manifest, pin).map_err(supervision)?;
    Ok((shell, launches, manifest))
}

fn supervision(error: impl std::fmt::Display) -> SessionError {
    SessionError::Supervision(error.to_string())
}

fn prepare_services(
    shell: &ShellSession,
    cwd: &Path,
    cancellation: &Cancellation,
) -> Result<PreparedServices, SessionError> {
    let mut launches = Vec::new();
    for service in shell.prepared.consumer().services() {
        for process in service.processes() {
            let role = format!("service:{}:{}", service.id(), process.id);
            crate::execution::launcher::service_coordinator::validate_role(&role)
                .map_err(supervision)?;
            let key = (
                Some(service.id().to_owned()),
                process.command.clone(),
            );
            let invocation = shell
                .prepared
                .invocations()
                .get(&key)
                .ok_or_else(|| {
                    SessionError::Supervision("prepared service command is missing".into())
                })?;
            let arguments = invocation
                .arguments()
                .iter()
                .map(|argument| super::render(argument, Some(service.id())).map(OsString::from))
                .collect::<Result<Vec<_>, _>>()?;
            let environment = invocation
                .environment()
                .iter()
                .map(|entry| {
                    Ok((
                        entry.name.clone(),
                        super::render(&entry.value, Some(service.id()))?,
                    ))
                })
                .collect::<Result<_, SessionError>>()?;
            let configuration = crate::runtime::RuntimeConfiguration::new(
                service.id().to_owned(),
                shell.files.service(service.id())?,
                environment,
            )?;
            let configuration = shell
                .secrets
                .configure(service.id(), configuration)?;
            let configuration = match &shell.state {
                Some(state) => state.configure(service.id(), configuration)?,
                None => configuration,
            };
            launches.push(ServiceRoleStart {
                role,
                restart: process.restart(),
                prepared: prepare_runtime_launch(
                    invocation.closure(),
                    &arguments,
                    cwd,
                    &configuration,
                    cancellation,
                )?,
            });
        }
    }
    Ok(launches)
}

#[cfg(test)]
fn session_manifest(
    boot: &BootId,
    snapshot: &[u8],
    configuration: &Path,
    cwd: &Path,
) -> Result<Vec<u8>, SessionError> {
    record::encode(boot, snapshot, configuration, cwd).map_err(supervision)
}

#[cfg(test)]
mod tests;

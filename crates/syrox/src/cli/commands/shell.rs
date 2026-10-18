use std::ffi::OsString;
use std::os::fd::AsFd as _;
use std::path::PathBuf;
use std::process::ExitCode;

use syrox_engine::{
    config::UserConfiguration, deployment::manifest::prepare_consumer,
    deployment::shell::ManagedShell, deployment::shell::ManagedShellConfiguration,
    deployment::shell::PreparedShellTerminal, deployment::shell::ShellSession,
    deployment::shell::validate_managed_shell_command, deployment::shell::validate_shell_command,
    project::CheckConfiguration, project::prepare_project_consumer_with,
    project::reference::ProjectReference, project::reference::parse_project_reference,
};

#[derive(Debug, clap::Args)]
#[command(group(clap::ArgGroup::new("execution_mode").required(true).args(["interactive", "non_interactive"])))]
pub(crate) struct Arguments {
    /// Locked project and Shell output, for example .#shell.
    reference: String,
    /// Exposed managed command to run in this Shell.
    #[arg(long)]
    command: String,
    /// Run the selected command with inherited noninteractive streams.
    #[arg(long)]
    non_interactive: bool,
    /// Run the selected managed command through a foreground terminal PTY.
    #[arg(long, requires_all = ["session_state", "systemd_user_bus"])]
    interactive: bool,
    /// Existing private mode-0700 directory for managed session state.
    #[arg(long, requires = "systemd_user_bus")]
    session_state: Option<PathBuf>,
    /// Explicit user-manager bus socket for supervised service processes.
    #[arg(long, requires = "session_state")]
    systemd_user_bus: Option<PathBuf>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    store: Option<PathBuf>,
    #[arg(short = 'o', long)]
    offline: bool,
    #[arg(long)]
    cwd: Option<PathBuf>,
    #[arg(last = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

pub(crate) fn run(arguments: &Arguments, checks: &CheckConfiguration) -> ExitCode {
    match execute(arguments, checks) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(arguments: &Arguments, checks: &CheckConfiguration) -> Result<ExitCode, String> {
    let ProjectReference::Project {
        path,
        export: Some(name),
    } = parse_project_reference(&arguments.reference).map_err(|error| error.to_string())?
    else {
        return Err("shell requires a locked project and Shell output, for example .#shell".into());
    };
    let prepared = prepare_project_consumer_with(path, checks, name)
        .map_err(|error| crate::cli::presentation::project_error(&error))?;
    if arguments.session_state.is_some() {
        validate_managed_shell_command(&prepared, name, &arguments.command)
    } else {
        validate_shell_command(&prepared, name, &arguments.command)
    }
    .map_err(|error| match error {
        syrox_engine::deployment::shell::SessionError::ProcessesUnsupported => {
            format!("{error}; provide --session-state and --systemd-user-bus")
        }
        error => error.to_string(),
    })?;
    let user = UserConfiguration::load_with_store(
        arguments.config.as_deref(),
        arguments.store.as_deref(),
    )
    .map_err(|error| error.to_string())?;
    let selection = syrox_engine::deployment::manifest::select_consumer(&prepared, name)
        .map_err(|error| error.to_string())?;
    let secrets = user
        .shell_secrets()
        .for_consumer(selection.consumer())
        .map_err(|error| error.to_string())?;
    let cwd = std::path::absolute(
        arguments
            .cwd
            .as_deref()
            .unwrap_or(std::path::Path::new(".")),
    )
    .map_err(|error| error.to_string())?;
    let signals = crate::signals::OperationSignals::install().map_err(|error| error.to_string())?;
    let result = (|| {
        if arguments.session_state.is_some() {
            secrets
                .validate_for_consumer(selection.consumer(), &cwd, &signals.cancellation)
                .map_err(|error| error.to_string())?;
        }
        let terminal = if arguments.interactive {
            Some(PreparedShellTerminal::prepare(std::io::stdin().as_fd(), std::io::stdout().as_fd())
                .map_err(|error| format!("interactive Shell requires stdin and stdout on the same foreground terminal: {error}; use --non-interactive for redirected streams"))?)
        } else {
            None
        };
        let worker = crate::cli::worker_path::installed()?;
        let managed = managed_configuration(
            arguments,
            &worker,
            &cwd,
            secrets,
            &signals.cancellation,
        )?;
        let prepared = prepare_consumer(
            prepared,
            name,
            &user,
            &worker,
            arguments.offline,
            &signals.cancellation,
            |_, _| {},
        )
        .map_err(|error| error.to_string())?;
        let session = if let Some(configuration) = &managed {
            ShellExecution::Managed(Box::new(
                ManagedShell::start(prepared, configuration, &signals.cancellation)
                    .map_err(|error| error.to_string())?,
            ))
        } else {
            ShellExecution::Direct(Box::new(
                ShellSession::new(prepared, &signals.cancellation)
                    .map_err(|error| error.to_string())?,
            ))
        };
        session.execute(arguments, &cwd, terminal, &signals.cancellation)
    })();
    Ok(
        crate::cli::presentation::render_cancellable_result(
            &signals,
            result.map(|status| crate::cli::presentation::exit_status(status, 129)),
        ),
    )
}

enum ShellExecution {
    Direct(Box<ShellSession>),
    Managed(Box<ManagedShell>),
}
impl ShellExecution {
    fn execute(
        self,
        arguments: &Arguments,
        cwd: &std::path::Path,
        terminal: Option<PreparedShellTerminal>,
        cancellation: &syrox_engine::cancellation::Cancellation,
    ) -> Result<std::process::ExitStatus, String> {
        let execution = self.run_command(
            &arguments.command,
            &arguments.argv,
            cwd,
            terminal,
            cancellation,
        );
        let cleanup = self.close();
        match (execution, cleanup) {
            (Ok(status), Ok(())) => Ok(status),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error.to_string()),
            (Err(error), Err(cleanup)) => Err(format!(
                "{error}; session cleanup also failed: {cleanup}"
            )),
        }
    }

    fn run_command(
        &self,
        name: &str,
        arguments: &[OsString],
        cwd: &std::path::Path,
        terminal: Option<PreparedShellTerminal>,
        cancellation: &syrox_engine::cancellation::Cancellation,
    ) -> Result<std::process::ExitStatus, syrox_engine::deployment::shell::SessionError> {
        match (self, terminal) {
            (Self::Direct(session), None) => {
                session.run_command(name, arguments, cwd, cancellation)
            }
            (Self::Managed(session), None) => session.run_command(name, arguments, cancellation),
            (Self::Managed(session), Some(terminal)) => {
                session.run_prepared_terminal(name, arguments, terminal, cancellation)
            }
            (Self::Direct(_), Some(_)) => Err(
                syrox_engine::deployment::shell::SessionError::Supervision(
                    "interactive Shell requires managed session ownership".to_owned(),
                ),
            ),
        }
    }
    fn close(self) -> Result<(), syrox_engine::deployment::shell::SessionError> {
        match self {
            Self::Direct(session) => session.close(),
            Self::Managed(session) => session.close(),
        }
    }
}

fn managed_configuration(
    arguments: &Arguments,
    worker: &std::path::Path,
    cwd: &std::path::Path,
    secrets: syrox_engine::config::ShellSecretSources,
    cancellation: &syrox_engine::cancellation::Cancellation,
) -> Result<Option<ManagedShellConfiguration>, String> {
    if let (Some(state), Some(bus)) = (
        &arguments.session_state,
        &arguments.systemd_user_bus,
    ) {
        let configuration = ManagedShellConfiguration {
            secrets,
            worker: worker.to_path_buf(),
            worker_digest: crate::cli::worker_path::digest(worker, cancellation)?,
            bus_socket: std::path::absolute(bus).map_err(|error| error.to_string())?,
            state_directory: std::path::absolute(state).map_err(|error| error.to_string())?,
            cwd: cwd.to_path_buf(),
        };
        configuration
            .validate(cancellation)
            .map_err(|error| error.to_string())?;
        Ok(Some(configuration))
    } else {
        Ok(None)
    }
}

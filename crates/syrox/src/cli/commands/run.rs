use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use syrox_engine::config::UserConfiguration;
use syrox_engine::project::CheckConfiguration;

#[derive(Debug, clap::Args)]
pub(crate) struct Arguments {
    /// Explicit public member: catalog member, .#member, or ./project#member.
    reference: Option<String>,
    /// Named command declared by the selected recipe.
    #[arg(long)]
    command: Option<String>,
    /// Select a project's main.srx.
    #[arg(short = 'f', long)]
    file: Option<PathBuf>,
    /// Explicit user configuration.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override the configured Store.
    #[arg(long)]
    store: Option<PathBuf>,
    /// Require all build sources in the verified local cache.
    #[arg(short = 'o', long)]
    offline: bool,
    /// Arguments for the application (after --).
    #[arg(last = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

pub(crate) fn run(args: &Arguments, checks: &CheckConfiguration) -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        match execute(args, checks) {
            Ok(code) => code,
            Err(message) => {
                eprintln!("error: {message}");
                ExitCode::from(1)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn execute(args: &Arguments, checks: &CheckConfiguration) -> Result<ExitCode, String> {
    use syrox_engine::{
        build::BuildError, realize::CommandError, realize::RealizeError, realize::realize_command,
        realize::resolve_command, runtime::RuntimeError, runtime::run_runtime_with_cancellation,
    };

    let user = UserConfiguration::load_with_store(args.config.as_deref(), args.store.as_deref())
        .map_err(|e| e.to_string())?;
    let reference = crate::cli::reference::select(args.reference.as_deref(), args.file.as_deref())?;
    let app = resolve_command(&reference, args.command.as_deref(), &user, checks)
        .map_err(|e| e.to_string())?;
    let signals = crate::signals::OperationSignals::install().map_err(|e| e.to_string())?;
    let worker = crate::cli::worker_path::build_candidate()?;
    let realized = realize_command(
        &app,
        &user,
        &worker,
        args.offline,
        &signals.cancellation,
        |_, _| {},
    );
    let closure = match realized {
        Ok(closure) => closure,
        Err(
            CommandError::Resolve(
                RealizeError::Cancelled | RealizeError::Build(BuildError::Cancelled),
            )
            | CommandError::Runtime(RuntimeError::Cancelled),
        ) => {
            return Ok(ExitCode::from(signals.cancelled_exit_code()));
        }
        Err(error) => return Err(error.to_string()),
    };
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let status =
        match run_runtime_with_cancellation(&closure, &args.argv, &cwd, &signals.cancellation) {
            Ok(status) => status,
            Err(RuntimeError::Cancelled) => {
                return Ok(ExitCode::from(signals.cancelled_exit_code()));
            }
            Err(error) => return Err(error.to_string()),
        };
    if signals.cancellation.is_cancelled() {
        return Ok(ExitCode::from(signals.cancelled_exit_code()));
    }
    Ok(crate::cli::presentation::exit_status(status, 1))
}

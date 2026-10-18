use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use syrox_engine::{
    cancellation::Cancellation, config::UserConfiguration, deployment::os::OsCandidatePhase,
    deployment::os::OsGenerationSummary, deployment::os::OsPreparation, plan::PlanConsumerKind,
    project::CheckConfiguration, project::reference::ProjectReference, store::ContentDigest,
    store::Store,
};

mod apply;
mod reconciliation;
mod status;

#[derive(Debug, clap::Subcommand)]
pub(crate) enum Command {
    /// Realize an Os consumer and durably retain a prepared generation.
    Prepare(PrepareArguments),
    /// Apply a retained candidate through the explicitly selected service manager.
    Apply(apply::Arguments),
    /// Restore an explicitly selected retained generation using the apply protocol.
    Rollback(apply::RollbackArguments),
    /// Reconcile recorded effects; --manager-changed explicitly revokes prior authority.
    Recover(reconciliation::RecoveryArguments),
    /// Clear a reconciled operation's desired selection without revoking authorizations or stopping services.
    Abandon(reconciliation::AbandonArguments),
    /// Observe activation journal evidence without contacting the service manager.
    Status {
        #[arg(long)]
        installation: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Read candidate journal states without opening a Store.
    List {
        #[arg(long)]
        installation: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Reopen and verify a retained generation and its outputs.
    Inspect {
        pin: ContentDigest,
        #[arg(long)]
        installation: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Compare the operational contents of two retained generations.
    Diff {
        previous: ContentDigest,
        candidate: ContentDigest,
        #[arg(long)]
        installation: PathBuf,
        #[arg(long)]
        store: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
pub(crate) struct PrepareArguments {
    /// Locked project and Os output, for example .#system.
    reference: String,
    /// Existing owned mode-0700 directory for installation state.
    #[arg(long)]
    installation: PathBuf,
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(short = 'o', long)]
    offline: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
#[command(group(clap::ArgGroup::new("manager").required(true).args(["systemd_user_bus", "systemd_system"])))]
struct ExecutionArguments {
    #[arg(long)]
    installation: PathBuf,
    #[arg(long)]
    store: PathBuf,
    /// Explicit persistent unit-fragment directory.
    #[arg(long)]
    units: PathBuf,
    #[arg(long)]
    cwd: PathBuf,
    #[arg(long)]
    systemd_user_bus: Option<PathBuf>,
    /// Use the local system manager; this does not elevate credentials.
    #[arg(long)]
    systemd_system: bool,
    #[arg(long)]
    uid: u32,
    #[arg(long)]
    gid: u32,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
    start_timeout_seconds: u64,
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=60))]
    stop_timeout_seconds: u64,
    #[arg(long)]
    json: bool,
}

impl ExecutionArguments {
    fn manager_scope(&self) -> Result<syrox_engine::systemd::SystemdScope, String> {
        match (&self.systemd_user_bus, self.systemd_system) {
            (Some(bus_socket), false) => Ok(syrox_engine::systemd::SystemdScope::User {
                bus_socket: bus_socket.clone(),
            }),
            (None, true) => Ok(syrox_engine::systemd::SystemdScope::System),
            _ => Err("select exactly one explicit systemd manager".into()),
        }
    }
}

pub(crate) fn run(command: &Command, checks: &CheckConfiguration) -> ExitCode {
    let signals = match crate::signals::OperationSignals::install() {
        Ok(signals) => signals,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = execute(command, checks, &signals.cancellation);
    crate::cli::presentation::render_cancellable_result(&signals, result.map(ExitCode::from))
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
fn execute(
    command: &Command,
    checks: &CheckConfiguration,
    cancel: &Cancellation,
) -> Result<u8, String> {
    match command {
        Command::Prepare(arguments) => prepare(arguments, checks, cancel),
        Command::Apply(arguments) => apply::run(arguments, cancel),
        Command::Rollback(arguments) => apply::rollback(arguments, cancel),
        Command::Recover(arguments) => reconciliation::recover(arguments, cancel),
        Command::Abandon(arguments) => reconciliation::abandon(arguments, cancel),
        Command::Status {
            installation,
            json,
        } => status::run(installation, *json, cancel),
        Command::List {
            installation,
            json,
        } => {
            let entries =
                syrox_engine::deployment::os::list_os_generations(installation, cancel, deadline())
                    .map_err(|error| error.to_string())?;
            let mut failed = false;
            let mut rows = Vec::new();
            for entry in entries {
                match entry.phase {
                    Ok(phase) => {
                        let phase = match phase {
                            OsCandidatePhase::Preparing => "preparing",
                            OsCandidatePhase::Prepared => "prepared",
                        };
                        if !json {
                            println!("{} journal={phase}", entry.pin);
                        }
                        rows.push(serde_json::json!({"pin":entry.pin.to_string(), "phase":phase}));
                    }
                    Err(error) => {
                        failed = true;
                        if !json {
                            eprintln!("{} unreadable: {error}", entry.pin);
                        }
                        rows.push(serde_json::json!({"pin":entry.pin.to_string(), "error":error}));
                    }
                }
            }
            if *json {
                println!("{}", serde_json::Value::Array(rows));
            }
            Ok(u8::from(failed))
        }
        Command::Inspect {
            pin,
            installation,
            store,
            json,
        } => {
            let store = Store::open(store).map_err(|error| error.to_string())?;
            let summary = syrox_engine::deployment::os::inspect_os_generation(
                installation,
                &store,
                *pin,
                cancel,
                deadline(),
            )
            .map_err(|error| error.to_string())?;
            print_summary(&summary, *json);
            Ok(0)
        }
        Command::Diff {
            previous,
            candidate,
            installation,
            store,
        } => {
            let store = Store::open(store).map_err(|error| error.to_string())?;
            let diff = syrox_engine::deployment::os::diff_os_generations(
                installation,
                &store,
                *previous,
                *candidate,
                cancel,
                deadline(),
            )
            .map_err(|error| error.to_string())?;
            print!("{diff}");
            Ok(0)
        }
    }
}

fn prepare(
    arguments: &PrepareArguments,
    checks: &CheckConfiguration,
    cancel: &Cancellation,
) -> Result<u8, String> {
    let ProjectReference::Project {
        path,
        export: Some(name),
    } = syrox_engine::project::reference::parse_project_reference(&arguments.reference)
        .map_err(|error| error.to_string())?
    else {
        return Err(
            "os prepare requires a locked project and Os output, for example .#system".into(),
        );
    };
    let prepared = syrox_engine::project::prepare_project_consumer_with(path, checks, name)
        .map_err(|error| crate::cli::presentation::project_error(&error))?;
    if syrox_engine::deployment::manifest::select_consumer(&prepared, name)
        .map_err(|error| error.to_string())?
        .consumer()
        .kind()
        != PlanConsumerKind::Os
    {
        return Err("generation preparation requires an Os consumer".into());
    }
    let worker = crate::cli::worker_path::installed()?;
    let digest = crate::cli::worker_path::digest(&worker, cancel)?;
    let user = UserConfiguration::load_with_store(
        arguments.config.as_deref(),
        Some(&arguments.store),
    )
    .map_err(|error| error.to_string())?;
    let installation = syrox_engine::deployment::os::initialize_os_installation(
        &arguments.installation,
        cancel,
        deadline(),
    )
    .map_err(|error| error.to_string())?;
    let prepared = syrox_engine::deployment::manifest::prepare_consumer(
        prepared,
        name,
        &user,
        &worker,
        arguments.offline,
        cancel,
        |_, _| {},
    )
    .map_err(|error| error.to_string())?;
    let store = Store::initialize(user.store()).map_err(|error| error.to_string())?;
    let summary = syrox_engine::deployment::os::prepare_os_generation(
        prepared,
        &OsPreparation {
            installation: &installation,
            store: &store,
            launcher: &worker,
            launcher_digest: digest,
        },
        cancel,
        deadline(),
    )
    .map_err(|error| error.to_string())?;
    print_summary(&summary, arguments.json);
    Ok(0)
}

fn print_summary(summary: &OsGenerationSummary, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({"pin":summary.pin.to_string(), "phase":"prepared",
            "outputs":summary.outputs, "services":summary.services, "commands":summary.commands,
            "processes":summary.processes, "configurations":summary.configurations})
        );
    } else {
        println!(
            "generation {} prepared: {} outputs, {} services, {} commands, {} processes, {} configuration files",
            summary.pin,
            summary.outputs,
            summary.services,
            summary.commands,
            summary.processes,
            summary.configurations
        );
    }
}

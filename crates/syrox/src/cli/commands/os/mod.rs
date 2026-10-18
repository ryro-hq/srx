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
mod profile;
mod profile_operations;
mod reconciliation;
mod status;

#[derive(Debug, clap::Subcommand)]
pub(crate) enum Command {
    /// Configure an installation profile without building or starting services.
    Init(profile::InitArguments),
    /// Apply an empty generation to stop all resources managed by this profile.
    Stop(profile_operations::StopArguments),
    /// Read logs for recorded invocations through the optional journalctl program.
    Logs(profile_operations::LogArguments),
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
    /// Observe live profile units and journal evidence; --recorded reads only evidence.
    Status {
        #[arg(long, required_unless_present = "profile", conflicts_with = "profile")]
        installation: Option<PathBuf>,
        #[arg(long)]
        profile: Option<String>,
        /// Read journal evidence without contacting systemd.
        #[arg(long)]
        recorded: bool,
        #[arg(long)]
        json: bool,
    },
    /// Read candidate journal states without opening a Store.
    List {
        #[arg(long, required_unless_present = "profile", conflicts_with = "profile")]
        installation: Option<PathBuf>,
        #[arg(long)]
        profile: Option<String>,
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
struct ExecutionArguments {
    #[arg(long, conflicts_with_all = ["installation", "store", "units", "cwd", "systemd_user_bus", "systemd_system", "uid", "gid", "start_timeout_seconds", "stop_timeout_seconds"])]
    profile: Option<String>,
    #[arg(long, required_unless_present = "profile")]
    installation: Option<PathBuf>,
    #[arg(long, required_unless_present = "profile")]
    store: Option<PathBuf>,
    #[arg(long, required_unless_present = "profile")]
    units: Option<PathBuf>,
    #[arg(long, required_unless_present = "profile")]
    cwd: Option<PathBuf>,
    #[arg(long, conflicts_with = "systemd_system")]
    systemd_user_bus: Option<PathBuf>,
    #[arg(long, required_unless_present_any = ["systemd_user_bus", "profile"])]
    systemd_system: bool,
    #[arg(long, required_unless_present = "profile")]
    uid: Option<u32>,
    #[arg(long, required_unless_present = "profile")]
    gid: Option<u32>,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=300))]
    start_timeout_seconds: Option<u64>,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=60))]
    stop_timeout_seconds: Option<u64>,
    #[arg(long)]
    json: bool,
}
impl ExecutionArguments {
    fn request(
        &self,
        candidate: ContentDigest,
        expected: Option<ContentDigest>,
    ) -> Result<syrox_engine::deployment::os::OsApplyRequest, String> {
        let scope = match (&self.systemd_user_bus, self.systemd_system) {
            (Some(bus_socket), false) => syrox_engine::systemd::SystemdScope::User {
                bus_socket: bus_socket.clone(),
            },
            (None, true) => syrox_engine::systemd::SystemdScope::System,
            _ => return Err("select exactly one explicit systemd manager".into()),
        };
        Ok(syrox_engine::deployment::os::OsApplyRequest {
            installation: self
                .installation
                .clone()
                .ok_or("--installation is required")?,
            store: self.store.clone().ok_or("--store is required")?,
            units: self.units.clone().ok_or("--units is required")?,
            cwd: self.cwd.clone().ok_or("--cwd is required")?,
            candidate,
            expected,
            scope,
            uid: self.uid.ok_or("--uid is required")?,
            gid: self.gid.ok_or("--gid is required")?,
            start_timeout: Duration::from_secs(self.start_timeout_seconds.unwrap_or(30)),
            stop_timeout: Duration::from_secs(self.stop_timeout_seconds.unwrap_or(5)),
        })
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
        Command::Init(arguments) => profile::init(arguments, cancel),
        Command::Stop(arguments) => profile_operations::stop(arguments, cancel),
        Command::Logs(arguments) => profile_operations::logs(arguments, cancel),
        Command::Prepare(arguments) => prepare(arguments, checks, cancel),
        Command::Apply(arguments) => apply::run(arguments, checks, cancel),
        Command::Rollback(arguments) => apply::rollback(arguments, cancel),
        Command::Recover(arguments) => reconciliation::recover(arguments, cancel),
        Command::Abandon(arguments) => reconciliation::abandon(arguments, cancel),
        Command::Status {
            installation,
            profile,
            recorded,
            json,
        } => {
            if let Some(name) = profile {
                profile_operations::status(name, *recorded, *json, cancel)
            } else {
                status::run(
                    installation
                        .as_deref()
                        .ok_or("--installation is required")?,
                    *json,
                    cancel,
                )
            }
        }
        Command::List {
            installation,
            profile,
            json,
        } => {
            let selected = profile
                .as_deref()
                .map(|name| profile::Loaded::load(name, cancel))
                .transpose()?;
            let installation = selected
                .as_ref()
                .map(|loaded| loaded.profile.installation.as_path())
                .or(installation.as_deref())
                .ok_or("--installation or --profile is required")?;
            let opened = syrox_engine::deployment::os::open_os_installation(
                installation,
                cancel,
                deadline(),
            )
            .map_err(|error| error.to_string())?;
            if selected
                .as_ref()
                .is_some_and(|loaded| loaded.profile.installation_id != opened.id())
            {
                return Err("profile installation identity differs".into());
            }
            let entries = opened
                .list(cancel, deadline())
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

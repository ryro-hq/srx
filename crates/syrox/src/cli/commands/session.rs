use std::path::{Path, PathBuf};
use std::process::ExitCode;

use syrox_engine::{
    deployment::shell::ShellAttemptOutcome, deployment::shell::list_managed_shell_sessions,
    deployment::shell::recover_managed_shell_session,
};

#[derive(Debug, clap::Subcommand)]
pub(crate) enum Command {
    /// Read existing journal evidence without contacting systemd or initializing state.
    List {
        #[arg(long)]
        session_state: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Revoke new starts and stop only recorded matching unit invocations.
    /// Unconfirmed process settlement preserves configuration and returns code 2.
    Recover {
        session: String,
        #[arg(long)]
        session_state: PathBuf,
        #[arg(long)]
        systemd_user_bus: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

pub(crate) fn run(command: &Command) -> ExitCode {
    let signals = match crate::signals::OperationSignals::install() {
        Ok(signals) => signals,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = execute(command, &signals.cancellation);
    crate::cli::presentation::render_cancellable_result(&signals, result.map(ExitCode::from))
}

fn execute(
    command: &Command,
    cancel: &syrox_engine::cancellation::Cancellation,
) -> Result<u8, String> {
    match command {
        Command::List {
            session_state,
            json,
        } => list(session_state, *json, cancel),
        Command::Recover {
            session,
            session_state,
            systemd_user_bus,
            store,
            json,
        } => recover(
            session,
            session_state,
            systemd_user_bus,
            store,
            *json,
            cancel,
        ),
    }
}

fn list(
    session_state: &Path,
    json: bool,
    cancel: &syrox_engine::cancellation::Cancellation,
) -> Result<u8, String> {
    let entries =
        list_managed_shell_sessions(session_state, cancel).map_err(|error| error.to_string())?;
    let mut invalid = false;
    let mut rows = Vec::new();
    for entry in entries {
        match entry.evidence {
            Ok(evidence) => {
                if !json {
                    println!(
                        "{} journal={} attempts={} pin={}",
                        entry.session, evidence.phase, evidence.attempts, evidence.pin
                    );
                }
                rows.push(serde_json::json!({"session":entry.session,
                    "phase":evidence.phase,"attempts":evidence.attempts,
                    "pin":evidence.pin.to_string(),"configuration_hint":evidence.configuration_hint,
                    "cwd":evidence.cwd,"boot":evidence.boot}));
            }
            Err(error) => {
                invalid = true;
                if !json {
                    eprintln!("{} unreadable: {error}", entry.session);
                }
                rows.push(serde_json::json!({"session":entry.session,"error":error}));
            }
        }
    }
    if json {
        println!("{}", serde_json::Value::Array(rows));
    }
    Ok(u8::from(invalid))
}

fn recover(
    session: &str,
    session_state: &Path,
    systemd_user_bus: &Path,
    store: &Path,
    json: bool,
    cancel: &syrox_engine::cancellation::Cancellation,
) -> Result<u8, String> {
    let bus = std::path::absolute(systemd_user_bus).map_err(|error| error.to_string())?;
    let report = recover_managed_shell_session(session_state, session, &bus, store, cancel)
        .map_err(|error| error.to_string())?;
    let mut rows = Vec::new();
    for attempt in &report.attempts {
        let (outcome, diagnostic) = match &attempt.outcome {
            ShellAttemptOutcome::ObservedStop => ("stop-observed", None),
            ShellAttemptOutcome::Absent => ("absent", None),
            ShellAttemptOutcome::Conflict => ("conflict", None),
            ShellAttemptOutcome::Unbound => ("unbound", None),
            ShellAttemptOutcome::Failed {
                stage,
                message,
            } => ("failed", Some(format!("{stage:?}: {message}"))),
        };
        if !json {
            println!(
                "{} {} {outcome}{}",
                attempt.id,
                attempt.role,
                diagnostic
                    .as_ref()
                    .map(|text| format!(": {text}"))
                    .unwrap_or_default()
            );
        }
        rows.push(
            serde_json::json!({"attempt":attempt.id,"role":attempt.role,
            "unit":attempt.unit.as_ref().map(syrox_engine::systemd::SystemdUnitName::as_str),
            "outcome":outcome,"diagnostic":diagnostic}),
        );
    }
    let retention = retention_rows(&report.retention, json);
    if json {
        println!(
            "{}",
            serde_json::json!({"session":report.session,
            "pin":report.pin.to_string(),"attempts":rows,
            "retention":retention,
            "needs_reconciliation":report.needs_reconciliation,
            "configuration_hint":report.configuration_hint})
        );
    } else if report.needs_reconciliation {
        eprintln!(
            "Session admission is closed; process settlement remains unconfirmed. Configuration and journal were retained."
        );
    }
    Ok(if report.needs_reconciliation {
        2
    } else {
        0
    })
}

fn retention_rows(
    roles: &[syrox_engine::deployment::shell::RoleRetentionRecovery],
    json: bool,
) -> Vec<serde_json::Value> {
    use syrox_engine::deployment::shell::RoleRetentionRecoveryOutcome as Outcome;
    roles
        .iter()
        .map(|role| {
            let (outcome, diagnostic) = match &role.outcome {
                Outcome::Verified => ("verified", None),
                Outcome::Retired => ("retired", None),
                Outcome::Pending {
                    message,
                } => ("pending", Some(message.as_str())),
                Outcome::Unprepared => ("unprepared", None),
                Outcome::RecordedRetired => ("recorded-retired", None),
                Outcome::Failed {
                    message,
                } => ("failed", Some(message.as_str())),
            };
            if !json {
                println!(
                    "{} retention={} {outcome}{}",
                    role.role,
                    role.phase,
                    diagnostic
                        .map(|text| format!(": {text}"))
                        .unwrap_or_default()
                );
            }
            serde_json::json!({"role":role.role,"first_attempt":role.first_attempt,
            "phase":role.phase,"outcome":outcome,"diagnostic":diagnostic})
        })
        .collect()
}

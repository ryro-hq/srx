use std::time::{Duration, Instant};

use super::ExecutionArguments;

use syrox_engine::{
    cancellation::Cancellation, deployment::os::OsApplyRequest, deployment::os::OsRollbackRequest,
    store::ContentDigest,
};

#[derive(Debug, clap::Args)]
#[command(group(clap::ArgGroup::new("previous_generation").required(true).args(["initial", "expected"])))]
pub(crate) struct Arguments {
    /// Prepared generation to apply; no project evaluation is performed.
    candidate: ContentDigest,
    /// Require that no generation has previously been selected.
    #[arg(long)]
    initial: bool,
    /// Compare the previously selected generation before making changes.
    #[arg(long)]
    expected: Option<ContentDigest>,
    #[command(flatten)]
    execution: ExecutionArguments,
}

#[derive(Debug, clap::Args)]
pub(crate) struct RollbackArguments {
    /// Explicit retained generation to restore, not an inferred healthy generation.
    candidate: ContentDigest,
    /// Compare the currently selected desired generation before rollback.
    #[arg(long)]
    expected: ContentDigest,
    #[command(flatten)]
    execution: ExecutionArguments,
}

pub(crate) fn run(arguments: &Arguments, cancel: &Cancellation) -> Result<u8, String> {
    if arguments.initial == arguments.expected.is_some() {
        return Err("select exactly one of --initial or --expected PIN".into());
    }
    execute(
        arguments.candidate,
        arguments.expected,
        &arguments.execution,
        false,
        cancel,
    )
}

pub(crate) fn rollback(arguments: &RollbackArguments, cancel: &Cancellation) -> Result<u8, String> {
    execute(
        arguments.candidate,
        Some(arguments.expected),
        &arguments.execution,
        true,
        cancel,
    )
}

fn execute(
    candidate: ContentDigest,
    expected: Option<ContentDigest>,
    arguments: &ExecutionArguments,
    rollback: bool,
    cancel: &Cancellation,
) -> Result<u8, String> {
    let scope = arguments.manager_scope()?;
    let request = OsApplyRequest {
        installation: arguments.installation.clone(),
        store: arguments.store.clone(),
        units: arguments.units.clone(),
        cwd: arguments.cwd.clone(),
        candidate,
        expected,
        scope,
        uid: arguments.uid,
        gid: arguments.gid,
        start_timeout: Duration::from_secs(arguments.start_timeout_seconds),
        stop_timeout: Duration::from_secs(arguments.stop_timeout_seconds),
    };
    let deadline = Instant::now() + Duration::from_secs(300);
    let report = if rollback {
        syrox_engine::deployment::os::rollback_os_generation(
            &OsRollbackRequest {
                target: request.candidate,
                expected: request
                    .expected
                    .ok_or("rollback requires --expected PIN")?,
                installation: request.installation,
                store: request.store,
                units: request.units,
                cwd: request.cwd,
                scope: request.scope,
                uid: request.uid,
                gid: request.gid,
                start_timeout: request.start_timeout,
                stop_timeout: request.stop_timeout,
            },
            cancel,
            deadline,
        )
    } else {
        syrox_engine::deployment::os::apply_os_generation(&request, cancel, deadline)
    }
    .map_err(|error| error.to_string())?;
    let action = if rollback {
        "rollback"
    } else {
        "apply"
    };
    if arguments.json {
        let resources = report
            .resources
            .iter()
            .map(|resource| {
                serde_json::json!({
                    "resource": resource.resource,
                    "unit": resource.unit,
                    "state": resource.state.as_str(),
                    "stage": resource.stage,
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::json!({
                "kind": action, "operation": report.operation,
                "candidate": report.candidate.to_string(),
                "resources": resources,
                "needs_reconciliation": report.needs_reconciliation,
            })
        );
    } else {
        println!(
            "{action} operation {} candidate={}",
            report.operation, report.candidate
        );
        for resource in &report.resources {
            println!(
                "{} unit={} state={}{}",
                resource.resource,
                resource.unit,
                resource.state.as_str(),
                resource
                    .stage
                    .map_or_else(String::new, |stage| format!(" stage={stage}"))
            );
        }
        if report.needs_reconciliation {
            println!("operation requires reconciliation; retained evidence is preserved");
        }
    }
    Ok(if report.needs_reconciliation {
        2
    } else {
        0
    })
}

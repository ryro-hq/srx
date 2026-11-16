use std::time::{Duration, Instant};

use super::{ExecutionArguments, profile, profile_operations};

use syrox_engine::{
    cancellation::Cancellation, deployment::os::OsRollbackRequest, store::ContentDigest,
};

#[derive(Debug, clap::Args)]
pub(crate) struct Arguments {
    /// Prepared generation to apply; no project evaluation is performed.
    #[arg(required_unless_present = "profile", conflicts_with = "profile")]
    candidate: Option<ContentDigest>,
    /// Require that no generation has previously been selected.
    #[arg(long, required_unless_present_any = ["expected", "profile"], conflicts_with_all = ["expected", "profile"])]
    initial: bool,
    /// Compare the previously selected generation before making changes.
    #[arg(long, conflicts_with = "profile")]
    expected: Option<ContentDigest>,
    /// Keep the root lock unchanged (the default refreshes only main.srx).
    #[arg(long, requires = "profile")]
    locked: bool,
    #[arg(short = 'o', long, requires = "profile")]
    offline: bool,
    #[command(flatten)]
    execution: ExecutionArguments,
}

#[derive(Debug, clap::Args)]
pub(crate) struct RollbackArguments {
    /// Explicit retained generation to restore, not an inferred healthy generation.
    candidate: ContentDigest,
    /// Compare the currently selected desired generation before rollback.
    #[arg(long, required_unless_present = "profile")]
    expected: Option<ContentDigest>,
    #[command(flatten)]
    execution: ExecutionArguments,
}

pub(crate) fn run(
    arguments: &Arguments,
    checks: &syrox_engine::project::CheckConfiguration,
    cancel: &Cancellation,
) -> Result<u8, String> {
    if let Some(name) = &arguments.execution.profile {
        if arguments.candidate.is_some() || arguments.initial || arguments.expected.is_some() {
            return Err("profile apply prepares its configured project; use rollback PIN --profile for retained generations".into());
        }
        return profile_operations::apply(
            name,
            arguments.locked,
            arguments.offline,
            arguments.execution.json,
            checks,
            cancel,
        );
    }
    if arguments.initial == arguments.expected.is_some() {
        return Err("select exactly one of --initial or --expected PIN".into());
    }
    execute(
        arguments
            .candidate
            .ok_or("a prepared generation is required without --profile")?,
        arguments.expected,
        &arguments.execution,
        false,
        cancel,
    )
}

pub(crate) fn rollback(arguments: &RollbackArguments, cancel: &Cancellation) -> Result<u8, String> {
    if let Some(name) = &arguments.execution.profile {
        let loaded = profile::Loaded::load(name, cancel)?;
        let status = loaded.status(cancel)?;
        if arguments
            .expected
            .is_some_and(|expected| status.desired != Some(expected))
        {
            return Err("desired generation comparison failed".into());
        }
        return profile_operations::activate(
            &loaded,
            &status,
            arguments.candidate,
            true,
            arguments.execution.json,
            cancel,
        );
    }
    execute(
        arguments.candidate,
        Some(
            arguments
                .expected
                .ok_or("rollback requires --expected PIN without --profile")?,
        ),
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
    let request = arguments.request(candidate, expected)?;
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
    Ok(print_report(&report, rollback, arguments.json))
}

pub(super) fn print_report(
    report: &syrox_engine::deployment::os::OsApplyReport,
    rollback: bool,
    json: bool,
) -> u8 {
    let action = if rollback {
        "rollback"
    } else {
        "apply"
    };
    if json {
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
    if report.needs_reconciliation {
        2
    } else {
        0
    }
}

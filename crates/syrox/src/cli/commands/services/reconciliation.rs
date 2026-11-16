use std::time::{Duration, Instant};

use syrox_engine::{
    cancellation::Cancellation, deployment::os::OsRecoveryEffect, deployment::os::OsRecoveryReport,
    deployment::os::OsRecoveryRequest,
};

#[derive(Debug, clap::Args)]
pub(crate) struct RecoveryArguments {
    /// Explicit journal operation identifier, as printed by apply or status.
    #[arg(value_parser = operation_id, required_unless_present = "profile")]
    operation: Option<String>,
    /// Explicitly reconcile an earlier boot; does not start services or authorize GC.
    #[arg(long)]
    new_boot: bool,
    /// Revoke prior manager authority in the same boot; retain unresolved evidence.
    #[arg(long, conflicts_with = "new_boot")]
    manager_changed: bool,
    #[command(flatten)]
    execution: super::ExecutionArguments,
}

pub(crate) fn operation_id(text: &str) -> Result<String, String> {
    if text.len() != 32
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || text.bytes().all(|byte| byte == b'0')
    {
        return Err("operation must be 32 lowercase hexadecimal digits and nonzero".into());
    }
    Ok(text.into())
}

pub(crate) fn recover(arguments: &RecoveryArguments, cancel: &Cancellation) -> Result<u8, String> {
    let execution = &arguments.execution;
    let loaded = execution
        .profile
        .as_deref()
        .map(|name| super::profile::Loaded::load(name, cancel))
        .transpose()?;
    let operation = match &arguments.operation {
        Some(operation) => operation.clone(),
        None => loaded
            .as_ref()
            .ok_or("an operation identifier is required without --profile")?
            .status(cancel)?
            .active_operation
            .ok_or("profile has no active operation to recover")?,
    };
    let selected = if let Some(loaded) = &loaded {
        loaded.request(
            syrox_engine::store::ContentDigest::sha256(b"recovery-context"),
            None,
        )
    } else {
        execution.request(
            syrox_engine::store::ContentDigest::sha256(b"recovery-context"),
            None,
        )?
    };
    let request = OsRecoveryRequest {
        installation: selected.installation,
        store: selected.store,
        units: selected.units,
        cwd: selected.cwd,
        operation,
        new_boot: arguments.new_boot,
        manager_changed: arguments.manager_changed,
        scope: selected.scope,
        uid: selected.uid,
        gid: selected.gid,
        start_timeout: selected.start_timeout,
        stop_timeout: selected.stop_timeout,
    };
    let report = if let Some(loaded) = &loaded {
        loaded.revalidate(cancel)?;
        syrox_engine::deployment::os::recover_os_generation_with_identity(
            &request,
            &loaded.profile.installation_id,
            cancel,
            Instant::now() + Duration::from_secs(300),
        )
    } else {
        syrox_engine::deployment::os::recover_os_generation(
            &request,
            cancel,
            Instant::now() + Duration::from_secs(300),
        )
    }
    .map_err(|error| error.to_string())?;
    if execution.json {
        println!("{}", report_json(&report));
    } else {
        println!(
            "recovery operation {} candidate={}",
            report.operation, report.candidate
        );
        for effect in &report.effects {
            println!("{}", effect_text(effect));
        }
        if report.needs_reconciliation {
            if arguments.manager_changed {
                println!("unresolved effects remain; retained evidence was preserved");
            } else {
                println!("unresolved effects remain; no manager actions were submitted");
            }
        }
    }
    Ok(report_exit_code(&report))
}

fn report_json(report: &OsRecoveryReport) -> serde_json::Value {
    let effects: Vec<_> = report
        .effects
        .iter()
        .map(|effect| {
            serde_json::json!({
                "effect": effect.effect, "resource": effect.resource, "kind": effect.kind,
                "state": effect.state.as_str(), "stage": effect.stage, "error": effect.error,
            })
        })
        .collect();
    serde_json::json!({
        "operation": report.operation, "candidate": report.candidate.to_string(),
        "effects": effects, "needs_reconciliation": report.needs_reconciliation,
    })
}
fn effect_text(effect: &OsRecoveryEffect) -> String {
    format!(
        "effect={} resource={} kind={} state={}{}{}",
        effect.effect,
        effect.resource,
        effect.kind,
        effect.state.as_str(),
        effect
            .stage
            .map_or_else(String::new, |stage| format!(" stage={stage}")),
        effect
            .error
            .as_ref()
            .map_or_else(String::new, |error| format!(" error={error}"))
    )
}
fn report_exit_code(report: &OsRecoveryReport) -> u8 {
    if report.needs_reconciliation {
        2
    } else {
        0
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct AbandonArguments {
    /// Explicit active operation identifier whose effects have been reconciled.
    #[arg(value_parser = operation_id)]
    operation: String,
    #[arg(long)]
    installation: std::path::PathBuf,
    #[arg(long)]
    json: bool,
}

pub(crate) fn abandon(arguments: &AbandonArguments, cancel: &Cancellation) -> Result<u8, String> {
    let report = syrox_engine::deployment::os::abandon_os_operation(
        &arguments.installation,
        &arguments.operation,
        cancel,
        super::deadline(),
    )
    .map_err(|error| error.to_string())?;
    if arguments.json {
        println!(
            "{}",
            serde_json::json!({
                "installation": report.installation,
                "operation": report.operation,
                "candidate": report.candidate.to_string(),
                "state": "abandoned",
                "desired": null,
            })
        );
    } else {
        println!(
            "operation {} candidate={} abandoned: desired selection cleared; existing authorizations, services and retention preserved",
            report.operation, report.candidate
        );
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use syrox_engine::{deployment::os::OsRecoveryState, store::ContentDigest};

    #[test]
    fn not_applied_is_reported_distinctly_without_claiming_candidate_application() {
        let mut report = OsRecoveryReport {
            operation: "1234567890abcdef1234567890abcdef".into(),
            candidate: ContentDigest::sha256(b"candidate"),
            effects: vec![OsRecoveryEffect {
                effect: "recorded-effect".into(),
                resource: "service/process".into(),
                kind: "publish",
                state: OsRecoveryState::NotApplied,
                stage: None,
                error: None,
            }],
            needs_reconciliation: false,
        };
        let json = report_json(&report);
        assert_eq!(json["effects"][0]["state"], "not_applied");
        assert_eq!(json["needs_reconciliation"], false);
        assert!(json.get("applied").is_none());
        assert!(effect_text(&report.effects[0]).contains("state=not_applied"));
        assert_eq!(report_exit_code(&report), 0);
        report.effects[0].state = OsRecoveryState::BootFenced;
        assert_eq!(
            report_json(&report)["effects"][0]["state"],
            "boot_fenced"
        );
        assert!(effect_text(&report.effects[0]).contains("state=boot_fenced"));
        assert_eq!(report_exit_code(&report), 0);
        report.effects[0].state = OsRecoveryState::Pending;
        report.needs_reconciliation = true;
        assert_eq!(
            report_json(&report)["effects"][0]["state"],
            "pending"
        );
        assert_eq!(report_exit_code(&report), 2);
        report.effects[0].stage = Some("query unit");
        report.effects[0].error = Some("manager connection lost".into());
        let effect = &report_json(&report)["effects"][0];
        assert_eq!(effect["stage"], "query unit");
        assert_eq!(effect["error"], "manager connection lost");
        let text = effect_text(&report.effects[0]);
        assert!(text.contains("stage=query unit"));
        assert!(text.contains("error=manager connection lost"));
        assert_eq!(report_exit_code(&report), 2);
    }
}

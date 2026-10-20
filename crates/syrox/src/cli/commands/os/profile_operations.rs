use super::profile::Loaded;
use std::time::{Duration, Instant};
use syrox_engine::{
    cancellation::Cancellation,
    deployment::os::{self, OsPreparation, OsStatus},
    project::CheckConfiguration,
    store::{ContentDigest, Store},
};

#[derive(Debug, clap::Args)]
pub(crate) struct StopArguments {
    #[arg(long)]
    profile: String,
    #[arg(long)]
    json: bool,
}
#[derive(Debug, clap::Args)]
pub(crate) struct LogArguments {
    /// Service name or exact service/process resource; omit for the entire profile.
    service: Option<String>,
    #[arg(long)]
    profile: String,
    #[arg(long)]
    follow: bool,
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=10000))]
    lines: u32,
}

pub(super) fn apply(
    name: &str,
    locked: bool,
    offline: bool,
    json: bool,
    checks: &CheckConfiguration,
    cancel: &Cancellation,
) -> Result<u8, String> {
    let loaded = Loaded::load(name, cancel)?;
    let before = loaded.status(cancel)?;
    require_settled(&before, name)?;
    loaded.check_manager_paths(cancel)?;
    let p = &loaded.profile;
    let prepared = if locked {
        syrox_engine::project::prepare_project_consumer_with(&p.project, checks, &p.output)
    } else {
        syrox_engine::project::prepare_project_consumer_refresh_root_with(
            &p.project, checks, &p.output,
        )
    }
    .map_err(|e| crate::cli::presentation::project_error(&e))?;
    if syrox_engine::deployment::manifest::select_consumer(&prepared, &p.output)
        .map_err(|e| e.to_string())?
        .consumer()
        .kind()
        != syrox_engine::plan::PlanConsumerKind::Os
    {
        return Err("profile output must be an Os consumer".into());
    }
    let worker = crate::cli::worker_path::installed()?;
    let digest = crate::cli::worker_path::digest(&worker, cancel)?;
    let user = syrox_engine::config::UserConfiguration::load_with_store(
        p.config.as_deref(),
        Some(&p.store),
    )
    .map_err(|e| e.to_string())?;
    let prepared = syrox_engine::deployment::manifest::prepare_consumer(
        prepared,
        &p.output,
        &user,
        &worker,
        offline,
        cancel,
        |_, _| {},
    )
    .map_err(|e| e.to_string())?;
    loaded.revalidate(cancel)?;
    let installation = os::open_os_installation(&p.installation, cancel, super::deadline())
        .map_err(|e| e.to_string())?;
    if installation.id() != p.installation_id {
        return Err("profile installation identity differs".into());
    }
    let store = Store::initialize(&p.store).map_err(|e| e.to_string())?;
    let summary = os::prepare_os_generation(
        prepared,
        &OsPreparation {
            installation: &installation,
            store: &store,
            launcher: &worker,
            launcher_digest: digest,
        },
        cancel,
        super::deadline(),
    )
    .map_err(|e| e.to_string())?;
    activate(&loaded, &before, summary.pin, false, json, cancel)
}

pub(super) fn activate(
    loaded: &Loaded,
    before: &OsStatus,
    pin: ContentDigest,
    rollback: bool,
    json: bool,
    cancel: &Cancellation,
) -> Result<u8, String> {
    require_settled(before, &loaded.profile.name)?;
    loaded.revalidate(cancel)?;
    let request = loaded.request(pin, before.desired);
    let report = os::apply_os_generation_with_authority(
        &request,
        &loaded.authority(before),
        rollback,
        cancel,
        Instant::now() + Duration::from_secs(300),
    )
    .map_err(|e| e.to_string())?;
    Ok(super::apply::print_report(
        &report, rollback, json,
    ))
}

pub(super) fn stop(arguments: &StopArguments, cancel: &Cancellation) -> Result<u8, String> {
    let loaded = Loaded::load(&arguments.profile, cancel)?;
    let before = loaded.status(cancel)?;
    require_settled(&before, &loaded.profile.name)?;
    let p = &loaded.profile;
    if before.desired.is_none() && before.bindings.is_empty() {
        if arguments.json {
            println!(
                "{}",
                serde_json::json!({"profile":p.name,"state":"not_applied","changed":false})
            );
        } else {
            println!("profile {} has no selected generation", p.name);
        }
        return Ok(0);
    }
    loaded.check_manager_paths(cancel)?;
    let worker = crate::cli::worker_path::installed()?;
    let digest = crate::cli::worker_path::digest(&worker, cancel)?;
    let installation = os::open_os_installation(&p.installation, cancel, super::deadline())
        .map_err(|e| e.to_string())?;
    if installation.id() != p.installation_id {
        return Err("profile installation identity differs".into());
    }
    let store = Store::open_existing(&p.store).map_err(|e| e.to_string())?;
    let summary = os::prepare_empty_os_generation(
        &OsPreparation {
            installation: &installation,
            store: &store,
            launcher: &worker,
            launcher_digest: digest,
        },
        cancel,
        super::deadline(),
    )
    .map_err(|e| e.to_string())?;
    if before.desired == Some(summary.pin)
        && before
            .bindings
            .iter()
            .all(|binding| !binding.authorized)
    {
        if arguments.json {
            println!(
                "{}",
                serde_json::json!({"profile":p.name,"desired":summary.pin.to_string(),"changed":false,"observation":"journal"})
            );
        } else {
            println!(
                "profile {} already selects the empty generation {} (journal)",
                p.name, summary.pin
            );
        }
        return Ok(0);
    }
    activate(
        &loaded,
        &before,
        summary.pin,
        false,
        arguments.json,
        cancel,
    )
}

fn require_settled(status: &OsStatus, name: &str) -> Result<(), String> {
    if !status.pending_effects.is_empty() {
        return Err(format!(
            "profile has pending effects; run srx os recover {} --profile {name} before another operation",
            status
                .active_operation
                .as_deref()
                .unwrap_or("OPERATION")
        ));
    }
    Ok(())
}

pub(super) fn status(
    name: &str,
    recorded: bool,
    json: bool,
    cancel: &Cancellation,
) -> Result<u8, String> {
    let loaded = Loaded::load(name, cancel)?;
    let status = loaded.status(cancel)?;
    if recorded {
        super::status::print(&status, json);
        return Ok(0);
    }
    let observation = observe(&loaded, &status, cancel);
    let (live, failed) = match observation {
        Ok(rows) => {
            let failed = rows
                .iter()
                .any(|row| row["matches_recorded"] != true);
            (serde_json::Value::Array(rows), failed)
        }
        Err(error) => (
            serde_json::json!({"available":false,"error":error}),
            true,
        ),
    };
    if json {
        println!(
            "{}",
            serde_json::json!({"profile":name,"recorded":super::status::json(&status),"live":live})
        );
    } else {
        super::status::print(&status, false);
        println!("live {live}");
    }
    Ok(u8::from(
        failed || !status.pending_effects.is_empty(),
    ))
}

fn observe(
    loaded: &Loaded,
    status: &OsStatus,
    cancel: &Cancellation,
) -> Result<Vec<serde_json::Value>, String> {
    let mut manager = syrox_engine::systemd::SystemdManager::connect(
        loaded.profile.manager_scope(),
        Duration::from_secs(5),
        cancel,
    )
    .map_err(|e| e.to_string())?;
    let identity = manager
        .observe_identity(Duration::from_secs(5), cancel)
        .map_err(|e| e.to_string())?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|e| e.to_string())?
        .trim()
        .replace('-', "");
    let mut rows = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    for binding in &status.bindings {
        if Instant::now() >= deadline {
            return Err("live status observation deadline expired".into());
        }
        let epoch_matches = binding.epoch.manager == identity.fingerprint().to_string()
            && binding.epoch.boot.replace('-', "") == boot;
        let unit = syrox_engine::systemd::SystemdUnitName::new(&binding.unit)
            .map_err(|e| e.to_string())?;
        let live = manager
            .query(
                &unit,
                deadline.saturating_duration_since(Instant::now()),
                cancel,
            )
            .map_err(|e| e.to_string())?;
        rows.push(match live {
            None => serde_json::json!({"resource":binding.resource,"unit":binding.unit,"present":false,"epoch_matches":epoch_matches,"matches_recorded":!binding.authorized}),
            Some(live) => {
                let invocation = hex(&live.invocation);
                let invocation_matches = binding.invocation.as_deref() == Some(invocation.as_str());
                let matches_recorded = if binding.authorized {
                    epoch_matches && invocation_matches && live.active_state == "active"
                } else {
                    matches!(live.active_state.as_str(), "inactive" | "failed")
                };
                serde_json::json!({"resource":binding.resource,"unit":binding.unit,"present":true,"active":live.active_state,"substate":live.sub_state,"result":live.result,"main_pid":live.main_pid,"invocation":invocation,"recorded_invocation":binding.invocation,"epoch_matches":epoch_matches,"invocation_matches":invocation_matches,"matches_recorded":matches_recorded})
            }
        });
    }
    if manager
        .observe_identity(
            deadline.saturating_duration_since(Instant::now()),
            cancel,
        )
        .map_err(|error| error.to_string())?
        != identity
    {
        return Err("manager changed during live status observation".into());
    }
    Ok(rows)
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("String write");
    }
    output
}

pub(super) fn logs(arguments: &LogArguments, cancel: &Cancellation) -> Result<u8, String> {
    let loaded = Loaded::load(&arguments.profile, cancel)?;
    let status = loaded.status(cancel)?;
    let matches = journal_matches(
        &loaded.profile,
        &status,
        arguments.service.as_deref(),
    )?;
    let mut command = std::process::Command::new("journalctl");
    command
        .args([
            "--no-pager",
            "--output=short-iso",
            "--lines",
        ])
        .arg(arguments.lines.to_string());
    if arguments.follow {
        command.arg("--follow");
    }
    command.args(matches);
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot start journalctl (optional logs dependency): {e}"))?;
    loop {
        if cancel.is_cancelled() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("log observation cancelled".into());
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(u8::try_from(status.code().unwrap_or(1)).unwrap_or(1)),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot wait for journalctl: {error}"));
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn journal_matches(
    profile: &os::profile::OsProfile,
    status: &OsStatus,
    service: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut arguments = Vec::new();
    for binding in &status.bindings {
        if service.is_some_and(|service| {
            binding.resource != service
                && !binding
                    .resource
                    .strip_prefix(service)
                    .is_some_and(|rest| rest.starts_with('/'))
        }) {
            continue;
        }
        let Some(invocation) = &binding.invocation else {
            continue;
        };
        let boot = binding.epoch.boot.replace('-', "");
        let (unit_field, manager_unit, manager_invocation, manager_uid) = match profile.scope {
            os::profile::ProfileScope::User {
                ..
            } => (
                "_SYSTEMD_USER_UNIT",
                "USER_UNIT",
                "USER_INVOCATION_ID",
                profile.uid,
            ),
            os::profile::ProfileScope::System => ("_SYSTEMD_UNIT", "UNIT", "INVOCATION_ID", 0),
        };
        for (unit_key, invocation_key, uid) in [
            (unit_field, "_SYSTEMD_INVOCATION_ID", profile.uid),
            (manager_unit, manager_invocation, manager_uid),
        ] {
            if !arguments.is_empty() {
                arguments.push("+".into());
            }
            arguments.extend([
                format!("{unit_key}={}", binding.unit),
                format!("{invocation_key}={invocation}"),
                format!("_UID={uid}"),
                format!("_BOOT_ID={boot}"),
            ]);
        }
    }
    if arguments.is_empty() {
        return Err("no recorded invocation for the selected service; inspect status --profile NAME --recorded".into());
    }
    Ok(arguments)
}

#[cfg(test)]
#[path = "profile_operations_tests.rs"]
mod tests;

use std::path::Path;

use syrox_engine::cancellation::Cancellation;
use syrox_engine::deployment::os::inspect_os_status;

pub(crate) fn run(installation: &Path, json: bool, cancel: &Cancellation) -> Result<u8, String> {
    let status = inspect_os_status(installation, cancel, super::deadline())
        .map_err(|error| error.to_string())?;
    if json {
        let boot_fences: Vec<_> = status.boot_fences.iter().map(|fence| serde_json::json!({
            "previous_boot": fence.previous_boot,
            "current": {"boot": fence.current.boot, "manager": fence.current.manager, "scope": fence.current.scope},
        })).collect();
        let bindings: Vec<_> = status
            .bindings
            .iter()
            .map(|binding| {
                serde_json::json!({
                    "resource": binding.resource,
                    "generation": binding.generation.to_string(),
                    "pin": binding.pin.to_string(),
                    "unit": binding.unit,
                    "authorized": binding.authorized,
                    "epoch": {
                        "boot": binding.epoch.boot,
                        "manager": binding.epoch.manager,
                        "scope": binding.epoch.scope,
                    },
                })
            })
            .collect();
        let pending_effects: Vec<_> = status
            .pending_effects
            .iter()
            .map(|effect| {
                serde_json::json!({
                    "operation": effect.operation,
                    "effect": effect.effect,
                    "kind": effect.kind,
                    "resource": effect.resource,
                    "target": effect.target.to_string(),
                    "phase": effect.phase,
                    "job": effect.job,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "observation": "journal",
                "installation": status.installation,
                "desired": status.desired.map(|pin| pin.to_string()),
                "active_operation": status.active_operation,
                "active_kind": status.active_kind,
                "boot_fences": boot_fences,
                "abandoned_operations": status.abandoned_operations,
                "bindings": bindings,
                "pending_effects": pending_effects,
            })
        );
    } else {
        println!(
            "journal {} desired={} active_operation={} active_kind={}",
            status.installation,
            status
                .desired
                .map_or_else(|| "none".into(), |pin| pin.to_string()),
            status
                .active_operation
                .as_deref()
                .unwrap_or("none"),
            status.active_kind.unwrap_or("none")
        );
        for operation in &status.abandoned_operations {
            println!("abandoned operation={operation}");
        }
        for fence in &status.boot_fences {
            println!(
                "boot_fence previous_boot={} current_boot={} manager={} scope={}",
                fence.previous_boot, fence.current.boot, fence.current.manager, fence.current.scope
            );
        }
        for binding in &status.bindings {
            println!(
                "binding {} generation={} pin={} unit={} authorized={} boot={} manager={} scope={}",
                binding.resource,
                binding.generation,
                binding.pin,
                binding.unit,
                binding.authorized,
                binding.epoch.boot,
                binding.epoch.manager,
                binding.epoch.scope
            );
        }
        for effect in &status.pending_effects {
            println!(
                "pending operation={} effect={} kind={} resource={} target={} phase={} job={}",
                effect.operation,
                effect.effect,
                effect.kind,
                effect.resource,
                effect.target,
                effect.phase,
                effect.job.as_deref().unwrap_or("none")
            );
        }
    }
    Ok(0)
}

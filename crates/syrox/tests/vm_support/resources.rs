//! Observe host resources and enforce VM startup admission, including ancestor limits.
use super::Result;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

pub const CPUS: u8 = 1;
pub const MEMORY_MIB: u32 = 512;
pub const WORKSPACE_MIB: u32 = 128;
pub const HOST_RESERVE_MIB: u32 = 1024;
pub const VM_HOST_MARGIN: u64 = (MEMORY_MIB as u64 + HOST_RESERVE_MIB as u64) * 1024 * 1024;

pub fn available(
    meminfo: &str,
    cgroup_root: &Path,
    membership: &Path,
    required: u64,
) -> Result<Value> {
    let host = meminfo
        .lines()
        .find_map(|line| {
            line.strip_prefix("MemAvailable:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()?
                .checked_mul(1024)
        })
        .ok_or("host MemAvailable is unavailable")?;
    if !membership.starts_with(cgroup_root)
        || membership
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("cgroup membership escapes its mount".into());
    }
    let mut available = host;
    let mut limits = Vec::new();
    for directory in membership.ancestors() {
        let maximum = directory.join("memory.max");
        if maximum.exists() {
            let maximum = fs::read_to_string(maximum)?;
            let current: u64 = fs::read_to_string(directory.join("memory.current"))?
                .trim()
                .parse()?;
            if maximum.trim() != "max" {
                let maximum: u64 = maximum.trim().parse()?;
                let remaining = maximum.saturating_sub(current);
                available = available.min(remaining);
                limits.push(json!({"path":directory,"maximum_bytes":maximum,"current_bytes":current,"available_bytes":remaining}));
            }
        }
        if directory == cgroup_root {
            break;
        }
    }
    Ok(
        json!({"host_available_bytes":host,"cgroup_limits":limits,"available_bytes":available,
        "required_bytes":required,"ready":available >= required}),
    )
}

/// Preparation observes availability without assigning a compiler memory budget.
pub fn host() -> Result<Value> {
    host_for(0)
}
pub fn host_for(required: u64) -> Result<Value> {
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let membership = Path::new(
        membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or("cgroup v2 required for resource admission")?,
    );
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let mount = mounts
        .lines()
        .find(|line| line.contains(" - cgroup2 "))
        .ok_or("cgroup v2 mount unavailable")?;
    let fields: Vec<_> = mount.split_whitespace().collect();
    let root = Path::new(fields.get(4).ok_or("cgroup mount path")?);
    let relative = membership.strip_prefix(Path::new(
        fields.get(3).ok_or("cgroup mount root")?,
    ))?;
    let directory = root.join(relative);
    if !directory.is_dir() {
        return Err("current cgroup directory unavailable".into());
    }
    available(
        &fs::read_to_string("/proc/meminfo")?,
        root,
        &directory,
        required,
    )
}

pub fn require_host_for(required: u64) -> Result<Value> {
    let result = host_for(required)?;
    if result["ready"] != true {
        return Err(format!("resource admission refused: {} bytes available; {} MiB required including cgroup limits",result["available_bytes"],required / (1024*1024)).into());
    }
    Ok(result)
}

pub fn verify_vm(config: &Value) -> Result<()> {
    let resources = &config["resources"];
    if resources["cpus"] != CPUS
        || resources["max_cpus"] != CPUS
        || resources["memory_mib"] != MEMORY_MIB
        || resources["max_memory_mib"] != MEMORY_MIB
    {
        return Err(format!(
            "SDK effective VM resources exceed or differ from 1 CPU/{MEMORY_MIB} MiB: {resources}"
        )
        .into());
    }
    Ok(())
}

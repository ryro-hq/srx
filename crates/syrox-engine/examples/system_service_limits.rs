//! Development-only native readback of System-action limits on a user unit.
//!
//! Uses the host-built harness, no recipe, Store, helper, disk device or boot.
//! Arguments are an explicit user-bus path and a new absolute evidence directory.
//! The metadata-only action does not claim authentication of a System worker.

use serde_json::{Value, json};
use std::fmt::Write as _;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use syrox_engine::{
    build::system::SystemBuildAction,
    cancellation::Cancellation,
    store::ContentDigest,
    system::budget::{BuildBudget, BuilderCapacity, BuilderLimits},
    systemd::{SystemdManager, SystemdScope, SystemdService, SystemdUnitName},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn budget() -> BuildBudget {
    BuildBudget {
        memory_bytes: 128 * 1024 * 1024,
        cpu_percent: 125,
        processes: 16,
        descriptors: 64,
        scratch_bytes: 16 * 1024 * 1024,
        files: 4096,
        output_bytes: 8 * 1024 * 1024,
        duration_seconds: 30,
    }
}

fn action(executable: &Path) -> Result<SystemBuildAction> {
    let request = budget();
    let admitted = BuilderLimits::new(request)?.admit(request)?;
    let mut policy = String::with_capacity(64);
    for byte in admitted.policy_fingerprint() {
        write!(policy, "{byte:02x}")?;
    }
    // Struct-ordered canonical metadata; this Directory program is not run.
    let wire = format!(
        "{{\"profile\":\"syrox-system-managed-x86_64-v1\",\"source\":\"{}\",\"source_limit\":1024,\"worker\":\"{}\",\"directory\":\"source-1\",\"inputs\":[],\"program\":\"5352584255494c440201000201000000030000006f7574010000000201050000006275696c64\",\"budget\":{},\"policy\":\"{policy}\",\"output_protocol\":\"syrox-system-worker-outputs-v1\",\"settlement\":\"subreaper-echild\"}}",
        ContentDigest::sha256(b"metadata-only native service-limits probe"),
        ContentDigest::sha256(&fs::read(executable)?),
        serde_json::to_string(&request)?,
    );
    let mut bytes = b"syrox-system-build-action-v1\n".to_vec();
    bytes.extend(wire.bytes());
    Ok(SystemBuildAction::parse(&bytes, &admitted)?)
}

#[allow(unsafe_code)]
fn process_limit(resource: libc::__rlimit_resource_t) -> io::Result<[u64; 2]> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: fixed current-process observation into writable ABI storage.
    if unsafe { libc::getrlimit(resource, &raw mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok([limit.rlim_cur, limit.rlim_max])
}

fn group_path(group: &str) -> Result<PathBuf> {
    if group == "/"
        || !group.starts_with('/')
        || group[1..]
            .split('/')
            .any(|s| matches!(s, "" | "." | ".."))
        || group.contains(['\n', '\0'])
    {
        return Err("unexpected unified cgroup path".into());
    }
    Ok(Path::new("/sys/fs/cgroup").join(&group[1..]))
}

fn kernel_values(group: &str) -> Result<Value> {
    let path = group_path(group)?;
    let number = |name| -> Result<u64> {
        Ok(fs::read_to_string(path.join(name))?
            .trim()
            .parse()?)
    };
    let cpu = fs::read_to_string(path.join("cpu.max"))?
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if cpu.len() != 2 {
        return Err("unexpected cpu.max".into());
    }
    Ok(json!({
        "memory_max": number("memory.max")?,
        "swap_max": number("memory.swap.max")?,
        "pids_max": number("pids.max")?,
        "cpu_max": cpu,
    }))
}

fn child(report: &Path) -> Result<()> {
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let groups = membership
        .lines()
        .filter_map(|s| s.strip_prefix("0::"))
        .collect::<Vec<_>>();
    let [group] = groups.as_slice() else {
        return Err("expected unified cgroup".into());
    };
    let record = json!({
        "pid": std::process::id(), "cgroup": group,
        "kernel": kernel_values(group)?,
        "nofile": process_limit(libc::RLIMIT_NOFILE)?,
        "fsize": process_limit(libc::RLIMIT_FSIZE)?,
        "core": process_limit(libc::RLIMIT_CORE)?,
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(report)?;
    serde_json::to_writer(&mut file, &record)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    // The coordinator observes us alive and then stops this unit explicitly.
    std::thread::sleep(Duration::from_secs(60));
    Err("coordinator did not stop the probe before its runtime ceiling".into())
}

#[allow(unsafe_code)]
fn matching_nonroot_identity() -> bool {
    // SAFETY: fixed observations of the current process's credentials.
    let identity = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    identity.0 != 0 && identity.0 == identity.1 && identity.2 == identity.3
}

fn run(bus: &Path, directory: &Path) -> Result<()> {
    if !matching_nonroot_identity() || !directory.is_absolute() || !bus.is_absolute() {
        return Err("probe requires matching non-root identity and absolute paths".into());
    }
    fs::create_dir(directory)?;
    let executable = std::env::current_exe()?;
    let action = action(&executable)?;
    fs::write(directory.join("action"), action.encode())?;
    let limits = action.service_limits()?;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos();
    let mut service = SystemdService::new(
        SystemdUnitName::new(format!(
            "syrox-system-limits-{}-{suffix}.service",
            std::process::id()
        ))?,
        executable,
    );
    service.arguments = vec![
        "--child".into(),
        directory
            .join("child.json")
            .to_str()
            .ok_or("non-UTF8 path")?
            .into(),
    ];
    service
        .environment
        .insert("LC_ALL".into(), "C".into());
    let request = budget();
    limits.apply(
        &mut service,
        BuilderCapacity {
            memory_bytes: request.memory_bytes,
            cpu_percent: request.cpu_percent,
            processes: request.processes,
            descriptors: request.descriptors,
            files: request.files,
            shared_storage_bytes: request.storage_bytes()?,
        },
    )?;
    // These are explicit diagnostic capacity values, not admission evidence for
    // a complete builder. Kernel readback below independently checks the subset.
    let cancel = Cancellation::default();
    let mut manager = SystemdManager::connect(
        SystemdScope::User {
            bus_socket: bus.into(),
        },
        Duration::from_secs(5),
        &cancel,
    )?;
    let job = manager.start_transient(&service, Duration::from_secs(5), &cancel);
    // Even an uncertain start gets a bounded stop attempt for this unique unit.
    let result = (|| -> Result<Value> {
        let job = job?;
        let completion = manager.wait_job(&job, Duration::from_secs(5), &cancel)?;
        let observation = limits.observe_unit(
            &service,
            &mut manager,
            &cancel,
            Instant::now() + Duration::from_secs(5),
        )?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let child: Value = loop {
            if let Ok(bytes) = fs::read(directory.join("child.json"))
                && let Ok(record) = serde_json::from_slice::<Value>(&bytes)
            {
                break record;
            }
            if Instant::now() >= deadline {
                return Err("child report deadline".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let kernel = kernel_values(&observation.status().control_group)?;
        if child["pid"] != observation.status().main_pid
            || child["cgroup"] != observation.status().control_group
            || child["kernel"] != kernel
            || kernel["memory_max"] != request.memory_bytes
            || kernel["swap_max"] != 0
            || kernel["pids_max"] != request.processes
            || kernel["cpu_max"][0].as_u64().ok_or("CPU quota")? * 100
                != kernel["cpu_max"][1]
                    .as_u64()
                    .ok_or("CPU period")?
                    * u64::from(request.cpu_percent)
            || child["nofile"] != json!([64, 64])
            || child["fsize"] != json!([16 * 1024 * 1024, 16 * 1024 * 1024])
            || child["core"] != json!([0, 0])
        {
            return Err("manager/child/kernel readbacks differ".into());
        }
        Ok(json!({
            "version": 1, "action": action.digest().to_string(), "budget": request,
            "unit": observation.unit().as_str(), "manager": observation.manager_digest().to_string(),
            "contract": observation.contract_digest().to_string(),
            "invocation": observation.status().invocation, "child": child,
            "start": format!("{completion:?}"),
            "system_recipe_executed": false, "full_budget_enforced": false,
        }))
    })();
    let cleanup = Cancellation::default();
    let stop = manager.stop(&service.unit, Duration::from_secs(5), &cleanup)?;
    let stopped = manager.wait_job(&stop, Duration::from_secs(5), &cleanup)?;
    let mut report = result?;
    let final_state = manager.query(&service.unit, Duration::from_secs(5), &cleanup)?;
    if final_state.as_ref().is_some_and(|s| {
        s.main_pid != 0 || !matches!(s.active_state.as_str(), "inactive" | "failed")
    }) {
        return Err("probe unit remains live after stop".into());
    }
    report["stop"] = json!(format!("{stopped:?}"));
    report["live_unit_after_stop"] = json!(false);
    serde_json::to_writer_pretty(
        File::create(directory.join("report.json"))?,
        &report,
    )?;
    println!("SRX_SYSTEM_SERVICE_LIMITS_OK {}", action.digest());
    Ok(())
}

fn main() -> Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [mode, report] if mode == "--child" => child(Path::new(report)),
        [bus, directory] => run(Path::new(bus), Path::new(directory)),
        _ => Err("usage: system_service_limits ABSOLUTE_USER_BUS NEW_ABSOLUTE_DIRECTORY".into()),
    }
}

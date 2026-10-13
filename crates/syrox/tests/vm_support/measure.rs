//! Separate sampled product processes from preparation and libtest accounting.
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Sampler {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Value>>,
}
impl Sampler {
    pub fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let started = Instant::now();
            let mut processes = BTreeMap::new();
            while !flag.load(Ordering::Relaxed) {
                sample(&mut processes, started.elapsed().as_secs_f64());
                std::thread::sleep(Duration::from_millis(20));
            }
            sample(&mut processes, started.elapsed().as_secs_f64());
            json!({"wall_seconds":started.elapsed().as_secs_f64(),"interval_ms":20,"clock_ticks_per_second":clock_ticks(),
                "method":"/proc samples identified by PID/starttime and candidate executable; CPU ticks and VmHWM per process, root observer reads non-dumpable workers; short lived processes may be missed; not an exact aggregate peak",
                "processes":processes.into_values().collect::<Vec<_>>()})
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
    pub fn finish(mut self) -> Value {
        self.stop.store(true, Ordering::Relaxed);
        self.thread
            .take()
            .and_then(|thread| thread.join().ok())
            .unwrap_or(json!({"error":"resource sampler panicked"}))
    }
}
impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn sample(processes: &mut BTreeMap<(u32, u64), Value>, elapsed: f64) {
    let Ok(entries) = fs::read_dir("/proc") else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let root = entry.path();
        let Ok(executable) = fs::read_link(root.join("exe")) else {
            continue;
        };
        let name = executable
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let role = match name {
            "srx" => "cli",
            "syrox-worker" => "worker",
            "worker"
                if executable
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name == "stage") =>
            {
                "worker"
            }
            name if name.starts_with("worker-")
                && executable
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("bin")) =>
            {
                "worker"
            }
            "session-payload" | "path-payload" => "payload",
            _ => {
                let status = fs::read_to_string(root.join("status")).unwrap_or_default();
                let parent = status.lines().find_map(|line| {
                    line.strip_prefix("PPid:")?
                        .trim()
                        .parse::<u32>()
                        .ok()
                });
                if !parent.is_some_and(|parent| {
                    processes.values().any(|value| {
                        value["pid"] == parent
                            && (value["role"] == "worker" || value["role"] == "payload")
                    })
                }) {
                    continue;
                }
                "payload"
            }
        };
        let Ok(stat) = fs::read_to_string(root.join("stat")) else {
            continue;
        };
        let Some((_, stat)) = stat.rsplit_once(") ") else {
            continue;
        };
        let fields: Vec<_> = stat.split_whitespace().collect();
        let number = |index: usize| fields.get(index)?.parse::<u64>().ok();
        let (Some(born), Some(user), Some(system)) = (number(19), number(11), number(12)) else {
            continue;
        };
        let status = fs::read_to_string(root.join("status")).unwrap_or_default();
        let hwm = status
            .lines()
            .find_map(|line| {
                line.strip_prefix("VmHWM:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
            .unwrap_or(0);
        let row=processes.entry((pid,born)).or_insert_with(||json!({"pid":pid,"start_ticks":born,"role":role,"executable":executable,"first_seen_user_ticks":user,"first_seen_system_ticks":system,"first_seen_seconds":elapsed}));
        row["last_seen_seconds"] = json!(elapsed);
        row["user_ticks"] = json!(user);
        row["system_ticks"] = json!(system);
        row["peak_rss_kib"] = json!(row["peak_rss_kib"].as_u64().unwrap_or(0).max(hwm));
    }
}

#[allow(unsafe_code)]
fn clock_ticks() -> libc::c_long {
    // SAFETY: sysconf reads a scalar system constant.
    unsafe { libc::sysconf(libc::_SC_CLK_TCK) }
}

/// The guest's root observer can read non-dumpable workers without changing
/// their confinement. It writes observations only, never controls product tasks.
pub fn serve(evidence: &Path) -> super::Result<()> {
    let mut gate = None;
    let mut sampler = None;
    fs::write(evidence.join("measurement-ready"), b"ready")?;
    while !evidence.join("measurement-stop").exists() {
        if let Ok(bytes) = fs::read(evidence.join("measurement-request.json")) {
            let request: Value = serde_json::from_slice(&bytes)?;
            let index = request["gate"]
                .as_u64()
                .ok_or("measurement gate missing")?;
            if request["phase"] == "start" && gate != Some(index) {
                if let (Some(previous), Some(previous_sampler)) = (gate, sampler.take()) {
                    save_measurement(evidence, previous, previous_sampler)?;
                }
                sampler = Some(Sampler::start());
                gate = Some(index);
            } else if request["phase"] == "end"
                && gate == Some(index)
                && let Some(current) = sampler.take()
            {
                save_measurement(evidence, index, current)?;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if let (Some(index), Some(current)) = (gate, sampler) {
        save_measurement(evidence, index, current)?;
    }
    Ok(())
}
fn save_measurement(evidence: &Path, index: u64, sampler: Sampler) -> super::Result<()> {
    super::common::save(
        &evidence.join(format!("gate-{index}.product-resources.json")),
        &sampler.finish(),
    )
}
pub fn begin(evidence: &Path, index: usize) -> super::Result<()> {
    if !evidence.join("measurement-ready").is_file() {
        return Err("privileged resource observer unavailable".into());
    }
    super::common::save(
        &evidence.join("measurement-request.json"),
        &json!({"gate":index,"phase":"start"}),
    )
}
pub fn finish(evidence: &Path, index: usize) -> super::Result<Value> {
    super::common::save(
        &evidence.join("measurement-request.json"),
        &json!({"gate":index,"phase":"end"}),
    )?;
    let result = evidence.join(format!("gate-{index}.product-resources.json"));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if result.is_file() {
            return Ok(serde_json::from_slice(&fs::read(result)?)?);
        }
        if Instant::now() >= deadline {
            return Err("resource observer did not flush gate measurements".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

use super::{Result, common::MAX_LOG};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Control {
    pub cancelled: Arc<AtomicBool>,
    pub cancel_file: Option<PathBuf>,
}

impl Control {
    pub fn uncancelled() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            cancel_file: None,
        }
    }

    pub fn new(cancel_file: Option<PathBuf>) -> Result<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        for signal in [
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
        ] {
            signal_hook::flag::register(signal, Arc::clone(&cancelled))?;
        }
        Ok(Self {
            cancelled,
            cancel_file,
        })
    }
    pub fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed)
            || self
                .cancel_file
                .as_ref()
                .is_some_and(|path| path.exists())
        {
            return Err("test run cancelled; evidence preserved".into());
        }
        Ok(())
    }

    /// Cancel preparation/startup as well as execution. Cleanup uses its own
    /// uncancelled control and deadline after dropping an in-flight SDK future.
    #[cfg(feature = "vm-tests")]
    pub async fn bounded<T, E: std::fmt::Display>(
        &self,
        stage: &str,
        timeout: Duration,
        future: impl Future<Output = std::result::Result<T, E>>,
    ) -> Result<T> {
        self.check()?;
        tokio::pin!(future);
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                biased;
                () = tokio::time::sleep(Duration::from_millis(40)) => self.check()?,
                () = &mut deadline => return Err(format!("{stage} timed out").into()),
                result = &mut future => {
                    self.check()?;
                    return result.map_err(|error| format!("{stage}: {error}").into());
                }
            }
        }
    }
}

/// Commands have their own process group; a deadline settles all build children.
pub fn command(
    cmd: &mut Command,
    log: &Path,
    timeout: Duration,
    control: &Control,
) -> Result<String> {
    control.check()?;
    require_waitable_children()?;
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(log)?;
    let errors = output.try_clone()?;
    cmd.stdout(Stdio::from(output))
        .stderr(Stdio::from(errors))
        .stdin(Stdio::null())
        .process_group(0);
    let started = Instant::now();
    let mut group = ProcessGroup {
        child: cmd.spawn()?,
        log: log.to_path_buf(),
        started,
        reaped: false,
    };
    loop {
        control.check()?;
        if started.elapsed() >= timeout || fs::metadata(log)?.len() > MAX_LOG {
            return Err(format!(
                "command timeout or output limit; {}",
                log.display()
            )
            .into());
        }
        if exited_without_reaping(group.child.id())? {
            // Keep the leader waitable until all group members have been
            // signalled: its PID must not be reused for an unrelated group.
            terminate_group(group.child.id());
            let status = group.reap()?;
            let text = read_log(log)?;
            if !status.success() {
                return Err(format!("command failed ({status}); {}", log.display()).into());
            }
            return Ok(text);
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

struct ProcessGroup {
    child: Child,
    log: PathBuf,
    started: Instant,
    reaped: bool,
}
impl ProcessGroup {
    #[allow(unsafe_code, clippy::cast_precision_loss)] // wait4 requires FFI; resource counters are approximate telemetry.
    fn reap(&mut self) -> Result<std::process::ExitStatus> {
        let mut status = 0;
        // SAFETY: this owned child remains waitable and unreaped; wait4 initializes
        // the bounded output structures before they are read.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        loop {
            let result = unsafe {
                libc::wait4(
                    i32::try_from(self.child.id())?,
                    &raw mut status,
                    0,
                    &raw mut usage,
                )
            };
            if result >= 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        self.reaped = true;
        let seconds =
            |value: libc::timeval| value.tv_sec as f64 + value.tv_usec as f64 / 1_000_000.0;
        super::common::save(
            &self.log.with_extension("metrics.json"),
            &serde_json::json!({
                "wall_seconds":self.started.elapsed().as_secs_f64(),"user_cpu_seconds":seconds(usage.ru_utime),
                "system_cpu_seconds":seconds(usage.ru_stime),"peak_rss_kib":usage.ru_maxrss,
                "scope":"wait4 command and waited descendants; max per-process RSS, not concurrent aggregate; Docker client excludes container workload",
                "exit_status":status
            }),
        )?;
        Ok(std::process::ExitStatus::from_raw(status))
    }
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if !self.reaped && exited_without_reaping(self.child.id()).is_ok() {
            terminate_group(self.child.id());
            let _ = self.reap();
        }
    }
}

#[allow(unsafe_code)]
fn require_waitable_children() -> std::io::Result<()> {
    // SAFETY: querying the current signal action does not alter its disposition.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut action) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if action.sa_sigaction == libc::SIG_IGN || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(std::io::Error::other(
            "test commands require waitable children",
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn exited_without_reaping(pid: u32) -> std::io::Result<bool> {
    // SAFETY: waitid initializes this siginfo and WNOWAIT preserves the child
    // identity until the group cleanup and the single final wait.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: waitid returned a valid, initialized siginfo_t.
    Ok(unsafe { info.si_pid() } != 0)
}

#[allow(unsafe_code)]
fn terminate_group(pid: u32) {
    if let Ok(pid) = i32::try_from(pid) {
        // SAFETY: the child was placed in its own group, whose positive ID is
        // the child PID. This never targets the caller's process group.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

pub fn read_log(path: &Path) -> Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(MAX_LOG)
        .read_to_string(&mut text)?;
    Ok(text)
}

pub fn append(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if file.metadata()?.len() + bytes.len() as u64 > MAX_LOG {
        return Err("log output limit".into());
    }
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

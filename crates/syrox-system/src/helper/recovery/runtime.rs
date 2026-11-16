use super::super::policy::refused;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read as _};
use std::os::unix::fs::MetadataExt as _;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Runtime {
    pub boot_id: String,
    pub pid_namespace: u64,
    pub helper_pid: u32,
    pub helper_start_ticks: u64,
}

pub(in crate::recovery) fn bounded(path: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(refused("kernel observation exceeds bound"));
    }
    Ok(bytes)
}

fn start_ticks(pid: u32) -> io::Result<u64> {
    let bytes = bounded(&format!("/proc/{pid}/stat"))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| refused("invalid process observation"))?;
    // comm can contain spaces and ')'; fields after the last ')' start at 3.
    text.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| refused("missing process start identity"))
}

impl Runtime {
    pub fn observe() -> io::Result<Self> {
        let boot = bounded("/proc/sys/kernel/random/boot_id")?;
        let boot_id = std::str::from_utf8(&boot)
            .map_err(|_| refused("invalid boot identity"))?
            .trim_end_matches('\n')
            .to_owned();
        if boot_id.len() != 36
            || !boot_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-')
        {
            return Err(refused("invalid boot identity"));
        }
        let helper_pid = std::process::id();
        Ok(Self {
            boot_id,
            pid_namespace: std::fs::metadata("/proc/self/ns/pid")?.ino(),
            helper_pid,
            helper_start_ticks: start_ticks(helper_pid)?,
        })
    }

    pub fn previous_session_ended(&self, now: &Self) -> io::Result<bool> {
        // Cross-reset or cross-namespace recovery needs separate qualification.
        if self.boot_id != now.boot_id || self.pid_namespace != now.pid_namespace {
            return Err(refused(
                "recovery requires the original boot and PID namespace",
            ));
        }
        match start_ticks(self.helper_pid) {
            Ok(ticks) => Ok(ticks != self.helper_start_ticks),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error),
        }
    }
}

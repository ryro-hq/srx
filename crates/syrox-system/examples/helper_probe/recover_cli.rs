//! Exercise the real CLI only inside the guarded disposable-VM root driver.

use super::{ID, ROOT, file_digest};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(super) fn run(state: &Path, endpoint: &str) -> io::Result<()> {
    let operation = state.join(format!("op-{ID}"));
    let authorized: serde_json::Value = serde_json::from_slice(&std::fs::read(
        operation.join("0000-authorized.json"),
    )?)?;
    let pid = authorized["details"]["runtime"]["helper_pid"]
        .as_u64()
        .unwrap();
    assert!(pid > 1);
    let deadline = Instant::now() + Duration::from_secs(30);
    while Path::new(&format!("/proc/{pid}")).try_exists()? {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Independently check both the lock and loop teardown before CLI inspection.
    let directory = File::open(state)?;
    // SAFETY: nonblocking exclusive advisory lock on this fixture's directory.
    if unsafe {
        libc::flock(
            directory.as_raw_fd(),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    drop(directory);
    super::wait_teardown(state)?;
    assert!(std::fs::read_dir(&operation)?.any(|e| {
        e.is_ok_and(|e| {
            e.file_name()
                .to_string_lossy()
                .ends_with("-uncertain.json")
        })
    }));
    let image = operation.join("scratch.img");
    let before = file_digest(&image)?;
    let entries = std::fs::read_dir(&operation)?.count();
    let report = invoke(endpoint, None, true)?.unwrap();
    assert_eq!(
        report["plan"]["action"],
        "reconcile-retained-image"
    );
    assert_eq!(report["plan"]["image_retained"], true);
    assert_eq!(
        report["plan"]["filesystem_health_verified"],
        false
    );
    let hash = report["plan_sha256"].as_str().unwrap();
    assert_eq!(std::fs::read_dir(&operation)?.count(), entries);
    assert_eq!(file_digest(&image)?, before);
    println!("SRX_HELPER_CASE_OK cli-inspect");
    invoke(endpoint, Some(&"0".repeat(64)), false)?;
    assert_eq!(std::fs::read_dir(&operation)?.count(), entries);
    assert_eq!(file_digest(&image)?, before);
    println!("SRX_HELPER_CASE_OK cli-wrong-hash");
    let receipt = invoke(endpoint, Some(hash), true)?.unwrap();
    assert_eq!(receipt["state"], "reconciled");
    assert_eq!(receipt["details"]["plan_sha256"], hash);
    assert_eq!(receipt["details"]["image_retained"], true);
    assert_eq!(
        receipt["details"]["filesystem_health_verified"],
        false
    );
    assert_eq!(
        std::fs::read_dir(&operation)?.count(),
        entries + 1
    );
    assert_eq!(file_digest(&image)?, before);
    println!("SRX_HELPER_CASE_OK cli-reconcile");
    let report = invoke(endpoint, None, true)?.unwrap();
    assert_eq!(report["plan"]["action"], "blocked");
    assert_eq!(
        std::fs::read_dir(&operation)?.count(),
        entries + 1
    );
    assert_eq!(file_digest(&image)?, before);
    println!("SRX_HELPER_CASE_OK cli-terminal");
    Ok(())
}

fn invoke(
    endpoint: &str,
    hash: Option<&str>,
    success: bool,
) -> io::Result<Option<serde_json::Value>> {
    let mut command = unprivileged_command();
    command.args([
        "--std",
        "none",
        "system",
        "recover",
        "--scratch-operation",
        ID,
        "--helper-socket",
        endpoint,
        "--json",
    ]);
    if let Some(hash) = hash {
        command.args(["--apply-plan", hash]);
    }
    let output = command.output()?;
    assert!(output.stdout.len() + output.stderr.len() <= 65_536);
    assert_eq!(
        output.status.success(),
        success,
        "CLI {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    if success {
        Ok(Some(serde_json::from_slice(&output.stdout)?))
    } else {
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        Ok(None)
    }
}

pub(super) fn unprivileged_command() -> Command {
    let mut command = Command::new(Path::new(ROOT).join("srx"));
    command.stdin(Stdio::null());
    // SAFETY: fixed UID/GID drop and CLOEXEC-only FD operation after fork.
    // The real CLI opens its connection after acquiring the non-root identity.
    unsafe {
        command.pre_exec(|| {
            if libc::setgroups(0, std::ptr::null()) < 0
                || libc::setgid(1000) < 0
                || libc::setuid(1000) < 0
                || libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

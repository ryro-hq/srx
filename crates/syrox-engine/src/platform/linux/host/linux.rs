use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::{HostCapability, HostCapabilityStatus as Status, HostInspectError, HostInspection};

const CGROUPFS: &str = "/sys/fs/cgroup";

fn bounded(path: &Path) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16 * 1024 {
        return Err(io::Error::other(
            "kernel control file exceeds 16 KiB",
        ));
    }
    String::from_utf8(bytes).map_err(io::Error::other)
}

fn membership(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .filter(|path| {
            path.starts_with('/')
                && path
                    .split('/')
                    .all(|part| part != ".." && part != ".")
        })
}

fn status(name: &'static str, probe: io::Result<String>) -> HostCapability {
    HostCapability {
        name,
        status: match probe {
            Ok(detail) => Status::Available(detail),
            Err(error) => Status::Unavailable(error.to_string()),
        },
    }
}

fn openat2() -> io::Result<String> {
    // SAFETY: zero is the kernel ABI's valid initial open_how; defined flags
    // are set explicitly before it is passed to openat2.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = u64::try_from(libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY)
        .expect("positive open flags");
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: "." is a live NUL-terminated pathname and `how` describes a
    // bounded read-only open; a successful return transfers one new FD.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c".".as_ptr(),
            &raw const how,
            size_of::<libc::open_how>(),
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let raw = i32::try_from(raw).map_err(|_| io::Error::other("openat2 FD out of range"))?;
    // SAFETY: successful openat2 returns a newly owned descriptor.
    let _file = unsafe { OwnedFd::from_raw_fd(raw) };
    Ok("read-only directory open succeeded".into())
}

fn landlock() -> io::Result<String> {
    // SAFETY: the ABI version query neither dereferences the null pointer nor
    // creates a ruleset; this does not alter the caller's sandbox policy.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0_usize,
            1_u32,
        )
    };
    if abi < 0 {
        return Err(io::Error::last_os_error());
    }
    if abi < 6 {
        return Err(io::Error::other(format!(
            "ABI {abi}; build requires >= 6"
        )));
    }
    Ok(format!("ABI {abi}"))
}

fn pidfd() -> io::Result<String> {
    let _owned = crate::platform::linux::fd::pidfd_open(std::process::id())?;
    Ok("pidfd_open(self) succeeded".into())
}

fn seccomp() -> io::Result<String> {
    let mut action = 0x8000_0000_u32; // SECCOMP_RET_KILL_PROCESS
    // SAFETY: SECCOMP_GET_ACTION_AVAIL writes one live u32, does not install a
    // filter, and returns whether this action is supported by the kernel.
    let result = unsafe { libc::syscall(libc::SYS_seccomp, 2_u32, 0_u32, &raw mut action) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok("kill-process action query succeeded".into())
}

fn cgroup_type(parent: &Path) -> io::Result<String> {
    let file = File::open(parent)?;
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: stat points to writable memory, is read only after fstatfs
    // succeeds, and the directory descriptor stays open through the call.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized the entire statfs structure.
    if unsafe { stat.assume_init() }.f_type != 0x6367_7270 {
        return Err(io::Error::other("parent is not on cgroup v2"));
    }
    Ok("cgroup v2 mounted".into())
}

fn controller(parent: &Path, name: &'static str) -> io::Result<String> {
    let available = bounded(&parent.join("cgroup.controllers"))?;
    let enabled = bounded(&parent.join("cgroup.subtree_control"))?;
    if !available
        .split_whitespace()
        .any(|entry| entry == name)
    {
        return Err(io::Error::other(format!(
            "{name} controller unavailable"
        )));
    }
    if !enabled
        .split_whitespace()
        .any(|entry| entry == name)
    {
        return Err(io::Error::other(format!(
            "{name} controller not enabled for children"
        )));
    }
    Ok("available and enabled for children".into())
}

fn probe_migration(child_path: &Path) -> io::Result<String> {
    let executable = std::env::current_exe()?;
    let mut child = Command::new(executable)
        .args(["host", "probe-child"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut reader = None;
    let result = (|| {
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("no probe pipe"))?;
        let (sender, receiver) = std::sync::mpsc::channel();
        reader = Some(std::thread::spawn(move || {
            let mut ready = [0];
            let result = stdout.read_exact(&mut ready).and_then(|()| {
                if ready == *b"R" {
                    Ok(())
                } else {
                    Err(io::Error::other("unexpected probe handshake"))
                }
            });
            let _ = sender.send(result);
        }));
        let handshake = receiver
            .recv_timeout(Duration::from_secs(5))
            .map_err(|error| io::Error::other(format!("probe handshake: {error}")))?;
        handshake?;
        if child.try_wait()?.is_some() {
            return Err(io::Error::other(
                "probe child exited before migration",
            ));
        }
        let pid = child.id();
        // cgroup.procs parses each write independently: write the complete PID
        // and newline in one syscall (writeln! may emit separate writes).
        File::options()
            .write(true)
            .open(child_path.join("cgroup.procs"))?
            .write_all(format!("{pid}\n").as_bytes())?;
        let pid_text = pid.to_string();
        if !bounded(&child_path.join("cgroup.procs"))?
            .split_whitespace()
            .any(|line| line == pid_text)
        {
            return Err(io::Error::other(
                "probe child did not appear in destination cgroup.procs",
            ));
        }
        Ok("gated srx child migrated from this CLI's cgroup and confirmed in cgroup.procs".into())
    })();
    // Even a failed migration must settle its gate before the cgroup is removed.
    let _ = child.kill();
    let settled = child.wait();
    let reader_settled = reader.map(std::thread::JoinHandle::join);
    match (result, settled) {
        (Ok(detail), Ok(_)) if matches!(reader_settled, Some(Ok(()))) => Ok(detail),
        (Ok(_), Ok(_)) => Err(io::Error::other("probe reader did not settle")),
        (Err(error), Ok(_)) => Err(error),
        (_, Err(error)) => Err(io::Error::other(format!(
            "probe child could not be reaped: {error}"
        ))),
    }
}

fn probe_child(parent: &Path) -> io::Result<(String, io::Result<String>)> {
    cgroup_type(parent)?;
    for name in ["cpu", "memory", "pids"] {
        controller(parent, name)?;
    }
    let mut nonce = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let mut suffix = String::with_capacity(32);
    for byte in nonce {
        write!(suffix, "{byte:02x}").expect("writing to String is infallible");
    }
    let child = parent.join(format!(
        "syrox-probe-{}-{suffix}",
        std::process::id()
    ));
    std::fs::create_dir(&child)?;
    let result = (|| {
        for (file, value) in [
            ("cpu.max", "100000 100000"),
            ("memory.max", "536870912"),
            ("pids.max", "64"),
        ] {
            let path = child.join(file);
            File::options()
                .write(true)
                .open(&path)?
                .write_all(value.as_bytes())?;
            if bounded(&path)?.trim() != value {
                return Err(io::Error::other(format!(
                    "{file} did not retain {value}"
                )));
            }
        }
        Ok(probe_migration(&child))
    })();
    let cleanup = std::fs::remove_dir(&child);
    match (result, cleanup) {
        (Ok(migration), Ok(())) => Ok((
            "created empty child, verified cpu/memory/pids limits, removed child".into(),
            migration,
        )),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(io::Error::other(format!(
            "probe cleanup failed for {}: {error}",
            child.display()
        ))),
        (Err(error), Err(cleanup)) => Err(io::Error::other(format!(
            "probe failed: {error}; cleanup failed for {}: {cleanup}",
            child.display()
        ))),
    }
}

fn report_probe(capabilities: &mut Vec<HostCapability>, parent: &Path, active: bool) {
    if active {
        match probe_child(parent) {
            Ok((control, migration)) => {
                capabilities.push(status("cgroup-child-control", Ok(control)));
                capabilities.push(status("cgroup-probe-migration", migration));
            }
            Err(error) => {
                let detail = error.to_string();
                capabilities.push(HostCapability {
                    name: "cgroup-child-control",
                    status: Status::Unavailable(detail.clone()),
                });
                capabilities.push(HostCapability {
                    name: "cgroup-probe-migration",
                    status: Status::Unavailable(format!("not attempted: {detail}")),
                });
            }
        }
    } else {
        capabilities.push(HostCapability {
            name: "cgroup-child-control",
            status: Status::NeedsActiveProbe(
                "pass --probe-cgroup to create, configure and remove a child".into(),
            ),
        });
        capabilities.push(HostCapability {
            name: "cgroup-probe-migration",
            status: Status::NeedsActiveProbe(
                "pass --probe-cgroup to migrate a gated srx child".into(),
            ),
        });
    }
}

pub(super) fn inspect(
    parent: Option<&Path>,
    probe_cgroup: bool,
) -> Result<HostInspection, HostInspectError> {
    let root = Path::new(CGROUPFS);
    let member = bounded(Path::new("/proc/self/cgroup"))
        .ok()
        .and_then(|contents| membership(&contents).map(str::to_owned));
    let selected = if let Some(parent) = parent {
        if !parent.is_absolute() {
            return Err(HostInspectError::InvalidCgroupParent);
        }
        parent.to_path_buf()
    } else {
        root.join(
            member
                .as_deref()
                .unwrap_or("/")
                .trim_start_matches('/'),
        )
    };
    let canonical_root = root
        .canonicalize()
        .unwrap_or_else(|_| root.to_path_buf());
    let canonical = if parent.is_some() {
        selected
            .canonicalize()
            .map_err(|_| HostInspectError::InvalidCgroupParent)?
    } else {
        selected.canonicalize().unwrap_or(selected)
    };
    if !canonical.starts_with(&canonical_root) {
        return Err(HostInspectError::InvalidCgroupParent);
    }
    let mut capabilities = vec![
        status("openat2", openat2()),
        status("pidfd", pidfd()),
        status("landlock-build", landlock()),
        status("seccomp-action", seccomp()),
        status("cgroup-v2", cgroup_type(&canonical)),
    ];
    for name in ["cpu", "memory", "pids"] {
        capabilities.push(status(name, controller(&canonical, name)));
    }
    report_probe(&mut capabilities, &canonical, probe_cgroup);
    capabilities.push(HostCapability {
        name: "cgroup.kill",
        status: if canonical == canonical_root {
            Status::Unavailable("root cgroup has no kill file; inspect a delegated child".into())
        } else {
            match std::fs::symlink_metadata(canonical.join("cgroup.kill")) {
                Ok(metadata) if metadata.file_type().is_file() => Status::NeedsActiveProbe(
                    "control file exists; write authority has not been tested".into(),
                ),
                Ok(_) => Status::Unavailable("cgroup.kill is not a control file".into()),
                Err(error) => Status::Unavailable(error.to_string()),
            }
        },
    });
    capabilities.push(HostCapability {
        name: "cgroup-delegation",
        status: Status::NeedsActiveProbe(
            "write authority and common-ancestor migration require executor creation".into(),
        ),
    });
    capabilities.push(HostCapability {
        name: "namespace-launch",
        status: Status::NeedsActiveProbe(
            "user/PID/mount namespaces and mounts require a contained launch".into(),
        ),
    });
    if member.is_none() {
        capabilities.push(HostCapability {
            name: "cgroup-membership",
            status: Status::Unavailable("no cgroup v2 membership in /proc/self/cgroup".into()),
        });
    }
    Ok(HostInspection {
        cgroup_parent: canonical,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_parsing_refuses_parent_traversal_and_v1_only() {
        assert_eq!(
            membership("2:cpu:/group\n0::/user/a\n"),
            Some("/user/a")
        );
        assert_eq!(membership("0::/user/../root\n"), None);
        assert_eq!(membership("2:cpu:/group\n"), None);
    }

    #[test]
    fn inspection_does_not_claim_delegation_from_readable_control_files() {
        let report = inspect(None, false).unwrap();
        assert!(
            report
                .capabilities
                .iter()
                .any(|item| item.name == "cgroup-delegation"
                    && matches!(item.status, Status::NeedsActiveProbe(_)))
        );
        assert!(
            report
                .capabilities
                .iter()
                .any(|item| item.name == "namespace-launch"
                    && matches!(item.status, Status::NeedsActiveProbe(_)))
        );
        assert!(matches!(
            inspect(Some(Path::new("/tmp")), false),
            Err(HostInspectError::InvalidCgroupParent)
        ));
    }
}

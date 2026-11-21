//! Qualification payload for the isolated tool runner, not a storage utility.
//!
//! Run only through `ext4_tool::run` in the marked disposable guest probe. All
//! forbidden syscall attempts use harmless arguments, even if the filter fails.
#![expect(
    clippy::unwrap_used,
    reason = "qualification probe: a failed step aborts the run"
)]
#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

#[repr(C)]
struct Header {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn main() -> io::Result<()> {
    // A separate unprivileged host oracle checks runtime startup under the
    // actual filter before repeating the expensive firmware/disk guest test.
    // The privileged runner clears this variable and always takes the full path.
    if std::env::var("SRX_TOOL_STARTUP_PROBE").as_deref() == Ok("1") {
        println!("SRX_TOOL_STARTUP_OK");
        return Ok(());
    }
    assert_eq!(
        std::env::args().skip(1).collect::<Vec<_>>(),
        ["-f", "-n", "/image"]
    );
    // Check before opening any files: descriptors retained by the runner or
    // deliberately inherited by the qualification parent must not survive exec.
    for fd in 3..4096 {
        assert_eq!(
            // SAFETY: F_GETFD is an observation, with no pointer argument.
            unsafe { libc::fcntl(fd, libc::F_GETFD) },
            -1,
            "inherited fd {fd}"
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }
    assert_eq!(
        std::env::current_dir()?,
        std::path::Path::new("/")
    );
    assert_eq!(std::fs::read("/config")?, []);
    let mut entries = std::fs::read_dir("/")?
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(entries, ["config", "dev", "image"]);
    for path in [
        "/etc/passwd",
        "/proc/self/fd",
        "/dev/zero",
        "/sys",
        "/../etc/passwd",
        "/tool",
    ] {
        assert_eq!(
            File::open(path).unwrap_err().kind(),
            io::ErrorKind::NotFound,
            "{path}"
        );
    }
    for path in ["/config", "/image"] {
        assert_eq!(
            OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EROFS),
            "{path}"
        );
    }
    let image = File::open("/image")?;
    assert!(image.metadata()?.is_file());
    let null = File::open("/dev/null")?.metadata()?;
    assert!(null.file_type().is_char_device());
    assert_eq!(null.rdev(), libc::makedev(1, 3));
    let devices = std::fs::read_dir("/dev")?
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(devices, ["null"]);
    for (resource, expected) in [
        (libc::RLIMIT_AS, 256 << 20),
        (libc::RLIMIT_STACK, 8 << 20),
        (libc::RLIMIT_CPU, 60),
        (libc::RLIMIT_NOFILE, 64),
        (libc::RLIMIT_NPROC, 0),
        (libc::RLIMIT_CORE, 0),
        (libc::RLIMIT_FSIZE, 64 << 20),
    ] {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            // SAFETY: fixed supported resource and writable ABI output storage.
            unsafe { libc::getrlimit(resource, &raw mut limit) },
            0
        );
        assert_eq!(
            (limit.rlim_cur, limit.rlim_max),
            (expected, expected)
        );
    }
    // Each syscall is effect-free if unexpectedly allowed: signal zero,
    // invalid clone3 pointers, setuid to the unchanged UID, read-only prlimit
    // request for an impossible PID, null mount arguments, etc.
    // SAFETY: only documented no-effect/invalid arguments; no fork or signal.
    unsafe {
        denied(libc::syscall(
            libc::SYS_clone3,
            std::ptr::null::<u8>(),
            0_usize,
        ));
        denied(libc::syscall(libc::SYS_kill, libc::getppid(), 0));
        denied(libc::syscall(
            libc::SYS_tgkill,
            libc::getpid(),
            libc::gettid(),
            0,
        ));
        denied(libc::syscall(libc::SYS_setuid, libc::getuid()));
        denied(libc::syscall(libc::SYS_unshare, 0));
        denied(libc::syscall(
            libc::SYS_prlimit64,
            i32::MAX,
            0,
            std::ptr::null::<u8>(),
            std::ptr::null::<u8>(),
        ));
    }
    let zero = Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };
    let mut data = [zero; 2];
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    assert_eq!(
        // SAFETY: exact version-3 capget ABI storage, querying only this process.
        unsafe {
            libc::syscall(
                libc::SYS_capget,
                &raw const header,
                data.as_mut_ptr(),
            )
        },
        0
    );
    assert_eq!(
        data, [zero; 2],
        "capabilities recovered across exec"
    );
    println!("SRX_EXT4_TOOL_ISOLATION_PROBE_OK");
    Ok(())
}

fn denied(value: i64) {
    assert_eq!(value, -1);
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
}

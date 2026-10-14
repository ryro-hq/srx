use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

const READ: u64 = (1 << 0) | (1 << 2) | (1 << 3);
const WRITE: u64 = (1 << 1)
    | (1 << 4)
    | (1 << 5)
    | (1 << 7)
    | (1 << 8)
    | (1 << 9)
    | (1 << 10)
    | (1 << 12)
    | (1 << 13)
    | (1 << 14);
const HANDLED: u64 = (1 << 16) - 1;

#[repr(C)]
struct Ruleset {
    fs: u64,
    net: u64,
    scoped: u64,
}
#[repr(C, packed)]
struct PathRule {
    access: u64,
    parent: i32,
}

fn invalid() -> io::Error {
    io::Error::other("managed build worker confinement is missing")
}

pub(crate) fn validate_environment() -> io::Result<()> {
    // SAFETY: identity queries have no memory arguments or side effects.
    let (pid, parent, uid, gid, effective_user, effective_group) = unsafe {
        (
            libc::getpid(),
            libc::getppid(),
            libc::getuid(),
            libc::getgid(),
            libc::geteuid(),
            libc::getegid(),
        )
    };
    if pid <= 1
        || parent != 1
        || uid == 0
        || gid == 0
        || uid != effective_user
        || gid != effective_group
    {
        return Err(invalid());
    }
    check_mount("/proc", true, Some(0x9fa0))?;
    identity_map(&read_bounded("/proc/self/uid_map", 4096)?, uid)?;
    identity_map(&read_bounded("/proc/self/gid_map", 4096)?, gid)?;
    let status = read_bounded("/proc/self/status", 64 * 1024)?;
    if !status
        .lines()
        .any(|line| line == format!("Pid:\t{pid}"))
        || !status.lines().any(|line| line == "PPid:\t1")
    {
        return Err(invalid());
    }
    for required in [
        "NoNewPrivs:\t1",
        "CapEff:\t0000000000000000",
        "CapPrm:\t0000000000000000",
        "CapInh:\t0000000000000000",
        "CapAmb:\t0000000000000000",
        "CapBnd:\t0000000000000000",
    ] {
        if !status.lines().any(|line| line == required) {
            return Err(invalid());
        }
    }
    for path in [
        "/",
        "/proc",
        "/source",
        "/syrox-worker",
        "/build-action",
        "/build-program",
    ] {
        check_mount(path, true, None)?;
    }
    for path in ["/work", "/out", "/tmp"] {
        check_mount(path, false, Some(0x0102_1994))?;
    }
    check_mount("/proc", true, Some(0x9fa0))?;
    check_mount("/", true, Some(0x0102_1994))?;
    for path in [
        "/source",
        "/syrox-worker",
        "/build-action",
        "/build-program",
    ] {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.mode() & 0o222 != 0 {
            return Err(invalid());
        }
    }
    drop(super::environment::open_null()?);
    match std::fs::symlink_metadata("/usr") {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(invalid()),
    }
}

fn identity_map(text: &str, id: u32) -> io::Result<()> {
    let mut values = text.split_whitespace();
    for expected in [id, id, 1] {
        if values
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            != Some(expected)
        {
            return Err(invalid());
        }
    }
    if values.next().is_none() {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn read_bounded(path: &str, maximum: u64) -> io::Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_string(&mut text)?;
    if u64::try_from(text.len()).map_err(io::Error::other)? > maximum {
        return Err(invalid());
    }
    Ok(text)
}

fn check_mount(path: &str, readonly: bool, filesystem: Option<i64>) -> io::Result<()> {
    let file = crate::platform::linux::fd::open_path(std::path::Path::new(path))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: both outputs are writable, fd is live.
    unsafe {
        super::checked(libc::fstatvfs(file.as_raw_fd(), stat.as_mut_ptr()).into())?;
        super::checked(libc::fstatfs(file.as_raw_fd(), fs.as_mut_ptr()).into())?;
        if (stat.assume_init().f_flag & libc::ST_RDONLY != 0) != readonly
            || filesystem.is_some_and(|expected| {
                !crate::platform::linux::fd::filesystem_magic_matches(
                    fs.assume_init().f_type,
                    expected,
                )
            })
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// # Safety
/// Only a dedicated, single-threaded worker process may call this function.
/// It must exit on failure: an error can follow a partially installed policy.
pub(crate) unsafe fn install() -> io::Result<()> {
    // No inherited authority beyond the three explicit stdio channels survives.
    // SAFETY: the caller owns this dedicated process and its descriptor table.
    super::checked(unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 2_u32) })?;
    crate::platform::linux::fd::require_build_landlock()?;
    let attributes = Ruleset {
        fs: HANDLED,
        net: 0,
        scoped: 0,
    };
    // SAFETY: attributes is the ABI 6 ruleset structure and remains live.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attributes,
            size_of::<Ruleset>(),
            0_u32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful syscall returns a new owned fd.
    let ruleset = unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).map_err(io::Error::other)?) };
    add_rule(&ruleset, "/", READ)?;
    for path in ["/work", "/out", "/tmp"] {
        add_rule(&ruleset, path, READ | WRITE)?;
    }
    add_rule(&ruleset, "/dev/null", (1 << 1) | (1 << 2))?;
    // SAFETY: no new privileges is already required; live ruleset is immutable.
    super::checked(unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            ruleset.as_raw_fd(),
            0_u32,
        )
    })?;
    let mut instructions = decode_filter(&crate::build::policy::seccomp_filter())?;
    let program = libc::sock_fprog {
        len: u16::try_from(instructions.len()).map_err(io::Error::other)?,
        filter: instructions.as_mut_ptr(),
    };
    // SAFETY: aligned filter storage remains live through the copying syscall.
    super::checked(
        unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &raw const program,
                0,
                0,
            )
        }
        .into(),
    )
}

fn add_rule(ruleset: &OwnedFd, path: &str, access: u64) -> io::Result<()> {
    let file = crate::platform::linux::fd::open_path(std::path::Path::new(path))?;
    let rule = PathRule {
        access,
        parent: file.as_raw_fd(),
    };
    // SAFETY: packed rule exactly matches landlock_path_beneath_attr ABI.
    super::checked(unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            1_u32,
            &raw const rule,
            0_u32,
        )
    })
}

fn decode_filter(bytes: &[u8]) -> io::Result<Vec<libc::sock_filter>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(8) || bytes.len() / 8 > 4096 {
        return Err(invalid());
    }
    Ok(bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| libc::sock_filter {
            code: u16::from_le_bytes([chunk[0], chunk[1]]),
            jt: chunk[2],
            jf: chunk[3],
            k: u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_mapping_excludes_initial_or_wider_namespaces() {
        assert!(identity_map("1000 1000 1\n", 1000).is_ok());
        for text in [
            "0 0 4294967295",
            "0 1000 1",
            "1000 1000 2",
            "1000 1000 1\n1001 1001 1",
        ] {
            assert!(identity_map(text, 1000).is_err());
        }
    }

    #[test]
    fn landlock_layout_and_access_are_explicit() {
        assert_eq!(size_of::<Ruleset>(), 24);
        assert_eq!(size_of::<PathRule>(), 12);
        assert_eq!(READ & WRITE, 0);
        assert_eq!(WRITE & ((1 << 6) | (1 << 11)), 0);
        assert_eq!((READ | WRITE) & !HANDLED, 0);
    }

    #[test]
    fn shared_filter_decodes_without_unaligned_access() {
        let bytes = crate::build::policy::seccomp_filter();
        let decoded = decode_filter(&bytes).unwrap();
        assert_eq!(decoded.len() * 8, bytes.len());
        assert_eq!(decoded[0].code, 0x20);
        assert_eq!(decoded[1].k, 0xc000_003e);
        assert_eq!(decoded.last().unwrap().k, 0x7fff_0000);
        assert!(decode_filter(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode_filter(&[]).is_err());
    }

    fn verdict(arch: u32, syscall: u32, flags: u32) -> u32 {
        let filter = decode_filter(&crate::build::policy::seccomp_filter()).unwrap();
        let mut pc = 0;
        let mut accumulator = 0;
        loop {
            let instruction = &filter[pc];
            match instruction.code {
                0x20 => {
                    accumulator = match instruction.k {
                        0 => syscall,
                        4 => arch,
                        16 => flags,
                        _ => panic!("unknown data offset"),
                    }
                }
                0x15 => {
                    pc += usize::from(if accumulator == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    });
                }
                0x45 => {
                    pc += usize::from(if accumulator & instruction.k != 0 {
                        instruction.jt
                    } else {
                        instruction.jf
                    });
                }
                0x06 => return instruction.k,
                _ => panic!("unknown instruction"),
            }
            pc += 1;
        }
    }

    #[test]
    fn shared_filter_preserves_architecture_network_namespace_and_thread_rules() {
        const ARCH: u32 = 0xc000_003e;
        assert_eq!(verdict(0, 0, 0), 0x8000_0000);
        assert_eq!(verdict(ARCH, 0x4000_0000, 0), 0x8000_0000);
        assert_eq!(verdict(ARCH, 435, 0), 0x0005_0026);
        for syscall in [41, 42, 101, 165, 272, 321, 425, 438] {
            assert_eq!(verdict(ARCH, syscall, 0), 0x0005_0001);
        }
        assert_eq!(verdict(ARCH, 56, 0x1000_0000), 0x0005_0001);
        assert_eq!(verdict(ARCH, 56, 0x0001_0900), 0x7fff_0000);
        for syscall in [0, 1, 3, 59, 61, 257] {
            assert_eq!(verdict(ARCH, syscall, 0), 0x7fff_0000);
        }
    }
}

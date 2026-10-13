//! Credenciais e identidades de processos obtidas por handles do kernel.
//!
//! Um PID numérico pode ser reutilizado. O pidfd mantém a referência ao processo
//! observado; os descritores dos namespaces guardam as identidades usadas nas
//! comparações seguintes.

use super::{
    AsFd, AsRawFd, BorrowedFd, File, FromRawFd, Metadata, OwnedFd, filesystem_type, io, metadata,
    status_flags,
};

pub(crate) fn real_uid() -> u32 {
    // SAFETY: getuid takes no pointers and only observes this process.
    unsafe { libc::getuid() }
}

pub(crate) fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no pointers and only observes this process.
    unsafe { libc::geteuid() }
}
pub(crate) fn real_gid() -> u32 {
    // SAFETY: getgid only observes this process's credentials.
    unsafe { libc::getgid() }
}
pub(crate) fn effective_gid() -> u32 {
    // SAFETY: getegid only observes this process's credentials.
    unsafe { libc::getegid() }
}

/// Pin the namespace init process before unblocking Bubblewrap's payload. A
/// pidfd becomes readable only after the kernel has completed process exit.
pub(crate) fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    loop {
        // SAFETY: pid is supplied by Bubblewrap's bounded info record; flags=0
        // follows the pidfd_open ABI and success transfers one new descriptor.
        let result = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if result >= 0 {
            let raw = libc::c_int::try_from(result)
                .map_err(|_| io::Error::other("pidfd exceeds supported descriptor range"))?;
            // SAFETY: a successful pidfd_open returns a newly owned descriptor.
            return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Stop the process pinned by a kernel descriptor. Signalling a numeric PID
/// here could target an unrelated process after PID reuse.
pub(crate) fn kill_pidfd(fd: BorrowedFd<'_>) -> io::Result<()> {
    loop {
        // SAFETY: fd is a live pidfd, siginfo is null for a standard signal,
        // flags=0 follows the pidfd_send_signal ABI. No pointer is dereferenced.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                libc::SIGKILL,
                0,
                0,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(error);
    }
}

/// Check that an authenticated handoff supplied a usable pidfd. Signal zero
/// only probes the handle; ESRCH is also valid for an already-exited process.
/// This does not establish whose namespace it is: that binding belongs to the
/// authenticated launcher transaction, and exit still needs separate observation.
pub(crate) fn validate_pidfd(fd: BorrowedFd<'_>) -> io::Result<()> {
    loop {
        // SAFETY: borrowed descriptor stays live, signal zero has no delivery,
        // siginfo is null and flags are zero as required by pidfd_send_signal.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// A pidfs inode identifies one retained kernel `struct pid`, unlike historical
/// shared anonymous inodes. Require the filesystem capability, not uname.
/// See Linux v6.12 `fs/pidfs.c` (`pidfs_inum`, `pidfs_alloc_file`).
pub(crate) fn require_unique_pidfd(fd: BorrowedFd<'_>) -> io::Result<Metadata> {
    let metadata = pidfs_metadata(fd)?;
    validate_pidfd(fd)?;
    Ok(metadata)
}
// Structural pidfs validation for descriptors obtained directly from pidfd_open.
// It does not request permission to signal a foreign process (e.g. observer PID1).
pub(super) fn pidfs_metadata(fd: BorrowedFd<'_>) -> io::Result<Metadata> {
    if filesystem_type(fd)? != 0x5049_4446 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unique pidfs identities required",
        ));
    }
    let metadata = metadata(fd)?;
    if metadata.identity.device == 0
        || metadata.identity.inode == 0
        || metadata.mode & libc::S_IFMT != 0
        || metadata.rdev != 0
    {
        return Err(io::Error::other(
            "unexpected pidfs inode metadata",
        ));
    }
    let flags = descriptor_status_flags(fd)?;
    if flags & (libc::O_PATH | libc::O_EXCL).cast_unsigned() != 0 {
        return Err(io::Error::other(
            "thread-only or path pidfd is unsupported",
        ));
    }
    Ok(metadata)
}
pub(crate) fn descriptor_status_flags(fd: BorrowedFd<'_>) -> io::Result<u32> {
    status_flags(fd).map(i32::cast_unsigned)
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum PidfdNamespace {
    Mount,
    Pid,
    User,
}
/// Kernel-returned namespace descriptor, with no procfs magic-link traversal.
/// Missing namespace ioctls are an unsupported capability, never a fallback.
pub(crate) fn pidfd_namespace(
    fd: BorrowedFd<'_>,
    namespace: PidfdNamespace,
) -> io::Result<OwnedFd> {
    let request = match namespace {
        PidfdNamespace::Mount => 0xff03,
        PidfdNamespace::Pid => 0xff05,
        PidfdNamespace::User => 0xff09,
    };
    loop {
        // SAFETY: PIDFD_GET_*_NAMESPACE takes argument zero and returns a new fd.
        let result = unsafe { libc::ioctl(fd.as_raw_fd(), request, 0) };
        if result >= 0 {
            // SAFETY: successful namespace ioctl transfers this fresh descriptor.
            let namespace = unsafe { OwnedFd::from_raw_fd(result) };
            if filesystem_type(namespace.as_fd())? != 0x6e73_6673 {
                return Err(io::Error::other(
                    "namespace descriptor is not nsfs",
                ));
            }
            return Ok(namespace);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Obtain the parent of a hierarchical nsfs namespace (`NS_GET_PARENT`).
/// Permission or capability failure is not evidence of a parent relationship.
pub(crate) fn namespace_parent(namespace: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    if filesystem_type(namespace)? != 0x6e73_6673 {
        return Err(io::Error::other("expected nsfs"));
    }
    // SAFETY: NS_GET_PARENT takes no pointer and returns one newly owned fd.
    let result = unsafe { libc::ioctl(namespace.as_raw_fd(), 0xb702, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful ioctl transferred this new descriptor.
    let parent = unsafe { OwnedFd::from_raw_fd(result) };
    if filesystem_type(parent.as_fd())? != 0x6e73_6673 {
        return Err(io::Error::other("namespace parent is not nsfs"));
    }
    Ok(parent)
}

/// The kernel's dynamic procfs self link identifies this proc mount's PID view.
pub(crate) fn proc_self_pid(proc: BorrowedFd<'_>) -> io::Result<u32> {
    if filesystem_type(proc)? != 0x9fa0 {
        return Err(io::Error::other("expected procfs"));
    }
    let mut bytes = [0u8; 32];
    // SAFETY: fixed NUL-terminated name and writable bounded buffer.
    let count = unsafe {
        libc::readlinkat(
            proc.as_raw_fd(),
            c"self".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    let count = usize::try_from(count).map_err(|_| io::Error::last_os_error())?;
    if count >= bytes.len() {
        return Err(io::Error::other("proc self PID exceeds bound"));
    }
    let text = std::str::from_utf8(&bytes[..count]).map_err(io::Error::other)?;
    let pid: u32 = text.parse().map_err(io::Error::other)?;
    if pid == 0 || pid.to_string() != text {
        return Err(io::Error::other("noncanonical proc self PID"));
    }
    Ok(pid)
}
/// Follow only the kernel's executable magic link beneath an already pinned
/// numeric proc directory. The caller checks process liveness and image bytes.
pub(crate) fn open_proc_executable(proc: BorrowedFd<'_>) -> io::Result<File> {
    if filesystem_type(proc)? != 0x9fa0 {
        return Err(io::Error::other("expected procfs"));
    }
    // SAFETY: fixed kernel link, live dirfd; success transfers a new descriptor.
    let fd = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            c"exe".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat success transferred this descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Observe an already-validated pidfd without waiting or signalling a process.
pub(crate) fn pidfd_exited(fd: BorrowedFd<'_>) -> io::Result<bool> {
    loop {
        let mut event = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: event is writable and its borrowed descriptor remains live.
        let result = unsafe { libc::poll(&raw mut event, 1, 0) };
        if result >= 0 {
            if event.revents & !(libc::POLLIN | libc::POLLHUP) != 0 {
                return Err(io::Error::other(
                    "unexpected pidfd readiness event",
                ));
            }
            return Ok(event.revents & libc::POLLIN != 0);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(crate) fn wait_pidfd(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: poll points to one initialized pollfd and remains live here.
        let result = unsafe { libc::poll(&raw mut poll, 1, -1) };
        if result > 0 {
            if poll.revents & libc::POLLIN != 0 {
                return Ok(());
            }
            return Err(io::Error::other(
                "namespace init pidfd reported an unexpected event",
            ));
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

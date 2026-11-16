//! Descriptor primitives shared by the engine and privileged system helper.
//!
//! Path-only pinning opens neither a device nor a socket endpoint. The final
//! symlink is pinned, never followed. Callers must still validate ownership,
//! resource type, identity and authority before performing any operation.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

pub mod pinned_tool;
pub mod sealed;
mod transport;
pub use transport::{PeerCredentials, peer_credentials, receive_fd, send_fd, seqpacket_pair};

/// Pin a node without opening its device or socket. The final symlink is pinned,
/// never followed; callers must validate the node's type and identity.
pub fn open_path(path: &Path) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // musl includes O_PATH in O_ACCMODE, which OpenOptions removes from custom
    // flags. Calling open directly preserves this handle's path-only contract.
    loop {
        // SAFETY: the C string is live; these flags require no mode argument.
        let raw = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw >= 0 {
            // SAFETY: successful open transfers a fresh descriptor to this owner.
            return Ok(unsafe { File::from_raw_fd(raw) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Open read-only using kernel path-resolution constraints. `None` selects the
/// current working directory; `Some` keeps a pinned base descriptor borrowed.
/// There is no fallback when `openat2` or a requested constraint is unsupported.
/// This primitive does not select authority or authorize a device; callers must
/// restrict their scope and validate the opened node before consuming it.
pub fn open_resolved(
    directory: Option<BorrowedFd<'_>>,
    path: &Path,
    directory_only: bool,
    resolve: u64,
) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL byte",
        )
    })?;
    let mut flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;
    if directory_only {
        flags |= libc::O_DIRECTORY;
    }
    // SAFETY: open_how's all-zero representation is valid; every defined field
    // is set before passing its fixed ABI layout to the kernel.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = u64::try_from(flags).expect("Linux open flags are nonnegative");
    how.resolve = resolve;
    loop {
        // SAFETY: the borrowed directory remains open, both pointers are live,
        // and the exact open_how size matches libc's syscall ABI declaration.
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                directory.map_or(libc::AT_FDCWD, |fd| fd.as_raw_fd()),
                path.as_ptr(),
                &raw const how,
                size_of::<libc::open_how>(),
            )
        };
        if result >= 0 {
            let descriptor = i32::try_from(result).map_err(|_| {
                io::Error::other("openat2 returned a descriptor outside the supported range")
            })?;
            // SAFETY: a successful openat2 returns one newly owned descriptor.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Read the shared open-file-description status flags without changing them.
pub fn status_flags(fd: BorrowedFd<'_>) -> io::Result<i32> {
    // SAFETY: F_GETFL only queries the live borrowed descriptor.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

/// Require an actual read-only descriptor, excluding path-only handles.
pub fn require_readonly(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: fcntl reads descriptor flags; the borrowed descriptor remains live.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_PATH != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descriptor is not read-only",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Existing lock modes; shared acquisition is nonblocking.
pub enum FlockMode {
    Unlock,
    Shared,
    Exclusive,
    ExclusiveNonblocking,
}

/// Return false on nonblocking contention. Exclusive acquisition can block;
/// deadline-aware callers must use the nonblocking mode and bounded retries.
pub fn flock(file: BorrowedFd<'_>, mode: FlockMode) -> io::Result<bool> {
    let operation = match mode {
        FlockMode::Unlock => libc::LOCK_UN,
        FlockMode::Shared => libc::LOCK_SH | libc::LOCK_NB,
        FlockMode::Exclusive => libc::LOCK_EX,
        FlockMode::ExclusiveNonblocking => libc::LOCK_EX | libc::LOCK_NB,
    };
    loop {
        // SAFETY: `file` is live and `operation` is one of flock's documented values.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(true);
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if source.raw_os_error() == Some(libc::EWOULDBLOCK)
            || source.raw_os_error() == Some(libc::EAGAIN)
        {
            return Ok(false);
        }
        return Err(source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::net::UnixListener;

    #[test]
    fn socket_handle_is_path_only_close_on_exec_and_cannot_read() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("socket");
        let _listener = UnixListener::bind(&path).unwrap();
        let handle = open_path(&path).unwrap();
        assert_ne!(
            status_flags(handle.as_fd()).unwrap() & libc::O_PATH,
            0
        );
        let expected = std::fs::symlink_metadata(&path).unwrap();
        let actual = handle.metadata().unwrap();
        assert_eq!(
            (actual.dev(), actual.ino()),
            (expected.dev(), expected.ino())
        );
        assert_eq!(actual.mode() & libc::S_IFMT, libc::S_IFSOCK);
        // SAFETY: live descriptor and a writable single-byte buffer.
        unsafe {
            assert_eq!(
                libc::fcntl(handle.as_raw_fd(), libc::F_GETFD) & libc::FD_CLOEXEC,
                libc::FD_CLOEXEC
            );
            assert_eq!(
                libc::read(
                    handle.as_raw_fd(),
                    [0_u8; 1].as_mut_ptr().cast(),
                    1
                ),
                -1
            );
        }
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn final_symlink_is_pinned_without_opening_its_target() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("link");
        std::os::unix::fs::symlink("/dev/tty", &path).unwrap();
        let handle = open_path(&path).unwrap();
        let expected = std::fs::symlink_metadata(&path).unwrap();
        let actual = handle.metadata().unwrap();
        assert_eq!(
            (actual.dev(), actual.ino()),
            (expected.dev(), expected.ino())
        );
        assert_eq!(actual.mode() & libc::S_IFMT, libc::S_IFLNK);
    }

    #[test]
    fn readonly_checks_reject_writable_and_path_only_descriptors_without_changing_flags() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data");
        let writable = File::create(&path).unwrap();
        let flags = status_flags(writable.as_fd()).unwrap();
        assert!(require_readonly(writable.as_fd()).is_err());
        assert_eq!(status_flags(writable.as_fd()).unwrap(), flags);
        let path_only = open_path(&path).unwrap();
        assert!(require_readonly(path_only.as_fd()).is_err());
        let readonly = File::open(&path).unwrap();
        require_readonly(readonly.as_fd()).unwrap();
        assert_eq!(
            status_flags(readonly.as_fd()).unwrap() & libc::O_ACCMODE,
            libc::O_RDONLY
        );
    }

    #[test]
    fn kernel_resolution_contains_paths_and_refuses_symlinks_and_wrong_node_types() {
        use std::io::Read as _;
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("child")).unwrap();
        std::fs::write(root.path().join("child/data"), b"verified data").unwrap();
        std::os::unix::fs::symlink("child", root.path().join("link")).unwrap();
        std::os::unix::fs::symlink("child/data", root.path().join("leaf")).unwrap();
        let base = File::open(root.path()).unwrap();
        let resolution =
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
        let mut file = open_resolved(
            Some(base.as_fd()),
            Path::new("child/data"),
            false,
            resolution,
        )
        .unwrap();
        require_readonly(file.as_fd()).unwrap();
        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        assert_eq!(text, "verified data");
        for (path, error) in [
            ("..", libc::EXDEV),
            ("link/data", libc::ELOOP),
            ("leaf", libc::ELOOP),
        ] {
            assert_eq!(
                open_resolved(
                    Some(base.as_fd()),
                    Path::new(path),
                    false,
                    resolution
                )
                .unwrap_err()
                .raw_os_error(),
                Some(error)
            );
        }
        assert_eq!(
            open_resolved(
                Some(base.as_fd()),
                Path::new("child/data"),
                true,
                resolution
            )
            .unwrap_err()
            .raw_os_error(),
            Some(libc::ENOTDIR)
        );
        let opened = open_resolved(
            None,
            root.path(),
            true,
            libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
        )
        .unwrap();
        assert_eq!(
            opened.metadata().unwrap().ino(),
            base.metadata().unwrap().ino()
        );
    }
}

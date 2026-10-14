use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

/// Pin a node without opening its device or socket. The final symlink is pinned,
/// never followed; callers must validate the node's type and identity.
pub(crate) fn open_path(path: &Path) -> io::Result<File> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd as _, AsRawFd as _};
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::net::UnixListener;

    #[test]
    fn socket_handle_is_path_only_close_on_exec_and_cannot_read() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("socket");
        let _listener = UnixListener::bind(&path).unwrap();
        let handle = open_path(&path).unwrap();
        assert_ne!(
            super::super::status_flags(handle.as_fd()).unwrap() & libc::O_PATH,
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
}

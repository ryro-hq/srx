use super::refused;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;

// A description retains its OLD mount namespace after CLONE_NEWNS. Reopen the
// same inode in the new namespace before using it as a mount source/target.
// Namespace-local resolution is constrained and identity is checked again;
// deleted/moved/inaccessible inputs fail, without following an alternate path.
pub(super) struct Reopen {
    path: CString,
    device: u64,
    inode: u64,
    directory: bool,
    bytes: u64,
}

impl Reopen {
    pub(super) fn new(fd: BorrowedFd<'_>, directory: bool) -> io::Result<Self> {
        let file = File::from(fd.try_clone_to_owned()?);
        let metadata = file.metadata()?;
        let path = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(refused(
                "tool input lacks a bounded absolute namespace path",
            ));
        }
        Ok(Self {
            path: CString::new(path.as_os_str().as_bytes())
                .map_err(|_| refused("invalid tool input path"))?,
            device: metadata.dev(),
            inode: metadata.ino(),
            directory,
            bytes: metadata.len(),
        })
    }

    // Only stack storage and syscalls: called after fork, before exec.
    pub(super) fn open(&self) -> io::Result<i32> {
        // SAFETY: zero is a valid initialized open_how ABI representation.
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = u64::try_from(
            libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | if self.directory {
                    libc::O_RDONLY | libc::O_DIRECTORY
                } else {
                    libc::O_RDWR
                },
        )
        .unwrap();
        how.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
        // SAFETY: bounded parent-prepared C string, initialized fixed ABI input.
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                self.path.as_ptr(),
                &raw const how,
                size_of::<libc::open_how>(),
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = i32::try_from(result).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        // SAFETY: stat is writable output-only ABI storage; fd is newly opened.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &raw mut stat) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let expected_mode = if self.directory {
            libc::S_IFDIR | 0o700
        } else {
            libc::S_IFREG | 0o600
        };
        if stat.st_dev != self.device
            || stat.st_ino != self.inode
            || stat.st_uid != 0
            || stat.st_mode & (libc::S_IFMT | 0o7777) != expected_mode
            || (!self.directory
                && (stat.st_nlink != 1 || u64::try_from(stat.st_size).ok() != Some(self.bytes)))
        {
            // No owned Rust file/drop machinery is used in the post-fork path.
            // SAFETY: close only our newly opened description on mismatch.
            unsafe {
                libc::close(fd);
            }
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(fd)
    }
}

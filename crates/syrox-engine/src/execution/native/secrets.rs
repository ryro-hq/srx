use super::mount;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::Path;
use std::path::PathBuf;

pub(super) fn mount_secret(source: &Path, destination: &Path) -> io::Result<()> {
    let file = std::fs::File::open(source)?;
    crate::platform::linux::fd::sealed_file::validate(file.as_fd())?;
    let identity = crate::platform::linux::fd::metadata(file.as_fd())?.identity();
    std::fs::create_dir_all(
        destination
            .parent()
            .ok_or_else(|| io::Error::other("secret target"))?,
    )?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    // Use our own live descriptor, with no read_link/path reopening. The private
    // namespace owns the mountpoint; MS_BIND is deliberately nonrecursive.
    let donor = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    mount(Some(&donor), destination, None, libc::MS_BIND)?;
    mount(
        None,
        destination,
        None,
        libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_RDONLY
            | libc::MS_NOSUID
            | libc::MS_NODEV
            | libc::MS_NOEXEC,
    )?;
    let mounted = std::fs::File::open(destination)?;
    crate::platform::linux::fd::sealed_file::validate(mounted.as_fd())?;
    if crate::platform::linux::fd::metadata(mounted.as_fd())?.identity() != identity {
        return Err(io::Error::other(
            "secret mounted identity changed",
        ));
    }
    Ok(())
}

use super::{FileType, filesystem_type, metadata, status_flags};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _};
use std::os::unix::fs::PermissionsExt as _;

pub(crate) const MAX_SECRET_BYTES: u64 = 64 * 1024;
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

pub(crate) fn snapshot(
    mut source: File,
    cancel: &crate::cancellation::Cancellation,
    maximum: u64,
) -> io::Result<File> {
    // SAFETY: constant NUL-terminated name, flags only; returned fd is uniquely owned.
    let fd = unsafe {
        libc::memfd_create(
            c"syrox-secret".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a new live descriptor.
    let mut output = unsafe { File::from_raw_fd(fd) };
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        cancel
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > MAX_SECRET_BYTES.min(maximum) {
            return Err(io::Error::other("secret byte limit exceeded"));
        }
        output.write_all(&buffer[..count])?;
        buffer.fill(0);
    }
    output.set_permissions(std::fs::Permissions::from_mode(0o400))?;
    // SAFETY: fcntl operates only on our live memfd.
    if unsafe { libc::fcntl(output.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let readonly = File::open(format!("/proc/self/fd/{}", output.as_raw_fd()))?;
    validate(readonly.as_fd())?;
    Ok(readonly)
}

pub(crate) fn validate(fd: BorrowedFd<'_>) -> io::Result<()> {
    let meta = metadata(fd)?;
    // SAFETY: getuid/fcntl have no pointer arguments and fd remains borrowed.
    let (uid, seals) = unsafe {
        (
            libc::geteuid(),
            libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS),
        )
    };
    if meta.file_type != FileType::Regular
        || meta.owner != uid
        || meta.links != 0
        || meta.mode & 0o7777 != 0o400
        || meta.size > MAX_SECRET_BYTES
        || filesystem_type(fd)? != 0x0102_1994
        || seals < 0
        || seals & SEALS != SEALS
        || status_flags(fd)? & (libc::O_ACCMODE | libc::O_PATH) != libc::O_RDONLY
    {
        return Err(io::Error::other(
            "invalid sealed secret descriptor",
        ));
    }
    Ok(())
}

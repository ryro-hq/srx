//! Bounded immutable credential snapshots independent of source-file changes.
//!
//! Callers select sources and authority. Checks run between I/O operations,
//! including retries; they cannot interrupt an individual blocking read. Admit
//! suitable sources before calling. Ownership and mode must be revalidated on
//! receipt because content seals do not freeze those inode attributes.

use super::require_readonly;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

pub const MAX_SECRET_BYTES: u64 = 64 * 1024;
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

/// Copy at most `min(maximum, MAX_SECRET_BYTES)` bytes to a new anonymous inode,
/// seal content and length, and return a read-only description at offset zero.
pub fn snapshot_secret(
    source: File,
    maximum: u64,
    check: impl FnMut() -> io::Result<()>,
) -> io::Result<File> {
    snapshot(source, maximum, check)
}

/// Seal an already bounded byte slice using the same inode/ownership contract
/// as file snapshots. The caller retains ownership of the original bytes.
pub fn snapshot_bytes(bytes: &[u8], check: impl FnMut() -> io::Result<()>) -> io::Result<File> {
    snapshot(bytes, MAX_SECRET_BYTES, check)
}

fn snapshot(
    mut source: impl io::Read,
    maximum: u64,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<File> {
    check()?;
    // SAFETY: constant terminated name and flags; success returns a fresh fd.
    let raw = unsafe {
        libc::memfd_create(
            c"syrox-secret".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this newly created memfd has no other Rust owner.
    let mut output = unsafe { File::from_raw_fd(raw) };
    copy(
        &mut source,
        &mut output,
        maximum.min(MAX_SECRET_BYTES),
        &mut check,
    )?;
    output.set_permissions(std::fs::Permissions::from_mode(0o400))?;
    check()?;
    // SAFETY: fcntl adds seals to our private live memfd with no pointer args.
    if unsafe { libc::fcntl(output.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let readonly = File::open(format!("/proc/self/fd/{}", output.as_raw_fd()))?;
    validate_secret(readonly.as_fd())?;
    check()?;
    Ok(readonly)
}

fn copy(
    source: &mut impl io::Read,
    output: &mut impl io::Write,
    maximum: u64,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        check()?;
        let count = match source.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        total = total
            .checked_add(count as u64)
            .ok_or_else(limit)?;
        if total > maximum {
            buffer.fill(0);
            return Err(limit());
        }
        let result = write(output, &buffer[..count], check);
        buffer.fill(0);
        result?;
    }
}

pub(super) fn write(
    output: &mut impl io::Write,
    mut bytes: &[u8],
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        check()?;
        match output.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn limit() -> io::Error {
    io::Error::other("secret byte limit exceeded")
}

/// Require a caller-owned unlinked tmpfs regular inode, mode 0400, bounded size,
/// all content/length/sealing seals and a genuine read-only descriptor.
pub fn validate_secret(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: credential observation only, with no pointer arguments.
    validate_secret_owned(fd, unsafe { libc::geteuid() })
}

/// Validate a sealed descriptor against an independently authorized owner, such
/// as kernel-observed Unix peer credentials. The expected UID must come from
/// receiver policy, never from a field inside the received document. This does
/// not authenticate the socket or authorize any operation named by its bytes.
pub fn validate_secret_owned(fd: BorrowedFd<'_>, expected_uid: u32) -> io::Result<()> {
    require_readonly(fd)?;
    let metadata = File::from(fd.try_clone_to_owned()?).metadata()?;
    // SAFETY: all-zero statfs is valid writable output storage.
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: fd stays live; the pointer spans writable ABI storage.
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &raw mut filesystem) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: these observe state with no pointer arguments.
    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.nlink() != 0
        || metadata.mode() & 0o7777 != 0o400
        || metadata.len() > MAX_SECRET_BYTES
        || filesystem.f_type != 0x0102_1994
        || seals < 0
        || seals & SEALS != SEALS
    {
        return Err(io::Error::other(
            "invalid sealed secret descriptor",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

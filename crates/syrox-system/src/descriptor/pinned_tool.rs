//! Content-pinned static tool snapshots for privileged operation preparation.
//!
//! The caller supplies an independently authorized pin and source descriptor.
//! Matching bytes do not grant root authority. No tool is executed here; the
//! helper must still select fixed operations, arguments, identity and isolation.
//! Executable memfd support is required, without a mutable-file fallback.

use super::require_readonly;
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};

mod elf;

pub const MAX_TOOL_BYTES: u64 = 64 * 1024 * 1024;
const MFD_EXEC: u32 = 0x0010;
const SEALS: i32 = libc::F_SEAL_WRITE
    | libc::F_SEAL_GROW
    | libc::F_SEAL_SHRINK
    | libc::F_SEAL_EXEC
    | libc::F_SEAL_SEAL;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolPin {
    pub sha256: [u8; 32],
    pub size_bytes: u64,
}

/// An anonymous, read-only, sealed tool whose exact bytes matched its pin and
/// passed the narrow static ELF contract. It retains neither a source path nor
/// authority to invoke an arbitrary program on behalf of a project.
#[derive(Debug)]
pub struct PinnedTool {
    file: File,
    pin: ToolPin,
}

impl PinnedTool {
    /// Snapshot an ordinary read-only regular file from offset zero using pread,
    /// independent of a shared source seek position. Positive sizes are bounded
    /// by 64 MiB; copying uses at most 64 KiB, verifies exact EOF and full SHA-256,
    /// then rejects dynamic, interpreter-backed or unsupported ELF executables.
    /// Checks run between I/O operations, not during a blocking kernel call.
    pub fn snapshot(
        source: File,
        pin: ToolPin,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        check()?;
        require_readonly(source.as_fd())?;
        let metadata = source.metadata()?;
        if !(64..=MAX_TOOL_BYTES).contains(&pin.size_bytes)
            || !metadata.is_file()
            || metadata.len() != pin.size_bytes
        {
            return Err(refused(
                "tool must be a regular file with its exact bounded pinned length",
            ));
        }
        // SAFETY: fixed terminated name and flags; success returns a fresh fd.
        let raw = unsafe {
            libc::memfd_create(
                c"syrox-system-tool".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | MFD_EXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this newly created memfd has no other Rust owner.
        let mut output = unsafe { File::from_raw_fd(raw) };
        let mut offset = 0_u64;
        let mut digest = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            check()?;
            let count = match source.read_at(&mut buffer, offset) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if count == 0 {
                break;
            }
            offset += count as u64;
            if offset > pin.size_bytes {
                return Err(refused("tool exceeded its pinned length"));
            }
            super::sealed::write(&mut output, &buffer[..count], &mut check)?;
            digest.update(&buffer[..count]);
        }
        if offset != pin.size_bytes || <[u8; 32]>::from(digest.finalize()) != pin.sha256 {
            return Err(refused(
                "tool content differs from its authorized pin",
            ));
        }
        elf::validate(&output, pin.size_bytes, &mut check)?;
        drop(source);
        output.set_permissions(std::fs::Permissions::from_mode(0o555))?;
        check()?;
        // SAFETY: fixed seal set on our live private memfd, with no pointer args.
        if unsafe { libc::fcntl(output.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = File::open(format!("/proc/self/fd/{}", output.as_raw_fd()))?;
        let tool = Self {
            file,
            pin,
        };
        tool.descriptor()?;
        check()?;
        Ok(tool)
    }

    pub const fn pin(&self) -> ToolPin {
        self.pin
    }

    /// Revalidate immutable content seals and mutable inode properties before
    /// handing off a borrowed description. No execution or permission elevation.
    pub fn descriptor(&self) -> io::Result<BorrowedFd<'_>> {
        let fd = self.file.as_fd();
        require_readonly(fd)?;
        let metadata = self.file.metadata()?;
        // SAFETY: statfs is writable output-only storage; zero is a valid value.
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: the borrowed fd stays open and the pointer spans ABI storage.
        if unsafe { libc::fstatfs(fd.as_raw_fd(), &raw mut filesystem) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: read-only integer queries with no pointer arguments.
        let (uid, seals) = unsafe {
            (
                libc::geteuid(),
                libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS),
            )
        };
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.nlink() != 0
            || metadata.mode() & 0o7777 != 0o555
            || metadata.len() != self.pin.size_bytes
            || filesystem.f_type != 0x0102_1994
            || seals < 0
            || seals & SEALS != SEALS
        {
            return Err(refused(
                "pinned tool descriptor is no longer valid",
            ));
        }
        Ok(fd)
    }
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests;

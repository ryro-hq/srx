//! Narrow loop-device operations for administrator-owned regular scratch images.
//!
//! These are effectful primitives, not an authorization boundary. The caller
//! must authorize descriptors, hold exclusive helper ownership and journal intent
//! before configuration or release. Other privileged device managers must be
//! excluded by that ownership policy; observation and ioctl are separate calls.
//! Device paths are never opened here. The fixed sysfs `max_part` parameter is
//! read before effects; no module is loaded and no device node is created.
//! Dropping a handle never issues a detach ioctl or reports recovery as complete.

use crate::descriptor::status_flags;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

mod abi;
use abi::{LoopConfig, LoopInfo};

const AUTOCLEAR: u32 = 4;

#[derive(Debug)]
pub struct LoopControl(File);

impl LoopControl {
    /// Admit a root-owned loop-control character device (10:237), opened RDWR.
    pub fn from_file(file: File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.file_type().is_char_device()
            || metadata.uid() != 0
            || libc::major(metadata.rdev()) != 10
            || libc::minor(metadata.rdev()) != 237
        {
            return Err(refused("not a root-owned loop controller"));
        }
        require_readwrite(file.as_fd())?;
        Ok(Self(file))
    }

    /// Ask the controller for a free number. This can create an unbound kernel
    /// loop device, so it is an effect and must not be used by read-only inspect.
    /// The number is advisory: another manager can win before atomic configure.
    pub fn select_free(&self) -> io::Result<u32> {
        abi::require_partitions_disabled()?;
        // SAFETY: fixed no-pointer ioctl on a validated live controller fd.
        let value = unsafe { libc::ioctl(self.0.as_raw_fd(), abi::GET_FREE) };
        if value < 0 {
            return Err(io::Error::last_os_error());
        }
        u32::try_from(value).map_err(|_| refused("invalid loop number"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    /// Configuration may have taken effect. Never retry or detach blindly.
    Attempted,
    Verified,
    ReleaseAttempted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    /// ENXIO also covers rundown; it does not prove that teardown finished.
    NotReportedBound,
    ExpectedBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ImageIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
}

/// Keeps both the loop description and backing file alive, including after an
/// uncertain error. There is deliberately no raw device path or arbitrary ioctl.
#[derive(Debug)]
pub struct ScratchLoop {
    device: File,
    image: File,
    number: u32,
    identity: ImageIdentity,
    phase: Phase,
}

impl ScratchLoop {
    /// Validate existing descriptors without configuring anything. The backing
    /// inode must be root-owned, singly linked, mode 0600, RDWR and exactly the
    /// requested positive 4 KiB multiple. The helper must independently establish
    /// its ownership of this new scratch file, not merely these inode properties.
    pub fn prepare(device: File, number: u32, image: File, bytes: u64) -> io::Result<Self> {
        let metadata = device.metadata()?;
        if !metadata.file_type().is_block_device()
            || metadata.uid() != 0
            || libc::major(metadata.rdev()) != 7
        {
            return Err(refused("not a root-owned loop block device"));
        }
        require_readwrite(device.as_fd())?;
        let identity = image_identity(&image, bytes)?;
        abi::require_partitions_disabled()?;
        // Only with max_part=0 is the minor also the whole-device loop number.
        // Other configurations can force partition scans even without PARTSCAN.
        if libc::minor(metadata.rdev()) != number {
            return Err(refused(
                "loop device number differs from the selected whole device",
            ));
        }
        if abi::status(device.as_fd())?.is_some() {
            return Err(refused("loop device is already bound"));
        }
        Ok(Self {
            device,
            image,
            number,
            identity,
            phase: Phase::Prepared,
        })
    }

    pub const fn phase(&self) -> Phase {
        self.phase
    }

    pub const fn image_bytes(&self) -> u64 {
        self.identity.bytes
    }

    /// Private workspace composition must reject two loop devices backed by
    /// the same image before mounting either filesystem.
    pub(crate) fn backing_identity(&self) -> io::Result<(u64, u64)> {
        self.verified_device()?;
        self.revalidate_image()?;
        Ok((self.identity.device, self.identity.inode))
    }

    /// Configure once using `LOOP_CONFIGURE` with AUTOCLEAR, offset zero, a fixed
    /// size limit and 4 KiB sectors. Caller must durably journal intent first.
    /// An ioctl error leaves Attempted; no older multi-ioctl fallback is allowed.
    pub fn configure(&mut self) -> io::Result<()> {
        if self.phase != Phase::Prepared {
            return Err(refused("loop attempt cannot be repeated"));
        }
        self.revalidate_image()?;
        abi::require_partitions_disabled()?;
        if abi::status(self.device.as_fd())?.is_some() {
            return Err(refused(
                "loop device became bound before configuration",
            ));
        }
        let config = LoopConfig::scratch(self.image.as_fd(), self.identity.bytes)?;
        self.phase = Phase::Attempted;
        // SAFETY: device is live; config spans the fixed initialized UAPI input.
        if unsafe {
            libc::ioctl(
                self.device.as_raw_fd(),
                abi::CONFIGURE,
                &raw const config,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if self.observe()? != Observation::ExpectedBinding {
            return Err(refused(
                "loop configuration disappeared before verification",
            ));
        }
        self.phase = Phase::Verified;
        Ok(())
    }

    /// Observe binding identity and exact geometry. A foreign or changed binding
    /// is an error; the caller must preserve its journal and reconcile explicitly.
    pub fn observe(&self) -> io::Result<Observation> {
        self.revalidate_image()?;
        let Some(info) = abi::status(self.device.as_fd())? else {
            return Ok(Observation::NotReportedBound);
        };
        verify_binding(&info, self.number, self.identity)?;
        let (bytes, sector) = abi::geometry(self.device.as_fd())?;
        if bytes != self.identity.bytes || sector != 4096 {
            return Err(refused(
                "loop geometry differs from the authorized image",
            ));
        }
        Ok(Observation::ExpectedBinding)
    }

    /// Borrow a device only after a successful attempt and current revalidation.
    /// Passing it to another process still requires that process's own authority.
    pub fn verified_device(&self) -> io::Result<BorrowedFd<'_>> {
        if self.phase != Phase::Verified || self.observe()? != Observation::ExpectedBinding {
            return Err(refused(
                "loop device is not a verified live binding",
            ));
        }
        Ok(self.device.as_fd())
    }

    /// Request release after payload/mount settlement and journal intent. Neither
    /// observation proves final teardown: ENXIO can mean rundown until last close,
    /// and another opener can defer release. Preserve the journal; the helper must
    /// close descriptions and independently verify completed teardown.
    pub fn release(&mut self) -> io::Result<Observation> {
        if self.phase != Phase::Verified {
            return Err(refused(
                "loop binding cannot be released in this phase",
            ));
        }
        if self.observe()? != Observation::ExpectedBinding {
            return Err(refused("loop binding changed before release"));
        }
        self.phase = Phase::ReleaseAttempted;
        // SAFETY: fixed no-pointer request, on the verified owned loop descriptor.
        if unsafe { libc::ioctl(self.device.as_raw_fd(), abi::CLEAR) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.observe()
    }

    fn revalidate_image(&self) -> io::Result<()> {
        if image_identity(&self.image, self.identity.bytes)? != self.identity {
            return Err(refused("scratch image identity changed"));
        }
        Ok(())
    }
}

fn image_identity(image: &File, bytes: u64) -> io::Result<ImageIdentity> {
    if bytes == 0 || !bytes.is_multiple_of(4096) || bytes > i64::MAX as u64 {
        return Err(refused(
            "scratch image size must be a positive supported 4 KiB multiple",
        ));
    }
    require_readwrite(image.as_fd())?;
    let metadata = image.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() != bytes
    {
        return Err(refused(
            "scratch image must be a private root-owned regular file of exact size",
        ));
    }
    Ok(ImageIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes,
    })
}

fn verify_binding(info: &LoopInfo, number: u32, identity: ImageIdentity) -> io::Result<()> {
    if info.number != number
        || info.device != abi::encode_device(identity.device)
        || info.inode != identity.inode
        || info.rdevice != 0
        || info.offset != 0
        || info.size_limit != identity.bytes
        || info.flags != AUTOCLEAR
        || info.encrypt_type != 0
        || info.encrypt_key_size != 0
        || info.file_name != [0; 64]
        || info.crypt_name != [0; 64]
        || info.encrypt_key != [0; 32]
        || info.init != [0; 2]
    {
        return Err(refused(
            "loop binding differs from the authorized scratch image",
        ));
    }
    Ok(())
}

fn require_readwrite(fd: BorrowedFd<'_>) -> io::Result<()> {
    if status_flags(fd)? & (libc::O_ACCMODE | libc::O_PATH | libc::O_APPEND | libc::O_DIRECT)
        != libc::O_RDWR
    {
        return Err(refused(
            "loop descriptors must be ordinary RDWR without append or direct I/O",
        ));
    }
    Ok(())
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests;

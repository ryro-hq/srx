use super::{AUTOCLEAR, refused};
use std::io;
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, BorrowedFd};

pub(super) const CONFIGURE: libc::Ioctl = 0x4c0a;
pub(super) const CLEAR: libc::Ioctl = 0x4c01;
pub(super) const GET_FREE: libc::Ioctl = 0x4c82;
const GET_STATUS: libc::Ioctl = 0x4c05;
const GET_BYTES: libc::Ioctl = 0x8008_1272_u32 as libc::Ioctl;
const GET_SECTOR: libc::Ioctl = libc::BLKSSZGET;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct LoopInfo {
    pub device: u64,
    pub inode: u64,
    pub rdevice: u64,
    pub offset: u64,
    pub size_limit: u64,
    pub number: u32,
    pub encrypt_type: u32,
    pub encrypt_key_size: u32,
    pub flags: u32,
    pub file_name: [u8; 64],
    pub crypt_name: [u8; 64],
    pub encrypt_key: [u8; 32],
    pub init: [u64; 2],
}

#[repr(C)]
#[derive(Debug)]
pub(super) struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo,
    reserved: [u64; 8],
}

const _: () = assert!(size_of::<LoopInfo>() == 232);
const _: () = assert!(size_of::<LoopConfig>() == 304);

pub(super) fn require_partitions_disabled() -> io::Result<()> {
    let file = crate::descriptor::open_resolved(
        None,
        std::path::Path::new("/sys/module/loop/parameters/max_part"),
        false,
        libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    )?;
    // SAFETY: statfs has valid zeroed output storage, borrowed fd stays live.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: fixed observation on a live descriptor with writable ABI storage.
    if unsafe { libc::fstatfs(file.as_raw_fd(), &raw mut stat) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if stat.f_type != 0x6265_6572 {
        return Err(refused("loop parameter is not on sysfs"));
    }
    let mut value = Vec::new();
    file.take(32).read_to_end(&mut value)?;
    if value != b"0\n" {
        return Err(refused(
            "scratch loop backend requires max_part=0",
        ));
    }
    Ok(())
}

impl LoopConfig {
    pub(super) fn scratch(fd: BorrowedFd<'_>, bytes: u64) -> io::Result<Self> {
        // SAFETY: integer/array-only UAPI structure, with no invalid bit patterns.
        let mut config: Self = unsafe { std::mem::zeroed() };
        config.fd =
            u32::try_from(fd.as_raw_fd()).map_err(|_| refused("invalid backing descriptor"))?;
        config.block_size = 4096;
        config.info.size_limit = bytes;
        config.info.flags = AUTOCLEAR;
        Ok(config)
    }
}

pub(super) fn status(fd: BorrowedFd<'_>) -> io::Result<Option<LoopInfo>> {
    // SAFETY: integer/array-only initialized writable UAPI output storage.
    let mut info: LoopInfo = unsafe { std::mem::zeroed() };
    // SAFETY: live descriptor and writable exact-sized output structure.
    if unsafe { libc::ioctl(fd.as_raw_fd(), GET_STATUS, &raw mut info) } == 0 {
        return Ok(Some(info));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENXIO) {
        Ok(None)
    } else {
        Err(error)
    }
}

pub(super) fn geometry(fd: BorrowedFd<'_>) -> io::Result<(u64, i32)> {
    let mut bytes = 0_u64;
    let mut sector = 0_i32;
    // SAFETY: both fixed ioctls receive live writable output storage of their ABI types.
    if unsafe { libc::ioctl(fd.as_raw_fd(), GET_BYTES, &raw mut bytes) } < 0
        || unsafe { libc::ioctl(fd.as_raw_fd(), GET_SECTOR, &raw mut sector) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((bytes, sector))
}

/// Kernel `huge_encode_dev` delegates to `new_encode_dev`. libc `dev_t` can use
/// additional high bits, so raw stat.dev cannot be compared with `lo_device`.
pub(super) fn encode_device(device: u64) -> u64 {
    let major = u64::from(libc::major(device));
    let minor = u64::from(libc::minor(device));
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

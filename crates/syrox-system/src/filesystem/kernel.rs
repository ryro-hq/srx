//! Fixed read-only Linux UAPI queries; no caller-supplied ioctl or quota command.
//!
//! Layouts follow `include/uapi/linux/{fs.h,dqblk_xfs.h,quota.h}`. Quota state must
//! distinguish accounting from enforcement; `Q_GETINFO` alone cannot do so.
//! See <https://man7.org/linux/man-pages/man2/quotactl.2.html> and
//! <https://github.com/torvalds/linux/blob/master/fs/quota/quota.c>.

use super::{ProjectQuotaLimits, ProjectQuotaState};
use std::{
    io,
    mem::MaybeUninit,
    os::fd::{AsRawFd as _, BorrowedFd},
};

const PROJECT_QUOTA: i32 = 2;
const PROJECT_INHERIT: u32 = 0x0000_0200;
const PROJECT_ACCOUNTING: u16 = 1 << 4;
const PROJECT_ENFORCEMENT: u16 = 1 << 5;
const GET_QUOTA_STATE_V1: i32 = (((b'X' as i32) << 8) + 8) << 8 | PROJECT_QUOTA;
const GET_PROJECT_QUOTA: i32 = (libc::Q_GETQUOTA << 8) | PROJECT_QUOTA;

#[repr(C)]
#[derive(Default)]
struct FsUuid {
    length: u8,
    bytes: [u8; 16],
}

pub(super) fn uuid(directory: BorrowedFd<'_>) -> io::Result<Vec<u8>> {
    let mut raw = FsUuid::default();
    // SAFETY: FS_IOC_GETFSUUID copies the fixed 17-byte fsuuid2 UAPI structure
    // to initialized writable output. It changes no filesystem state.
    if unsafe {
        libc::ioctl(
            directory.as_raw_fd(),
            libc::_IOR::<FsUuid>(0x15, 0),
            &raw mut raw,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    decode_uuid(&raw)
}

fn decode_uuid(raw: &FsUuid) -> io::Result<Vec<u8>> {
    let length = usize::from(raw.length);
    if !(1..=16).contains(&length) || raw.bytes[length..].iter().any(|byte| *byte != 0) {
        return Err(invalid(
            "invalid external filesystem UUID length or padding",
        ));
    }
    Ok(raw.bytes[..length].to_vec())
}

#[repr(C)]
#[derive(Default)]
struct FileAttributes {
    flags: u32,
    extent_size: u32,
    extents: u32,
    project_id: u32,
    cow_extent_size: u32,
    padding: [u8; 8],
}

#[repr(C)]
#[derive(Default)]
struct QuotaFileState {
    inode: u64,
    blocks: u64,
    extents: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Default)]
struct QuotaStateV1 {
    version: i8,
    padding1: u8,
    flags: u16,
    in_core: u32,
    user: QuotaFileState,
    group: QuotaFileState,
    project: QuotaFileState,
    block_time: i32,
    inode_time: i32,
    realtime_time: i32,
    block_warnings: u16,
    inode_warnings: u16,
    realtime_warnings: u16,
    padding3: u16,
    padding4: u32,
    padding2: [u64; 7],
}

pub(super) struct Capacity {
    pub filesystem_type: i64,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub total_inodes: u64,
    pub available_inodes: u64,
}

// Native libc counter widths differ between Linux ABIs; widening casts remain
// intentional on both GNU/musl and 32/64-bit targets.
#[expect(
    clippy::unnecessary_cast,
    reason = "statfs/statvfs field widths differ across libc ABIs; the casts are needed on targets where they are not identity"
)]
pub(super) fn capacity(directory: BorrowedFd<'_>) -> io::Result<Capacity> {
    let mut kind = MaybeUninit::<libc::statfs>::uninit();
    let mut capacity = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the borrowed fd remains open; successful calls initialize exactly
    // their respective native output structures. Neither query modifies the fs.
    if unsafe { libc::fstatfs(directory.as_raw_fd(), kind.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same descriptor/lifetime; capacity is read only on success.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), capacity.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both structures were initialized by successful calls above.
    let (kind, capacity) = unsafe { (kind.assume_init(), capacity.assume_init()) };
    let block = capacity.f_frsize as u64;
    if block == 0 {
        return Err(invalid(
            "filesystem reports a zero allocation unit",
        ));
    }
    Ok(Capacity {
        filesystem_type: kind.f_type as i64,
        total_bytes: (capacity.f_blocks as u64)
            .checked_mul(block)
            .ok_or_else(|| invalid("filesystem size overflows"))?,
        available_bytes: (capacity.f_bavail as u64)
            .checked_mul(block)
            .ok_or_else(|| invalid("available filesystem size overflows"))?,
        total_inodes: capacity.f_files as u64,
        available_inodes: capacity.f_favail as u64,
    })
}

pub(super) fn project(directory: BorrowedFd<'_>) -> io::Result<(u32, bool)> {
    let mut attributes = FileAttributes::default();
    // SAFETY: FS_IOC_FSGETXATTR copies the fixed repr(C) fsxattr layout into the
    // initialized, writable output. No set-attributes request is accepted here.
    if unsafe {
        libc::ioctl(
            directory.as_raw_fd(),
            libc::_IOR::<FileAttributes>(u32::from(b'X'), 31),
            &raw mut attributes,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((
        attributes.project_id,
        attributes.flags & PROJECT_INHERIT != 0,
    ))
}

pub(super) fn quota_state(directory: BorrowedFd<'_>) -> io::Result<ProjectQuotaState> {
    let mut state = QuotaStateV1 {
        version: 1,
        ..QuotaStateV1::default()
    };
    // SAFETY: this fixed GET operation reads the version byte then fills the
    // matching repr(C) fs_quota_statv v1 buffer. The live fd selects the mount.
    if unsafe {
        libc::syscall(
            libc::SYS_quotactl_fd,
            directory.as_raw_fd(),
            GET_QUOTA_STATE_V1,
            0,
            &raw mut state,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if state.version != 1 {
        return Err(invalid("unsupported kernel quota state version"));
    }
    Ok(ProjectQuotaState {
        accounting: state.flags & PROJECT_ACCOUNTING != 0,
        enforcement: state.flags & PROJECT_ENFORCEMENT != 0,
    })
}

pub(super) fn quota_limits(
    directory: BorrowedFd<'_>,
    project: u32,
) -> io::Result<ProjectQuotaLimits> {
    let mut limits = MaybeUninit::<libc::dqblk>::uninit();
    // SAFETY: fixed Q_GETQUOTA/PRJQUOTA uses native libc's dqblk buffer. Project
    // IDs are unsigned 32-bit values in the UAPI; no quota-setting op is exposed.
    if unsafe {
        libc::syscall(
            libc::SYS_quotactl_fd,
            directory.as_raw_fd(),
            GET_PROJECT_QUOTA,
            project,
            limits.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful Q_GETQUOTA initialized the native output structure.
    decode_limits(&unsafe { limits.assume_init() })
}

fn decode_limits(limits: &libc::dqblk) -> io::Result<ProjectQuotaLimits> {
    if limits.dqb_valid & 0x0f != 0x0f {
        return Err(invalid(
            "kernel omitted required quota limits or usage",
        ));
    }
    let bytes = limits
        .dqb_bhardlimit
        .checked_mul(1024)
        .ok_or_else(|| invalid("quota byte limit overflows"))?;
    Ok(ProjectQuotaLimits {
        hard_bytes: (bytes != 0).then_some(bytes),
        hard_inodes: (limits.dqb_ihardlimit != 0).then_some(limits.dqb_ihardlimit),
        used_bytes: limits.dqb_curspace,
        used_inodes: limits.dqb_curinodes,
    })
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

// These fixed-size assertions also protect ioctl request-number construction.
const _: () = assert!(size_of::<FileAttributes>() == 28);
const _: () = assert!(size_of::<FsUuid>() == 17);
const _: () = assert!(size_of::<QuotaFileState>() == 24);
const _: () = assert!(size_of::<QuotaStateV1>() == 160);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_decoding_rejects_invalid_lengths_and_padding_without_losing_short_ids() {
        for length in [0, 17, 255] {
            assert!(
                decode_uuid(&FsUuid {
                    length,
                    bytes: [0; 16]
                })
                .is_err()
            );
        }
        let raw = FsUuid {
            length: 4,
            bytes: [
                1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        };
        assert_eq!(decode_uuid(&raw).unwrap(), [1, 2, 3, 4]);
        let mut invalid = raw;
        invalid.bytes[15] = 9;
        assert!(decode_uuid(&invalid).is_err());
        assert_eq!(
            decode_uuid(&FsUuid {
                length: 16,
                bytes: [0xa5; 16]
            })
            .unwrap(),
            [0xa5; 16]
        );
        #[cfg(target_arch = "x86_64")]
        assert_eq!(libc::_IOR::<FsUuid>(0x15, 0), 0x8011_1500);
    }

    #[test]
    fn unlimited_incomplete_and_overflowing_kernel_limits_are_not_finite_quotas() {
        // SAFETY: dqblk consists entirely of integer fields, all valid at zero.
        let mut raw: libc::dqblk = unsafe { std::mem::zeroed() };
        assert!(decode_limits(&raw).is_err());
        raw.dqb_valid = 0x3f;
        let empty = decode_limits(&raw).unwrap();
        assert_eq!(empty.hard_bytes, None);
        assert_eq!(empty.hard_inodes, None);
        raw.dqb_bhardlimit = 1024;
        raw.dqb_ihardlimit = 200;
        raw.dqb_curspace = 4096;
        raw.dqb_curinodes = 3;
        assert_eq!(
            decode_limits(&raw).unwrap(),
            ProjectQuotaLimits {
                hard_bytes: Some(1024 * 1024),
                hard_inodes: Some(200),
                used_bytes: 4096,
                used_inodes: 3
            }
        );
        raw.dqb_bhardlimit = u64::MAX;
        assert!(decode_limits(&raw).is_err());
    }
}

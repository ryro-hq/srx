//! Detached ext4 mounts backed by an owned, verified private loop image.
//!
//! The caller must format/check its new regular image with authorized tools and
//! journal mount intent before calling. No image, path target, disk or host mount
//! is discovered here. A detached mount can be handed off by descriptor; helper
//! policy, worker isolation and journal/recovery remain separate responsibilities.
//! Filesystem geometry bounds allocated storage and inodes, not the logical
//! length of sparse files. Workers still need file-size and logical-output limits.

use crate::{budget::AdmittedBudget, descriptor, loop_device::ScratchLoop};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _};
use std::os::unix::fs::MetadataExt as _;

mod received;
pub use received::{AttachedScratch, ReceivedScratch};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScratchCapacity {
    pub filesystem_bytes: u64,
    pub inodes: u64,
}

/// Owns an unattached mount and its root description, borrowing the loop owner
/// so release cannot be requested through it while this local mount is alive.
/// Transferred/duplicated descriptors can outlive this handle: dropping it does
/// not prove final filesystem or loop teardown, nor permit deleting the image.
#[derive(Debug)]
pub struct DetachedScratch<'a> {
    _mount: File,
    root: File,
    device: &'a ScratchLoop,
    capacity: ScratchCapacity,
}

impl<'a> DetachedScratch<'a> {
    /// Create an exclusive new ext4 superblock and a detached nodev/nosuid mount.
    /// Executable scratch is needed by compilers. No existing mount is reused;
    /// unsupported modern mount syscalls fail without a legacy/global fallback.
    /// The full backing size and actual inode count must fit the admitted budget.
    pub fn mount(
        device: &'a ScratchLoop,
        budget: &AdmittedBudget,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        Self::mount_with_limits(
            device,
            budget.request().scratch_bytes,
            budget.request().files,
            check,
        )
    }

    pub(crate) fn mount_with_limits(
        device: &'a ScratchLoop,
        maximum_bytes: u64,
        maximum_inodes: u64,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        check()?;
        if device.image_bytes() > maximum_bytes {
            return Err(refused(
                "private scratch image exceeds the admitted byte budget",
            ));
        }
        let block = device.verified_device()?;
        let expected_device = File::from(block.try_clone_to_owned()?)
            .metadata()?
            .rdev();
        let source = CString::new(format!("/proc/self/fd/{}", block.as_raw_fd())).unwrap();
        // SAFETY: fixed terminated filesystem name, supported CLOEXEC flag only.
        let context = owned(unsafe { libc::syscall(libc::SYS_fsopen, c"ext4".as_ptr(), 1_u32) })?;
        check()?;
        configure(&context, 1, Some(c"source"), Some(&source))?;
        configure(&context, 1, Some(c"errors"), Some(c"remount-ro"))?;
        check()?;
        // FSCONFIG_CMD_CREATE_EXCL prevents reusing an already mounted superblock.
        configure(&context, 8, None, None)?;
        check()?;
        // SAFETY: initialized context, CLOEXEC and fixed NOSUID|NODEV attributes.
        let mount = owned(unsafe {
            libc::syscall(
                libc::SYS_fsmount,
                context.as_raw_fd(),
                1_u32,
                6_u32,
            )
        })?;
        drop(context);
        check()?;
        let root = descriptor::open_resolved(
            Some(mount.as_fd()),
            std::path::Path::new("."),
            true,
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
        )?;
        let capacity = observe(&root, expected_device)?;
        if capacity.filesystem_bytes > device.image_bytes() || capacity.inodes > maximum_inodes {
            return Err(refused(
                "formatted scratch filesystem exceeds the admitted byte/inode ceilings",
            ));
        }
        device.verified_device()?;
        check()?;
        Ok(Self {
            _mount: mount,
            root,
            device,
            capacity,
        })
    }

    pub const fn capacity(&self) -> ScratchCapacity {
        self.capacity
    }

    /// Revalidate the backing and filesystem before borrowing the root. A
    /// receiver still needs explicit authorization to use or attach the mount.
    pub fn root(&self) -> io::Result<BorrowedFd<'_>> {
        let block = self.device.verified_device()?;
        let expected = File::from(block.try_clone_to_owned()?)
            .metadata()?
            .rdev();
        if observe(&self.root, expected)? != self.capacity {
            return Err(refused("scratch filesystem geometry changed"));
        }
        Ok(self.root.as_fd())
    }

    /// Select ownership explicitly for the authorized builder identity. This
    /// affects only the root inode of this new private filesystem. Failure may
    /// follow a successful chown: preserve journal intent and reconcile it.
    pub fn assign_owner(&self, uid: u32, gid: u32) -> io::Result<()> {
        let root = self.root()?;
        // SAFETY: a live root fd belonging to our verified private filesystem.
        if unsafe { libc::fchown(root.as_raw_fd(), uid, gid) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the same live private root descriptor, with a fixed mode.
        if unsafe { libc::fchmod(root.as_raw_fd(), 0o700) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let metadata = self.root.metadata()?;
        if metadata.uid() != uid || metadata.gid() != gid || metadata.mode() & 0o7777 != 0o700 {
            return Err(refused(
                "scratch root ownership differs from the authorized builder",
            ));
        }
        Ok(())
    }
}

fn configure(
    context: &File,
    operation: u32,
    key: Option<&CStr>,
    value: Option<&CStr>,
) -> io::Result<()> {
    // SAFETY: context stays live; optional terminated strings stay borrowed for
    // this call. Fixed commands use either strings or null and never binary data.
    let result = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            operation,
            key.map_or(std::ptr::null(), CStr::as_ptr),
            value.map_or(std::ptr::null(), CStr::as_ptr),
            0_i32,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn observe(root: &File, expected_device: u64) -> io::Result<ScratchCapacity> {
    let metadata = root.metadata()?;
    // SAFETY: output-only integer structures have valid all-zero storage.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: output-only integer structures have valid all-zero storage.
    let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: root stays open and pointers span writable ABI output structures.
    if unsafe { libc::fstatfs(root.as_raw_fd(), &raw mut fs) } < 0
        || unsafe { libc::fstatvfs(root.as_raw_fd(), &raw mut space) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if !metadata.is_dir()
        || metadata.dev() != expected_device
        || fs.f_type != 0xef53
        || space.f_frsize != 4096
        || space.f_flag & (libc::ST_NOSUID | libc::ST_NODEV) != libc::ST_NOSUID | libc::ST_NODEV
        || space.f_flag & libc::ST_RDONLY != 0
    {
        return Err(refused(
            "scratch mount has unexpected filesystem, device, geometry or flags",
        ));
    }
    let bytes = space
        .f_blocks
        .checked_mul(space.f_frsize)
        .ok_or_else(|| refused("scratch capacity overflow"))?;
    if bytes == 0 || space.f_files == 0 {
        return Err(refused("scratch filesystem has zero capacity"));
    }
    Ok(ScratchCapacity {
        filesystem_bytes: bytes,
        inodes: space.f_files,
    })
}

fn owned(result: libc::c_long) -> io::Result<File> {
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(result).expect("kernel descriptor fits a nonnegative int");
    // SAFETY: successful descriptor-producing syscall transfers a fresh owner.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

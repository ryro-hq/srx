use super::{ScratchCapacity, observe, refused};
use crate::{budget::AdmittedBudget, descriptor};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::os::unix::fs::MetadataExt as _;

/// A received ext4 root whose authority the caller has independently established
/// through the root helper's authenticated connection and sealed receipt.
/// Geometry and ownership validation alone do not authenticate its producer.
#[derive(Debug)]
pub struct ReceivedScratch {
    root: File,
    identity: Identity,
    capacity: ScratchCapacity,
}

#[derive(Debug)]
struct Identity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
}

impl Identity {
    fn validate(&self, root: &File) -> io::Result<()> {
        descriptor::require_readonly(root.as_fd())?;
        let m = root.metadata()?;
        // SAFETY: fixed observations of this dedicated worker's credentials.
        let credentials = unsafe {
            (
                libc::getuid(),
                libc::geteuid(),
                libc::getgid(),
                libc::getegid(),
            )
        };
        if self.uid == 0
            || credentials != (self.uid, self.uid, self.gid, self.gid)
            || !m.is_dir()
            || m.uid() != self.uid
            || m.gid() != self.gid
            || m.mode() & 0o7777 != 0o700
            || m.dev() != self.device
            || m.ino() != self.inode
            || m.ino() != 2
        // This contract is the actual ext4 root, not a subdirectory.
        {
            return Err(refused(
                "received scratch requires the authorized non-root identity and ext4 root",
            ));
        }
        Ok(())
    }
}

impl ReceivedScratch {
    /// Validate a genuine read-only directory descriptor, non-root ownership,
    /// ext4 identity, writable nodev/nosuid flags and byte/inode ceilings.
    /// No namespace or mount operation occurs here. The receipt/peer authority
    /// must be checked separately before admitting this descriptor.
    pub fn from_authorized_root(root: File, budget: &AdmittedBudget) -> io::Result<Self> {
        Self::from_authorized_root_with_limits(
            root,
            budget.request().scratch_bytes,
            budget.request().files,
        )
    }

    pub(crate) fn from_authorized_root_with_limits(
        root: File,
        maximum_bytes: u64,
        maximum_inodes: u64,
    ) -> io::Result<Self> {
        let m = root.metadata()?;
        let identity = Identity {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
        };
        identity.validate(&root)?;
        let capacity = observe(&root, identity.device)?;
        if capacity.filesystem_bytes > maximum_bytes || capacity.inodes > maximum_inodes {
            return Err(refused(
                "received scratch exceeds admitted storage or inode budget",
            ));
        }
        Ok(Self {
            root,
            identity,
            capacity,
        })
    }

    pub const fn capacity(&self) -> ScratchCapacity {
        self.capacity
    }

    pub(crate) fn root_identity(&self) -> (u64, u64) {
        (self.identity.device, self.identity.inode)
    }

    pub(crate) fn revalidate(&self) -> io::Result<()> {
        self.identity.validate(&self.root)?;
        if observe(&self.root, self.identity.device)? != self.capacity {
            return Err(refused("received scratch geometry changed"));
        }
        Ok(())
    }

    pub(crate) fn validate_target(&self, target: &File) -> io::Result<()> {
        self.revalidate()?;
        descriptor::require_readonly(target.as_fd())?;
        let m = target.metadata()?;
        if !m.is_dir()
            || m.uid() != self.identity.uid
            || m.gid() != self.identity.gid
            || m.mode() & 0o7777 != 0o700
            || (m.dev(), m.ino()) == self.root_identity()
        {
            return Err(refused(
                "scratch target requires a distinct private worker directory",
            ));
        }
        if std::fs::read_dir(format!("/proc/self/fd/{}", target.as_raw_fd()))?
            .next()
            .transpose()?
            .is_some()
        {
            return Err(refused("scratch attachment target is not empty"));
        }
        Ok(())
    }

    /// Move the actual detached mount onto a pinned empty private directory.
    /// Both operands use empty-path fd resolution; no pathname hint, mount
    /// source discovery, recursive bind or global/legacy fallback is used.
    ///
    /// # Safety
    /// Only a dedicated single-threaded non-root worker in its own private
    /// mount/user namespaces may call this. The target must have been opened
    /// in that mount namespace. The caller must discard the namespace after
    /// any failure, which may follow successful attachment. It must close all
    /// mount/file copies and end the namespace before releasing to the helper.
    pub unsafe fn attach(
        self,
        target: File,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<AttachedScratch> {
        check()?;
        self.identity.validate(&self.root)?;
        if observe(&self.root, self.identity.device)? != self.capacity {
            return Err(refused(
                "received scratch geometry changed before attachment",
            ));
        }
        self.validate_target(&target)?;
        check()?;
        // SAFETY: the caller guarantees namespace isolation; owned descriptors
        // remain live. Fixed F_EMPTY_PATH|T_EMPTY_PATH moves only this mount.
        if unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                self.root.as_raw_fd(),
                c"".as_ptr(),
                target.as_raw_fd(),
                c"".as_ptr(),
                0x44_u32,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        check()?;
        self.identity.validate(&self.root)?;
        if observe(&self.root, self.identity.device)? != self.capacity {
            return Err(refused(
                "scratch geometry changed after attachment",
            ));
        }
        Ok(AttachedScratch {
            root: self.root,
            _target: target,
            capacity: self.capacity,
            identity: self.identity,
        })
    }
}

/// Retains the attached filesystem until the worker has finished using it.
/// Drop closes descriptors only: it does not unmount or establish namespace/
/// loop teardown. The helper independently observes completion on release.
#[derive(Debug)]
pub struct AttachedScratch {
    root: File,
    _target: File,
    capacity: ScratchCapacity,
    identity: Identity,
}

impl AttachedScratch {
    pub(crate) fn revalidate(&self) -> io::Result<()> {
        self.identity.validate(&self.root)?;
        if observe(&self.root, self.identity.device)? != self.capacity {
            return Err(refused("attached scratch geometry changed"));
        }
        Ok(())
    }
    pub fn root(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }
    pub const fn capacity(&self) -> ScratchCapacity {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{BuildBudget, BuilderLimits};

    #[test]
    fn non_filesystem_descriptors_and_unowned_directories_fail_without_mount_effects() {
        let request = BuildBudget {
            memory_bytes: 134_217_728,
            cpu_percent: 100,
            processes: 16,
            descriptors: 128,
            scratch_bytes: 67_108_864,
            files: 512,
            output_bytes: 1_048_576,
            duration_seconds: 60,
        };
        let budget = BuilderLimits::new(request)
            .unwrap()
            .admit(request)
            .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("untouched");
        std::fs::write(&path, b"original").unwrap();
        let before = std::fs::metadata(&path).unwrap();
        assert!(
            ReceivedScratch::from_authorized_root(File::open(&path).unwrap(), &budget).is_err()
        );
        assert!(
            ReceivedScratch::from_authorized_root(File::open(temporary.path()).unwrap(), &budget)
                .is_err()
        );
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.mode(),
                before.len()
            ),
            (
                after.dev(),
                after.ino(),
                after.mode(),
                after.len()
            )
        );
        assert_eq!(std::fs::read(path).unwrap(), b"original");
    }
}

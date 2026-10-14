//!
//! Linux v6.12: `cgroup_destroy_locked` rejects populated groups and online
//! children, marks the group offline, then removes its core files. Unlike PSI
//! files, `cgroup.events` is never hidden by `cgroup_file_show`; its single-record
//! callback returns no ENODEV. Creation rollback is excluded by an initial read.
//! <https://github.com/torvalds/linux/blob/v6.12/kernel/cgroup/cgroup.c>
//!
//! `kernfs_seq_start` returns ENODEV when the node cannot acquire an active ref.
//! This would not prove removal for an arbitrary kernfs file (HIDDEN also does
//! that). `seq_read_iter` resets buffered records when the read offset is zero.
//! <https://github.com/torvalds/linux/blob/v6.12/fs/kernfs/file.c>
//! <https://github.com/torvalds/linux/blob/v6.12/fs/seq_file.c>
use super::{CGROUP2_MAGIC, MAX_EVENTS_BYTES, QuiescenceError, Result, open_error, populated};
use crate::platform::linux::fd::{self as linux_fd, FileIdentity};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::fs::FileExt as _;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EventsObservation {
    Populated,
    Empty,
    Removed,
}

#[derive(Debug)]
pub(super) struct PinnedEvents {
    file: File,
    identity: FileIdentity,
}
impl PinnedEvents {
    pub(super) fn capture(directory: BorrowedFd<'_>) -> Result<Self> {
        if linux_fd::filesystem_type(directory)? != CGROUP2_MAGIC {
            return Err(QuiescenceError::Invalid(
                "kernel filesystem type differs",
            ));
        }
        let opened = linux_fd::open_beneath(directory, Path::new("cgroup.events"), false)
            .map_err(open_error)?;
        let result = Self {
            identity: opened.metadata().identity(),
            file: opened.into_file(),
        };
        if result.observe()? == EventsObservation::Removed {
            return Err(QuiescenceError::Invalid(
                "events removed before capture",
            ));
        }
        Ok(result)
    }
    pub(super) fn observe(&self) -> Result<EventsObservation> {
        self.validate()?;
        let mut bytes = [0_u8; MAX_EVENTS_BYTES + 1];
        // A positional zero-offset read forces seq_file to discard old buffered
        // records, even when a prior caller stopped before EOF. No shared cursor.
        let result = classify(self.file.read_at(&mut bytes, 0), &bytes)?;
        self.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        let metadata = linux_fd::metadata(self.file.as_fd())?;
        if linux_fd::filesystem_type(self.file.as_fd())? != CGROUP2_MAGIC
            || metadata.file_type() != linux_fd::FileType::Regular
            || metadata.identity() != self.identity
        {
            return Err(QuiescenceError::Invalid(
                "pinned core events identity differs",
            ));
        }
        Ok(())
    }
}

fn classify(result: io::Result<usize>, bytes: &[u8]) -> Result<EventsObservation> {
    match result {
        Err(error) if error.raw_os_error() == Some(libc::ENODEV) => Ok(EventsObservation::Removed),
        Err(error) => Err(error.into()),
        Ok(count) => {
            let bytes = bytes
                .get(..count)
                .ok_or(QuiescenceError::Invalid("invalid events read"))?;
            Ok(if populated(bytes)? {
                EventsObservation::Populated
            } else {
                EventsObservation::Empty
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_enodev_can_represent_core_file_retirement() {
        assert_eq!(
            classify(
                Err(io::Error::from_raw_os_error(libc::ENODEV)),
                b""
            )
            .unwrap(),
            EventsObservation::Removed
        );
        for code in [
            libc::ENOENT,
            libc::EACCES,
            libc::EIO,
            libc::EBADF,
            libc::EINTR,
        ] {
            assert!(classify(Err(io::Error::from_raw_os_error(code)), b"").is_err());
        }
        assert!(classify(Ok(0), b"").is_err());
        assert_eq!(
            classify(Ok(12), b"populated 1\n").unwrap(),
            EventsObservation::Populated
        );
        assert_eq!(
            classify(Ok(12), b"populated 0\n").unwrap(),
            EventsObservation::Empty
        );
    }
}

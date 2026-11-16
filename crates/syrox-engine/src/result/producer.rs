//! Bounded package frames from an explicitly selected, settled output directory.

use super::{ResultError, artifact, check, invalid};
use crate::{
    cancellation::Cancellation, platform::linux::fd as linux_fd, system::budget::AdmittedBudget,
};
use std::{fs::File, io, os::fd::AsFd as _, os::unix::fs::FileExt as _, path::Path};

mod tree;
use tree::{Entry, Tree};

/// A pull-based package encoder for the System worker boundary. It holds one
/// pinned directory, bounded metadata and at most one payload file, never a
/// complete file/package buffer. All reads are at most 64 KiB.
///
/// The caller must settle every possible writer before preparing this stream.
/// Revalidation detects observed changes; it does not establish process
/// settlement, filesystem exclusivity, execution or a successful build receipt.
/// Legacy worker profiles and their framing/limits are unchanged.
#[derive(Debug)]
pub struct SystemOutputStream<'a> {
    root: File,
    tree: Tree,
    cancellation: &'a Cancellation,
    prefix: io::Cursor<Vec<u8>>,
    next: usize,
    payload: Option<Payload>,
    started: bool,
    ended: bool,
    failed: bool,
}

#[derive(Debug)]
struct Payload {
    file: File,
    entry: usize,
    offset: u64,
}

impl<'a> SystemOutputStream<'a> {
    /// Pin a genuine read-only directory descriptor and admit its complete
    /// metadata against byte, expanded-alias and inode limits before emission.
    /// No Store, helper, execution or mutable host path is consulted.
    pub fn from_directory(
        root: File,
        budget: &AdmittedBudget,
        cancellation: &'a Cancellation,
    ) -> Result<Self, ResultError> {
        check(cancellation)?;
        let limits = super::staging::system_limits(budget)?;
        let tree = Tree::capture(&root, limits, cancellation)
            .map_err(|error| map_error(&error, cancellation))?;
        let mut prefix = artifact::HEADER.to_vec();
        prefix.extend_from_slice(
            &u32::try_from(tree.files.len())
                .expect("bounded files")
                .to_le_bytes(),
        );
        Ok(Self {
            root,
            tree,
            cancellation,
            prefix: io::Cursor::new(prefix),
            next: 0,
            payload: None,
            started: false,
            ended: false,
            failed: false,
        })
    }

    /// Exact package frame length, including record headers and alias strings.
    pub const fn encoded_size(&self) -> u64 {
        self.tree.size
    }

    /// Encoded files/aliases, distinct from the charged directory/inode count.
    pub fn files(&self) -> usize {
        self.tree.files.len()
    }

    pub(super) fn charge(&self) -> (u64, usize) {
        (
            self.tree.size.max(self.tree.expanded_bytes),
            self.tree.entries,
        )
    }

    pub(super) fn preflight(&self) -> io::Result<()> {
        if self.started || self.ended || self.failed {
            return Err(changed());
        }
        self.tree
            .revalidate(&self.root, self.cancellation)
    }

    fn read_inner(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.cancellation
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        if !self.started {
            self.tree
                .revalidate(&self.root, self.cancellation)?;
            self.started = true;
        }
        loop {
            let count = io::Read::read(&mut self.prefix, bytes)?;
            if count != 0 {
                return Ok(count);
            }
            if let Some(payload) = self.payload.as_mut() {
                let entry = &self.tree.files[payload.entry];
                let remaining = entry.snapshot.size - payload.offset;
                let take =
                    usize::try_from(remaining.min(bytes.len() as u64)).expect("bounded read");
                let count = payload
                    .file
                    .read_at(&mut bytes[..take], payload.offset)?;
                if count == 0 && remaining != 0 {
                    return Err(changed());
                }
                payload.offset += count as u64;
                if payload.offset == entry.snapshot.size {
                    let mut trailing = [0];
                    if payload
                        .file
                        .read_at(&mut trailing, payload.offset)?
                        != 0
                        || !entry.snapshot.matches(&payload.file.metadata()?)
                    {
                        return Err(changed());
                    }
                    self.payload = None;
                }
                if count != 0 {
                    return Ok(count);
                }
                continue;
            }
            let Some(entry) = self.tree.files.get(self.next) else {
                self.tree
                    .revalidate(&self.root, self.cancellation)?;
                self.ended = true;
                return Ok(0);
            };
            let mut prefix = Vec::with_capacity(11 + entry.path.len() + 255);
            prefix.extend_from_slice(
                &u16::try_from(entry.path.len())
                    .expect("bounded path")
                    .to_le_bytes(),
            );
            prefix.extend_from_slice(entry.path.as_bytes());
            if let Some(target) = &entry.alias {
                prefix.push(2);
                prefix.extend_from_slice(&(target.len() as u64).to_le_bytes());
                prefix.extend_from_slice(target.as_bytes());
            } else {
                let file = open_payload(&self.root, entry)?;
                prefix.push(u8::from(entry.snapshot.mode & 0o111 != 0));
                prefix.extend_from_slice(&entry.snapshot.size.to_le_bytes());
                self.payload = Some(Payload {
                    file,
                    entry: self.next,
                    offset: 0,
                });
            }
            self.next += 1;
            self.prefix = io::Cursor::new(prefix);
        }
    }
}

impl io::Read for SystemOutputStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(changed());
        }
        if self.ended {
            return Ok(0);
        }
        let take = bytes.len().min(64 * 1024);
        match self.read_inner(&mut bytes[..take]) {
            Ok(count) => Ok(count),
            // Interrupted positioned reads are safe to retry from our offset.
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted
                    && !crate::cancellation::is_cancellation_io(&error) =>
            {
                Err(error)
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
}

fn open_payload(root: &File, entry: &Entry) -> io::Result<File> {
    let file = linux_fd::open_beneath_no_mounts(root.as_fd(), Path::new(&entry.path), false)
        .map_err(|_| changed())?
        .into_file();
    if !entry.snapshot.matches(&file.metadata()?) {
        return Err(changed());
    }
    Ok(file)
}

fn changed() -> io::Error {
    io::Error::other("invalid or changed system output tree")
}

pub(super) fn map_error(error: &io::Error, cancellation: &Cancellation) -> ResultError {
    if cancellation.is_cancelled() || crate::cancellation::is_cancellation_io(error) {
        ResultError::Cancelled
    } else {
        invalid(error.to_string())
    }
}

#[cfg(test)]
mod tests;

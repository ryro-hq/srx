//! Retained source descriptors and bounded, verified staging without a source `Vec`.

use super::{BuildError, journal};
use crate::{
    cancellation::Cancellation,
    platform::linux::fd,
    store::{ContentDigest, VerifiedReader},
};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{File, Metadata, Permissions},
    io,
    os::{
        fd::AsFd as _,
        unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _},
    },
    path::Path,
};

pub(in crate::build) struct Source {
    file: File,
    metadata: Snapshot,
    digest: ContentDigest,
    size: u64,
    limit: u64,
}

impl Source {
    pub fn capture(
        reader: &VerifiedReader,
        expected: ContentDigest,
        limit: u64,
        cancellation: &Cancellation,
    ) -> Result<Self, BuildError> {
        cancellation.check()?;
        if reader.digest() != expected || reader.size() > limit {
            return Err(BuildError::InvalidRequest);
        }
        let file = File::from(reader.duplicate_readonly_descriptor()?);
        fd::require_readonly(file.as_fd())?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != reader.size() {
            return Err(BuildError::InputChanged);
        }
        let source = Self {
            file,
            metadata: snapshot(&metadata),
            digest: expected,
            size: reader.size(),
            limit,
        };
        source.copy_to(|_| Ok(()), cancellation)?;
        Ok(source)
    }

    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    pub const fn size(&self) -> u64 {
        self.size
    }

    pub fn verify(&self, cancellation: &Cancellation) -> Result<(), BuildError> {
        self.copy_to(|_| Ok(()), cancellation)
    }

    pub fn duplicate_readonly_descriptor(&self) -> io::Result<std::os::fd::OwnedFd> {
        self.file.as_fd().try_clone_to_owned()
    }

    /// Cheap preflight before allocating an operation. Copying still rehashes
    /// every byte and requires EOF; metadata is never substituted for content.
    pub fn revalidate_metadata(&self, cancellation: &Cancellation) -> Result<(), BuildError> {
        cancellation.check()?;
        fd::require_readonly(self.file.as_fd())?;
        let current = self.file.metadata()?;
        if snapshot(&current) != self.metadata {
            return Err(BuildError::InputChanged);
        }
        Ok(())
    }

    pub fn stage(
        &self,
        directory: &fd::OpenedPath,
        cancellation: &Cancellation,
    ) -> Result<(), BuildError> {
        self.revalidate_metadata(cancellation)?;
        let mut temporary =
            fd::create_atomic_beneath_with_prefix(directory.fd(), journal::TEMP_PREFIX)
                .map_err(|error| BuildError::Cache(format!("source staging: {error:?}")))?;
        self.copy_to(|bytes| temporary.write_all(bytes), cancellation)?;
        cancellation.check()?;
        let status = temporary
            .publish_noreplace(Path::new("source"))
            .map_err(|error| BuildError::Cache(format!("source publication: {error:?}")))?;
        if status != fd::PublishStatus::Published {
            return Err(BuildError::InputChanged);
        }
        let file = fd::open_existing_regular(directory.fd(), Path::new("source"))?.into_file();
        file.set_permissions(Permissions::from_mode(0o400))?;
        file.sync_all()?;
        cancellation.check()?;
        Ok(())
    }

    fn copy_to(
        &self,
        append: impl FnMut(&[u8]) -> io::Result<()>,
        cancellation: &Cancellation,
    ) -> Result<(), BuildError> {
        self.revalidate_metadata(cancellation)?;
        let mut offset = 0;
        let size = copy_source(
            |buffer| {
                let count = self.file.read_at(buffer, offset)?;
                offset += count as u64;
                Ok(count)
            },
            append,
            self.digest,
            self.limit,
            cancellation,
        )?;
        if size != self.size {
            return Err(BuildError::InputChanged);
        }
        self.revalidate_metadata(cancellation)
    }
}

#[derive(PartialEq, Eq)]
struct Snapshot {
    device: u64,
    inode: u64,
    bytes: u64,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn snapshot(metadata: &Metadata) -> Snapshot {
    Snapshot {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
        links: metadata.nlink(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

pub(super) fn copy_source(
    mut read: impl FnMut(&mut [u8]) -> io::Result<usize>,
    mut append: impl FnMut(&[u8]) -> io::Result<()>,
    expected: ContentDigest,
    limit: u64,
    cancellation: &Cancellation,
) -> Result<u64, BuildError> {
    let mut hash = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        cancellation.check()?;
        let count = match read(&mut buffer) {
            Ok(0) => break,
            Ok(count) if count <= buffer.len() => count,
            Ok(_) => return Err(BuildError::InvalidRequest),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        size = size
            .checked_add(count as u64)
            .filter(|size| *size <= limit)
            .ok_or(BuildError::InvalidRequest)?;
        hash.update(&buffer[..count]);
        append(&buffer[..count])?;
    }
    cancellation.check()?;
    if ContentDigest::from_sha256_hash(hash.finalize().into()) != expected {
        return Err(BuildError::InputChanged);
    }
    Ok(size)
}

#[cfg(test)]
mod tests;

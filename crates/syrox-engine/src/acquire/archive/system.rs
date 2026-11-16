//! System source extraction gets its own admission; legacy limits stay finite.

use super::{
    AdmittedArchiveLimits, ArchiveError, ArchiveFormat, ArchiveInventory, ArchiveLimits,
    Inspection, MAX_XZ_DECODER_MEMORY_BYTES, check_cancelled, visit_admitted_reader,
};
use crate::{
    cancellation::{CancellableReader, Cancellation},
    system::{budget::AdmittedBudget, workspace::WorkspaceLayout},
};
use std::{
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsFd as _, BorrowedFd},
        unix::fs::FileExt as _,
    },
};

/// Fixed transport extent and positioned reads are independent of shared cursors.
/// Complete source authenticity still comes from the caller's independent pin.
struct SourceReader {
    file: File,
    position: u64,
    length: u64,
}
impl SourceReader {
    fn new(file: File, maximum: u64) -> Result<Self, ArchiveError> {
        crate::system::descriptor::require_readonly(file.as_fd())?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(ArchiveError::UnsafeEntry);
        }
        if metadata.len() > maximum {
            return Err(ArchiveError::Limit);
        }
        Ok(Self {
            file,
            position: 0,
            length: metadata.len(),
        })
    }
}
impl Read for SourceReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.file.metadata()?.len() != self.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "System archive transport length changed",
            ));
        }
        let size = usize::try_from((self.length - self.position).min(buffer.len() as u64))
            .expect("read bounded by buffer");
        let count = self
            .file
            .read_at(&mut buffer[..size], self.position)?;
        if count == 0 && size != 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.position += count as u64;
        if self.file.metadata()?.len() != self.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "System archive transport length changed",
            ));
        }
        Ok(count)
    }
}

/// Metadata remains bounded even when a builder admits more writable inodes.
pub const MAX_SYSTEM_ARCHIVE_ENTRIES: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemArchiveRole {
    Scratch,
    Output,
}

/// Bounds for unpacking a source into a System workspace's scratch role. This
/// token grants no destination, namespace, source authenticity or execution
/// authority. Callers authenticate the source and pin the destination separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemArchiveLimits {
    admitted: AdmittedArchiveLimits,
    budget: AdmittedBudget,
    role: SystemArchiveRole,
}
impl SystemArchiveLimits {
    /// Source transport remains within the existing Store blob ceiling. Expanded
    /// files/data instead use the separately admitted scratch geometry/inodes.
    pub fn new(
        budget: &AdmittedBudget,
        source_limit: u64,
        format: ArchiveFormat,
    ) -> Result<Self, ArchiveError> {
        Self::for_role(
            budget,
            source_limit,
            format,
            SystemArchiveRole::Scratch,
        )
    }
    pub fn for_role(
        budget: &AdmittedBudget,
        source_limit: u64,
        format: ArchiveFormat,
        role: SystemArchiveRole,
    ) -> Result<Self, ArchiveError> {
        if source_limit == 0 || source_limit > crate::store::MAX_STORE_BLOB_BYTES {
            return Err(ArchiveError::Limit);
        }
        let layout = WorkspaceLayout::from_budget(budget).map_err(|_| ArchiveError::Limit)?;
        let geometry = match role {
            SystemArchiveRole::Scratch => layout.scratch_geometry(),
            SystemArchiveRole::Output => layout.output_geometry(),
        };
        let limits = ArchiveLimits {
            compressed_bytes: source_limit,
            expanded_bytes: geometry.image_bytes(),
            file_bytes: geometry.image_bytes(),
            entries: usize::try_from(
                geometry
                    .requested_inodes()
                    .min(MAX_SYSTEM_ARCHIVE_ENTRIES as u64),
            )
            .map_err(|_| ArchiveError::Limit)?,
            decoder_memory_bytes: if format == ArchiveFormat::XzTar {
                MAX_XZ_DECODER_MEMORY_BYTES.min(budget.request().memory_bytes)
            } else {
                0
            },
        };
        Ok(Self {
            admitted: AdmittedArchiveLimits {
                format,
                limits,
                allow_aliases: true,
            },
            budget: *budget,
            role,
        })
    }
    pub const fn budget(&self) -> &AdmittedBudget {
        &self.budget
    }
    pub const fn format(&self) -> ArchiveFormat {
        self.admitted.format
    }
    pub const fn role(&self) -> SystemArchiveRole {
        self.role
    }
    pub const fn limits(&self) -> ArchiveLimits {
        self.admitted.limits
    }
}

/// Inspect a caller-authenticated readonly source without opening a Store/path.
/// The caller retains source custody and revalidates its complete pin afterwards.
pub fn inspect_system_archive(
    source: File,
    limits: &SystemArchiveLimits,
    cancellation: &Cancellation,
) -> Result<ArchiveInventory, ArchiveError> {
    check_cancelled(cancellation)?;
    let source = SourceReader::new(source, limits.limits().compressed_bytes)?;
    visit_admitted_reader(
        CancellableReader {
            source,
            cancellation,
        },
        limits.admitted,
        &mut Inspection,
    )
    .map_err(|error| super::cancelled_archive_error(error, cancellation))
}

/// Extract only beneath a separately pinned directory. Unsupported members,
/// aliases, collisions and limits use the same streaming parser/tree writer as
/// ordinary archives. Failure can leave partial new files; it publishes nothing
/// and never cleans up/retries. Sparse logical data still charges expanded bytes.
pub fn extract_system_archive(
    source: File,
    limits: &SystemArchiveLimits,
    destination: BorrowedFd<'_>,
    cancellation: &Cancellation,
) -> Result<ArchiveInventory, ArchiveError> {
    check_cancelled(cancellation)?;
    let source = SourceReader::new(source, limits.limits().compressed_bytes)?;
    super::extract::extract_stream(source, limits.admitted, destination, cancellation)
}

#[cfg(test)]
mod tests;

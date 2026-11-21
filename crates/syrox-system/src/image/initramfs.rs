//! Uncompressed Linux initramfs in the upstream `newc` format.
//! <https://docs.kernel.org/driver-api/early-userspace/buffer-format.html>

use super::{Entry, FileSource, SystemTree};
use crate::budget::AdmittedBudget;
use sha2::{Digest as _, Sha256};
use std::io::{self, Read, Write};

/// The caller resolves only authenticated component artifacts. Implementations
/// must open the declared relative file within that component, without following
/// host paths or falling back to the environment. The writer independently checks
/// its complete byte length and SHA-256. It never opens source paths itself.
pub trait ComponentReader {
    fn open_file(&mut self, source: &FileSource) -> io::Result<Box<dyn Read + '_>>;
}

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("initramfs operation cancelled")]
    Cancelled,
    #[error("initramfs exceeds the admitted {0} budget")]
    Budget(&'static str),
    #[error("image entry {0:?} cannot be represented in newc")]
    Format(String),
    #[error("component file {0:?} does not match its declared length and SHA-256")]
    Content(String),
    #[error("initramfs I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrittenArchive {
    pub bytes: u64,
    pub sha256: [u8; 32],
    pub tree_sha256: [u8; 32],
}

impl SystemTree {
    /// Emit a reproducible, uncompressed initramfs. Preflight all format/size
    /// limits before opening a source or writing a byte. The complete archive,
    /// including padding and metadata, consumes the output budget. File contents
    /// use at most 64 KiB of buffering regardless of the total image size.
    ///
    /// Errors may leave a prefix in the destination. Publish a staged artifact
    /// only after success. This operation grants no installation authority.
    /// Cancellation is cooperative; readers and writers must bound blocked I/O.
    pub fn write_initramfs(
        &self,
        sources: &mut impl ComponentReader,
        output: &mut impl Write,
        budget: &AdmittedBudget,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<WrittenArchive, ArchiveError> {
        check(&mut cancelled)?;
        if self.entries.len() as u64 > budget.request().files {
            return Err(ArchiveError::Budget("files"));
        }
        let mut expected = record_bytes("TRAILER!!!", 0)?;
        for (path, entry) in &self.entries {
            check(&mut cancelled)?;
            expected = expected
                .checked_add(record_bytes(
                    &archive_name(path),
                    data_size(&entry.entry),
                )?)
                .ok_or(ArchiveError::Budget("output bytes"))?;
        }
        expected = align(expected, 512).ok_or(ArchiveError::Budget("output bytes"))?;
        if expected > budget.request().output_bytes {
            return Err(ArchiveError::Budget("output bytes"));
        }
        let mut sink = Sink {
            output,
            hasher: Sha256::new(),
            bytes: 0,
        };
        let mut buffer = vec![0_u8; 64 * 1024];
        for (index, (path, entry)) in self.entries.iter().enumerate() {
            check(&mut cancelled)?;
            let (mode, uid, gid, links) = match &entry.entry {
                Entry::Directory {
                    metadata,
                } => (
                    0o040_000 | metadata.mode,
                    metadata.uid,
                    metadata.gid,
                    2,
                ),
                Entry::File {
                    metadata,
                    ..
                } => (
                    0o100_000 | metadata.mode,
                    metadata.uid,
                    metadata.gid,
                    1,
                ),
                Entry::Symlink {
                    uid,
                    gid,
                    ..
                } => (0o120_777, *uid, *gid, 1),
            };
            let size = data_size(&entry.entry);
            let name = archive_name(path);
            sink.header(
                &name,
                [
                    u32::try_from(index + 1).expect("bounded entry count"),
                    mode,
                    uid,
                    gid,
                    links,
                    0,
                    u32::try_from(size).expect("preflight bounded payload"),
                    0,
                    0,
                    0,
                    0,
                    u32::try_from(name.len() + 1).expect("bounded name"),
                    0,
                ],
            )?;
            match &entry.entry {
                Entry::File {
                    source,
                    ..
                } => {
                    check(&mut cancelled)?;
                    let mut input = sources.open_file(source)?;
                    let mut remaining = size;
                    let mut hasher = Sha256::new();
                    while remaining != 0 {
                        check(&mut cancelled)?;
                        let take = usize::try_from(remaining.min(buffer.len() as u64))
                            .expect("bounded read");
                        let read = read(&mut input, &mut buffer[..take], &mut cancelled)?;
                        if read == 0 {
                            return Err(ArchiveError::Content(path.clone()));
                        }
                        hasher.update(&buffer[..read]);
                        sink.append(&buffer[..read])?;
                        remaining -= read as u64;
                    }
                    if read(&mut input, &mut buffer[..1], &mut cancelled)? != 0
                        || crate::hex(&hasher.finalize()) != source.content_sha256
                    {
                        return Err(ArchiveError::Content(path.clone()));
                    }
                }
                Entry::Symlink {
                    target,
                    ..
                } => sink.append(target.as_bytes())?,
                Entry::Directory {
                    ..
                } => {}
            }
            sink.pad(4)?;
        }
        check(&mut cancelled)?;
        sink.header(
            "TRAILER!!!",
            [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0],
        )?;
        sink.pad(512)?;
        check(&mut cancelled)?;
        debug_assert_eq!(sink.bytes, expected);
        Ok(WrittenArchive {
            bytes: sink.bytes,
            sha256: sink.hasher.finalize().into(),
            tree_sha256: self.fingerprint(),
        })
    }
}

fn archive_name(path: &str) -> String {
    match path {
        "/" => ".".into(),
        "/TRAILER!!!" => "./TRAILER!!!".into(),
        _ => path[1..].into(),
    }
}

fn data_size(entry: &Entry) -> u64 {
    match entry {
        Entry::Directory {
            ..
        } => 0,
        Entry::File {
            source,
            ..
        } => source.size_bytes,
        Entry::Symlink {
            target,
            ..
        } => target.len() as u64,
    }
}

fn record_bytes(name: &str, size: u64) -> Result<u64, ArchiveError> {
    if name.len() + 1 > super::MAX_PATH_BYTES || size > u64::from(u32::MAX) {
        return Err(ArchiveError::Format(name.into()));
    }
    let header = align(110 + name.len() as u64 + 1, 4).expect("bounded header");
    Ok(header + align(size, 4).expect("u32 payload"))
}

fn align(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
}

fn check(cancelled: &mut impl FnMut() -> bool) -> Result<(), ArchiveError> {
    if cancelled() {
        Err(ArchiveError::Cancelled)
    } else {
        Ok(())
    }
}

fn read(
    input: &mut impl Read,
    bytes: &mut [u8],
    cancelled: &mut impl FnMut() -> bool,
) -> Result<usize, ArchiveError> {
    loop {
        check(cancelled)?;
        match input.read(bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return Ok(result?),
        }
    }
}

struct Sink<'a, W> {
    output: &'a mut W,
    hasher: Sha256,
    bytes: u64,
}

impl<W: Write> Sink<'_, W> {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.output.write_all(bytes)?;
        self.hasher.update(bytes);
        self.bytes += bytes.len() as u64;
        Ok(())
    }
    fn pad(&mut self, alignment: u64) -> io::Result<()> {
        let padding = (alignment - self.bytes % alignment) % alignment;
        self.append(&[0_u8; 512][..usize::try_from(padding).expect("bounded padding")])
    }
    fn header(&mut self, name: &str, fields: [u32; 13]) -> io::Result<()> {
        use std::fmt::Write as _;
        let mut header = String::from("070701");
        for field in fields {
            write!(&mut header, "{field:08x}").expect("string formatting");
        }
        debug_assert_eq!(header.len(), 110);
        self.append(header.as_bytes())?;
        self.append(name.as_bytes())?;
        self.append(&[0])?;
        self.pad(4)
    }
}

#[cfg(test)]
mod tests;

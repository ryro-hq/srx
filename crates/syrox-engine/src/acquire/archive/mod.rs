//! Inspeção limitada do tar comprimido que chegou como fonte.
//!
//! Os paths, tipos de entrada e tamanho expandido são conferidos antes de usar
//! o archive. A inspeção não extrai arquivos nem libera a execução de seu conteúdo.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufReader;
use std::io::{self, Read};

use flate2::read::MultiGzDecoder;
use thiserror::Error;

use crate::store::{ContentDigest, Store, StoreError};

pub(crate) mod extract;

pub const MAX_ARCHIVE_ENTRIES: usize = 16_384;
pub const MAX_ARCHIVE_EXPANDED_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_ARCHIVE_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_ARCHIVE_PATH_BYTES: usize = 255;
pub const MAX_ARCHIVE_DEPTH: usize = 64;
pub const MAX_LARGE_ARCHIVE_ENTRIES: usize = 65_536;
pub const DEFAULT_LARGE_ARCHIVE_EXPANDED_BYTES: u64 = 384 * 1024 * 1024;
pub const DEFAULT_LARGE_ARCHIVE_COMPRESSED_BYTES: u64 = 32 * 1024 * 1024;
/// Limit for the decoder's internal dictionary and related buffers, separate
/// from the maximum number of bytes produced by decompression.
pub const MAX_XZ_DECODER_MEMORY_BYTES: u64 = 128 * 1024 * 1024;

/// Archive admission is independent of the package name. The caller chooses a
/// format and an explicit resource envelope; neither is inferred from the URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveFormat {
    GzipTar,
    XzTar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveLimits {
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    pub file_bytes: u64,
    pub entries: usize,
    pub decoder_memory_bytes: u64,
}

impl ArchiveLimits {
    pub const fn small_gzip() -> Self {
        Self {
            compressed_bytes: 16 * 1024 * 1024,
            expanded_bytes: MAX_ARCHIVE_EXPANDED_BYTES,
            file_bytes: MAX_ARCHIVE_FILE_BYTES,
            entries: MAX_ARCHIVE_ENTRIES,
            decoder_memory_bytes: 0,
        }
    }

    pub const fn large_xz() -> Self {
        Self {
            compressed_bytes: DEFAULT_LARGE_ARCHIVE_COMPRESSED_BYTES,
            expanded_bytes: DEFAULT_LARGE_ARCHIVE_EXPANDED_BYTES,
            file_bytes: MAX_ARCHIVE_FILE_BYTES,
            entries: MAX_LARGE_ARCHIVE_ENTRIES,
            decoder_memory_bytes: MAX_XZ_DECODER_MEMORY_BYTES,
        }
    }

    fn validate(self, format: ArchiveFormat) -> Result<Self, ArchiveError> {
        if self.compressed_bytes == 0
            || self.compressed_bytes > crate::store::MAX_STORE_BLOB_BYTES
            || self.expanded_bytes == 0
            || self.expanded_bytes > crate::store::MAX_STORE_BLOB_BYTES
            || self.file_bytes == 0
            || self.file_bytes > self.expanded_bytes
            || self.entries == 0
            || self.entries > MAX_LARGE_ARCHIVE_ENTRIES
            || match format {
                ArchiveFormat::GzipTar => self.decoder_memory_bytes != 0,
                ArchiveFormat::XzTar => {
                    self.decoder_memory_bytes == 0
                        || self.decoder_memory_bytes > MAX_XZ_DECODER_MEMORY_BYTES
                }
            }
        {
            return Err(ArchiveError::Limit);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveInventory {
    entries: usize,
    files: usize,
    expanded_bytes: u64,
}

impl ArchiveInventory {
    pub const fn entries(&self) -> usize {
        self.entries
    }
    pub const fn files(&self) -> usize {
        self.files
    }
    pub const fn expanded_bytes(&self) -> u64 {
        self.expanded_bytes
    }
}

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("the verified source object is absent")]
    MissingSource,
    #[error("source archive exceeds a configured bound")]
    Limit,
    #[error("source archive is malformed or uses unsupported tar metadata")]
    InvalidTar,
    #[error("source archive contains an unsafe path, entry type or permission")]
    UnsafeEntry,
    #[error("source archive decompression or reading failed: {0}")]
    Io(#[from] io::Error),
    #[error("source archive inspection cancelled")]
    Cancelled,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Verifies the Store object first, then checks every compressed and expanded
/// byte without extracting any entry on the host. Only regular files and
/// directories in the old tar and ustar subsets are admitted.
pub fn inspect_source_archive(
    store: &Store,
    digest: ContentDigest,
    maximum_compressed_bytes: u64,
) -> Result<ArchiveInventory, ArchiveError> {
    let mut limits = ArchiveLimits::small_gzip();
    limits.compressed_bytes = maximum_compressed_bytes;
    inspect_archive(store, digest, ArchiveFormat::GzipTar, limits)
}

/// Inspect a verified Store source using caller-selected format and bounded
/// resources. Decoder memory, tar payload bytes and transport size are distinct.
pub fn inspect_archive(
    store: &Store,
    digest: ContentDigest,
    format: ArchiveFormat,
    limits: ArchiveLimits,
) -> Result<ArchiveInventory, ArchiveError> {
    inspect_archive_with_cancellation(
        store,
        digest,
        format,
        limits,
        &crate::cancellation::Cancellation::default(),
    )
}

/// Inspect an archive, checking cancellation during Store verification and
/// throughout decompression rather than only between members.
pub fn inspect_archive_with_cancellation(
    store: &Store,
    digest: ContentDigest,
    format: ArchiveFormat,
    limits: ArchiveLimits,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<ArchiveInventory, ArchiveError> {
    #[cfg(target_os = "linux")]
    {
        check_cancelled(cancellation)?;
        let limits = limits.validate(format)?;
        let lease = store.operation()?;
        let source = lease
            .open_verified_checked(digest, limits.compressed_bytes, || {
                if cancellation.is_cancelled() {
                    Err(crate::cancellation::cancellation_io())
                } else {
                    Ok(())
                }
            })
            .map_err(|error| {
                if cancellation.is_cancelled()
                    && matches!(error, StoreError::Io(ref source) if crate::cancellation::is_cancellation_io(source))
                {
                    ArchiveError::Cancelled
                } else {
                    ArchiveError::Store(error)
                }
            })?
            .ok_or(ArchiveError::MissingSource)?;
        let reader = crate::cancellation::CancellableReader {
            source,
            cancellation,
        };
        inspect_reader(reader, format, limits)
            .map_err(|error| cancelled_archive_error(error, cancellation))
    }
}

fn check_cancelled(cancellation: &crate::cancellation::Cancellation) -> Result<(), ArchiveError> {
    if cancellation.is_cancelled() {
        Err(ArchiveError::Cancelled)
    } else {
        Ok(())
    }
}

fn cancelled_archive_error(
    error: ArchiveError,
    cancellation: &crate::cancellation::Cancellation,
) -> ArchiveError {
    if cancellation.is_cancelled()
        && matches!(error, ArchiveError::Io(ref source) if crate::cancellation::is_cancellation_io(source))
    {
        ArchiveError::Cancelled
    } else {
        error
    }
}

pub(crate) fn inspect_gzip_tar(source: impl Read) -> Result<ArchiveInventory, ArchiveError> {
    inspect_reader(
        source,
        ArchiveFormat::GzipTar,
        ArchiveLimits::small_gzip(),
    )
}

pub(crate) fn inspect_gzip_tar_with_cancellation(
    source: impl Read,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<ArchiveInventory, ArchiveError> {
    check_cancelled(cancellation)?;
    inspect_gzip_tar(crate::cancellation::CancellableReader {
        source,
        cancellation,
    })
    .map_err(|error| cancelled_archive_error(error, cancellation))
}

/// Separate, resource-bounded admission for xz sources. Only
/// same-directory aliases to regular files are permitted; general source
/// symlinks and cross-directory traversal remain forbidden.
#[cfg(test)]
pub(crate) fn inspect_large_xz_tar(source: impl Read) -> Result<ArchiveInventory, ArchiveError> {
    inspect_reader(
        source,
        ArchiveFormat::XzTar,
        ArchiveLimits::large_xz(),
    )
}

trait ArchiveSink {
    fn entry(
        &mut self,
        path: &str,
        kind: &MemberKind,
        mode: u32,
        size: u64,
        payload: &mut dyn Read,
    ) -> Result<(), ArchiveError>;
    fn finish(&mut self) -> Result<(), ArchiveError> {
        Ok(())
    }
}
struct Inspection;
impl ArchiveSink for Inspection {
    fn entry(
        &mut self,
        _: &str,
        _: &MemberKind,
        _: u32,
        _: u64,
        _: &mut dyn Read,
    ) -> Result<(), ArchiveError> {
        Ok(())
    }
}
fn inspect_reader(
    source: impl Read,
    format: ArchiveFormat,
    limits: ArchiveLimits,
) -> Result<ArchiveInventory, ArchiveError> {
    visit_reader(source, format, limits, &mut Inspection)
}
fn visit_reader(
    source: impl Read,
    format: ArchiveFormat,
    limits: ArchiveLimits,
    sink: &mut impl ArchiveSink,
) -> Result<ArchiveInventory, ArchiveError> {
    let limits = limits.validate(format)?;
    match format {
        ArchiveFormat::GzipTar => inspect_tar(MultiGzDecoder::new(source), limits, false, sink),
        ArchiveFormat::XzTar => {
            let stream = xz2::stream::Stream::new_stream_decoder(
                limits.decoder_memory_bytes,
                xz2::stream::CONCATENATED,
            )
            .map_err(|_| ArchiveError::Limit)?;
            inspect_tar(
                xz2::bufread::XzDecoder::new_stream(BufReader::new(source), stream),
                limits,
                true,
                sink,
            )
        }
    }
}

fn inspect_tar(
    source: impl Read,
    limits: ArchiveLimits,
    allow_aliases: bool,
    sink: &mut impl ArchiveSink,
) -> Result<ArchiveInventory, ArchiveError> {
    let mut reader =
        source.take(limits.expanded_bytes + (limits.entries as u64) * 1024 + 16 * 1024 + 1);
    let mut seen = BTreeSet::<String>::new();
    let mut regular_files = BTreeSet::<String>::new();
    let mut aliases = BTreeMap::<String, String>::new();
    let mut inventory = ArchiveInventory {
        entries: 0,
        files: 0,
        expanded_bytes: 0,
    };
    let mut header = [0_u8; 512];
    let mut zeros = 0_u8;
    loop {
        reader
            .read_exact(&mut header)
            .map_err(map_archive_io)?;
        if header.iter().all(|byte| *byte == 0) {
            zeros += 1;
            if zeros == 2 {
                break;
            }
            continue;
        }
        if zeros != 0 {
            return Err(ArchiveError::InvalidTar);
        }
        inventory.entries += 1;
        if inventory.entries > limits.entries {
            return Err(ArchiveError::Limit);
        }
        let (path, size, kind) = parse_member(&header, allow_aliases)?;
        if kind == MemberKind::GlobalComment {
            validate_global_comment(&mut reader, size, inventory.entries)?;
            inventory.expanded_bytes += size;
            if inventory.expanded_bytes > limits.expanded_bytes {
                return Err(ArchiveError::Limit);
            }
            continue;
        }
        register_member(
            (path.clone(), size, kind.clone()),
            &mut seen,
            &mut regular_files,
            &mut aliases,
            &mut inventory,
            limits.file_bytes,
        )?;
        let padded = size.checked_add(511).ok_or(ArchiveError::Limit)? / 512 * 512;
        inventory.expanded_bytes = inventory
            .expanded_bytes
            .checked_add(size)
            .ok_or(ArchiveError::Limit)?;
        if inventory.expanded_bytes > limits.expanded_bytes {
            return Err(ArchiveError::Limit);
        }
        let mode =
            u32::try_from(octal(&header[100..108])? & 0o777).expect("permission mask fits u32");
        let mut payload = reader.by_ref().take(size);
        sink.entry(&path, &kind, mode, size, &mut payload)?;
        io::copy(&mut payload, &mut io::sink()).map_err(map_archive_io)?;
        if payload.limit() != 0 {
            return Err(ArchiveError::InvalidTar);
        }
        let padding = padded - size;
        io::copy(
            &mut reader.by_ref().take(padding),
            &mut io::sink(),
        )
        .and_then(|copied| {
            if copied == padding {
                Ok(copied)
            } else {
                Err(io::Error::from(io::ErrorKind::UnexpectedEof))
            }
        })
        .map_err(map_archive_io)?;
    }
    // The two zero records must be followed only by bounded zero padding.
    let mut tail = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut tail).map_err(map_archive_io)?;
        if read == 0 {
            break;
        }
        if tail[..read].iter().any(|byte| *byte != 0) {
            return Err(ArchiveError::InvalidTar);
        }
    }
    if reader.limit() == 0 {
        return Err(ArchiveError::Limit);
    }
    for (path, target) in aliases {
        let full = match path.rsplit_once('/') {
            Some((parent, _)) => format!("{parent}/{target}"),
            None => target,
        };
        if !regular_files.contains(&full) {
            return Err(ArchiveError::UnsafeEntry);
        }
    }
    sink.finish()?;
    Ok(inventory)
}

fn register_member(
    (path, size, kind): (String, u64, MemberKind),
    seen: &mut BTreeSet<String>,
    regular_files: &mut BTreeSet<String>,
    aliases: &mut BTreeMap<String, String>,
    inventory: &mut ArchiveInventory,
    maximum_file_bytes: u64,
) -> Result<(), ArchiveError> {
    if !seen.insert(path.clone()) {
        return Err(ArchiveError::UnsafeEntry);
    }
    let mut ancestor = path.as_str();
    while let Some((parent, _)) = ancestor.rsplit_once('/') {
        if regular_files.contains(parent) || aliases.contains_key(parent) {
            return Err(ArchiveError::UnsafeEntry);
        }
        ancestor = parent;
    }
    if kind != MemberKind::Directory {
        let prefix = format!("{path}/");
        if seen
            .range(prefix.clone()..)
            .next()
            .is_some_and(|entry| entry.starts_with(&prefix))
        {
            return Err(ArchiveError::UnsafeEntry);
        }
        if size > maximum_file_bytes {
            return Err(ArchiveError::Limit);
        }
        match kind {
            MemberKind::File => {
                inventory.files += 1;
                regular_files.insert(path);
            }
            MemberKind::Alias(target) => {
                aliases.insert(path, target);
            }
            MemberKind::Directory | MemberKind::GlobalComment => unreachable!(),
        }
    }
    Ok(())
}

pub(crate) fn validate_global_comment(
    reader: &mut impl Read,
    size: u64,
    entry: usize,
) -> Result<[u8; 40], ArchiveError> {
    if entry != 1 || size > 128 {
        return Err(ArchiveError::UnsafeEntry);
    }
    let length = usize::try_from(size).map_err(|_| ArchiveError::Limit)?;
    let mut padded = [0_u8; 512];
    reader
        .read_exact(&mut padded)
        .map_err(map_archive_io)?;
    let body = &padded[..length];
    let Some(space) = body.iter().position(|byte| *byte == b' ') else {
        return Err(ArchiveError::InvalidTar);
    };
    let (count, tail) = body.split_at(space);
    let count = std::str::from_utf8(count).map_err(|_| ArchiveError::InvalidTar)?;
    let declared: usize = count
        .parse()
        .map_err(|_| ArchiveError::InvalidTar)?;
    let value = &tail[1..];
    if declared != length
        || !value.starts_with(b"comment=")
        || value.len() != 8 + 40 + 1
        || value.last() != Some(&b'\n')
        || !value[8..48].iter().all(u8::is_ascii_hexdigit)
        || padded[length..].iter().any(|byte| *byte != 0)
    {
        return Err(ArchiveError::InvalidTar);
    }
    Ok(value[8..48]
        .try_into()
        .expect("validated comment length"))
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum MemberKind {
    Directory,
    File,
    Alias(String),
    GlobalComment,
}

pub(crate) fn parse_member(
    header: &[u8; 512],
    allow_aliases: bool,
) -> Result<(String, u64, MemberKind), ArchiveError> {
    let checksum = octal(&header[148..156])?;
    let actual: u64 = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            u64::from(if (148..156).contains(&index) {
                b' '
            } else {
                *byte
            })
        })
        .sum();
    if checksum != actual {
        return Err(ArchiveError::InvalidTar);
    }
    let size = octal(&header[124..136])?;
    let mode = octal(&header[100..108])?;
    if mode & 0o7000 != 0 {
        return Err(ArchiveError::UnsafeEntry);
    }
    let name = text_field(&header[..100])?;
    let prefix = if &header[257..263] == b"ustar\0" || &header[257..263] == b"ustar " {
        text_field(&header[345..500])?
    } else if header[257..329].iter().all(|byte| *byte == 0)
        && header[345..500].iter().all(|byte| *byte == 0)
        && [329..337, 337..345].iter().all(|range| {
            header[range.clone()]
                .iter()
                .all(|byte| *byte == 0)
                || octal(&header[range.clone()]).is_ok_and(|value| value == 0)
        })
    {
        ""
    } else {
        return Err(ArchiveError::InvalidTar);
    };
    let full = if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    };
    let path = full.trim_end_matches('/');
    if path.is_empty()
        || path.len() > MAX_ARCHIVE_PATH_BYTES
        || full.ends_with("//")
        || !path.is_ascii()
        || path.starts_with('/')
        || path.contains('\\')
        || path.split('/').count() > MAX_ARCHIVE_DEPTH
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ArchiveError::UnsafeEntry);
    }
    let kind = match header[156] {
        b'g' if allow_aliases && path == "pax_global_header" && size <= 128 => {
            MemberKind::GlobalComment
        }
        b'5' if size == 0 => MemberKind::Directory,
        0 | b'0' if !full.ends_with('/') => MemberKind::File,
        b'2' if allow_aliases && size == 0 && !full.ends_with('/') => {
            let target = text_field(&header[157..257])?;
            if target.is_empty()
                || target.len() > 100
                || target.contains('/')
                || matches!(target, "." | "..")
                || target.contains('\\')
                || !target.is_ascii()
                || target.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(ArchiveError::UnsafeEntry);
            }
            MemberKind::Alias(target.to_owned())
        }
        _ => return Err(ArchiveError::UnsafeEntry),
    };
    Ok((path.to_owned(), size, kind))
}

fn map_archive_io(error: io::Error) -> ArchiveError {
    if error
        .get_ref()
        .and_then(|source| source.downcast_ref::<xz2::stream::Error>())
        == Some(&xz2::stream::Error::MemLimit)
    {
        ArchiveError::Limit
    } else if error.kind() == io::ErrorKind::UnexpectedEof {
        ArchiveError::InvalidTar
    } else {
        ArchiveError::Io(error)
    }
}

fn text_field(value: &[u8]) -> Result<&str, ArchiveError> {
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    if value[end..].iter().any(|byte| *byte != 0) {
        return Err(ArchiveError::InvalidTar);
    }
    std::str::from_utf8(&value[..end]).map_err(|_| ArchiveError::UnsafeEntry)
}

fn octal(value: &[u8]) -> Result<u64, ArchiveError> {
    let text = std::str::from_utf8(value).map_err(|_| ArchiveError::InvalidTar)?;
    let text = text.trim_matches(|character| character == '\0' || character == ' ');
    if text.is_empty()
        || !text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'7'))
    {
        return Err(ArchiveError::InvalidTar);
    }
    u64::from_str_radix(text, 8).map_err(|_| ArchiveError::InvalidTar)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use flate2::{Compression, write::GzEncoder};
    use xz2::write::XzEncoder;

    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn cancelled_archive_does_not_start_store_inspection() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(temporary.path()).unwrap();
        let cancellation = crate::cancellation::Cancellation::default();
        cancellation.cancel();
        assert!(matches!(
            inspect_archive_with_cancellation(
                &store,
                ContentDigest::sha256(b"absent"),
                ArchiveFormat::XzTar,
                ArchiveLimits::large_xz(),
                &cancellation,
            ),
            Err(ArchiveError::Cancelled)
        ));
    }

    pub(super) fn member(path: &str, data: &[u8], kind: u8, mode: u64) -> Vec<u8> {
        let mut block = [0_u8; 512];
        block[..path.len()].copy_from_slice(path.as_bytes());
        block[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
        block[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        block[156] = kind;
        block[148..156].fill(b' ');
        let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
        block[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        let mut result = block.to_vec();
        result.extend_from_slice(data);
        result.resize(result.len().div_ceil(512) * 512, 0);
        result
    }

    pub(super) fn gzip(tar: &[u8]) -> Vec<u8> {
        let mut writer = GzEncoder::new(Vec::new(), Compression::fast());
        writer.write_all(tar).unwrap();
        writer.finish().unwrap()
    }

    pub(super) fn archive(members: &[Vec<u8>]) -> Vec<u8> {
        let mut tar = Vec::new();
        for member in members {
            tar.extend_from_slice(member);
        }
        tar.extend_from_slice(&[0_u8; 1024]);
        gzip(&tar)
    }

    #[test]
    fn cancellation_during_gzip_decode_stops_retrying_reads() {
        struct CancelAfterRead<'a> {
            bytes: &'a [u8],
            cancellation: crate::cancellation::Cancellation,
        }
        impl Read for CancelAfterRead<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let length = buffer.len().min(1);
                let read = self.bytes.read(&mut buffer[..length])?;
                self.cancellation.cancel();
                Ok(read)
            }
        }
        let cancellation = crate::cancellation::Cancellation::default();
        let bytes = archive(&[member("file", b"data", b'0', 0o644)]);
        let reader = CancelAfterRead {
            bytes: &bytes,
            cancellation: cancellation.clone(),
        };
        assert!(matches!(
            inspect_gzip_tar_with_cancellation(reader, &cancellation),
            Err(ArchiveError::Cancelled)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cancellation_during_xz_decode_stops_before_next_read() {
        struct CancelAfterRead<'a> {
            bytes: &'a [u8],
            cancellation: crate::cancellation::Cancellation,
        }
        impl Read for CancelAfterRead<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let read = self.bytes.read(&mut buffer[..1])?;
                self.cancellation.cancel();
                Ok(read)
            }
        }
        let cancellation = crate::cancellation::Cancellation::default();
        let bytes = xz_archive(&[member("file", b"data", b'0', 0o644)]);
        let reader = CancelAfterRead {
            bytes: &bytes,
            cancellation: cancellation.clone(),
        };
        let error = inspect_reader(
            crate::cancellation::CancellableReader {
                source: reader,
                cancellation: &cancellation,
            },
            ArchiveFormat::XzTar,
            ArchiveLimits::large_xz(),
        )
        .unwrap_err();
        assert!(matches!(
            cancelled_archive_error(error, &cancellation),
            ArchiveError::Cancelled
        ));
    }

    pub(super) fn xz_archive(members: &[Vec<u8>]) -> Vec<u8> {
        let mut writer = XzEncoder::new(Vec::new(), 1);
        for member in members {
            writer.write_all(member).unwrap();
        }
        writer.write_all(&[0_u8; 1024]).unwrap();
        writer.finish().unwrap()
    }

    pub(super) fn alias(path: &str, target: &str) -> Vec<u8> {
        let mut record = member(path, b"", b'2', 0o777);
        record[157..157 + target.len()].copy_from_slice(target.as_bytes());
        record[148..156].fill(b' ');
        let checksum: u64 = record[..512]
            .iter()
            .map(|byte| u64::from(*byte))
            .sum();
        record[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        record
    }

    #[test]
    fn xz_admits_bounded_same_directory_aliases_and_refuses_chains_or_escape() {
        let valid = xz_archive(&[
            member("source/", b"", b'5', 0o755),
            alias("source/link", "target"),
            member("source/target", b"payload", b'0', 0o644),
        ]);
        let inventory = inspect_large_xz_tar(valid.as_slice()).unwrap();
        assert_eq!(inventory.files(), 1);
        assert_eq!(inventory.entries(), 3);
        assert!(inspect_gzip_tar(valid.as_slice()).is_err());
        let mut low_memory = ArchiveLimits::large_xz();
        low_memory.decoder_memory_bytes = 1024 * 1024;
        assert!(matches!(
            inspect_reader(valid.as_slice(), ArchiveFormat::XzTar, low_memory),
            Err(ArchiveError::Limit)
        ));
        assert!(
            inspect_reader(
                valid.as_slice(),
                ArchiveFormat::XzTar,
                ArchiveLimits {
                    entries: MAX_LARGE_ARCHIVE_ENTRIES + 1,
                    ..ArchiveLimits::large_xz()
                }
            )
            .is_err()
        );
        let mut low_entries = ArchiveLimits::large_xz();
        low_entries.entries = 2;
        assert!(matches!(
            inspect_reader(
                valid.as_slice(),
                ArchiveFormat::XzTar,
                low_entries
            ),
            Err(ArchiveError::Limit)
        ));
        for entries in [
            vec![alias("source/link", "missing")],
            vec![
                alias("source/link", "../escape"),
                member("escape", b"data", b'0', 0o644),
            ],
            vec![
                alias("source/link", "next"),
                alias("source/next", "target"),
                member("source/target", b"data", b'0', 0o644),
            ],
            vec![
                alias("source/link", "target"),
                member("source/link/child", b"data", b'0', 0o644),
                member("source/target", b"data", b'0', 0o644),
            ],
        ] {
            assert!(matches!(
                inspect_large_xz_tar(xz_archive(&entries).as_slice()),
                Err(ArchiveError::UnsafeEntry)
            ));
        }
    }

    #[test]
    fn verified_source_uses_independent_compressed_expanded_and_decoder_budgets() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(temporary.path()).unwrap();
        let bytes = xz_archive(&[member("source", b"data", b'0', 0o644)]);
        let digest = ContentDigest::sha256(&bytes);
        store
            .operation()
            .unwrap()
            .ingest(&bytes[..], digest, bytes.len() as u64)
            .unwrap();
        let mut limits = ArchiveLimits::large_xz();
        limits.compressed_bytes = bytes.len() as u64;
        assert_eq!(
            inspect_archive(&store, digest, ArchiveFormat::XzTar, limits)
                .unwrap()
                .files(),
            1
        );
        limits.compressed_bytes -= 1;
        assert!(inspect_archive(&store, digest, ArchiveFormat::XzTar, limits).is_err());
        limits.compressed_bytes += 1;
        limits.expanded_bytes = 3;
        limits.file_bytes = 3;
        assert!(matches!(
            inspect_archive(&store, digest, ArchiveFormat::XzTar, limits),
            Err(ArchiveError::Limit)
        ));
        limits.expanded_bytes = 4;
        limits.file_bytes = 4;
        limits.decoder_memory_bytes = 1024 * 1024;
        assert!(inspect_archive(&store, digest, ArchiveFormat::XzTar, limits).is_err());
    }

    #[test]
    fn accepts_small_regular_tree_and_reads_to_validated_gzip_eof() {
        let bytes = archive(&[
            member("hello/", b"", b'5', 0o755),
            member(
                "hello/main.c",
                b"int main(void) { return 0; }",
                b'0',
                0o644,
            ),
        ]);
        let inventory = inspect_gzip_tar(bytes.as_slice()).unwrap();
        assert_eq!(inventory.entries(), 2);
        assert_eq!(inventory.files(), 1);
        assert_eq!(inventory.expanded_bytes(), 28);

        let mut corrupt = bytes;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(inspect_gzip_tar(corrupt.as_slice()).is_err());
    }

    #[test]
    fn rejects_path_escape_links_duplicate_and_nonzero_tail() {
        for path in [
            "../outside",
            "/absolute",
            "a/./b",
            "a//b",
            "a\\b",
        ] {
            let bytes = archive(&[member(path, b"x", b'0', 0o644)]);
            assert!(matches!(
                inspect_gzip_tar(bytes.as_slice()),
                Err(ArchiveError::UnsafeEntry)
            ));
        }
        let link = archive(&[member("link", b"", b'2', 0o777)]);
        assert!(matches!(
            inspect_gzip_tar(link.as_slice()),
            Err(ArchiveError::UnsafeEntry)
        ));
        let duplicate = archive(&[
            member("hello", b"a", b'0', 0o644),
            member("hello", b"b", b'0', 0o644),
        ]);
        assert!(matches!(
            inspect_gzip_tar(duplicate.as_slice()),
            Err(ArchiveError::UnsafeEntry)
        ));
        let mut tar = member("hello", b"a", b'0', 0o644);
        tar.extend_from_slice(&[0_u8; 1024]);
        tar.extend_from_slice(b"hidden");
        assert!(matches!(
            inspect_gzip_tar(gzip(&tar).as_slice()),
            Err(ArchiveError::InvalidTar)
        ));
    }

    #[test]
    fn refuses_truncation_invalid_checksum_and_oversized_claim() {
        let truncated = gzip(&member("hello", b"x", b'0', 0o644));
        assert!(matches!(
            inspect_gzip_tar(truncated.as_slice()),
            Err(ArchiveError::InvalidTar)
        ));
        let mut invalid = member("hello", b"x", b'0', 0o644);
        invalid[10] ^= 1;
        invalid.extend_from_slice(&[0_u8; 1024]);
        assert!(matches!(
            inspect_gzip_tar(gzip(&invalid).as_slice()),
            Err(ArchiveError::InvalidTar)
        ));
        let mut too_large = member("hello", b"", b'0', 0o644);
        too_large[124..136]
            .copy_from_slice(format!("{:011o}\0", MAX_ARCHIVE_FILE_BYTES + 1).as_bytes());
        too_large[148..156].fill(b' ');
        let checksum: u64 = too_large[..512]
            .iter()
            .map(|byte| u64::from(*byte))
            .sum();
        too_large[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        too_large.extend_from_slice(&[0_u8; 1024]);
        assert!(matches!(
            inspect_gzip_tar(gzip(&too_large).as_slice()),
            Err(ArchiveError::Limit)
        ));
    }
}

//! Readonly descriptor handoff of chunked streams without Store path access.
//!
//! Sender custody retains object names. Receivers authenticate the selected pin
//! and retain an independent interest through their own trusted handoff protocol.

use super::{
    CHUNK_BYTES, ChunkedArtifactError, ChunkedArtifactManifest, IO_BYTES, MAX_MANIFEST_BYTES,
    Result, RetainedChunkedArtifact, check, validate_limit,
};
use crate::{cancellation::Cancellation, platform::linux::fd, store::ContentDigest};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::{
        fd::{AsFd as _, OwnedFd},
        unix::fs::{FileExt as _, MetadataExt as _},
    },
};

/// Manifest first, then one readonly CAS description per unique chunk digest in
/// ascending order. The sender holds granular custody, not a global GC barrier.
#[derive(Debug)]
pub struct ChunkedDescriptorSet {
    artifact: RetainedChunkedArtifact,
    descriptors: Vec<OwnedFd>,
}

impl ChunkedDescriptorSet {
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.artifact.manifest_digest()
    }
    pub fn descriptors(&self) -> &[OwnedFd] {
        &self.descriptors
    }
}

impl RetainedChunkedArtifact {
    /// Preflight the complete deduplicated FD count before opening objects. The
    /// supplied slot ceiling must exclude the transport/executor's other roles.
    /// Keep this owner until independently retained receiver custody is proven.
    pub fn prepare_descriptors(
        &self,
        maximum_slots: u32,
        cancellation: &Cancellation,
    ) -> Result<ChunkedDescriptorSet> {
        check(cancellation)?;
        let chunks = unique_chunks(self.manifest())?;
        check_slots(chunks.len() + 1, maximum_slots)?;
        let mut descriptors = Vec::with_capacity(chunks.len() + 1);
        for (pin, maximum) in std::iter::once((self.pin, MAX_MANIFEST_BYTES as u64))
            .chain(chunks.iter().map(|(pin, size)| (*pin, *size)))
        {
            check(cancellation)?;
            let operation = self.lease.operation()?;
            let reader = operation
                .open_verified_checked(pin, maximum, || super::check_io(cancellation))?
                .ok_or(ChunkedArtifactError::MissingChunk {
                    digest: pin,
                })?;
            descriptors.push(reader.duplicate_readonly_descriptor()?);
            // Each object opens under a short Store barrier. The original
            // artifact's granular interest protects the complete closure.
            drop((reader, operation));
        }
        check(cancellation)?;
        Ok(ChunkedDescriptorSet {
            artifact: self.clone(),
            descriptors,
        })
    }
}

#[derive(Debug)]
struct Chunk {
    file: File,
    identity: Snapshot,
    size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

/// Seekable logical content from authenticated descriptor roles. Construction
/// verifies manifest, chunk lengths/pins and the complete logical content pin.
/// Reads cache at most one 4-MiB chunk and never access a Store/host pathname.
/// This owns descriptors only: independently retain object custody and peer /
/// selected-output authorization before handing it to an untrusted payload.
#[derive(Debug)]
pub struct ChunkedDescriptorReader {
    manifest: ChunkedArtifactManifest,
    chunks: BTreeMap<ContentDigest, Chunk>,
    cancellation: Cancellation,
    position: u64,
    cache: Option<(ContentDigest, Vec<u8>)>,
}

impl ChunkedDescriptorReader {
    pub(crate) const fn manifest(&self) -> &ChunkedArtifactManifest {
        &self.manifest
    }

    pub fn from_received(
        expected_manifest: ContentDigest,
        mut descriptors: Vec<OwnedFd>,
        maximum_bytes: u64,
        maximum_slots: u32,
        cancellation: &Cancellation,
    ) -> Result<Self> {
        check(cancellation)?;
        validate_limit(maximum_bytes)?;
        check_slots(descriptors.len(), maximum_slots)?;
        let manifest_file = File::from(descriptors.remove(0));
        let manifest_identity = regular(&manifest_file, MAX_MANIFEST_BYTES as u64)?;
        let bytes = verified_bytes(
            &manifest_file,
            manifest_identity,
            expected_manifest,
            cancellation,
        )?;
        let manifest = ChunkedArtifactManifest::decode(&bytes, maximum_bytes)?;
        drop((bytes, manifest_file));
        let selected = unique_chunks(&manifest)?;
        if descriptors.len() != selected.len() {
            return Err(invalid(
                "descriptor count differs from unique chunks",
            ));
        }
        let mut chunks = BTreeMap::new();
        for ((pin, size), descriptor) in selected.into_iter().zip(descriptors) {
            check(cancellation)?;
            let file = File::from(descriptor);
            let identity = regular(&file, CHUNK_BYTES as u64)?;
            if identity.size != size {
                return Err(ChunkedArtifactError::ChunkSize {
                    digest: pin,
                    expected: size,
                    actual: identity.size,
                });
            }
            chunks.insert(
                pin,
                Chunk {
                    file,
                    identity,
                    size,
                },
            );
        }
        let mut reader = Self {
            manifest,
            chunks,
            cancellation: cancellation.clone(),
            position: 0,
            cache: None,
        };
        let mut digest = Sha256::new();
        for index in 0..reader.manifest.chunks.len() {
            let pin = reader.manifest.chunks[index];
            digest.update(reader.load(pin)?);
        }
        let actual = ContentDigest::from_sha256_hash(digest.finalize().into());
        if actual != reader.manifest.content {
            return Err(ChunkedArtifactError::ContentMismatch {
                expected: reader.manifest.content,
                actual,
            });
        }
        reader.revalidate()?;
        // No last-chunk allocation stays alive across initial seek/index work.
        reader.cache = None;
        Ok(reader)
    }

    pub const fn size(&self) -> u64 {
        self.manifest.size
    }
    pub const fn content_digest(&self) -> ContentDigest {
        self.manifest.content
    }

    fn revalidate(&self) -> Result<()> {
        check(&self.cancellation)?;
        for chunk in self.chunks.values() {
            check(&self.cancellation)?;
            if regular(&chunk.file, CHUNK_BYTES as u64)? != chunk.identity {
                return Err(invalid("chunk metadata changed"));
            }
        }
        Ok(())
    }

    fn load(&mut self, pin: ContentDigest) -> Result<&[u8]> {
        check(&self.cancellation)?;
        let chunk = &self.chunks[&pin];
        // A verified cache never substitutes for current object custody. GC
        // unlinking a role after its interest is dropped invalidates reads,
        // including ranges in the cached chunk.
        if regular(&chunk.file, chunk.size)? != chunk.identity {
            return Err(invalid(
                "chunk metadata changed before cached read",
            ));
        }
        if self
            .cache
            .as_ref()
            .is_none_or(|(cached, _)| *cached != pin)
        {
            self.cache = None;
            let bytes = verified_bytes(
                &chunk.file,
                chunk.identity,
                pin,
                &self.cancellation,
            )?;
            if bytes.len() as u64 != chunk.size {
                return Err(invalid("chunk length changed"));
            }
            self.cache = Some((pin, bytes));
        }
        Ok(&self.cache.as_ref().expect("verified cache").1)
    }
}

impl Read for ChunkedDescriptorReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        check(&self.cancellation).map_err(io::Error::other)?;
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.position >= self.size() {
            self.revalidate().map_err(io::Error::other)?;
            return Ok(0);
        }
        let pin = self.manifest.chunks
            [usize::try_from(self.position / CHUNK_BYTES as u64).expect("bounded index")];
        let offset = usize::try_from(self.position % CHUNK_BYTES as u64).expect("bounded offset");
        let chunk = self.load(pin).map_err(io::Error::other)?;
        let count = bytes
            .len()
            .min(IO_BYTES)
            .min(chunk.len() - offset);
        bytes[..count].copy_from_slice(&chunk[offset..offset + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for ChunkedDescriptorReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        check(&self.cancellation).map_err(io::Error::other)?;
        let position = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.size()) + i128::from(n),
        };
        self.position = u64::try_from(position).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside u64 range",
            )
        })?;
        let next = usize::try_from(self.position / CHUNK_BYTES as u64)
            .ok()
            .and_then(|index| self.manifest.chunks.get(index));
        if self
            .cache
            .as_ref()
            .is_some_and(|(pin, _)| Some(pin) != next)
        {
            self.cache = None;
        }
        Ok(self.position)
    }
}

fn unique_chunks(manifest: &ChunkedArtifactManifest) -> Result<BTreeMap<ContentDigest, u64>> {
    let mut result = BTreeMap::new();
    for (index, pin) in manifest.chunks.iter().enumerate() {
        let size = manifest.chunk_size(index);
        if result
            .insert(*pin, size)
            .is_some_and(|before| before != size)
        {
            return Err(invalid(
                "one chunk digest has inconsistent lengths",
            ));
        }
    }
    Ok(result)
}

fn check_slots(count: usize, maximum: u32) -> Result<()> {
    if count == 0
        || count > super::MAX_CHUNKS + 1
        || count > usize::try_from(maximum).unwrap_or(usize::MAX)
    {
        return Err(invalid(
            "descriptor slot budget exceeded or empty",
        ));
    }
    Ok(())
}

fn regular(file: &File, maximum: u64) -> Result<Snapshot> {
    fd::require_readonly(file.as_fd())?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != fd::effective_uid()
        || metadata.nlink() != 1
        || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
        || metadata.len() > maximum
    {
        return Err(invalid(
            "descriptor is not a bounded readonly CAS object",
        ));
    }
    Ok(Snapshot {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        size: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

fn verified_bytes(
    file: &File,
    before: Snapshot,
    pin: ContentDigest,
    cancellation: &Cancellation,
) -> Result<Vec<u8>> {
    if regular(file, before.size)? != before {
        return Err(invalid("descriptor changed before read"));
    }
    let mut bytes =
        vec![0; usize::try_from(before.size).map_err(|_| invalid("object exceeds address space"))?];
    let mut position = 0;
    while position < bytes.len() {
        check(cancellation)?;
        let end = (position + IO_BYTES).min(bytes.len());
        match file.read_at(&mut bytes[position..end], position as u64) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(n) => position += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    check(cancellation)?;
    loop {
        check(cancellation)?;
        let mut extra = [0];
        match file.read_at(&mut extra, before.size) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            result => {
                if result? != 0 || regular(file, before.size)? != before {
                    return Err(invalid("descriptor changed during read"));
                }
                break;
            }
        }
    }
    let actual = ContentDigest::sha256(&bytes);
    if actual != pin {
        return Err(ChunkedArtifactError::ContentMismatch {
            expected: pin,
            actual,
        });
    }
    Ok(bytes)
}

fn invalid(reason: &'static str) -> ChunkedArtifactError {
    ChunkedArtifactError::InvalidManifest(reason)
}

#[cfg(test)]
mod tests;

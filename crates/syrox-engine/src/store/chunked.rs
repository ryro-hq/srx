//! Large byte streams represented by a versioned manifest and 4 MiB CAS objects.
//!
//! Admission authenticates the complete logical content before publishing its
//! manifest. Handles and roots retain the expanded object closure, using the
//! Store's existing interest, publication, recovery and GC protocols. Keeping a
//! manifest as an ordinary opaque blob alone does not retain its chunks.
//!
//! This container does not change package-output formats or build budgets.

use super::{
    ContentDigest, ObjectLease, OperationLease, RootName, RootPublicationState, StoreError,
};
use crate::cancellation::{CancellableReader, Cancellation, cancellation_io, is_cancellation_io};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::io::{self, Read, Write};

mod writer;
pub use writer::ChunkedStaging;
mod reader;
pub use reader::ChunkedReader;
mod descriptors;
pub use descriptors::{ChunkedDescriptorReader, ChunkedDescriptorSet};

/// Every chunk except the last has exactly this length.
pub const CHUNK_BYTES: usize = 4 * 1024 * 1024;
/// Leave one reference for the manifest in the existing bounded root format.
pub const MAX_CHUNKS: usize = 65_535;
const _: () = assert!((MAX_CHUNKS as u64) < super::MAX_ROOT_REFERENCES);
pub const MAX_ARTIFACT_BYTES: u64 = CHUNK_BYTES as u64 * MAX_CHUNKS as u64;
const HEADER: &[u8] = b"syrox-chunked-artifact-v1\n";
const FIXED_FIELDS: usize = 4 + 8 + 32 + 4;
const MAX_MANIFEST_BYTES: usize = HEADER.len() + FIXED_FIELDS + 32 * MAX_CHUNKS;
const IO_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ChunkedArtifactError {
    #[error(
        "configured artifact limit {configured} exceeds the hard {MAX_ARTIFACT_BYTES}-byte limit"
    )]
    InvalidLimit {
        configured: u64,
    },
    #[error("artifact exceeds the configured {limit}-byte limit")]
    TooLarge {
        limit: u64,
    },
    #[error("invalid chunked artifact manifest: {0}")]
    InvalidManifest(&'static str),
    #[error("chunked artifact references missing object {digest}")]
    MissingChunk {
        digest: ContentDigest,
    },
    #[error("chunk {digest} has length {actual}, expected {expected}")]
    ChunkSize {
        digest: ContentDigest,
        expected: u64,
        actual: u64,
    },
    #[error("artifact content digest mismatch: expected {expected}, calculated {actual}")]
    ContentMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("chunked artifact operation cancelled")]
    Cancelled,
    #[error("chunked staging cannot be used after a failed append or flush")]
    FailedStaging,
    #[error(transparent)]
    Store(StoreError),
    #[error("artifact I/O failed: {0}")]
    Io(#[from] io::Error),
}

impl From<StoreError> for ChunkedArtifactError {
    fn from(error: StoreError) -> Self {
        if matches!(&error, StoreError::Io(source) if is_cancellation_io(source)) {
            Self::Cancelled
        } else {
            Self::Store(error)
        }
    }
}

type Result<T> = std::result::Result<T, ChunkedArtifactError>;

/// Immutable ordered chunk identities, logical length and complete content pin.
/// A manifest's own digest identifies the container, separately from its content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkedArtifactManifest {
    content: ContentDigest,
    size: u64,
    chunks: Vec<ContentDigest>,
}

impl ChunkedArtifactManifest {
    pub const fn content_digest(&self) -> ContentDigest {
        self.content
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub fn chunks(&self) -> &[ContentDigest] {
        &self.chunks
    }

    /// Canonical v1 bytes. The size and chunk count have already been bounded
    /// before this manifest was constructed; no payload bytes are embedded here.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER.len() + FIXED_FIELDS + 32 * self.chunks.len());
        bytes.extend_from_slice(HEADER);
        bytes.extend_from_slice(
            &u32::try_from(CHUNK_BYTES)
                .expect("fixed chunk size fits u32")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.size.to_le_bytes());
        bytes.extend_from_slice(self.content.as_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.chunks.len())
                .expect("bounded chunk count fits u32")
                .to_le_bytes(),
        );
        for digest in &self.chunks {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes
    }

    pub(crate) fn decode(bytes: &[u8], maximum_bytes: u64) -> Result<Self> {
        let invalid = ChunkedArtifactError::InvalidManifest;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(invalid("manifest byte limit exceeded"));
        }
        let fields = bytes
            .strip_prefix(HEADER)
            .ok_or(invalid("unsupported format"))?;
        if fields.len() < FIXED_FIELDS {
            return Err(invalid("truncated fields"));
        }
        let chunk_bytes = u32::from_le_bytes(fields[..4].try_into().expect("bounded fields"));
        let size = u64::from_le_bytes(fields[4..12].try_into().expect("bounded fields"));
        let count = u32::from_le_bytes(fields[44..48].try_into().expect("bounded fields")) as usize;
        if u64::from(chunk_bytes) != CHUNK_BYTES as u64 || count > MAX_CHUNKS {
            return Err(invalid("unsupported chunk size or count"));
        }
        if size > maximum_bytes {
            return Err(ChunkedArtifactError::TooLarge {
                limit: maximum_bytes,
            });
        }
        if size > MAX_ARTIFACT_BYTES
            || size.div_ceil(CHUNK_BYTES as u64) != count as u64
            || fields.len() != FIXED_FIELDS + 32 * count
        {
            return Err(invalid("inconsistent length or trailing bytes"));
        }
        let content =
            ContentDigest::from_sha256_hash(fields[12..44].try_into().expect("bounded fields"));
        let chunks = fields[FIXED_FIELDS..]
            .as_chunks::<32>()
            .0
            .iter()
            .map(|digest| ContentDigest::from_sha256_hash(*digest))
            .collect();
        Ok(Self {
            content,
            size,
            chunks,
        })
    }

    fn references(&self, pin: ContentDigest) -> Vec<ContentDigest> {
        self.chunks
            .iter()
            .copied()
            .chain([pin])
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn chunk_size(&self, index: usize) -> u64 {
        (self.size - index as u64 * CHUNK_BYTES as u64).min(CHUNK_BYTES as u64)
    }
}

/// Verified artifact with a granular interest in its manifest and all chunks.
/// Clones share retention. This handle grants no installation or execution rights.
#[derive(Clone, Debug)]
pub struct RetainedChunkedArtifact {
    manifest: ChunkedArtifactManifest,
    pin: ContentDigest,
    lease: ObjectLease,
}

impl RetainedChunkedArtifact {
    pub(crate) const fn object_lease(&self) -> &ObjectLease {
        &self.lease
    }

    pub(crate) fn retained_references(&self) -> Vec<ContentDigest> {
        self.manifest.references(self.pin)
    }

    pub const fn manifest_digest(&self) -> ContentDigest {
        self.pin
    }

    pub const fn manifest(&self) -> &ChunkedArtifactManifest {
        &self.manifest
    }

    /// Atomically retain the complete closure with the usual immutable root
    /// protocol. Existing roots and publication uncertainty keep their semantics.
    pub fn publish_root(
        &self,
        name: &RootName,
        cancellation: &Cancellation,
    ) -> Result<RootPublicationState> {
        Ok(self
            .lease
            .publish_root_checked(name, &self.manifest.references(self.pin), || {
                check_io(cancellation)
            })?)
    }

    /// Reverify each bounded chunk before emitting its bytes in logical order.
    /// The destination may contain a prefix on failure. Callers publishing files
    /// must stage and commit them only after success. Transports must independently
    /// bound blocked I/O; cooperative cancellation cannot interrupt a blocked call.
    pub fn copy_to(
        &self,
        destination: &mut impl Write,
        cancellation: &Cancellation,
    ) -> Result<u64> {
        let mut content = Sha256::new();
        for (index, digest) in self.manifest.chunks.iter().enumerate() {
            check(cancellation)?;
            // The object interest protects the whole closure across these short
            // operation barriers. A slow destination never keeps GC excluded.
            let bytes = read_chunk(
                &self.lease.operation()?,
                *digest,
                self.manifest.chunk_size(index),
                cancellation,
            )?;
            content.update(&bytes);
            for part in bytes.chunks(IO_BYTES) {
                check(cancellation)?;
                destination.write_all(part)?;
            }
        }
        check(cancellation)?;
        verify_content(content, self.manifest.content)?;
        Ok(self.manifest.size)
    }
}

impl OperationLease {
    /// Admit a pinned logical stream without buffering the complete artifact.
    /// Chunks published before failure remain unretained and collectible. The
    /// manifest becomes visible only after EOF, budget and full digest checks.
    pub fn ingest_chunked(
        &self,
        mut source: impl Read,
        expected: ContentDigest,
        maximum_bytes: u64,
        cancellation: &Cancellation,
    ) -> Result<RetainedChunkedArtifact> {
        validate_limit(maximum_bytes)?;
        check(cancellation)?;
        let mut buffer = vec![0; CHUNK_BYTES];
        let mut chunks = Vec::new();
        let mut size = 0;
        let mut content = Sha256::new();
        loop {
            let mut used = 0;
            while used < buffer.len() {
                check(cancellation)?;
                let requested = (buffer.len() - used).min(IO_BYTES).min(
                    usize::try_from(maximum_bytes.saturating_sub(size) + 1).unwrap_or(usize::MAX),
                );
                let count = match source.read(&mut buffer[used..used + requested]) {
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                };
                if count == 0 {
                    break;
                }
                size += count as u64;
                if size > maximum_bytes {
                    return Err(ChunkedArtifactError::TooLarge {
                        limit: maximum_bytes,
                    });
                }
                used += count;
            }
            if used == 0 {
                break;
            }
            let bytes = &buffer[..used];
            let digest = ContentDigest::sha256(bytes);
            content.update(bytes);
            self.ingest(
                CancellableReader {
                    source: bytes,
                    cancellation,
                },
                digest,
                used as u64,
            )?;
            chunks.push(digest);
            if used < buffer.len() {
                break;
            }
        }
        check(cancellation)?;
        verify_content(content, expected)?;
        let manifest = ChunkedArtifactManifest {
            content: expected,
            size,
            chunks,
        };
        let bytes = manifest.canonical_bytes();
        let pin = ContentDigest::sha256(&bytes);
        check(cancellation)?;
        // Finish publication and custody without a later cancellation check
        // hiding a completed or uncertain manifest publication.
        self.ingest(bytes.as_slice(), pin, MAX_MANIFEST_BYTES as u64)?;
        self.retain_chunked(manifest, pin)
    }

    /// Open an explicitly pinned manifest and verify every transitive object,
    /// chunk length and the complete logical digest before returning custody.
    /// Only an absent manifest returns None; a broken closure is an error.
    pub fn open_chunked(
        &self,
        pin: ContentDigest,
        maximum_bytes: u64,
        cancellation: &Cancellation,
    ) -> Result<Option<RetainedChunkedArtifact>> {
        self.open_chunked_control(pin, maximum_bytes, cancellation)
    }

    pub(crate) fn open_chunked_control(
        &self,
        pin: ContentDigest,
        maximum_bytes: u64,
        cancellation: &(impl crate::cancellation::OperationControl + ?Sized),
    ) -> Result<Option<RetainedChunkedArtifact>> {
        validate_limit(maximum_bytes)?;
        check(cancellation)?;
        let Some(reader) = self.open_verified_checked(pin, MAX_MANIFEST_BYTES as u64, || {
            check_io(cancellation)
        })?
        else {
            return Ok(None);
        };
        let mut bytes =
            Vec::with_capacity(usize::try_from(reader.size()).expect("bounded manifest size") + 1);
        reader
            .take(MAX_MANIFEST_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        let actual = ContentDigest::sha256(&bytes);
        if actual != pin {
            return Err(StoreError::CorruptObject {
                expected: pin,
                actual,
            }
            .into());
        }
        let manifest = ChunkedArtifactManifest::decode(&bytes, maximum_bytes)?;
        let mut content = Sha256::new();
        for (index, digest) in manifest.chunks.iter().enumerate() {
            let bytes = read_chunk(
                self,
                *digest,
                manifest.chunk_size(index),
                cancellation,
            )?;
            content.update(&bytes);
        }
        check(cancellation)?;
        verify_content(content, manifest.content)?;
        self.retain_chunked(manifest, pin).map(Some)
    }

    fn retain_chunked(
        &self,
        manifest: ChunkedArtifactManifest,
        pin: ContentDigest,
    ) -> Result<RetainedChunkedArtifact> {
        let lease = self.retain_objects(&manifest.references(pin), &[])?;
        Ok(RetainedChunkedArtifact {
            manifest,
            pin,
            lease,
        })
    }
}

fn read_chunk(
    operation: &OperationLease,
    digest: ContentDigest,
    expected_size: u64,
    cancellation: &(impl crate::cancellation::OperationControl + ?Sized),
) -> Result<Vec<u8>> {
    let Some(reader) = operation.open_verified_checked(digest, CHUNK_BYTES as u64, || {
        check_io(cancellation)
    })?
    else {
        return Err(ChunkedArtifactError::MissingChunk {
            digest,
        });
    };
    if reader.size() != expected_size {
        return Err(ChunkedArtifactError::ChunkSize {
            digest,
            expected: expected_size,
            actual: reader.size(),
        });
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(expected_size).expect("bounded chunk size") + 1);
    reader
        .take(expected_size + 1)
        .read_to_end(&mut bytes)?;
    // Defend the bound and pin even if the inode changed after verification.
    if bytes.len() as u64 != expected_size {
        return Err(ChunkedArtifactError::ChunkSize {
            digest,
            expected: expected_size,
            actual: bytes.len() as u64,
        });
    }
    let actual = ContentDigest::sha256(&bytes);
    if actual != digest {
        return Err(StoreError::CorruptObject {
            expected: digest,
            actual,
        }
        .into());
    }
    Ok(bytes)
}

fn validate_limit(maximum_bytes: u64) -> Result<()> {
    if maximum_bytes > MAX_ARTIFACT_BYTES {
        Err(ChunkedArtifactError::InvalidLimit {
            configured: maximum_bytes,
        })
    } else {
        Ok(())
    }
}

fn verify_content(hasher: Sha256, expected: ContentDigest) -> Result<()> {
    let actual = ContentDigest::from_sha256_hash(hasher.finalize().into());
    if actual == expected {
        Ok(())
    } else {
        Err(ChunkedArtifactError::ContentMismatch {
            expected,
            actual,
        })
    }
}

fn check(cancellation: &(impl crate::cancellation::OperationControl + ?Sized)) -> Result<()> {
    cancellation
        .check_cancelled()
        .map_err(|_| ChunkedArtifactError::Cancelled)
}

fn check_io(
    cancellation: &(impl crate::cancellation::OperationControl + ?Sized),
) -> io::Result<()> {
    cancellation
        .check_cancelled()
        .map_err(|_| cancellation_io())
}

#[cfg(test)]
mod tests;

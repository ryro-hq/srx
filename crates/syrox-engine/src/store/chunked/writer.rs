//! A producer-side stream which publishes a manifest only on verified finish.

use super::{
    CHUNK_BYTES, Cancellation, ChunkedArtifactError, ChunkedArtifactManifest, ContentDigest,
    IO_BYTES, OperationLease, Result, RetainedChunkedArtifact, check, validate_limit,
    verify_content,
};
use sha2::{Digest as _, Sha256};
use std::io::{self, Write};

/// Bounded, fallible staging for a logical stream. Complete chunks may enter CAS
/// before finish, but have no durable consumer root or manifest. Dropping or
/// poisoning the writer leaves those objects collectible by normal GC.
///
/// `flush` checks state/cancellation; it cannot emit a partial non-final chunk.
/// Only `finish` validates the full digest, publishes a manifest and transfers
/// the complete closure to granular live retention. No installation is implied.
pub struct ChunkedStaging<'a> {
    operation: OperationLease,
    cancellation: &'a Cancellation,
    maximum_bytes: u64,
    buffer: Vec<u8>,
    used: usize,
    size: u64,
    hasher: Sha256,
    chunks: Vec<ContentDigest>,
    failed: bool,
}

impl std::fmt::Debug for ChunkedStaging<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkedStaging")
            .field("maximum_bytes", &self.maximum_bytes)
            .field("size", &self.size)
            .field("chunks", &self.chunks.len())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl OperationLease {
    pub fn begin_chunked<'a>(
        &self,
        maximum_bytes: u64,
        cancellation: &'a Cancellation,
    ) -> Result<ChunkedStaging<'a>> {
        validate_limit(maximum_bytes)?;
        check(cancellation)?;
        Ok(ChunkedStaging {
            operation: self.clone(),
            cancellation,
            maximum_bytes,
            buffer: vec![0; CHUNK_BYTES],
            used: 0,
            size: 0,
            hasher: Sha256::new(),
            chunks: Vec::new(),
            failed: false,
        })
    }
}

impl ChunkedStaging<'_> {
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Append a bounded caller slice. Any failure permanently poisons staging,
    /// including an oversized write; callers cannot finish a silently short image.
    pub fn append(&mut self, bytes: &[u8]) -> Result<()> {
        if self.failed {
            return Err(ChunkedArtifactError::FailedStaging);
        }
        let result = self.append_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn append_inner(&mut self, mut bytes: &[u8]) -> Result<()> {
        check(self.cancellation)?;
        if bytes.len() as u64 > self.maximum_bytes - self.size {
            return Err(ChunkedArtifactError::TooLarge {
                limit: self.maximum_bytes,
            });
        }
        while !bytes.is_empty() {
            check(self.cancellation)?;
            let take = bytes
                .len()
                .min(CHUNK_BYTES - self.used)
                .min(IO_BYTES);
            self.buffer[self.used..self.used + take].copy_from_slice(&bytes[..take]);
            self.hasher.update(&bytes[..take]);
            self.used += take;
            self.size += take as u64;
            bytes = &bytes[take..];
            if self.used == CHUNK_BYTES {
                self.publish_chunk()?;
            }
        }
        Ok(())
    }

    fn publish_chunk(&mut self) -> Result<()> {
        check(self.cancellation)?;
        let bytes = &self.buffer[..self.used];
        let digest = ContentDigest::sha256(bytes);
        self.operation.ingest(
            crate::cancellation::CancellableReader {
                source: bytes,
                cancellation: self.cancellation,
            },
            digest,
            self.used as u64,
        )?;
        self.chunks.push(digest);
        self.used = 0;
        Ok(())
    }

    pub fn finish(mut self, expected: ContentDigest) -> Result<RetainedChunkedArtifact> {
        if self.failed {
            return Err(ChunkedArtifactError::FailedStaging);
        }
        check(self.cancellation)?;
        // Check the logical hash before publishing the final partial chunk.
        verify_content(self.hasher.clone(), expected)?;
        if self.used != 0 {
            self.publish_chunk()?;
        }
        let manifest = ChunkedArtifactManifest {
            content: expected,
            size: self.size,
            chunks: self.chunks,
        };
        let bytes = manifest.canonical_bytes();
        let pin = ContentDigest::sha256(&bytes);
        check(self.cancellation)?;
        // Do not observe cancellation after successful/uncertain publication.
        self.operation.ingest(
            bytes.as_slice(),
            pin,
            super::MAX_MANIFEST_BYTES as u64,
        )?;
        self.operation.retain_chunked(manifest, pin)
    }
}

impl Write for ChunkedStaging<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Avoid copying an arbitrarily large slice in one cooperative I/O call.
        let take = bytes.len().min(IO_BYTES);
        self.append(&bytes[..take])
            .map_err(io::Error::other)?;
        Ok(take)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other(
                ChunkedArtifactError::FailedStaging,
            ));
        }
        if let Err(error) = check(self.cancellation) {
            self.failed = true;
            return Err(io::Error::other(error));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

//! Seekable verified logical streams for artifact indexes and bounded file reads.

use super::{CHUNK_BYTES, Cancellation, IO_BYTES, RetainedChunkedArtifact, check, read_chunk};
use std::io::{self, Read, Seek, SeekFrom};

/// A seekable view with one verified chunk cached in memory. Granular retention
/// keeps the complete closure alive, while short Store barriers cover chunk reads.
/// The verified cache can serve ranges without reopening or trusting host paths.
pub struct ChunkedReader {
    artifact: RetainedChunkedArtifact,
    cancellation: Cancellation,
    position: u64,
    cache: Option<(usize, Vec<u8>)>,
}

impl std::fmt::Debug for ChunkedReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChunkedReader")
            .field("manifest", &self.artifact.manifest_digest())
            .field("size", &self.size())
            .field("position", &self.position)
            .field(
                "cached_chunk",
                &self
                    .cache
                    .as_ref()
                    .map(|(index, bytes)| (*index, bytes.len())),
            )
            .finish_non_exhaustive()
    }
}

impl RetainedChunkedArtifact {
    /// Share this already-verified artifact's retention without loading its whole
    /// content or holding a global maintenance barrier for the reader's lifetime.
    pub fn open_reader(&self, cancellation: &Cancellation) -> ChunkedReader {
        ChunkedReader {
            artifact: self.clone(),
            cancellation: cancellation.clone(),
            position: 0,
            cache: None,
        }
    }
}

impl ChunkedReader {
    pub const fn size(&self) -> u64 {
        self.artifact.manifest.size
    }
    pub const fn content_digest(&self) -> super::ContentDigest {
        self.artifact.manifest.content
    }
}

impl Read for ChunkedReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        check(&self.cancellation).map_err(io::Error::other)?;
        if bytes.is_empty() || self.position >= self.size() {
            return Ok(0);
        }
        let index =
            usize::try_from(self.position / CHUNK_BYTES as u64).expect("bounded chunk index");
        if self
            .cache
            .as_ref()
            .is_none_or(|(cached, _)| *cached != index)
        {
            // Drop the previous allocation before acquiring another chunk.
            self.cache = None;
            let chunk = {
                let operation = self
                    .artifact
                    .lease
                    .operation()
                    .map_err(io::Error::other)?;
                read_chunk(
                    &operation,
                    self.artifact.manifest.chunks[index],
                    self.artifact.manifest.chunk_size(index),
                    &self.cancellation,
                )
                .map_err(io::Error::other)?
            };
            self.cache = Some((index, chunk));
        }
        let (_, chunk) = self.cache.as_ref().expect("verified cache");
        let offset = usize::try_from(self.position % CHUNK_BYTES as u64).expect("bounded offset");
        let length = bytes
            .len()
            .min(IO_BYTES)
            .min(chunk.len() - offset);
        bytes[..length].copy_from_slice(&chunk[offset..offset + length]);
        self.position += length as u64;
        Ok(length)
    }
}

impl Seek for ChunkedReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        check(&self.cancellation).map_err(io::Error::other)?;
        let position = match from {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
            SeekFrom::End(offset) => i128::from(self.size()) + i128::from(offset),
        };
        let position = u64::try_from(position).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start or past u64 range",
            )
        })?;
        if self
            .cache
            .as_ref()
            .is_some_and(|(index, _)| *index as u64 != position / CHUNK_BYTES as u64)
        {
            self.cache = None;
        }
        self.position = position;
        Ok(position)
    }
}

#[cfg(test)]
mod tests;

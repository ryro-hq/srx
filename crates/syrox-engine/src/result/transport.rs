//! Explicit versioned storage descriptors for system package outputs.

use super::{ResultError, invalid};
use crate::{
    cancellation::{Cancellation, OperationControl},
    result::artifact::ArtifactLimits,
    store::{
        ContentDigest, OperationLease, VerifiedReader,
        chunked::{
            ChunkedArtifactManifest, ChunkedReader, MAX_ARTIFACT_BYTES, RetainedChunkedArtifact,
        },
    },
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Seek, SeekFrom};

/// Canonical chunk manifest embedded in a v3 consumption result. Keeping these
/// bytes in the result makes its full GC and transport closure explicit without
/// trusting an opaque manifest blob as a transitive reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkedOutput {
    manifest: String,
}

impl ChunkedOutput {
    pub fn from_artifact(artifact: &RetainedChunkedArtifact) -> Self {
        Self {
            manifest: syrox_encoding::hex(&artifact.manifest().canonical_bytes()),
        }
    }

    pub(crate) fn decoded(&self) -> Result<ChunkedArtifactManifest, ResultError> {
        let bytes = decode_hex(&self.manifest)?;
        ChunkedArtifactManifest::decode(&bytes, MAX_ARTIFACT_BYTES)
            .map_err(|error| invalid(error.to_string()))
    }

    pub(crate) fn references(&self, pin: ContentDigest) -> Result<Vec<ContentDigest>, ResultError> {
        let manifest = self.decoded()?;
        if ContentDigest::sha256(&manifest.canonical_bytes()) != pin {
            return Err(invalid(
                "chunk manifest disagrees with output identity",
            ));
        }
        Ok(manifest
            .chunks()
            .iter()
            .copied()
            .chain([pin])
            .collect())
    }
}

fn decode_hex(text: &str) -> Result<Vec<u8>, ResultError> {
    if text.len() > 2 * (crate::store::chunked::MAX_CHUNKS * 32 + 128)
        || !text.len().is_multiple_of(2)
    {
        return Err(invalid("chunk manifest encoding exceeds bounds"));
    }
    syrox_encoding::decode_lower_hex(text)
        .ok_or_else(|| invalid("noncanonical chunk manifest encoding"))
}

/// A seekable logical artifact. The chunked reader has one verified chunk in
/// memory; existing file indexes and view writers work identically with either
/// storage form. Callers must retain and validate the complete authorization.
#[derive(Debug)]
pub(crate) enum ArtifactReader {
    Blob(VerifiedReader),
    Chunked(ChunkedReader),
}

impl ArtifactReader {
    pub(crate) fn open(
        operation: &OperationLease,
        pin: ContentDigest,
        chunked: Option<&ChunkedOutput>,
        limits: ArtifactLimits,
        cancellation: &(impl OperationControl + ?Sized),
    ) -> Result<Self, ResultError> {
        if let Some(descriptor) = chunked {
            let expected = descriptor.decoded()?;
            if expected.size() > limits.bytes
                || ContentDigest::sha256(&expected.canonical_bytes()) != pin
            {
                return Err(invalid(
                    "chunked output exceeds policy or disagrees with identity",
                ));
            }
            let artifact = operation
                .open_chunked_control(pin, limits.bytes, cancellation)
                .map_err(|error| {
                    if cancellation.is_cancelled() {
                        ResultError::Cancelled
                    } else if let crate::store::chunked::ChunkedArtifactError::Store(error) = error
                    {
                        ResultError::from(error)
                    } else {
                        invalid(error.to_string())
                    }
                })?
                .ok_or_else(|| invalid("chunked output is absent"))?;
            if artifact.manifest() != &expected {
                return Err(invalid(
                    "chunked output disagrees with result descriptor",
                ));
            }
            // The outer artifact scanner/view copier checks the shared control
            // before every bounded read. This token owns no cancellation authority
            // over the operation's other consumers.
            Ok(Self::Chunked(
                artifact.open_reader(&Cancellation::default()),
            ))
        } else {
            Ok(Self::Blob(
                operation
                    .open_verified_checked(pin, limits.bytes, || {
                        cancellation
                            .check_cancelled()
                            .map_err(|_| crate::cancellation::cancellation_io())
                    })?
                    .ok_or_else(|| invalid("output artifact is absent"))?,
            ))
        }
    }

    pub(crate) fn duplicate_readonly_descriptor(&self) -> io::Result<std::os::fd::OwnedFd> {
        match self {
            Self::Blob(reader) => reader.duplicate_readonly_descriptor(),
            Self::Chunked(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "legacy worker descriptor protocol cannot consume chunked outputs",
            )),
        }
    }

    pub(crate) fn read_range_checked(
        &mut self,
        offset: u64,
        length: usize,
        cancellation: &(impl OperationControl + ?Sized),
    ) -> io::Result<Vec<u8>> {
        if let Self::Blob(reader) = self {
            return reader.read_range_checked(offset, length, || {
                cancellation
                    .check_cancelled()
                    .map_err(|_| crate::cancellation::cancellation_io())
            });
        }
        self.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; length];
        for buffer in bytes.chunks_mut(64 * 1024) {
            cancellation
                .check_cancelled()
                .map_err(|_| crate::cancellation::cancellation_io())?;
            self.read_exact(buffer)?;
        }
        cancellation
            .check_cancelled()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        Ok(bytes)
    }

    pub(crate) fn size(&self) -> u64 {
        match self {
            Self::Blob(reader) => reader.size(),
            Self::Chunked(reader) => reader.size(),
        }
    }
}

impl Read for ArtifactReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Blob(reader) => reader.read(bytes),
            Self::Chunked(reader) => reader.read(bytes),
        }
    }
}
impl Seek for ArtifactReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        match self {
            Self::Blob(reader) => reader.seek(from),
            Self::Chunked(reader) => reader.seek(from),
        }
    }
}

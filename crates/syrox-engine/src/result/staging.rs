//! Streaming validation at the boundary of a system output producer.

use super::{
    ChunkedOutput, ResultError, ResultOutput,
    artifact::{self, ArtifactLimits},
    check, invalid,
};
use crate::{
    cancellation::Cancellation,
    store::{
        ContentDigest, Store,
        chunked::{ChunkedStaging, MAX_ARTIFACT_BYTES, RetainedChunkedArtifact},
    },
    system::budget::AdmittedBudget,
};
use sha2::{Digest as _, Sha256};
use std::io::{self, Read};

/// A fully checked logical package stream and its v3 result descriptor. Its
/// granular interest protects chunks between producer validation and admission.
/// This evidence grants no build receipt, execution or installation authority.
#[derive(Debug)]
pub struct PreparedSystemOutput {
    artifact: RetainedChunkedArtifact,
    output: ResultOutput,
}

impl PreparedSystemOutput {
    pub const fn artifact(&self) -> &RetainedChunkedArtifact {
        &self.artifact
    }
    pub const fn metadata(&self) -> &ResultOutput {
        &self.output
    }
}

/// Validate records, aliases, lengths, expanded bytes and file/inode counts while
/// hashing and chunking a producer stream in one pass. Neither the chunk manifest
/// nor a result root is published for malformed, cancelled or hash-mismatched
/// input. Complete chunks left by failure are recoverable through normal GC.
pub fn ingest_system_output(
    store: &Store,
    input: impl Read,
    expected_content: ContentDigest,
    action: ContentDigest,
    output: &str,
    budget: &AdmittedBudget,
    cancellation: &Cancellation,
) -> Result<PreparedSystemOutput, ResultError> {
    ingest(
        store,
        input,
        Some(expected_content),
        action,
        output,
        budget,
        cancellation,
    )
}

/// Encode and validate an explicitly selected, settled System output directory
/// directly into retained chunks. The full content pin is computed from emitted
/// bytes; the canonical scanner still checks the complete frame before publishing
/// its chunk manifest. No build receipt or consumer root is created here.
pub fn stage_system_output(
    store: &Store,
    directory: std::fs::File,
    action: ContentDigest,
    output: &str,
    budget: &AdmittedBudget,
    cancellation: &Cancellation,
) -> Result<PreparedSystemOutput, ResultError> {
    check(cancellation)?;
    if !super::valid_name(output) {
        return Err(invalid("invalid system output name"));
    }
    let input = super::SystemOutputStream::from_directory(directory, budget, cancellation)?;
    ingest(
        store,
        input,
        None,
        action,
        output,
        budget,
        cancellation,
    )
}

pub(super) fn system_limits(budget: &AdmittedBudget) -> Result<ArtifactLimits, ResultError> {
    if budget.request().output_bytes > MAX_ARTIFACT_BYTES || budget.request().files > 1_000_000 {
        return Err(invalid(
            "system output budget exceeds artifact format limits",
        ));
    }
    Ok(ArtifactLimits {
        bytes: budget.request().output_bytes,
        expanded_bytes: budget.request().output_bytes,
        files: usize::try_from(budget.request().files).expect("bounded files"),
    })
}

fn ingest(
    store: &Store,
    input: impl Read,
    expected_content: Option<ContentDigest>,
    action: ContentDigest,
    output: &str,
    budget: &AdmittedBudget,
    cancellation: &Cancellation,
) -> Result<PreparedSystemOutput, ResultError> {
    check(cancellation)?;
    if !super::valid_name(output) {
        return Err(invalid("invalid system output name"));
    }
    let limits = system_limits(budget)?;
    let operation = store.operation()?;
    let mut staging = operation
        .begin_chunked(limits.bytes, cancellation)
        .map_err(|error| invalid(error.to_string()))?;
    let scanned = scan_into(
        input,
        &mut staging,
        limits,
        expected_content.is_none(),
        cancellation,
    )?;
    let expected_content =
        expected_content.unwrap_or_else(|| scanned.content.expect("local producer hasher"));
    finish_staged(
        staging,
        expected_content,
        action,
        output,
        scanned.files,
        cancellation,
    )
}

pub(super) struct ScannedOutput {
    pub files: usize,
    pub entries: usize,
    pub expanded_bytes: u64,
    pub content: Option<ContentDigest>,
}

pub(super) fn scan_into(
    input: impl Read,
    staging: &mut ChunkedStaging<'_>,
    limits: ArtifactLimits,
    compute_hash: bool,
    cancellation: &Cancellation,
) -> Result<ScannedOutput, ResultError> {
    let mut hasher = compute_hash.then(Sha256::new);
    let index = artifact::scan_with_limits(
        io::BufReader::with_capacity(
            64 * 1024,
            Tee {
                input,
                staging,
                cancellation,
                hasher: &mut hasher,
            },
        ),
        "",
        limits,
    )
    .map_err(|error| {
        if cancellation.is_cancelled() {
            ResultError::Cancelled
        } else {
            invalid(error.to_string())
        }
    })?;
    let entries = index
        .view_entries(limits.files)
        .map_err(|error| invalid(error.to_string()))?;
    check(cancellation)?;
    Ok(ScannedOutput {
        files: index.len(),
        entries,
        expanded_bytes: index.expanded_bytes(),
        content: hasher.map(|h| ContentDigest::from_sha256_hash(h.finalize().into())),
    })
}

pub(super) fn finish_staged(
    staging: ChunkedStaging<'_>,
    expected_content: ContentDigest,
    action: ContentDigest,
    output: &str,
    files: usize,
    cancellation: &Cancellation,
) -> Result<PreparedSystemOutput, ResultError> {
    check(cancellation)?;
    let artifact = staging
        .finish(expected_content)
        .map_err(|error| {
            if cancellation.is_cancelled() {
                ResultError::Cancelled
            } else {
                invalid(error.to_string())
            }
        })?;
    let output = ResultOutput {
        action,
        output: output.to_owned(),
        artifact: artifact.manifest_digest(),
        files,
        chunked: Some(ChunkedOutput::from_artifact(&artifact)),
    };
    Ok(PreparedSystemOutput {
        artifact,
        output,
    })
}

struct Tee<'a, 'b, R> {
    input: R,
    staging: &'a mut ChunkedStaging<'b>,
    cancellation: &'a Cancellation,
    hasher: &'a mut Option<Sha256>,
}

impl<R: Read> Read for Tee<'_, '_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.cancellation
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        let maximum = bytes.len().min(64 * 1024);
        let count = loop {
            self.cancellation
                .check()
                .map_err(|_| crate::cancellation::cancellation_io())?;
            match self.input.read(&mut bytes[..maximum]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => break result?,
            }
        };
        self.staging
            .append(&bytes[..count])
            .map_err(io::Error::other)?;
        if let Some(hasher) = self.hasher.as_mut() {
            hasher.update(&bytes[..count]);
        }
        Ok(count)
    }
}

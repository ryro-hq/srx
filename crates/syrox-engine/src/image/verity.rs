use super::{ImageBuildError, check};
use crate::{
    cancellation::Cancellation,
    store::{
        ContentDigest, ObjectLease, RootName, RootPublicationState, Store,
        chunked::{CHUNK_BYTES, RetainedChunkedArtifact},
    },
    system::{
        budget::AdmittedBudget,
        verity::{Geometry, VerityError, write_level},
    },
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    io::{self, Read as _},
    time::{Duration, Instant},
};

/// A data stream and separate root-first hash device, with pinned parameters.
/// This handle proves artifact identity, not a signed boot or installation.
#[derive(Clone, Debug)]
pub struct BuiltVerity {
    data: RetainedChunkedArtifact,
    hashes: RetainedChunkedArtifact,
    geometry: Geometry,
    root_hash: ContentDigest,
    salt: [u8; 32],
    manifest: ContentDigest,
    references: Vec<ContentDigest>,
    lease: ObjectLease,
}

impl BuiltVerity {
    pub const fn data(&self) -> &RetainedChunkedArtifact {
        &self.data
    }
    pub const fn hash_tree(&self) -> &RetainedChunkedArtifact {
        &self.hashes
    }
    pub const fn geometry(&self) -> &Geometry {
        &self.geometry
    }
    pub const fn root_hash(&self) -> ContentDigest {
        self.root_hash
    }
    pub const fn salt(&self) -> &[u8; 32] {
        &self.salt
    }
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.manifest
    }

    /// Retain both complete streams and their parameter manifest. Source build
    /// receipts/tree provenance must be retained separately by their generation.
    pub fn publish_root(
        &self,
        root: &RootName,
        cancellation: &Cancellation,
    ) -> Result<RootPublicationState, ImageBuildError> {
        check(cancellation)?;
        Ok(self
            .lease
            .publish_root_checked(root, &self.references, || {
                cancellation
                    .check()
                    .map_err(|_| crate::cancellation::cancellation_io())
            })?)
    }
}

#[derive(Serialize)]
struct Manifest {
    version: u8,
    algorithm: &'static str,
    data_block_bytes: u32,
    hash_block_bytes: u32,
    hash_start_block: u64,
    superblock: bool,
    data_manifest_sha256: String,
    data_sha256: String,
    data_bytes: u64,
    hash_manifest_sha256: String,
    hash_sha256: String,
    hash_bytes: u64,
    root_hash: String,
    salt: String,
}

/// Build dm-verity v1 SHA-256/4 KiB parameters and a separate headerless hash
/// device. An explicit salt makes this operation deterministic. Input and
/// scratch levels remain in authenticated chunks; no host utility, local image
/// file, device, mount or lookup is used. Published parameters use hash offset 0.
///
/// The combined data/hash streams must fit output bytes; intermediate levels
/// consume scratch bytes. A conservative root-reference bound is checked before
/// reading data. At least 32 MiB memory is required for bounded CAS transport
/// and metadata. The executor still owns process/CPU/descriptor enforcement.
/// Cancellation and duration are checked between bounded I/O calls; kernel I/O
/// and consumer transports must themselves have bounded blocked-I/O behavior.
pub fn build_verity(
    store: &Store,
    data: &RetainedChunkedArtifact,
    salt: [u8; 32],
    budget: &AdmittedBudget,
    cancellation: &Cancellation,
) -> Result<BuiltVerity, ImageBuildError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(u64::from(
            budget.request().duration_seconds,
        )))
        .ok_or(ImageBuildError::Input(
            "verity deadline overflows the clock",
        ))?;
    check_time(cancellation, deadline)?;
    if !data.object_lease().same_store(store)? {
        return Err(ImageBuildError::Input(
            "verity data belongs to another Store",
        ));
    }
    let geometry = Geometry::new(data.manifest().size())?;
    if data
        .manifest()
        .size()
        .checked_add(geometry.hash_bytes())
        .is_none_or(|bytes| bytes > budget.request().output_bytes)
    {
        return Err(ImageBuildError::Input(
            "verity data and hashes exceed output budget",
        ));
    }
    if geometry.hash_bytes() > budget.request().scratch_bytes {
        return Err(ImageBuildError::Input(
            "verity intermediate levels exceed scratch budget",
        ));
    }
    if budget.request().memory_bytes < 32 * 1024 * 1024 {
        return Err(ImageBuildError::Input(
            "verity chunk transport requires at least 32 MiB memory",
        ));
    }
    let references = data.retained_references();
    let hash_chunks = geometry.hash_bytes().div_ceil(CHUNK_BYTES as u64);
    if references.len() as u64 + hash_chunks + 2 > crate::store::MAX_ROOT_REFERENCES {
        return Err(ImageBuildError::Input(
            "verity pair exceeds retention reference budget",
        ));
    }
    let operation = store.operation()?;
    let mut levels: Vec<RetainedChunkedArtifact> = Vec::new();
    let mut root_hash = None;
    // Single-block data has no stored hash levels, but still needs its salted
    // root and complete source identity independently checked.
    let expected_levels: Vec<u64> = if geometry.level_blocks().is_empty() {
        vec![0]
    } else {
        geometry.level_blocks().to_vec()
    };
    for blocks in expected_levels {
        check_time(cancellation, deadline)?;
        let input = levels.last().unwrap_or(data);
        let mut reader = input.open_reader(cancellation);
        let mut staging = operation.begin_chunked(
            blocks * crate::system::verity::BLOCK_BYTES as u64,
            cancellation,
        )?;
        let written = write_level(
            &mut reader,
            input.manifest().size(),
            *input.manifest().content_digest().as_bytes(),
            &salt,
            &mut staging,
            || cancellation.is_cancelled() || Instant::now() >= deadline,
        )
        .map_err(|error| match error {
            VerityError::Cancelled => check_time(cancellation, deadline)
                .err()
                .unwrap_or(ImageBuildError::Cancelled),
            error => ImageBuildError::Verity(error),
        })?;
        if written.blocks != blocks {
            return Err(ImageBuildError::Input(
                "verity level geometry disagrees",
            ));
        }
        root_hash = written.root_hash;
        drop(reader);
        levels.push(staging.finish(ContentDigest::from_sha256_hash(written.sha256))?);
    }
    let root_hash = ContentDigest::from_sha256_hash(root_hash.ok_or(ImageBuildError::Input(
        "verity tree lacks a root hash",
    ))?);
    let mut staging = operation.begin_chunked(geometry.hash_bytes(), cancellation)?;
    let mut content = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    for level in levels.iter().rev() {
        let mut reader = level.open_reader(cancellation);
        loop {
            check_time(cancellation, deadline)?;
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            staging.append(&buffer[..count])?;
            content.update(&buffer[..count]);
        }
    }
    if staging.size() != geometry.hash_bytes() {
        return Err(ImageBuildError::Input(
            "verity tree length disagrees",
        ));
    }
    check_time(cancellation, deadline)?;
    let hashes = staging.finish(ContentDigest::from_sha256_hash(
        content.finalize().into(),
    ))?;
    let metadata = Manifest {
        version: 1,
        algorithm: "sha256",
        data_block_bytes: 4096,
        hash_block_bytes: 4096,
        hash_start_block: 0,
        superblock: false,
        data_manifest_sha256: data.manifest_digest().to_string(),
        data_sha256: data.manifest().content_digest().to_string(),
        data_bytes: geometry.data_bytes(),
        hash_manifest_sha256: hashes.manifest_digest().to_string(),
        hash_sha256: hashes.manifest().content_digest().to_string(),
        hash_bytes: geometry.hash_bytes(),
        root_hash: root_hash.to_string(),
        salt: ContentDigest::from_sha256_hash(salt).to_string(),
    };
    let mut bytes = b"syrox-verity-image-v1\n".to_vec();
    serde_json::to_writer(&mut bytes, &metadata).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let manifest = ContentDigest::sha256(&bytes);
    check_time(cancellation, deadline)?;
    operation.ingest(bytes.as_slice(), manifest, 16 * 1024)?;
    let references: Vec<_> = references
        .into_iter()
        .chain(hashes.retained_references())
        .chain([manifest])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let lease = operation.retain_objects(&references, &[])?;
    Ok(BuiltVerity {
        data: data.clone(),
        hashes,
        geometry,
        root_hash,
        salt,
        manifest,
        references,
        lease,
    })
}

fn check_time(cancellation: &Cancellation, deadline: Instant) -> Result<(), ImageBuildError> {
    check(cancellation)?;
    if Instant::now() >= deadline {
        Err(ImageBuildError::Deadline)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;

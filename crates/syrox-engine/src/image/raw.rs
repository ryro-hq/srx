use super::{ImageBuildError, check};
use crate::{
    cancellation::Cancellation,
    store::{
        ContentDigest, ObjectLease, RootName, RootPublicationState, Store,
        chunked::{CHUNK_BYTES, MAX_ARTIFACT_BYTES, RetainedChunkedArtifact},
    },
    system::{
        budget::AdmittedBudget,
        disk::{DiskError, DiskLayout, DiskSpec, PartitionReader},
    },
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read},
    time::{Duration, Instant},
};

/// Bind an already authenticated stream to one explicit GPT entry number.
#[derive(Clone, Debug)]
pub struct PartitionImage {
    pub number: u32,
    pub image: RetainedChunkedArtifact,
}

/// Complete RAW stream, validated geometry and input-content provenance.
/// Source tree/build receipts and authorized generation signatures remain the
/// generation's responsibility; this handle confers no installation authority.
#[derive(Clone, Debug)]
pub struct BuiltRaw {
    image: RetainedChunkedArtifact,
    layout: DiskLayout,
    manifest: ContentDigest,
    references: Vec<ContentDigest>,
    lease: ObjectLease,
}
impl BuiltRaw {
    pub const fn image(&self) -> &RetainedChunkedArtifact {
        &self.image
    }
    pub const fn layout(&self) -> &DiskLayout {
        &self.layout
    }
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.manifest
    }
    pub(super) fn retained_references(&self) -> &[ContentDigest] {
        &self.references
    }
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
struct SourceManifest {
    number: u32,
    chunk_manifest_sha256: String,
    content_sha256: String,
    bytes: u64,
}
#[derive(Serialize)]
struct Manifest<'a> {
    version: u8,
    format: &'static str,
    specification: &'a DiskSpec,
    image_sha256: String,
    image_manifest_sha256: String,
    image_bytes: u64,
    partitions: Vec<SourceManifest>,
}

/// Compose authenticated partition streams directly into CAS chunks. Every
/// binding must match the validated layout's length/hash and the same Store.
/// Preflight the complete logical disk, a conservative retention closure and
/// at least 32 MiB for bounded chunk transport/metadata before staging any data.
/// The shared writer checks file/output/memory/duration limits. Process resource
/// enforcement and bounded blocked I/O remain executor/transport responsibilities.
pub fn build_raw(
    store: &Store,
    layout: &DiskLayout,
    partitions: &[PartitionImage],
    budget: &AdmittedBudget,
    cancellation: &Cancellation,
) -> Result<BuiltRaw, ImageBuildError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(u64::from(
            budget.request().duration_seconds,
        )))
        .ok_or(ImageBuildError::Deadline)?;
    check_time(cancellation, deadline)?;
    let specification = layout.specification();
    if specification.bytes > budget.request().output_bytes
        || specification.bytes > MAX_ARTIFACT_BYTES
    {
        return Err(ImageBuildError::Input(
            "RAW disk exceeds output or artifact size budget",
        ));
    }
    if budget.request().memory_bytes < 32 * 1024 * 1024 {
        return Err(ImageBuildError::Input(
            "RAW chunk transport requires at least 32 MiB memory",
        ));
    }
    if partitions.len() != specification.partitions.len() {
        return Err(ImageBuildError::Input(
            "RAW partition bindings do not match the layout",
        ));
    }
    let mut inputs = BTreeMap::new();
    let mut references = BTreeSet::new();
    let output_references = specification.bytes.div_ceil(CHUNK_BYTES as u64) + 2;
    for input in partitions {
        check_time(cancellation, deadline)?;
        if inputs
            .insert(input.number, &input.image)
            .is_some()
        {
            return Err(ImageBuildError::Input(
                "duplicate RAW partition binding",
            ));
        }
        if !input.image.object_lease().same_store(store)? {
            return Err(ImageBuildError::Input(
                "RAW input belongs to another Store",
            ));
        }
        for reference in input.image.retained_references() {
            references.insert(reference);
            if references.len() as u64 + output_references > crate::store::MAX_ROOT_REFERENCES {
                return Err(ImageBuildError::Input(
                    "RAW image exceeds retention reference budget",
                ));
            }
        }
    }
    let mut sources_manifest = Vec::with_capacity(partitions.len());
    for partition in &specification.partitions {
        let input = inputs
            .get(&partition.number)
            .ok_or(ImageBuildError::Input(
                "RAW partition image is missing",
            ))?;
        if input.manifest().size() != partition.image_bytes
            || input.manifest().content_digest().as_bytes() != &partition.image_sha256
        {
            return Err(ImageBuildError::Input(
                "RAW partition image identity disagrees with layout",
            ));
        }
        sources_manifest.push(SourceManifest {
            number: partition.number,
            chunk_manifest_sha256: input.manifest_digest().to_string(),
            content_sha256: input.manifest().content_digest().to_string(),
            bytes: input.manifest().size(),
        });
    }
    if references.len() as u64 + output_references > crate::store::MAX_ROOT_REFERENCES {
        return Err(ImageBuildError::Input(
            "RAW image exceeds retention reference budget",
        ));
    }
    let operation = store.operation()?;
    let mut staging = operation.begin_chunked(specification.bytes, cancellation)?;
    let mut sources = Sources {
        inputs,
        cancellation,
    };
    let written = layout
        .write_raw(&mut sources, &mut staging, budget, || {
            cancellation.is_cancelled()
        })
        .map_err(|error| match error {
            _ if cancellation.is_cancelled() => ImageBuildError::Cancelled,
            DiskError::Deadline => ImageBuildError::Deadline,
            error => error.into(),
        })?;
    drop(sources);
    check_time(cancellation, deadline)?;
    if written.bytes != specification.bytes || staging.size() != written.bytes {
        return Err(ImageBuildError::Input(
            "RAW writer length disagrees with staged bytes",
        ));
    }
    let image = staging.finish(ContentDigest::from_sha256_hash(written.sha256))?;
    let metadata = Manifest {
        version: 1,
        format: "gpt",
        specification,
        image_sha256: image.manifest().content_digest().to_string(),
        image_manifest_sha256: image.manifest_digest().to_string(),
        image_bytes: written.bytes,
        partitions: sources_manifest,
    };
    let mut bytes = b"syrox-raw-image-v1\n".to_vec();
    serde_json::to_writer(&mut bytes, &metadata).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let manifest = ContentDigest::sha256(&bytes);
    check_time(cancellation, deadline)?;
    operation.ingest(bytes.as_slice(), manifest, 1024 * 1024)?;
    references.extend(image.retained_references());
    references.insert(manifest);
    let references: Vec<_> = references.into_iter().collect();
    let lease = operation.retain_objects(&references, &[])?;
    Ok(BuiltRaw {
        image,
        layout: layout.clone(),
        manifest,
        references,
        lease,
    })
}

struct Sources<'a> {
    inputs: BTreeMap<u32, &'a RetainedChunkedArtifact>,
    cancellation: &'a Cancellation,
}
impl PartitionReader for Sources<'_> {
    fn open_partition(&mut self, number: u32) -> io::Result<Box<dyn Read + '_>> {
        let image = self
            .inputs
            .get(&number)
            .ok_or(io::ErrorKind::NotFound)?;
        Ok(Box::new(image.open_reader(self.cancellation)))
    }
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

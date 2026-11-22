use super::{BuiltRaw, ImageBuildError, check};
use crate::{
    cancellation::Cancellation,
    store::{
        ContentDigest, ObjectLease, RootName, RootPublicationState, Store,
        chunked::{CHUNK_BYTES, MAX_ARTIFACT_BYTES, RetainedChunkedArtifact},
    },
    system::{
        budget::AdmittedBudget,
        qcow2::{CLUSTER_BYTES, Geometry, QcowError},
    },
};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    io,
    time::{Duration, Instant},
};
use syrox_encoding::formats;

/// Standalone qcow2 plus the complete supplied RAW/GPT provenance closure.
/// No boot, installation or signing authority follows from this handle.
#[derive(Clone, Debug)]
pub struct BuiltQcow2 {
    raw: BuiltRaw,
    image: RetainedChunkedArtifact,
    geometry: Geometry,
    manifest: ContentDigest,
    references: Vec<ContentDigest>,
    lease: ObjectLease,
}
impl BuiltQcow2 {
    pub const fn raw(&self) -> &BuiltRaw {
        &self.raw
    }
    pub const fn image(&self) -> &RetainedChunkedArtifact {
        &self.image
    }
    pub const fn geometry(&self) -> &Geometry {
        &self.geometry
    }
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.manifest
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
struct Manifest {
    format: &'static str,
    qcow2_version: u8,
    cluster_bytes: u64,
    refcount_bits: u8,
    raw_provenance_sha256: String,
    raw_manifest_sha256: String,
    raw_sha256: String,
    virtual_bytes: u64,
    image_manifest_sha256: String,
    image_sha256: String,
    image_bytes: u64,
}

/// Convert an engine-built RAW/GPT image directly into authenticated qcow2
/// chunks, retaining its complete supplied provenance and partition streams.
/// No utility, host temporary image, backing path or external data is used.
/// The complete encoded qcow2 length consumes output bytes. Preflight 32 MiB
/// for bounded CAS transport/metadata and a conservative complete root closure.
/// Cooperative deadline/cancellation checks do not bound blocked kernel I/O or
/// enforce the executor's process/CPU/descriptor resource envelope.
pub fn build_qcow2(
    store: &Store,
    raw: &BuiltRaw,
    budget: &AdmittedBudget,
    cancellation: &Cancellation,
) -> Result<BuiltQcow2, ImageBuildError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(u64::from(
            budget.request().duration_seconds,
        )))
        .ok_or(ImageBuildError::Deadline)?;
    check_time(cancellation, deadline)?;
    if !raw.image().object_lease().same_store(store)? {
        return Err(ImageBuildError::Input(
            "qcow2 RAW image belongs to another Store",
        ));
    }
    let geometry = Geometry::new(raw.image().manifest().size())?;
    if geometry.encoded_bytes() > budget.request().output_bytes
        || geometry.encoded_bytes() > MAX_ARTIFACT_BYTES
    {
        return Err(ImageBuildError::Input(
            "qcow2 exceeds output or artifact byte limit",
        ));
    }
    if budget.request().memory_bytes < 32 * 1024 * 1024 {
        return Err(ImageBuildError::Input(
            "qcow2 chunk transport requires at least 32 MiB memory",
        ));
    }
    if raw.retained_references().len() as u64
        + geometry
            .encoded_bytes()
            .div_ceil(CHUNK_BYTES as u64)
        + 2
        > crate::store::MAX_ROOT_REFERENCES
    {
        return Err(ImageBuildError::Input(
            "qcow2 exceeds retention reference budget",
        ));
    }
    let operation = store.operation()?;
    let mut staging = operation.begin_chunked(geometry.encoded_bytes(), cancellation)?;
    let written = geometry
        .write(
            &mut raw.image().open_reader(cancellation),
            *raw.image().manifest().content_digest().as_bytes(),
            &mut staging,
            budget,
            || cancellation.is_cancelled(),
        )
        .map_err(|error| match error {
            _ if cancellation.is_cancelled() => ImageBuildError::Cancelled,
            QcowError::Deadline => ImageBuildError::Deadline,
            error => error.into(),
        })?;
    check_time(cancellation, deadline)?;
    if staging.size() != written.bytes || written.bytes != geometry.encoded_bytes() {
        return Err(ImageBuildError::Input(
            "qcow2 writer length disagrees with staged bytes",
        ));
    }
    let image = staging.finish(ContentDigest::from_sha256_hash(written.sha256))?;
    let metadata = Manifest {
        format: "qcow2",
        qcow2_version: 3,
        cluster_bytes: CLUSTER_BYTES,
        refcount_bits: 16,
        raw_provenance_sha256: raw.manifest_digest().to_string(),
        raw_manifest_sha256: raw.image().manifest_digest().to_string(),
        raw_sha256: raw
            .image()
            .manifest()
            .content_digest()
            .to_string(),
        virtual_bytes: geometry.virtual_bytes(),
        image_manifest_sha256: image.manifest_digest().to_string(),
        image_sha256: image.manifest().content_digest().to_string(),
        image_bytes: written.bytes,
    };
    let mut bytes = formats::QCOW2_IMAGE_LINE.as_bytes().to_vec();
    serde_json::to_writer(&mut bytes, &metadata).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let manifest = ContentDigest::sha256(&bytes);
    check_time(cancellation, deadline)?;
    operation.ingest(bytes.as_slice(), manifest, 16 * 1024)?;
    let references: Vec<_> = raw
        .retained_references()
        .iter()
        .copied()
        .chain(image.retained_references())
        .chain([manifest])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let lease = operation.retain_objects(&references, &[])?;
    Ok(BuiltQcow2 {
        raw: raw.clone(),
        image,
        geometry,
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

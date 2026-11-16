//! Compose images from authenticated package artifacts, never ambient host files.
//!
//! Writers emit initramfs, dm-verity hash devices, GPT RAW disks and standalone qcow2.
//! This module does not install images, execute contents or sign boot artifacts.

use crate::{
    cancellation::Cancellation,
    result::{MaterializedArtifact, OutputOrigin, artifact::IndexedArtifact},
    store::{
        ContentDigest, ObjectLease, RootName, RootPublicationState, Store, StoreError,
        chunked::{ChunkedArtifactError, MAX_ARTIFACT_BYTES, RetainedChunkedArtifact},
    },
    system::{
        budget::AdmittedBudget,
        image::{ArchiveError, ComponentReader, FileSource, SystemTree},
    },
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read},
};

mod verity;
pub use verity::{BuiltVerity, build_verity};
mod raw;
pub use raw::{BuiltRaw, PartitionImage, build_raw};
mod qcow2;
pub use qcow2::{BuiltQcow2, build_qcow2};

const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ImageBuildError {
    #[error("image construction cancelled")]
    Cancelled,
    #[error("image construction deadline elapsed")]
    Deadline,
    #[error("invalid image input: {0}")]
    Input(&'static str),
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error(transparent)]
    Verity(#[from] crate::system::verity::VerityError),
    #[error(transparent)]
    Disk(#[from] crate::system::disk::DiskError),
    #[error(transparent)]
    Qcow2(#[from] crate::system::qcow2::QcowError),
    #[error(transparent)]
    Chunked(#[from] ChunkedArtifactError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("image staging failed: {0}")]
    Io(#[from] io::Error),
}

/// Image plus complete tree/component provenance in the same Store interest.
/// Dropping this handle ends only live retention. A published root persists.
#[derive(Clone, Debug)]
pub struct BuiltInitramfs {
    archive: RetainedChunkedArtifact,
    manifest: ContentDigest,
    tree: ContentDigest,
    lease: ObjectLease,
    references: Vec<ContentDigest>,
}

impl BuiltInitramfs {
    pub const fn archive(&self) -> &RetainedChunkedArtifact {
        &self.archive
    }
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.manifest
    }
    pub const fn tree_manifest_digest(&self) -> ContentDigest {
        self.tree
    }

    /// Retain archive chunks, the complete tree, provenance manifest and source
    /// result closures atomically under the existing immutable root protocol.
    pub fn publish_root(
        &self,
        name: &RootName,
        cancellation: &Cancellation,
    ) -> Result<RootPublicationState, ImageBuildError> {
        check(cancellation)?;
        Ok(self
            .lease
            .publish_root_checked(name, &self.references, || {
                cancellation
                    .check()
                    .map_err(|_| crate::cancellation::cancellation_io())
            })?)
    }
}

#[derive(Debug, Serialize)]
struct ImageManifest {
    format: &'static str,
    tree_sha256: String,
    tree_manifest_sha256: String,
    content_sha256: String,
    chunk_manifest_sha256: String,
    bytes: u64,
    components: Vec<ComponentProvenance>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct ComponentProvenance {
    action_sha256: String,
    artifact_sha256: String,
    output: String,
    origin: ComponentOrigin,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ComponentOrigin {
    Built {
        receipt_sha256: String,
    },
    Imported {
        manifest_sha256: String,
    },
}

/// Build from live authenticated outputs. No temporary image file, package
/// discovery, executable lookup, or host content fallback is used.
///
/// Output streams to bounded chunked staging. Its complete hash is verified
/// before publishing the chunk manifest; image provenance is published last. No durable consumer
/// root is created until `BuiltInitramfs::publish_root` is explicitly called.
pub fn build_initramfs(
    store: &Store,
    tree: &SystemTree,
    outputs: &[&MaterializedArtifact],
    budget: &AdmittedBudget,
    cancellation: &Cancellation,
) -> Result<BuiltInitramfs, ImageBuildError> {
    check(cancellation)?;
    if budget.request().output_bytes > MAX_ARTIFACT_BYTES {
        return Err(ImageBuildError::Input(
            "image budget exceeds chunked format cap",
        ));
    }
    let mut sources = PackageComponents::new(store, outputs, cancellation)?;
    for entry in tree.entries().values() {
        if entry
            .origins
            .iter()
            .any(|pin| !sources.outputs.contains_key(pin))
        {
            return Err(ImageBuildError::Input(
                "tree names an unselected component artifact",
            ));
        }
    }
    let mut references = BTreeSet::new();
    let mut provenance = BTreeSet::new();
    for output in outputs {
        references.extend(output.retained_references().iter().copied());
        let identity = output.identity();
        provenance.insert(ComponentProvenance {
            action_sha256: identity.action.to_string(),
            artifact_sha256: identity.artifact.to_string(),
            output: identity.output.clone(),
            origin: match identity.origin {
                OutputOrigin::Built {
                    receipt,
                } => ComponentOrigin::Built {
                    receipt_sha256: receipt.to_string(),
                },
                OutputOrigin::Imported {
                    manifest,
                } => ComponentOrigin::Imported {
                    manifest_sha256: manifest.to_string(),
                },
            },
        });
    }
    let tree_bytes = tree.canonical_bytes();
    if tree_bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(ImageBuildError::Input(
            "tree metadata exceeds byte limit",
        ));
    }
    let tree_manifest = ContentDigest::sha256(&tree_bytes);
    check(cancellation)?;
    let operation = store.operation()?;
    let mut staging = operation.begin_chunked(budget.request().output_bytes, cancellation)?;
    let written = tree
        .write_initramfs(&mut sources, &mut staging, budget, || {
            cancellation.is_cancelled()
        })
        .map_err(|error| {
            if cancellation.is_cancelled() {
                ImageBuildError::Cancelled
            } else {
                error.into()
            }
        })?;
    // Release the verified package descriptor as soon as its bytes are consumed.
    drop(sources);
    check(cancellation)?;
    if staging.size() != written.bytes {
        return Err(ImageBuildError::Input(
            "archive writer length disagrees with staged bytes",
        ));
    }
    let archive = staging.finish(ContentDigest::from_sha256_hash(written.sha256))?;
    let manifest = ImageManifest {
        format: "syrox-initramfs-v1",
        tree_sha256: ContentDigest::from_sha256_hash(written.tree_sha256).to_string(),
        tree_manifest_sha256: tree_manifest.to_string(),
        content_sha256: archive.manifest().content_digest().to_string(),
        chunk_manifest_sha256: archive.manifest_digest().to_string(),
        bytes: written.bytes,
        components: provenance.into_iter().collect(),
    };
    let mut manifest_bytes = b"syrox-system-image-v1\n".to_vec();
    serde_json::to_writer(&mut manifest_bytes, &manifest).map_err(io::Error::other)?;
    manifest_bytes.push(b'\n');
    if manifest_bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(ImageBuildError::Input(
            "image provenance exceeds byte limit",
        ));
    }
    let manifest_digest = ContentDigest::sha256(&manifest_bytes);
    references.extend(archive.retained_references());
    references.extend([tree_manifest, manifest_digest]);
    if references.len() as u64 > crate::store::MAX_ROOT_REFERENCES {
        return Err(ImageBuildError::Input(
            "image closure exceeds Store root reference limit",
        ));
    }
    check(cancellation)?;
    operation.ingest(
        tree_bytes.as_slice(),
        tree_manifest,
        MAX_METADATA_BYTES,
    )?;
    // Complete publication and retention without hiding a published manifest
    // behind a subsequent cancellation observation.
    operation.ingest(
        manifest_bytes.as_slice(),
        manifest_digest,
        MAX_METADATA_BYTES,
    )?;
    let references: Vec<_> = references.into_iter().collect();
    let lease = operation.retain_objects(&references, &[])?;
    Ok(BuiltInitramfs {
        archive,
        manifest: manifest_digest,
        tree: tree_manifest,
        lease,
        references,
    })
}

struct PackageComponents<'a> {
    outputs: BTreeMap<String, &'a MaterializedArtifact>,
    current: Option<(
        String,
        IndexedArtifact<crate::result::ArtifactReader>,
    )>,
    cancellation: &'a Cancellation,
}

impl<'a> PackageComponents<'a> {
    fn new(
        store: &Store,
        outputs: &[&'a MaterializedArtifact],
        cancellation: &'a Cancellation,
    ) -> Result<Self, ImageBuildError> {
        let mut selected = BTreeMap::new();
        for output in outputs {
            check(cancellation)?;
            if !output.object_lease().same_store(store)? {
                return Err(ImageBuildError::Input(
                    "component belongs to another Store",
                ));
            }
            selected.insert(output.artifact().to_string(), *output);
        }
        Ok(Self {
            outputs: selected,
            current: None,
            cancellation,
        })
    }
}

impl ComponentReader for PackageComponents<'_> {
    fn open_file(&mut self, source: &FileSource) -> io::Result<Box<dyn Read + '_>> {
        if self.cancellation.is_cancelled() {
            return Err(crate::cancellation::cancellation_io());
        }
        if self
            .current
            .as_ref()
            .is_none_or(|(pin, _)| pin != &source.component)
        {
            self.current = None;
            let output = self
                .outputs
                .get(&source.component)
                .ok_or_else(|| io::Error::other("unselected component artifact"))?;
            let input = output
                .open_artifact(self.cancellation)
                .map_err(io::Error::other)?;
            let indexed = IndexedArtifact::open_with_limits(
                input,
                "",
                output.artifact_limits(),
                self.cancellation,
            )
            .map_err(io::Error::other)?;
            self.current = Some((source.component.clone(), indexed));
        }
        let (_, indexed) = self.current.as_mut().expect("selected component");
        let (index, input) = indexed.parts();
        let file = index
            .find(&source.path)
            .ok_or_else(|| io::Error::other("component file is missing"))?;
        if file.size != source.size_bytes {
            return Err(io::Error::other(
                "component file length differs from declaration",
            ));
        }
        Ok(Box::new(IndexedArtifact::reader_from(
            input, &file,
        )?))
    }
}

fn check(cancellation: &Cancellation) -> Result<(), ImageBuildError> {
    cancellation
        .check()
        .map_err(|_| ImageBuildError::Cancelled)
}

#[cfg(test)]
mod tests;

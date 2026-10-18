//! Explicitly pinned local artifact authority, independent of mutable indexes.
//! Recipe origin and the complete selected program must match before import.
use crate::{
    cancellation::Cancellation,
    plan::{PlanOutputRef, PlanPackageId},
    project::PreparedPlan,
    result::ResultManifest,
    store::ContentDigest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

mod authorize;
mod selection;
pub use authorize::authorize_artifacts;
pub(crate) use selection::ArtifactSelection;
#[cfg(test)]
mod tests;

const MAX_DESCRIPTOR: u64 = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("artifact authorization refused: {0}")]
    Invalid(String),
    #[error("required authorized artifact is unavailable for {0}")]
    Missing(String),
    #[error("artifact operation cancelled")]
    Cancelled,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Catalog(#[from] super::CatalogError),
    #[error(transparent)]
    Project(#[from] crate::project::ProjectOperationError),
    #[error(transparent)]
    Result(#[from] crate::result::ResultError),
    #[error(transparent)]
    Bundle(#[from] crate::bundle::BundleError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
}
fn invalid(message: impl Into<String>) -> ArtifactError {
    ArtifactError::Invalid(message.into())
}
fn check(cancel: &Cancellation) -> Result<(), ArtifactError> {
    cancel
        .check()
        .map_err(|_| ArtifactError::Cancelled)
}
fn pin(text: &str) -> Result<ContentDigest, ArtifactError> {
    text.parse()
        .map_err(|_| invalid("invalid digest"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptor {
    schema: u32,
    catalog_lock_sha256: String,
    project_lock_sha256: String,
    release_sha256: String,
    entries: Vec<ArtifactEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEntry {
    locked: super::LockedVersion,
    recipe_sha256: String,
    bundle: String,
    bundle_sha256: String,
    manifest_sha256: String,
    manifest: ResultManifest,
    toolchain: String,
    outputs: Vec<ArtifactOutput>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactOutput {
    recipe_sha256: String,
    output: String,
    key: String,
}

impl ArtifactDescriptor {
    pub fn encode(&self) -> Result<Vec<u8>, ArtifactError> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| invalid(e.to_string()))?;
        if bytes.len() as u64 > MAX_DESCRIPTOR {
            return Err(invalid("descriptor exceeds byte limit"));
        }
        Ok(bytes)
    }
    fn validate(&self) -> Result<(), ArtifactError> {
        if self.schema != 1
            || self.entries.is_empty()
            || self.entries.len() > super::model::MAX_ENTRIES
        {
            return Err(invalid("descriptor schema or entry limit"));
        }
        for value in [
            &self.catalog_lock_sha256,
            &self.project_lock_sha256,
            &self.release_sha256,
        ] {
            pin(value)?;
        }
        let mut identities = std::collections::BTreeSet::new();
        for entry in &self.entries {
            if !identities.insert(&entry.locked.identity)
                || entry.outputs.is_empty()
                || entry.outputs.len() > crate::result::MAX_RESULT_OUTPUTS
            {
                return Err(invalid(
                    "duplicate artifact identity or output limit",
                ));
            }
            let identity = serde_json::to_vec(&(&entry.locked.package, &entry.locked.inputs))
                .map_err(|e| invalid(e.to_string()))?;
            if ContentDigest::sha256(&identity) != pin(&entry.locked.identity)? {
                return Err(invalid(
                    "catalog identity does not match its inputs",
                ));
            }
            for value in [
                &entry.recipe_sha256,
                &entry.bundle_sha256,
                &entry.toolchain,
            ] {
                pin(value)?;
            }
            if entry.manifest.digest()? != pin(&entry.manifest_sha256)? {
                return Err(invalid("result manifest changed"));
            }
            if !super::files::component(&entry.bundle) {
                return Err(invalid("bundle must be a relative filename"));
            }
            let mut keys = std::collections::BTreeSet::new();
            for output in &entry.outputs {
                pin(&output.recipe_sha256)?;
                if !keys.insert(&output.key)
                    || entry
                        .manifest
                        .outputs()
                        .get(&output.key)
                        .is_none_or(|item| item.output != output.output)
                {
                    return Err(invalid(
                        "artifact output mapping differs from manifest",
                    ));
                }
            }
            if keys.len() != entry.manifest.outputs().len() {
                return Err(invalid("unmapped closure output"));
            }
            let command = entry
                .manifest
                .commands()
                .get(&entry.locked.package.name)
                .ok_or_else(|| invalid("authorized package command is absent"))?;
            if entry.manifest.commands().len() != 1
                || !entry.outputs.iter().any(|output| {
                    output.key == command.application && output.recipe_sha256 == entry.recipe_sha256
                })
            {
                return Err(invalid(
                    "authorized application does not belong to the selected recipe",
                ));
            }
        }
        Ok(())
    }
}

fn open_file(path: &Path) -> Result<File, ArtifactError> {
    let opened = crate::platform::linux::fd::open_top(path).map_err(|error| match error {
        crate::platform::linux::fd::OpenError::Other(error)
        | crate::platform::linux::fd::OpenError::Unsupported(error) => ArtifactError::Io(error),
        crate::platform::linux::fd::OpenError::Symlink => {
            invalid("artifact path contains a symlink")
        }
    })?;
    let file = opened.into_file();
    if !file.metadata()?.is_file() {
        return Err(invalid("artifact input must be a regular file"));
    }
    Ok(file)
}
fn read_file(path: &Path, maximum: u64) -> Result<Vec<u8>, ArtifactError> {
    let mut bytes = Vec::new();
    open_file(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid("artifact input exceeds byte limit"));
    }
    Ok(bytes)
}
fn verify_bundle(
    path: &Path,
    expected: ContentDigest,
    cancel: &Cancellation,
) -> Result<File, ArtifactError> {
    let mut file = open_file(path)?;
    if file.metadata()?.len() > crate::bundle::MAX_BUNDLE_BYTES {
        return Err(invalid("bundle exceeds byte limit"));
    }
    let mut digest = Sha256::new();
    let mut bytes = vec![0; 64 * 1024];
    let mut total = 0_u64;
    loop {
        check(cancel)?;
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > crate::bundle::MAX_BUNDLE_BYTES {
            return Err(invalid("bundle grew beyond byte limit"));
        }
        digest.update(&bytes[..count]);
    }
    if ContentDigest::from_sha256_hash(digest.finalize().into()) != expected {
        return Err(invalid(
            "bundle content differs from authorized digest",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// The encoding excludes graph-local node names, but includes authenticated source
/// snapshots, sources, all build inputs, the full program and runtime commands.
fn fingerprints(prepared: &PreparedPlan) -> Result<BTreeMap<PlanPackageId, String>, ArtifactError> {
    fn node(
        prepared: &PreparedPlan,
        id: &PlanPackageId,
        done: &mut BTreeMap<PlanPackageId, String>,
        active: &mut std::collections::BTreeSet<PlanPackageId>,
    ) -> Result<String, ArtifactError> {
        if let Some(pin) = done.get(id) {
            return Ok(pin.clone());
        }
        if active.len() >= 256 || !active.insert(id.clone()) {
            return Err(invalid("artifact graph cycle or depth limit"));
        }
        let plan = prepared.plan();
        let package = plan
            .packages()
            .find(|item| item.id() == id)
            .ok_or_else(|| invalid("missing recipe node"))?;
        let owner = prepared
            .recipe_source_pin(package)
            .map(|pin| pin.to_string());
        let sources = plan
            .acquisitions()
            .filter(|item| item.package() == id)
            .flat_map(crate::plan::PlanAcquisition::sources)
            .map(|source| {
                serde_json::json!([
                    source.url(),
                    source.digest().to_string(),
                    source.maximum_bytes()
                ])
            })
            .collect::<Vec<_>>();
        let mut dependencies = package
            .dependencies()
            .map(|id| node(prepared, id, done, active))
            .collect::<Result<Vec<_>, _>>()?;
        dependencies.sort();
        let mut output = |reference: &PlanOutputRef| -> Result<serde_json::Value, ArtifactError> {
            let identity = if &reference.package == id {
                "self".to_owned()
            } else {
                node(prepared, &reference.package, done, active)?
            };
            Ok(serde_json::json!([identity, reference.output]))
        };
        let build = plan
            .builds()
            .find(|item| item.package() == id)
            .map(|build| {
                let inputs = build
                    .inputs()
                    .iter()
                    .map(&mut output)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, ArtifactError>(serde_json::json!([
                    build.source_directory(),
                    build.timeout_seconds(),
                    ContentDigest::sha256(&build.program().encode()).to_string(),
                    inputs
                ]))
            })
            .transpose()?;
        let commands = plan
            .commands()
            .filter(|command| command.package() == id)
            .map(|command| {
                let loader = command
                    .loader()
                    .map(|file| {
                        output(&file.output).map(|value| serde_json::json!([value, file.path]))
                    })
                    .transpose()?;
                let libraries = command
                    .libraries()
                    .map(&mut output)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, ArtifactError>(serde_json::json!([
                    command.name(),
                    command.output(),
                    command.path(),
                    loader,
                    libraries
                ]))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let imported = plan
            .imports()
            .find(|item| item.package() == id)
            .map(|item| {
                serde_json::json!([
                    item.manifest().to_string(),
                    item.outputs()
                ])
            });
        let value = serde_json::json!([
            "syrox-artifact-recipe-v1",
            owner,
            id.as_str(),
            sources,
            dependencies,
            build,
            commands,
            imported
        ]);
        let encoded = serde_json::to_vec(&value).map_err(|e| invalid(e.to_string()))?;
        let fingerprint = ContentDigest::sha256(&encoded).to_string();
        active.remove(id);
        done.insert(id.clone(), fingerprint.clone());
        Ok(fingerprint)
    }
    let mut done = BTreeMap::new();
    for package in prepared.plan().packages() {
        node(
            prepared,
            package.id(),
            &mut done,
            &mut std::collections::BTreeSet::new(),
        )?;
    }
    Ok(done)
}

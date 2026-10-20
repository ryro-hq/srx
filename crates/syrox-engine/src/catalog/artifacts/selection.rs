use super::*;
use crate::{
    config::{ArtifactConfiguration, ArtifactPolicy},
    result::AdmittedResult,
    store::{RootName, Store},
};
use std::path::PathBuf;

/// A pure selection: no Store, acquisition, worker or process is opened.
pub(crate) struct ArtifactSelection {
    policy: ArtifactPolicy,
    directory: PathBuf,
    descriptor: Option<ArtifactDescriptor>,
    fingerprints: BTreeMap<PlanPackageId, String>,
    authorized_roots: std::collections::BTreeSet<String>,
}
pub(crate) struct SelectedArtifact<'a> {
    selection: &'a ArtifactSelection,
    candidates: Vec<(&'a ArtifactEntry, BTreeMap<String, String>)>,
}
pub(crate) struct ImportedArtifact {
    pub admitted: AdmittedResult,
    pub outputs: BTreeMap<String, String>,
}
impl ArtifactSelection {
    pub(crate) fn resolve(
        prepared: &PreparedPlan,
        configuration: &ArtifactConfiguration,
    ) -> Result<Self, ArtifactError> {
        let mut selection = Self {
            policy: configuration.policy(),
            directory: PathBuf::new(),
            descriptor: None,
            fingerprints: BTreeMap::new(),
            authorized_roots: std::collections::BTreeSet::new(),
        };
        if selection.policy == ArtifactPolicy::Compile {
            return Ok(selection);
        }
        let (path, expected) = configuration
            .descriptor()
            .ok_or_else(|| invalid("missing descriptor pin"))?;
        let bytes = read_file(path, MAX_DESCRIPTOR)?;
        if ContentDigest::sha256(&bytes) != expected {
            return Err(invalid(
                "descriptor content differs from configured pin",
            ));
        }
        let descriptor: ArtifactDescriptor =
            serde_json::from_slice(&bytes).map_err(|e| invalid(e.to_string()))?;
        descriptor.validate()?;
        selection.fingerprints = fingerprints(prepared)?;
        for package in prepared.plan().packages() {
            if prepared
                .recipe_source_pin(package)
                .is_some_and(|pin| pin.to_string() == descriptor.project_lock_sha256)
            {
                selection
                    .authorized_roots
                    .insert(selection.fingerprints[package.id()].clone());
            }
        }
        // Several selected packages may share a libc or another runtime output.
        // Never choose one bundle's bytes arbitrarily when authorities disagree.
        let mut identities = BTreeMap::new();
        for entry in descriptor.entries.iter().filter(|entry| {
            selection
                .authorized_roots
                .contains(&entry.recipe_sha256)
        }) {
            for output in &entry.outputs {
                let value = &entry.manifest.outputs()[&output.key];
                let key = (&output.recipe_sha256, &output.output);
                if identities
                    .insert(key, value)
                    .is_some_and(|previous| previous != value)
                {
                    return Err(invalid(
                        "authorized bundles disagree about a shared runtime output",
                    ));
                }
            }
        }
        path.parent()
            .ok_or_else(|| invalid("descriptor has no directory"))?
            .clone_into(&mut selection.directory);
        selection.descriptor = Some(descriptor);
        Ok(selection)
    }
    pub(crate) fn select(
        &self,
        reference: &PlanOutputRef,
    ) -> Result<Option<SelectedArtifact<'_>>, ArtifactError> {
        let mut candidates = Vec::new();
        if let Some(descriptor) = &self.descriptor {
            let fingerprint = &self.fingerprints[&reference.package];
            for entry in &descriptor.entries {
                if !self
                    .authorized_roots
                    .contains(&entry.recipe_sha256)
                {
                    continue;
                }
                let mut outputs = BTreeMap::new();
                for output in entry
                    .outputs
                    .iter()
                    .filter(|output| &output.recipe_sha256 == fingerprint)
                {
                    if let Some(previous) =
                        outputs.insert(output.output.clone(), output.key.clone())
                        && entry.manifest.outputs()[&previous]
                            != entry.manifest.outputs()[&output.key]
                    {
                        return Err(invalid(
                            "one recipe output maps to contradictory artifacts",
                        ));
                    }
                }
                if outputs.contains_key(&reference.output) {
                    candidates.push((entry, outputs));
                }
            }
        }
        if !candidates.is_empty() {
            return Ok(Some(SelectedArtifact {
                selection: self,
                candidates,
            }));
        }
        if self.policy == ArtifactPolicy::Require {
            return Err(ArtifactError::Missing(format!(
                "{}:{}",
                reference.package, reference.output
            )));
        }
        Ok(None)
    }
}
impl SelectedArtifact<'_> {
    pub(crate) fn manifest_digest(&self) -> Result<ContentDigest, ArtifactError> {
        pin(&self.candidates[0].0.manifest_sha256)
    }
    pub(crate) fn import(
        &self,
        store: &Store,
        cancellation: &Cancellation,
    ) -> Result<Option<ImportedArtifact>, ArtifactError> {
        check(cancellation)?;
        // A shared library may be carried by several authorized applications.
        // Reuse any verified closure already present before opening transport.
        for (entry, outputs) in &self.candidates {
            let manifest = pin(&entry.manifest_sha256)?;
            let root = RootName::new(format!("artifact_{manifest}"))
                .map_err(|e| invalid(e.to_string()))?;
            if store
                .operation()?
                .build_references(&root)?
                .is_some()
            {
                return Ok(Some(ImportedArtifact {
                    admitted: AdmittedResult::open(store, &root, manifest, cancellation)?,
                    outputs: outputs.clone(),
                }));
            }
        }
        for (entry, outputs) in &self.candidates {
            let mut file = match verify_bundle(
                &self.selection.directory.join(&entry.bundle),
                pin(&entry.bundle_sha256)?,
                cancellation,
            ) {
                Err(ArtifactError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    continue;
                }
                other => other?,
            };
            let manifest = pin(&entry.manifest_sha256)?;
            let root = RootName::new(format!("artifact_{manifest}"))
                .map_err(|e| invalid(e.to_string()))?;
            return Ok(Some(ImportedArtifact {
                admitted: crate::bundle::import_bundle(
                    store,
                    &root,
                    manifest,
                    &mut file,
                    cancellation,
                )?,
                outputs: outputs.clone(),
            }));
        }
        if self.selection.policy == ArtifactPolicy::Require {
            return Err(ArtifactError::Missing(
                self.candidates[0].0.locked.identity.clone(),
            ));
        }
        Ok(None)
    }
}

use std::path::Path;
use std::time::Instant;

use super::installation::{
    CandidatePhase, GenerationInstallation, InstallationError, RetainedGeneration,
};
use crate::{
    cancellation::Cancellation, deployment::manifest::PreparedConsumer, store::ContentDigest,
    store::Store,
};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct OsGenerationError(String);
impl From<InstallationError> for OsGenerationError {
    fn from(error: InstallationError) -> Self {
        // JSON errors can quote persisted input, including configuration text.
        let message = match error {
            InstallationError::Encoding(_) | InstallationError::Generation(_) => {
                "invalid Os candidate description; evidence preserved".into()
            }
            error => error.to_string(),
        };
        Self(message)
    }
}

#[derive(Clone, Debug)]
pub struct OsGenerationSummary {
    pub pin: ContentDigest,
    pub outputs: usize,
    pub services: usize,
    pub commands: usize,
    pub processes: usize,
    pub configurations: usize,
}
impl From<&RetainedGeneration> for OsGenerationSummary {
    fn from(generation: &RetainedGeneration) -> Self {
        let manifest = generation.manifest();
        Self {
            pin: generation.digest(),
            outputs: generation.outputs().len(),
            services: manifest.services.len(),
            commands: generation.commands().len(),
            processes: manifest.processes.len(),
            configurations: manifest.configs.len(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OsCandidatePhase {
    Preparing,
    Prepared,
}
#[derive(Debug)]
pub struct OsCandidateEntry {
    pub pin: ContentDigest,
    pub phase: Result<OsCandidatePhase, String>,
}

/// Initialize metadata within an existing owned, mode-0700 directory.
pub fn initialize_os_installation(
    path: &Path,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsInstallation, OsGenerationError> {
    Ok(OsInstallation(
        GenerationInstallation::initialize(path, cancellation, deadline)?,
    ))
}

/// Pinned installation authority retained across package realization. Replacing
/// its pathname cannot redirect subsequent candidate publication.
#[derive(Debug)]
pub struct OsInstallation(GenerationInstallation);
impl OsInstallation {
    pub fn id(&self) -> &str {
        self.0.id()
    }
}

#[derive(Debug)]
pub struct OsPreparation<'a> {
    pub installation: &'a OsInstallation,
    pub store: &'a Store,
    pub launcher: &'a Path,
    pub launcher_digest: ContentDigest,
}

/// Persist an Os candidate, its roots, executable launcher snapshot and private
/// configuration. Prepared journal state describes retained candidate bytes;
/// an error while publishing derived files preserves that candidate for retry.
pub fn prepare_os_generation(
    prepared: PreparedConsumer,
    configuration: &OsPreparation<'_>,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsGenerationSummary, OsGenerationError> {
    let launcher = super::LauncherIdentity::new(configuration.launcher_digest, 1)
        .map_err(|error| OsGenerationError(error.to_string()))?;
    let generation = super::PreparedGeneration::freeze(prepared, launcher)
        .map_err(|error| OsGenerationError(error.to_string()))?;
    let retained = configuration.installation.0.prepare(
        &generation,
        configuration.store,
        configuration.launcher,
        cancellation,
        deadline,
    )?;
    configuration.installation.0.prepare_launcher(
        &retained,
        configuration.store,
        cancellation,
        deadline,
    )?;
    configuration
        .installation
        .0
        .prepare_configuration(&retained, cancellation, deadline)?;
    Ok(OsGenerationSummary::from(&retained))
}

/// List journal evidence only, without opening or creating a Store.
pub fn list_os_generations(
    path: &Path,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<Vec<OsCandidateEntry>, OsGenerationError> {
    let installation = GenerationInstallation::open_existing(path, cancellation, deadline)?;
    Ok(installation
        .list(cancellation, deadline)?
        .into_iter()
        .map(|entry| OsCandidateEntry {
            pin: entry.pin,
            phase: entry
                .phase
                .map(|phase| match phase {
                    CandidatePhase::Preparing => OsCandidatePhase::Preparing,
                    CandidatePhase::Prepared => OsCandidatePhase::Prepared,
                })
                .map_err(|_| "invalid candidate journal evidence".into()),
        })
        .collect())
}

pub fn inspect_os_generation(
    path: &Path,
    store: &Store,
    pin: ContentDigest,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsGenerationSummary, OsGenerationError> {
    let installation = GenerationInstallation::open_existing(path, cancellation, deadline)?;
    Ok(OsGenerationSummary::from(&installation.open(
        store,
        pin,
        cancellation,
        deadline,
    )?))
}

/// Verify both retained candidates before computing a pure operational diff.
pub fn diff_os_generations(
    path: &Path,
    store: &Store,
    previous: ContentDigest,
    candidate: ContentDigest,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<String, OsGenerationError> {
    let installation = GenerationInstallation::open_existing(path, cancellation, deadline)?;
    let previous = installation.open(store, previous, cancellation, deadline)?;
    let candidate = installation.open(store, candidate, cancellation, deadline)?;
    Ok(super::diff::diff_generations(previous.manifest(), candidate.manifest()).render())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;

    #[test]
    fn installation_replacement_during_realization_cannot_redirect_publication() {
        let (root, prepared) =
            crate::deployment::manifest::tests::prepared_service_payload_fixture_kind(
                &crate::runtime::tests::elf(2, None, &[], None, None),
                "",
                "Os",
            );
        let path = root.path().join("installation");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(10);
        let original = initialize_os_installation(&path, &cancel, deadline).unwrap();
        fs::rename(&path, root.path().join("original-installation")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement = initialize_os_installation(&path, &cancel, deadline).unwrap();
        assert_ne!(original.id(), replacement.id());
        let worker = root.path().join("launcher");
        fs::write(&worker, b"inert launcher").unwrap();
        let store = Store::open(&root.path().join("store")).unwrap();
        let result = prepare_os_generation(
            prepared,
            &OsPreparation {
                installation: &original,
                store: &store,
                launcher: &worker,
                launcher_digest: ContentDigest::sha256(b"inert launcher"),
            },
            &cancel,
            deadline,
        );
        assert!(result.is_err());
        assert!(
            list_os_generations(&path, &cancel, deadline)
                .unwrap()
                .is_empty()
        );
        assert!(
            list_os_generations(
                &root.path().join("original-installation"),
                &cancel,
                deadline
            )
            .unwrap()
            .is_empty()
        );
    }
}

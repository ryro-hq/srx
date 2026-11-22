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
pub struct ServicesGenerationError(String);
impl From<InstallationError> for ServicesGenerationError {
    fn from(error: InstallationError) -> Self {
        // JSON errors can quote persisted input, including configuration text.
        let message = match error {
            InstallationError::Encoding(_) | InstallationError::Generation(_) => {
                "invalid Services candidate description; evidence preserved".into()
            }
            error => error.to_string(),
        };
        Self(message)
    }
}

#[derive(Clone, Debug)]
pub struct ServicesGenerationSummary {
    pub pin: ContentDigest,
    pub outputs: usize,
    pub services: usize,
    pub commands: usize,
    pub processes: usize,
    pub configurations: usize,
}
impl From<&RetainedGeneration> for ServicesGenerationSummary {
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
pub enum ServicesCandidatePhase {
    Preparing,
    Prepared,
}
#[derive(Debug)]
pub struct ServicesCandidateEntry {
    pub pin: ContentDigest,
    pub phase: Result<ServicesCandidatePhase, String>,
}

/// Initialize metadata within an existing owned, mode-0700 directory.
pub fn initialize_services_installation(
    path: &Path,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<ServicesInstallation, ServicesGenerationError> {
    Ok(ServicesInstallation(
        GenerationInstallation::initialize(path, cancellation, deadline)?,
    ))
}

/// Pinned installation authority retained across package realization. Replacing
/// its pathname cannot redirect subsequent candidate publication.
#[derive(Debug)]
pub struct ServicesInstallation(GenerationInstallation);
impl ServicesInstallation {
    pub fn id(&self) -> &str {
        self.0.id()
    }

    /// Read candidate evidence through this pinned installation identity.
    pub fn list(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Vec<ServicesCandidateEntry>, ServicesGenerationError> {
        Ok(self
            .0
            .list(cancellation, deadline)?
            .into_iter()
            .map(|entry| ServicesCandidateEntry {
                pin: entry.pin,
                phase: entry
                    .phase
                    .map(|phase| match phase {
                        CandidatePhase::Preparing => ServicesCandidatePhase::Preparing,
                        CandidatePhase::Prepared => ServicesCandidatePhase::Prepared,
                    })
                    .map_err(|_| "invalid candidate journal evidence".into()),
            })
            .collect())
    }
}

#[derive(Debug)]
pub struct ServicesPreparation<'a> {
    pub installation: &'a ServicesInstallation,
    pub store: &'a Store,
    pub launcher: &'a Path,
    pub launcher_digest: ContentDigest,
}

/// Persist a Services candidate, its roots, executable launcher snapshot and private
/// configuration. Prepared journal state describes retained candidate bytes;
/// an error while publishing derived files preserves that candidate for retry.
pub fn prepare_services_generation(
    prepared: PreparedConsumer,
    configuration: &ServicesPreparation<'_>,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<ServicesGenerationSummary, ServicesGenerationError> {
    let launcher = super::LauncherIdentity::new(configuration.launcher_digest, 1)
        .map_err(|error| ServicesGenerationError(error.to_string()))?;
    let generation = super::PreparedGeneration::freeze(prepared, launcher)
        .map_err(|error| ServicesGenerationError(error.to_string()))?;
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
    Ok(ServicesGenerationSummary::from(&retained))
}

/// Prepare an empty desired generation through the normal retention protocol.
/// This needs no project source, package realization or service-manager action.
pub fn prepare_empty_services_generation(
    configuration: &ServicesPreparation<'_>,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<ServicesGenerationSummary, ServicesGenerationError> {
    let launcher = super::LauncherIdentity::new(configuration.launcher_digest, 1)
        .map_err(|error| ServicesGenerationError(error.to_string()))?;
    let retained = configuration.installation.0.prepare_empty(
        launcher,
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
    Ok(ServicesGenerationSummary::from(&retained))
}

/// Open existing installation authority without initializing or repairing it.
pub fn open_services_installation(
    path: &Path,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<ServicesInstallation, ServicesGenerationError> {
    Ok(ServicesInstallation(
        GenerationInstallation::open_existing(path, cancellation, deadline)?,
    ))
}

/// List journal evidence only, without opening or creating a Store.
pub fn list_services_generations(
    path: &Path,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<Vec<ServicesCandidateEntry>, ServicesGenerationError> {
    open_services_installation(path, cancellation, deadline)?.list(cancellation, deadline)
}

pub fn inspect_services_generation(
    path: &Path,
    store: &Store,
    pin: ContentDigest,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<ServicesGenerationSummary, ServicesGenerationError> {
    let installation = GenerationInstallation::open_existing(path, cancellation, deadline)?;
    Ok(ServicesGenerationSummary::from(
        &installation.open(store, pin, cancellation, deadline)?,
    ))
}

/// Verify both retained candidates before computing a pure operational diff.
pub fn diff_services_generations(
    path: &Path,
    store: &Store,
    previous: ContentDigest,
    candidate: ContentDigest,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<String, ServicesGenerationError> {
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
                "Services",
            );
        let path = root.path().join("installation");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(10);
        let original = initialize_services_installation(&path, &cancel, deadline).unwrap();
        fs::rename(&path, root.path().join("original-installation")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement = initialize_services_installation(&path, &cancel, deadline).unwrap();
        assert_ne!(original.id(), replacement.id());
        let worker = root.path().join("launcher");
        fs::write(&worker, b"inert launcher").unwrap();
        let store = Store::open(&root.path().join("store")).unwrap();
        let result = prepare_services_generation(
            prepared,
            &ServicesPreparation {
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
            list_services_generations(&path, &cancel, deadline)
                .unwrap()
                .is_empty()
        );
        assert!(
            list_services_generations(
                &root.path().join("original-installation"),
                &cancel,
                deadline
            )
            .unwrap()
            .is_empty()
        );
    }
}

#[cfg(test)]
mod empty_tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn empty_generation_is_retained_without_project_and_preserves_installation_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("installation");
        crate::deployment::services::profile::ensure_profile_directory(&path).unwrap();
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(10);
        let installation = initialize_services_installation(&path, &cancel, deadline).unwrap();
        let store = Store::initialize(&root.path().join("store")).unwrap();
        let worker = root.path().join("worker");
        std::fs::write(&worker, b"nonexecuted launcher fixture").unwrap();
        let configuration = ServicesPreparation {
            installation: &installation,
            store: &store,
            launcher: &worker,
            launcher_digest: ContentDigest::sha256(b"nonexecuted launcher fixture"),
        };
        let first = prepare_empty_services_generation(&configuration, &cancel, deadline).unwrap();
        let second = prepare_empty_services_generation(&configuration, &cancel, deadline).unwrap();
        assert_eq!(first.pin, second.pin);
        assert_eq!(
            (
                first.outputs,
                first.services,
                first.commands,
                first.processes,
                first.configurations
            ),
            (0, 0, 0, 0, 0)
        );
        let reopened =
            inspect_services_generation(&path, &store, first.pin, &cancel, deadline).unwrap();
        assert_eq!(reopened.pin, first.pin);
        assert_eq!(
            open_services_installation(&path, &cancel, deadline)
                .unwrap()
                .id(),
            installation.id()
        );
        assert!(
            crate::deployment::services::inspect_services_status(&path, &cancel, deadline)
                .unwrap()
                .desired
                .is_none()
        );
    }
}

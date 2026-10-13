use super::{
    CandidatePhase, GenerationInstallation, InstallationError, MAX_MANIFEST_BYTES, Record, Result,
    RetainedGeneration, check, storage,
};
use crate::deployment::os::launch_binding::OsLaunchBinding;
use crate::{cancellation::Cancellation, store::ContentDigest};
use std::time::Instant;

impl GenerationInstallation {
    /// Observe existing publication evidence, confirming durability without
    /// rewriting bytes. Absence is not proof that an earlier effect never ran.
    pub(crate) fn observe_launch_binding(
        &self,
        pin: ContentDigest,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Option<OsLaunchBinding>> {
        let _lock = self.storage.lock(cancellation, deadline)?;
        if self.storage.installation_id(false)? != self.id {
            return Err(InstallationError::Invalid(
                "installation identity changed",
            ));
        }
        let Some(bytes) = self
            .storage
            .observe_launch(pin, cancellation, deadline)?
        else {
            return Ok(None);
        };
        let binding = OsLaunchBinding::decode(&bytes, pin)
            .map_err(|_| InstallationError::Invalid("invalid launch binding"))?;
        if binding.installation_id() != self.id {
            return Err(InstallationError::Invalid(
                "launch binding belongs to another installation",
            ));
        }
        check(cancellation, deadline)?;
        Ok(Some(binding))
    }
    pub(crate) fn publish_launch_binding(
        &self,
        generation: &RetainedGeneration,
        binding: &OsLaunchBinding,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<ContentDigest> {
        check(cancellation, deadline)?;
        if generation.installation_id() != self.id
            || binding.installation_id() != self.id
            || binding.generation() != generation.digest()
            || binding.launcher() != &generation.manifest().launcher
            || !generation
                .manifest()
                .processes
                .get(&binding.process_key())
                .is_some_and(|process| {
                    process.command == binding.command_key()
                        && process.restart == binding.context().restart()
                })
            || !generation
                .commands()
                .contains_key(&binding.command_key())
        {
            return Err(InstallationError::Invalid(
                "launch binding differs from retained generation",
            ));
        }
        let bytes = binding
            .canonical_bytes()
            .map_err(|_| InstallationError::Invalid("invalid launch binding"))?;
        let pin = ContentDigest::sha256(&bytes);
        let _lock = self.storage.lock(cancellation, deadline)?;
        if self.storage.installation_id(false)? != self.id {
            return Err(InstallationError::Invalid(
                "installation identity changed",
            ));
        }
        let directory = self
            .storage
            .candidate(generation.digest(), false)?;
        let record = Record::parse(
            &storage::read(directory.fd(), "state", 1024)?,
            &self.id,
            generation.digest(),
        )?;
        if record.phase != CandidatePhase::Prepared
            || storage::read(directory.fd(), "manifest", MAX_MANIFEST_BYTES)?
                != generation.canonical_bytes()
        {
            return Err(InstallationError::Invalid(
                "candidate evidence differs from retained generation",
            ));
        }
        self.storage
            .confirm_durable(generation.digest(), &directory)?;
        check(cancellation, deadline)?;
        self.storage
            .publish_launch(pin, &bytes, cancellation, deadline)?;
        Ok(pin)
    }

    pub(crate) fn read_launch_binding(
        &self,
        pin: ContentDigest,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<OsLaunchBinding> {
        let _lock = self.storage.lock(cancellation, deadline)?;
        if self.storage.installation_id(false)? != self.id {
            return Err(InstallationError::Invalid(
                "installation identity changed",
            ));
        }
        let bytes = self
            .storage
            .read_launch(pin)?
            .ok_or(InstallationError::Invalid(
                "launch binding is absent",
            ))?;
        let binding = OsLaunchBinding::decode(&bytes, pin)
            .map_err(|_| InstallationError::Invalid("invalid launch binding"))?;
        if binding.installation_id() != self.id {
            return Err(InstallationError::Invalid(
                "launch binding belongs to another installation",
            ));
        }
        check(cancellation, deadline)?;
        Ok(binding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    fn fixture() -> (tempfile::TempDir, GenerationInstallation) {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let installation =
            GenerationInstallation::initialize(temp.path(), &Cancellation::default(), deadline())
                .unwrap();
        (temp, installation)
    }

    #[test]
    fn binding_absence_observation_syncs_and_rechecks_without_creating_evidence() {
        let (temp, installation) = fixture();
        let pin = ContentDigest::sha256(b"not published");
        let before = fs::read_dir(temp.path()).unwrap().count();
        assert!(
            installation
                .observe_launch_binding(pin, &Cancellation::default(), deadline())
                .unwrap()
                .is_none()
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), before);
        assert!(!temp.path().join(format!("launch-{pin}")).exists());
    }

    #[test]
    fn binding_appearing_after_directory_sync_is_not_reported_absent() {
        let (temp, installation) = fixture();
        let pin = ContentDigest::sha256(b"appearing bytes");
        let file = temp.path().join(format!("launch-{pin}"));
        let changed = file.clone();
        storage::before_absence_readback(Box::new(move || {
            fs::write(&changed, b"appearing bytes").unwrap();
            fs::set_permissions(&changed, fs::Permissions::from_mode(0o600)).unwrap();
        }));
        assert!(
            installation
                .observe_launch_binding(pin, &Cancellation::default(), deadline())
                .is_err()
        );
        assert_eq!(fs::read(file).unwrap(), b"appearing bytes");
    }

    #[test]
    fn binding_absence_cannot_cross_replaced_authority_or_cancellation() {
        let (temp, installation) = fixture();
        let pin = ContentDigest::sha256(b"not published");
        let authority = temp.path().join("authority.lock");
        storage::before_absence_readback(Box::new(move || {
            fs::rename(&authority, authority.with_extension("previous")).unwrap();
            fs::write(&authority, b"").unwrap();
            fs::set_permissions(&authority, fs::Permissions::from_mode(0o600)).unwrap();
        }));
        assert!(
            installation
                .observe_launch_binding(pin, &Cancellation::default(), deadline())
                .is_err()
        );
        let (_temp, installation) = fixture();
        let cancel = Cancellation::default();
        let signal = cancel.clone();
        storage::before_absence_readback(Box::new(move || signal.cancel()));
        assert!(matches!(
            installation.observe_launch_binding(pin, &cancel, deadline()),
            Err(InstallationError::Cancelled)
        ));
    }
}

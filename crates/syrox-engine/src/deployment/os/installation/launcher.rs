use super::{
    CandidatePhase, GenerationInstallation, InstallationError, MAX_LAUNCHER_BYTES,
    MAX_MANIFEST_BYTES, Record, Result, RetainedGeneration, check, check_io, launcher_digest,
    storage,
};
use crate::platform::linux::fd::{self as linux_fd, FileIdentity, OpenedPath};
use crate::{cancellation::Cancellation, store::ContentDigest, store::Store};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug)]
pub(crate) struct GenerationLauncher {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    digest: ContentDigest,
}
impl GenerationLauncher {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) const fn digest(&self) -> ContentDigest {
        self.digest
    }
    pub(crate) fn verify_path(&self, cancellation: &Cancellation, deadline: Instant) -> Result<()> {
        check(cancellation, deadline)?;
        let opened = linux_fd::open_top(&self.path).map_err(storage::open_error)?;
        if opened.metadata().identity() != self.identity {
            return Err(InstallationError::Invalid(
                "launcher snapshot was replaced",
            ));
        }
        verify_worker(opened, self.digest, cancellation, deadline)?;
        // The retained descriptor keeps the selected inode alive; it grants no
        // authority to delete its directory or to trust a later path replacement.
        self.file.metadata()?;
        Ok(())
    }
}
impl GenerationInstallation {
    pub(crate) fn prepare_launcher(
        &self,
        generation: &RetainedGeneration,
        store: &Store,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<GenerationLauncher> {
        self.prepare_launcher_inner(generation, store, cancellation, deadline)
            .map_err(|error| self.latch_launcher_uncertainty(error))
    }
    pub(crate) fn open_launcher(
        &self,
        generation: &RetainedGeneration,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<GenerationLauncher> {
        self.open_launcher_inner(generation, cancellation, deadline)
            .map_err(|error| self.latch_launcher_uncertainty(error))
    }
    fn latch_launcher_uncertainty(&self, error: InstallationError) -> InstallationError {
        if matches!(error, InstallationError::Uncertain(_)) {
            self.storage.mark_uncertain()
        } else {
            error
        }
    }
    fn prepare_launcher_inner(
        &self,
        generation: &RetainedGeneration,
        store: &Store,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<GenerationLauncher> {
        let _lock = self.storage.lock(cancellation, deadline)?;
        let directory = self.launcher_candidate(generation)?;
        let digest = launcher_digest(generation.manifest())?;
        if let Some(existing) = open_snapshot(&directory, digest, cancellation, deadline)? {
            self.storage
                .confirm_durable(generation.digest(), &directory)?;
            return Ok(existing);
        }
        let mut entries = 0;
        linux_fd::read_directory(&directory, |_| {
            check(cancellation, deadline)?;
            entries += 1;
            if entries >= 1024 {
                return Err(InstallationError::Invalid(
                    "candidate staging capacity exhausted",
                ));
            }
            Ok(())
        })
        .map_err(|error| match error {
            linux_fd::ReadDirectoryError::Io(error) => InstallationError::Io(error),
            linux_fd::ReadDirectoryError::Admission(error) => error,
        })?;
        let operation = store.operation()?;
        let mut source = operation
            .open_verified_checked(digest, MAX_LAUNCHER_BYTES, || {
                check_io(cancellation, deadline)
            })?
            .ok_or(InstallationError::Invalid(
                "retained launcher is absent",
            ))?;
        let parent_path = PathBuf::from(format!(
            "/proc/self/fd/{}",
            directory.fd().as_raw_fd()
        ));
        let name = format!("launcher-{}", linux_fd::operation_name()?);
        let staging_path = parent_path.join(&name);
        // create_dir is exclusive. Once created, staging survives all failures;
        // recovery can inspect it, but no partially written bytes are executable.
        fs::create_dir(&staging_path)?;
        let staging = linux_fd::open_beneath(directory.fd(), Path::new(&name), true)
            .map_err(storage::open_error)?;
        File::from(staging.fd().try_clone_to_owned()?)
            .set_permissions(fs::Permissions::from_mode(0o700))?;
        linux_fd::sync_directory(directory.fd())?;
        let pinned_path = PathBuf::from(format!(
            "/proc/self/fd/{}",
            staging.fd().as_raw_fd()
        ));
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW)
            .open(pinned_path.join("worker"))?;
        output.set_permissions(fs::Permissions::from_mode(0o400))?;
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; 16384];
        loop {
            check(cancellation, deadline)?;
            let size = source.read(&mut buffer)?;
            if size == 0 {
                break;
            }
            bytes += size as u64;
            if bytes > MAX_LAUNCHER_BYTES {
                return Err(InstallationError::Invalid(
                    "launcher exceeds byte bound",
                ));
            }
            output.write_all(&buffer[..size])?;
        }
        drop(source);
        drop(operation);
        output.set_permissions(fs::Permissions::from_mode(0o500))?;
        output.sync_all()?;
        drop(output); // Close writable handle before any executable snapshot is published.
        let worker = linux_fd::open_beneath(staging.fd(), Path::new("worker"), false)
            .map_err(storage::open_error)?;
        verify_worker(worker, digest, cancellation, deadline)?;
        File::from(staging.fd().try_clone_to_owned()?)
            .set_permissions(fs::Permissions::from_mode(0o500))?;
        linux_fd::sync_directory(staging.fd())?;
        self.storage
            .confirm_durable(generation.digest(), &directory)?;
        check(cancellation, deadline)?;
        linux_fd::rename_directory(
            directory.fd(),
            Path::new(&name),
            Path::new("launcher"),
            staging.metadata().identity(),
        )
        .map_err(|_| {
            InstallationError::Uncertain("launcher directory publication needs reconciliation")
        })?;
        #[cfg(test)]
        if FAIL_AFTER_RENAME.replace(false) {
            return Err(InstallationError::Uncertain(
                "injected uncertainty after launcher rename",
            ));
        }
        open_snapshot(&directory, digest, cancellation, deadline)?.ok_or(
            InstallationError::Uncertain("published launcher is absent"),
        )
    }
    fn open_launcher_inner(
        &self,
        generation: &RetainedGeneration,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<GenerationLauncher> {
        let _lock = self.storage.lock(cancellation, deadline)?;
        let directory = self.launcher_candidate(generation)?;
        self.storage
            .confirm_durable(generation.digest(), &directory)?;
        open_snapshot(
            &directory,
            launcher_digest(generation.manifest())?,
            cancellation,
            deadline,
        )?
        .ok_or(InstallationError::Invalid(
            "launcher has not been published",
        ))
    }
    fn launcher_candidate(&self, generation: &RetainedGeneration) -> Result<OpenedPath> {
        if self.storage.installation_id(false)? != self.id
            || generation.installation_id() != self.id
        {
            return Err(InstallationError::Invalid(
                "launcher installation identity differs",
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
                "launcher candidate evidence differs",
            ));
        }
        Ok(directory)
    }
}
fn open_snapshot(
    parent: &OpenedPath,
    digest: ContentDigest,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<Option<GenerationLauncher>> {
    check(cancellation, deadline)?;
    let directory = match linux_fd::open_beneath(parent.fd(), Path::new("launcher"), true) {
        Ok(directory) => directory,
        Err(linux_fd::OpenError::Other(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(storage::open_error(error)),
    };
    if !directory.metadata().is_trusted_directory() || directory.metadata().mode() & 0o7777 != 0o500
    {
        return Err(InstallationError::Invalid(
            "launcher directory permissions differ",
        ));
    }
    let mut count = 0;
    let names = linux_fd::read_directory(&directory, |_| {
        check(cancellation, deadline)?;
        count += 1;
        if count > 1 {
            return Err(InstallationError::Invalid(
                "unexpected launcher directory entry",
            ));
        }
        Ok(())
    })
    .map_err(|error| match error {
        linux_fd::ReadDirectoryError::Io(error) => InstallationError::Io(error),
        linux_fd::ReadDirectoryError::Admission(error) => error,
    })?;
    if names.len() != 1 || names[0] != "worker" {
        return Err(InstallationError::Invalid(
            "launcher worker is absent",
        ));
    }
    let worker = linux_fd::open_beneath(directory.fd(), Path::new("worker"), false)
        .map_err(storage::open_error)?;
    let identity = worker.metadata().identity();
    let file = verify_worker(worker, digest, cancellation, deadline)?;
    linux_fd::sync_file(file.as_fd())
        .map_err(|_| InstallationError::Uncertain("launcher file durability unknown"))?;
    linux_fd::sync_directory(directory.fd())
        .map_err(|_| InstallationError::Uncertain("launcher directory durability unknown"))?;
    linux_fd::sync_directory(parent.fd())
        .map_err(|_| InstallationError::Uncertain("launcher publication durability unknown"))?;
    let path = linux_fd::directory_path(&directory)?.join("worker");
    Ok(Some(GenerationLauncher {
        path,
        file,
        identity,
        digest,
    }))
}
fn verify_worker(
    worker: OpenedPath,
    digest: ContentDigest,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<File> {
    if !worker.metadata().is_trusted_regular()
        || worker.metadata().mode() & 0o7777 != 0o500
        || worker.metadata().size() > MAX_LAUNCHER_BYTES
    {
        return Err(InstallationError::Invalid(
            "launcher is not a private bounded executable",
        ));
    }
    let mut file = worker.into_file();
    let mut hash = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 16384];
    loop {
        check(cancellation, deadline)?;
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        bytes += size as u64;
        if bytes > MAX_LAUNCHER_BYTES {
            return Err(InstallationError::Invalid(
                "launcher exceeds byte bound",
            ));
        }
        hash.update(&buffer[..size]);
    }
    let actual = ContentDigest::from_sha256_hash(hash.finalize().into());
    if actual != digest {
        return Err(InstallationError::Invalid(
            "launcher snapshot pin differs",
        ));
    }
    Ok(file)
}

#[cfg(test)]
thread_local! {
    static FAIL_AFTER_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::os::{LauncherIdentity, PreparedGeneration};
    use std::time::Duration;
    const WORKER: &[u8] = b"authenticated nonexecuted candidate worker fixture";
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }
    fn fixture() -> (
        tempfile::TempDir,
        tempfile::TempDir,
        GenerationInstallation,
        RetainedGeneration,
        Store,
    ) {
        let (project, consumer) =
            crate::deployment::manifest::tests::prepared_service_payload_fixture_kind(
                &crate::runtime::tests::elf(2, None, &[], None, None),
                "",
                "Os",
            );
        let worker = project.path().join("worker");
        fs::write(&worker, WORKER).unwrap();
        let prepared = PreparedGeneration::freeze(
            consumer,
            LauncherIdentity::new(ContentDigest::sha256(WORKER), 1).unwrap(),
        )
        .unwrap();
        let store = Store::open(&project.path().join("store")).unwrap();
        let path = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let cancel = Cancellation::default();
        let installation =
            GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
        let retained = installation
            .prepare(&prepared, &store, &worker, &cancel, deadline())
            .unwrap();
        fs::remove_file(worker).unwrap();
        fs::remove_file(project.path().join("main.srx")).unwrap();
        (project, path, installation, retained, store)
    }
    #[test]
    fn executable_snapshot_survives_original_worker_project_and_coordinator() {
        let (_project, path, installation, retained, store) = fixture();
        let cancel = Cancellation::default();
        let snapshot = installation
            .prepare_launcher(&retained, &store, &cancel, deadline())
            .unwrap();
        assert_eq!(fs::read(snapshot.path()).unwrap(), WORKER);
        assert_eq!(
            fs::metadata(snapshot.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o500
        );
        assert_eq!(snapshot.digest(), ContentDigest::sha256(WORKER));
        snapshot.verify_path(&cancel, deadline()).unwrap();
        let original = snapshot.identity;
        assert_eq!(
            installation
                .prepare_launcher(&retained, &store, &cancel, deadline())
                .unwrap()
                .identity,
            original
        );
        let pin = retained.digest();
        drop((snapshot, retained, installation));
        let reopened =
            GenerationInstallation::open_existing(path.path(), &cancel, deadline()).unwrap();
        let retained = reopened
            .open(&store, pin, &cancel, deadline())
            .unwrap();
        let snapshot = reopened
            .open_launcher(&retained, &cancel, deadline())
            .unwrap();
        assert_eq!(snapshot.identity, original);
        assert_eq!(fs::read(snapshot.path()).unwrap(), WORKER);
    }
    #[test]
    fn modified_snapshot_is_preserved_and_never_repaired_from_store() {
        let (_project, _path, installation, retained, store) = fixture();
        let cancel = Cancellation::default();
        let snapshot = installation
            .prepare_launcher(&retained, &store, &cancel, deadline())
            .unwrap();
        fs::set_permissions(snapshot.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(snapshot.path(), b"tampered").unwrap();
        fs::set_permissions(snapshot.path(), fs::Permissions::from_mode(0o500)).unwrap();
        assert!(snapshot.verify_path(&cancel, deadline()).is_err());
        assert!(
            installation
                .prepare_launcher(&retained, &store, &cancel, deadline())
                .is_err()
        );
        assert_eq!(fs::read(snapshot.path()).unwrap(), b"tampered");
    }
    #[test]
    fn cancelled_preparation_and_incomplete_destination_never_publish_a_worker() {
        let (_project, _path, installation, retained, store) = fixture();
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(
            installation
                .prepare_launcher(&retained, &store, &cancel, deadline())
                .is_err()
        );
        let directory = installation
            .storage
            .candidate(retained.digest(), false)
            .unwrap();
        let path = linux_fd::directory_path(&directory)
            .unwrap()
            .join("launcher");
        assert!(!path.exists());
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(
            installation
                .prepare_launcher(
                    &retained,
                    &store,
                    &Cancellation::default(),
                    deadline()
                )
                .is_err()
        );
        assert!(fs::read_dir(path).unwrap().next().is_none());
    }
    #[test]
    fn replaced_snapshot_and_symlink_are_refused_even_with_matching_bytes() {
        use std::os::unix::fs::symlink;
        let (_project, _path, installation, retained, store) = fixture();
        let cancel = Cancellation::default();
        let snapshot = installation
            .prepare_launcher(&retained, &store, &cancel, deadline())
            .unwrap();
        let parent = snapshot.path().parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(snapshot.path(), parent.join("old")).unwrap();
        fs::write(snapshot.path(), WORKER).unwrap();
        fs::set_permissions(snapshot.path(), fs::Permissions::from_mode(0o500)).unwrap();
        assert!(snapshot.verify_path(&cancel, deadline()).is_err());
        fs::remove_file(snapshot.path()).unwrap();
        symlink("old", snapshot.path()).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(
            installation
                .open_launcher(&retained, &cancel, deadline())
                .is_err()
        );
    }

    #[test]
    fn uncertain_publication_preserves_snapshot_and_requires_reopening_authority() {
        let (_project, path, installation, retained, store) = fixture();
        let cancel = Cancellation::default();
        FAIL_AFTER_RENAME.set(true);
        assert!(matches!(
            installation.prepare_launcher(&retained, &store, &cancel, deadline()),
            Err(InstallationError::Uncertain(_))
        ));
        assert!(matches!(
            installation.list(&cancel, deadline()),
            Err(InstallationError::Uncertain(_))
        ));
        assert!(matches!(
            installation.open_launcher(&retained, &cancel, deadline()),
            Err(InstallationError::Uncertain(_))
        ));
        let reopened =
            GenerationInstallation::open_existing(path.path(), &cancel, deadline()).unwrap();
        let worker = reopened
            .open_launcher(&retained, &cancel, deadline())
            .unwrap();
        assert_eq!(fs::read(worker.path()).unwrap(), WORKER);
        worker.verify_path(&cancel, deadline()).unwrap();
    }
}

use super::{
    CandidatePhase, GenerationInstallation, InstallationError, MAX_MANIFEST_BYTES, Record, Result,
    RetainedGeneration, check, storage,
};
use crate::cancellation::Cancellation;
use crate::platform::linux::fd::{self as linux_fd, OpenedPath};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

const STAGING_PREFIX: &str = "configuration-op-";
const MAX_STAGING: usize = 64;
pub(crate) struct GenerationConfiguration {
    root: OpenedPath,
    visible_root: PathBuf,
    services: BTreeMap<String, OpenedPath>,
}
impl GenerationConfiguration {
    /// Revalidates that these descriptors are still published at their pinned
    /// paths. This returns data, not authorization to mutate or clean up files.
    pub(crate) fn service(&self, id: &str) -> Result<(File, PathBuf)> {
        let root = linux_fd::directory_path(&self.root)?;
        if root != self.visible_root {
            return Err(InstallationError::Invalid(
                "configuration root path changed",
            ));
        }
        let service = self
            .services
            .get(id)
            .ok_or(InstallationError::Invalid(
                "unknown configuration service",
            ))?;
        let current = linux_fd::open_beneath(self.root.fd(), Path::new(id), true)
            .map_err(storage::open_error)?;
        if current.metadata().identity() != service.metadata().identity() {
            return Err(InstallationError::Invalid(
                "configuration service directory was replaced",
            ));
        }
        let path = linux_fd::directory_path(service)?;
        if path != root.join(id) {
            return Err(InstallationError::Invalid(
                "configuration service path changed",
            ));
        }
        Ok((
            File::from(service.fd().try_clone_to_owned()?),
            path,
        ))
    }
}
impl GenerationInstallation {
    pub(crate) fn prepare_configuration(
        &self,
        generation: &RetainedGeneration,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<GenerationConfiguration> {
        let _lock = self.storage.lock(cancellation, deadline)?;
        let parent = self.configuration_candidate(generation, cancellation, deadline)?;
        if let Some(root) = open_optional(&parent)? {
            return self.verify_published(generation, &parent, root, cancellation, deadline);
        }
        let (name, staging) = create_staging(&parent, cancellation, deadline)?;
        populate(generation, &staging, cancellation, deadline)?;
        let staging = linux_fd::open_beneath(parent.fd(), Path::new(&name), true)
            .map_err(storage::open_error)?;
        verify(generation, &staging, cancellation, deadline)?;
        check(cancellation, deadline)?;
        if linux_fd::rename_directory(
            parent.fd(),
            Path::new(&name),
            Path::new("configuration"),
            staging.metadata().identity(),
        )
        .is_err()
        {
            return Err(self.storage.mark_uncertain());
        }
        let root = open_optional(&parent)?.ok_or_else(|| self.storage.mark_uncertain())?;
        self.verify_published(generation, &parent, root, cancellation, deadline)
    }
    pub(crate) fn open_configuration(
        &self,
        generation: &RetainedGeneration,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<GenerationConfiguration> {
        let _lock = self.storage.lock(cancellation, deadline)?;
        let parent = self.configuration_candidate(generation, cancellation, deadline)?;
        let root = open_optional(&parent)?.ok_or(InstallationError::Invalid(
            "generation configuration is absent",
        ))?;
        self.verify_published(generation, &parent, root, cancellation, deadline)
    }
    fn configuration_candidate(
        &self,
        generation: &RetainedGeneration,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<OpenedPath> {
        check(cancellation, deadline)?;
        if self.storage.installation_id(false)? != self.id
            || generation.installation_id() != self.id
        {
            return Err(InstallationError::Invalid(
                "configuration installation identity differs",
            ));
        }
        let parent = self
            .storage
            .candidate(generation.digest(), false)?;
        let record = Record::parse(
            &storage::read(parent.fd(), "state", 1024)?,
            &self.id,
            generation.digest(),
        )?;
        if record.phase != CandidatePhase::Prepared
            || storage::read(parent.fd(), "manifest", MAX_MANIFEST_BYTES)?
                != generation.canonical_bytes()
        {
            return Err(InstallationError::Invalid(
                "configuration candidate evidence differs",
            ));
        }
        check(cancellation, deadline)?;
        Ok(parent)
    }
    fn verify_published(
        &self,
        generation: &RetainedGeneration,
        parent: &OpenedPath,
        root: OpenedPath,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<GenerationConfiguration> {
        let services = verify(generation, &root, cancellation, deadline)?;
        let synced = (|| {
            for service in services.values() {
                sync_tree(service, 0, &mut 0, cancellation, deadline)?;
            }
            linux_fd::sync_directory(root.fd())?;
            linux_fd::sync_directory(parent.fd())?;
            Ok::<_, InstallationError>(())
        })();
        if let Err(error) = synced {
            return match error {
                InstallationError::Cancelled | InstallationError::Deadline => Err(error),
                _ => Err(self.storage.mark_uncertain()),
            };
        }
        self.storage
            .confirm_durable(generation.digest(), parent)?;
        check(cancellation, deadline)?;
        let visible_root = linux_fd::directory_path(parent)?.join("configuration");
        let published = open_optional(parent)?.ok_or(InstallationError::Invalid(
            "configuration publication disappeared",
        ))?;
        if published.metadata().identity() != root.metadata().identity()
            || linux_fd::directory_path(&root)? != visible_root
        {
            return Err(InstallationError::Invalid(
                "configuration publication moved or was replaced",
            ));
        }
        Ok(GenerationConfiguration {
            root,
            visible_root,
            services,
        })
    }
}
fn open_optional(parent: &OpenedPath) -> Result<Option<OpenedPath>> {
    match linux_fd::open_beneath(parent.fd(), Path::new("configuration"), true) {
        Ok(root) => Ok(Some(root)),
        Err(linux_fd::OpenError::Other(error)) if error.kind() == io::ErrorKind::NotFound => {
            Ok(None)
        }
        Err(error) => Err(storage::open_error(error)),
    }
}
fn create_staging(
    parent: &OpenedPath,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(String, OpenedPath)> {
    let mut entries = 0;
    let names = linux_fd::read_directory(parent, |_| {
        check(cancellation, deadline)?;
        entries += 1;
        if entries >= 4096 {
            return Err(InstallationError::Invalid(
                "candidate directory bound exceeded",
            ));
        }
        Ok(())
    })
    .map_err(directory_error)?;
    if names
        .iter()
        .filter(|name| {
            name.as_encoded_bytes()
                .starts_with(STAGING_PREFIX.as_bytes())
        })
        .count()
        >= MAX_STAGING
    {
        return Err(InstallationError::Invalid(
            "configuration staging registry exhausted",
        ));
    }
    for _ in 0..64 {
        check(cancellation, deadline)?;
        let name = format!("configuration-{}", linux_fd::operation_name()?);
        let (directory, created) =
            linux_fd::ensure_directory_beneath_with_status(parent.fd(), Path::new(&name))
                .map_err(|_| InstallationError::Invalid("cannot create configuration staging"))?;
        if created {
            return Ok((name, directory));
        }
    }
    Err(InstallationError::Invalid(
        "configuration staging entropy exhausted",
    ))
}
fn populate(
    generation: &RetainedGeneration,
    root: &OpenedPath,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<()> {
    let groups = grouped(generation);
    for service in &generation.manifest().services {
        check(cancellation, deadline)?;
        let directory = new_directory(root.fd(), Path::new(service))?;
        let mut dirs: BTreeMap<PathBuf, OpenedPath> = BTreeMap::new();
        for config in groups.get(service.as_str()).into_iter().flatten() {
            check(cancellation, deadline)?;
            let relative = Path::new(&config.path);
            let mut current = directory.fd().try_clone_to_owned()?;
            let mut prefix = PathBuf::new();
            for component in relative.parent().into_iter().flat_map(Path::iter) {
                prefix.push(component);
                let child = if let Some(child) = dirs.get(&prefix) {
                    child
                } else {
                    let created = new_directory(current.as_fd(), Path::new(component))?;
                    dirs.entry(prefix.clone()).or_insert(created)
                };
                current = child.fd().try_clone_to_owned()?;
            }
            let (opened, created) = linux_fd::initialize_regular(
                current.as_fd(),
                Path::new(
                    relative
                        .file_name()
                        .ok_or(InstallationError::Invalid(
                            "invalid configuration path",
                        ))?,
                ),
            )?;
            if !created {
                return Err(InstallationError::Invalid(
                    "staged configuration file already exists",
                ));
            }
            let mut file = opened.into_file();
            for chunk in config.text.as_bytes().chunks(8192) {
                check(cancellation, deadline)?;
                file.write_all(chunk)?;
            }
            file.set_permissions(std::fs::Permissions::from_mode(config.mode))?;
            file.sync_all()?;
        }
        for dir in dirs.values().rev() {
            seal(dir)?;
        }
        seal(&directory)?;
    }
    seal(root)
}
fn new_directory(parent: BorrowedFd<'_>, name: &Path) -> Result<OpenedPath> {
    let (directory, created) = linux_fd::ensure_directory_beneath_with_status(parent, name)
        .map_err(|_| InstallationError::Invalid("cannot create staged configuration directory"))?;
    if !created {
        return Err(InstallationError::Invalid(
            "staged configuration directory already exists",
        ));
    }
    Ok(directory)
}
fn seal(directory: &OpenedPath) -> Result<()> {
    File::from(directory.fd().try_clone_to_owned()?)
        .set_permissions(std::fs::Permissions::from_mode(0o500))?;
    linux_fd::sync_directory(directory.fd())?;
    Ok(())
}
fn verify(
    generation: &RetainedGeneration,
    root: &OpenedPath,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<BTreeMap<String, OpenedPath>> {
    if !root.metadata().is_trusted_directory() || root.metadata().mode() & 0o7777 != 0o500 {
        return Err(InstallationError::Invalid(
            "configuration root is not private and immutable",
        ));
    }
    let mut seen = BTreeSet::new();
    let names = linux_fd::read_directory(root, |name| {
        check(cancellation, deadline)?;
        let name = name.to_str().ok_or(InstallationError::Invalid(
            "invalid configuration service name",
        ))?;
        if !generation.manifest().services.contains(name) {
            return Err(InstallationError::Invalid(
                "undeclared configuration service",
            ));
        }
        seen.insert(name.to_owned());
        Ok(())
    })
    .map_err(directory_error)?;
    if seen != generation.manifest().services {
        return Err(InstallationError::Invalid(
            "configuration service inventory differs",
        ));
    }
    let groups = grouped(generation);
    let mut services = BTreeMap::new();
    for name in names {
        check(cancellation, deadline)?;
        let id = name.to_str().ok_or(InstallationError::Invalid(
            "invalid configuration service name",
        ))?;
        let directory = linux_fd::open_beneath(root.fd(), Path::new(&name), true)
            .map_err(storage::open_error)?;
        let file = File::from(directory.fd().try_clone_to_owned()?);
        crate::deployment::os::runtime::verify_configuration_subset_until(
            groups.get(id).map_or(&[], Vec::as_slice),
            &file,
            cancellation,
            deadline,
        )
        .map_err(|error| match error {
            crate::deployment::os::runtime::OsRuntimeError::Cancelled => {
                InstallationError::Cancelled
            }
            crate::deployment::os::runtime::OsRuntimeError::Deadline => InstallationError::Deadline,
            _ => InstallationError::Invalid("configuration tree differs from retained generation"),
        })?;
        services.insert(id.into(), directory);
    }
    Ok(services)
}
fn sync_tree(
    root: &OpenedPath,
    depth: usize,
    entries: &mut usize,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<()> {
    check(cancellation, deadline)?;
    if depth > crate::execution::configuration::MAX_CONFIGURATION_DEPTH {
        return Err(InstallationError::Invalid(
            "configuration sync depth exceeded",
        ));
    }
    let names = linux_fd::read_directory(root, |_| {
        check(cancellation, deadline)?;
        *entries += 1;
        if *entries > crate::execution::configuration::MAX_CONFIGURATION_ENTRIES {
            return Err(InstallationError::Invalid(
                "configuration sync entry bound exceeded",
            ));
        }
        Ok(())
    })
    .map_err(directory_error)?;
    for name in names {
        check(cancellation, deadline)?;
        let child = linux_fd::open_beneath(root.fd(), Path::new(&name), false)
            .map_err(storage::open_error)?;
        if child.metadata().file_type() == linux_fd::FileType::Directory {
            if !child.metadata().is_trusted_directory() {
                return Err(InstallationError::Invalid(
                    "configuration sync directory changed",
                ));
            }
            sync_tree(&child, depth + 1, entries, cancellation, deadline)?;
        } else if child.metadata().is_trusted_regular() {
            linux_fd::sync_file(child.fd())?;
        } else {
            return Err(InstallationError::Invalid(
                "configuration sync entry changed",
            ));
        }
    }
    linux_fd::sync_directory(root.fd())?;
    Ok(())
}
fn grouped(
    generation: &RetainedGeneration,
) -> BTreeMap<&str, Vec<&crate::deployment::os::manifest::Config>> {
    let mut groups: BTreeMap<&str, Vec<&crate::deployment::os::manifest::Config>> = BTreeMap::new();
    for config in generation.manifest().configs.values() {
        groups
            .entry(&config.service)
            .or_default()
            .push(config);
    }
    groups
}
fn directory_error(error: linux_fd::ReadDirectoryError<InstallationError>) -> InstallationError {
    match error {
        linux_fd::ReadDirectoryError::Io(error) => error.into(),
        linux_fd::ReadDirectoryError::Admission(error) => error,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::os::{LauncherIdentity, PreparedGeneration};
    use crate::{store::ContentDigest, store::Store};
    use std::fs;
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }
    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    struct Fixture {
        directory: tempfile::TempDir,
        installation: GenerationInstallation,
        generation: RetainedGeneration,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fn unlock(path: &Path) {
                if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
                    chmod(path, 0o700);
                    for entry in fs::read_dir(path).unwrap() {
                        unlock(&entry.unwrap().path());
                    }
                }
            }
            unlock(self.directory.path());
        }
    }
    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let project = directory.path().join("project");
            fs::create_dir(&project).unwrap();
            fs::write(project.join("main.srx"), r#"outputs { os: std::Os = std::Os { pkgs = []; services = [std::Service { id = "git"; files = [std::ConfigFile { path = "nested/config"; text = "controlled"; }]; }, std::Service { id = "empty"; }]; }; }"#).unwrap();
            let checks = crate::project::CheckConfiguration {
                standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
                ..crate::project::CheckConfiguration::default()
            };
            crate::project::lock_project_with(&project, &checks).unwrap();
            let plan =
                crate::project::prepare_project_consumer_with(&project, &checks, "os").unwrap();
            let cancel = Cancellation::default();
            let user = crate::config::UserConfiguration::parse("", directory.path().join("store"))
                .unwrap();
            let consumer = crate::deployment::manifest::prepare_consumer(
                plan,
                "os",
                &user,
                Path::new("unused"),
                true,
                &cancel,
                |_, _| panic!("configuration-only must not build"),
            )
            .unwrap();
            let worker = directory.path().join("worker");
            fs::write(&worker, b"pinned launcher").unwrap();
            let prepared = PreparedGeneration::freeze(
                consumer,
                LauncherIdentity::new(ContentDigest::sha256(b"pinned launcher"), 1).unwrap(),
            )
            .unwrap();
            let store = Store::initialize(user.store()).unwrap();
            let path = directory.path().join("installation");
            fs::create_dir(&path).unwrap();
            chmod(&path, 0o700);
            let installation =
                GenerationInstallation::initialize(&path, &cancel, deadline()).unwrap();
            let generation = installation
                .prepare(&prepared, &store, &worker, &cancel, deadline())
                .unwrap();
            drop(prepared);
            fs::remove_dir_all(project).unwrap();
            fs::remove_file(worker).unwrap();
            Self {
                directory,
                installation,
                generation,
            }
        }
        fn candidate(&self) -> PathBuf {
            self.directory
                .path()
                .join("installation/generations")
                .join(self.generation.digest().to_string())
        }
        fn staging(&self) -> Vec<PathBuf> {
            fs::read_dir(self.candidate())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.file_name()
                        .unwrap()
                        .as_encoded_bytes()
                        .starts_with(STAGING_PREFIX.as_bytes())
                })
                .collect()
        }
    }
    #[test]
    fn configuration_only_generation_publishes_reopens_and_preserves_exact_modes() {
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        let first = fixture
            .installation
            .prepare_configuration(&fixture.generation, &cancel, deadline())
            .unwrap();
        let (_, path) = first.service("git").unwrap();
        let identity = linux_fd::open_top_directory(&path)
            .unwrap()
            .metadata()
            .identity();
        assert_eq!(
            fs::read(path.join("nested/config")).unwrap(),
            b"controlled"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o500
        );
        assert_eq!(
            fs::metadata(path.join("nested/config"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o400
        );
        assert_eq!(
            fs::read_dir(first.service("empty").unwrap().1)
                .unwrap()
                .count(),
            0
        );
        drop(first);
        let owner = GenerationInstallation::open_existing(
            &fixture.directory.path().join("installation"),
            &cancel,
            deadline(),
        )
        .unwrap();
        let reopened = owner
            .open_configuration(&fixture.generation, &cancel, deadline())
            .unwrap();
        assert_eq!(
            linux_fd::open_top_directory(&reopened.service("git").unwrap().1)
                .unwrap()
                .metadata()
                .identity(),
            identity
        );
        owner
            .prepare_configuration(&fixture.generation, &cancel, deadline())
            .unwrap();
        assert!(fixture.staging().is_empty());
    }
    #[test]
    fn changed_bytes_modes_and_inventory_are_conflicts_not_overwritten() {
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        let config = fixture
            .installation
            .prepare_configuration(&fixture.generation, &cancel, deadline())
            .unwrap();
        let path = config.service("git").unwrap().1;
        let file = path.join("nested/config");
        chmod(&file, 0o600);
        fs::write(&file, b"edited____").unwrap();
        chmod(&file, 0o400);
        assert!(
            fixture
                .installation
                .prepare_configuration(&fixture.generation, &cancel, deadline())
                .is_err()
        );
        assert_eq!(fs::read(&file).unwrap(), b"edited____");
        chmod(&file, 0o600);
        fs::write(&file, b"controlled").unwrap();
        assert!(
            fixture
                .installation
                .open_configuration(&fixture.generation, &cancel, deadline())
                .is_err()
        );
        chmod(&file, 0o400);
        chmod(&path, 0o700);
        fs::write(path.join("unknown"), b"keep").unwrap();
        chmod(&path.join("unknown"), 0o400);
        chmod(&path, 0o500);
        assert!(
            fixture
                .installation
                .prepare_configuration(&fixture.generation, &cancel, deadline())
                .is_err()
        );
        assert_eq!(fs::read(path.join("unknown")).unwrap(), b"keep");
    }
    #[test]
    fn cancellation_and_deadline_leave_no_configuration_effects() {
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            fixture
                .installation
                .prepare_configuration(&fixture.generation, &cancel, deadline()),
            Err(InstallationError::Cancelled)
        ));
        assert!(matches!(
            fixture.installation.prepare_configuration(
                &fixture.generation,
                &Cancellation::default(),
                Instant::now()
            ),
            Err(InstallationError::Deadline)
        ));
        assert!(!fixture.candidate().join("configuration").exists());
        assert!(fixture.staging().is_empty());
    }
    #[test]
    fn authority_replacement_and_unprepared_candidate_cannot_publish() {
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        let state = fixture.candidate().join("state");
        let original = fs::read(&state).unwrap();
        let mut record = Record::parse(
            &original,
            fixture.installation.id(),
            fixture.generation.digest(),
        )
        .unwrap();
        record.phase = CandidatePhase::Preparing;
        fs::write(&state, record.bytes().unwrap()).unwrap();
        assert!(
            fixture
                .installation
                .prepare_configuration(&fixture.generation, &cancel, deadline())
                .is_err()
        );
        fs::write(state, original).unwrap();
        let lock = fixture
            .directory
            .path()
            .join("installation/authority.lock");
        fs::rename(&lock, lock.with_extension("saved")).unwrap();
        fs::write(&lock, []).unwrap();
        chmod(&lock, 0o600);
        assert!(
            fixture
                .installation
                .prepare_configuration(&fixture.generation, &cancel, deadline())
                .is_err()
        );
        assert!(!fixture.candidate().join("configuration").exists());
    }
    #[test]
    fn interrupted_staging_is_preserved_and_not_promoted_by_reopening() {
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        linux_fd::fail_next_maintenance_sync();
        assert!(
            fixture
                .installation
                .prepare_configuration(&fixture.generation, &cancel, deadline())
                .is_err()
        );
        let evidence = fixture.staging();
        assert_eq!(evidence.len(), 1);
        assert!(
            fixture
                .installation
                .open_configuration(&fixture.generation, &cancel, deadline())
                .is_err()
        );
        fixture
            .installation
            .prepare_configuration(&fixture.generation, &cancel, deadline())
            .unwrap();
        assert!(evidence[0].exists());
        assert_eq!(fixture.staging(), evidence);
    }
    #[test]
    fn published_handle_refuses_a_replaced_service_inode() {
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        let config = fixture
            .installation
            .prepare_configuration(&fixture.generation, &cancel, deadline())
            .unwrap();
        let path = config.service("git").unwrap().1;
        let root = path.parent().unwrap();
        chmod(root, 0o700);
        fs::rename(&path, root.join("old-git")).unwrap();
        fs::create_dir(&path).unwrap();
        chmod(&path, 0o500);
        chmod(root, 0o500);
        assert!(config.service("git").is_err());
        assert!(
            fixture
                .installation
                .open_configuration(&fixture.generation, &cancel, deadline())
                .is_err()
        );
    }

    #[test]
    fn published_handle_refuses_whole_configuration_moved_outside_installation() {
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        let config = fixture
            .installation
            .prepare_configuration(&fixture.generation, &cancel, deadline())
            .unwrap();
        let visible = fixture.candidate().join("configuration");
        let displaced = fixture
            .directory
            .path()
            .join("displaced-configuration");
        // Simulate an owner changing permissions before moving the directory between parents.
        chmod(&visible, 0o700);
        fs::rename(&visible, &displaced).unwrap();
        chmod(&displaced, 0o500);
        assert!(config.service("git").is_err());
        assert!(
            fixture
                .installation
                .open_configuration(&fixture.generation, &cancel, deadline())
                .is_err()
        );
        assert!(
            fixture
                .directory
                .path()
                .join("displaced-configuration/git/nested/config")
                .exists()
        );
    }
}

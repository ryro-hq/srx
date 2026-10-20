use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use crate::{cancellation::Cancellation, plan::PlanConsumer};

pub(crate) struct SessionFiles {
    directory: Option<tempfile::TempDir>,
    services: BTreeMap<String, File>,
    directories: Vec<File>,
    preserve_on_drop: bool,
    pinned_parent: Option<crate::platform::linux::fd::OpenedPath>,
    visible_path: PathBuf,
    root: Option<File>,
}

fn directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

impl SessionFiles {
    pub fn new(consumer: &PlanConsumer, cancellation: &Cancellation) -> io::Result<Self> {
        cancellation
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        let temporary = tempfile::Builder::new()
            .prefix("syrox-shell-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        Self::populate(consumer, temporary, false, cancellation)
    }

    /// A managed session keeps configuration after coordinator loss. Only an
    /// explicit close, after its callers establish settlement, removes it.
    pub fn new_retained_in(
        consumer: &PlanConsumer,
        parent: &Path,
        cancellation: &Cancellation,
    ) -> io::Result<Self> {
        cancellation
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        let parent = std::path::absolute(parent)?;
        let pinned = crate::platform::linux::fd::open_top_directory(&parent).map_err(|error| {
            io::Error::other(format!(
                "invalid session state directory: {error:?}"
            ))
        })?;
        if !pinned.metadata().is_trusted_directory() || pinned.metadata().mode() & 0o7777 != 0o700 {
            return Err(io::Error::other(
                "session state directory must be owned and mode 0700",
            ));
        }
        // The parent descriptor anchors both creation and eventual cleanup.
        let anchored = PathBuf::from(format!(
            "/proc/self/fd/{}",
            pinned.fd().as_raw_fd()
        ));
        let temporary = tempfile::Builder::new()
            .prefix("configuration-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(anchored)?;
        let visible_path = parent.join(
            temporary
                .path()
                .file_name()
                .expect("temporary basename"),
        );
        Self::populate_at(
            consumer,
            temporary,
            true,
            Some(pinned),
            Some(visible_path),
            cancellation,
        )
    }

    fn populate(
        consumer: &PlanConsumer,
        temporary: tempfile::TempDir,
        preserve_on_drop: bool,
        cancellation: &Cancellation,
    ) -> io::Result<Self> {
        Self::populate_at(
            consumer,
            temporary,
            preserve_on_drop,
            None,
            None,
            cancellation,
        )
    }

    fn populate_at(
        consumer: &PlanConsumer,
        temporary: tempfile::TempDir,
        preserve_on_drop: bool,
        pinned_parent: Option<crate::platform::linux::fd::OpenedPath>,
        visible_path: Option<PathBuf>,
        cancellation: &Cancellation,
    ) -> io::Result<Self> {
        let visible_path = visible_path.unwrap_or_else(|| temporary.path().to_path_buf());
        let mut files = Self {
            directory: Some(temporary),
            services: BTreeMap::new(),
            directories: Vec::new(),
            preserve_on_drop,
            pinned_parent,
            visible_path,
            root: None,
        };
        files.root = Some(directory(
            files
                .directory
                .as_ref()
                .expect("live session")
                .path(),
        )?);
        // Install preservation before the first durability operation can fail.
        if let Some(parent) = &files.pinned_parent {
            crate::platform::linux::fd::sync_directory(parent.fd())?;
        }
        for service in consumer.services() {
            cancellation
                .check()
                .map_err(|_| crate::cancellation::cancellation_io())?;
            let root = files
                .directory
                .as_ref()
                .expect("live session")
                .path()
                .join(service.id());
            fs::create_dir(&root)?;
            let descriptor = directory(&root)?;
            descriptor.set_permissions(fs::Permissions::from_mode(0o700))?;
            files.directories.push(descriptor.try_clone()?);
            files
                .services
                .insert(service.id().to_owned(), descriptor);
            let mut made = BTreeSet::new();
            for config in service.files() {
                cancellation
                    .check()
                    .map_err(|_| crate::cancellation::cancellation_io())?;
                let relative = Path::new(config.path());
                let mut prefix = PathBuf::new();
                if let Some(parent) = relative.parent() {
                    for part in parent.components() {
                        prefix.push(part);
                        if made.insert(prefix.clone()) {
                            let path = root.join(&prefix);
                            fs::create_dir(&path)?;
                            let descriptor = directory(&path)?;
                            descriptor.set_permissions(fs::Permissions::from_mode(0o700))?;
                            files.directories.push(descriptor);
                        }
                    }
                }
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o400)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(root.join(relative))?;
                output.set_permissions(fs::Permissions::from_mode(0o400))?;
                output.write_all(config.text().as_bytes())?;
                if preserve_on_drop {
                    output.sync_all()?;
                }
            }
        }
        for descriptor in &files.directories {
            descriptor.set_permissions(fs::Permissions::from_mode(0o500))?;
        }
        if preserve_on_drop {
            for descriptor in files.directories.iter().rev() {
                descriptor.sync_all()?;
            }
            directory(
                files
                    .directory
                    .as_ref()
                    .expect("live session")
                    .path(),
            )?
            .sync_all()?;
        }
        cancellation
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        Ok(files)
    }
    pub fn path(&self) -> &Path {
        &self.visible_path
    }

    pub fn service(&self, name: &str) -> io::Result<File> {
        self.services
            .get(name)
            .ok_or_else(|| io::Error::other("unknown session service"))?
            .try_clone()
    }

    fn make_removable(&self) -> io::Result<()> {
        let mut failure = None;
        for descriptor in &self.directories {
            if let Err(error) = descriptor.set_permissions(fs::Permissions::from_mode(0o700)) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    pub fn close(mut self) -> io::Result<()> {
        if self.preserve_on_drop {
            let path = self
                .directory
                .as_ref()
                .expect("live session")
                .path();
            let current = directory(path)?.metadata()?;
            let original = self
                .root
                .as_ref()
                .expect("initialized session")
                .metadata()?;
            if (current.dev(), current.ino()) != (original.dev(), original.ino()) {
                return Err(io::Error::other(
                    "session configuration directory was replaced; cleanup pending",
                ));
            }
        }
        self.make_removable()?;
        let directory = self.directory.take().expect("live session");
        if self.preserve_on_drop {
            let path = directory.keep();
            fs::remove_dir_all(&path).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "session configuration cleanup pending at {}: {error}",
                        self.visible_path.display()
                    ),
                )
            })?;
            if let Some(parent) = &self.pinned_parent {
                crate::platform::linux::fd::sync_directory(parent.fd())?;
            }
            Ok(())
        } else {
            directory.close()
        }
    }
}

impl Drop for SessionFiles {
    fn drop(&mut self) {
        if self.preserve_on_drop {
            // Seal only the directories this constructor actually pinned, even
            // when cancellation interrupted construction before its final pass.
            for directory in &self.directories {
                let _ = directory.set_permissions(fs::Permissions::from_mode(0o500));
            }
            if let Some(directory) = self.directory.take() {
                let _ = directory.keep();
            }
            return;
        }
        // Restore only directories opened when this session created them. The
        // descriptor operation cannot chmod an external target substituted later.
        let _ = self.make_removable();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn consumer() -> PlanConsumer {
        let project = tempfile::tempdir().unwrap();
        fs::write(
            project.path().join("main.srx"),
            r#"outputs { shell: std::Shell = std::Shell { pkgs = []; services = [
                std::Service { id = "git"; files = [std::ConfigFile {
                    path = "nested/gitconfig"; text = "[user]\nname = retained\n";
                }]; }
            ]; }; }"#,
        )
        .unwrap();
        let checks = crate::project::CheckConfiguration {
            standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
            ..crate::project::CheckConfiguration::default()
        };
        crate::project::lock_project_with(project.path(), &checks).unwrap();
        let plan = crate::project::prepare_project_consumer_with(project.path(), &checks, "shell")
            .unwrap();
        crate::deployment::manifest::select_consumer(&plan, "shell")
            .unwrap()
            .consumer()
            .clone()
    }

    fn private_parent() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn retained_drop_conserves_bytes_and_readonly_tree() {
        let parent = private_parent();
        let files = SessionFiles::new_retained_in(
            &consumer(),
            parent.path(),
            &Cancellation::default(),
        )
        .unwrap();
        let root = files.path().to_path_buf();
        drop(files);
        for (path, expected) in [
            (root.clone(), 0o700),
            (root.join("git"), 0o500),
            (root.join("git/nested"), 0o500),
            (root.join("git/nested/gitconfig"), 0o400),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o7777,
                expected
            );
        }
        assert_eq!(
            fs::read_to_string(root.join("git/nested/gitconfig")).unwrap(),
            "[user]\nname = retained\n"
        );
        // Test teardown is explicit; dropping the session itself must not do this.
        fs::set_permissions(
            root.join("git"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(
            root.join("git/nested"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_close_removes_retained_configuration() {
        let parent = private_parent();
        let files = SessionFiles::new_retained_in(
            &consumer(),
            parent.path(),
            &Cancellation::default(),
        )
        .unwrap();
        let root = files.path().to_path_buf();
        files.close().unwrap();
        assert!(!root.exists());
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
        assert_eq!(
            fs::metadata(parent.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
    }

    #[test]
    fn permissive_parent_is_rejected_before_creating_configuration() {
        let parent = private_parent();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            SessionFiles::new_retained_in(
                &consumer(),
                parent.path(),
                &Cancellation::default()
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    #[test]
    fn symlink_parent_is_rejected_without_writing_to_target() {
        let parent = private_parent();
        let target = private_parent();
        let link = parent.path().join("state");
        symlink(target.path(), &link).unwrap();
        assert!(
            SessionFiles::new_retained_in(&consumer(), &link, &Cancellation::default()).is_err()
        );
        assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
        assert!(
            fs::symlink_metadata(link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn cancellation_precedes_parent_access_and_leaves_no_configuration() {
        let parent = private_parent();
        let cancellation = Cancellation::default();
        cancellation.cancel();
        let consumer = consumer();
        for path in [
            parent.path().to_path_buf(),
            parent.path().join("absent"),
        ] {
            let error = SessionFiles::new_retained_in(&consumer, &path, &cancellation)
                .err()
                .expect("cancelled preparation must fail");
            assert!(crate::cancellation::is_cancellation_io(&error));
        }
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    #[test]
    fn cancellation_after_directory_creation_keeps_recovery_evidence() {
        let parent = private_parent();
        let temporary = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(parent.path())
            .unwrap();
        let path = temporary.path().to_path_buf();
        let cancellation = Cancellation::default();
        cancellation.cancel();
        let error = SessionFiles::populate(&consumer(), temporary, true, &cancellation)
            .err()
            .expect("cancelled population must fail");
        assert!(crate::cancellation::is_cancellation_io(&error));
        assert!(path.is_dir());
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o700
        );
    }

    #[test]
    fn parent_rename_and_replacement_cannot_redirect_cleanup() {
        let sandbox = private_parent();
        let parent = sandbox.path().join("state");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let files =
            SessionFiles::new_retained_in(&consumer(), &parent, &Cancellation::default()).unwrap();
        let basename = files.path().file_name().unwrap().to_owned();
        let moved = sandbox.path().join("original-state");
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        let replacement = parent.join(&basename);
        fs::create_dir(&replacement).unwrap();
        fs::write(replacement.join("unrelated"), "must survive").unwrap();

        let descriptor = files.service("git").unwrap();
        let anchored = PathBuf::from(format!(
            "/proc/self/fd/{}",
            descriptor.as_raw_fd()
        ));
        assert_eq!(
            fs::read_to_string(anchored.join("nested/gitconfig")).unwrap(),
            "[user]\nname = retained\n"
        );
        files.close().unwrap();
        assert!(!moved.join(basename).exists());
        assert_eq!(
            fs::read_to_string(replacement.join("unrelated")).unwrap(),
            "must survive"
        );
    }

    #[test]
    fn parent_replaced_with_symlink_cannot_redirect_cleanup() {
        let sandbox = private_parent();
        let parent = sandbox.path().join("state");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let files =
            SessionFiles::new_retained_in(&consumer(), &parent, &Cancellation::default()).unwrap();
        let basename = files.path().file_name().unwrap().to_owned();
        let moved = sandbox.path().join("original-state");
        fs::rename(&parent, &moved).unwrap();
        let external = private_parent();
        let replacement = external.path().join(&basename);
        fs::create_dir(&replacement).unwrap();
        fs::write(replacement.join("unrelated"), "must survive").unwrap();
        symlink(external.path(), &parent).unwrap();

        files.close().unwrap();
        assert!(!moved.join(basename).exists());
        assert!(
            fs::symlink_metadata(parent)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(replacement.join("unrelated")).unwrap(),
            "must survive"
        );
    }

    #[test]
    fn replaced_configuration_basename_preserves_both_trees() {
        let parent = private_parent();
        let files = SessionFiles::new_retained_in(
            &consumer(),
            parent.path(),
            &Cancellation::default(),
        )
        .unwrap();
        let original_name = files.path().to_path_buf();
        let moved = parent.path().join("original-configuration");
        fs::rename(&original_name, &moved).unwrap();
        fs::create_dir(&original_name).unwrap();
        fs::write(original_name.join("unrelated"), "must survive").unwrap();

        assert!(
            files.close().is_err(),
            "cleanup must reject a substituted root"
        );
        assert_eq!(
            fs::read_to_string(original_name.join("unrelated")).unwrap(),
            "must survive"
        );
        assert_eq!(
            fs::read_to_string(moved.join("git/nested/gitconfig")).unwrap(),
            "[user]\nname = retained\n"
        );
        assert_eq!(
            fs::metadata(moved.join("git"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o500
        );
        // Explicit teardown of the preserved original evidence.
        fs::set_permissions(
            moved.join("git"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(
            moved.join("git/nested"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
}

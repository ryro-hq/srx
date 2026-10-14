use crate::platform::linux::fd as linux_fd;
use crate::{
    cancellation::Cancellation, config::ShellSecretSources, plan::PlanConsumer,
    runtime::RuntimeConfiguration, runtime::RuntimeError,
};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

#[derive(Default)]
pub(super) struct SessionSecrets(BTreeMap<(String, String), File>);

fn refused() -> io::Error {
    io::Error::other("secret source refused or changed")
}
impl SessionSecrets {
    pub(super) fn snapshot(
        consumer: &PlanConsumer,
        sources: &ShellSecretSources,
        cwd: &Path,
        cancel: &Cancellation,
    ) -> io::Result<Self> {
        let selected = sources
            .for_consumer(consumer)
            .map_err(|_| refused())?;
        let mut files = BTreeMap::new();
        let mut total = 0_u64;
        for service in consumer.services() {
            for name in service.secrets() {
                cancel
                    .check()
                    .map_err(|_| crate::cancellation::cancellation_io())?;
                let path = selected
                    .source(service.id(), name)
                    .ok_or_else(refused)?;
                let file = read_source_bounded(path, cwd, cancel, 4 * 1024 * 1024 - total)
                    .map_err(|e| {
                        if crate::cancellation::is_cancellation_io(&e) {
                            e
                        } else {
                            refused()
                        }
                    })?;
                total += file.metadata()?.len();
                if total > 4 * 1024 * 1024 {
                    return Err(refused());
                }
                files.insert((service.id().to_owned(), name.clone()), file);
            }
        }
        Ok(Self(files))
    }
    pub(super) fn configure(
        &self,
        service: &str,
        mut config: RuntimeConfiguration,
    ) -> Result<RuntimeConfiguration, RuntimeError> {
        for ((owner, name), file) in &self.0 {
            if owner == service {
                config = config.with_secret(service, name, file.as_fd())?;
            }
        }
        Ok(config)
    }
}
impl ShellSecretSources {
    /// Validate only grants selected by this consumer, without reading secret
    /// bytes. Repeated during session snapshot; this is not launch authority.
    pub fn validate_for_consumer(
        &self,
        consumer: &PlanConsumer,
        cwd: &Path,
        cancel: &Cancellation,
    ) -> io::Result<()> {
        let selected = self
            .for_consumer(consumer)
            .map_err(|_| refused())?;
        let mut total = 0_u64;
        for service in consumer.services() {
            for name in service.secrets() {
                cancel
                    .check()
                    .map_err(|_| crate::cancellation::cancellation_io())?;
                let source = Source::open(
                    selected
                        .source(service.id(), name)
                        .ok_or_else(refused)?,
                    cwd,
                )
                .map_err(|_| refused())?;
                total += source.before.len();
                if total > 4 * 1024 * 1024 {
                    return Err(refused());
                }
            }
        }
        Ok(())
    }
}
struct Source {
    parent: linux_fd::OpenedPath,
    file: File,
    path: std::path::PathBuf,
    anchored: std::path::PathBuf,
    before: std::fs::Metadata,
}
impl Source {
    fn open(path: &Path, cwd: &Path) -> io::Result<Self> {
        let cwd = linux_fd::open_top_directory(cwd).map_err(|_| refused())?;
        let cwd_path = linux_fd::directory_path(&cwd)?;
        let parent = linux_fd::open_top_directory(path.parent().ok_or_else(refused)?)
            .map_err(|_| refused())?;
        let name = path.file_name().ok_or_else(refused)?;
        let real = linux_fd::directory_path(&parent)?.join(name);
        if real.starts_with(cwd_path) {
            return Err(refused());
        }
        let anchored = std::path::PathBuf::from(format!(
            "/proc/self/fd/{}",
            parent.fd().as_raw_fd()
        ))
        .join(name);
        let file = open_source(&anchored)?;
        let before = file.metadata()?;
        if !linux_fd::metadata(file.as_fd())?.is_trusted_regular()
            || !matches!(before.mode() & 0o7777, 0o400 | 0o600)
            || before.len() > linux_fd::sealed_file::MAX_SECRET_BYTES
        {
            return Err(refused());
        }
        Ok(Self {
            parent,
            file,
            path: real,
            anchored,
            before,
        })
    }
    fn revalidate(&self) -> io::Result<()> {
        let after = self.file.metadata()?;
        let current = open_source(&self.anchored)?.metadata()?;
        if !same_metadata(&self.before, &after)
            || !same_metadata(&self.before, &current)
            || linux_fd::directory_path(&self.parent)?
                .join(self.path.file_name().ok_or_else(refused)?)
                != self.path
        {
            return Err(refused());
        }
        Ok(())
    }
}
fn open_source(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}
#[cfg(test)]
fn read_source(path: &Path, cwd: &Path, cancel: &Cancellation) -> io::Result<File> {
    read_source_bounded(path, cwd, cancel, 65536)
}
fn read_source_bounded(
    path: &Path,
    cwd: &Path,
    cancel: &Cancellation,
    maximum: u64,
) -> io::Result<File> {
    cancel
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())?;
    let source = Source::open(path, cwd)?;
    if source.before.len() > maximum {
        return Err(refused());
    }
    let snapshot = linux_fd::sealed_file::snapshot(
        source.file.try_clone()?,
        cancel,
        source.before.len(),
    )?;
    source.revalidate()?;
    Ok(snapshot)
}

fn same_metadata(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.nlink() == b.nlink()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().join("work");
        std::fs::create_dir(&cwd).unwrap();
        let source = temp.path().join("source");
        std::fs::write(&source, b"original").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        (temp, source, cwd)
    }
    #[test]
    fn sealed_session_snapshot_survives_rotation_and_closes_without_source_changes() {
        let (_temp, source, cwd) = fixture();
        let cancel = Cancellation::default();
        let first = read_source(&source, &cwd, &cancel).unwrap();
        std::fs::write(&source, b"rotated").unwrap();
        let second = read_source(&source, &cwd, &cancel).unwrap();
        let mut original = String::new();
        first
            .try_clone()
            .unwrap()
            .read_to_string(&mut original)
            .unwrap();
        assert_eq!(original, "original");
        let mut rotated = String::new();
        second
            .try_clone()
            .unwrap()
            .read_to_string(&mut rotated)
            .unwrap();
        assert_eq!(rotated, "rotated");
        assert!(
            first
                .try_clone()
                .unwrap()
                .write_all(b"change")
                .is_err()
        );
        first
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let mut reopen = OpenOptions::new()
            .write(true)
            .open(format!("/proc/self/fd/{}", first.as_raw_fd()))
            .unwrap();
        first
            .set_permissions(std::fs::Permissions::from_mode(0o400))
            .unwrap();
        assert!(reopen.write_all(b"change").is_err());
        assert!(linux_fd::sealed_file::validate(reopen.as_fd()).is_err());
        std::fs::remove_file(&source).unwrap();
        linux_fd::sealed_file::validate(first.as_fd()).unwrap();
    }
    #[test]
    fn source_policy_rejects_exposure_links_modes_capacity_and_cancellation() {
        let (temp, source, cwd) = fixture();
        let cancel = Cancellation::default();
        assert!(read_source(&source, temp.path(), &cancel).is_err());
        for mode in [0o644, 0o700, 0o4600] {
            std::fs::set_permissions(&source, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(read_source(&source, &cwd, &cancel).is_err());
        }
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = temp.path().join("alias");
        symlink(&source, &link).unwrap();
        assert!(read_source(&link, &cwd, &cancel).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::hard_link(&source, &link).unwrap();
        assert!(read_source(&source, &cwd, &cancel).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::write(&source, vec![0; 65537]).unwrap();
        assert!(read_source(&source, &cwd, &cancel).is_err());
        std::fs::write(&source, vec![0; 65536]).unwrap();
        assert!(read_source(&source, &cwd, &cancel).is_ok());
        cancel.cancel();
        assert!(crate::cancellation::is_cancellation_io(
            &read_source(&source, &cwd, &cancel).unwrap_err()
        ));
    }
    #[test]
    fn descriptor_validator_refuses_regular_files_and_source_replacement() {
        let (_temp, source, cwd) = fixture();
        let pinned = Source::open(&source, &cwd).unwrap();
        assert!(linux_fd::sealed_file::validate(pinned.file.as_fd()).is_err());
        std::fs::rename(&source, source.with_extension("old")).unwrap();
        std::fs::write(&source, b"original").unwrap();
        assert!(pinned.revalidate().is_err());
    }

    fn consumer(counts: &[usize]) -> PlanConsumer {
        let project = tempfile::tempdir().unwrap();
        let services = counts
            .iter()
            .enumerate()
            .map(|(service, count)| {
                let names = (0..*count)
                    .map(|n| format!("\"key{n}\""))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("std::Service {{ id = \"service{service}\"; secrets = [{names}]; }}")
            })
            .collect::<Vec<_>>()
            .join(",");
        std::fs::write(project.path().join("main.srx"), format!("outputs {{ shell: std::Shell = std::Shell {{ pkgs = []; services = [{services}]; }}; }}")).unwrap();
        let checks = crate::project::CheckConfiguration {
            standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
            ..crate::project::CheckConfiguration::default()
        };
        crate::project::lock_project_with(project.path(), &checks).unwrap();
        let plan = crate::project::plan_project_with(project.path(), &checks).unwrap();
        plan.consumers().next().unwrap().clone()
    }
    #[test]
    fn snapshots_are_service_scoped_and_unused_global_grants_are_not_opened() {
        let (_temp, source, cwd) = fixture();
        let other = source.with_extension("other");
        std::fs::write(&other, b"other service").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
        let consumer = consumer(&[1, 1]);
        let sources = ShellSecretSources::new([
            ("service0".into(), "key0".into(), source.clone()),
            ("service1".into(), "key0".into(), other),
            (
                "unselected".into(),
                "key0".into(),
                "/not-opened/missing".into(),
            ),
        ])
        .unwrap();
        let cancel = Cancellation::default();
        sources
            .validate_for_consumer(&consumer, &cwd, &cancel)
            .unwrap();
        let secrets = SessionSecrets::snapshot(&consumer, &sources, &cwd, &cancel).unwrap();
        std::fs::write(source, b"rotated").unwrap();
        for (service, expected) in [
            ("service0", "original"),
            ("service1", "other service"),
        ] {
            let config = secrets
                .configure(service, RuntimeConfiguration::default())
                .unwrap();
            // RuntimeConfiguration deliberately does not expose descriptors publicly.
            assert!(!format!("{config:?}").contains(expected));
            assert!(format!("{config:?}").contains("secret_entries: 1"));
            let mut contents = String::new();
            secrets.0[&(service.into(), "key0".into())]
                .try_clone()
                .unwrap()
                .read_to_string(&mut contents)
                .unwrap();
            assert_eq!(contents, expected);
        }
        let empty = secrets
            .configure("missing", RuntimeConfiguration::default())
            .unwrap();
        assert!(format!("{empty:?}").contains("secret_entries: 0"));
        assert_eq!(secrets.0.len(), 2);
    }
    #[test]
    fn aggregate_limit_is_checked_before_snapshot_and_again_during_snapshot() {
        let (_temp, source, cwd) = fixture();
        std::fs::write(&source, vec![0; 65536]).unwrap();
        let cancel = Cancellation::default();
        for (counts, accepted) in [
            ([32, 32, 0], true),
            ([32, 32, 1], false),
        ] {
            let consumer = consumer(&counts);
            let sources = ShellSecretSources::new(counts.iter().enumerate().flat_map(
                |(service, count)| {
                    let source = source.clone();
                    (0..*count).map(move |key| {
                        (
                            format!("service{service}"),
                            format!("key{key}"),
                            source.clone(),
                        )
                    })
                },
            ))
            .unwrap();
            assert_eq!(
                sources
                    .validate_for_consumer(&consumer, &cwd, &cancel)
                    .is_ok(),
                accepted
            );
            assert_eq!(
                SessionSecrets::snapshot(&consumer, &sources, &cwd, &cancel).is_ok(),
                accepted
            );
        }
    }
}

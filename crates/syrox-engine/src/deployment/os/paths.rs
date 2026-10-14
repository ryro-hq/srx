use crate::platform::linux::fd::{self as linux_fd, FileIdentity, OpenedPath};
use crate::{cancellation::Cancellation, execution::resources};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

#[derive(Debug, thiserror::Error)]
pub(crate) enum OsPathsError {
    #[error("invalid Os execution paths: {0}")]
    Invalid(&'static str),
    #[error("Os execution path observation cancelled")]
    Cancelled,
    #[error("Os execution path observation deadline expired")]
    Deadline,
    #[error(transparent)]
    Io(#[from] io::Error),
}
type Result<T> = std::result::Result<T, OsPathsError>;

#[derive(Debug)]
struct Directory {
    path: PathBuf,
    opened: OpenedPath,
    identity: FileIdentity,
}
impl Directory {
    fn open(path: &Path, cancel: &Cancellation, deadline: Instant) -> Result<Self> {
        check(cancel, deadline)?;
        let path = normalized(path)?;
        let opened = linux_fd::open_top_directory(&path).map_err(open_error)?;
        check(cancel, deadline)?;
        if linux_fd::directory_path(&opened)? != path {
            return Err(OsPathsError::Invalid(
                "directory spelling or identity changed",
            ));
        }
        let identity = opened.metadata().identity();
        Ok(Self {
            path,
            opened,
            identity,
        })
    }
    fn revalidate(&self, cancel: &Cancellation, deadline: Instant) -> Result<()> {
        check(cancel, deadline)?;
        let current = linux_fd::open_top_directory(&self.path).map_err(open_error)?;
        if current.metadata().identity() != self.identity
            || linux_fd::directory_path(&self.opened)? != self.path
        {
            return Err(OsPathsError::Invalid(
                "selected directory was renamed or replaced",
            ));
        }
        check(cancel, deadline)
    }
}

#[derive(Debug)]
pub(crate) struct OsExecutionPaths {
    installation: Directory,
    store: Directory,
    cwd: Directory,
}
impl OsExecutionPaths {
    pub(crate) fn open(
        installation: &Path,
        store: &Path,
        cwd: &Path,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        check(cancellation, deadline)?;
        // Reject lexical conflicts before opening any directory.
        let paths = [
            normalized(installation)?,
            normalized(store)?,
            normalized(cwd)?,
        ];
        separated(&paths)?;
        if !resources::valid_managed_working_directory(&paths[2]) {
            return Err(OsPathsError::Invalid(
                "working directory overlaps managed filesystems",
            ));
        }
        let selected = Self {
            installation: Directory::open(&paths[0], cancellation, deadline)?,
            store: Directory::open(&paths[1], cancellation, deadline)?,
            cwd: Directory::open(&paths[2], cancellation, deadline)?,
        };
        selected.revalidate(cancellation, deadline)?;
        Ok(selected)
    }
    pub(crate) fn installation(&self) -> &Path {
        &self.installation.path
    }
    pub(crate) fn store(&self) -> &Path {
        &self.store.path
    }
    pub(crate) fn cwd(&self) -> &Path {
        &self.cwd.path
    }

    pub(crate) fn revalidate(&self, cancellation: &Cancellation, deadline: Instant) -> Result<()> {
        let directories = [
            &self.installation,
            &self.store,
            &self.cwd,
        ];
        for directory in directories {
            directory.revalidate(cancellation, deadline)?;
        }
        separated(&directories.map(|directory| directory.path.clone()))?;
        for left in 0..directories.len() {
            for right in left + 1..directories.len() {
                if directories[left].identity == directories[right].identity {
                    return Err(OsPathsError::Invalid(
                        "selected directories alias the same inode",
                    ));
                }
            }
        }
        if !resources::valid_managed_working_directory(self.cwd()) {
            return Err(OsPathsError::Invalid(
                "working directory overlaps managed filesystems",
            ));
        }
        resources::validate_managed_working_descriptor(self.cwd.opened.fd())?;
        check(cancellation, deadline)
    }
}
fn separated(paths: &[PathBuf; 3]) -> Result<()> {
    for left in 0..paths.len() {
        for right in left + 1..paths.len() {
            if paths[left].starts_with(&paths[right]) || paths[right].starts_with(&paths[left]) {
                return Err(OsPathsError::Invalid(
                    "installation, Store and cwd must not overlap",
                ));
            }
        }
    }
    Ok(())
}
fn normalized(path: &Path) -> Result<PathBuf> {
    let text = path
        .to_str()
        .ok_or(OsPathsError::Invalid("path is not UTF-8"))?;
    if text.is_empty()
        || text.len() > 4096
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(OsPathsError::Invalid(
            "path must be bounded and contain no parent traversal or controls",
        ));
    }
    let absolute = std::path::absolute(path)?;
    let normalized: PathBuf = absolute.components().collect();
    let absolute_text = normalized.to_str().ok_or(OsPathsError::Invalid(
        "absolute path is not UTF-8",
    ))?;
    if absolute_text.len() > 4096 || absolute_text.chars().any(char::is_control) {
        return Err(OsPathsError::Invalid(
            "absolute path exceeds bound or contains controls",
        ));
    }
    Ok(normalized)
}
fn check(cancel: &Cancellation, deadline: Instant) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(OsPathsError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(OsPathsError::Deadline);
    }
    Ok(())
}
fn open_error(error: linux_fd::OpenError) -> OsPathsError {
    match error {
        linux_fd::OpenError::Symlink => OsPathsError::Invalid("directory path traverses a symlink"),
        linux_fd::OpenError::Other(error) | linux_fd::OpenError::Unsupported(error) => error.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    fn fixture() -> (tempfile::TempDir, [PathBuf; 3]) {
        let temp = tempfile::tempdir().unwrap();
        let paths = ["installation", "store", "work"].map(|name| temp.path().join(name));
        for path in &paths {
            fs::create_dir(path).unwrap();
        }
        (temp, paths)
    }
    fn open(paths: &[PathBuf; 3]) -> Result<OsExecutionPaths> {
        OsExecutionPaths::open(
            &paths[0],
            &paths[1],
            &paths[2],
            &Cancellation::default(),
            deadline(),
        )
    }

    #[test]
    fn accepts_disjoint_directories_without_initializing_them() {
        let (_temp, paths) = fixture();
        let selected = open(&paths).unwrap();
        assert_eq!(selected.installation(), paths[0]);
        assert_eq!(selected.store(), paths[1]);
        assert_eq!(selected.cwd(), paths[2]);
        selected
            .revalidate(&Cancellation::default(), deadline())
            .unwrap();
        for path in &paths {
            assert_eq!(fs::read_dir(path).unwrap().count(), 0);
        }
        let decorated = paths.clone().map(|path| path.join("."));
        assert_eq!(open(&decorated).unwrap().cwd(), paths[2]);
    }

    #[test]
    fn rejects_equal_and_nested_directories_for_every_pair_and_direction() {
        let (_temp, paths) = fixture();
        for left in 0..3 {
            for right in 0..3 {
                if left == right {
                    continue;
                }
                let mut equal = paths.clone();
                equal[right] = equal[left].clone();
                assert!(open(&equal).is_err());
                let mut nested = paths.clone();
                nested[right] = nested[left].join("child");
                // A missing child cannot distract from the pre-I/O overlap check.
                assert!(matches!(
                    open(&nested),
                    Err(OsPathsError::Invalid(
                        "installation, Store and cwd must not overlap"
                    ))
                ));
                assert!(!nested[right].exists());
            }
        }
    }

    #[test]
    fn rejects_symlink_at_any_role_and_in_a_parent() {
        let (temp, paths) = fixture();
        for index in 0..3 {
            let link = temp.path().join(format!("link-{index}"));
            std::os::unix::fs::symlink(&paths[index], &link).unwrap();
            let mut candidate = paths.clone();
            candidate[index] = link;
            assert!(open(&candidate).is_err());
        }
        let parent = temp.path().join("parent-link");
        std::os::unix::fs::symlink(temp.path(), &parent).unwrap();
        let mut candidate = paths.clone();
        candidate[2] = parent.join("work");
        assert!(open(&candidate).is_err());
    }

    #[test]
    fn pinned_handles_refuse_rename_and_replacement_in_every_role() {
        for index in 0..3 {
            let (temp, paths) = fixture();
            let selected = open(&paths).unwrap();
            let moved = temp.path().join("moved");
            fs::rename(&paths[index], &moved).unwrap();
            assert!(
                selected
                    .revalidate(&Cancellation::default(), deadline())
                    .is_err()
            );
            fs::create_dir(&paths[index]).unwrap();
            fs::write(paths[index].join("replacement"), b"preserve").unwrap();
            assert!(
                selected
                    .revalidate(&Cancellation::default(), deadline())
                    .is_err()
            );
            assert!(moved.is_dir());
            assert_eq!(
                fs::read(paths[index].join("replacement")).unwrap(),
                b"preserve"
            );
        }
    }

    #[test]
    fn cancellation_deadline_and_missing_paths_never_initialize_state() {
        let (temp, paths) = fixture();
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            OsExecutionPaths::open(
                &paths[0],
                &paths[1],
                &paths[2],
                &cancel,
                deadline()
            ),
            Err(OsPathsError::Cancelled)
        ));
        assert!(matches!(
            OsExecutionPaths::open(
                &paths[0],
                &paths[1],
                &paths[2],
                &Cancellation::default(),
                Instant::now()
            ),
            Err(OsPathsError::Deadline)
        ));
        let selected = open(&paths).unwrap();
        assert!(matches!(
            selected.revalidate(&cancel, deadline()),
            Err(OsPathsError::Cancelled)
        ));
        let mut absent = paths.clone();
        absent[1] = temp.path().join("absent");
        assert!(open(&absent).is_err());
        assert!(!absent[1].exists());
    }

    #[test]
    fn rejects_reserved_cwd_and_unbounded_or_ambiguous_spelling() {
        let (_temp, paths) = fixture();
        for cwd in [
            "/",
            "/tmp",
            "/proc",
            "/proc/self",
            "/dev",
            "/sys/fs/cgroup",
        ] {
            let mut candidate = paths.clone();
            candidate[2] = cwd.into();
            assert!(open(&candidate).is_err());
        }
        for text in [
            "",
            "/tmp/../work",
            "/tmp/control\n",
            "/tmp/control\0",
            "/tmp/control\u{85}",
        ] {
            assert!(normalized(Path::new(text)).is_err());
        }
        assert!(normalized(Path::new(&format!("/{}", "a".repeat(4096)))).is_err());
        assert!(normalized(Path::new(".")).unwrap().is_absolute());
    }
}

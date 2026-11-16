use super::{changed, linux_fd};
use crate::{
    cancellation::Cancellation,
    result::artifact::{ArtifactLimits, relative_path, resolve_alias},
};
use std::{
    collections::BTreeMap,
    fs::{File, Metadata},
    io,
    os::fd::AsFd as _,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    device: u64,
    inode: u64,
    links: u64,
    uid: u32,
    gid: u32,
    pub size: u64,
    pub mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Snapshot {
    fn new(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            links: m.nlink(),
            uid: m.uid(),
            gid: m.gid(),
            size: m.len(),
            mode: m.mode(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
    pub fn matches(&self, m: &Metadata) -> bool {
        self == &Self::new(m)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub path: String,
    pub alias: Option<String>,
    pub snapshot: Snapshot,
}

#[derive(Debug)]
pub(super) struct Tree {
    pub files: Vec<Entry>,
    directories: Vec<(String, Snapshot)>,
    pub size: u64,
    pub expanded_bytes: u64,
    pub entries: usize,
    limits: ArtifactLimits,
}

impl Tree {
    pub fn capture(
        root: &File,
        limits: ArtifactLimits,
        cancellation: &Cancellation,
    ) -> io::Result<Self> {
        linux_fd::require_readonly(root.as_fd())?;
        let root_metadata = root.metadata()?;
        if !root_metadata.is_dir() || root_metadata.mode() & 0o7000 != 0 {
            return Err(changed());
        }
        let mut pending = vec![PathBuf::from(".")];
        let mut directories = Vec::new();
        let mut files = Vec::new();
        // Charge the root, empty directories, regular files and aliases alike.
        let mut visited = 1_usize;
        if visited > limits.files {
            return Err(changed());
        }
        while let Some(path) = pending.pop() {
            cancelled(cancellation)?;
            let opened = linux_fd::open_beneath_no_mounts(root.as_fd(), &path, true)
                .map_err(|_| changed())?;
            let directory = linux_fd::tree::Directory::from_fd(opened.fd())?;
            let metadata = File::from(opened.fd().try_clone_to_owned()?).metadata()?;
            let snapshot = Snapshot::new(&metadata);
            if metadata.dev() != root_metadata.dev() || metadata.mode() & 0o7000 != 0 {
                return Err(changed());
            }
            let names = linux_fd::read_directory(&opened, |_| {
                cancelled(cancellation)?;
                visited = visited
                    .checked_add(1)
                    .filter(|n| *n <= limits.files)
                    .ok_or_else(changed)?;
                Ok(())
            })
            .map_err(|e| match e {
                linux_fd::ReadDirectoryError::Io(e)
                | linux_fd::ReadDirectoryError::Admission(e) => e,
            })?;
            for name in names {
                cancelled(cancellation)?;
                let relative = if path == Path::new(".") {
                    PathBuf::from(&name)
                } else {
                    path.join(&name)
                };
                let relative_text = relative
                    .to_str()
                    .filter(|s| relative_path(s))
                    .ok_or_else(changed)?;
                let m = directory.metadata(&name)?.ok_or_else(changed)?;
                if m.dev() != root_metadata.dev() || m.mode() & 0o7000 != 0 {
                    return Err(changed());
                }
                if m.is_dir() {
                    pending.push(relative);
                    continue;
                }
                let alias = if m.is_symlink() && m.nlink() == 1 {
                    let target = directory.read_link(&name)?;
                    let target = target.to_str().ok_or_else(changed)?;
                    resolve_alias(relative_text, target).ok_or_else(changed)?;
                    Some(target.to_owned())
                } else if m.is_file() && m.nlink() == 1 {
                    None
                } else {
                    return Err(changed());
                };
                files.push(Entry {
                    path: relative_text.to_owned(),
                    alias,
                    snapshot: Snapshot::new(&m),
                });
            }
            if !snapshot.matches(&File::from(opened.fd().try_clone_to_owned()?).metadata()?) {
                return Err(changed());
            }
            directories.push((
                path.to_str().ok_or_else(changed)?.to_owned(),
                snapshot,
            ));
        }
        if files.is_empty() {
            return Err(changed());
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        directories.sort_by(|a, b| a.0.cmp(&b.0));
        let by_path = files
            .iter()
            .map(|e| (e.path.as_str(), e))
            .collect::<BTreeMap<_, _>>();
        let mut size = super::artifact::HEADER.len() as u64 + 4;
        let mut expanded = 0_u64;
        for entry in &files {
            let (payload, expansion) = if let Some(target) = &entry.alias {
                let resolved = resolve_alias(&entry.path, target).ok_or_else(changed)?;
                let destination = by_path
                    .get(resolved.as_str())
                    .filter(|e| e.alias.is_none())
                    .ok_or_else(changed)?;
                (target.len() as u64, destination.snapshot.size)
            } else {
                (entry.snapshot.size, entry.snapshot.size)
            };
            size = size
                .checked_add(11 + entry.path.len() as u64)
                .and_then(|n| n.checked_add(payload))
                .filter(|n| *n <= limits.bytes)
                .ok_or_else(changed)?;
            expanded = expanded
                .checked_add(expansion)
                .filter(|n| *n <= limits.expanded_bytes)
                .ok_or_else(changed)?;
        }
        cancelled(cancellation)?;
        Ok(Self {
            files,
            directories,
            size,
            expanded_bytes: expanded,
            entries: visited,
            limits,
        })
    }

    pub fn revalidate(&self, root: &File, cancellation: &Cancellation) -> io::Result<()> {
        let observed = Self::capture(root, self.limits, cancellation)?;
        if self.files != observed.files
            || self.directories != observed.directories
            || self.size != observed.size
        {
            return Err(changed());
        }
        Ok(())
    }
}

fn cancelled(cancellation: &Cancellation) -> io::Result<()> {
    cancellation
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())
}

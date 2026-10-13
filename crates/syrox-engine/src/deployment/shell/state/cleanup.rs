use super::{SessionState, anchored, checked, invalid};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{fs, io};

const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 32;
pub(super) struct Entry {
    path: PathBuf,
    identity: (u64, u64),
    directory: bool,
}

pub(super) fn scan(
    state: &SessionState,
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<Vec<Entry>> {
    let mut result = Vec::new();
    let mut pending = state
        .services
        .keys()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    while let Some(relative) = pending.pop() {
        checked(cancel, deadline)?;
        if relative.components().count() > MAX_DEPTH {
            return Err(invalid());
        }
        let directory = linux_fd::open_beneath_no_mounts(state.root.fd(), &relative, true)
            .map_err(|_| invalid())?;
        let mut count = result.len();
        let names = linux_fd::read_directory(&directory, |_| {
            checked(cancel, deadline)?;
            count += 1;
            if count > MAX_ENTRIES {
                Err(invalid())
            } else {
                Ok(())
            }
        })
        .map_err(|_| invalid())?;
        if result.len() + names.len() > MAX_ENTRIES {
            return Err(invalid());
        }
        for name in names {
            let path = relative.join(&name);
            let metadata = fs::symlink_metadata(anchored(&directory, Path::new(&name)))?;
            if metadata.uid() != linux_fd::effective_uid() {
                return Err(invalid());
            }
            let is_directory = metadata.is_dir();
            if is_directory {
                // Reject a mount before ever enumerating its contents.
                linux_fd::open_beneath_no_mounts(state.root.fd(), &path, true)
                    .map_err(|_| invalid())?;
                pending.push(path.clone());
            }
            result.push(Entry {
                path,
                identity: (metadata.dev(), metadata.ino()),
                directory: is_directory,
            });
        }
    }
    Ok(result)
}

pub(super) fn remove(
    state: &SessionState,
    mut entries: Vec<Entry>,
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<()> {
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.path.components().count()));
    for entry in entries {
        checked(cancel, deadline)?;
        let parent = linux_fd::open_beneath_no_mounts(
            state.root.fd(),
            entry.path.parent().ok_or_else(invalid)?,
            true,
        )
        .map_err(|_| invalid())?;
        let path = anchored(
            &parent,
            Path::new(entry.path.file_name().ok_or_else(invalid)?),
        );
        let metadata = fs::symlink_metadata(&path)?;
        if (metadata.dev(), metadata.ino()) != entry.identity
            || metadata.is_dir() != entry.directory
        {
            return Err(invalid());
        }
        if entry.directory {
            linux_fd::open_beneath_no_mounts(state.root.fd(), &entry.path, true)
                .map_err(|_| invalid())?;
            fs::remove_dir(path)?;
        } else {
            // unlink never follows a final symlink and does not modify the
            // contents of a hard-linked file or a socket/FIFO target.
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

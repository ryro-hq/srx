//! Compilation storage is shared by environment and lock, independently of
//! immutable source evidence. Entry leases exclude active builds from eviction.
use super::{Result, process::Control, snapshot::valid_digest};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub const COMPILATION_LIMIT: u64 = 32 * 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_FILES: usize = 2_000_000;

#[derive(Debug)]
pub struct EntryLease {
    // The lock remains held until the guest and its compilation children exit.
    _file: File,
    pub directory: PathBuf,
}

impl EntryLease {
    /// A lost SDK cleanup reply must remain protected after the host exits.
    pub fn mark_active(&self) -> Result<()> {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(self.directory.join(".active"))?;
        file.sync_all()?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
    pub fn confirm_inactive(&self) -> Result<()> {
        fs::remove_file(self.directory.join(".active"))?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

fn lease_file(directory: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join(".lease"))?)
}

pub fn acquire(root: &Path, key: &str, control: &Control) -> Result<EntryLease> {
    control.check()?;
    if !valid_digest(key) {
        return Err("invalid compilation environment key".into());
    }
    super::common::private(root)?;
    let directory = root.join(key);
    if directory.exists() && !fs::symlink_metadata(&directory)?.is_dir() {
        return Err("compilation entry is not a directory".into());
    }
    super::common::private(&directory)?;
    if fs::symlink_metadata(directory.join(".active")).is_ok() {
        return Err(
            "previous VM cleanup is unconfirmed; compilation entry remains protected".into(),
        );
    }
    let file = lease_file(&directory)?;
    let started = std::time::Instant::now();
    loop {
        control.check()?;
        match file.try_lock() {
            Ok(()) => break,
            Err(fs::TryLockError::WouldBlock) if started.elapsed() < Duration::from_mins(5) => {
                std::thread::sleep(Duration::from_millis(40));
            }
            Err(error) => return Err(format!("compilation entry busy: {error}").into()),
        }
    }
    let used = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join(".used"))?;
    used.set_modified(SystemTime::now())?;
    Ok(EntryLease {
        _file: file,
        directory,
    })
}

/// Count paths without following links. Counting hard links separately is a
/// conservative bound and cannot undercount compilation storage.
pub fn bytes(root: &Path, control: &Control) -> Result<u64> {
    if !root.exists() {
        return Ok(0);
    }
    let mut pending = vec![(root.to_path_buf(), 0)];
    let mut count = 0_usize;
    let mut bytes = 0_u64;
    while let Some((path, depth)) = pending.pop() {
        control.check()?;
        count += 1;
        if count > MAX_FILES || depth > 256 {
            return Err("compilation cache inventory limit".into());
        }
        let metadata = fs::symlink_metadata(&path)?;
        bytes = bytes
            .checked_add(
                metadata
                    .len()
                    .max(metadata.blocks().saturating_mul(512)),
            )
            .ok_or("cache size overflow")?;
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push((entry?.path(), depth + 1));
            }
        }
    }
    Ok(bytes)
}

/// Caller serializes the namespace with execution.lock. Every removed entry
/// must additionally have an exclusive lease, so concurrent consumers survive.
pub fn prune(root: &Path, limit: u64, control: &Control) -> Result<serde_json::Value> {
    super::common::private(root)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(root)? {
        control.check()?;
        let entry = entry?;
        if entries.len() >= MAX_ENTRIES
            || !entry.file_type()?.is_dir()
            || !entry
                .file_name()
                .to_str()
                .is_some_and(valid_digest)
        {
            return Err("unexpected compilation cache entry".into());
        }
        let directory = entry.path();
        let used = fs::metadata(directory.join(".used"))
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        entries.push((
            used,
            directory.clone(),
            bytes(&directory, control)?,
        ));
    }
    entries.sort();
    let mut total = entries.iter().try_fold(0_u64, |sum, entry| {
        sum.checked_add(entry.2)
            .ok_or("cache size overflow")
    })?;
    let before = total;
    let mut removed = Vec::new();
    for (_, directory, size) in entries {
        if total <= limit {
            break;
        }
        control.check()?;
        if fs::symlink_metadata(directory.join(".active")).is_ok() {
            continue;
        }
        let file = lease_file(&directory)?;
        match file.try_lock() {
            Ok(()) => {
                // remove_dir_all does not traverse symlinks inside the tree.
                fs::remove_dir_all(&directory)?;
                removed.push(
                    directory
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or("cache name")?
                        .to_owned(),
                );
                total -= size;
            }
            Err(fs::TryLockError::WouldBlock) => {}
            Err(error) => return Err(error.into()),
        }
    }
    if total > limit {
        return Err(
            format!("active compilation cache exceeds global quota: {total} > {limit}").into(),
        );
    }
    Ok(
        serde_json::json!({"before_bytes":before,"after_bytes":total,"limit_bytes":limit,"removed":removed}),
    )
}

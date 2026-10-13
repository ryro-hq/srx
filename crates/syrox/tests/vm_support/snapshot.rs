use super::{Result, common::private};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::process::Command;

pub fn digest(path: &Path) -> Result<String> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() {
        return Err(format!("expected regular file: {}", path.display()).into());
    }
    let mut stream = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !same_file(&before, &stream.metadata()?) {
        return Err("input changed before hashing".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 65536];
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let after = fs::symlink_metadata(path)?;
    if !same_file(&before, &after) || !same_file(&before, &stream.metadata()?) {
        return Err(format!("input changed while reading: {}", path.display()).into());
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Copy a bounded regular candidate once, refusing links and overwritten evidence.
pub fn copy_candidate(source: &Path, destination: &Path, maximum: u64) -> Result<String> {
    let before = fs::symlink_metadata(source)?;
    if !before.is_file() || before.len() > maximum {
        return Err(format!(
            "candidate must be a bounded regular file: {}",
            source.display()
        )
        .into());
    }
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    if !same_file(&before, &input.metadata()?) {
        return Err("candidate changed before copying".into());
    }
    let parent = destination
        .parent()
        .ok_or("candidate destination parent")?;
    if fs::symlink_metadata(destination).is_ok() {
        return Err("candidate evidence already exists".into());
    }
    // Unpublished copies disappear on every error, including a concurrent
    // rebuild replacing or extending the source. Publication refuses overwrite.
    let mut output = tempfile::Builder::new()
        .prefix(".candidate-")
        .tempfile_in(parent)?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0; 65536];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .filter(|size| *size <= maximum)
            .ok_or("candidate grew beyond its byte limit")?;
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    let pin = format!("{:x}", hash.finalize());
    if total != before.len()
        || !same_file(&before, &input.metadata()?)
        || !same_file(&before, &fs::symlink_metadata(source)?)
        || digest(source)? != pin
    {
        return Err("candidate changed while copying".into());
    }
    output
        .as_file()
        .set_permissions(fs::Permissions::from_mode(
            if before.mode() & 0o111 == 0 {
                0o400
            } else {
                0o500
            },
        ))?;
    output.as_file().sync_all()?;
    output
        .persist_noclobber(destination)
        .map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(pin)
}

fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.is_file()
        && b.is_file()
        && a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mode() == b.mode()
        && (
            a.mtime(),
            a.mtime_nsec(),
            a.ctime(),
            a.ctime_nsec(),
        ) == (
            b.mtime(),
            b.mtime_nsec(),
            b.ctime(),
            b.ctime_nsec(),
        )
}

pub fn verify_files(root: &Path, expected: &BTreeMap<String, String>) -> Result<()> {
    for (name, pin) in expected {
        if digest(&root.join(name))? != *pin {
            return Err(format!("pinned input changed: {name}").into());
        }
    }
    Ok(())
}

/// Capture tracked and new files, including dirty bytes. Git deletions stay absent.
/// Build products, operational state and VCS internals never enter the guest.
pub fn snapshot(root: &Path, destination: &Path) -> Result<Value> {
    let listing = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()?;
    if !listing.status.success() {
        return Err("git source inventory failed".into());
    }
    let mut names = BTreeSet::new();
    for name in listing
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        names.insert(String::from_utf8(name.to_vec())?);
    }
    private(destination)?;
    let mut files = BTreeMap::new();
    for name in names {
        let path = Path::new(&name);
        if path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err("source path escapes checkout".into());
        }
        if path.components().any(|part| {
            matches!(
                part.as_os_str().to_str(),
                Some("target" | ".git" | ".syrox" | "__pycache__")
            )
        }) {
            continue;
        }
        let source = root.join(path);
        let metadata = match fs::symlink_metadata(&source) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() {
            return Err(format!("source must be a regular file: {name}").into());
        }
        // Also refuse symlinked ancestors rather than importing external bytes.
        if source.canonicalize()? != source {
            return Err(format!("source has linked ancestor: {name}").into());
        }
        let pin = digest(&source)?;
        let copied = destination.join(path);
        fs::create_dir_all(copied.parent().ok_or("source parent")?)?;
        fs::copy(&source, &copied)?;
        if digest(&copied)? != pin || digest(&source)? != pin {
            return Err("source changed during snapshot".into());
        }
        fs::set_permissions(
            &copied,
            fs::Permissions::from_mode(if metadata.permissions().mode() & 0o111 == 0 {
                0o444
            } else {
                0o555
            }),
        )?;
        files.insert(name, pin);
    }
    // Recheck all captured files as a set before freezing the directory tree.
    verify_files(root, &files)?;
    freeze_directories(destination)?;
    let hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&files)?)
    );
    let revision = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()?;
    Ok(
        json!({"sha256":hash,"files":files,"head":String::from_utf8_lossy(&revision.stdout).trim(),
        "scope":"captured working tree bytes; includes local modifications and new files"}),
    )
}

fn freeze_directories(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            freeze_directories(&entry.path())?;
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o555))?;
    Ok(())
}

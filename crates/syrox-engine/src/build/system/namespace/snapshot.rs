use crate::store::ContentDigest;
use crate::{build::BuildError, cancellation::Cancellation};
use sha2::{Digest as _, Sha256};
use std::os::unix::fs::FileExt as _;
use std::{
    fs::File,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

pub(super) fn verify(
    file: &std::os::fd::OwnedFd,
    expected: ContentDigest,
    maximum: u64,
    cancellation: &Cancellation,
) -> Result<(), BuildError> {
    let file = File::from(file.try_clone()?);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(BuildError::InputChanged);
    }
    let mut hash = Sha256::new();
    let mut position = 0_u64;
    let mut buffer = vec![0; 64 * 1024];
    loop {
        cancellation.check()?;
        let count = match file.read_at(&mut buffer, position) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        position = position
            .checked_add(count as u64)
            .ok_or(BuildError::InputChanged)?;
        if position > maximum {
            return Err(BuildError::InputChanged);
        }
        hash.update(&buffer[..count]);
    }
    if position != metadata.len()
        || ContentDigest::from_sha256_hash(hash.finalize().into()) != expected
    {
        return Err(BuildError::InputChanged);
    }
    Ok(())
}

/// Private regular-file snapshots, retained by their namespace resource owner.
/// Keep their protected directory until the nonrecursive binds are established;
/// inherited `f_paths` must be reopened with the same inode in the new namespace.
/// Content is rehashed before gate readiness and again by the payload entry.
pub(super) fn bytes(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    mode: u32,
    cancellation: &Cancellation,
) -> Result<File, BuildError> {
    cancellation.check()?;
    if bytes.len() > 128 * 1024 * 1024
        || !matches!(mode, 0o400 | 0o500)
        || !matches!(name, "action" | "program" | "worker" | "policy")
    {
        return Err(BuildError::InvalidRequest);
    }
    let path = directory.join(name);
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    for chunk in bytes.chunks(64 * 1024) {
        cancellation.check()?;
        file.write_all(chunk)?;
    }
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    drop(file);
    let readonly = File::open(path)?;
    cancellation.check()?;
    Ok(readonly)
}

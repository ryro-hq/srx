use super::{CatalogError, model::MAX_BYTES};
use std::{
    fs,
    io::Read as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Component, Path},
};

pub(super) fn invalid(message: impl Into<String>) -> CatalogError {
    CatalogError::Invalid(message.into())
}

pub(super) fn bounded_file(root: &Path, name: &str) -> Result<Vec<u8>, CatalogError> {
    let path = Path::new(name);
    if path.as_os_str().is_empty()
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(invalid(
            "catalog paths must be relative without traversal",
        ));
    }
    let mut full = root.to_path_buf();
    for part in path.components() {
        full.push(part);
        if fs::symlink_metadata(&full)?
            .file_type()
            .is_symlink()
        {
            return Err(invalid("catalog paths cannot contain symlinks"));
        }
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(full)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("catalog input is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("catalog input exceeds byte limit"));
    }
    Ok(bytes)
}

pub(super) fn component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(super) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

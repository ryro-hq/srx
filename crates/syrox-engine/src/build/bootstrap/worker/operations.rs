//! Bounded transformations inside the already confined build worker.
use super::BuildError;
use crate::platform::linux::fd::tree::Directory;
use std::{fs::Metadata, io::Read as _, os::unix::fs::MetadataExt as _, path::Path};

const MAXIMUM: u64 = 128 * 1024 * 1024;

fn unchanged(a: &Metadata, b: &Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.len(),
        a.mode(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.len(),
        b.mode(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
    )
}

fn read(
    path: &Path,
    executable: bool,
) -> Result<(Directory, std::ffi::OsString, Metadata, Vec<u8>), BuildError> {
    let (parent, name) = Directory::parent(path)?;
    let file = parent.read_file(&name)?;
    let before = file.metadata()?;
    if before.len() > MAXIMUM
        || before.mode() & 0o7000 != 0
        || (executable && before.mode() & 0o111 == 0)
    {
        return Err(BuildError::InvalidRequest);
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAXIMUM + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len() || !unchanged(&before, &file.metadata()?) {
        return Err(BuildError::InvalidRequest);
    }
    Ok((parent, name, before, bytes))
}

pub(super) fn validate_static_elf(path: &Path) -> Result<(), BuildError> {
    let (_, _, _, bytes) = read(path, true)?;
    crate::runtime::validate_static_worker_image(&bytes)
        .map_err(|error| BuildError::Execution(format!("static ELF {}: {error}", path.display())))
}

pub(super) fn replace_shebang(
    path: &Path,
    expected: &str,
    interpreter: &Path,
) -> Result<(), BuildError> {
    let interpreter = interpreter
        .to_str()
        .ok_or(BuildError::InvalidRequest)?;
    if !interpreter.starts_with('/')
        || interpreter.bytes().any(|b| b <= 32 || b == 127)
        || interpreter.len() + 3 > 127
        || !expected.starts_with("#!")
        || !expected.ends_with('\n')
        || expected[..expected.len() - 1].contains(['\n', '\r', '\0'])
    {
        return Err(BuildError::InvalidRequest);
    }
    let (parent, name, before, bytes) = read(path, false)?;
    let rest = bytes
        .strip_prefix(expected.as_bytes())
        .ok_or(BuildError::InvalidRequest)?;
    let mut updated = format!("#!{interpreter}\n").into_bytes();
    updated.extend_from_slice(rest);
    if updated.len() as u64 > MAXIMUM {
        return Err(BuildError::InvalidRequest);
    }
    let mut check = || {
        let current = parent.read_file(&name)?.metadata()?;
        if unchanged(&before, &current) {
            Ok(())
        } else {
            Err(std::io::Error::other("shebang input changed"))
        }
    };
    parent.write_file(
        &name,
        &mut updated.as_slice(),
        updated.len() as u64,
        before.mode() & 0o777,
        true,
        &mut check,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    #[test]
    fn replacement_requires_exact_bytes_and_preserves_mode() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("script");
        std::fs::write(&path, "#! /bin/sh\necho hello\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o751)).unwrap();
        assert!(replace_shebang(&path, "#!/bin/sh\n", Path::new("/input/bin/sh")).is_err());
        replace_shebang(&path, "#! /bin/sh\n", Path::new("/input/bin/sh")).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "#!/input/bin/sh\necho hello\n"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().mode() & 0o777,
            0o751
        );
        assert!(
            replace_shebang(
                &path,
                "#!/input/bin/sh\n",
                Path::new("/bad interpreter")
            )
            .is_err()
        );
        let link = root.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(validate_static_elf(&link).is_err());
        assert!(replace_shebang(&link, "#!/input/bin/sh\n", Path::new("/bin/sh")).is_err());
        assert!(validate_static_elf(&path).is_err());
    }
}

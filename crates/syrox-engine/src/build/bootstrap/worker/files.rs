use super::*;
use crate::platform::linux::fd::tree::Directory;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt as _;

struct Budget {
    entries: usize,
    bytes: u64,
    maximum_entries: usize,
    maximum_bytes: u64,
}
impl Budget {
    fn new(resources: super::super::BuildResources) -> Self {
        Self {
            entries: 0,
            bytes: 0,
            maximum_entries: crate::acquire::archive::MAX_LARGE_ARCHIVE_ENTRIES,
            maximum_bytes: resources.envelope().work_tmpfs,
        }
    }
    fn entry(&mut self, depth: usize, bytes: u64) -> Result<(), BuildError> {
        self.entries += 1;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(BuildError::Output)?;
        if depth > crate::acquire::archive::MAX_ARCHIVE_DEPTH
            || self.entries > self.maximum_entries
            || self.bytes > self.maximum_bytes
        {
            return Err(BuildError::Output);
        }
        Ok(())
    }
}

pub(in crate::build) fn transfer(
    source: &Path,
    destination: &Path,
    moving: bool,
    resources: super::super::BuildResources,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> Result<(), BuildError> {
    check()?;
    let (source_parent, source_name) = Directory::parent(source)?;
    let (mut target_parent, mut target_name) = Directory::parent(destination)?;
    if target_parent
        .metadata(&target_name)?
        .is_some_and(|value| value.is_dir())
    {
        target_parent = target_parent.child(&target_name)?;
        target_name.clone_from(&source_name);
    }
    let metadata = source_parent
        .metadata(&source_name)?
        .ok_or_else(crate::platform::linux::fd::tree::invalid)?;
    if let Some(target) = target_parent.metadata(&target_name)? {
        if target.file_type().is_symlink()
            || (metadata.dev(), metadata.ino()) == (target.dev(), target.ino())
        {
            return Err(BuildError::Output);
        }
        if moving
            && target.is_dir()
            && !target_parent
                .child(&target_name)?
                .entries(1)?
                .is_empty()
        {
            return Err(BuildError::Output);
        }
    }
    if metadata.is_dir() {
        let target = if destination.is_dir() {
            destination.join(&source_name)
        } else {
            destination.to_path_buf()
        };
        if target.starts_with(source) {
            return Err(BuildError::Output);
        }
    }
    let mut budget = Budget::new(resources);
    // Validate the entire source even for the constant-time rename fast path.
    scan(
        &source_parent,
        &source_name,
        0,
        &mut budget,
        check,
    )?;
    if moving {
        match rename(
            &source_parent,
            &source_name,
            &target_parent,
            &target_name,
        ) {
            Ok(()) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {}
            Err(error) => return Err(error.into()),
        }
    }
    copy(
        &source_parent,
        &source_name,
        &target_parent,
        &target_name,
        0,
        &mut Budget::new(resources),
        check,
    )?;
    if moving {
        remove(
            &source_parent,
            &source_name,
            0,
            &mut Budget::new(resources),
            check,
        )?;
    }
    Ok(())
}

fn metadata(parent: &Directory, name: &OsStr) -> Result<fs::Metadata, BuildError> {
    let value = parent
        .metadata(name)?
        .ok_or_else(crate::platform::linux::fd::tree::invalid)?;
    if value.permissions().mode() & 0o7000 != 0
        || !(value.is_file() || value.is_dir() || value.file_type().is_symlink())
    {
        return Err(BuildError::Output);
    }
    Ok(value)
}
fn scan(
    parent: &Directory,
    name: &OsStr,
    depth: usize,
    budget: &mut Budget,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> Result<(), BuildError> {
    check()?;
    let value = metadata(parent, name)?;
    budget.entry(
        depth,
        if value.is_file() {
            value.len()
        } else {
            0
        },
    )?;
    if value.is_dir() {
        let directory = parent.child(name)?;
        for entry in directory.entries(
            budget
                .maximum_entries
                .saturating_sub(budget.entries),
        )? {
            scan(&directory, &entry, depth + 1, budget, check)?;
        }
    } else if value.file_type().is_symlink() {
        parent.read_link(name)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Two pinned parents plus independent bounded traversal state.
fn copy(
    source: &Directory,
    name: &OsStr,
    target: &Directory,
    destination: &OsStr,
    depth: usize,
    budget: &mut Budget,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> Result<(), BuildError> {
    check()?;
    let value = metadata(source, name)?;
    budget.entry(
        depth,
        if value.is_file() {
            value.len()
        } else {
            0
        },
    )?;
    if value.is_dir() {
        let input = source.child(name)?;
        let existing = target.metadata(destination)?.is_some();
        let output = target.ensure_child(destination)?;
        for entry in input.entries(
            budget
                .maximum_entries
                .saturating_sub(budget.entries),
        )? {
            copy(
                &input,
                &entry,
                &output,
                &entry,
                depth + 1,
                budget,
                check,
            )?;
        }
        if !existing {
            output.set_mode(value.permissions().mode() & 0o777)?;
        }
    } else if value.is_file() {
        let mut input = source.read_file(name)?;
        if input.metadata()?.len() != value.len() {
            return Err(BuildError::Output);
        }
        let copied = target.write_file(
            destination,
            &mut input,
            value.len(),
            value.permissions().mode() & 0o777,
            true,
            check,
        )?;
        if copied != value.len() {
            return Err(BuildError::Output);
        }
    } else {
        target.write_link(destination, &source.read_link(name)?, true)?;
    }
    Ok(())
}
fn remove(
    parent: &Directory,
    name: &OsStr,
    depth: usize,
    budget: &mut Budget,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> Result<(), BuildError> {
    check()?;
    let value = metadata(parent, name)?;
    budget.entry(depth, 0)?;
    if value.is_dir() {
        let directory = parent.child(name)?;
        for entry in directory.entries(
            budget
                .maximum_entries
                .saturating_sub(budget.entries),
        )? {
            remove(&directory, &entry, depth + 1, budget, check)?;
        }
        parent.remove_directory(name)?;
    } else {
        parent.remove_file(name)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::BuildResources;

    #[test]
    fn copies_regular_tree_modes_and_links_without_dereferencing_targets() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("tool"), b"tool").unwrap();
        fs::set_permissions(
            source.join("tool"),
            fs::Permissions::from_mode(0o751),
        )
        .unwrap();
        std::os::unix::fs::symlink("tool", source.join("alias")).unwrap();
        let destination = temp.path().join("destination");
        fs::create_dir(&destination).unwrap();
        transfer(
            &source,
            &destination,
            false,
            BuildResources::Standard,
            &mut || Ok(()),
        )
        .unwrap();
        let copied = destination.join("source");
        assert_eq!(fs::read(copied.join("tool")).unwrap(), b"tool");
        assert_eq!(
            fs::metadata(copied.join("tool"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o751
        );
        assert_eq!(
            fs::read_link(copied.join("alias")).unwrap(),
            Path::new("tool")
        );
        assert!(source.exists());
    }

    #[test]
    fn move_renames_and_refuses_to_merge_nonempty_directories() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        fs::write(&source, b"move").unwrap();
        let destination = temp.path().join("destination");
        transfer(
            &source,
            &destination,
            true,
            BuildResources::Standard,
            &mut || Ok(()),
        )
        .unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(&destination).unwrap(), b"move");
        fs::remove_file(&destination).unwrap();
        fs::create_dir(&source).unwrap();
        fs::create_dir_all(destination.join("source")).unwrap();
        fs::write(destination.join("source/existing"), b"keep").unwrap();
        assert!(
            transfer(
                &source,
                &destination,
                true,
                BuildResources::Standard,
                &mut || Ok(())
            )
            .is_err()
        );
        assert!(source.is_dir());
        assert_eq!(
            fs::read(destination.join("source/existing")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn destination_and_parent_symlinks_do_not_mutate_outside_files() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"untouched").unwrap();
        fs::write(&source, b"new").unwrap();
        let destination = temp.path().join("link");
        std::os::unix::fs::symlink(outside.join("keep"), &destination).unwrap();
        assert!(
            transfer(
                &source,
                &destination,
                false,
                BuildResources::Standard,
                &mut || Ok(())
            )
            .is_err()
        );
        fs::remove_file(&destination).unwrap();
        std::os::unix::fs::symlink(&outside, &destination).unwrap();
        assert!(
            transfer(
                &source,
                &destination.join("keep"),
                false,
                BuildResources::Standard,
                &mut || Ok(())
            )
            .is_err()
        );
        assert_eq!(
            fs::read(outside.join("keep")).unwrap(),
            b"untouched"
        );
        assert!(
            transfer(
                Path::new("/dev/null"),
                &temp.path().join("special"),
                false,
                BuildResources::Standard,
                &mut || Ok(())
            )
            .is_err()
        );
    }

    #[test]
    fn copy_checks_cancellation_between_chunks_without_replacing_destination() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        fs::write(&source, vec![7; 128 * 1024]).unwrap();
        fs::write(&destination, b"original").unwrap();
        let mut count = 0;
        assert!(
            transfer(
                &source,
                &destination,
                false,
                BuildResources::Standard,
                &mut || {
                    count += 1;
                    if count >= 6 {
                        Err(crate::cancellation::cancellation_io())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        assert_eq!(fs::read(&destination).unwrap(), b"original");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    }

    #[test]
    fn oversized_sparse_source_is_rejected_before_destination_creation() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        fs::File::create(&source)
            .unwrap()
            .set_len(BuildResources::Standard.envelope().work_tmpfs + 1)
            .unwrap();
        let destination = temp.path().join("destination");
        assert!(
            transfer(
                &source,
                &destination,
                false,
                BuildResources::Standard,
                &mut || Ok(())
            )
            .is_err()
        );
        assert!(!destination.exists());
    }

    #[test]
    fn cross_device_move_copies_complete_tree_before_removing_source() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("payload"), b"contents").unwrap();
        std::os::unix::fs::symlink("payload", source.join("alias")).unwrap();
        let target = temp.path().join("target");
        FORCE_CROSS_DEVICE.with(|value| value.set(true));
        transfer(
            &source,
            &target,
            true,
            BuildResources::Standard,
            &mut || Ok(()),
        )
        .unwrap();
        assert!(!source.exists());
        assert_eq!(
            fs::read(target.join("payload")).unwrap(),
            b"contents"
        );
        assert_eq!(
            fs::read_link(target.join("alias")).unwrap(),
            Path::new("payload")
        );
    }

    #[test]
    fn premature_eof_does_not_replace_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("target"), b"existing").unwrap();
        let directory = Directory::open(temp.path()).unwrap();
        let error = directory
            .write_file(
                OsStr::new("target"),
                &mut &b"short"[..],
                8,
                0o644,
                true,
                &mut || Ok(()),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(
            fs::read(temp.path().join("target")).unwrap(),
            b"existing"
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}
fn rename(
    source: &Directory,
    name: &OsStr,
    target: &Directory,
    destination: &OsStr,
) -> io::Result<()> {
    #[cfg(test)]
    if FORCE_CROSS_DEVICE.with(|value| value.replace(false)) {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    source.rename(name, target, destination)
}

#[cfg(test)]
thread_local! {
    static FORCE_CROSS_DEVICE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

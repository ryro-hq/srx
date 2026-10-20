use super::{
    ArchiveError, ArchiveFormat, ArchiveInventory, ArchiveLimits, ArchiveSink, MemberKind, Read,
    cancelled_archive_error, check_cancelled, visit_reader,
};
use crate::cancellation::CancellableReader;
use crate::platform::linux::fd::tree::Directory;
use std::fs::File;
use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};

pub(crate) fn extract_archive(
    source: File,
    format: ArchiveFormat,
    limits: ArchiveLimits,
    destination: BorrowedFd<'_>,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<ArchiveInventory, ArchiveError> {
    let limits = limits.validate(format)?;
    check_cancelled(cancellation)?;
    let metadata = source.metadata()?;
    if !metadata.is_file() {
        return Err(ArchiveError::UnsafeEntry);
    }
    if metadata.len() > limits.compressed_bytes {
        return Err(ArchiveError::Limit);
    }
    let mut sink = Extraction {
        root: Directory::from_fd(destination)?,
        aliases: Vec::new(),
        directories: Vec::new(),
        cancellation,
    };
    visit_reader(
        CancellableReader {
            source,
            cancellation,
        },
        format,
        limits,
        &mut sink,
    )
    .map_err(|error| cancelled_archive_error(error, cancellation))
}

struct Extraction<'a> {
    root: Directory,
    aliases: Vec<(PathBuf, PathBuf)>,
    directories: Vec<(PathBuf, u32)>,
    cancellation: &'a crate::cancellation::Cancellation,
}
impl ArchiveSink for Extraction<'_> {
    fn entry(
        &mut self,
        path: &str,
        kind: &MemberKind,
        mode: u32,
        size: u64,
        payload: &mut dyn Read,
    ) -> Result<(), ArchiveError> {
        check_cancelled(self.cancellation)?;
        let path = Path::new(path);
        let parent = self
            .root
            .ensure_relative(path.parent().ok_or(ArchiveError::UnsafeEntry)?)?;
        let name = path
            .file_name()
            .ok_or(ArchiveError::UnsafeEntry)?;
        match kind {
            MemberKind::Directory => {
                parent.ensure_child(name)?;
                self.directories.push((path.to_path_buf(), mode));
            }
            MemberKind::File => {
                let cancellation = self.cancellation;
                let copied = parent.write_source_file(name, payload, size, mode, &mut || {
                    cancellation
                        .check()
                        .map_err(|_| crate::cancellation::cancellation_io())
                })?;
                if copied != size {
                    return Err(ArchiveError::InvalidTar);
                }
            }
            MemberKind::Alias(target) => {
                self.aliases
                    .push((path.to_path_buf(), target.into()));
            }
            MemberKind::GlobalComment => return Err(ArchiveError::InvalidTar),
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<(), ArchiveError> {
        for (path, target) in &self.aliases {
            check_cancelled(self.cancellation)?;
            let parent = self
                .root
                .ensure_relative(path.parent().ok_or(ArchiveError::UnsafeEntry)?)?;
            parent.write_link(
                path.file_name()
                    .ok_or(ArchiveError::UnsafeEntry)?,
                target,
                false,
            )?;
        }
        self.directories
            .sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        for (path, mode) in &self.directories {
            check_cancelled(self.cancellation)?;
            self.root.ensure_relative(path)?.set_mode(*mode)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acquire::archive::inspect_reader;
    use crate::acquire::archive::tests::{alias, archive, member, xz_archive};
    use std::fs;
    use std::io::{Seek as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;

    fn extract(
        bytes: &[u8],
        format: ArchiveFormat,
        limits: ArchiveLimits,
        destination: &Path,
    ) -> Result<ArchiveInventory, ArchiveError> {
        let mut source = tempfile::tempfile().unwrap();
        source.write_all(bytes).unwrap();
        source.rewind().unwrap();
        let destination = Directory::open(destination).unwrap();
        extract_archive(
            source,
            format,
            limits,
            destination.as_fd(),
            &crate::cancellation::Cancellation::default(),
        )
    }

    #[test]
    fn inspection_and_extraction_agree_on_gzip_and_xz_and_preserve_modes() {
        for format in [
            ArchiveFormat::GzipTar,
            ArchiveFormat::XzTar,
        ] {
            let mut members = vec![
                member("source", b"", b'5', 0o750),
                member("source/run", b"program", b'0', 0o751),
            ];
            if format == ArchiveFormat::XzTar {
                members.insert(1, alias("source/alias", "run"));
            }
            let (bytes, limits) = match format {
                ArchiveFormat::GzipTar => (archive(&members), ArchiveLimits::small_gzip()),
                ArchiveFormat::XzTar => (xz_archive(&members), ArchiveLimits::large_xz()),
            };
            let expected = inspect_reader(bytes.as_slice(), format, limits).unwrap();
            let target = tempfile::tempdir().unwrap();
            assert_eq!(
                extract(&bytes, format, limits, target.path()).unwrap(),
                expected
            );
            assert_eq!(
                fs::read(target.path().join("source/run")).unwrap(),
                b"program"
            );
            assert_eq!(
                fs::metadata(target.path().join("source/run"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o751
            );
            assert_eq!(
                fs::metadata(target.path().join("source"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o750
            );
            if format == ArchiveFormat::XzTar {
                assert_eq!(
                    fs::read_link(target.path().join("source/alias")).unwrap(),
                    Path::new("run")
                );
            }
        }
    }

    #[test]
    fn source_file_times_do_not_depend_on_archive_member_order_or_read_permissions() {
        let bytes = archive(&[
            member("configure", b"generated", b'0', 0o755),
            member("configure.ac", b"input", b'0', 0o644),
            member("unreadable", b"private", b'0', 0o000),
        ]);
        let target = tempfile::tempdir().unwrap();
        extract(
            &bytes,
            ArchiveFormat::GzipTar,
            ArchiveLimits::small_gzip(),
            target.path(),
        )
        .unwrap();
        for name in [
            "configure",
            "configure.ac",
            "unreadable",
        ] {
            assert_eq!(
                fs::metadata(target.path().join(name))
                    .unwrap()
                    .modified()
                    .unwrap(),
                std::time::UNIX_EPOCH
            );
        }
    }

    #[test]
    fn shared_walker_refuses_escapes_duplicates_specials_and_late_invalid_members() {
        let good = member("source/okay", b"okay", b'0', 0o644);
        let cases = vec![
            archive(&[member("../escape", b"bad", b'0', 0o644)]),
            archive(&[good.clone(), good.clone()]),
            archive(&[
                good.clone(),
                member("source/device", b"", b'3', 0o644),
            ]),
            archive(&[
                good,
                member("source/setuid", b"bad", b'0', 0o4755),
            ]),
        ];
        for bytes in cases {
            let target = tempfile::tempdir().unwrap();
            assert!(
                inspect_reader(
                    bytes.as_slice(),
                    ArchiveFormat::GzipTar,
                    ArchiveLimits::small_gzip()
                )
                .is_err()
            );
            assert!(
                extract(
                    &bytes,
                    ArchiveFormat::GzipTar,
                    ArchiveLimits::small_gzip(),
                    target.path()
                )
                .is_err()
            );
            assert!(!target.path().join("source/device").exists());
            assert!(!target.path().join("source/setuid").exists());
        }
    }

    #[test]
    fn existing_files_or_symlink_parents_are_not_overwritten() {
        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("file"), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), target.path().join("source")).unwrap();
        let bytes = archive(&[member(
            "source/file",
            b"replacement",
            b'0',
            0o644,
        )]);
        assert!(
            extract(
                &bytes,
                ArchiveFormat::GzipTar,
                ArchiveLimits::small_gzip(),
                target.path()
            )
            .is_err()
        );
        assert_eq!(
            fs::read(outside.path().join("file")).unwrap(),
            b"outside"
        );
        fs::remove_file(target.path().join("source")).unwrap();
        fs::create_dir(target.path().join("source")).unwrap();
        fs::write(target.path().join("source/file"), b"existing").unwrap();
        assert!(
            extract(
                &bytes,
                ArchiveFormat::GzipTar,
                ArchiveLimits::small_gzip(),
                target.path()
            )
            .is_err()
        );
        assert_eq!(
            fs::read(target.path().join("source/file")).unwrap(),
            b"existing"
        );
    }

    #[test]
    fn expansion_limits_and_unresolved_aliases_have_identical_admission() {
        let target = tempfile::tempdir().unwrap();
        let bytes = archive(&[member("file", b"too long", b'0', 0o644)]);
        let limits = ArchiveLimits {
            file_bytes: 3,
            ..ArchiveLimits::small_gzip()
        };
        assert!(inspect_reader(bytes.as_slice(), ArchiveFormat::GzipTar, limits).is_err());
        assert!(
            extract(
                &bytes,
                ArchiveFormat::GzipTar,
                limits,
                target.path()
            )
            .is_err()
        );
        assert!(!target.path().join("file").exists());
        let bytes = xz_archive(&[alias("missing", "target")]);
        assert!(
            inspect_reader(
                bytes.as_slice(),
                ArchiveFormat::XzTar,
                ArchiveLimits::large_xz()
            )
            .is_err()
        );
        assert!(
            extract(
                &bytes,
                ArchiveFormat::XzTar,
                ArchiveLimits::large_xz(),
                target.path()
            )
            .is_err()
        );
        assert!(
            target
                .path()
                .join("missing")
                .symlink_metadata()
                .is_err()
        );
    }

    #[test]
    fn cancelled_extraction_does_not_create_members() {
        let target = tempfile::tempdir().unwrap();
        let directory = Directory::open(target.path()).unwrap();
        let bytes = archive(&[member("file", b"contents", b'0', 0o644)]);
        let mut source = tempfile::tempfile().unwrap();
        source.write_all(&bytes).unwrap();
        source.rewind().unwrap();
        let cancellation = crate::cancellation::Cancellation::default();
        cancellation.cancel();
        assert!(
            extract_archive(
                source,
                ArchiveFormat::GzipTar,
                ArchiveLimits::small_gzip(),
                directory.as_fd(),
                &cancellation
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
    }
}

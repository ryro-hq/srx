use super::*;
use crate::system::budget::{BuildBudget, BuilderLimits};
use std::{
    fs,
    io::{self, Seek as _, Write as _},
    path::Path,
    process::Command,
};

fn request() -> BuildBudget {
    BuildBudget {
        memory_bytes: 268_435_456,
        cpu_percent: 100,
        processes: 16,
        descriptors: 128,
        scratch_bytes: 2 * 1024 * 1024 * 1024,
        files: 100_000,
        output_bytes: 67_108_864,
        duration_seconds: 180,
    }
}
fn limits(request: BuildBudget, format: ArchiveFormat) -> SystemArchiveLimits {
    let budget = BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap();
    SystemArchiveLimits::new(&budget, 64 * 1024 * 1024, format).unwrap()
}
fn header(
    writer: &mut impl io::Write,
    name: &str,
    size: u64,
    kind: u8,
    target: &str,
) -> io::Result<()> {
    let mut bytes = [0_u8; 512];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    bytes[100..108].copy_from_slice(b"0000644\0");
    bytes[108..116].copy_from_slice(b"0000000\0");
    bytes[116..124].copy_from_slice(b"0000000\0");
    bytes[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    bytes[136..148].copy_from_slice(b"00000000000\0");
    bytes[148..156].fill(b' ');
    bytes[156] = kind;
    bytes[157..157 + target.len()].copy_from_slice(target.as_bytes());
    bytes[257..263].copy_from_slice(b"ustar\0");
    bytes[263..265].copy_from_slice(b"00");
    let sum: u32 = bytes.iter().map(|b| u32::from(*b)).sum();
    bytes[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    writer.write_all(&bytes)
}
fn member(writer: &mut impl io::Write, name: &str, data: &[u8]) -> io::Result<()> {
    header(writer, name, data.len() as u64, b'0', "")?;
    writer.write_all(data)?;
    writer.write_all(&vec![0; (512 - data.len() % 512) % 512])
}
fn compressed(path: &Path, format: ArchiveFormat, body: impl FnOnce(&mut Vec<u8>)) -> File {
    let mut tar = Vec::new();
    body(&mut tar);
    tar.extend([0; 1024]);
    let bytes = match format {
        ArchiveFormat::GzipTar => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(&tar).unwrap();
            encoder.finish().unwrap()
        }
        ArchiveFormat::XzTar => {
            let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
            encoder.write_all(&tar).unwrap();
            encoder.finish().unwrap()
        }
    };
    fs::write(path, bytes).unwrap();
    File::open(path).unwrap()
}

#[test]
fn system_limits_derive_from_scratch_without_changing_legacy_validation() {
    for format in [
        ArchiveFormat::GzipTar,
        ArchiveFormat::XzTar,
    ] {
        let selected = limits(request(), format);
        let geometry = WorkspaceLayout::from_budget(selected.budget())
            .unwrap()
            .scratch_geometry();
        assert_eq!(selected.format(), format);
        assert_eq!(
            selected.limits().expanded_bytes,
            request().scratch_bytes
        );
        assert_eq!(
            selected.limits().file_bytes,
            request().scratch_bytes
        );
        assert_eq!(
            selected.limits().entries,
            usize::try_from(geometry.requested_inodes()).unwrap()
        );
        assert!(selected.limits().entries > super::super::MAX_LARGE_ARCHIVE_ENTRIES);
        assert!(selected.limits().validate(format).is_err());
        assert!(SystemArchiveLimits::new(selected.budget(), 0, format).is_err());
        assert!(
            SystemArchiveLimits::new(
                selected.budget(),
                crate::store::MAX_STORE_BLOB_BYTES + 1,
                format
            )
            .is_err()
        );
    }
    let small = limits(
        BuildBudget {
            memory_bytes: 1024 * 1024,
            ..request()
        },
        ArchiveFormat::XzTar,
    );
    assert_eq!(small.limits().decoder_memory_bytes, 1024 * 1024);
}

#[test]
fn positioned_source_reads_preserve_shared_cursor_and_detect_growth_even_at_eof() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source");
    fs::write(&path, b"bytes").unwrap();
    let mut file = File::open(&path).unwrap();
    file.seek(io::SeekFrom::End(0)).unwrap();
    let mut observer = file.try_clone().unwrap();
    let mut reader = SourceReader::new(file, 5).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"bytes");
    assert_eq!(observer.stream_position().unwrap(), 5);
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(6)
        .unwrap();
    assert_eq!(
        reader.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn both_system_formats_inspect_and_extract_canonical_aliases() {
    for format in [
        ArchiveFormat::GzipTar,
        ArchiveFormat::XzTar,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source");
        let mut source = compressed(&path, format, |tar| {
            member(tar, "root/file", b"payload").unwrap();
            header(tar, "root/copy", 0, b'2', "file").unwrap();
            header(tar, "root/link", 0, b'2', "file").unwrap();
        });
        source.seek(io::SeekFrom::End(0)).unwrap();
        let selected = limits(request(), format);
        let expected = inspect_system_archive(source, &selected, &Cancellation::default()).unwrap();
        let destination = tempfile::tempdir().unwrap();
        let root = File::open(destination.path()).unwrap();
        let mut cursor_changed = File::open(&path).unwrap();
        cursor_changed.seek(io::SeekFrom::End(0)).unwrap();
        let actual = extract_system_archive(
            cursor_changed,
            &selected,
            root.as_fd(),
            &Cancellation::default(),
        )
        .unwrap();
        assert_eq!(actual, expected);
        for name in ["file", "copy", "link"] {
            assert_eq!(
                fs::read(destination.path().join("root").join(name)).unwrap(),
                b"payload"
            );
        }
        if format == ArchiveFormat::GzipTar {
            assert!(
                super::super::inspect_reader(
                    File::open(&path).unwrap(),
                    format,
                    ArchiveLimits::small_gzip()
                )
                .is_err()
            );
        }
    }
}

#[test]
fn system_rejects_readwrite_sources_cancellation_collisions_and_parent_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source");
    drop(compressed(&path, ArchiveFormat::GzipTar, |tar| {
        member(tar, "root/file", b"replacement").unwrap();
    }));
    let selected = limits(request(), ArchiveFormat::GzipTar);
    let destination = tempfile::tempdir().unwrap();
    let root = File::open(destination.path()).unwrap();
    let writable = File::options()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(
        extract_system_archive(
            writable,
            &selected,
            root.as_fd(),
            &Cancellation::default()
        )
        .is_err()
    );
    let cancelled = Cancellation::default();
    cancelled.cancel();
    assert!(matches!(
        extract_system_archive(
            File::open(&path).unwrap(),
            &selected,
            root.as_fd(),
            &cancelled
        ),
        Err(ArchiveError::Cancelled)
    ));
    assert_eq!(
        fs::read_dir(destination.path()).unwrap().count(),
        0
    );
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("file"), b"preserved").unwrap();
    std::os::unix::fs::symlink(outside.path(), destination.path().join("root")).unwrap();
    assert!(
        extract_system_archive(
            File::open(&path).unwrap(),
            &selected,
            root.as_fd(),
            &Cancellation::default()
        )
        .is_err()
    );
    assert_eq!(
        fs::read(outside.path().join("file")).unwrap(),
        b"preserved"
    );
    let collision = tempfile::tempdir().unwrap();
    fs::create_dir(collision.path().join("root")).unwrap();
    fs::write(collision.path().join("root/file"), b"existing").unwrap();
    assert!(
        extract_system_archive(
            File::open(&path).unwrap(),
            &selected,
            File::open(collision.path()).unwrap().as_fd(),
            &Cancellation::default()
        )
        .is_err()
    );
    assert_eq!(
        fs::read(collision.path().join("root/file")).unwrap(),
        b"existing"
    );
}

#[test]
fn system_metadata_count_can_exceed_the_legacy_large_ceiling() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source");
    let count = super::super::MAX_LARGE_ARCHIVE_ENTRIES + 1;
    let source = compressed(&path, ArchiveFormat::GzipTar, |tar| {
        for n in 0..count {
            member(tar, &format!("file-{n}"), b"").unwrap();
        }
    });
    let inventory = inspect_system_archive(
        source,
        &limits(request(), ArchiveFormat::GzipTar),
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(inventory.entries(), count);
    assert_eq!(inventory.files(), count);
    let legacy = ArchiveLimits {
        decoder_memory_bytes: 0,
        ..ArchiveLimits::large_xz()
    };
    assert!(matches!(
        super::super::inspect_reader(
            File::open(path).unwrap(),
            ArchiveFormat::GzipTar,
            legacy
        ),
        Err(ArchiveError::Limit)
    ));
}

#[test]
fn hardlinks_and_escape_aliases_remain_outside_the_system_archive_subset() {
    for (kind, target) in [
        (b'1', "root/file"),
        (b'2', "../outside"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source");
        let source = compressed(&path, ArchiveFormat::GzipTar, |tar| {
            header(tar, "root/link", 0, kind, target).unwrap();
        });
        assert!(matches!(
            inspect_system_archive(
                source,
                &limits(request(), ArchiveFormat::GzipTar),
                &Cancellation::default()
            ),
            Err(ArchiveError::UnsafeEntry)
        ));
    }
}

#[test]
fn byte_and_entry_bounds_refuse_without_overwriting_existing_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source");
    let selected = limits(
        BuildBudget {
            scratch_bytes: 67_108_864,
            files: 32,
            ..request()
        },
        ArchiveFormat::GzipTar,
    );
    drop(compressed(&path, ArchiveFormat::GzipTar, |tar| {
        for n in 0..=selected.limits().entries {
            member(tar, &format!("entry-{n}"), b"").unwrap();
        }
    }));
    let destination = tempfile::tempdir().unwrap();
    let root = File::open(destination.path()).unwrap();
    assert!(matches!(
        extract_system_archive(
            File::open(&path).unwrap(),
            &selected,
            root.as_fd(),
            &Cancellation::default()
        ),
        Err(ArchiveError::Limit)
    ));
    assert!(fs::read_dir(destination.path()).unwrap().count() <= selected.limits().entries);
    let tiny = SystemArchiveLimits::new(selected.budget(), 1, ArchiveFormat::GzipTar).unwrap();
    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(
        extract_system_archive(
            File::open(&path).unwrap(),
            &tiny,
            File::open(empty.path()).unwrap().as_fd(),
            &Cancellation::default()
        ),
        Err(ArchiveError::Limit)
    ));
    assert_eq!(fs::read_dir(empty.path()).unwrap().count(), 0);
    drop(compressed(&path, ArchiveFormat::GzipTar, |tar| {
        header(
            tar,
            "huge",
            selected.limits().file_bytes + 1,
            b'0',
            "",
        )
        .unwrap();
    }));
    assert!(matches!(
        extract_system_archive(
            File::open(&path).unwrap(),
            &selected,
            File::open(empty.path()).unwrap().as_fd(),
            &Cancellation::default()
        ),
        Err(ArchiveError::Limit)
    ));
    assert_eq!(fs::read_dir(empty.path()).unwrap().count(), 0);
}

fn available_bytes(path: &Path) -> u64 {
    use std::os::fd::AsRawFd as _;
    let directory = File::open(path).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: live descriptor and writable exact ABI storage.
    #[expect(
        unsafe_code,
        reason = "fstatvfs FFI measures free space of the test directory"
    )]
    let status = unsafe { libc::fstatvfs(directory.as_raw_fd(), stat.as_mut_ptr()) };
    assert_eq!(status, 0, "{}", io::Error::last_os_error());
    // SAFETY: fstatvfs initialized the structure on success.
    #[expect(unsafe_code, reason = "reads the statvfs that fstatvfs initialized")]
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail.saturating_mul(stat.f_frsize)
}

#[test]
fn expanded_source_exceeding_one_gib_passes_in_a_memory_bounded_child() {
    use std::os::unix::process::CommandExt as _;
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.gz");
    let size = 1024 * 1024 * 1024 + 17;
    let available = available_bytes(directory.path());
    if available < size + 64 * 1024 * 1024 {
        // Small tmpfs scratch (the VM guest) cannot hold the expanded member;
        // the property is still proven wherever the temporary directory fits it.
        println!("SRX_SYSTEM_ARCHIVE_LARGE_SKIPPED available={available} required={size}");
        return;
    }
    let mut encoder = flate2::write::GzEncoder::new(
        File::create(&source).unwrap(),
        flate2::Compression::fast(),
    );
    header(&mut encoder, "large", size, b'0', "").unwrap();
    io::copy(&mut io::repeat(0x7a).take(size), &mut encoder).unwrap();
    encoder
        .write_all(&vec![
            0;
            usize::try_from((512 - size % 512) % 512)
                .unwrap()
        ])
        .unwrap();
    encoder.write_all(&[0; 1024]).unwrap();
    encoder.finish().unwrap().sync_all().unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "acquire::archive::system::tests::system_archive_large_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SRX_SYSTEM_ARCHIVE_CHILD", directory.path());
    // SAFETY: changes only this test child's resource limits before exec.
    #[expect(
        unsafe_code,
        reason = "pre_exec setrlimit bounds only the test child's address space"
    )]
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 268_435_456,
                rlim_max: 268_435_456,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &raw const limit) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    assert!(command.status().unwrap().success());
}

#[test]
#[ignore = "private memory-bounded child of the real large source archive test"]
fn system_archive_large_child() {
    let directory = std::env::var_os("SRX_SYSTEM_ARCHIVE_CHILD").expect("private child directory");
    let directory = Path::new(&directory);
    let source = directory.join("source.gz");
    let selected = limits(request(), ArchiveFormat::GzipTar);
    let expected = inspect_system_archive(
        File::open(&source).unwrap(),
        &selected,
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(expected.expanded_bytes(), 1024 * 1024 * 1024 + 17);
    let target = directory.join("output");
    fs::create_dir(&target).unwrap();
    let root = File::open(&target).unwrap();
    let actual = extract_system_archive(
        File::open(&source).unwrap(),
        &selected,
        root.as_fd(),
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(actual, expected);
    let file = File::open(target.join("large")).unwrap();
    assert_eq!(
        file.metadata().unwrap().len(),
        expected.expanded_bytes()
    );
    let mut tail = [0; 17];
    file.read_exact_at(&mut tail, 1024 * 1024 * 1024)
        .unwrap();
    assert_eq!(tail, [0x7a; 17]);
    println!(
        "SRX_SYSTEM_ARCHIVE_LARGE_OK bytes={} address_space=268435456",
        expected.expanded_bytes()
    );
}

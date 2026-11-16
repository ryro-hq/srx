//! Real source descriptors, atomic staging, interruption and bounded copying.

use super::*;
use crate::store::Store;
use std::io::{Read as _, Seek as _, SeekFrom};

fn source(
    data: &[u8],
) -> (
    tempfile::TempDir,
    Store,
    Source,
    std::path::PathBuf,
) {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::initialize(&temporary.path().join("store")).unwrap();
    let digest = ContentDigest::sha256(data);
    let lease = store.operation().unwrap();
    lease
        .ingest(data, digest, data.len() as u64)
        .unwrap();
    let reader = lease
        .open_verified(digest, data.len() as u64)
        .unwrap()
        .unwrap();
    let source = Source::capture(
        &reader,
        digest,
        data.len() as u64,
        &Cancellation::default(),
    )
    .unwrap();
    let pin = digest.to_string();
    let path = temporary
        .path()
        .join("store/objects/sha256")
        .join(&pin[..2])
        .join(pin);
    (temporary, store, source, path)
}

#[test]
fn source_is_staged_readonly_without_changing_shared_seek_or_replacing_a_name() {
    let (_temporary, _store, source, _path) = source(b"retained source bytes");
    let target = tempfile::tempdir().unwrap();
    let directory = fd::open_top_directory(target.path()).unwrap();
    let mut shared = source.file.try_clone().unwrap();
    shared.seek(SeekFrom::Start(5)).unwrap();
    source
        .stage(&directory, &Cancellation::default())
        .unwrap();
    assert_eq!(shared.stream_position().unwrap(), 5);
    let output = target.path().join("source");
    assert_eq!(
        std::fs::read(&output).unwrap(),
        b"retained source bytes"
    );
    assert_eq!(
        std::fs::metadata(&output).unwrap().mode() & 0o7777,
        0o400
    );
    assert!(matches!(
        source.stage(&directory, &Cancellation::default()),
        Err(BuildError::InputChanged)
    ));
    assert_eq!(
        std::fs::read(&output).unwrap(),
        b"retained source bytes"
    );
    assert_eq!(
        std::fs::read_dir(target.path()).unwrap().count(),
        1
    );
}

#[test]
fn changed_source_is_refused_before_staging_and_capture_rechecks_verified_store_bytes() {
    let (_temporary, store, source, path) = source(b"source bytes");
    let target = tempfile::tempdir().unwrap();
    let directory = fd::open_top_directory(target.path()).unwrap();
    let lease = store.operation().unwrap();
    let reader = lease
        .open_verified(source.digest, source.size)
        .unwrap()
        .unwrap();
    std::fs::write(path, b"changed data").unwrap();
    assert!(matches!(
        source.stage(&directory, &Cancellation::default()),
        Err(BuildError::InputChanged)
    ));
    assert!(matches!(
        Source::capture(
            &reader,
            source.digest,
            source.limit,
            &Cancellation::default()
        ),
        Err(BuildError::InputChanged)
    ));
    assert_eq!(
        std::fs::read_dir(target.path()).unwrap().count(),
        0
    );
}

#[test]
fn metadata_is_revalidated_after_copy_even_if_changed_bytes_were_already_consumed() {
    let data = vec![0x35; 128 * 1024 + 17];
    let (_temporary, _store, source, path) = source(&data);
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap();
    let mut changed = false;
    let result = source.copy_to(
        |_| {
            if !changed {
                writer.write_all_at(b"X", 0)?;
                // Do not depend on filesystem timestamp granularity for this
                // metadata-change oracle; the copied bytes still hash as before.
                writer.set_permissions(Permissions::from_mode(
                    (source.metadata.mode & 0o7777) ^ 0o200,
                ))?;
                writer.sync_all()?;
                changed = true;
            }
            Ok(())
        },
        &Cancellation::default(),
    );
    assert!(changed);
    assert!(matches!(result, Err(BuildError::InputChanged)));
}

#[test]
fn streaming_accepts_short_interrupted_reads_and_observes_sink_cancellation() {
    let data = vec![0x73; 3 * 64 * 1024 + 17];
    let expected = ContentDigest::sha256(&data);
    let mut cursor = io::Cursor::new(&data);
    let mut interrupted = false;
    let mut copied = 0;
    let size = copy_source(
        |buffer| {
            assert!(buffer.len() <= 64 * 1024);
            if !interrupted {
                interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            cursor.read(&mut buffer[..13])
        },
        |chunk| {
            copied += chunk.len();
            Ok(())
        },
        expected,
        data.len() as u64,
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(copied, data.len());
    assert_eq!(size, data.len() as u64);
    let cancellation = Cancellation::default();
    let mut cursor = io::Cursor::new(data);
    let result = copy_source(
        |buffer| cursor.read(buffer),
        |_| {
            cancellation.cancel();
            Ok(())
        },
        expected,
        size,
        &cancellation,
    );
    assert!(matches!(result, Err(BuildError::Cancelled)));
}

use super::*;
use crate::store::{ContentDigest, GcRequest, Store};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn ranges_cross_chunk_boundaries_and_seek_without_buffering_the_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let mut content = vec![1; 2 * CHUNK_BYTES + 17];
    content[CHUNK_BYTES..2 * CHUNK_BYTES].fill(2);
    content[2 * CHUNK_BYTES..].fill(3);
    let token = Cancellation::default();
    let artifact = store
        .operation()
        .unwrap()
        .ingest_chunked(
            content.as_slice(),
            ContentDigest::sha256(&content),
            content.len() as u64,
            &token,
        )
        .unwrap();
    let mut reader = artifact.open_reader(&token);
    assert_eq!(reader.size(), content.len() as u64);
    assert_eq!(
        reader.content_digest(),
        ContentDigest::sha256(&content)
    );
    reader
        .seek(SeekFrom::Start(CHUNK_BYTES as u64 - 3))
        .unwrap();
    let mut crossing = [0; 9];
    reader.read_exact(&mut crossing).unwrap();
    assert_eq!(crossing, [1, 1, 1, 2, 2, 2, 2, 2, 2]);
    reader.seek(SeekFrom::End(-5)).unwrap();
    let mut tail = Vec::new();
    reader.read_to_end(&mut tail).unwrap();
    assert_eq!(tail, [3; 5]);
    reader.seek(SeekFrom::Current(-7)).unwrap();
    assert_eq!(
        reader.stream_position().unwrap(),
        content.len() as u64 - 7
    );
    assert!(reader.seek(SeekFrom::Start(u64::MAX)).is_ok());
    assert_eq!(reader.read(&mut crossing).unwrap(), 0);
    assert!(reader.seek(SeekFrom::Current(1)).is_err());
    reader.rewind().unwrap();
    assert!(reader.seek(SeekFrom::Current(-1)).is_err());
    let mut all = Vec::new();
    reader.read_to_end(&mut all).unwrap();
    assert_eq!(all, content);
    assert!(reader.cache.as_ref().unwrap().1.capacity() <= CHUNK_BYTES + 1);
}

#[test]
fn reader_retention_allows_gc_and_survives_after_the_original_handle_is_dropped() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let token = Cancellation::default();
    let artifact = store
        .operation()
        .unwrap()
        .ingest_chunked(
            b"retained bytes".as_slice(),
            ContentDigest::sha256(b"retained bytes"),
            64,
            &token,
        )
        .unwrap();
    let pin = artifact.manifest_digest();
    let mut reader = artifact.open_reader(&token);
    drop(artifact);
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    let mut all = Vec::new();
    reader.read_to_end(&mut all).unwrap();
    assert_eq!(all, b"retained bytes");
    drop(reader);
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    assert!(
        store
            .operation()
            .unwrap()
            .verify(pin)
            .unwrap()
            .is_none()
    );
}

#[test]
fn uncached_chunks_are_reverified_and_cancellation_does_not_become_eof() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let token = Cancellation::default();
    let content = vec![0x41; CHUNK_BYTES + 3];
    let artifact = store
        .operation()
        .unwrap()
        .ingest_chunked(
            content.as_slice(),
            ContentDigest::sha256(&content),
            content.len() as u64,
            &token,
        )
        .unwrap();
    let mut reader = artifact.open_reader(&token);
    reader.read_exact(&mut [0; 1]).unwrap();
    let chunk = artifact.manifest().chunks()[1].to_string();
    let path = directory
        .path()
        .join("objects/sha256")
        .join(&chunk[..2])
        .join(chunk);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(path, b"bad").unwrap();
    reader
        .seek(SeekFrom::Start(CHUNK_BYTES as u64))
        .unwrap();
    assert!(reader.read(&mut [0; 1]).is_err());
    assert_eq!(
        reader.stream_position().unwrap(),
        CHUNK_BYTES as u64
    );
    token.cancel();
    assert!(reader.read(&mut [0; 1]).is_err());
    assert!(reader.rewind().is_err());
}

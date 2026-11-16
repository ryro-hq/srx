use super::*;
use crate::store::{GcRequest, Store};
use std::{fs, io::Write as _, os::unix::fs::PermissionsExt as _, path::Path};

fn clone_fds(set: &ChunkedDescriptorSet) -> Vec<OwnedFd> {
    set.descriptors()
        .iter()
        .map(|fd| fd.try_clone().unwrap())
        .collect()
}

fn artifact(store: &Store, bytes: &[u8]) -> RetainedChunkedArtifact {
    store
        .operation()
        .unwrap()
        .ingest_chunked(
            bytes,
            ContentDigest::sha256(bytes),
            bytes.len() as u64,
            &Cancellation::default(),
        )
        .unwrap()
}

fn object_path(store: &Path, pin: ContentDigest) -> std::path::PathBuf {
    let pin = pin.to_string();
    store
        .join("objects/sha256")
        .join(&pin[..2])
        .join(pin)
}

#[test]
fn sparse_stream_larger_than_a_blob_uses_deduplicated_descriptors_and_bounded_cache() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(&directory.path().join("store")).unwrap();
    let source = directory.path().join("large-source");
    let mut file = File::create(&source).unwrap();
    let size = 1024 * 1024 * 1024 + 17;
    file.set_len(size).unwrap();
    file.write_all(b"first marker").unwrap();
    file.seek(SeekFrom::End(-11)).unwrap();
    file.write_all(b"last marker").unwrap();
    drop(file);
    let mut hasher = Sha256::new();
    let mut source_file = File::open(&source).unwrap();
    let mut buffer = vec![0; IO_BYTES];
    loop {
        let count = source_file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let expected = ContentDigest::from_sha256_hash(hasher.finalize().into());
    let cancel = Cancellation::default();
    let admitted = store
        .operation()
        .unwrap()
        .ingest_chunked(
            File::open(source).unwrap(),
            expected,
            size,
            &cancel,
        )
        .unwrap();
    assert_eq!(admitted.manifest().chunks().len(), 257);
    let set = admitted.prepare_descriptors(4, &cancel).unwrap();
    assert_eq!(set.descriptors().len(), 4); // manifest + first/zero/last chunks
    assert!(admitted.prepare_descriptors(3, &cancel).is_err());
    let mut reader = ChunkedDescriptorReader::from_received(
        set.manifest_digest(),
        clone_fds(&set),
        size,
        4,
        &cancel,
    )
    .unwrap();
    assert_eq!(reader.size(), size);
    assert_eq!(reader.content_digest(), expected);
    assert!(reader.cache.is_none());
    reader.seek(SeekFrom::End(-11)).unwrap();
    let mut end = [0; 11];
    reader.read_exact(&mut end).unwrap();
    assert_eq!(&end, b"last marker");
    assert!(reader.cache.as_ref().unwrap().1.capacity() <= CHUNK_BYTES);
    reader
        .seek(SeekFrom::Start(CHUNK_BYTES as u64 - 3))
        .unwrap();
    let mut cross = [1; 7];
    reader.read_exact(&mut cross).unwrap();
    assert_eq!(cross, [0; 7]);
    reader.seek(SeekFrom::Start(0)).unwrap();
    let mut start = [0; 12];
    reader.read_exact(&mut start).unwrap();
    assert_eq!(&start, b"first marker");
}

#[test]
fn sender_custody_survives_gc_and_receiver_never_uses_shared_seek_positions() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let admitted = artifact(&store, b"descriptor custody");
    let pin = admitted.manifest_digest();
    let set = admitted
        .prepare_descriptors(2, &Cancellation::default())
        .unwrap();
    drop(admitted);
    for descriptor in set.descriptors() {
        File::from(descriptor.try_clone().unwrap())
            .seek(SeekFrom::End(0))
            .unwrap();
    }
    let mut reader = ChunkedDescriptorReader::from_received(
        pin,
        clone_fds(&set),
        1024,
        2,
        &Cancellation::default(),
    )
    .unwrap();
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"descriptor custody");
    drop(set);
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    // Open descriptors alone do not replace the trusted retention handoff.
    reader.seek(SeekFrom::Start(0)).unwrap();
    assert!(reader.read(&mut [0]).is_err());
}

#[test]
fn wrong_role_order_count_pin_limits_and_writable_descriptors_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let bytes = vec![0x41; CHUNK_BYTES + 7];
    let admitted = artifact(&store, &bytes);
    let cancel = Cancellation::default();
    let set = admitted.prepare_descriptors(3, &cancel).unwrap();
    for index in 0..7 {
        let mut descriptors = clone_fds(&set);
        let mut pin = set.manifest_digest();
        let mut maximum = bytes.len() as u64;
        let mut slots = 3;
        match index {
            0 => {
                descriptors.swap(1, 2);
            }
            1 => {
                descriptors.pop();
            }
            2 => pin = ContentDigest::sha256(b"different manifest"),
            3 => maximum -= 1,
            4 => slots = 2,
            5 => {
                descriptors[1] = File::create(directory.path().join("writable"))
                    .unwrap()
                    .into();
            }
            6 => {
                descriptors.clear();
            }
            _ => unreachable!(),
        }
        assert!(
            ChunkedDescriptorReader::from_received(pin, descriptors, maximum, slots, &cancel)
                .is_err(),
            "case {index}"
        );
    }
    assert!(
        ChunkedDescriptorReader::from_received(
            set.manifest_digest(),
            clone_fds(&set),
            super::super::MAX_ARTIFACT_BYTES + 1,
            3,
            &cancel
        )
        .is_err()
    );
}

#[test]
fn authenticated_manifest_with_false_whole_content_digest_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let admitted = artifact(&store, b"real content");
    let cancel = Cancellation::default();
    let set = admitted.prepare_descriptors(2, &cancel).unwrap();
    let mut manifest = admitted.manifest().clone();
    manifest.content = ContentDigest::sha256(b"false whole-content claim");
    let bytes = manifest.canonical_bytes();
    let pin = ContentDigest::sha256(&bytes);
    let operation = store.operation().unwrap();
    operation
        .ingest(bytes.as_slice(), pin, bytes.len() as u64)
        .unwrap();
    let source = operation
        .open_verified(pin, bytes.len() as u64)
        .unwrap()
        .unwrap();
    let mut descriptors = clone_fds(&set);
    descriptors[0] = source.duplicate_readonly_descriptor().unwrap();
    assert!(matches!(
        ChunkedDescriptorReader::from_received(pin, descriptors, 1024, 2, &cancel),
        Err(ChunkedArtifactError::ContentMismatch { .. })
    ));
}

#[test]
fn chunk_changes_after_construction_fail_before_exposing_new_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let bytes = b"original chunk";
    let admitted = artifact(&store, bytes);
    let cancel = Cancellation::default();
    let set = admitted.prepare_descriptors(2, &cancel).unwrap();
    let mut reader = ChunkedDescriptorReader::from_received(
        set.manifest_digest(),
        clone_fds(&set),
        1024,
        2,
        &cancel,
    )
    .unwrap();
    let path = object_path(directory.path(), admitted.manifest().chunks()[0]);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(path, b"mutated  chunk").unwrap();
    let mut output = [0xa5; 14];
    assert!(reader.read(&mut output).is_err());
    assert_eq!(output, [0xa5; 14]);
}

#[test]
fn empty_stream_and_cancellation_have_explicit_descriptor_contracts() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let admitted = artifact(&store, b"");
    let cancel = Cancellation::default();
    assert!(admitted.prepare_descriptors(0, &cancel).is_err());
    let set = admitted.prepare_descriptors(1, &cancel).unwrap();
    assert_eq!(set.descriptors().len(), 1);
    let mut reader = ChunkedDescriptorReader::from_received(
        set.manifest_digest(),
        clone_fds(&set),
        0,
        1,
        &cancel,
    )
    .unwrap();
    assert_eq!(reader.read(&mut [0]).unwrap(), 0);
    assert!(reader.seek(SeekFrom::Current(-1)).is_err());
    assert_eq!(
        reader.seek(SeekFrom::Start(u64::MAX)).unwrap(),
        u64::MAX
    );
    assert!(reader.seek(SeekFrom::Current(1)).is_err());
    cancel.cancel();
    assert!(admitted.prepare_descriptors(1, &cancel).is_err());
    assert!(reader.read(&mut [0]).is_err());
    assert!(reader.seek(SeekFrom::Start(0)).is_err());
    assert!(matches!(
        ChunkedDescriptorReader::from_received(
            set.manifest_digest(),
            clone_fds(&set),
            0,
            1,
            &cancel
        ),
        Err(ChunkedArtifactError::Cancelled)
    ));
}

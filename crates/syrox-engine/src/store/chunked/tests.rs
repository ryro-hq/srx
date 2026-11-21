use super::*;
use crate::store::{GcLimits, GcReport, GcRequest, RecoveryLimits, Store};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

fn fixture() -> (tempfile::TempDir, Store) {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    (directory, store)
}

fn object_path(root: &Path, digest: ContentDigest) -> PathBuf {
    root.join("objects/sha256")
        .join(&digest.to_string()[..2])
        .join(digest.to_string())
}

fn ingest(operation: &OperationLease, bytes: &[u8]) -> RetainedChunkedArtifact {
    operation
        .ingest_chunked(
            bytes,
            ContentDigest::sha256(bytes),
            bytes.len() as u64,
            &Cancellation::default(),
        )
        .unwrap()
}

fn collect(store: &Store, remove_roots: Vec<RootName>) -> GcReport {
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain);
    assert!(report.failures.is_empty());
    report
}

fn admit_manifest(operation: &OperationLease, manifest: &ChunkedArtifactManifest) -> ContentDigest {
    let bytes = manifest.canonical_bytes();
    let pin = ContentDigest::sha256(&bytes);
    operation
        .ingest(bytes.as_slice(), pin, bytes.len() as u64)
        .unwrap();
    pin
}

#[test]
fn chunked_manifest_has_a_fixed_wire_identity() {
    let content: ContentDigest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        .parse()
        .unwrap();
    let manifest = ChunkedArtifactManifest {
        content,
        size: 3,
        chunks: vec![content],
    };
    let mut expected =
        b"syrox-chunked-artifact-v1\n\x00\x00\x40\x00\x03\x00\x00\x00\x00\x00\x00\x00".to_vec();
    expected.extend_from_slice(content.as_bytes());
    expected.extend_from_slice(&[1, 0, 0, 0]);
    expected.extend_from_slice(content.as_bytes());
    assert_eq!(manifest.canonical_bytes(), expected);
    assert_eq!(
        ContentDigest::sha256(&expected).to_string(),
        "a8620b3a02fb5fafe38f57d5ccd7670c5edcd6c1034480e95e41cd1db5da359e"
    );
    assert_eq!(
        ChunkedArtifactManifest::decode(&expected, 3).unwrap(),
        manifest
    );
}

#[test]
fn chunk_boundaries_empty_streams_and_reopening_preserve_content() {
    for size in [
        0,
        1,
        CHUNK_BYTES - 1,
        CHUNK_BYTES,
        CHUNK_BYTES + 1,
        2 * CHUNK_BYTES + 17,
    ] {
        let (_directory, store) = fixture();
        let operation = store.operation().unwrap();
        let mut data = vec![7; size];
        if let Some(last) = data.last_mut() {
            *last = 19;
        }
        let artifact = ingest(&operation, &data);
        assert_eq!(artifact.manifest().size(), size as u64);
        assert_eq!(
            artifact.manifest().chunks().len(),
            size.div_ceil(CHUNK_BYTES)
        );
        let pin = artifact.manifest_digest();
        assert_eq!(
            pin,
            ContentDigest::sha256(&artifact.manifest().canonical_bytes())
        );
        let reopened = operation
            .open_chunked(pin, size as u64, &Cancellation::default())
            .unwrap()
            .unwrap();
        assert_eq!(reopened.manifest(), artifact.manifest());
        drop(operation);
        let mut output = Vec::new();
        assert_eq!(
            reopened
                .copy_to(&mut output, &Cancellation::default())
                .unwrap(),
            size as u64
        );
        assert_eq!(output, data);
    }
}

struct ShortReads<R> {
    source: R,
    interrupted: bool,
}
impl<R: Read> Read for ShortReads<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        assert!(buffer.len() <= IO_BYTES);
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let count = buffer.len().min(997);
        self.source.read(&mut buffer[..count])
    }
}

#[test]
fn short_reads_and_interrupted_io_do_not_change_manifest_identity() {
    let (_directory, store) = fixture();
    let operation = store.operation().unwrap();
    let bytes = vec![3; CHUNK_BYTES + 43];
    let regular = ingest(&operation, &bytes);
    let short = operation
        .ingest_chunked(
            ShortReads {
                source: bytes.as_slice(),
                interrupted: false,
            },
            ContentDigest::sha256(&bytes),
            bytes.len() as u64,
            &Cancellation::default(),
        )
        .unwrap();
    assert_eq!(regular.manifest_digest(), short.manifest_digest());
    assert_eq!(regular.manifest(), short.manifest());
}

#[test]
fn wrong_content_pin_never_publishes_the_manifest_and_chunks_are_collectible() {
    let (_directory, store) = fixture();
    let operation = store.operation().unwrap();
    let bytes = vec![5; CHUNK_BYTES + 13];
    let wrong = ContentDigest::sha256(b"different content");
    let chunks: Vec<_> = bytes
        .chunks(CHUNK_BYTES)
        .map(ContentDigest::sha256)
        .collect();
    let manifest = ChunkedArtifactManifest {
        content: wrong,
        size: bytes.len() as u64,
        chunks: chunks.clone(),
    };
    let pin = ContentDigest::sha256(&manifest.canonical_bytes());
    assert!(matches!(
        operation.ingest_chunked(
            bytes.as_slice(),
            wrong,
            bytes.len() as u64,
            &Cancellation::default()
        ),
        Err(ChunkedArtifactError::ContentMismatch { .. })
    ));
    assert!(operation.verify(pin).unwrap().is_none());
    drop(operation);
    assert_eq!(
        collect(&store, vec![])
            .removed_objects
            .into_iter()
            .collect::<BTreeSet<_>>(),
        chunks.into_iter().collect()
    );
}

struct NeverRead;
impl Read for NeverRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("preflight must reject without reading")
    }
}

#[test]
fn invalid_budgets_and_precancelled_operations_fail_before_reading_or_publication() {
    let (_directory, store) = fixture();
    let operation = store.operation().unwrap();
    let pin = ContentDigest::sha256(b"");
    assert!(matches!(
        operation.ingest_chunked(
            NeverRead,
            pin,
            MAX_ARTIFACT_BYTES + 1,
            &Cancellation::default()
        ),
        Err(ChunkedArtifactError::InvalidLimit { .. })
    ));
    assert!(matches!(
        operation.open_chunked(pin, u64::MAX, &Cancellation::default()),
        Err(ChunkedArtifactError::InvalidLimit { .. })
    ));
    let cancellation = Cancellation::default();
    cancellation.cancel();
    assert!(matches!(
        operation.ingest_chunked(NeverRead, pin, 10, &cancellation),
        Err(ChunkedArtifactError::Cancelled)
    ));
    assert!(matches!(
        operation.open_chunked(pin, 10, &cancellation),
        Err(ChunkedArtifactError::Cancelled)
    ));
    drop(operation);
    assert!(collect(&store, vec![]).removed_objects.is_empty());
}

#[test]
fn stream_budgets_consume_at_most_one_extra_byte_and_admit_no_manifest() {
    let (_directory, store) = fixture();
    let operation = store.operation().unwrap();
    for limit in [
        0,
        3,
        CHUNK_BYTES as u64,
        CHUNK_BYTES as u64 + 5,
    ] {
        let mut source = io::repeat(8).take(limit + 100);
        assert!(
            matches!(operation.ingest_chunked(&mut source, ContentDigest::sha256(b"unused"), limit, &Cancellation::default()), Err(ChunkedArtifactError::TooLarge { limit: observed }) if observed == limit)
        );
        assert_eq!(source.limit(), 99);
    }
    drop(operation);
    // Only the complete first chunk from the larger attempts could be published.
    assert_eq!(
        collect(&store, vec![]).removed_objects,
        [ContentDigest::sha256(&vec![
            8;
            CHUNK_BYTES
        ])]
    );
}

struct InterruptedSource {
    remaining: usize,
    cancellation: Option<Cancellation>,
}
impl Read for InterruptedSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            if let Some(cancellation) = &self.cancellation {
                cancellation.cancel();
                return Ok(0);
            }
            return Err(io::Error::other("source disconnected"));
        }
        let count = buffer.len().min(self.remaining);
        buffer[..count].fill(9);
        self.remaining -= count;
        Ok(count)
    }
}

#[test]
fn cancellation_and_source_failure_leave_only_recoverable_unretained_chunks() {
    for cancelled in [false, true] {
        let (directory, store) = fixture();
        let operation = store.operation().unwrap();
        let cancellation = Cancellation::default();
        let result = operation.ingest_chunked(
            InterruptedSource {
                remaining: CHUNK_BYTES + 71,
                cancellation: cancelled.then(|| cancellation.clone()),
            },
            ContentDigest::sha256(b"unused"),
            2 * CHUNK_BYTES as u64,
            &cancellation,
        );
        if cancelled {
            assert!(matches!(
                result,
                Err(ChunkedArtifactError::Cancelled)
            ));
        } else {
            assert!(matches!(result, Err(ChunkedArtifactError::Io(_))));
        }
        drop(operation);
        // Model a staging file left by a terminated publisher. It shares the
        // established Store recovery format; no artifact-specific deletion path.
        let temporary = directory
            .path()
            .join("objects/sha256/00")
            .join(format!(
                "{}{}",
                super::super::OBJECT_TEMP_PREFIX,
                "c".repeat(32)
            ));
        fs::write(&temporary, b"partial").unwrap();
        let report = store
            .maintenance()
            .unwrap()
            .recover(RecoveryLimits::default())
            .unwrap();
        assert!(!report.uncertain);
        assert_eq!(report.removed.len(), 1);
        assert!(!temporary.exists());
        assert_eq!(
            collect(&store, vec![]).removed_objects,
            [ContentDigest::sha256(&vec![
                9;
                CHUNK_BYTES
            ])]
        );
    }
}

#[test]
fn malformed_manifests_are_rejected_before_allocating_claimed_chunks() {
    let base = ChunkedArtifactManifest {
        content: ContentDigest::sha256(b""),
        size: 0,
        chunks: vec![],
    }
    .canonical_bytes();
    let mut cases = vec![vec![], base[..base.len() - 1].to_vec()];
    let mut version = base.clone();
    version[HEADER.len() - 2] = b'2';
    cases.push(version);
    let mut chunk_size = base.clone();
    chunk_size[HEADER.len()..HEADER.len() + 4].copy_from_slice(&1_u32.to_le_bytes());
    cases.push(chunk_size);
    let mut count = base.clone();
    count[HEADER.len() + 44..HEADER.len() + 48].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push(count);
    let mut length = base.clone();
    length[HEADER.len() + 4..HEADER.len() + 12].copy_from_slice(&1_u64.to_le_bytes());
    cases.push(length);
    let mut trailing = base.clone();
    trailing.push(0);
    cases.push(trailing);
    cases.push(vec![0; MAX_MANIFEST_BYTES + 1]);
    for bytes in cases {
        assert!(matches!(
            ChunkedArtifactManifest::decode(&bytes, MAX_ARTIFACT_BYTES),
            Err(ChunkedArtifactError::InvalidManifest(_))
        ));
    }
    assert_eq!(
        ChunkedArtifactManifest::decode(&base, 0)
            .unwrap()
            .canonical_bytes(),
        base
    );
}

#[test]
fn manifest_limits_allow_the_maximum_without_allocating_payloads() {
    let manifest = ChunkedArtifactManifest {
        content: ContentDigest::sha256(b"content"),
        size: MAX_ARTIFACT_BYTES,
        chunks: vec![ContentDigest::sha256(b"chunk"); MAX_CHUNKS],
    };
    let bytes = manifest.canonical_bytes();
    assert_eq!(bytes.len(), MAX_MANIFEST_BYTES);
    assert_eq!(
        ChunkedArtifactManifest::decode(&bytes, MAX_ARTIFACT_BYTES).unwrap(),
        manifest
    );
    assert_eq!(
        manifest
            .references(ContentDigest::sha256(&bytes))
            .len(),
        2
    );
    assert!(matches!(
        ChunkedArtifactManifest::decode(&bytes, MAX_ARTIFACT_BYTES - 1),
        Err(ChunkedArtifactError::TooLarge { .. })
    ));
}

#[test]
fn opening_missing_manifests_is_distinct_from_missing_or_corrupt_chunks() {
    let (directory, store) = fixture();
    let operation = store.operation().unwrap();
    assert!(
        operation
            .open_chunked(
                ContentDigest::sha256(b"missing"),
                100,
                &Cancellation::default()
            )
            .unwrap()
            .is_none()
    );
    let artifact = ingest(&operation, b"payload");
    let chunk = artifact.manifest().chunks()[0];
    let path = object_path(directory.path(), chunk);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"damaged").unwrap();
    assert!(matches!(
        operation.open_chunked(
            artifact.manifest_digest(),
            100,
            &Cancellation::default()
        ),
        Err(ChunkedArtifactError::Store(
            StoreError::CorruptObject { .. }
        ))
    ));
    fs::remove_file(&path).unwrap();
    assert!(
        matches!(operation.open_chunked(artifact.manifest_digest(), 100, &Cancellation::default()), Err(ChunkedArtifactError::MissingChunk { digest }) if digest == chunk)
    );
    let mut output = Vec::new();
    assert!(
        artifact
            .copy_to(&mut output, &Cancellation::default())
            .is_err()
    );
    assert!(output.is_empty());
}

#[test]
fn ordered_content_and_exact_chunk_lengths_are_verified_in_addition_to_each_hash() {
    let (_directory, store) = fixture();
    let operation = store.operation().unwrap();
    let mut data = vec![1; CHUNK_BYTES];
    data.extend_from_slice(&vec![2; CHUNK_BYTES]);
    let artifact = ingest(&operation, &data);
    let mut reordered = artifact.manifest().clone();
    reordered.chunks.reverse();
    let pin = admit_manifest(&operation, &reordered);
    assert!(matches!(
        operation.open_chunked(pin, data.len() as u64, &Cancellation::default()),
        Err(ChunkedArtifactError::ContentMismatch { .. })
    ));
    let mut wrong_size = artifact.manifest().clone();
    wrong_size.size -= 1;
    let pin = admit_manifest(&operation, &wrong_size);
    assert!(matches!(
        operation.open_chunked(pin, data.len() as u64, &Cancellation::default()),
        Err(ChunkedArtifactError::ChunkSize { .. })
    ));
    assert!(matches!(
        operation.open_chunked(
            artifact.manifest_digest(),
            data.len() as u64 - 1,
            &Cancellation::default()
        ),
        Err(ChunkedArtifactError::TooLarge { .. })
    ));
    let bad_empty = ChunkedArtifactManifest {
        content: ContentDigest::sha256(b"not empty"),
        size: 0,
        chunks: vec![],
    };
    assert!(matches!(
        operation.open_chunked(
            admit_manifest(&operation, &bad_empty),
            0,
            &Cancellation::default()
        ),
        Err(ChunkedArtifactError::ContentMismatch { .. })
    ));
}

#[test]
fn roots_expand_the_complete_closure_and_shared_chunks_survive_other_root_removal() {
    let (directory, store) = fixture();
    let operation = store.operation().unwrap();
    let mut first_data = vec![6; CHUNK_BYTES];
    first_data.push(1);
    let first = ingest(&operation, &first_data);
    let mut second_data = first_data.clone();
    *second_data.last_mut().unwrap() = 2;
    let second = ingest(&operation, &second_data);
    assert_eq!(
        first.manifest().chunks()[0],
        second.manifest().chunks()[0]
    );
    let first_root = RootName::new("first_image").unwrap();
    let second_root = RootName::new("second_image").unwrap();
    first
        .publish_root(&first_root, &Cancellation::default())
        .unwrap();
    second
        .publish_root(&second_root, &Cancellation::default())
        .unwrap();
    assert_eq!(
        operation
            .build_references(&first_root)
            .unwrap()
            .unwrap(),
        first
            .manifest()
            .references(first.manifest_digest())
    );
    let first_only = BTreeSet::from([
        first.manifest_digest(),
        first.manifest().chunks()[1],
    ]);
    let second_pin = second.manifest_digest();
    let second_refs: BTreeSet<_> = second
        .manifest()
        .references(second_pin)
        .into_iter()
        .collect();
    drop((operation, first, second));
    assert_eq!(
        collect(&store, vec![first_root])
            .removed_objects
            .into_iter()
            .collect::<BTreeSet<_>>(),
        first_only
    );
    let reopened_store = Store::open_existing(directory.path()).unwrap();
    let operation = reopened_store.operation().unwrap();
    let reopened = operation
        .open_chunked(
            second_pin,
            second_data.len() as u64,
            &Cancellation::default(),
        )
        .unwrap()
        .unwrap();
    let mut output = Vec::new();
    reopened
        .copy_to(&mut output, &Cancellation::default())
        .unwrap();
    assert_eq!(output, second_data);
    drop((operation, reopened));
    assert_eq!(
        collect(&store, vec![second_root])
            .removed_objects
            .into_iter()
            .collect::<BTreeSet<_>>(),
        second_refs
    );
}

#[test]
fn corrupt_retained_closure_causes_zero_gc_deletions_including_requested_roots() {
    let (directory, store) = fixture();
    let operation = store.operation().unwrap();
    let artifact = ingest(&operation, b"image");
    let root = RootName::new("booted_image").unwrap();
    artifact
        .publish_root(&root, &Cancellation::default())
        .unwrap();
    let unrelated = ContentDigest::sha256(b"unrelated");
    operation
        .ingest(b"unrelated".as_slice(), unrelated, 9)
        .unwrap();
    fs::remove_file(object_path(
        directory.path(),
        artifact.manifest().chunks()[0],
    ))
    .unwrap();
    drop((operation, artifact));
    assert!(matches!(
        store
            .maintenance()
            .unwrap()
            .garbage_collect(&GcRequest {
                collect: true,
                remove_roots: vec![root.clone()],
                ..GcRequest::default()
            }),
        Err(StoreError::MissingRootObject { .. })
    ));
    assert!(
        directory
            .path()
            .join("roots/retained")
            .join(root.as_str())
            .exists()
    );
    assert!(
        store
            .operation()
            .unwrap()
            .verify(unrelated)
            .unwrap()
            .is_some()
    );
}

struct CollectDuringWrite<'a> {
    store: &'a Store,
    root: Option<RootName>,
    bytes: Vec<u8>,
}
impl Write for CollectDuringWrite<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if let Some(root) = self.root.take() {
            // This succeeds only if copy_to releases every operation barrier
            // before calling a potentially slow destination.
            assert!(
                collect(self.store, vec![root])
                    .removed_objects
                    .is_empty()
            );
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn granular_interests_protect_all_chunks_without_blocking_gc_during_copy() {
    let (_directory, store) = fixture();
    let operation = store.operation().unwrap();
    let data = vec![4; CHUNK_BYTES + 3];
    let artifact = ingest(&operation, &data);
    let root = RootName::new("candidate_image").unwrap();
    artifact
        .publish_root(&root, &Cancellation::default())
        .unwrap();
    let surviving = artifact.clone();
    let references: BTreeSet<_> = artifact
        .manifest()
        .references(artifact.manifest_digest())
        .into_iter()
        .collect();
    drop((operation, artifact));
    let mut writer = CollectDuringWrite {
        store: &store,
        root: Some(root),
        bytes: Vec::new(),
    };
    surviving
        .copy_to(&mut writer, &Cancellation::default())
        .unwrap();
    assert_eq!(writer.bytes, data);
    drop(surviving);
    assert_eq!(
        collect(&store, vec![])
            .removed_objects
            .into_iter()
            .collect::<BTreeSet<_>>(),
        references
    );
}

struct CancelOnWrite {
    cancellation: Cancellation,
    written: usize,
}
impl Write for CancelOnWrite {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.written += buffer.len();
        self.cancellation.cancel();
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn copy_cancellation_and_root_conflicts_preserve_existing_custody_and_evidence() {
    let (directory, store) = fixture();
    let operation = store.operation().unwrap();
    let data = vec![2; IO_BYTES * 2];
    let artifact = ingest(&operation, &data);
    let different = ingest(&operation, b"other image");
    let root = RootName::new("immutable_image").unwrap();
    assert_eq!(
        artifact
            .publish_root(&root, &Cancellation::default())
            .unwrap(),
        RootPublicationState::Published
    );
    assert_eq!(
        artifact
            .publish_root(&root, &Cancellation::default())
            .unwrap(),
        RootPublicationState::Existing
    );
    assert!(matches!(
        different.publish_root(&root, &Cancellation::default()),
        Err(ChunkedArtifactError::Store(
            StoreError::RootConflict { .. }
        ))
    ));
    let cancellation = Cancellation::default();
    let mut writer = CancelOnWrite {
        cancellation: cancellation.clone(),
        written: 0,
    };
    assert!(matches!(
        artifact.copy_to(&mut writer, &cancellation),
        Err(ChunkedArtifactError::Cancelled)
    ));
    assert_eq!(writer.written, IO_BYTES);
    let cancelled_root = RootName::new("cancelled_image").unwrap();
    assert!(matches!(
        artifact.publish_root(&cancelled_root, &cancellation),
        Err(ChunkedArtifactError::Cancelled)
    ));
    assert!(
        !directory
            .path()
            .join("roots/retained")
            .join(cancelled_root.as_str())
            .exists()
    );
    let mut output = Vec::new();
    artifact
        .copy_to(&mut output, &Cancellation::default())
        .unwrap();
    assert_eq!(output, data);
}

#[test]
fn gc_reference_budget_failure_leaves_the_artifact_root_and_objects_untouched() {
    let (directory, store) = fixture();
    let operation = store.operation().unwrap();
    let artifact = ingest(&operation, &vec![1; CHUNK_BYTES + 1]);
    let root = RootName::new("image").unwrap();
    artifact
        .publish_root(&root, &Cancellation::default())
        .unwrap();
    let pin = artifact.manifest_digest();
    drop((operation, artifact));
    assert!(matches!(
        store
            .maintenance()
            .unwrap()
            .garbage_collect(&GcRequest {
                collect: true,
                remove_roots: vec![root.clone()],
                limits: GcLimits {
                    references: 2,
                    ..GcLimits::default()
                }
            }),
        Err(StoreError::LimitExceeded { .. })
    ));
    assert!(
        directory
            .path()
            .join("roots/retained")
            .join(root.as_str())
            .exists()
    );
    assert!(
        store
            .operation()
            .unwrap()
            .open_chunked(
                pin,
                CHUNK_BYTES as u64 + 1,
                &Cancellation::default()
            )
            .unwrap()
            .is_some()
    );
}

#[test]
fn artifact_larger_than_the_single_blob_limit_streams_without_a_large_blob() {
    let (_directory, store) = fixture();
    let operation = store.operation().unwrap();
    let size = super::super::MAX_STORE_BLOB_BYTES + 19;
    let mut source = io::repeat(11).take(size);
    let mut content = Sha256::new();
    let block = vec![11; IO_BYTES];
    let mut remaining = size;
    while remaining != 0 {
        let count = usize::try_from(remaining.min(IO_BYTES as u64)).unwrap();
        content.update(&block[..count]);
        remaining -= count as u64;
    }
    let expected = ContentDigest::from_sha256_hash(content.finalize().into());
    let artifact = operation
        .ingest_chunked(
            &mut source,
            expected,
            size,
            &Cancellation::default(),
        )
        .unwrap();
    assert_eq!(artifact.manifest().size(), size);
    assert_eq!(
        artifact.manifest().chunks().len() as u64,
        size.div_ceil(CHUNK_BYTES as u64)
    );
    // Repeated chunks share one CAS identity, plus the tail and the manifest.
    assert_eq!(
        artifact
            .manifest()
            .references(artifact.manifest_digest())
            .len(),
        3
    );
    drop(operation);
    assert_eq!(
        artifact
            .copy_to(&mut io::sink(), &Cancellation::default())
            .unwrap(),
        size
    );
}

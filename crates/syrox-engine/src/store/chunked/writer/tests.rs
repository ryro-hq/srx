use super::*;
use crate::store::{GcRequest, Store};

#[test]
fn producer_boundaries_and_flushes_preserve_existing_chunked_wire_identity() {
    for length in [
        0,
        1,
        CHUNK_BYTES - 1,
        CHUNK_BYTES,
        CHUNK_BYTES + 1,
        2 * CHUNK_BYTES + 17,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::initialize(directory.path()).unwrap();
        let operation = store.operation().unwrap();
        let cancellation = Cancellation::default();
        let bytes = vec![0x53; length];
        let expected = ContentDigest::sha256(&bytes);
        let admitted = operation
            .ingest_chunked(
                bytes.as_slice(),
                expected,
                length as u64,
                &cancellation,
            )
            .unwrap();
        let mut producer = operation
            .begin_chunked(length as u64, &cancellation)
            .unwrap();
        for fragment in bytes.chunks(7919) {
            producer.append(fragment).unwrap();
            producer.flush().unwrap();
        }
        assert_eq!(producer.size(), length as u64);
        let streamed = producer.finish(expected).unwrap();
        assert_eq!(streamed.manifest(), admitted.manifest());
        assert_eq!(
            streamed.manifest_digest(),
            admitted.manifest_digest()
        );
        let mut producer = operation
            .begin_chunked(length as u64, &cancellation)
            .unwrap();
        producer.write_all(&bytes).unwrap();
        assert_eq!(
            producer
                .finish(expected)
                .unwrap()
                .manifest_digest(),
            admitted.manifest_digest()
        );
    }
}

#[test]
fn oversized_append_and_io_failure_poison_staging_instead_of_finishing_a_short_image() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let operation = store.operation().unwrap();
    let cancellation = Cancellation::default();
    let mut producer = operation.begin_chunked(3, &cancellation).unwrap();
    producer.append(b"ab").unwrap();
    assert!(matches!(
        producer.append(b"cd"),
        Err(ChunkedArtifactError::TooLarge {
            limit: 3
        })
    ));
    assert_eq!(producer.size(), 2);
    assert!(matches!(
        producer.append(b"c"),
        Err(ChunkedArtifactError::FailedStaging)
    ));
    assert!(matches!(
        producer.finish(ContentDigest::sha256(b"ab")),
        Err(ChunkedArtifactError::FailedStaging)
    ));
    let mut producer = operation.begin_chunked(3, &cancellation).unwrap();
    assert!(producer.write_all(b"oversized").is_err());
    assert!(producer.flush().is_err());
    assert!(matches!(
        producer.finish(ContentDigest::sha256(b"")),
        Err(ChunkedArtifactError::FailedStaging)
    ));
}

#[test]
fn dropped_or_mismatched_streams_publish_no_manifest_and_their_chunks_are_collectible() {
    for finish in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::initialize(directory.path()).unwrap();
        let operation = store.operation().unwrap();
        let cancellation = Cancellation::default();
        let payload = vec![0x41; CHUNK_BYTES];
        let chunk = ContentDigest::sha256(&payload);
        let manifest = ChunkedArtifactManifest {
            content: chunk,
            size: CHUNK_BYTES as u64,
            chunks: vec![chunk],
        };
        let manifest_pin = ContentDigest::sha256(&manifest.canonical_bytes());
        let mut producer = operation
            .begin_chunked(CHUNK_BYTES as u64, &cancellation)
            .unwrap();
        producer.append(&payload).unwrap();
        producer.flush().unwrap();
        assert!(operation.verify(chunk).unwrap().is_some());
        assert!(operation.verify(manifest_pin).unwrap().is_none());
        if finish {
            assert!(matches!(
                producer.finish(ContentDigest::sha256(b"wrong")),
                Err(ChunkedArtifactError::ContentMismatch { .. })
            ));
        } else {
            drop(producer);
        }
        drop(operation);
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
                .verify(chunk)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .operation()
                .unwrap()
                .verify(manifest_pin)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn cancellation_and_hard_caps_fail_before_manifest_publication() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let operation = store.operation().unwrap();
    let cancellation = Cancellation::default();
    assert!(matches!(
        operation.begin_chunked(
            super::super::MAX_ARTIFACT_BYTES + 1,
            &cancellation
        ),
        Err(ChunkedArtifactError::InvalidLimit { .. })
    ));
    let mut producer = operation.begin_chunked(1, &cancellation).unwrap();
    producer.append(b"a").unwrap();
    cancellation.cancel();
    assert!(producer.flush().is_err());
    assert!(matches!(
        producer.finish(ContentDigest::sha256(b"a")),
        Err(ChunkedArtifactError::FailedStaging)
    ));
    assert!(matches!(
        operation.begin_chunked(1, &cancellation),
        Err(ChunkedArtifactError::Cancelled)
    ));
}

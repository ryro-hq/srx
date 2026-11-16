use super::*;
use crate::{
    image::{PartitionImage, build_raw},
    store::GcRequest,
    system::{
        budget::{BuildBudget, BuilderLimits},
        disk::{DiskSpec, Guid, Partition},
    },
};
use std::{io::Read as _, os::unix::fs::PermissionsExt as _};

fn budget(output_bytes: u64) -> AdmittedBudget {
    let request = BuildBudget {
        memory_bytes: 32 * 1024 * 1024,
        cpu_percent: 100,
        processes: 8,
        descriptors: 32,
        scratch_bytes: 1024 * 1024,
        files: 1024,
        output_bytes,
        duration_seconds: 60,
    };
    BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap()
}
fn fixture(store: &Store) -> BuiltRaw {
    let bytes = vec![0x71; 4096];
    let hash = ContentDigest::sha256(&bytes);
    let source = store
        .operation()
        .unwrap()
        .ingest_chunked(
            &bytes[..],
            hash,
            bytes.len() as u64,
            &Cancellation::default(),
        )
        .unwrap();
    let layout = DiskSpec {
        bytes: 3 * 1024 * 1024,
        logical_block_bytes: 512,
        guid: Guid([1; 16]),
        partitions: vec![Partition {
            number: 1,
            partition_type: Guid([2; 16]),
            guid: Guid([3; 16]),
            start_bytes: 1024 * 1024,
            size_bytes: 4096,
            name: "root-a".into(),
            attributes: 0,
            image_bytes: bytes.len() as u64,
            image_sha256: *hash.as_bytes(),
        }],
    }
    .validate()
    .unwrap();
    build_raw(
        store,
        &layout,
        &[PartitionImage {
            number: 1,
            image: source,
        }],
        &budget(layout.specification().bytes),
        &Cancellation::default(),
    )
    .unwrap()
}

#[test]
fn qcow2_retains_complete_raw_gpt_provenance_and_partition_closures_after_gc() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let raw = fixture(&store);
    let cancelled = Cancellation::default();
    let admitted = budget(4 * 1024 * 1024);
    let image = build_qcow2(&store, &raw, &admitted, &cancelled).unwrap();
    let again = build_qcow2(&store, &raw, &admitted, &cancelled).unwrap();
    assert_eq!(image.manifest_digest(), again.manifest_digest());
    assert_eq!(
        image.raw().manifest_digest(),
        raw.manifest_digest()
    );
    assert_eq!(
        image.geometry().virtual_bytes(),
        raw.image().manifest().size()
    );
    let raw_references = raw.retained_references().to_vec();
    let manifest = image.manifest_digest();
    let pin = image.image().manifest_digest();
    let raw_metadata = raw.manifest_digest();
    image
        .publish_root(&RootName::new("qcow_image").unwrap(), &cancelled)
        .unwrap();
    drop((raw, image, again));
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    let operation = store.operation().unwrap();
    for reference in raw_references {
        assert!(
            operation
                .read_verified(reference, 4 * 1024 * 1024)
                .unwrap()
                .is_some()
        );
    }
    let image = operation
        .open_chunked(pin, 4 * 1024 * 1024, &cancelled)
        .unwrap()
        .unwrap();
    let mut bytes = Vec::new();
    image
        .open_reader(&cancelled)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(&bytes[..4], b"QFI\xfb");
    assert_eq!(
        ContentDigest::sha256(&bytes),
        image.manifest().content_digest()
    );
    let bytes = operation
        .read_verified(manifest, 16384)
        .unwrap()
        .unwrap()
        .into_bytes();
    let json: serde_json::Value = serde_json::from_slice(
        bytes
            .strip_prefix(b"syrox-qcow2-image-v1\n")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        json["raw_provenance_sha256"],
        raw_metadata.to_string()
    );
    assert_eq!(json["image_manifest_sha256"], pin.to_string());
}

#[test]
fn qcow2_rejects_foreign_inputs_inadequate_output_and_cancelled_requests() {
    let directory = tempfile::tempdir().unwrap();
    let second_directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let other = Store::open(second_directory.path()).unwrap();
    let raw = fixture(&store);
    let cancelled = Cancellation::default();
    let geometry = Geometry::new(raw.image().manifest().size()).unwrap();
    assert!(
        build_qcow2(
            &other,
            &raw,
            &budget(geometry.encoded_bytes()),
            &cancelled
        )
        .is_err()
    );
    assert!(
        build_qcow2(
            &store,
            &raw,
            &budget(geometry.encoded_bytes() - 1),
            &cancelled
        )
        .is_err()
    );
    cancelled.cancel();
    assert!(matches!(
        build_qcow2(
            &store,
            &raw,
            &budget(geometry.encoded_bytes()),
            &cancelled
        ),
        Err(ImageBuildError::Cancelled)
    ));
}

#[test]
fn qcow2_rechecks_corrupted_raw_cas_chunks_before_publishing_a_result() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let raw = fixture(&store);
    let chunk = raw.image().manifest().chunks()[0].to_string();
    let path = directory
        .path()
        .join("objects/sha256")
        .join(&chunk[..2])
        .join(&chunk);
    let permissions = std::fs::metadata(&path).unwrap().permissions();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, vec![0; 3 * 1024 * 1024]).unwrap();
    std::fs::set_permissions(&path, permissions).unwrap();
    assert!(
        build_qcow2(
            &store,
            &raw,
            &budget(4 * 1024 * 1024),
            &Cancellation::default()
        )
        .is_err()
    );
}

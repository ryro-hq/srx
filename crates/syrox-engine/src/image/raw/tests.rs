use super::*;
use crate::{
    store::GcRequest,
    system::{
        budget::{BuildBudget, BuilderLimits},
        disk::{DiskSpec, Guid, Partition},
    },
};
use std::os::unix::fs::PermissionsExt as _;

fn budget(bytes: u64) -> AdmittedBudget {
    let request = BuildBudget {
        memory_bytes: 32 * 1024 * 1024,
        cpu_percent: 100,
        processes: 16,
        descriptors: 32,
        scratch_bytes: 1024 * 1024,
        files: 1024,
        output_bytes: bytes,
        duration_seconds: 60,
    };
    BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap()
}
fn fixture(store: &Store) -> (DiskLayout, PartitionImage) {
    let bytes = vec![0x71; 70_001];
    let digest = ContentDigest::sha256(&bytes);
    let image = store
        .operation()
        .unwrap()
        .ingest_chunked(
            &bytes[..],
            digest,
            bytes.len() as u64,
            &Cancellation::default(),
        )
        .unwrap();
    let layout = DiskSpec {
        bytes: 12 * 1024 * 1024,
        logical_block_bytes: 512,
        guid: Guid([1; 16]),
        partitions: vec![Partition {
            number: 1,
            partition_type: Guid([2; 16]),
            guid: Guid([3; 16]),
            start_bytes: 1024 * 1024,
            size_bytes: 4 * 1024 * 1024,
            name: "root-a".into(),
            attributes: 0,
            image_bytes: bytes.len() as u64,
            image_sha256: *digest.as_bytes(),
        }],
    }
    .validate()
    .unwrap();
    (
        layout,
        PartitionImage {
            number: 1,
            image,
        },
    )
}

#[test]
fn raw_stream_metadata_inputs_and_chunks_survive_gc_and_rebuild_identically() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let (layout, input) = fixture(&store);
    let cancelled = Cancellation::default();
    let admitted = budget(layout.specification().bytes);
    let built = build_raw(
        &store,
        &layout,
        std::slice::from_ref(&input),
        &admitted,
        &cancelled,
    )
    .unwrap();
    let again = build_raw(
        &store,
        &layout,
        std::slice::from_ref(&input),
        &admitted,
        &cancelled,
    )
    .unwrap();
    assert_eq!(built.manifest_digest(), again.manifest_digest());
    assert_eq!(
        built.image().manifest_digest(),
        again.image().manifest_digest()
    );
    assert_eq!(built.layout(), &layout);
    let input_pin = input.image.manifest_digest();
    let image_pin = built.image().manifest_digest();
    let metadata_pin = built.manifest_digest();
    built
        .publish_root(&RootName::new("raw_image").unwrap(), &cancelled)
        .unwrap();
    drop((built, again, input));
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    let operation = store.operation().unwrap();
    assert!(
        operation
            .open_chunked(input_pin, 100_000, &cancelled)
            .unwrap()
            .is_some()
    );
    let image = operation
        .open_chunked(
            image_pin,
            layout.specification().bytes,
            &cancelled,
        )
        .unwrap()
        .unwrap();
    let mut bytes = Vec::new();
    image
        .open_reader(&cancelled)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(&bytes[512..520], b"EFI PART");
    assert_eq!(
        &bytes[bytes.len() - 512..bytes.len() - 504],
        b"EFI PART"
    );
    assert_eq!(
        &bytes[1024 * 1024..1024 * 1024 + 70_001],
        &vec![0x71; 70_001]
    );
    assert_eq!(
        ContentDigest::sha256(&bytes),
        image.manifest().content_digest()
    );
    let metadata = operation
        .read_verified(metadata_pin, 1024 * 1024)
        .unwrap()
        .unwrap()
        .into_bytes();
    let json: serde_json::Value = serde_json::from_slice(
        metadata
            .strip_prefix(b"syrox-raw-image\n")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        json["partitions"][0]["chunk_manifest_sha256"],
        input_pin.to_string()
    );
    assert_eq!(
        json["image_manifest_sha256"],
        image_pin.to_string()
    );
    assert_eq!(
        json["specification"]["bytes"],
        layout.specification().bytes
    );
}

#[test]
fn admission_rejects_foreign_missing_duplicate_wrong_identity_and_inadequate_output() {
    let directory = tempfile::tempdir().unwrap();
    let other_directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let other = Store::open(other_directory.path()).unwrap();
    let (layout, input) = fixture(&store);
    let (_, foreign) = fixture(&other);
    let cancelled = Cancellation::default();
    let admitted = budget(layout.specification().bytes);
    assert!(build_raw(&store, &layout, &[], &admitted, &cancelled).is_err());
    assert!(build_raw(&store, &layout, &[foreign], &admitted, &cancelled).is_err());
    let mut wrong = layout.specification().clone();
    wrong.partitions[0].image_sha256 = [0; 32];
    assert!(
        build_raw(
            &store,
            &wrong.validate().unwrap(),
            std::slice::from_ref(&input),
            &admitted,
            &cancelled
        )
        .is_err()
    );
    assert!(
        build_raw(
            &store,
            &layout,
            std::slice::from_ref(&input),
            &budget(layout.specification().bytes - 1),
            &cancelled
        )
        .is_err()
    );
    let mut two = layout.specification().clone();
    let mut second = two.partitions[0].clone();
    second.number = 2;
    second.guid = Guid([4; 16]);
    second.start_bytes = 6 * 1024 * 1024;
    two.partitions.push(second);
    assert!(
        build_raw(
            &store,
            &two.validate().unwrap(),
            &[input.clone(), input.clone()],
            &admitted,
            &cancelled
        )
        .is_err()
    );
    cancelled.cancel();
    assert!(matches!(
        build_raw(&store, &layout, &[input], &admitted, &cancelled),
        Err(ImageBuildError::Cancelled)
    ));
}

#[test]
fn raw_construction_rechecks_corrupted_cas_payloads() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let (layout, input) = fixture(&store);
    let digest = input.image.manifest().chunks()[0];
    let digest = digest.to_string();
    let path = directory
        .path()
        .join("objects/sha256")
        .join(&digest[..2])
        .join(&digest);
    let original = std::fs::metadata(&path).unwrap().permissions();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, vec![0x72; 70_001]).unwrap();
    std::fs::set_permissions(&path, original).unwrap();
    assert!(
        build_raw(
            &store,
            &layout,
            &[input],
            &budget(layout.specification().bytes),
            &Cancellation::default()
        )
        .is_err()
    );
}

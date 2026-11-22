use super::*;
use crate::{
    store::GcRequest,
    system::budget::{BuildBudget, BuilderLimits},
};
use std::os::unix::fs::PermissionsExt as _;

fn budget(output: u64, scratch: u64, memory: u64) -> AdmittedBudget {
    let request = BuildBudget {
        memory_bytes: memory,
        cpu_percent: 100,
        processes: 16,
        descriptors: 64,
        scratch_bytes: scratch,
        files: 1024,
        output_bytes: output,
        duration_seconds: 60,
    };
    BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap()
}

fn data(store: &Store, blocks: usize) -> RetainedChunkedArtifact {
    let bytes = vec![0x5a; blocks * 4096];
    store
        .operation()
        .unwrap()
        .ingest_chunked(
            &bytes[..],
            ContentDigest::sha256(&bytes),
            bytes.len() as u64,
            &Cancellation::default(),
        )
        .unwrap()
}

#[test]
fn data_hashes_and_parameters_survive_gc_and_rebuild_identically() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let source = data(&store, 129);
    let admitted = budget(1024 * 1024, 16384, 64 * 1024 * 1024);
    let cancellation = Cancellation::default();
    let image = build_verity(
        &store,
        &source,
        [0x23; 32],
        &admitted,
        &cancellation,
    )
    .unwrap();
    assert_eq!(image.geometry().level_blocks(), &[2, 1]);
    assert_eq!(image.hash_tree().manifest().size(), 3 * 4096);
    let rebuilt = build_verity(
        &store,
        &source,
        [0x23; 32],
        &admitted,
        &cancellation,
    )
    .unwrap();
    assert_eq!(image.root_hash(), rebuilt.root_hash());
    assert_eq!(image.manifest_digest(), rebuilt.manifest_digest());
    let source_pin = source.manifest_digest();
    let hash_pin = image.hash_tree().manifest_digest();
    let manifest = image.manifest_digest();
    image
        .publish_root(&RootName::new("verity").unwrap(), &cancellation)
        .unwrap();
    drop((source, rebuilt, image));
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
            .open_chunked(source_pin, 1024 * 1024, &cancellation)
            .unwrap()
            .is_some()
    );
    assert!(
        operation
            .open_chunked(hash_pin, 16384, &cancellation)
            .unwrap()
            .is_some()
    );
    let bytes = operation
        .read_verified(manifest, 16384)
        .unwrap()
        .unwrap()
        .into_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(
        bytes
            .strip_prefix(b"syrox-verity-image\n")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(metadata["hash_bytes"], 12288);
    assert_eq!(
        metadata["data_manifest_sha256"],
        source_pin.to_string()
    );
    assert_eq!(
        metadata["hash_manifest_sha256"],
        hash_pin.to_string()
    );
    assert_eq!(metadata["version"], 1);
    assert_eq!(metadata["superblock"], false);
    assert_eq!(metadata["hash_start_block"], 0);
    assert_eq!(metadata["salt"], "23".repeat(32));
}

#[test]
fn preflight_refuses_inadequate_budgets_foreign_inputs_and_cancellation() {
    let directory = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let foreign = Store::open(other.path()).unwrap();
    let source = data(&store, 129);
    let cancellation = Cancellation::default();
    for budget in [
        budget(129 * 4096, 16384, 64 * 1024 * 1024),
        budget(1024 * 1024, 12287, 64 * 1024 * 1024),
        budget(1024 * 1024, 16384, 1024 * 1024),
    ] {
        assert!(matches!(
            build_verity(&store, &source, [0; 32], &budget, &cancellation),
            Err(ImageBuildError::Input(_))
        ));
    }
    let budget = budget(1024 * 1024, 16384, 64 * 1024 * 1024);
    assert!(matches!(
        build_verity(&foreign, &source, [0; 32], &budget, &cancellation),
        Err(ImageBuildError::Input(_))
    ));
    cancellation.cancel();
    assert!(matches!(
        build_verity(&store, &source, [0; 32], &budget, &cancellation),
        Err(ImageBuildError::Cancelled)
    ));
}

#[test]
fn single_block_has_an_empty_hash_device_and_salt_changes_the_authorized_identity() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let data = data(&store, 1);
    let budget = budget(4096, 1, 64 * 1024 * 1024);
    let cancellation = Cancellation::default();
    let first = build_verity(&store, &data, [1; 32], &budget, &cancellation).unwrap();
    let second = build_verity(&store, &data, [2; 32], &budget, &cancellation).unwrap();
    assert_eq!(first.hash_tree().manifest().size(), 0);
    assert_ne!(first.root_hash(), second.root_hash());
    assert_ne!(first.manifest_digest(), second.manifest_digest());
}

#[test]
fn mutable_store_chunk_corruption_is_rejected_before_a_verity_manifest_is_returned() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let data = data(&store, 2);
    let chunk = data.manifest().chunks()[0].to_string();
    let path = directory
        .path()
        .join("objects/sha256")
        .join(&chunk[..2])
        .join(&chunk);
    // Deliberately corrupt the CAS inode while a handle retains its identity.
    let original_mode = std::fs::metadata(&path)
        .unwrap()
        .permissions()
        .mode();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, vec![0; 8192]).unwrap();
    std::fs::set_permissions(
        &path,
        std::fs::Permissions::from_mode(original_mode),
    )
    .unwrap();
    assert!(
        build_verity(
            &store,
            &data,
            [0; 32],
            &budget(16384, 4096, 64 * 1024 * 1024),
            &Cancellation::default()
        )
        .is_err()
    );
}

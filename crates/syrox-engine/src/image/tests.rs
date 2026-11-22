use super::*;
use crate::{
    result::{ResultManifest, admit_result},
    store::{GcRequest, chunked::CHUNK_BYTES},
    system::{
        budget::{BuildBudget, BuilderLimits},
        image::{ComponentEntry, ComponentManifest, Entry, FileMetadata},
    },
};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;

fn budget() -> AdmittedBudget {
    let request = BuildBudget {
        memory_bytes: 64 * 1024 * 1024,
        cpu_percent: 100,
        processes: 8,
        descriptors: 64,
        scratch_bytes: 1024 * 1024,
        files: 100,
        output_bytes: 16 * 1024 * 1024,
        duration_seconds: 60,
    };
    BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap()
}

fn output(store: &Store, bytes: &[u8]) -> MaterializedArtifact {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("init"), bytes).unwrap();
    let mut packed = Vec::new();
    crate::result::artifact::pack(directory.path(), &mut packed).unwrap();
    let artifact = ContentDigest::sha256(&packed);
    store
        .operation()
        .unwrap()
        .ingest(packed.as_slice(), artifact, packed.len() as u64)
        .unwrap();
    let metadata = format!(
        "syrox-package-result\n{{\"outputs\":{{\"data\":{{\"action\":\"{}\",\"output\":\"data\",\"artifact\":\"{artifact}\",\"files\":1}}}},\"commands\":{{}}}}\n",
        ContentDigest::sha256(b"fixture logical action")
    );
    let manifest = ResultManifest::parse(metadata.as_bytes()).unwrap();
    let cancel = Cancellation::default();
    admit_result(
        store,
        &RootName::new("fixture_input").unwrap(),
        &manifest,
        manifest.digest().unwrap(),
        &cancel,
    )
    .unwrap()
    .output("data")
    .unwrap()
    .open(store, &cancel)
    .unwrap()
}

fn tree(output: &MaterializedArtifact, bytes: &[u8]) -> SystemTree {
    let metadata = FileMetadata {
        uid: 0,
        gid: 0,
        mode: 0o755,
    };
    SystemTree::compose(
        &[ComponentManifest {
            identity_sha256: output.artifact().to_string(),
            entries: vec![
                ComponentEntry {
                    path: "/".into(),
                    entry: Entry::Directory {
                        metadata,
                    },
                },
                ComponentEntry {
                    path: "/init".into(),
                    entry: Entry::File {
                        metadata,
                        source: FileSource {
                            component: output.artifact().to_string(),
                            path: "init".into(),
                            content_sha256: ContentDigest::sha256(bytes).to_string(),
                            size_bytes: bytes.len() as u64,
                        },
                    },
                },
            ],
        }],
        &budget(),
    )
    .unwrap()
}

#[test]
fn package_to_chunked_initramfs_retains_tree_provenance_and_input_closure_across_gc() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let payload = vec![0x5a; CHUNK_BYTES + 17];
    let component = output(&store, &payload);
    let tree = tree(&component, &payload);
    let cancel = Cancellation::default();
    let image = build_initramfs(&store, &tree, &[&component], &budget(), &cancel).unwrap();
    assert_eq!(image.archive().manifest().chunks().len(), 2);
    let manifest_pin = image.manifest_digest();
    let tree_pin = image.tree_manifest_digest();
    let chunk_pin = image.archive().manifest_digest();
    let input_pin = component.artifact();
    let source_pin = match component.identity().origin {
        OutputOrigin::Imported {
            manifest,
        } => manifest,
        OutputOrigin::Built {
            ..
        } => panic!("fixture is imported"),
    };
    let image_root = RootName::new("qualified_structure_fixture").unwrap();
    image.publish_root(&image_root, &cancel).unwrap();
    drop(image);
    drop(component);
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![RootName::new("fixture_input").unwrap()],
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    let op = store.operation().unwrap();
    for pin in [
        manifest_pin,
        tree_pin,
        chunk_pin,
        input_pin,
        source_pin,
    ] {
        assert!(op.verify(pin).unwrap().is_some());
    }
    let manifest_bytes = op
        .read_verified(manifest_pin, MAX_METADATA_BYTES)
        .unwrap()
        .unwrap()
        .into_bytes();
    let provenance: serde_json::Value = serde_json::from_slice(
        manifest_bytes
            .strip_prefix(b"syrox-system-image\n")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(provenance["format"], "syrox-initramfs");
    assert_eq!(
        provenance["components"][0]["origin"]["kind"],
        "imported"
    );
    assert_eq!(
        provenance["components"][0]["origin"]["manifest_sha256"],
        source_pin.to_string()
    );
    let tree_bytes = op
        .read_verified(tree_pin, MAX_METADATA_BYTES)
        .unwrap()
        .unwrap()
        .into_bytes();
    assert_eq!(
        ContentDigest::sha256(&tree_bytes).to_string(),
        provenance["tree_sha256"].as_str().unwrap()
    );
    let archive = op
        .open_chunked(
            chunk_pin,
            budget().request().output_bytes,
            &cancel,
        )
        .unwrap()
        .unwrap();
    let mut emitted = Vec::new();
    archive.copy_to(&mut emitted, &cancel).unwrap();
    assert!(emitted.starts_with(b"070701"));
    assert!(
        emitted
            .windows(payload.len())
            .any(|window| window == payload)
    );
    drop(archive);
    drop(op);
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![image_root],
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    assert!(
        store
            .operation()
            .unwrap()
            .verify(manifest_pin)
            .unwrap()
            .is_none()
    );
}

#[test]
fn authenticated_artifact_bytes_override_changed_materialized_view_and_host_paths() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let component = output(&store, b"authentic");
    let tree = tree(&component, b"authentic");
    // The writer reopens verified CAS, never reads the physical view.
    let physical = component.directory().unwrap().join("init");
    fs::set_permissions(&physical, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(physical, b"ambient injected bytes").unwrap();
    let image = build_initramfs(
        &store,
        &tree,
        &[&component],
        &budget(),
        &Cancellation::default(),
    )
    .unwrap();
    let mut emitted = Vec::new();
    image
        .archive()
        .copy_to(&mut emitted, &Cancellation::default())
        .unwrap();
    assert!(
        emitted
            .windows(9)
            .any(|window| window == b"authentic")
    );
    assert!(
        !emitted
            .windows(8)
            .any(|window| window == b"injected")
    );
}

#[test]
fn missing_mismatched_foreign_and_cancelled_inputs_never_publish_an_image_manifest() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let component = output(&store, b"authentic");
    let tree = tree(&component, b"different");
    assert!(matches!(
        build_initramfs(
            &store,
            &tree,
            &[],
            &budget(),
            &Cancellation::default()
        ),
        Err(ImageBuildError::Input(_))
    ));
    assert!(matches!(
        build_initramfs(
            &store,
            &tree,
            &[&component],
            &budget(),
            &Cancellation::default()
        ),
        Err(ImageBuildError::Archive(ArchiveError::Content(_)))
    ));
    let foreign_dir = tempfile::tempdir().unwrap();
    let foreign = Store::initialize(foreign_dir.path()).unwrap();
    assert!(matches!(
        build_initramfs(
            &foreign,
            &tree,
            &[&component],
            &budget(),
            &Cancellation::default()
        ),
        Err(ImageBuildError::Input(_))
    ));
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(matches!(
        build_initramfs(&store, &tree, &[&component], &budget(), &cancel),
        Err(ImageBuildError::Cancelled)
    ));
    let roots = fs::read_dir(directory.path().join("roots"))
        .unwrap()
        .count();
    assert_eq!(
        roots, 1,
        "only the explicitly imported input has a durable root"
    );
}

#[test]
fn late_source_corruption_leaves_collectible_chunks_without_image_or_chunk_manifests() {
    use std::io::Read as _;

    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let payload = vec![0x5a; CHUNK_BYTES + 17];
    let component = output(&store, &payload);
    let wrong_content = vec![0x5b; payload.len()];
    let tree = tree(&component, &wrong_content);
    assert!(matches!(
        build_initramfs(
            &store,
            &tree,
            &[&component],
            &budget(),
            &Cancellation::default()
        ),
        Err(ImageBuildError::Archive(ArchiveError::Content(_)))
    ));
    let objects = directory.path().join("objects/sha256");
    let mut chunks = Vec::new();
    for shard in fs::read_dir(objects).unwrap() {
        for object in fs::read_dir(shard.unwrap().path()).unwrap() {
            let path = object.unwrap().path();
            let mut prefix = [0; 32];
            let count = fs::File::open(&path)
                .unwrap()
                .read(&mut prefix)
                .unwrap();
            assert!(!prefix[..count].starts_with(b"syrox-system-image\n"));
            assert!(!prefix[..count].starts_with(b"syrox-chunked-artifact\n"));
            if prefix[..count].starts_with(b"070701") {
                chunks.push(path);
            }
        }
    }
    assert_eq!(
        chunks.len(),
        1,
        "a complete first chunk was staged before the source hash failed"
    );
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    assert!(!chunks[0].exists());
    assert!(
        store
            .operation()
            .unwrap()
            .verify(component.artifact())
            .unwrap()
            .is_some()
    );
}

#[test]
fn chunked_system_output_feeds_initramfs_and_retains_its_complete_source_closure() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::initialize(temporary.path()).unwrap();
    let files = tempfile::tempdir().unwrap();
    let payload = vec![0x31; CHUNK_BYTES + 257];
    fs::write(files.path().join("init"), &payload).unwrap();
    let mut packed = Vec::new();
    crate::result::artifact::pack(files.path(), &mut packed).unwrap();
    let cancel = Cancellation::default();
    let budget = budget();
    let prepared = crate::result::ingest_system_output(
        &store,
        packed.as_slice(),
        ContentDigest::sha256(&packed),
        ContentDigest::sha256(b"chunked image fixture"),
        "out",
        &budget,
        &cancel,
    )
    .unwrap();
    let source_chunks = prepared.artifact().manifest().chunks().to_vec();
    let manifest = ResultManifest::for_system(
        BTreeMap::from([("data".into(), prepared.metadata().clone())]),
        BTreeMap::new(),
        &budget,
    )
    .unwrap();
    let pin = manifest.digest().unwrap();
    let root = RootName::new("chunked_image_input").unwrap();
    let admitted =
        crate::result::admit_system_result(&store, &root, &manifest, pin, &budget, &cancel)
            .unwrap();
    let component = admitted
        .output("data")
        .unwrap()
        .open(&store, &cancel)
        .unwrap();
    let tree = tree(&component, &payload);
    let image = build_initramfs(&store, &tree, &[&component], &budget, &cancel).unwrap();
    let archive_pin = image.archive().manifest_digest();
    image
        .publish_root(
            &RootName::new("chunked_component_image").unwrap(),
            &cancel,
        )
        .unwrap();
    drop(prepared);
    drop(admitted);
    drop(component);
    drop(image);
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![root],
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    let operation = store.operation().unwrap();
    for source in source_chunks.into_iter().chain([pin]) {
        assert!(operation.verify(source).unwrap().is_some());
    }
    let archive = operation
        .open_chunked(
            archive_pin,
            budget.request().output_bytes,
            &cancel,
        )
        .unwrap()
        .unwrap();
    let mut encoded = Vec::new();
    archive.copy_to(&mut encoded, &cancel).unwrap();
    assert!(encoded.starts_with(b"070701"));
    assert!(
        encoded
            .windows(payload.len())
            .any(|window| window == payload)
    );
}

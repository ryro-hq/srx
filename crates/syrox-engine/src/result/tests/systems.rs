use super::*;
use crate::{
    bundle::{export_bundle, export_system_bundle, import_bundle, import_system_bundle},
    store::{GcRequest, chunked::CHUNK_BYTES},
    system::budget::{AdmittedBudget, BuildBudget, BuilderLimits},
};
use sha2::{Digest as _, Sha256};
use std::io::{self, Read as _};

fn budget(bytes: u64, files: u64) -> AdmittedBudget {
    let request = BuildBudget {
        memory_bytes: 64 * 1024 * 1024,
        cpu_percent: 100,
        processes: 16,
        descriptors: 64,
        scratch_bytes: 1024 * 1024,
        files,
        output_bytes: bytes,
        duration_seconds: 60,
    };
    BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap()
}

fn header(path: &str, size: u64) -> Vec<u8> {
    let mut bytes = artifact::HEADER.to_vec();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(path.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes
}

fn prepare(store: &Store, size: u64, budget: &AdmittedBudget) -> PreparedSystemOutput {
    let header = header("share/payload", size);
    let mut hasher = Sha256::new();
    hasher.update(&header);
    let buffer = vec![0x5a; 64 * 1024];
    let mut remaining = size;
    while remaining != 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
        hasher.update(&buffer[..take]);
        remaining -= take as u64;
    }
    ingest_system_output(
        store,
        header
            .as_slice()
            .chain(io::repeat(0x5a).take(size)),
        ContentDigest::from_sha256_hash(hasher.finalize().into()),
        ContentDigest::sha256(b"system producer"),
        "out",
        budget,
        &Cancellation::default(),
    )
    .unwrap()
}

fn manifest(output: &PreparedSystemOutput, budget: &AdmittedBudget) -> ResultManifest {
    ResultManifest::for_system(
        BTreeMap::from([("data".into(), output.metadata().clone())]),
        BTreeMap::new(),
        budget,
    )
    .unwrap()
}

fn collect(store: &Store, remove_roots: Vec<RootName>) {
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
}

#[test]
fn system_output_larger_than_a_store_blob_is_streamed_and_retained() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::initialize(temporary.path()).unwrap();
    let size = 1024 * 1024 * 1024 + 17;
    let budget = budget(size + 1024, 10);
    let output = prepare(&store, size, &budget);
    assert!(output.artifact().manifest().size() > 1024 * 1024 * 1024);
    let manifest = manifest(&output, &budget);
    let pin = manifest.digest().unwrap();
    let root = RootName::new("large_system_result").unwrap();
    let cancel = Cancellation::default();
    let admitted = admit_system_result(&store, &root, &manifest, pin, &budget, &cancel).unwrap();
    let references = manifest.references().unwrap();
    // Identical full payload chunks are shared while order/length remain pinned.
    assert!(references.len() < 10);
    assert_eq!(
        store
            .operation()
            .unwrap()
            .build_references(&root)
            .unwrap()
            .unwrap(),
        references
    );
    drop(output);
    drop(admitted);
    collect(&store, vec![]);
    let reopened = AdmittedResult::open(&store, &root, pin, &cancel).unwrap();
    assert_eq!(reopened.manifest(), &manifest);
    drop(reopened);
    collect(&store, vec![root]);
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
fn system_bundle_and_view_round_trip_preserve_chunks_and_import_origin() {
    let first = tempfile::tempdir().unwrap();
    let source = Store::initialize(first.path()).unwrap();
    let budget = budget(16 * 1024 * 1024, 100);
    let prepared = prepare(&source, CHUNK_BYTES as u64 + 17, &budget);
    let manifest = manifest(&prepared, &budget);
    let encoded = manifest.encode().unwrap();
    assert!(encoded.starts_with(b"syrox-system-result\n"));
    assert_eq!(ResultManifest::parse(&encoded).unwrap(), manifest);
    let pin = manifest.digest().unwrap();
    let root = RootName::new("system_transport").unwrap();
    let cancel = Cancellation::default();
    let admitted = admit_system_result(&source, &root, &manifest, pin, &budget, &cancel).unwrap();
    let view = admitted
        .output("data")
        .unwrap()
        .open(&source, &cancel)
        .unwrap();
    assert_eq!(
        view.read_file("share/payload", 8 * 1024 * 1024, &cancel)
            .unwrap(),
        vec![0x5a; CHUNK_BYTES + 17]
    );
    assert!(
        matches!(view.identity().origin, OutputOrigin::Imported { manifest } if manifest == pin)
    );
    assert!(
        ResultManifest::from_views(
            BTreeMap::from([("data".into(), &view)]),
            BTreeMap::new()
        )
        .is_err()
    );
    let mut legacy = Vec::new();
    assert!(export_bundle(&source, &root, pin, &mut legacy, &cancel).is_err());
    assert!(legacy.is_empty());
    let mut bundle = Vec::new();
    export_system_bundle(&source, &root, pin, &mut bundle, &budget, &cancel).unwrap();
    assert!(bundle.starts_with(b"syrox-system-bundle\n"));
    let second = tempfile::tempdir().unwrap();
    let destination = Store::initialize(second.path()).unwrap();
    assert!(
        import_bundle(
            &destination,
            &root,
            pin,
            &mut bundle.as_slice(),
            &cancel
        )
        .is_err()
    );
    let imported = import_system_bundle(
        &destination,
        &root,
        pin,
        &mut bundle.as_slice(),
        &budget,
        &cancel,
    )
    .unwrap();
    assert_eq!(imported.manifest(), &manifest);
    let retained = imported.output("data").unwrap();
    drop(imported);
    collect(&destination, vec![]);
    let imported_view = retained.open(&destination, &cancel).unwrap();
    assert_eq!(imported_view.identity(), view.identity());
    assert_eq!(
        imported_view
            .read_file("share/payload", 8 * 1024 * 1024, &cancel)
            .unwrap(),
        vec![0x5a; CHUNK_BYTES + 17]
    );
}

#[test]
fn result_versions_and_budgets_cannot_be_confused() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::initialize(temporary.path()).unwrap();
    let admitted_budget = budget(1024, 10);
    let prepared = prepare(&store, 100, &admitted_budget);
    let manifest = manifest(&prepared, &admitted_budget);
    let root = RootName::new("system_rejected").unwrap();
    let cancel = Cancellation::default();
    assert!(
        admit_result(
            &store,
            &root,
            &manifest,
            manifest.digest().unwrap(),
            &cancel
        )
        .is_err()
    );
    for smaller in [budget(1023, 10), budget(1024, 9)] {
        assert!(
            admit_system_result(
                &store,
                &root,
                &manifest,
                manifest.digest().unwrap(),
                &smaller,
                &cancel
            )
            .is_err()
        );
    }
    assert!(matches!(
        admit_system_result(
            &store,
            &root,
            &manifest,
            ContentDigest::sha256(b"wrong"),
            &admitted_budget,
            &cancel
        ),
        Err(ResultError::PinMismatch)
    ));
    let wrong_version = String::from_utf8(manifest.encode().unwrap())
        .unwrap()
        .replace("syrox-system-result", "syrox-package-result");
    assert!(ResultManifest::parse(wrong_version.as_bytes()).is_err());
    let mut wrong_files = manifest.clone();
    wrong_files.outputs.get_mut("data").unwrap().files = 2;
    assert!(
        admit_system_result(
            &store,
            &root,
            &wrong_files,
            wrong_files.digest().unwrap(),
            &admitted_budget,
            &cancel
        )
        .is_err()
    );
    assert!(
        store
            .operation()
            .unwrap()
            .build_references(&root)
            .unwrap()
            .is_none()
    );
}

#[test]
fn malformed_or_cancelled_producer_never_publishes_a_chunk_manifest() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::initialize(temporary.path()).unwrap();
    let budget = budget(16 * 1024 * 1024, 10);
    let mut bytes = header("payload", CHUNK_BYTES as u64 + 1);
    bytes.extend(std::iter::repeat_n(0x5a, CHUNK_BYTES + 1));
    let pin = ContentDigest::sha256(&bytes);
    let action = ContentDigest::sha256(b"failed system producer");
    let cancel = Cancellation::default();
    let mut malformed = bytes.clone();
    malformed.push(0);
    assert!(
        ingest_system_output(
            &store,
            malformed.as_slice(),
            ContentDigest::sha256(&malformed),
            action,
            "out",
            &budget,
            &cancel
        )
        .is_err()
    );
    assert!(
        ingest_system_output(
            &store,
            bytes.as_slice(),
            ContentDigest::sha256(b"wrong"),
            action,
            "out",
            &budget,
            &cancel
        )
        .is_err()
    );
    cancel.cancel();
    assert!(matches!(
        ingest_system_output(
            &store,
            bytes.as_slice(),
            pin,
            action,
            "out",
            &budget,
            &cancel
        ),
        Err(ResultError::Cancelled)
    ));
    collect(&store, vec![]);
    // Failed streams created no roots, and every completed chunk is collectible.
    assert!(
        store
            .operation()
            .unwrap()
            .verify(ContentDigest::sha256(&vec![0x5a; CHUNK_BYTES]))
            .unwrap()
            .is_none()
    );
}

#[test]
fn system_bundle_rejects_missing_extra_changed_and_unauthorized_objects_without_root() {
    let source_dir = tempfile::tempdir().unwrap();
    let source = Store::initialize(source_dir.path()).unwrap();
    let budget = budget(1024 * 1024, 100);
    let prepared = prepare(&source, 100, &budget);
    let manifest = manifest(&prepared, &budget);
    let pin = manifest.digest().unwrap();
    let root = RootName::new("bundle_negative").unwrap();
    let cancel = Cancellation::default();
    admit_system_result(&source, &root, &manifest, pin, &budget, &cancel).unwrap();
    let mut bundle = Vec::new();
    export_system_bundle(&source, &root, pin, &mut bundle, &budget, &cancel).unwrap();
    let mut trailing = bundle.clone();
    trailing.push(0);
    let mut corrupt = bundle.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut wrong_count = bundle.clone();
    let offset = b"syrox-system-bundle\n".len() + 4 + manifest.encode().unwrap().len();
    wrong_count[offset] ^= 1;
    for changed in [
        &bundle[..bundle.len() - 1],
        &trailing,
        &corrupt,
        &wrong_count,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::initialize(directory.path()).unwrap();
        assert!(
            import_system_bundle(
                &store,
                &root,
                pin,
                &mut &changed[..],
                &budget,
                &cancel
            )
            .is_err()
        );
        assert!(
            store
                .operation()
                .unwrap()
                .build_references(&root)
                .unwrap()
                .is_none()
        );
        collect(&store, vec![]);
    }
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    assert!(
        import_system_bundle(
            &store,
            &root,
            ContentDigest::sha256(b"different authorization"),
            &mut bundle.as_slice(),
            &budget,
            &cancel
        )
        .is_err()
    );
    assert!(
        import_system_bundle(
            &store,
            &root,
            pin,
            &mut bundle.as_slice(),
            &self::budget(1024, 10),
            &cancel
        )
        .is_err()
    );
}

#[test]
fn system_result_and_bundle_have_fixed_wire_identities() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let budget = budget(1024, 10);
    let prepared = prepare(&store, 3, &budget);
    let manifest = manifest(&prepared, &budget);
    let pin = manifest.digest().unwrap();
    assert_eq!(
        pin.to_string(),
        "65c0ee1281a8098983fde876042d526edbaa28c12e1db1c80d9ed418ac464a76"
    );
    let root = RootName::new("system_wire_identity").unwrap();
    let cancellation = Cancellation::default();
    admit_system_result(
        &store,
        &root,
        &manifest,
        pin,
        &budget,
        &cancellation,
    )
    .unwrap();
    let mut bundle = Vec::new();
    export_system_bundle(
        &store,
        &root,
        pin,
        &mut bundle,
        &budget,
        &cancellation,
    )
    .unwrap();
    assert_eq!(
        ContentDigest::sha256(&bundle).to_string(),
        "85de19e785eabd8e6c63d447f3969c3a40c88c1e3bab5d18ebbed84d1f3110b2"
    );
}

#[test]
fn expanded_alias_bytes_and_implicit_directories_obey_system_budgets() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let cancellation = Cancellation::default();
    let action = ContentDigest::sha256(b"bounded aliases");
    let mut bytes = artifact::HEADER.to_vec();
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    for (path, kind, data) in [
        ("a", 0, vec![1; 100]),
        ("b", 2, b"a".to_vec()),
        ("c", 2, b"a".to_vec()),
    ] {
        bytes.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(kind);
        bytes.extend_from_slice(&(data.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&data);
    }
    assert!(bytes.len() < 200);
    assert!(
        ingest_system_output(
            &store,
            bytes.as_slice(),
            ContentDigest::sha256(&bytes),
            action,
            "out",
            &budget(200, 10),
            &cancellation
        )
        .is_err()
    );
    let directories = header("one/two/three", 0);
    assert!(
        ingest_system_output(
            &store,
            directories.as_slice(),
            ContentDigest::sha256(&directories),
            action,
            "out",
            &budget(1024, 2),
            &cancellation
        )
        .is_err()
    );
    assert!(
        ingest_system_output(
            &store,
            directories.as_slice(),
            ContentDigest::sha256(&directories),
            action,
            "out",
            &budget(1024, 3),
            &cancellation
        )
        .is_ok()
    );
}

#[test]
fn aggregate_system_budget_counts_unique_complete_views() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let budget = budget(1024, 100);
    let first = prepare(&store, 500, &budget);
    let second = prepare(&store, 501, &budget);
    let root = RootName::new("aggregate_system").unwrap();
    let cancellation = Cancellation::default();
    let too_large = ResultManifest::for_system(
        BTreeMap::from([
            ("first".into(), first.metadata().clone()),
            (
                "second".into(),
                ResultOutput {
                    action: ContentDigest::sha256(b"second action"),
                    ..second.metadata().clone()
                },
            ),
        ]),
        BTreeMap::new(),
        &budget,
    );
    assert!(too_large.is_err());
    assert!(
        store
            .operation()
            .unwrap()
            .build_references(&root)
            .unwrap()
            .is_none()
    );
    let shared = ResultManifest::for_system(
        BTreeMap::from([
            ("first".into(), first.metadata().clone()),
            ("alias".into(), first.metadata().clone()),
        ]),
        BTreeMap::new(),
        &budget,
    )
    .unwrap();
    admit_system_result(
        &store,
        &root,
        &shared,
        shared.digest().unwrap(),
        &budget,
        &cancellation,
    )
    .unwrap();
}

#[test]
fn chunked_command_admission_inspects_elf_and_rejects_nonexecutable_content() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    let budget = budget(16 * 1024 * 1024, 100);
    let cancellation = Cancellation::default();
    let mut payload = crate::runtime::tests::elf(2, None, &[], None, None);
    payload.resize(CHUNK_BYTES + 128, 0);
    let mut bytes = header("bin/app", payload.len() as u64);
    let kind_offset = bytes.len() - 9;
    bytes[kind_offset] = 1;
    bytes.extend_from_slice(&payload);
    for executable in [true, false] {
        bytes[kind_offset] = u8::from(executable);
        let prepared = ingest_system_output(
            &store,
            bytes.as_slice(),
            ContentDigest::sha256(&bytes),
            ContentDigest::sha256(b"command fixture"),
            "out",
            &budget,
            &cancellation,
        )
        .unwrap();
        let manifest = ResultManifest::for_system(
            BTreeMap::from([("app".into(), prepared.metadata().clone())]),
            BTreeMap::from([(
                "app".into(),
                ResultCommand {
                    application: "app".into(),
                    application_path: "bin/app".into(),
                    loader: None,
                    loader_path: None,
                    libraries: vec![],
                },
            )]),
            &budget,
        )
        .unwrap();
        let root = RootName::new(if executable {
            "executable_system"
        } else {
            "nonexecutable_system"
        })
        .unwrap();
        let result = admit_system_result(
            &store,
            &root,
            &manifest,
            manifest.digest().unwrap(),
            &budget,
            &cancellation,
        );
        if executable {
            let admitted = result.unwrap();
            assert!(admitted.command("app").is_some());
            let view = admitted
                .output("app")
                .unwrap()
                .open(&store, &cancellation)
                .unwrap();
            view.verify_view(&cancellation).unwrap();
        } else {
            assert!(result.is_err());
            assert!(
                store
                    .operation()
                    .unwrap()
                    .build_references(&root)
                    .unwrap()
                    .is_none()
            );
        }
    }
}

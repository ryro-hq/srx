use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;

fn fixture(store: &Store) -> ResultManifest {
    let path = b"share/message";
    let content = b"offline data";
    let mut bytes = artifact::HEADER.to_vec();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(path);
    bytes.push(0);
    bytes.extend_from_slice(&(content.len() as u64).to_le_bytes());
    bytes.extend_from_slice(content);
    let digest = ContentDigest::sha256(&bytes);
    store
        .operation()
        .unwrap()
        .ingest(bytes.as_slice(), digest, bytes.len() as u64)
        .unwrap();
    ResultManifest {
        outputs: BTreeMap::from([(
            "data".into(),
            ResultOutput {
                action: ContentDigest::sha256(b"logical build identity only"),
                output: "data".into(),
                artifact: digest,
                files: 1,
            },
        )]),
        commands: BTreeMap::new(),
    }
}

#[test]
fn pinned_data_import_reopens_after_all_handles_and_without_build_records() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::initialize(temp.path()).unwrap();
    let manifest = fixture(&store);
    let root = RootName::new("import_data").unwrap();
    let cancellation = Cancellation::default();
    let admitted = admit_result(
        &store,
        &root,
        &manifest,
        manifest.digest().unwrap(),
        &cancellation,
    )
    .unwrap();
    let retained = admitted.output("data").unwrap();
    assert_eq!(manifest.references().unwrap().len(), 2);
    assert!(
        store
            .operation()
            .unwrap()
            .verify(retained.identity.action)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        retained.identity.origin,
        OutputOrigin::Imported { .. }
    ));
    drop(admitted);
    drop(store);
    let store = Store::open(temp.path()).unwrap();
    let view = retained.open(&store, &cancellation).unwrap();
    assert_eq!(
        view.read_file("share/message", 12, &cancellation)
            .unwrap(),
        b"offline data"
    );
    assert_eq!(
        view.logical_prefix(),
        format!("/syrox/store/{}/data", retained.identity.action)
    );
    let next = view
        .retain(
            &RootName::new("generation_data").unwrap(),
            &cancellation,
        )
        .unwrap();
    drop(view);
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            remove_roots: vec![root],
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert_eq!(
        next.open(&store, &cancellation).unwrap().files(),
        1
    );
}

#[test]
fn pin_corrupt_artifact_and_bad_metadata_never_publish_a_root() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::initialize(temp.path()).unwrap();
    let manifest = fixture(&store);
    let root = RootName::new("rejected").unwrap();
    let cancellation = Cancellation::default();
    assert!(matches!(
        admit_result(
            &store,
            &root,
            &manifest,
            ContentDigest::sha256(b"different pin"),
            &cancellation
        ),
        Err(ResultError::PinMismatch)
    ));
    let mut wrong_count = manifest.clone();
    wrong_count.outputs.get_mut("data").unwrap().files = 2;
    assert!(
        admit_result(
            &store,
            &root,
            &wrong_count,
            wrong_count.digest().unwrap(),
            &cancellation
        )
        .is_err()
    );
    let digest = manifest.outputs["data"].artifact.to_string();
    let object = temp.path().join(format!(
        "objects/sha256/{}/{digest}",
        &digest[..2]
    ));
    fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(object, b"tampered").unwrap();
    assert!(
        admit_result(
            &store,
            &root,
            &manifest,
            manifest.digest().unwrap(),
            &cancellation
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
fn canonical_manifest_rejects_unknown_versions_fields_duplicates_and_bounds() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::initialize(temp.path()).unwrap();
    let mut manifest = fixture(&store);
    let bytes = manifest.encode().unwrap();
    assert_eq!(ResultManifest::parse(&bytes).unwrap(), manifest);
    let changed = String::from_utf8(bytes.clone())
        .unwrap()
        .replace("syrox-result-v2", "syrox-result-v1");
    assert!(ResultManifest::parse(changed.as_bytes()).is_err());
    let changed = String::from_utf8(bytes.clone())
        .unwrap()
        .replace("\"commands\":{}", "\"commands\":{},\"unknown\":0");
    assert!(ResultManifest::parse(changed.as_bytes()).is_err());
    let changed = String::from_utf8(bytes.clone()).unwrap().replace(
        "\"commands\":{}",
        "\"commands\":{},\"commands\":{}",
    );
    assert!(ResultManifest::parse(changed.as_bytes()).is_err());
    let mut whitespace = bytes;
    whitespace.push(b' ');
    assert!(ResultManifest::parse(&whitespace).is_err());
    assert!(
        ResultManifest::parse(&vec![
            b' ';
            usize::try_from(MAX_RESULT_MANIFEST_BYTES)
                .unwrap()
                + 1
        ])
        .is_err()
    );
    let output = manifest.outputs["data"].clone();
    for number in 0..MAX_RESULT_OUTPUTS {
        manifest
            .outputs
            .insert(format!("alias{number}"), output.clone());
    }
    assert!(manifest.encode().is_err());
}

#[test]
fn missing_command_output_and_conflicting_logical_identity_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::initialize(temp.path()).unwrap();
    let mut manifest = fixture(&store);
    manifest.commands.insert(
        "run".into(),
        ResultCommand {
            application: "missing".into(),
            application_path: "bin/missing".into(),
            loader: None,
            loader_path: None,
            libraries: Vec::new(),
        },
    );
    assert!(manifest.encode().is_err());
    manifest.commands.clear();
    let mut other = manifest.outputs["data"].clone();
    other.artifact = ContentDigest::sha256(b"conflict");
    manifest.outputs.insert("other".into(), other);
    assert!(manifest.encode().is_err());
}

#[test]
fn cancellation_before_admission_leaves_no_root() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::initialize(temp.path()).unwrap();
    let manifest = fixture(&store);
    let root = RootName::new("cancelled").unwrap();
    let cancellation = Cancellation::default();
    cancellation.cancel();
    assert!(matches!(
        admit_result(
            &store,
            &root,
            &manifest,
            manifest.digest().unwrap(),
            &cancellation
        ),
        Err(ResultError::Cancelled)
    ));
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
fn reopening_one_output_rejects_corruption_in_an_unselected_sibling() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::initialize(temp.path()).unwrap();
    let mut manifest = fixture(&store);
    let mut sibling = manifest.outputs["data"].clone();
    let lease = store.operation().unwrap();
    let source = lease
        .read_verified(sibling.artifact, 1024)
        .unwrap()
        .unwrap();
    let mut bytes = source.as_bytes().to_vec();
    *bytes.last_mut().unwrap() = b'!';
    sibling.artifact = ContentDigest::sha256(&bytes);
    sibling.output = "extra".into();
    lease
        .ingest(bytes.as_slice(), sibling.artifact, 1024)
        .unwrap();
    manifest
        .outputs
        .insert("extra".into(), sibling.clone());
    drop(lease);
    let root = RootName::new("siblings").unwrap();
    let cancellation = Cancellation::default();
    let admitted = admit_result(
        &store,
        &root,
        &manifest,
        manifest.digest().unwrap(),
        &cancellation,
    )
    .unwrap();
    let retained = admitted.output("data").unwrap();
    assert!(retained.open(&store, &cancellation).is_ok());
    drop(admitted);
    let digest = sibling.artifact.to_string();
    let object = temp.path().join(format!(
        "objects/sha256/{}/{digest}",
        &digest[..2]
    ));
    fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(object, b"corrupt sibling").unwrap();
    assert!(retained.open(&store, &cancellation).is_err());
}

#[test]
fn artifact_budget_charges_unique_objects_at_the_exact_aggregate_boundary() {
    let mut budget = ArtifactBudget::default();
    for number in 0_u8..4 {
        let digest = ContentDigest::sha256(&[number]);
        budget
            .charge(digest, artifact::MAX_OUTPUT_BYTES)
            .unwrap();
        budget
            .charge(digest, artifact::MAX_OUTPUT_BYTES)
            .unwrap();
    }
    assert_eq!(budget.bytes, MAX_RESULT_ARTIFACT_BYTES);
    assert!(
        budget
            .charge(ContentDigest::sha256(b"overflow"), 1)
            .is_err()
    );
    assert!(
        budget
            .charge(
                ContentDigest::sha256(b"arithmetic overflow"),
                u64::MAX
            )
            .is_err()
    );
    assert_eq!(budget.seen.len(), 4);
}

#[test]
fn commands_select_distinct_paths_in_one_output_and_reject_invalid_entries() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::initialize(temp.path()).unwrap();
    let content = crate::runtime::tests::elf(2, None, &[], None, None);
    let mut bytes = artifact::HEADER.to_vec();
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    for name in ["data", "first", "second"] {
        let path = format!("bin/{name}");
        bytes.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(u8::from(name != "data"));
        bytes.extend_from_slice(&(content.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&content);
    }
    let digest = ContentDigest::sha256(&bytes);
    store
        .operation()
        .unwrap()
        .ingest(bytes.as_slice(), digest, bytes.len() as u64)
        .unwrap();
    let mut manifest = ResultManifest {
        outputs: BTreeMap::from([(
            "programs".into(),
            ResultOutput {
                action: ContentDigest::sha256(b"multi-command-output"),
                output: "out".into(),
                artifact: digest,
                files: 3,
            },
        )]),
        commands: ["first", "second"]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    ResultCommand {
                        application: "programs".into(),
                        application_path: format!("bin/{name}"),
                        loader: None,
                        loader_path: None,
                        libraries: vec![],
                    },
                )
            })
            .collect(),
    };
    let cancel = Cancellation::default();
    let admitted = admit_result(
        &store,
        &RootName::new("commands").unwrap(),
        &manifest,
        manifest.digest().unwrap(),
        &cancel,
    )
    .unwrap();
    let first = admitted.command("first").unwrap();
    let second = admitted.command("second").unwrap();
    assert_eq!(
        first.application.output.identity,
        second.application.output.identity
    );
    assert!(
        first
            .open(&store, &cancel)
            .unwrap()
            .entry()
            .ends_with("/bin/first")
    );
    assert!(
        second
            .open(&store, &cancel)
            .unwrap()
            .entry()
            .ends_with("/bin/second")
    );
    for (index, path) in ["bin/missing", "bin/data", "../escape"]
        .into_iter()
        .enumerate()
    {
        manifest
            .commands
            .get_mut("first")
            .unwrap()
            .application_path = path.into();
        let root = RootName::new(format!("invalid_{index}")).unwrap();
        if let Ok(pin) = manifest.digest() {
            assert!(admit_result(&store, &root, &manifest, pin, &cancel).is_err());
        }
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

#[test]
fn manifest_uses_the_same_library_limit_as_recipe_and_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::initialize(temp.path()).unwrap();
    let mut manifest = fixture(&store);
    manifest.commands.insert(
        "main".into(),
        ResultCommand {
            application: "data".into(),
            application_path: "bin/main".into(),
            loader: None,
            loader_path: None,
            libraries: vec!["data".into(); crate::runtime::MAX_RUNTIME_LIBRARIES],
        },
    );
    let bytes = manifest.encode().unwrap();
    assert_eq!(ResultManifest::parse(&bytes).unwrap(), manifest);
    manifest
        .commands
        .get_mut("main")
        .unwrap()
        .libraries
        .push("data".into());
    assert!(manifest.encode().is_err());
}

#[test]
fn admitted_result_allows_gc_and_retains_bytes_through_materialization_after_root_removal() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::initialize(temporary.path()).unwrap();
    let manifest = fixture(&store);
    let pin = manifest.digest().unwrap();
    let root = RootName::new("live_import").unwrap();
    let cancel = Cancellation::default();
    let admitted = admit_result(&store, &root, &manifest, pin, &cancel).unwrap();
    let reopened = AdmittedResult::open(&store, &root, pin, &cancel).unwrap();
    let selected = reopened.output("data").unwrap();
    drop(admitted);
    let garbage = ContentDigest::sha256(b"unrelated object");
    store
        .operation()
        .unwrap()
        .ingest(&b"unrelated object"[..], garbage, 16)
        .unwrap();
    let collected = store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            remove_roots: vec![root],
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert!(collected.removed_objects.contains(&garbage));
    assert!(
        manifest
            .references()
            .unwrap()
            .iter()
            .all(|pin| !collected.removed_objects.contains(pin))
    );
    let view = reopened
        .materialize_output(&selected.identity, &cancel)
        .unwrap();
    drop(reopened);
    let collected = store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert!(!collected.removed_objects.contains(&pin));
    assert_eq!(
        view.read_file("share/message", 12, &cancel)
            .unwrap(),
        b"offline data"
    );
    drop(view);
    let collected = store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert!(
        manifest
            .references()
            .unwrap()
            .iter()
            .all(|pin| collected.removed_objects.contains(pin))
    );
}

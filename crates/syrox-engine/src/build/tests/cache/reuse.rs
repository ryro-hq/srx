use super::*;

fn object_path(root: &Path, digest: ContentDigest) -> PathBuf {
    let digest = digest.to_string();
    root.join("objects/sha256")
        .join(&digest[..2])
        .join(digest)
}

#[test]
fn retained_provider_can_be_verified_without_views_and_rejects_missing_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"executable");
    let (found, receipt) = retained_result(
        &lease,
        &result.root,
        result.receipt,
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(found, action);
    assert_eq!(receipt.digest(), result.receipt);
    assert!(
        !directory
            .path()
            .join(".syrox-store/views")
            .exists()
    );
    let digest = ContentDigest::sha256(SOURCE).to_string();
    fs::remove_file(
        directory
            .path()
            .join("objects/sha256")
            .join(&digest[..2])
            .join(digest),
    )
    .unwrap();
    assert!(
        retained_result(
            &lease,
            &result.root,
            result.receipt,
            &Cancellation::default()
        )
        .is_err()
    );
}

#[test]
fn complete_results_reuse_with_explicit_retention_and_input_changes_miss() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let cancellation = Cancellation::default();
    let result = retained(&lease, &action, b"executable");
    // A visible root without a committed index does not turn into an implicit hit.
    assert!(
        lookup(&lease, &action, None, &cancellation)
            .unwrap()
            .is_none()
    );
    record(&lease, &action, &result).unwrap();
    let caller_root = RootName::new("caller_retention").unwrap();
    let hit = lookup(&lease, &action, Some(&caller_root), &cancellation)
        .unwrap()
        .unwrap();
    assert!(matches!(hit.execution, BuildExecution::Cached));
    assert_eq!(
        (hit.action, hit.artifact, hit.receipt, hit.root),
        (
            result.action,
            result.artifact,
            result.receipt,
            caller_root.clone()
        )
    );
    assert_eq!(
        lease.build_references(&caller_root).unwrap(),
        lease.build_references(&result.root).unwrap()
    );
    assert!(
        !directory
            .path()
            .join(".syrox-store/builds")
            .exists()
    );
    for field in [
        "source",
        "worker",
        "toolchain",
        "directory",
        "resources",
    ] {
        let mut other = action.clone();
        match field {
            "source" => other.source = ContentDigest::sha256(b"another source"),
            "worker" => other.worker = ContentDigest::sha256(b"another worker"),
            "toolchain" => other.toolchain = Some(ContentDigest::sha256(b"another toolchain")),
            "directory" => other.directory = "other".into(),
            _ => other.program.resources = super::super::super::BuildResources::Large,
        }
        assert!(
            lookup(&lease, &other, None, &cancellation)
                .unwrap()
                .is_none(),
            "{field}"
        );
    }
    cancellation.cancel();
    assert!(matches!(
        lookup(&lease, &action, None, &cancellation),
        Err(BuildError::Cancelled)
    ));
}

#[test]
fn incomplete_provider_closure_is_not_authorized() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let provider = retained(&lease, &action(), b"provider");
    let mut consumer_action = action();
    consumer_action.directory = "consumer".into();
    consumer_action.inputs = vec![
        super::super::super::records::InputIdentity {
            origin: crate::result::OutputOrigin::Built {
                receipt: provider.receipt,
            },
            action: provider.action,
            artifact: provider.artifact,
            output: "out".into(),
        },
    ];
    assert!(
        Receipt::new(&consumer_action, provider.artifact, 1)
            .with_inputs(&consumer_action, vec![provider.receipt])
            .is_err()
    );
    let mut incomplete = vec![
        provider.receipt,
        provider.action,
        provider.artifact,
    ];
    incomplete.sort_unstable();
    let receipt = Receipt::new(&consumer_action, provider.artifact, 1)
        .with_inputs(&consumer_action, incomplete)
        .unwrap();
    assert!(
        receipt
            .verify_inputs(&lease, &consumer_action, &Cancellation::default())
            .is_err()
    );
}

#[test]
fn orphaned_autotools_provider_reuses_only_without_a_divergence_marker() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let mut provider_action = action();
    provider_action.directory = "provider".into();
    let inventory = b"syrox-host-toolchain\nindependent cache provider";
    let producer_inventory = ContentDigest::sha256(inventory);
    lease
        .ingest(
            &inventory[..],
            producer_inventory,
            inventory.len() as u64,
        )
        .unwrap();
    provider_action.worker = ContentDigest::sha256(b"independent cache provider worker");
    provider_action.toolchain = Some(producer_inventory);

    let provider = retained(&lease, &provider_action, b"provider");
    let provider_references = lease
        .build_references(&provider.root)
        .unwrap()
        .unwrap();
    let mut consumer = action();
    assert_ne!(provider_action.worker, consumer.worker);
    assert_ne!(provider_action.toolchain, consumer.toolchain);
    // The independent provider and application must share the same index
    // shard without trying to acquire its flock twice through separate fds.
    let prefix = &provider_action.digest().to_string()[..2];
    consumer.directory = (0..4096)
        .map(|index| format!("consumer-{index}"))
        .find(|package| {
            consumer.directory = package.clone();
            consumer.inputs = vec![
                super::super::super::records::InputIdentity {
                    origin: crate::result::OutputOrigin::Built {
                        receipt: provider.receipt,
                    },
                    action: provider.action,
                    artifact: provider.artifact,
                    output: "out".into(),
                },
            ];
            consumer.digest().to_string().starts_with(prefix)
        })
        .expect("one-byte shard collision");
    consumer.inputs = vec![
        super::super::super::records::InputIdentity {
            origin: crate::result::OutputOrigin::Built {
                receipt: provider.receipt,
            },
            action: provider.action,
            artifact: provider.artifact,
            output: "out".into(),
        },
    ];
    assert_eq!(&consumer.digest().to_string()[..2], prefix);
    let publish = |lease: &OperationLease, content: &[u8]| {
        let tree = tempfile::tempdir().unwrap();
        let path = tree.path().join("bin/hello");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let mut artifact = Vec::new();
        artifact::pack(tree.path(), &mut artifact).unwrap();
        let receipt = Receipt::new(&consumer, ContentDigest::sha256(&artifact), 1)
            .with_inputs(&consumer, provider_references.clone())
            .unwrap();
        for bytes in [
            &consumer.encode()[..],
            &artifact,
            &receipt.encode(),
        ] {
            lease
                .ingest(
                    bytes,
                    ContentDigest::sha256(bytes),
                    bytes.len() as u64,
                )
                .unwrap();
        }
        lease
            .publish_root(&receipt.root(), &receipt.references())
            .unwrap();
        BuildResult {
            retention: lease
                .retain_objects(&receipt.references(), &[])
                .unwrap(),
            execution: BuildExecution::Cached,
            action: consumer.digest(),
            artifact: receipt.output("out").unwrap().artifact,
            receipt: receipt.digest(),
            toolchain: consumer.toolchain,
            files: 1,
            root: receipt.root(),
        }
    };
    let first = publish(&lease, b"first");
    record(&lease, &consumer, &first).unwrap();
    drop(lease);
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![provider.root.clone()],
            ..GcRequest::default()
        })
        .unwrap();
    let lease = store.operation().unwrap();
    let query = RetainedQuery {
        application: description(&consumer),
        provider: description(&provider_action),
        worker: consumer.worker,
        toolchain: consumer.toolchain,
        input_outputs: vec!["out"],
    };
    // The fast path cannot accept an independent provider root before its own
    // index has been published, even when the consumer is already indexed.
    lease
        .publish_root(&provider.root, &provider_references)
        .unwrap();
    assert!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    record(&lease, &provider_action, &provider).unwrap();
    assert_eq!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default())
            .unwrap()
            .unwrap()
            .0
            .receipt,
        first.receipt
    );
    drop(lease);
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![provider.root],
            ..GcRequest::default()
        })
        .unwrap();
    let lease = store.operation().unwrap();
    // A visible retained result without a successfully published index must
    // not become a cache hit merely because its provider root was collected.
    fs::remove_file(index_path(directory.path(), &consumer)).unwrap();
    assert!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    record(&lease, &consumer, &first).unwrap();
    assert_eq!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default())
            .unwrap()
            .unwrap()
            .0
            .receipt,
        first.receipt
    );
    let inventory_path = object_path(directory.path(), producer_inventory);
    fs::write(&inventory_path, b"corrupt independent inventory").unwrap();
    assert!(retained_build_with_inputs(&lease, &query, &Cancellation::default()).is_err());
    fs::write(&inventory_path, inventory).unwrap();
    let second = publish(&lease, b"divergent");
    assert!(matches!(
        record(&lease, &consumer, &second),
        Err(BuildError::DivergentResults { .. })
    ));
    assert!(matches!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default()),
        Err(BuildError::DivergentResults { .. })
    ));
    drop(lease);
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![second.root],
            ..GcRequest::default()
        })
        .unwrap();
    let lease = store.operation().unwrap();
    assert!(matches!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default()),
        Err(BuildError::DivergentResults { .. })
    ));
}

#[test]
fn current_result_index_ignores_prelaunch_receipt_in_the_same_store() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"current executable");
    let current = lease
        .read_verified(result.receipt, MAX_RECORD_BYTES)
        .unwrap()
        .unwrap();
    let old = String::from_utf8(current.into_bytes())
        .unwrap()
        .replacen(
            "syrox-build-result\n",
            "syrox-build-result-v3\n",
            1,
        )
        .replacen("inputs 0\n", "", 1);
    let digest = ContentDigest::sha256(old.as_bytes());
    lease
        .ingest(old.as_bytes(), digest, old.len() as u64)
        .unwrap();
    let root = RootName::new(format!("build_{digest}")).unwrap();
    lease.publish_root(&root, &[digest]).unwrap();
    record(&lease, &action, &result).unwrap();
    assert_eq!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .unwrap()
            .receipt,
        result.receipt
    );
}

#[test]
fn every_retained_object_and_root_relationship_is_verified_before_a_hit() {
    for corrupt in [
        "source",
        "toolchain",
        "action",
        "artifact",
        "receipt",
        "root",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let lease = store.operation().unwrap();
        let action = action();
        let result = retained(&lease, &action, b"executable");
        record(&lease, &action, &result).unwrap();
        let digest = match corrupt {
            "source" => action.source,
            "toolchain" => action.toolchain.unwrap(),
            "action" => result.action,
            "artifact" => result.artifact,
            _ => result.receipt,
        };
        if corrupt == "root" {
            let path = directory
                .path()
                .join("roots/retained")
                .join(result.root.as_str());
            let text = fs::read_to_string(&path).unwrap();
            fs::write(
                path,
                text.replace(&format!("{}\n", result.artifact), ""),
            )
            .unwrap();
        } else {
            fs::write(object_path(directory.path(), digest), b"corrupt").unwrap();
        }
        assert!(
            lookup(&lease, &action, None, &Cancellation::default()).is_err(),
            "{corrupt}"
        );
    }
}

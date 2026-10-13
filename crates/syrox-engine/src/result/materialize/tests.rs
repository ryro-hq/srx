use super::*;

#[test]
fn cancellation_during_view_copy_stops_before_another_write() {
    struct CancelAfterFirstRead<'a>(&'a Cancellation);
    impl std::io::Read for CancelAfterFirstRead<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            buffer[0] = b'x';
            self.0.cancel();
            Ok(1)
        }
    }
    let cancellation = Cancellation::default();
    let mut output = Vec::new();
    assert!(matches!(
        copy_with_cancellation(
            CancelAfterFirstRead(&cancellation),
            &mut output,
            &cancellation
        ),
        Err(MaterializationError::Cancelled)
    ));
    assert!(output.is_empty());
}

#[test]
fn named_receipt_retains_and_materializes_independent_outputs() {
    use crate::build::records::NamedOutput;
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let mut action = crate::build::cache::tests::action();
    action.program.outputs = vec!["dev".into(), "out".into()];
    let make_artifact = |path: &str, content: &[u8]| {
        let tree = tempfile::tempdir().unwrap();
        let destination = tree.path().join(path);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&destination, content).unwrap();
        fs::set_permissions(
            destination,
            fs::Permissions::from_mode(if path == "bin/hello" {
                0o755
            } else {
                0o644
            }),
        )
        .unwrap();
        let mut bytes = Vec::new();
        artifact::pack(tree.path(), &mut bytes).unwrap();
        bytes
    };
    let primary = make_artifact("bin/hello", b"runtime");
    let development = make_artifact("usr/include/stdio.h", b"headers");
    let named = NamedOutput {
        artifact: ContentDigest::sha256(&development),
        files: 1,
    };
    let receipt = Receipt::new(&action, ContentDigest::sha256(&primary), 1)
        .with_outputs(&action, BTreeMap::from([("dev".into(), named)]))
        .unwrap();
    let encoded = receipt.encode();
    assert!(encoded.starts_with(b"syrox-build-result-v4\n"));
    assert_eq!(Receipt::parse(&encoded).unwrap(), receipt);
    assert_eq!(receipt.references().len(), 6);
    let lease = store.operation().unwrap();
    let action_bytes = action.encode();
    for bytes in [
        &b"fixture source"[..],
        &b"syrox-host-toolchain\nfixture toolchain"[..],
        &action_bytes,
        &primary,
        &development,
        &encoded,
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
    let result = crate::build::BuildResult {
        retention: lease
            .retain_objects(&receipt.references(), &[])
            .unwrap(),
        execution: crate::build::BuildExecution::Cached,
        action: action.digest(),
        artifact: receipt.output("out").unwrap().artifact,
        receipt: receipt.digest(),
        toolchain: action.toolchain,
        files: receipt.output("out").unwrap().files,
        root: receipt.root(),
    };
    crate::build::cache::record(&lease, &action, &result).unwrap();
    assert!(
        crate::build::cache::lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_some()
    );
    drop(lease);
    let out = materialize_artifact(&store, &receipt.root(), receipt.digest()).unwrap();
    let dev = materialize_named_artifact(&store, &receipt.root(), receipt.digest(), "dev").unwrap();
    assert_eq!(
        fs::read(out.directory().unwrap().join("bin/hello")).unwrap(),
        b"runtime"
    );
    assert_eq!(
        fs::read(
            dev.directory()
                .unwrap()
                .join("usr/include/stdio.h")
        )
        .unwrap(),
        b"headers"
    );
    assert_eq!(
        dev.logical_prefix(),
        format!("/syrox/store/{}/dev", action.digest())
    );
    let cancellation = Cancellation::default();
    let retained = dev
        .retain(
            &RootName::new("generation_dev").unwrap(),
            &cancellation,
        )
        .unwrap();
    assert_eq!(retained.identity.output, "dev");
    assert_eq!(
        retained.identity.origin,
        OutputOrigin::Built {
            receipt: receipt.digest()
        }
    );
    assert_ne!(retained.identity.artifact, out.artifact());
    assert_eq!(
        retained
            .open(&store, &cancellation)
            .unwrap()
            .read_file("usr/include/stdio.h", 7, &cancellation)
            .unwrap(),
        b"headers"
    );
    assert!(
        materialize_named_artifact(
            &store,
            &receipt.root(),
            receipt.digest(),
            "missing"
        )
        .is_err()
    );
    fs::set_permissions(
        dev.directory()
            .unwrap()
            .join("usr/include/stdio.h"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::write(
        dev.directory()
            .unwrap()
            .join("usr/include/stdio.h"),
        b"changed",
    )
    .unwrap();
    assert!(materialize_named_artifact(&store, &receipt.root(), receipt.digest(), "dev").is_err());
    assert!(materialize_artifact(&store, &receipt.root(), receipt.digest()).is_ok());
    drop((out, dev));
    let digest = receipt.outputs["dev"].artifact.to_string();
    let object = temporary
        .path()
        .join("objects/sha256")
        .join(&digest[..2])
        .join(digest);
    fs::write(object, b"corrupt named output").unwrap();
    assert!(
        crate::build::cache::lookup(
            &store.operation().unwrap(),
            &action,
            None,
            &Cancellation::default()
        )
        .is_err()
    );
    assert!(materialize_artifact(&store, &receipt.root(), receipt.digest()).is_err());
}

#[test]
fn generation_root_reopens_after_preparation_gc_and_view_reclamation() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let result = crate::build::cache::tests::retained(
        &store.operation().unwrap(),
        &crate::build::cache::tests::action(),
        b"content",
    );
    let cancellation = Cancellation::default();
    let view = materialize_artifact(&store, &result.root, result.receipt).unwrap();
    let physical = view.directory().unwrap();
    let generation = RootName::new("generation_42_tool").unwrap();
    let retained = view.retain(&generation, &cancellation).unwrap();
    assert_eq!(
        view.retain(&generation, &cancellation).unwrap(),
        retained
    );
    assert_eq!(
        clear_materializations(&mut store.maintenance().unwrap()).unwrap(),
        0
    );
    assert_eq!(
        view.read_file("bin/hello", 7, &cancellation)
            .unwrap(),
        b"content"
    );
    assert!(
        view.read_file("bin/hello", 6, &cancellation)
            .is_err()
    );
    for path in [
        "../bin/hello",
        "/bin/hello",
        "bin/missing",
    ] {
        assert!(view.read_file(path, 64, &cancellation).is_err());
    }
    let cancelled = Cancellation::default();
    cancelled.cancel();
    let unused = RootName::new("cancelled_generation").unwrap();
    assert!(matches!(
        view.retain(&unused, &cancelled),
        Err(MaterializationError::Cancelled)
    ));
    assert!(
        store
            .operation()
            .unwrap()
            .build_references(&unused)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        view.read_file("bin/hello", 7, &cancelled),
        Err(MaterializationError::Cancelled)
    ));
    assert!(matches!(
        retained.open(&store, &cancelled),
        Err(MaterializationError::Cancelled)
    ));
    drop(view);
    {
        let mut maintenance = store.maintenance().unwrap();
        assert_eq!(
            clear_materializations(&mut maintenance).unwrap(),
            1
        );
        let report = maintenance
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                remove_roots: vec![result.root.clone()],
                limits: crate::store::GcLimits::default(),
            })
            .unwrap();
        assert!(report.removed_objects.is_empty());
        assert!(!report.uncertain);
    }
    assert!(!physical.exists());
    drop(store);
    let store = Store::open(directory.path()).unwrap();
    let view = retained.open(&store, &cancellation).unwrap();
    assert!(!view.reused());
    assert_eq!(
        view.read_file("bin/hello", 7, &cancellation)
            .unwrap(),
        b"content"
    );
    assert!(materialize_artifact(&store, &result.root, result.receipt).is_err());
    for field in 0..5 {
        let mut invalid = retained.clone();
        match field {
            0 => invalid.identity.action = ContentDigest::sha256(b"wrong"),
            1 => invalid.identity.artifact = ContentDigest::sha256(b"wrong"),
            2 => {
                invalid.identity.origin = OutputOrigin::Built {
                    receipt: ContentDigest::sha256(b"wrong"),
                }
            }
            3 => invalid.identity.output = "missing".into(),
            _ => invalid.root = unused.clone(),
        }
        assert!(invalid.open(&store, &cancellation).is_err());
    }
    let other = crate::build::cache::tests::retained(
        &store.operation().unwrap(),
        &crate::build::cache::tests::action(),
        b"other",
    );
    let other_view = materialize_artifact(&store, &other.root, other.receipt).unwrap();
    assert!(matches!(
        other_view.retain(&generation, &cancellation),
        Err(MaterializationError::Store(
            StoreError::RootConflict { .. }
        ))
    ));
    let other_root = other.root.clone();
    drop((view, other_view, result, other));
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            remove_roots: vec![generation, other_root],
            limits: crate::store::GcLimits::default(),
        })
        .unwrap();
    assert!(
        report
            .removed_objects
            .contains(&retained.identity.artifact)
    );
    assert!(retained.open(&store, &cancellation).is_err());
}

#[test]
fn verified_tree_reuses_and_detects_tampering_and_rebuilds_missing_view() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let result = {
        let lease = store.operation().unwrap();
        crate::build::cache::tests::retained(
            &lease,
            &crate::build::cache::tests::action(),
            b"hello",
        )
    };
    let caller = RootName::new("caller_view").unwrap();
    {
        let lease = store.operation().unwrap();
        let references = lease
            .build_references(&result.root)
            .unwrap()
            .unwrap();
        lease.publish_root(&caller, &references).unwrap();
    }
    let view = materialize_artifact(&store, &result.root, result.receipt).unwrap();
    assert_eq!(
        clear_materializations(&mut store.maintenance().unwrap()).unwrap(),
        0
    );
    assert!(!view.reused());
    assert_eq!(view.files(), 1);
    assert_eq!(
        view.logical_prefix(),
        format!("/syrox/store/{}/out", result.action)
    );
    let path = view.directory().unwrap();
    assert_eq!(
        fs::read(path.join("bin/hello")).unwrap(),
        b"hello"
    );
    assert!(
        materialize_artifact(&store, &caller, result.receipt)
            .unwrap()
            .reused()
    );
    fs::set_permissions(
        path.join("bin/hello"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::write(path.join("bin/hello"), b"other").unwrap();
    assert!(matches!(
        materialize_artifact(&store, &result.root, result.receipt),
        Err(MaterializationError::Invalid(_))
    ));
    drop(view);
    fs::remove_dir_all(&path).unwrap();
    let rebuilt = materialize_artifact(&store, &result.root, result.receipt).unwrap();
    assert!(!rebuilt.reused());
    assert_eq!(
        fs::read(rebuilt.directory().unwrap().join("bin/hello")).unwrap(),
        b"hello"
    );
    drop(rebuilt);
    assert!(store.maintenance().is_ok());
}

#[test]
fn only_retained_receipts_authorize_views_and_recovery_removes_staging() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let result = {
        let lease = store.operation().unwrap();
        crate::build::cache::tests::retained(
            &lease,
            &crate::build::cache::tests::action(),
            b"hello",
        )
    };
    assert!(
        materialize_artifact(
            &store,
            &RootName::new("unknown").unwrap(),
            result.receipt
        )
        .is_err()
    );
    store
        .operation()
        .unwrap()
        .view_directory()
        .unwrap();
    let parent = temporary.path().join(".syrox-store/views");
    fs::create_dir(parent.join("init-0123456789abcdef0123456789abcdef")).unwrap();
    fs::write(
        parent.join("init-0123456789abcdef0123456789abcdef/partial"),
        b"partial",
    )
    .unwrap();
    assert_eq!(recover_materializations(&store).unwrap(), 1);
    assert!(
        !parent
            .join("init-0123456789abcdef0123456789abcdef")
            .exists()
    );
    let _view = materialize_artifact(&store, &result.root, result.receipt).unwrap();
    assert_eq!(recover_materializations(&store).unwrap(), 0);
}

#[test]
fn recovery_refuses_links_and_keeps_unrelated_staging_untouched() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    store
        .operation()
        .unwrap()
        .view_directory()
        .unwrap();
    let staging = temporary
        .path()
        .join(".syrox-store/views/init-0123456789abcdef0123456789abcdef");
    fs::create_dir(&staging).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", staging.join("unsafe")).unwrap();
    assert!(recover_materializations(&store).is_err());
    assert!(fs::symlink_metadata(staging.join("unsafe")).is_ok());
}

#[test]
fn soname_alias_materializes_as_verified_regular_bytes() {
    use std::os::unix::fs::symlink;
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let tree = tempfile::tempdir().unwrap();
    fs::create_dir(tree.path().join("bin")).unwrap();
    fs::create_dir_all(tree.path().join("usr/lib")).unwrap();
    fs::write(tree.path().join("bin/hello"), b"hello").unwrap();
    fs::set_permissions(
        tree.path().join("bin/hello"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::write(
        tree.path().join("usr/lib/libanswer.so.1.2"),
        b"shared object",
    )
    .unwrap();
    symlink(
        "libanswer.so.1.2",
        tree.path().join("usr/lib/libanswer.so.1"),
    )
    .unwrap();
    let mut bytes = Vec::new();
    artifact::pack(tree.path(), &mut bytes).unwrap();
    let action = crate::build::cache::tests::action();
    let receipt = Receipt::new(&action, ContentDigest::sha256(&bytes), 3);
    let lease = store.operation().unwrap();
    let action_bytes = action.encode();
    let receipt_bytes = receipt.encode();
    for bytes in [
        &b"fixture source"[..],
        &b"syrox-host-toolchain\nfixture toolchain"[..],
        &action_bytes,
        &bytes,
        &receipt_bytes,
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
    drop(lease);
    let view = materialize_artifact(&store, &receipt.root(), receipt.digest()).unwrap();
    let alias = view
        .directory()
        .unwrap()
        .join("usr/lib/libanswer.so.1");
    assert!(!fs::symlink_metadata(&alias).unwrap().is_symlink());
    assert_eq!(fs::read(&alias).unwrap(), b"shared object");
    fs::set_permissions(&alias, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&alias, b"changed").unwrap();
    assert!(materialize_artifact(&store, &receipt.root(), receipt.digest()).is_err());
}

#[test]
fn cross_directory_loader_link_is_a_regular_materialized_file() {
    use std::os::unix::fs::symlink;
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let tree = tempfile::tempdir().unwrap();
    fs::create_dir_all(tree.path().join("usr/bin")).unwrap();
    fs::create_dir_all(tree.path().join("usr/lib")).unwrap();
    let loader = tree.path().join("usr/lib/ld-linux-x86-64.so.2");
    fs::write(&loader, b"loader bytes").unwrap();
    fs::set_permissions(&loader, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(
        "../lib/ld-linux-x86-64.so.2",
        tree.path().join("usr/bin/ld.so"),
    )
    .unwrap();
    let mut artifact_bytes = Vec::new();
    artifact::pack(tree.path(), &mut artifact_bytes).unwrap();
    let action = crate::build::cache::tests::action();
    let receipt = Receipt::new(&action, ContentDigest::sha256(&artifact_bytes), 2);
    let lease = store.operation().unwrap();
    let action_bytes = action.encode();
    let receipt_bytes = receipt.encode();
    for bytes in [
        &b"fixture source"[..],
        &b"syrox-host-toolchain\nfixture toolchain"[..],
        &action_bytes,
        &artifact_bytes,
        &receipt_bytes,
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
    drop(lease);
    let view = materialize_artifact(&store, &receipt.root(), receipt.digest()).unwrap();
    let link = view.directory().unwrap().join("usr/bin/ld.so");
    assert!(!fs::symlink_metadata(&link).unwrap().is_symlink());
    assert_eq!(fs::read(link).unwrap(), b"loader bytes");
}

#[test]
fn exclusive_maintenance_reclaims_views_without_dropping_retained_results() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let result = {
        let lease = store.operation().unwrap();
        crate::build::cache::tests::retained(
            &lease,
            &crate::build::cache::tests::action(),
            b"hello",
        )
    };
    let view = materialize_artifact(&store, &result.root, result.receipt).unwrap();
    let physical = view.directory().unwrap();
    assert_eq!(
        clear_materializations(&mut store.maintenance().unwrap()).unwrap(),
        0
    );
    drop(view);
    assert_eq!(
        clear_materializations(&mut store.maintenance().unwrap()).unwrap(),
        1
    );
    assert!(!physical.exists());
    let rebuilt = materialize_artifact(&store, &result.root, result.receipt).unwrap();
    assert!(!rebuilt.reused());
}

#[test]
fn materialization_rejects_a_missing_retained_source_even_with_a_valid_artifact() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let result = {
        let lease = store.operation().unwrap();
        crate::build::cache::tests::retained(
            &lease,
            &crate::build::cache::tests::action(),
            b"hello",
        )
    };
    let source = ContentDigest::sha256(b"fixture source").to_string();
    fs::remove_file(
        temporary
            .path()
            .join("objects/sha256")
            .join(&source[..2])
            .join(source),
    )
    .unwrap();
    assert!(materialize_artifact(&store, &result.root, result.receipt).is_err());
}

#[test]
fn live_view_survives_root_retirement_while_unrelated_objects_are_collected() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let operation = store.operation().unwrap();
    let result = crate::build::cache::tests::retained(
        &operation,
        &crate::build::cache::tests::action(),
        b"content",
    );
    let junk = ContentDigest::sha256(b"unrelated garbage");
    operation
        .ingest(&b"unrelated garbage"[..], junk, 17)
        .unwrap();
    drop(operation);
    let view = materialize_artifact(&store, &result.root, result.receipt).unwrap();
    let physical = view.directory().unwrap();
    let root = result.root.clone();
    drop(result);
    let mut maintenance = store.maintenance().unwrap();
    let report = maintenance
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            remove_roots: vec![root],
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert_eq!(report.removed_objects, [junk]);
    assert_eq!(
        clear_materializations(&mut maintenance).unwrap(),
        0
    );
    drop(maintenance);
    assert_eq!(
        view.read_file("bin/hello", 7, &Cancellation::default())
            .unwrap(),
        b"content"
    );
    assert!(physical.exists());
    drop(view);
    let mut maintenance = store.maintenance().unwrap();
    assert_eq!(
        clear_materializations(&mut maintenance).unwrap(),
        1
    );
    assert!(!physical.exists());
    assert!(
        !maintenance
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                ..crate::store::GcRequest::default()
            })
            .unwrap()
            .removed_objects
            .is_empty()
    );
}

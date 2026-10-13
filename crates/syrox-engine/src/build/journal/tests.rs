use super::*;

#[test]
fn active_operations_are_skipped_and_unlaunched_orphans_recover_idempotently() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let lease = store.operation().unwrap();
    let operation = Operation::create(&lease).unwrap();
    operation
        .write_stage("source", b"input", false)
        .unwrap();
    let path = operation.path.clone();
    assert_eq!(
        recover(&store).unwrap().entries[0].state,
        BuildRecoveryState::Active
    );
    assert!(path.join("stage/source").exists());
    drop(operation);
    assert_eq!(
        recover(&store).unwrap().entries[0].state,
        BuildRecoveryState::Recovered
    );
    assert!(!path.exists());
    assert!(recover(&store).unwrap().entries.is_empty());
}

#[test]
fn revoked_and_removed_operations_cannot_launch_even_with_old_open_descriptors() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let operation = Operation::create(&store.operation().unwrap()).unwrap();
    operation
        .authorize(ContentDigest::sha256(b"action"), None)
        .unwrap();
    let old = fd::open_top_directory(&operation.path).unwrap();
    operation.clean_stage().unwrap();
    assert!(enter_gate(&operation.path).is_err());
    let path = operation.path.clone();
    drop(operation);
    assert_eq!(
        recover(&store).unwrap().entries[0].state,
        BuildRecoveryState::Recovered
    );
    assert!(enter_gate(&path).is_err());
    assert!(lock_existing(&old, "gate").is_err());
}

#[test]
fn recovery_refuses_symlinks_hardlinks_unknown_files_and_namespace_swaps() {
    use std::os::unix::fs::symlink;
    for corruption in [
        "symlink", "hardlink", "unknown", "identity",
    ] {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(root.path()).unwrap();
        let operation = Operation::create(&store.operation().unwrap()).unwrap();
        let path = operation.path.clone();
        let outside = root.path().join("untouched");
        fs::write(&outside, b"keep").unwrap();
        match corruption {
            "symlink" => symlink(&outside, path.join("stage/source")).unwrap(),
            "hardlink" => fs::hard_link(&outside, path.join("stage/source")).unwrap(),
            "unknown" => fs::write(path.join("stage/unknown"), b"keep").unwrap(),
            _ => fs::write(path.join("identity"), b"wrong identity").unwrap(),
        }
        drop(operation);
        assert!(matches!(
            recover(&store).unwrap().entries[0].state,
            BuildRecoveryState::Retained(_)
        ));
        assert!(path.exists());
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
    }
}

#[test]
fn initialization_and_interrupted_removal_are_recoverable_without_manager_access() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let lease = store.operation().unwrap();
    let parent = lease.build_directory().unwrap();
    for prefix in ["init-", "gc-"] {
        let name = format!("{prefix}{}", "a".repeat(32));
        let directory = fd::ensure_directory_beneath(parent.fd(), Path::new(&name)).unwrap();
        write(&directory, "log", b"last diagnostic").unwrap();
        assert_eq!(
            recover(&store).unwrap().entries[0].state,
            BuildRecoveryState::Recovered
        );
    }
}

#[test]
fn uncertain_journal_write_never_authorizes_launch_and_cleanup_failure_is_retryable() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let operation = Operation::create(&store.operation().unwrap()).unwrap();
    operation
        .write_stage("source", b"input", false)
        .unwrap();
    fd::fail_next_lock_after_rename();
    assert!(
        operation
            .authorize(ContentDigest::sha256(b"action"), None)
            .is_err()
    );
    assert!(enter_gate(&operation.path).is_err());
    let path = operation.path.clone();
    drop(operation);
    fd::fail_next_maintenance_unlink();
    assert!(matches!(
        recover(&store).unwrap().entries[0].state,
        BuildRecoveryState::Retained(_)
    ));
    assert!(path.exists());
    assert_eq!(
        recover(&store).unwrap().entries[0].state,
        BuildRecoveryState::Recovered
    );
}

#[test]
fn previous_boot_cannot_launch_and_recovery_needs_no_current_manager() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let lease = store.operation().unwrap();
    let parent = lease.build_directory().unwrap();
    let operation = Operation::create(&lease).unwrap();
    operation
        .authorize(ContentDigest::sha256(b"action"), None)
        .unwrap();
    let current = boot_id().unwrap();
    let old = if let Some(suffix) = current.strip_prefix('a') {
        format!("b{suffix}")
    } else {
        format!("a{}", &current[1..])
    };
    write(
        &operation.directory,
        "identity",
        identity(
            &operation.name,
            &old,
            parent.metadata().identity(),
            operation.directory.metadata().identity(),
        )
        .as_bytes(),
    )
    .unwrap();
    assert!(
        enter_gate(&operation.path)
            .err()
            .unwrap()
            .to_string()
            .contains("previous boot")
    );
    let name = operation.name.clone();
    drop(operation);
    // A marker-only authorized operation from the old boot needs no manager
    // query and must never stop a recycled current-boot unit by name.
    assert_eq!(
        recover_one(&parent, &name, &current).unwrap(),
        BuildRecoveryState::Recovered
    );
}

#[test]
fn identity_checksum_and_store_binding_refuse_changed_authority() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let store = Store::open(first.path()).unwrap();
    let other = Store::open(second.path()).unwrap();
    let operation = Operation::create(&store.operation().unwrap()).unwrap();
    let path = operation.path.clone();
    let name = operation.name.clone();
    let bytes = fs::read(path.join("identity")).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    let boot = boot_id().unwrap();
    let changed = if let Some(suffix) = boot.strip_prefix('a') {
        format!("b{suffix}")
    } else {
        format!("a{}", &boot[1..])
    };
    fs::write(
        path.join("identity"),
        text.replace(&boot, &changed),
    )
    .unwrap();
    drop(operation);
    assert!(matches!(
        recover(&store).unwrap().entries[0].state,
        BuildRecoveryState::Retained(_)
    ));
    fs::write(path.join("identity"), bytes).unwrap();
    let parent = other
        .operation()
        .unwrap()
        .build_directory()
        .unwrap();
    let moved = fd::directory_path(&parent).unwrap().join(name);
    fs::rename(path, &moved).unwrap();
    assert!(matches!(
        recover(&other).unwrap().entries[0].state,
        BuildRecoveryState::Retained(_)
    ));
    assert!(moved.exists());
}

#[test]
fn publication_survives_journal_update_uncertainty_and_recovery() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let lease = store.operation().unwrap();
    let operation = Operation::create(&lease).unwrap();
    operation.clean_stage().unwrap();
    let digest = ContentDigest::sha256(b"retained result");
    lease
        .ingest(&b"retained result"[..], digest, 15)
        .unwrap();
    let name = crate::store::RootName::new("published_result").unwrap();
    lease.publish_root(&name, &[digest]).unwrap();
    let result = BuildResult {
        retention: lease.retain_objects(&[digest], &[]).unwrap(),
        execution: super::super::BuildExecution::Built {
            operation: operation.name.clone(),
        },
        action: digest,
        artifact: digest,
        receipt: digest,
        toolchain: Some(digest),
        files: 1,
        root: name,
    };
    fd::fail_next_lock_after_rename();
    assert!(matches!(
        operation.finish(Ok(result)),
        Err(BuildError::PublishedAndJournal { .. })
    ));
    drop(operation);
    let before = fs::read(
        root.path()
            .join("roots/retained/published_result"),
    )
    .unwrap();
    assert_eq!(
        recover(&store).unwrap().entries[0].state,
        BuildRecoveryState::Recovered
    );
    assert_eq!(
        fs::read(
            root.path()
                .join("roots/retained/published_result")
        )
        .unwrap(),
        before
    );
    assert_eq!(
        lease
            .read_verified(digest, 15)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"retained result"
    );
}

#[test]
fn interrupted_record_removal_retries_without_recreating_locks() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let lease = store.operation().unwrap();
    let operation = Operation::create(&lease).unwrap();
    operation.clean_stage().unwrap();
    let parent = lease.build_directory().unwrap();
    let garbage = format!("gc-{}", &operation.name[3..]);
    fd::rename_directory(
        parent.fd(),
        Path::new(&operation.name),
        Path::new(&garbage),
        operation.directory.metadata().identity(),
    )
    .unwrap();
    for name in ["lease", "gate", "identity"] {
        let file = fd::open_existing_regular(operation.directory.fd(), Path::new(name)).unwrap();
        fd::unlink_opened(
            operation.directory.fd(),
            Path::new(name),
            file.metadata().identity(),
        )
        .unwrap();
    }
    drop(operation);
    assert_eq!(
        recover(&store).unwrap().entries[0].state,
        BuildRecoveryState::Recovered
    );
    assert!(recover(&store).unwrap().entries.is_empty());
}

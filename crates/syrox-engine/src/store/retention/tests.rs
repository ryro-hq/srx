use super::*;
use std::os::unix::fs::FileExt as _;

fn ingest(operation: &OperationLease, bytes: &[u8]) -> ContentDigest {
    let digest = ContentDigest::sha256(bytes);
    operation
        .ingest(bytes, digest, bytes.len() as u64)
        .unwrap();
    digest
}
fn collect(store: &Store) -> GcReport {
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap()
}

#[test]
fn independent_interests_allow_gc_and_explicit_root_retirement() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let operation = store.operation().unwrap();
    let first = ingest(&operation, b"first session");
    let second = ingest(&operation, b"second session");
    let unrelated = ingest(&operation, b"unrelated");
    let first_root = RootName::new("first").unwrap();
    let second_root = RootName::new("second").unwrap();
    operation
        .publish_root(&first_root, &[first])
        .unwrap();
    operation
        .publish_root(&second_root, &[second])
        .unwrap();
    let first_interest = operation
        .retain_objects(&[first], &[first])
        .unwrap();
    let second_interest = operation
        .retain_objects(&[second], &[second])
        .unwrap();
    drop(operation);
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![first_root, second_root],
            ..GcRequest::default()
        })
        .unwrap();
    assert_eq!(report.removed_objects, [unrelated]);
    assert_eq!(
        store
            .maintenance()
            .unwrap()
            .protected_views()
            .unwrap(),
        BTreeSet::from([first, second])
    );
    drop(first_interest);
    assert_eq!(collect(&store).removed_objects, [first]);
    assert!(
        second_interest
            .open_verified_checked(second, 100, || Ok(()))
            .unwrap()
            .is_some()
    );
    drop(second_interest);
    assert_eq!(collect(&store).removed_objects, [second]);
}

#[test]
fn independent_process_description_survives_local_unlock_and_duplicate_close() {
    // A foreign harness fork can inherit the process-retention OFD before exec.
    if crate::platform::linux::fd::retention_fork_tests::isolate_test(
        "store::retention::tests::independent_process_description_survives_local_unlock_and_duplicate_close",
        "SYROX_STORE_PROCESS_GC_ISOLATED",
    ) {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let operation = store.operation().unwrap();
    let digest = ingest(&operation, b"remote manager owns this");
    let interest = operation
        .retain_objects(&[digest], &[digest])
        .unwrap();
    let process = interest.process_retention().unwrap();
    let manager_copy = process.try_clone().unwrap();
    drop(operation);
    drop(interest); // Explicitly unlocks the *local* OFD only.
    drop(process);
    assert!(collect(&store).removed_objects.is_empty());
    drop(manager_copy);
    assert_eq!(collect(&store).removed_objects, [digest]);
}

#[test]
fn union_retains_each_closure_and_accepts_reopened_store_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let reopened = Store::open(temporary.path()).unwrap();
    let operation = store.operation().unwrap();
    let first = ingest(&operation, b"application");
    let second = ingest(&operation, b"loader");
    let one = operation
        .retain_objects(&[first], &[first])
        .unwrap();
    let two = reopened
        .operation()
        .unwrap()
        .retain_objects(&[second], &[second])
        .unwrap();
    assert!(one.same_store(&reopened).unwrap());
    let combined = ObjectLease::combine(&[&one, &two]).unwrap();
    drop((operation, one, two));
    assert!(collect(&store).removed_objects.is_empty());
    assert_eq!(
        store
            .maintenance()
            .unwrap()
            .protected_views()
            .unwrap(),
        BTreeSet::from([first, second])
    );
    let other = tempfile::tempdir().unwrap();
    let other_store = Store::open(other.path()).unwrap();
    let foreign = other_store
        .operation()
        .unwrap()
        .retain_objects(&[], &[])
        .unwrap();
    assert!(matches!(
        ObjectLease::combine(&[&combined, &foreign]),
        Err(StoreError::InterestStoreMismatch)
    ));
    drop(combined);
    assert_eq!(collect(&store).removed_objects.len(), 2);
}

#[test]
#[allow(clippy::used_underscore_binding)] // Fault injection into the retained private writer.
fn malformed_live_interest_or_budget_never_sweeps_unrelated_objects() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let operation = store.operation().unwrap();
    let digest = ingest(&operation, b"retained");
    let unrelated = ingest(
        &operation,
        b"must not be swept after invalid inventory",
    );
    let interest = operation.retain_objects(&[digest], &[]).unwrap();
    drop(operation);
    assert!(
        store
            .maintenance()
            .unwrap()
            .garbage_collect(&GcRequest {
                collect: true,
                limits: GcLimits {
                    references: 0,
                    ..GcLimits::default()
                },
                ..GcRequest::default()
            })
            .is_err()
    );
    // Simulate corruption through the already-open writer without chmod/path races.
    interest
        ._lock
        .0
        .write_all_at(b"broken", 0)
        .unwrap();
    assert!(matches!(
        store
            .maintenance()
            .unwrap()
            .garbage_collect(&GcRequest {
                collect: true,
                ..GcRequest::default()
            }),
        Err(StoreError::InterestCorrupt)
    ));
    assert!(
        store
            .operation()
            .unwrap()
            .verify(unrelated)
            .unwrap()
            .is_some()
    );
    drop(interest);
    assert_eq!(collect(&store).removed_objects.len(), 2); // Abandoned torn records carry no authority.
}

#[test]
fn interest_codec_rejects_noncanonical_and_unreferenced_views() {
    let digest = ContentDigest::sha256(b"x");
    assert!(validate_sets(&[digest, digest], &[]).is_err());
    assert!(validate_sets(&[], &[digest]).is_err());
    let encoded = encode(&[digest], &[digest]);
    assert_eq!(
        decode(&encoded).unwrap(),
        (vec![digest], vec![digest])
    );
    assert!(decode(&encoded[..encoded.len() - 1]).is_err());
}

#[test]
fn replaced_interest_directory_fails_closed_for_existing_store() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let operation = store.operation().unwrap();
    let digest = ingest(&operation, b"must remain live");
    let interest = operation.retain_objects(&[digest], &[]).unwrap();
    drop(operation);
    let directory = temporary.path().join(".syrox-store/interests");
    std::fs::rename(
        &directory,
        temporary.path().join("original-interests"),
    )
    .unwrap();
    std::fs::create_dir(&directory).unwrap();
    assert!(matches!(
        store.maintenance(),
        Err(StoreError::InterestCorrupt)
    ));
    assert!(matches!(
        interest.process_retention(),
        Err(StoreError::InterestCorrupt)
    ));
}

#[test]
#[ignore = "subprocess fixture invoked only by process_interest_survives_coordinator_handles"]
fn process_interest_child() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("SYROX_INTEREST_CHILD_DIRECTORY").expect("explicit fixture directory"),
    );
    std::fs::write(directory.join("ready"), b"ready").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !directory.join("release").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "fixture release timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn process_interest_survives_coordinator_handles() {
    use std::os::fd::AsRawFd as _;
    use std::process::{Command, Stdio};
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    // A foreign harness fork can inherit the process-retention OFD before exec.
    if crate::platform::linux::fd::retention_fork_tests::isolate_test(
        "store::retention::tests::process_interest_survives_coordinator_handles",
        "SYROX_STORE_CHILD_GC_ISOLATED",
    ) {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let operation = store.operation().unwrap();
    let digest = ingest(&operation, b"child owns the interest");
    let unrelated = ingest(&operation, b"unrelated child garbage");
    let interest = operation
        .retain_objects(&[digest], &[digest])
        .unwrap();
    let process = interest.process_retention().unwrap();
    assert!(
        (&process)
            .write_all(b"cannot mutate through process fd")
            .is_err()
    );
    let mut command = Command::new(crate::reexec_test_executable(
        "store::retention::tests::process_interest_child",
        true,
    ));
    command
        .args([
            "--exact",
            "store::retention::tests::process_interest_child",
            "--ignored",
        ])
        .env("SYROX_INTEREST_CHILD_DIRECTORY", temporary.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    crate::platform::linux::fd::pass_fd_to_child(&mut command, process.as_raw_fd());
    let mut child = ChildGuard(command.spawn().unwrap());
    drop((operation, interest, process));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !temporary.path().join("ready").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "child startup timed out"
        );
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before retention observation"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(collect(&store).removed_objects, [unrelated]);
    assert_eq!(
        store
            .maintenance()
            .unwrap()
            .protected_views()
            .unwrap(),
        BTreeSet::from([digest])
    );
    std::fs::write(temporary.path().join("release"), b"release").unwrap();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "child settlement timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(collect(&store).removed_objects, [digest]);
}

#[test]
fn concurrent_gc_cannot_cross_the_operation_to_interest_handoff() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let operation = store.operation().unwrap();
    let digest = ingest(&operation, b"handoff object");
    let junk = ingest(&operation, b"handoff garbage");
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let start = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            start.wait();
            let interest = operation
                .retain_objects(&[digest], &[digest])
                .unwrap();
            sender.send(interest).unwrap();
            drop(operation);
        });
        assert!(matches!(
            store.maintenance(),
            Err(StoreError::Busy)
        ));
        start.wait();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match store.maintenance() {
                Ok(mut maintenance) => {
                    let report = maintenance
                        .garbage_collect(&GcRequest {
                            collect: true,
                            ..GcRequest::default()
                        })
                        .unwrap();
                    assert_eq!(report.removed_objects, [junk]);
                    break;
                }
                Err(StoreError::Busy) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "handoff remained globally locked"
                    );
                    std::thread::yield_now();
                }
                Err(error) => panic!("unexpected maintenance failure: {error}"),
            }
        }
        drop(
            receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
        );
    });
    assert_eq!(collect(&store).removed_objects, [digest]);
}

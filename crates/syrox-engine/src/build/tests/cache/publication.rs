use super::*;

#[test]
fn inverse_shard_pairs_and_coincident_shards_serialize_without_deadlock() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let digest = |prefix: &str| -> ContentDigest {
        format!("{prefix}{}", "0".repeat(62))
            .parse()
            .unwrap()
    };
    for ((first_a, first_b), (second_a, second_b), coincident) in [
        (
            (digest("10"), digest("f0")),
            (digest("f0"), digest("10")),
            false,
        ),
        (
            (digest("10"), digest("10")),
            (digest("10"), digest("10")),
            true,
        ),
    ] {
        let barrier = Arc::new(Barrier::new(3));
        let (acquired, received) = mpsc::channel();
        let mut releases = Vec::new();
        let handles: Vec<_> = [(first_a, first_b), (second_a, second_b)]
            .into_iter()
            .enumerate()
            .map(|(index, (application, provider))| {
                let (release, permit) = mpsc::channel::<()>();
                releases.push(release);
                let barrier = Arc::clone(&barrier);
                let acquired = acquired.clone();
                let lease = lease.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let guards = index_shards(
                        &lease,
                        application,
                        provider,
                        &Cancellation::default(),
                    )
                    .unwrap();
                    assert_eq!(guards.1.is_none(), coincident);
                    acquired.send(index).unwrap();
                    permit
                        .recv_timeout(Duration::from_secs(3))
                        .unwrap();
                    drop(guards);
                })
            })
            .collect();
        barrier.wait();
        let first = received
            .recv_timeout(Duration::from_secs(3))
            .expect("first pair must acquire");
        assert!(
            received
                .recv_timeout(Duration::from_millis(80))
                .is_err(),
            "second pair bypassed held shard"
        );
        releases[first].send(()).unwrap();
        received
            .recv_timeout(Duration::from_secs(3))
            .expect("second pair must acquire after release");
        releases[1 - first].send(()).unwrap();
        for handle in handles {
            handle.join().unwrap();
        }
    }
}

#[test]
fn conflicting_concurrent_publications_preserve_both_roots_and_refuse_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let first = retained(&lease, &action, b"first executable");
    let second = retained(&lease, &action, b"second executable");
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            record(&lease, &action, &first)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            record(&lease, &action, &second)
        });
        let results = [a.join().unwrap(), b.join().unwrap()];
        assert!(results.iter().filter(|r| r.is_ok()).count() <= 1);
        assert!(
            results
                .iter()
                .filter(|r| matches!(r, Err(BuildError::DivergentResults { .. })))
                .count()
                >= 1
        );
    });
    assert!(matches!(
        lookup(&lease, &action, None, &Cancellation::default()),
        Err(BuildError::DivergentResults { .. })
    ));
    assert!(
        lease
            .build_references(&first.root)
            .unwrap()
            .is_some()
    );
    assert!(
        lease
            .build_references(&second.root)
            .unwrap()
            .is_some()
    );
    let report = rebuild(&store).unwrap();
    assert_eq!(report.conflicts, [action.digest()]);
}

#[test]
fn uncertain_root_publication_is_not_automatically_indexed_and_index_failure_keeps_root() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"executable");
    let references = lease
        .build_references(&result.root)
        .unwrap()
        .unwrap();
    fs::remove_file(
        directory
            .path()
            .join("roots/retained")
            .join(result.root.as_str()),
    )
    .unwrap();
    fd::fail_next_atomic(fd::AtomicFault::DirectorySync);
    assert!(matches!(
        lease.publish_root(&result.root, &references),
        Err(crate::store::StoreError::PublicationUncertain { .. })
    ));
    // Inject a real post-rename durability failure. Visibility alone is not an
    // automatic cache hit, even though every blob and root name is present.
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    lease
        .publish_root(&result.root, &references)
        .unwrap();
    fd::fail_next_lock_before_rename();
    assert!(record(&lease, &action, &result).is_err());
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    assert!(
        lease
            .build_references(&result.root)
            .unwrap()
            .is_some()
    );
    fd::fail_next_lock_after_rename();
    assert!(record(&lease, &action, &result).is_err());
    // Index durability was uncertain; the underlying result was fully committed.
    // A new hit independently verifies and reconfirms durable retention.
    assert_eq!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .unwrap()
            .receipt,
        result.receipt
    );
}

#[test]
fn uncertain_publication_requires_rebuild_before_hit_and_gc_prunes_its_index() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"uncertain build result");
    let references = lease
        .build_references(&result.root)
        .unwrap()
        .unwrap();
    fs::remove_file(
        directory
            .path()
            .join("roots/retained")
            .join(result.root.as_str()),
    )
    .unwrap();
    fd::fail_next_atomic(fd::AtomicFault::DirectorySync);
    assert!(matches!(
        lease.publish_root(&result.root, &references),
        Err(crate::store::StoreError::PublicationUncertain { .. })
    ));
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    drop(lease);

    let report = rebuild(&store).unwrap();
    assert_eq!(report.indexed, 1);
    let lease = store.operation().unwrap();
    assert_eq!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .unwrap()
            .receipt,
        result.receipt
    );
    drop(lease);

    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![result.root],
            ..GcRequest::default()
        })
        .unwrap();
    let lease = store.operation().unwrap();
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    drop(lease);
    assert_eq!(rebuild(&store).unwrap().removed_stale, 1);
    assert!(!index_path(directory.path(), &action).exists());
}

use super::*;

#[test]
fn corrupt_unsafe_and_misbound_index_entries_are_errors_not_misses() {
    for damage in [
        "truncated",
        "symlink",
        "hardlink",
        "action",
        "receipt",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let lease = store.operation().unwrap();
        let action = action();
        let result = retained(&lease, &action, b"executable");
        record(&lease, &action, &result).unwrap();
        let path = index_path(directory.path(), &action);
        let bytes = fs::read(&path).unwrap();
        let other = directory.path().join("outside");
        fs::write(&other, &bytes).unwrap();
        match damage {
            "truncated" => fs::write(&path, &bytes[..bytes.len() - 1]).unwrap(),
            "symlink" => {
                fs::remove_file(&path).unwrap();
                symlink(&other, &path).unwrap();
            }
            "hardlink" => {
                fs::remove_file(&path).unwrap();
                fs::hard_link(&other, &path).unwrap();
            }
            "action" => fs::write(
                &path,
                String::from_utf8(bytes.clone()).unwrap().replace(
                    &action.digest().to_string(),
                    &ContentDigest::sha256(b"wrong action").to_string(),
                ),
            )
            .unwrap(),
            _ => fs::write(
                &path,
                String::from_utf8(bytes.clone()).unwrap().replace(
                    &format!("result {} ", result.receipt),
                    &format!(
                        "result {} ",
                        ContentDigest::sha256(b"missing receipt")
                    ),
                ),
            )
            .unwrap(),
        }
        assert!(
            lookup(&lease, &action, None, &Cancellation::default()).is_err(),
            "{damage}"
        );
        assert_eq!(fs::read(other).unwrap(), bytes);
    }
}

#[test]
fn losing_the_index_cannot_hide_a_retained_divergent_result() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let first = retained(&lease, &action, b"first");
    record(&lease, &action, &first).unwrap();
    fs::remove_file(index_path(directory.path(), &action)).unwrap();
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    let second = retained(&lease, &action, b"different rebuild");
    assert!(matches!(
        record(&lease, &action, &second),
        Err(BuildError::DivergentResults { .. })
    ));
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
}

#[test]
fn reconstruction_uses_retained_receipts_and_identical_writers_converge() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"executable");
    std::thread::scope(|scope| {
        let a = scope.spawn(|| record(&lease, &action, &result));
        let b = scope.spawn(|| record(&lease, &action, &result));
        a.join().unwrap().unwrap();
        b.join().unwrap().unwrap();
    });
    fs::remove_dir_all(directory.path().join(".syrox-store/actions")).unwrap();
    let report = rebuild(&store).unwrap();
    assert_eq!(report.indexed, 1);
    assert!(report.conflicts.is_empty());
    assert_eq!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .unwrap()
            .receipt,
        result.receipt
    );
}

#[test]
fn reindex_repairs_bounded_malformed_hints_and_prunes_only_unretained_entries() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"executable");
    record(&lease, &action, &result).unwrap();
    let path = index_path(directory.path(), &action);
    fs::write(&path, b"truncated").unwrap();
    assert!(lookup(&lease, &action, None, &Cancellation::default()).is_err());
    assert_eq!(rebuild(&store).unwrap().indexed, 1);
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_some()
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
    assert_eq!(rebuild(&store).unwrap().removed_stale, 1);
    assert!(!path.exists());
}

#[test]
fn a_divergence_marker_stays_closed_until_explicit_reconstruction() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let first = retained(&lease, &action, b"first");
    record(&lease, &action, &first).unwrap();
    let second = retained(&lease, &action, b"second");
    assert!(matches!(
        record(&lease, &action, &second),
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
        lookup(&lease, &action, None, &Cancellation::default()),
        Err(BuildError::DivergentResults { .. })
    ));
    assert_eq!(rebuild(&store).unwrap().indexed, 1);
    assert_eq!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .unwrap()
            .receipt,
        first.receipt
    );
}

use super::*;

const EXECUTION: &str = "1234567890abcdef1234567890abcdef";

fn setup() -> (
    tempfile::TempDir,
    Store,
    ObjectLease,
    ContentDigest,
) {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let operation = store.operation().unwrap();
    let bytes: &[u8] = b"persistent runtime closure";
    let digest = ContentDigest::sha256(bytes);
    operation
        .ingest(bytes, digest, bytes.len() as u64)
        .unwrap();
    let interest = operation
        .retain_objects(&[digest], &[digest])
        .unwrap();
    drop(operation);
    (directory, store, interest, digest)
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
fn durable_record_survives_all_lease_closes_and_protects_objects_and_views() {
    let (_directory, store, lease, digest) = setup();
    let durable = lease
        .persist_checked(EXECUTION, || Ok(()))
        .unwrap();
    drop(lease);
    assert!(collect(&store).removed_objects.is_empty());
    assert_eq!(
        store
            .maintenance()
            .unwrap()
            .protected_views()
            .unwrap(),
        BTreeSet::from([digest])
    );
    durable.retire_checked(|| Ok(())).unwrap();
    assert_eq!(collect(&store).removed_objects, [digest]);
    assert!(
        store
            .maintenance()
            .unwrap()
            .protected_views()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn dropping_durable_owner_never_retires_and_matching_identity_can_be_resumed() {
    let (_directory, store, lease, digest) = setup();
    let durable = lease
        .persist_checked(EXECUTION, || Ok(()))
        .unwrap();
    let identity = durable.identity;
    drop(durable);
    drop(lease);
    assert!(collect(&store).removed_objects.is_empty());
    let recovered = store
        .operation()
        .unwrap()
        .retain_objects(&[digest], &[digest])
        .unwrap();
    let durable = recovered
        .persist_checked(EXECUTION, || Ok(()))
        .unwrap();
    assert_eq!(durable.identity, identity);
    drop(recovered);
    durable.retire_checked(|| Ok(())).unwrap();
    assert_eq!(collect(&store).removed_objects, [digest]);
}

#[test]
fn publication_conflict_cancellation_and_invalid_identity_never_replace_retention() {
    let (_directory, store, lease, digest) = setup();
    let durable = lease
        .persist_checked(EXECUTION, || Ok(()))
        .unwrap();
    let different = store
        .operation()
        .unwrap()
        .retain_objects(&[digest], &[])
        .unwrap();
    assert!(
        different
            .persist_checked(EXECUTION, || Ok(()))
            .is_err()
    );
    for identity in [
        "../escape",
        "",
        "ABCDEF1234567890abcdef1234567890ab",
    ] {
        assert!(
            lease
                .persist_checked(identity, || Ok(()))
                .is_err()
        );
    }
    assert!(
        lease
            .persist_checked("abcdef1234567890abcdef1234567890", || {
                Err(crate::cancellation::cancellation_io())
            })
            .is_err()
    );
    drop((lease, different));
    assert!(collect(&store).removed_objects.is_empty());
    assert_eq!(
        store
            .maintenance()
            .unwrap()
            .protected_views()
            .unwrap(),
        BTreeSet::from([digest])
    );
    assert!(
        durable
            .retire_checked(|| Err(crate::cancellation::cancellation_io()))
            .is_err()
    );
    assert!(collect(&store).removed_objects.is_empty());
}

#[test]
fn retirement_rejects_replaced_inode_and_malformed_durable_record_blocks_gc() {
    let (directory, store, lease, _digest) = setup();
    let durable = lease
        .persist_checked(EXECUTION, || Ok(()))
        .unwrap();
    let path = directory
        .path()
        .join(".syrox-store/interests")
        .join(&durable.name);
    let displaced = directory.path().join("displaced-interest");
    std::fs::rename(&path, &displaced).unwrap();
    std::fs::write(&path, &durable.bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(durable.retire_checked(|| Ok(())).is_err());
    assert!(path.exists());
    drop(lease);
    std::fs::write(&path, b"partial durable record").unwrap();
    assert!(
        store
            .maintenance()
            .unwrap()
            .garbage_collect(&GcRequest {
                collect: true,
                ..GcRequest::default()
            })
            .is_err()
    );
}

#[test]
fn uncertain_publication_remains_protected_and_can_be_reconciled() {
    let (_directory, store, lease, digest) = setup();
    crate::platform::linux::fd::fail_next_atomic(
        crate::platform::linux::fd::AtomicFault::DirectorySync,
    );
    assert!(matches!(
        lease.persist_checked(EXECUTION, || Ok(())),
        Err(StoreError::PublicationUncertain { .. })
    ));
    drop(lease);
    assert!(collect(&store).removed_objects.is_empty());
    assert_eq!(
        store
            .maintenance()
            .unwrap()
            .protected_views()
            .unwrap(),
        BTreeSet::from([digest])
    );
    let lease = store
        .operation()
        .unwrap()
        .retain_objects(&[digest], &[digest])
        .unwrap();
    let durable = lease
        .persist_checked(EXECUTION, || Ok(()))
        .unwrap();
    drop(lease);
    durable.retire_checked(|| Ok(())).unwrap();
    assert_eq!(collect(&store).removed_objects, [digest]);
}

mod reopen;

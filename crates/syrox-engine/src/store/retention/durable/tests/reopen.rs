use super::*;

#[test]
fn reopened_store_recovers_existing_hold_without_republishing_or_live_lease() {
    let (directory, store, lease, digest) = setup();
    let durable = lease
        .persist_checked(EXECUTION, || Ok(()))
        .unwrap();
    let pin = durable.digest();
    let anchor = lease.durable_store_anchor().unwrap();
    assert_eq!(anchor, durable.store_anchor());
    let identity = durable.identity;
    drop((durable, lease, store));
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(store.durable_interest_anchor().unwrap(), anchor);
    let reopened = store
        .reopen_durable_interest_checked(EXECUTION, pin, anchor, || Ok(()))
        .unwrap();
    assert_eq!(reopened.identity, identity);
    assert_eq!(reopened.digest(), pin);
    assert_eq!(reopened.execution(), EXECUTION);
    assert!(collect(&store).removed_objects.is_empty());
    reopened.retire_checked(|| Ok(())).unwrap();
    assert_eq!(collect(&store).removed_objects, [digest]);
}
#[test]
fn absence_and_wrong_content_pin_never_create_or_replace_a_hold() {
    let (directory, store, lease, _digest) = setup();
    let anchor = store.durable_interest_anchor().unwrap();
    let pin = lease.durable_digest();
    let path = directory
        .path()
        .join(".syrox-store/interests")
        .join(format!("hold-{EXECUTION}"));
    assert!(
        matches!(store.reopen_durable_interest_checked(EXECUTION, pin, anchor, || Ok(())), Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound)
    );
    assert!(!path.exists());
    let durable = lease
        .persist_checked(EXECUTION, || Ok(()))
        .unwrap();
    let identity = durable.identity;
    assert!(
        store
            .reopen_durable_interest_checked(
                EXECUTION,
                ContentDigest::sha256(b"wrong"),
                anchor,
                || Ok(())
            )
            .is_err()
    );
    assert_eq!(
        open_regular(&durable.directory, &durable.name)
            .unwrap()
            .metadata()
            .identity(),
        identity
    );
    assert!(
        store
            .reopen_durable_interest_checked("../outside", pin, anchor, || Ok(()))
            .is_err()
    );
    assert!(
        store
            .reopen_durable_interest_checked(EXECUTION, pin, anchor, || Err(
                crate::cancellation::cancellation_io()
            ))
            .is_err()
    );
    assert!(path.exists());
}
#[test]
fn same_content_in_another_store_does_not_match_the_recorded_store_anchor() {
    let (_directory, store, lease, _digest) = setup();
    let (_other_directory, other_store, other_lease, _) = setup();
    let durable = lease
        .persist_checked(EXECUTION, || Ok(()))
        .unwrap();
    let other = other_lease
        .persist_checked(EXECUTION, || Ok(()))
        .unwrap();
    assert_eq!(durable.digest(), other.digest());
    let anchor = store.durable_interest_anchor().unwrap();
    assert_ne!(
        anchor,
        other_store.durable_interest_anchor().unwrap()
    );
    assert!(matches!(
        other_store.reopen_durable_interest_checked(EXECUTION, durable.digest(), anchor, || Ok(())),
        Err(StoreError::InterestStoreMismatch)
    ));
}
#[test]
fn replacement_during_read_and_after_reopening_are_refused() {
    let (directory, store, lease, _digest) = setup();
    let durable = lease
        .persist_checked(EXECUTION, || Ok(()))
        .unwrap();
    let path = directory
        .path()
        .join(".syrox-store/interests")
        .join(&durable.name);
    let pin = durable.digest();
    let anchor = durable.store_anchor();
    let original = durable.bytes.clone();
    let mut calls = 0;
    assert!(
        store
            .reopen_durable_interest_checked(EXECUTION, pin, anchor, || {
                calls += 1;
                // The first callback precedes open; the second follows the initial pin.
                if calls == 2 {
                    std::fs::rename(&path, directory.path().join("displaced"))?;
                    std::fs::write(&path, &original)?;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                }
                Ok(())
            })
            .is_err()
    );
    // Identical canonical contents before capture are acceptable; retirement
    // thereafter pins that exact inode and refuses a subsequent replacement.
    let reopened = store
        .reopen_durable_interest_checked(EXECUTION, pin, anchor, || Ok(()))
        .unwrap();
    std::fs::rename(&path, directory.path().join("displaced-again")).unwrap();
    std::fs::write(&path, &original).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(reopened.retire_checked(|| Ok(())).is_err());
    assert!(path.exists());
}
#[test]
fn retirement_sync_uncertainty_is_not_converted_to_reopen_success() {
    let (directory, store, lease, _digest) = setup();
    let durable = lease
        .persist_checked(EXECUTION, || Ok(()))
        .unwrap();
    let pin = durable.digest();
    let anchor = durable.store_anchor();
    crate::platform::linux::fd::fail_next_maintenance_sync();
    assert!(matches!(
        durable.retire_checked(|| Ok(())),
        Err(StoreError::PublicationUncertain { .. })
    ));
    let path = directory
        .path()
        .join(".syrox-store/interests")
        .join(format!("hold-{EXECUTION}"));
    assert!(!path.exists());
    assert!(
        matches!(store.reopen_durable_interest_checked(EXECUTION, pin, anchor, || Ok(())), Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound)
    );
    assert!(!path.exists());
}

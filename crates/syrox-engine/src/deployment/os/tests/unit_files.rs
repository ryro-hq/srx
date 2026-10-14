use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
const ID: &str = "1234567890abcdef1234567890abcdef";
const FIRST: &[u8] = b"# syrox-os-unit-v1\n[Service]\nType=notify\n";
const SECOND: &[u8] = b"# syrox-os-unit-v1\n[Service]\nType=notify\nRestart=no\n";
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn unit() -> SystemdUnitName {
    SystemdUnitName::new(format!(
        "syrox-os-{ID}-{}.service",
        ContentDigest::sha256(b"service/process")
    ))
    .unwrap()
}
fn fixture() -> (tempfile::TempDir, UnitFiles) {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let publisher = UnitFiles::open(
        temp.path(),
        ID,
        &Cancellation::default(),
        deadline(),
    )
    .unwrap();
    (temp, publisher)
}

#[test]
fn durable_previous_absence_after_pre_rename_loss_never_replays_publication() {
    let (temp, publisher) = fixture();
    let cancel = Cancellation::default();
    let target = ContentDigest::sha256(FIRST);
    publisher
        .confirm_previous(&unit(), None, target, &cancel, deadline())
        .unwrap();
    FAIL_AT.with(|stage| stage.set(1));
    let result = publish(&publisher, FIRST, None);
    FAIL_AT.with(|stage| stage.set(0));
    assert!(result.is_err());
    let publisher = reopen(temp.path());
    assert!(
        publisher
            .confirm_previous(&unit(), None, target, &cancel, deadline())
            .is_err()
    );
    assert_eq!(
        publisher
            .reconcile_expected(&unit(), None, target, &cancel, deadline())
            .unwrap(),
        UnitReconciliation::NotPublished {
            unit: unit().as_str().into(),
            previous: None
        }
    );
    assert_eq!(
        publisher
            .observe(&unit(), &cancel, deadline())
            .unwrap(),
        None
    );
    publisher
        .confirm_previous(&unit(), None, target, &cancel, deadline())
        .unwrap();
    assert!(!temp.path().join(unit().as_str()).exists());
    assert!(publisher.load().unwrap().units.is_empty());
}

#[test]
fn durable_owned_previous_requires_distinct_target_and_exact_ownership() {
    let (temp, publisher) = fixture();
    let cancel = Cancellation::default();
    let previous = publish(&publisher, FIRST, None).unwrap();
    let target = ContentDigest::sha256(SECOND);
    FAIL_AT.with(|stage| stage.set(1));
    let result = publish(&publisher, SECOND, Some(previous));
    FAIL_AT.with(|stage| stage.set(0));
    assert!(result.is_err());
    let publisher = reopen(temp.path());
    publisher
        .reconcile_expected(
            &unit(),
            Some(previous),
            target,
            &cancel,
            deadline(),
        )
        .unwrap();
    publisher
        .confirm_previous(
            &unit(),
            Some(previous),
            target,
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        publisher
            .confirm_previous(
                &unit(),
                Some(previous),
                previous,
                &cancel,
                deadline()
            )
            .is_err()
    );
    assert!(
        publisher
            .confirm_previous(&unit(), None, target, &cancel, deadline())
            .is_err()
    );
    assert_eq!(
        fs::read(temp.path().join(unit().as_str())).unwrap(),
        FIRST
    );
    assert_eq!(
        publisher.load().unwrap().units[unit().as_str()],
        previous
    );
}

#[test]
fn missing_committed_target_and_foreign_bytes_never_prove_previous_absence() {
    let (temp, publisher) = fixture();
    let cancel = Cancellation::default();
    let target = publish(&publisher, FIRST, None).unwrap();
    fs::remove_file(temp.path().join(unit().as_str())).unwrap();
    assert!(
        publisher
            .confirm_previous(&unit(), None, target, &cancel, deadline())
            .is_err()
    );
    assert!(
        publisher
            .observe(&unit(), &cancel, deadline())
            .is_err()
    );
    assert_eq!(
        publisher.load().unwrap().units[unit().as_str()],
        target
    );
    let (foreign, publisher) = fixture();
    let file = foreign.path().join(unit().as_str());
    fs::write(&file, FIRST).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    for previous in [None, Some(target)] {
        assert!(
            publisher
                .confirm_previous(
                    &unit(),
                    previous,
                    ContentDigest::sha256(SECOND),
                    &cancel,
                    deadline()
                )
                .is_err()
        );
    }
    assert_eq!(fs::read(file).unwrap(), FIRST);
    assert!(publisher.load().unwrap().units.is_empty());
}

#[test]
fn conflicting_pending_intent_cannot_prove_a_different_publication_was_absent() {
    let (temp, publisher) = fixture();
    let cancel = Cancellation::default();
    FAIL_AT.with(|stage| stage.set(1));
    let result = publish(&publisher, FIRST, None);
    FAIL_AT.with(|stage| stage.set(0));
    assert!(result.is_err());
    let publisher = reopen(temp.path());
    let conflicting = ContentDigest::sha256(SECOND);
    assert!(
        publisher
            .reconcile_expected(&unit(), None, conflicting, &cancel, deadline())
            .is_err()
    );
    assert!(
        publisher
            .confirm_previous(&unit(), None, conflicting, &cancel, deadline())
            .is_err()
    );
    assert!(publisher.load().unwrap().pending.is_some());
    assert!(!temp.path().join(unit().as_str()).exists());
}

#[test]
fn durable_observation_rechecks_absence_and_file_and_ledger_inodes() {
    for changed in ["appearance", "file", "ledger"] {
        let (temp, publisher) = fixture();
        let previous = if changed == "appearance" {
            None
        } else {
            Some(publish(&publisher, FIRST, None).unwrap())
        };
        let file = if changed == "ledger" {
            temp.path()
                .join(format!(".syrox-os-{ID}/ownership"))
        } else {
            temp.path().join(unit().as_str())
        };
        OBSERVATION_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let bytes = if changed == "ledger" {
                    fs::read(&file).unwrap()
                } else {
                    FIRST.to_vec()
                };
                if file.exists() {
                    fs::rename(&file, file.with_extension("previous")).unwrap();
                }
                fs::write(&file, bytes).unwrap();
                fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            }));
        });
        assert!(
            publisher
                .confirm_previous(
                    &unit(),
                    previous,
                    ContentDigest::sha256(SECOND),
                    &Cancellation::default(),
                    deadline()
                )
                .is_err()
        );
    }
}
fn reopen(path: &Path) -> UnitFiles {
    UnitFiles::open(path, ID, &Cancellation::default(), deadline()).unwrap()
}
fn publish(p: &UnitFiles, bytes: &[u8], previous: Option<ContentDigest>) -> Result<ContentDigest> {
    p.publish(
        &unit(),
        bytes,
        previous,
        &Cancellation::default(),
        deadline(),
    )
}

#[test]
fn owns_only_created_units_and_replaces_by_exact_previous_pin() {
    let (temp, p) = fixture();
    let first = publish(&p, FIRST, None).unwrap();
    assert_eq!(
        fs::metadata(temp.path().join(unit().as_str()))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert!(publish(&p, SECOND, None).is_err());
    assert!(publish(&p, SECOND, Some(ContentDigest::sha256(b"wrong"))).is_err());
    let p = reopen(temp.path());
    assert_eq!(
        p.observe(&unit(), &Cancellation::default(), deadline())
            .unwrap(),
        Some(first)
    );
    let second = publish(&p, SECOND, Some(first)).unwrap();
    assert_eq!(second, ContentDigest::sha256(SECOND));
    assert_eq!(
        fs::read(temp.path().join(unit().as_str())).unwrap(),
        SECOND
    );
    assert_eq!(
        p.reconcile(&Cancellation::default(), deadline())
            .unwrap(),
        UnitReconciliation::NoPending
    );
}

#[test]
fn preexisting_equal_bytes_without_ownership_are_never_adopted() {
    let (temp, p) = fixture();
    let file = temp.path().join(unit().as_str());
    fs::write(&file, FIRST).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(publish(&p, FIRST, None).is_err());
    assert!(publish(&p, FIRST, Some(ContentDigest::sha256(FIRST))).is_err());
    assert!(
        p.observe(&unit(), &Cancellation::default(), deadline())
            .is_err()
    );
    assert_eq!(fs::read(&file).unwrap(), FIRST);
    assert!(p.load().unwrap().units.is_empty());
}

#[test]
fn lost_reply_after_rename_requires_reopen_and_explicit_reconciliation() {
    let (temp, p) = fixture();
    FAIL_AT.with(|stage| stage.set(2));
    let result = publish(&p, FIRST, None);
    FAIL_AT.with(|stage| stage.set(0));
    assert!(result.is_err());
    assert_eq!(
        fs::read(temp.path().join(unit().as_str())).unwrap(),
        FIRST
    );
    assert!(
        p.reconcile(&Cancellation::default(), deadline())
            .is_err()
    );
    let p = reopen(temp.path());
    assert!(publish(&p, SECOND, None).is_err());
    assert_eq!(
        p.reconcile(&Cancellation::default(), deadline())
            .unwrap(),
        UnitReconciliation::Published {
            unit: unit().as_str().into(),
            pin: ContentDigest::sha256(FIRST)
        }
    );
    publish(&p, SECOND, Some(ContentDigest::sha256(FIRST))).unwrap();
}

#[test]
fn intent_before_write_is_not_retried_and_conflicting_bytes_are_preserved() {
    let (temp, p) = fixture();
    FAIL_AT.with(|stage| stage.set(1));
    let result = publish(&p, FIRST, None);
    FAIL_AT.with(|stage| stage.set(0));
    assert!(result.is_err());
    assert!(!temp.path().join(unit().as_str()).exists());
    let p = reopen(temp.path());
    assert_eq!(
        p.reconcile(&Cancellation::default(), deadline())
            .unwrap(),
        UnitReconciliation::NotPublished {
            unit: unit().as_str().into(),
            previous: None
        }
    );
    assert!(!temp.path().join(unit().as_str()).exists());
    FAIL_AT.with(|stage| stage.set(1));
    let result = publish(&p, FIRST, None);
    FAIL_AT.with(|stage| stage.set(0));
    assert!(result.is_err());
    let file = temp.path().join(unit().as_str());
    fs::write(&file, SECOND).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let p = reopen(temp.path());
    assert!(
        p.reconcile(&Cancellation::default(), deadline())
            .is_err()
    );
    assert!(p.load().unwrap().pending.is_some());
    assert_eq!(fs::read(file).unwrap(), SECOND);
}

#[test]
fn wrong_namespace_symlinks_hardlinks_and_replaced_authority_are_refused() {
    let (temp, p) = fixture();
    assert!(
        p.publish(
            &SystemdUnitName::new("syrox-other.service").unwrap(),
            FIRST,
            None,
            &Cancellation::default(),
            deadline()
        )
        .is_err()
    );
    let outside = temp.path().join("outside");
    fs::write(&outside, FIRST).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
    let file = temp.path().join(unit().as_str());
    std::os::unix::fs::symlink(&outside, &file).unwrap();
    assert!(publish(&p, FIRST, None).is_err());
    fs::remove_file(&file).unwrap();
    fs::hard_link(&outside, &file).unwrap();
    assert!(publish(&p, FIRST, None).is_err());
    fs::remove_file(&file).unwrap();
    let lock = temp
        .path()
        .join(format!(".syrox-os-{ID}/authority.lock"));
    fs::rename(&lock, lock.with_extension("old")).unwrap();
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(publish(&p, FIRST, None).is_err());
    assert_eq!(fs::read(outside).unwrap(), FIRST);
}

#[test]
fn canceled_missing_and_world_writable_directories_have_no_publication() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing");
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(matches!(
        UnitFiles::open(&missing, ID, &cancel, deadline()),
        Err(UnitFilesError::Cancelled)
    ));
    assert!(UnitFiles::open(&missing, ID, &Cancellation::default(), deadline()).is_err());
    assert!(!missing.exists());
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        UnitFiles::open(
            temp.path(),
            ID,
            &Cancellation::default(),
            deadline()
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn marker_size_inventory_and_temporary_budgets_fail_without_unit_mutation() {
    let (temp, p) = fixture();
    assert!(publish(&p, b"foreign", None).is_err());
    let mut oversized = FIRST.to_vec();
    oversized.resize(MAX_UNIT + 1, b' ');
    assert!(publish(&p, &oversized, None).is_err());
    for index in 0..64 {
        fs::write(
            temp.path()
                .join(format!(".syrox-os-{ID}.tmp.{index}")),
            b"evidence",
        )
        .unwrap();
    }
    assert!(publish(&p, FIRST, None).is_err());
    assert!(!temp.path().join(unit().as_str()).exists());
    for index in 0..64 {
        fs::remove_file(
            temp.path()
                .join(format!(".syrox-os-{ID}.tmp.{index}")),
        )
        .unwrap();
    }
    let mut ledger = p.load().unwrap();
    for index in 0_u64..MAX_UNITS as u64 {
        let hash = ContentDigest::sha256(&index.to_le_bytes());
        ledger
            .units
            .insert(format!("syrox-os-{ID}-{hash}.service"), hash);
    }
    p.save(&ledger).unwrap();
    assert!(publish(&p, FIRST, None).is_err());
    assert!(!temp.path().join(unit().as_str()).exists());
}

#[test]
fn moved_unit_directory_and_lost_ledger_never_reinitialize_ownership() {
    let (temp, p) = fixture();
    fs::remove_file(
        temp.path()
            .join(format!(".syrox-os-{ID}/ownership")),
    )
    .unwrap();
    assert!(
        UnitFiles::open(
            temp.path(),
            ID,
            &Cancellation::default(),
            deadline()
        )
        .is_err()
    );
    assert!(publish(&p, FIRST, None).is_err());
    let parent = tempfile::tempdir().unwrap();
    let original = parent.path().join("units");
    fs::create_dir(&original).unwrap();
    let p = reopen(&original);
    fs::rename(&original, parent.path().join("moved")).unwrap();
    fs::create_dir(&original).unwrap();
    assert!(publish(&p, FIRST, None).is_err());
    assert_eq!(fs::read_dir(original).unwrap().count(), 0);
}

fn named_unit(index: usize) -> SystemdUnitName {
    SystemdUnitName::new(format!(
        "syrox-os-{ID}-{}.service",
        ContentDigest::sha256(index.to_string().as_bytes())
    ))
    .unwrap()
}

#[test]
fn capacity_preflight_counts_retained_units_and_distinct_new_names_without_writes() {
    let (temp, publisher) = fixture();
    publish(&publisher, FIRST, None).unwrap();
    let ledger_path = temp
        .path()
        .join(format!(".syrox-os-{ID}/ownership"));
    let before = fs::read(&ledger_path).unwrap();
    let mut requested: Vec<_> = (0..MAX_UNITS - 1).map(named_unit).collect();
    requested.extend([unit(), unit()]);
    publisher
        .check_capacity(&requested, &Cancellation::default(), deadline())
        .unwrap();
    requested.push(named_unit(MAX_UNITS));
    let error = publisher
        .check_capacity(&requested, &Cancellation::default(), deadline())
        .unwrap_err();
    assert!(error.to_string().contains("capacity"));
    assert_eq!(fs::read(ledger_path).unwrap(), before);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    assert_eq!(
        fs::read(temp.path().join(unit().as_str())).unwrap(),
        FIRST
    );
}

#[test]
fn capacity_preflight_rejects_divergent_owned_and_unowned_files() {
    let (temp, publisher) = fixture();
    publish(&publisher, FIRST, None).unwrap();
    fs::write(temp.path().join(unit().as_str()), SECOND).unwrap();
    assert!(
        publisher
            .check_capacity(&[], &Cancellation::default(), deadline())
            .is_err()
    );
    fs::write(temp.path().join(unit().as_str()), FIRST).unwrap();
    let rogue = named_unit(42);
    fs::write(temp.path().join(rogue.as_str()), FIRST).unwrap();
    fs::set_permissions(
        temp.path().join(rogue.as_str()),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(
        publisher
            .check_capacity(
                std::slice::from_ref(&rogue),
                &Cancellation::default(),
                deadline()
            )
            .is_err()
    );
    assert_eq!(
        fs::read(temp.path().join(rogue.as_str())).unwrap(),
        FIRST
    );
    let foreign = SystemdUnitName::new("syrox-unrelated.service").unwrap();
    assert!(
        publisher
            .check_capacity(&[foreign], &Cancellation::default(), deadline())
            .is_err()
    );
}

#[test]
fn capacity_preflight_never_repairs_pending_publication_and_obeys_budgets() {
    let (temp, publisher) = fixture();
    FAIL_AT.with(|stage| stage.set(1));
    let result = publish(&publisher, FIRST, None);
    FAIL_AT.with(|stage| stage.set(0));
    assert!(result.is_err());
    let publisher = reopen(temp.path());
    let ledger_path = temp
        .path()
        .join(format!(".syrox-os-{ID}/ownership"));
    let before = fs::read(&ledger_path).unwrap();
    assert!(
        publisher
            .check_capacity(&[], &Cancellation::default(), deadline())
            .is_err()
    );
    assert_eq!(fs::read(ledger_path).unwrap(), before);
    assert!(!temp.path().join(unit().as_str()).exists());
    let (_clean, publisher) = fixture();
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(matches!(
        publisher.check_capacity(&[], &cancel, deadline()),
        Err(UnitFilesError::Cancelled)
    ));
    assert!(matches!(
        publisher.check_capacity(&[], &Cancellation::default(), Instant::now()),
        Err(UnitFilesError::Deadline)
    ));
}

#[test]
fn recovery_open_existing_never_initializes_missing_authority() {
    let directory = tempfile::tempdir().unwrap();
    let cancel = Cancellation::default();
    assert!(UnitFiles::open_existing(directory.path(), ID, &cancel, deadline()).is_err());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    let missing = directory.path().join("missing");
    assert!(UnitFiles::open_existing(&missing, ID, &cancel, deadline()).is_err());
    assert!(!missing.exists());
    let authority = directory.path().join(format!(".syrox-os-{ID}"));
    fs::create_dir(&authority).unwrap();
    fs::set_permissions(&authority, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(UnitFiles::open_existing(directory.path(), ID, &cancel, deadline()).is_err());
    assert_eq!(fs::read_dir(authority).unwrap().count(), 0);
}

#[test]
fn recovery_requires_exact_unit_previous_and_target_before_reconciling() {
    let (temp, publisher) = fixture();
    let previous = publish(&publisher, FIRST, None).unwrap();
    FAIL_AT.with(|stage| stage.set(2));
    let result = publish(&publisher, SECOND, Some(previous));
    FAIL_AT.with(|stage| stage.set(0));
    assert!(result.is_err());
    let cancel = Cancellation::default();
    let publisher = UnitFiles::open_existing(temp.path(), ID, &cancel, deadline()).unwrap();
    let ledger_path = temp
        .path()
        .join(format!(".syrox-os-{ID}/ownership"));
    let ledger_before = fs::read(&ledger_path).unwrap();
    let target = ContentDigest::sha256(SECOND);
    for (selected, expected, pin) in [
        (named_unit(12), Some(previous), target),
        (unit(), None, target),
        (
            unit(),
            Some(ContentDigest::sha256(b"wrong previous")),
            target,
        ),
        (
            unit(),
            Some(previous),
            ContentDigest::sha256(b"wrong target"),
        ),
    ] {
        assert!(
            publisher
                .reconcile_expected(&selected, expected, pin, &cancel, deadline())
                .is_err()
        );
        assert_eq!(fs::read(&ledger_path).unwrap(), ledger_before);
        assert_eq!(
            fs::read(temp.path().join(unit().as_str())).unwrap(),
            SECOND
        );
    }
    assert_eq!(
        publisher
            .reconcile_expected(
                &unit(),
                Some(previous),
                target,
                &cancel,
                deadline()
            )
            .unwrap(),
        UnitReconciliation::Published {
            unit: unit().as_str().into(),
            pin: target
        }
    );
    assert_eq!(
        publisher
            .observe(&unit(), &cancel, deadline())
            .unwrap(),
        Some(target)
    );
}

#[test]
fn recovery_without_pending_intent_does_not_adopt_matching_unowned_file() {
    let (temp, publisher) = fixture();
    let path = temp.path().join(unit().as_str());
    fs::write(&path, FIRST).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let ledger = temp
        .path()
        .join(format!(".syrox-os-{ID}/ownership"));
    let before = fs::read(&ledger).unwrap();
    let cancel = Cancellation::default();
    assert_eq!(
        publisher
            .reconcile_expected(
                &unit(),
                None,
                ContentDigest::sha256(FIRST),
                &cancel,
                deadline()
            )
            .unwrap(),
        UnitReconciliation::NoPending
    );
    assert!(
        publisher
            .observe(&unit(), &cancel, deadline())
            .is_err()
    );
    assert_eq!(fs::read(ledger).unwrap(), before);
    assert_eq!(fs::read(path).unwrap(), FIRST);
}

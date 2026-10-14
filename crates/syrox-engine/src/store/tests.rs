use std::fs;
use std::io::Cursor;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(std::path::PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "syrox-store-d-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn ingest(lease: &OperationLease, bytes: &[u8]) -> ContentDigest {
    let digest = ContentDigest::sha256(bytes);
    lease
        .ingest(Cursor::new(bytes), digest, bytes.len() as u64)
        .unwrap();
    digest
}

#[test]
fn open_existing_never_initializes_or_repairs_metadata() {
    let temp = TempDirectory::new();
    assert!(Store::open_existing(&temp.0).is_err());
    assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0);
    assert!(Store::open_existing(&temp.0.join("absent")).is_err());
    assert!(!temp.0.join("absent").exists());
    let store = Store::initialize(&temp.0).unwrap();
    drop(store);
    for name in [
        "objects/sha256/00",
        ".syrox-store/interests",
    ] {
        let path = temp.0.join(name);
        fs::remove_dir(&path).unwrap();
        assert!(Store::open_existing(&temp.0).is_err());
        assert!(!path.exists());
        fs::create_dir(&path).unwrap();
    }
    let lease = temp.0.join(".syrox-store/state/lease");
    fs::remove_file(&lease).unwrap();
    assert!(matches!(
        Store::open_existing(&temp.0),
        Err(StoreError::LeaseCorrupt)
    ));
    assert!(!lease.exists());
}

#[test]
fn open_existing_preserves_permanent_lease_and_operation_exclusion() {
    let temp = TempDirectory::new();
    let initialized = Store::initialize(&temp.0).unwrap();
    let operation = initialized.operation().unwrap();
    let digest = ingest(&operation, b"existing Store object");
    let opened = Store::open_existing(&temp.0).unwrap();
    assert_eq!(
        opened.inner.lease_identity,
        initialized.inner.lease_identity
    );
    assert!(matches!(
        opened.maintenance(),
        Err(StoreError::Busy)
    ));
    assert!(
        opened
            .operation()
            .unwrap()
            .verify(digest)
            .unwrap()
            .is_some()
    );
    drop(operation);
    assert!(opened.maintenance().is_ok());
    let lease = temp.0.join(".syrox-store/state/lease");
    fs::rename(&lease, lease.with_extension("previous")).unwrap();
    fs::write(&lease, b"").unwrap();
    assert!(matches!(
        opened.operation(),
        Err(StoreError::LeaseCorrupt)
    ));
}

#[test]
fn open_existing_rejects_symlinks_and_untrusted_metadata() {
    let temp = TempDirectory::new();
    let store = Store::initialize(&temp.0).unwrap();
    drop(store);
    let shard = temp.0.join("objects/sha256/00");
    fs::set_permissions(&shard, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        Store::open_existing(&temp.0),
        Err(StoreError::UntrustedDirectory)
    ));
    fs::set_permissions(&shard, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir(&shard).unwrap();
    symlink("01", &shard).unwrap();
    assert!(Store::open_existing(&temp.0).is_err());
    assert!(
        fs::symlink_metadata(&shard)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn published_build_roots_round_trip_beyond_legacy_reader_limits() {
    let temp = TempDirectory::new();
    let store = Store::initialize(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let mut digests = (0_u64..60)
        .map(|number| ingest(&lease, &number.to_le_bytes()))
        .collect::<Vec<_>>();
    digests.sort_unstable();
    for count in [45, 46, 60] {
        let name = RootName::new(format!("build_closure_{count}")).unwrap();
        let references = &digests[..count];
        lease.publish_root(&name, references).unwrap();
        assert_eq!(
            lease.build_references(&name).unwrap().unwrap(),
            references
        );
        assert_eq!(
            lease.publish_root(&name, references).unwrap(),
            RootPublicationState::Existing
        );
    }
}

#[test]
fn maximum_root_reference_count_round_trips_at_maximum_name_length() {
    let name = RootName::new("a".repeat(MAX_ROOT_NAME_BYTES)).unwrap();
    let mut digests = (0..MAX_ROOT_REFERENCES)
        .map(|number| ContentDigest::sha256(&number.to_le_bytes()))
        .collect::<Vec<_>>();
    digests.sort_unstable();
    let bytes = encode_root(&name, &digests).unwrap();
    assert!(bytes.len() as u64 <= MAX_ROOT_BYTES);
    assert_eq!(
        parse_root(&name, &bytes, MAX_ROOT_REFERENCES).unwrap(),
        digests
    );
    assert!(matches!(
        parse_root(&name, &bytes, MAX_ROOT_REFERENCES - 1),
        Err(StoreError::LimitExceeded {
            resource: "root references"
        })
    ));
}

#[test]
fn admission_cross_shard_publication_preserves_uncertainty_and_deduplication() {
    use crate::platform::linux::fd::{AtomicFault, fail_next_atomic};
    for fault in [
        AtomicFault::Rename,
        AtomicFault::DirectorySync,
        AtomicFault::SourceDirectorySync,
    ] {
        let temp = TempDirectory::new();
        let store = Store::initialize(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let bytes = b"newly admitted output";
        let digest = ContentDigest::sha256(bytes);
        assert!(!digest.to_string().starts_with("00"));
        let mut admission = lease.begin_admission(bytes.len() as u64).unwrap();
        admission.append(bytes).unwrap();
        assert!(lease.verify(digest).unwrap().is_none());
        fail_next_atomic(fault);
        let result = admission.finish();
        if fault == AtomicFault::Rename {
            assert!(matches!(result, Err(StoreError::Io(_))));
            assert!(lease.verify(digest).unwrap().is_none());
        } else {
            assert!(matches!(
                result,
                Err(StoreError::PublicationUncertain { .. })
            ));
            assert!(lease.verify(digest).unwrap().is_some());
        }
        let mut retry = lease.begin_admission(bytes.len() as u64).unwrap();
        retry.append(bytes).unwrap();
        assert_eq!(retry.finish().unwrap().digest(), digest);
        assert_eq!(
            lease
                .read_verified(digest, bytes.len() as u64)
                .unwrap()
                .unwrap()
                .as_bytes(),
            bytes
        );
    }
}

#[test]
fn incompatible_layout_is_rejected_before_creating_shards_or_leases() {
    for old in [
        "roots/v1",
        ".syrox-store/v1",
        ".syrox-store/actions-v1",
    ] {
        let temp = TempDirectory::new();
        fs::create_dir_all(temp.0.join(old)).unwrap();
        assert!(matches!(
            Store::initialize(&temp.0),
            Err(StoreError::UnsupportedLayout)
        ));
        assert!(!temp.0.join("objects").exists());
        assert!(!temp.0.join("roots/retained").exists());
        assert!(!temp.0.join(".syrox-store/state").exists());
    }
}

#[test]
fn concurrent_initialization_preserves_one_store_and_its_permanent_lease() {
    let temp = TempDirectory::new();
    let path = temp.0.join("data with spaces/syrox/store");
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || Store::initialize(&path).unwrap())
        })
        .collect();
    let stores: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    let identity = stores[0].inner.lease_identity;
    assert!(
        stores
            .iter()
            .all(|store| store.inner.lease_identity == identity)
    );
    let lease = stores[0].operation().unwrap();
    let digest = ingest(&lease, b"retained through reinitialization");
    lease
        .publish_root(&RootName::new("retained").unwrap(), &[digest])
        .unwrap();
    let reopened = Store::initialize(&path).unwrap();
    assert_eq!(reopened.inner.lease_identity, identity);
    assert!(
        reopened
            .operation()
            .unwrap()
            .verify(digest)
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        reopened.maintenance(),
        Err(StoreError::Busy)
    ));
}

#[test]
fn shared_leases_coexist_and_exclusive_is_nonblocking() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let first = store.operation().unwrap();
    let second = store.operation().unwrap();
    assert!(matches!(
        store.maintenance(),
        Err(StoreError::Busy)
    ));
    drop(first);
    assert!(matches!(
        store.maintenance(),
        Err(StoreError::Busy)
    ));
    drop(second);
    let maintenance = store.maintenance().unwrap();
    assert!(matches!(store.operation(), Err(StoreError::Busy)));
    drop(maintenance);
    assert!(store.operation().is_ok());
}

#[test]
#[allow(clippy::used_underscore_binding)] // Inspect the RAII-only maintenance guard.
fn inherited_descriptor_cannot_extend_a_released_store_lease() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let consumer = lease.clone();
    // dup and fork share the same open file description. Retain a duplicate
    // to deterministically model a child paused between fork and exec.
    let inherited = lease.lock.0.fd().try_clone_to_owned().unwrap();
    drop(lease);
    assert!(matches!(
        store.maintenance(),
        Err(StoreError::Busy)
    ));
    drop(consumer);
    let maintenance = store.maintenance().unwrap();
    let inherited_exclusive = maintenance
        ._lock
        .0
        .fd()
        .try_clone_to_owned()
        .unwrap();
    assert!(matches!(store.operation(), Err(StoreError::Busy)));
    drop(maintenance);
    assert!(store.operation().is_ok());
    drop((inherited, inherited_exclusive));
}

#[test]
fn lease_inode_is_permanent_and_staging_and_reader_retain_it() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lock = temp.0.join(".syrox-store/state/lease");
    let inode = fs::metadata(&lock).unwrap().ino();
    let lease = store.operation().unwrap();
    let digest = ingest(&lease, b"retained");
    let staging = lease
        .begin_staging(ContentDigest::sha256(b"staging"), 7)
        .unwrap();
    let reader = lease.open_verified(digest, 8).unwrap().unwrap();
    drop(lease);
    assert!(matches!(
        store.maintenance(),
        Err(StoreError::Busy)
    ));
    staging.abort().unwrap();
    assert!(matches!(
        store.maintenance(),
        Err(StoreError::Busy)
    ));
    drop(reader);
    assert!(store.maintenance().is_ok());
    assert_eq!(fs::metadata(lock).unwrap().ino(), inode);
}

#[test]
fn roots_are_canonical_immutable_and_require_verified_objects() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let first = ingest(&lease, b"first");
    let second = ingest(&lease, b"second");
    let mut sorted = vec![first, second];
    sorted.sort();
    let name = RootName::new("release_1").unwrap();
    assert_eq!(
        lease.publish_root(&name, &sorted).unwrap(),
        RootPublicationState::Published
    );
    assert_eq!(
        lease.publish_root(&name, &sorted).unwrap(),
        RootPublicationState::Existing
    );
    assert!(matches!(
        lease.publish_root(&name, &sorted[..1]),
        Err(StoreError::RootConflict { .. })
    ));
    assert!(matches!(
        lease.publish_root(
            &RootName::new("missing").unwrap(),
            &[ContentDigest::sha256(b"absent")]
        ),
        Err(StoreError::MissingRootObject { .. })
    ));
    assert!(RootName::new("bad order").is_err());

    let corrupt = ingest(&lease, b"will corrupt");
    fs::write(
        temp.0
            .join("objects/sha256")
            .join(&corrupt.to_string()[..2])
            .join(corrupt.to_string()),
        b"changed",
    )
    .unwrap();
    assert!(matches!(
        lease.publish_root(&RootName::new("corrupt").unwrap(), &[corrupt]),
        Err(StoreError::CorruptObject { .. })
    ));

    fs::write(
        temp.0.join("roots/retained/release_1"),
        b"malformed\n",
    )
    .unwrap();
    assert!(matches!(
        lease.publish_root(&name, &sorted),
        Err(StoreError::CorruptRoot { .. })
    ));
}

#[test]
fn cancellation_during_root_verification_prevents_any_publication() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let digest = ingest(&lease, &vec![b'x'; 256 * 1024]);
    let root = RootName::new("cancelled_generation").unwrap();
    let mut checks = 0;
    let result = lease.publish_root_checked(&root, &[digest], || {
        checks += 1;
        if checks == 3 {
            Err(crate::cancellation::cancellation_io())
        } else {
            Ok(())
        }
    });
    assert!(
        matches!(result, Err(StoreError::Io(ref error)) if crate::cancellation::is_cancellation_io(error))
    );
    assert!(lease.build_references(&root).unwrap().is_none());
    assert_eq!(
        fs::read_dir(temp.0.join("roots/retained"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        lease.publish_root(&root, &[digest]).unwrap(),
        RootPublicationState::Published
    );
}

#[test]
fn empty_roots_and_owned_bytes_are_valid() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let name = RootName::new("empty").unwrap();
    lease.publish_root(&name, &[]).unwrap();
    let digest = ingest(&lease, b"owned");
    let bytes = lease.read_verified(digest, 5).unwrap().unwrap();
    drop(lease);
    assert_eq!(bytes.into_bytes(), b"owned");
}

#[test]
fn gc_dry_run_retains_everything_and_collect_obeys_roots() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let live = ingest(&lease, b"live");
    let dead = ingest(&lease, b"dead");
    let root = RootName::new("keep").unwrap();
    lease.publish_root(&root, &[live]).unwrap();
    drop(lease);
    let mut maintenance = store.maintenance().unwrap();
    let dry = maintenance
        .garbage_collect(&GcRequest::default())
        .unwrap();
    assert_eq!(
        dry.candidates,
        vec![GcCandidate {
            digest: dead,
            bytes: 4
        }]
    );
    drop(maintenance);
    assert!(
        store
            .operation()
            .unwrap()
            .verify(dead)
            .unwrap()
            .is_some()
    );
    let mut maintenance = store.maintenance().unwrap();
    let report = maintenance
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert_eq!(report.removed_objects, [dead]);
    drop(maintenance);
    let lease = store.operation().unwrap();
    assert!(lease.verify(live).unwrap().is_some());
    assert!(lease.verify(dead).unwrap().is_none());
}

#[test]
fn collect_removes_requested_root_before_sweeping() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let digest = ingest(&lease, b"only root");
    let root = RootName::new("remove_me").unwrap();
    lease.publish_root(&root, &[digest]).unwrap();
    drop(lease);
    let mut maintenance = store.maintenance().unwrap();
    let report = maintenance
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![root.clone()],
            ..GcRequest::default()
        })
        .unwrap();
    assert_eq!(report.removed_roots, [root]);
    assert_eq!(report.removed_objects, [digest]);
}

#[test]
fn malformed_inventory_causes_zero_deletes() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let dead = ingest(&lease, b"dead");
    drop(lease);
    fs::write(
        temp.0.join("objects/sha256/00/not-an-object"),
        b"bad",
    )
    .unwrap();
    let mut maintenance = store.maintenance().unwrap();
    assert!(matches!(
        maintenance.garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        }),
        Err(StoreError::UnexpectedEntry { .. })
    ));
    drop(maintenance);
    assert!(
        store
            .operation()
            .unwrap()
            .verify(dead)
            .unwrap()
            .is_some()
    );
}

#[test]
fn recovery_only_accepts_exact_temporary_names() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let exact = format!("{OBJECT_TEMP_PREFIX}{}", "a".repeat(32));
    fs::write(
        temp.0.join("objects/sha256/00").join(&exact),
        b"temporary",
    )
    .unwrap();
    let root_exact = format!("{ROOT_TEMP_PREFIX}{}", "b".repeat(32));
    fs::write(
        temp.0.join("roots/retained").join(root_exact),
        b"temporary",
    )
    .unwrap();
    let mut maintenance = store.maintenance().unwrap();
    let report = maintenance
        .recover(RecoveryLimits::default())
        .unwrap();
    assert_eq!(report.removed.len(), 2);
    drop(maintenance);
    fs::write(
        temp.0
            .join("objects/sha256/00/.syrox-store.tmp.lookalike"),
        b"bad",
    )
    .unwrap();
    let mut maintenance = store.maintenance().unwrap();
    assert!(matches!(
        maintenance.recover(RecoveryLimits::default()),
        Err(StoreError::UnexpectedEntry { .. })
    ));
}

#[test]
fn maintenance_limits_are_hard_and_charged_before_growth() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let digest = ingest(&lease, b"one");
    drop(lease);
    let mut maintenance = store.maintenance().unwrap();
    let limits = GcLimits {
        objects: 0,
        ..GcLimits::default()
    };
    assert!(matches!(
        maintenance.garbage_collect(&GcRequest {
            limits,
            ..GcRequest::default()
        }),
        Err(StoreError::LimitExceeded {
            resource: "GC objects"
        })
    ));
    let limits = GcLimits {
        objects: MAX_GC_OBJECTS + 1,
        ..GcLimits::default()
    };
    assert!(matches!(
        maintenance.garbage_collect(&GcRequest {
            limits,
            ..GcRequest::default()
        }),
        Err(StoreError::InvalidMaintenanceLimit {
            resource: "GC objects"
        })
    ));
    assert!(matches!(
        maintenance.recover(RecoveryLimits {
            entries: MAX_RECOVERY_ENTRIES + 1,
            ..RecoveryLimits::default()
        }),
        Err(StoreError::InvalidMaintenanceLimit {
            resource: "recovery entries"
        })
    ));
    let limits = GcLimits {
        work: 263,
        ..GcLimits::default()
    };
    assert!(matches!(
        maintenance.garbage_collect(&GcRequest {
            collect: true,
            limits,
            ..GcRequest::default()
        }),
        Err(StoreError::LimitExceeded {
            resource: "GC work"
        })
    ));
    drop(maintenance);
    assert!(
        store
            .operation()
            .unwrap()
            .verify(digest)
            .unwrap()
            .is_some()
    );

    let recovery_temp = TempDirectory::new();
    let recovery_store = Store::open(&recovery_temp.0).unwrap();
    let temporary = recovery_temp
        .0
        .join("objects/sha256/00")
        .join(format!("{OBJECT_TEMP_PREFIX}{}", "d".repeat(32)));
    fs::write(&temporary, b"temporary").unwrap();
    let mut maintenance = recovery_store.maintenance().unwrap();
    assert!(matches!(
        maintenance.recover(RecoveryLimits {
            work: 263,
            ..RecoveryLimits::default()
        }),
        Err(StoreError::LimitExceeded {
            resource: "recovery work"
        })
    ));
    assert!(temporary.exists());
}

#[test]
fn corrupt_root_and_object_are_rejected_before_gc_mutation() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let digest = ingest(&lease, b"data");
    let root = RootName::new("root").unwrap();
    lease.publish_root(&root, &[digest]).unwrap();
    drop(lease);
    fs::write(
        temp.0.join("roots/retained/root"),
        b"not canonical\n",
    )
    .unwrap();
    let mut maintenance = store.maintenance().unwrap();
    assert!(matches!(
        maintenance.garbage_collect(&GcRequest::default()),
        Err(StoreError::CorruptRoot { .. })
    ));
    drop(maintenance);
    fs::set_permissions(
        temp.0.join("roots/retained/root"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}

#[test]
fn digest_text_is_strict_lowercase_sha256() {
    let digest = ContentDigest::sha256(b"abc");
    let text = digest.to_string();
    assert_eq!(text.len(), 64);
    assert_eq!(text.parse::<ContentDigest>().unwrap(), digest);
    assert!(
        text.to_uppercase()
            .parse::<ContentDigest>()
            .is_err()
    );
    assert!(text[..63].parse::<ContentDigest>().is_err());
}

#[test]
fn staging_is_private_bounded_and_failed_state_is_terminal() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let bytes = b"two chunks";
    let digest = ContentDigest::sha256(bytes);
    let mut staging = lease
        .begin_staging(digest, bytes.len() as u64)
        .unwrap();
    staging.append(b"two ").unwrap();
    staging.append(b"chunks").unwrap();
    assert_eq!(lease.verify(digest).unwrap(), None);
    assert_eq!(
        staging.finish().unwrap().state(),
        StoreObjectState::Published
    );

    let empty = ContentDigest::sha256(b"");
    assert_eq!(
        lease
            .begin_staging(empty, 0)
            .unwrap()
            .finish()
            .unwrap()
            .size(),
        0
    );
    let over = ContentDigest::sha256(b"five!");
    let mut staging = lease.begin_staging(over, 4).unwrap();
    assert!(matches!(
        staging.append(b"five!"),
        Err(StoreError::BlobTooLarge {
            limit: 4
        })
    ));
    assert!(matches!(
        staging.append(b"x"),
        Err(StoreError::StagingFailed)
    ));
    assert!(matches!(
        staging.finish(),
        Err(StoreError::StagingFailed)
    ));

    let aborted = ContentDigest::sha256(b"abort");
    let mut staging = lease.begin_staging(aborted, 5).unwrap();
    staging.append(b"abort").unwrap();
    staging.abort().unwrap();
    assert_eq!(lease.verify(aborted).unwrap(), None);
}

#[test]
fn mismatch_and_transport_failure_clean_up_or_preserve_both_errors() {
    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("transport failed"))
        }
    }

    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let expected = ContentDigest::sha256(b"expected");
    assert!(matches!(
        lease.ingest(Cursor::new(b"different"), expected, 32),
        Err(StoreError::DigestMismatch { .. })
    ));
    assert_eq!(lease.verify(expected).unwrap(), None);

    crate::platform::linux::fd::fail_next_atomic(
        crate::platform::linux::fd::AtomicFault::CleanupUnlink,
    );
    let error = lease
        .ingest(FailingReader, expected, 32)
        .unwrap_err();
    assert!(matches!(
        error,
        StoreError::CleanupFailed {
            primary,
            cleanup: StoreCleanupError::Removal { .. }
        } if matches!(*primary, StoreError::Io(_))
    ));
}

#[test]
fn verified_reads_reject_corrupt_oversized_and_unsafe_objects() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let digest = ingest(&lease, b"limit");
    assert!(matches!(
        lease.read_verified(digest, 4),
        Err(StoreError::CorruptObjectTooLarge { .. })
    ));
    let object = temp
        .0
        .join("objects/sha256")
        .join(&digest.to_string()[..2])
        .join(digest.to_string());
    fs::write(&object, b"wrong").unwrap();
    assert!(matches!(
        lease.verify(digest),
        Err(StoreError::CorruptObject { .. })
    ));

    let hard_temp = TempDirectory::new();
    let hard_store = Store::open(&hard_temp.0).unwrap();
    let hard_lease = hard_store.operation().unwrap();
    let hard = ingest(&hard_lease, b"hard");
    let hard_path = hard_temp
        .0
        .join("objects/sha256")
        .join(&hard.to_string()[..2])
        .join(hard.to_string());
    fs::hard_link(&hard_path, hard_temp.0.join("extra")).unwrap();
    assert!(matches!(
        hard_lease.verify(hard),
        Err(StoreError::UnsafeObject { .. })
    ));

    let mode_temp = TempDirectory::new();
    let mode_store = Store::open(&mode_temp.0).unwrap();
    let mode_lease = mode_store.operation().unwrap();
    let mode = ingest(&mode_lease, b"mode");
    let mode_path = mode_temp
        .0
        .join("objects/sha256")
        .join(&mode.to_string()[..2])
        .join(mode.to_string());
    fs::set_permissions(&mode_path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(
        mode_lease.verify(mode),
        Err(StoreError::UnsafeObject { .. })
    ));

    let link_temp = TempDirectory::new();
    let link_store = Store::open(&link_temp.0).unwrap();
    let link_lease = link_store.operation().unwrap();
    let link = ingest(&link_lease, b"link");
    let link_path = link_temp
        .0
        .join("objects/sha256")
        .join(&link.to_string()[..2])
        .join(link.to_string());
    fs::remove_file(&link_path).unwrap();
    symlink("elsewhere", link_path).unwrap();
    assert!(matches!(
        link_lease.verify(link),
        Err(StoreError::SymbolicLink)
    ));
}

#[test]
fn concurrent_identical_writers_converge() {
    let temp = TempDirectory::new();
    let store = Arc::new(Store::open(&temp.0).unwrap());
    let bytes = b"one immutable object";
    let digest = ContentDigest::sha256(bytes);
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                store
                    .operation()
                    .unwrap()
                    .ingest(Cursor::new(bytes), digest, 1024)
                    .unwrap()
            })
        })
        .collect();
    for thread in threads {
        assert_eq!(thread.join().unwrap().digest(), digest);
    }
    let shard = temp
        .0
        .join("objects/sha256")
        .join(&digest.to_string()[..2]);
    assert_eq!(fs::read_dir(shard).unwrap().count(), 1);
}

#[test]
fn verified_reader_retains_the_rehashed_inode_after_path_replacement() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let bytes = b"retained inode";
    let digest = ingest(&lease, bytes);
    let mut reader = lease.open_verified(digest, 64).unwrap().unwrap();
    let object = temp
        .0
        .join("objects/sha256")
        .join(&digest.to_string()[..2])
        .join(digest.to_string());
    fs::remove_file(&object).unwrap();
    fs::write(object, b"replacement").unwrap();
    let mut actual = Vec::new();
    reader.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, bytes);
}

#[test]
fn separately_opened_verified_readers_have_independent_cursors() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let bytes = b"independent verified cursors";
    let digest = ingest(&lease, bytes);
    let mut first = lease.open_verified(digest, 64).unwrap().unwrap();
    let mut second = lease.open_verified(digest, 64).unwrap().unwrap();
    let mut prefix = [0_u8; 12];
    first.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, &bytes[..12]);
    second.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, &bytes[..12]);
    let mut remaining = Vec::new();
    first.read_to_end(&mut remaining).unwrap();
    assert_eq!(remaining, &bytes[12..]);
}

#[test]
#[ignore = "explicit bounded Store read profiling; reads 32 MiB three times"]
fn read_verified_profile_one_pass() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let bytes = (0_usize..32 * 1024 * 1024)
        .map(|index| u8::try_from(index % 251).expect("remainder is a byte"))
        .collect::<Vec<_>>();
    let digest = ContentDigest::sha256(&bytes);
    lease
        .ingest(bytes.as_slice(), digest, bytes.len() as u64)
        .unwrap();
    let before = fs::read_to_string("/proc/self/io").unwrap();
    let start = std::time::Instant::now();
    for _ in 0..3 {
        let result = lease
            .read_verified(digest, bytes.len() as u64)
            .unwrap()
            .unwrap();
        assert_eq!(result.as_bytes(), bytes);
    }
    let elapsed = start.elapsed();
    let after = fs::read_to_string("/proc/self/io").unwrap();
    let counter = |input: &str, key: &str| -> u64 {
        input
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    };
    eprintln!(
        "store_read_3x_elapsed={elapsed:?} rchar={} syscr={} read_bytes={}",
        counter(&after, "rchar:") - counter(&before, "rchar:"),
        counter(&after, "syscr:") - counter(&before, "syscr:"),
        counter(&after, "read_bytes:") - counter(&before, "read_bytes:")
    );
}

#[test]
fn atomic_faults_preserve_commit_and_cleanup_boundaries() {
    use crate::platform::linux::fd::AtomicFault;

    let bytes = b"fault boundary";
    let digest = ContentDigest::sha256(bytes);
    for fault in [
        AtomicFault::FileSync,
        AtomicFault::TemporaryReopen,
        AtomicFault::Rename,
    ] {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let mut staging = lease
            .begin_staging(digest, bytes.len() as u64)
            .unwrap();
        staging.append(bytes).unwrap();
        crate::platform::linux::fd::fail_next_atomic(fault);
        assert!(matches!(staging.finish(), Err(StoreError::Io(_))));
        assert_eq!(lease.verify(digest).unwrap(), None);
    }
    for fault in [
        AtomicFault::PublishedReopen,
        AtomicFault::DirectorySync,
    ] {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let mut staging = lease
            .begin_staging(digest, bytes.len() as u64)
            .unwrap();
        staging.append(bytes).unwrap();
        crate::platform::linux::fd::fail_next_atomic(fault);
        assert!(matches!(
            staging.finish(),
            Err(StoreError::PublicationUncertain { .. })
        ));
        assert!(lease.verify(digest).unwrap().is_some());
    }
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let mut staging = lease
        .begin_staging(digest, bytes.len() as u64)
        .unwrap();
    crate::platform::linux::fd::fail_next_atomic(AtomicFault::Write);
    assert!(matches!(
        staging.append(bytes),
        Err(StoreError::Io(_))
    ));
    assert!(matches!(
        staging.finish(),
        Err(StoreError::StagingFailed)
    ));

    let staging = lease
        .begin_staging(digest, bytes.len() as u64)
        .unwrap();
    crate::platform::linux::fd::fail_next_atomic(AtomicFault::CleanupUnlink);
    crate::platform::linux::fd::fail_next_atomic(AtomicFault::CleanupSync);
    assert!(matches!(
        staging.abort(),
        Err(StoreError::CleanupUncertain {
            cleanup: StoreCleanupError::RemovalAndSynchronization { .. }
        })
    ));
}

#[test]
fn missing_or_replaced_lease_inode_is_corruption_and_never_recreated() {
    let missing_temp = TempDirectory::new();
    let missing_store = Store::open(&missing_temp.0).unwrap();
    let missing = missing_temp.0.join(".syrox-store/state/lease");
    let original = fs::metadata(&missing).unwrap().ino();
    fs::remove_file(&missing).unwrap();
    assert!(matches!(
        missing_store.operation(),
        Err(StoreError::LeaseCorrupt)
    ));
    assert!(!missing.exists());
    assert!(matches!(
        Store::open(&missing_temp.0),
        Err(StoreError::LeaseCorrupt)
    ));
    assert!(!missing.exists());

    let replaced_temp = TempDirectory::new();
    let replaced_store = Store::open(&replaced_temp.0).unwrap();
    let replaced = replaced_temp.0.join(".syrox-store/state/lease");
    let replaced_original = fs::metadata(&replaced).unwrap().ino();
    fs::remove_file(&replaced).unwrap();
    fs::write(&replaced, b"replacement").unwrap();
    assert_ne!(
        fs::metadata(&replaced).unwrap().ino(),
        replaced_original
    );
    assert!(matches!(
        replaced_store.maintenance(),
        Err(StoreError::LeaseCorrupt)
    ));
    assert_eq!(fs::metadata(&replaced).unwrap().len(), 11);
    assert_ne!(original, 0);
}

#[test]
fn simultaneous_first_open_converges_on_one_lease_inode() {
    let temp = Arc::new(TempDirectory::new());
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let temp = Arc::clone(&temp);
            std::thread::spawn(move || Store::open(&temp.0).unwrap())
        })
        .collect();
    let stores: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    let inode = fs::metadata(temp.0.join(".syrox-store/state/lease"))
        .unwrap()
        .ino();
    assert!(
        stores.iter().all(|store| {
            store.inner.lease_identity.inode == inode && store.operation().is_ok()
        })
    );
}

#[test]
fn recovery_validates_unsafe_later_object_before_any_delete() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let temporary = format!("{OBJECT_TEMP_PREFIX}{}", "a".repeat(32));
    let temporary_path = temp.0.join("objects/sha256/00").join(&temporary);
    fs::write(&temporary_path, b"temporary").unwrap();
    let digest = (0_u64..10_000)
        .map(|value| ContentDigest::sha256(value.to_string().as_bytes()))
        .find(|digest| digest.to_string().starts_with("ff"))
        .unwrap();
    let unsafe_path = temp
        .0
        .join("objects/sha256/ff")
        .join(digest.to_string());
    fs::write(&unsafe_path, b"unsafe").unwrap();
    fs::hard_link(&unsafe_path, temp.0.join("extra-link")).unwrap();
    let mut maintenance = store.maintenance().unwrap();
    assert!(matches!(
        maintenance.recover(RecoveryLimits::default()),
        Err(StoreError::UnsafeObject { .. })
    ));
    assert!(temporary_path.exists());
}

#[test]
fn maintenance_reports_partial_unlink_and_sync_failures() {
    let unlink_temp = TempDirectory::new();
    let unlink_store = Store::open(&unlink_temp.0).unwrap();
    for suffix in ["a", "b"] {
        fs::write(
            unlink_temp
                .0
                .join("objects/sha256/00")
                .join(format!(
                    "{OBJECT_TEMP_PREFIX}{}",
                    suffix.repeat(32)
                )),
            b"temporary",
        )
        .unwrap();
    }
    let mut maintenance = unlink_store.maintenance().unwrap();
    crate::platform::linux::fd::fail_next_maintenance_unlink();
    let report = maintenance
        .recover(RecoveryLimits::default())
        .unwrap();
    assert_eq!(report.removed.len(), 1);
    assert_eq!(report.failures.len(), 1);
    assert!(report.uncertain);

    let sync_temp = TempDirectory::new();
    let sync_store = Store::open(&sync_temp.0).unwrap();
    fs::write(
        sync_temp
            .0
            .join("roots/retained")
            .join(format!("{ROOT_TEMP_PREFIX}{}", "c".repeat(32))),
        b"temporary",
    )
    .unwrap();
    let mut maintenance = sync_store.maintenance().unwrap();
    crate::platform::linux::fd::fail_next_maintenance_sync();
    let report = maintenance
        .recover(RecoveryLimits::default())
        .unwrap();
    assert_eq!(report.removed.len(), 1);
    assert!(matches!(
        report.failures.as_slice(),
        [MaintenanceFailure {
            operation: MaintenanceFailureOperation::Synchronize,
            ..
        }]
    ));
    assert!(report.uncertain);
}

#[test]
fn gc_sync_failure_preserves_removed_objects_in_partial_report() {
    let temp = TempDirectory::new();
    let store = Store::open(&temp.0).unwrap();
    let lease = store.operation().unwrap();
    let digest = ingest(&lease, b"unrooted");
    drop(lease);
    let mut maintenance = store.maintenance().unwrap();
    crate::platform::linux::fd::fail_next_maintenance_sync();
    let report = maintenance
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert_eq!(report.removed_objects, [digest]);
    assert!(matches!(
        report.failures.as_slice(),
        [MaintenanceFailure {
            operation: MaintenanceFailureOperation::Synchronize,
            ..
        }]
    ));
    assert!(report.uncertain);
}

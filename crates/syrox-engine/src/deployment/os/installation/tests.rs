use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::time::Duration;

const WORKER: &[u8] = b"candidate launcher fixture";
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn private() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

#[test]
fn execution_guard_serializes_operators_without_blocking_worker_journal() {
    use crate::deployment::os::activation::ActivationJournal;
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let guard = installation
        .execution(&cancel, deadline())
        .unwrap();
    let other = GenerationInstallation::open_existing(path.path(), &cancel, deadline()).unwrap();
    assert!(matches!(
        other.execution(
            &cancel,
            Instant::now() + Duration::from_millis(30)
        ),
        Err(InstallationError::Deadline)
    ));
    // Workers take authority.lock, not execution.lock. Journal reads and writes
    // remain available while the operator retains the independent guard.
    let journal = ActivationJournal::open_existing(path.path(), &cancel, deadline()).unwrap();
    let snapshot = journal.snapshot(&cancel, deadline()).unwrap();
    assert_eq!(snapshot.installation, installation.id());
    let epoch = crate::deployment::os::activation::ExecutionEpoch {
        boot: crate::platform::linux::boot::BootId::parse("11111111-1111-4111-8111-111111111111")
            .unwrap(),
        manager: "fixture-manager".into(),
        scope: "fixture-scope".into(),
    };
    journal
        .begin_test_pin(
            ContentDigest::sha256(b"candidate"),
            None,
            epoch,
            &cancel,
            deadline(),
        )
        .unwrap();
    drop(guard);
    assert!(other.execution(&cancel, deadline()).is_ok());
}

#[test]
fn execution_wait_observes_cancellation_and_does_not_acquire_late() {
    let path = private();
    let initial = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &initial, deadline()).unwrap();
    let _guard = installation
        .execution(&initial, deadline())
        .unwrap();
    let other = GenerationInstallation::open_existing(path.path(), &initial, deadline()).unwrap();
    let cancel = Cancellation::default();
    let signal = cancel.clone();
    let (waiting, observed) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            storage::signal_lock_wait(waiting);
            other.execution(&cancel, deadline())
        });
        observed
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        signal.cancel();
        assert!(matches!(
            waiter.join().unwrap(),
            Err(InstallationError::Cancelled)
        ));
    });
}

#[test]
fn execution_lock_revalidates_replacement_after_waiting_on_original_inode() {
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let other = GenerationInstallation::open_existing(path.path(), &cancel, deadline()).unwrap();
    let guard = installation
        .execution(&cancel, deadline())
        .unwrap();
    let (waiting, observed) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            storage::signal_lock_wait(waiting);
            other.execution(&cancel, deadline())
        });
        observed
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        fs::rename(
            path.path().join("execution.lock"),
            path.path().join("previous.lock"),
        )
        .unwrap();
        fs::write(path.path().join("execution.lock"), b"replacement").unwrap();
        fs::set_permissions(
            path.path().join("execution.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        drop(guard);
        assert!(matches!(
            waiter.join().unwrap(),
            Err(InstallationError::Invalid(_))
        ));
    });
    assert_eq!(
        fs::read(path.path().join("execution.lock")).unwrap(),
        b"replacement"
    );
}

#[test]
fn missing_execution_authority_is_never_reinitialized() {
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let execution = path.path().join("execution.lock");
    let bytes = fs::read(path.path().join("installation")).unwrap();
    assert_eq!(
        fs::metadata(&execution)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    fs::remove_file(&execution).unwrap();
    assert!(GenerationInstallation::initialize(path.path(), &cancel, deadline()).is_err());
    assert!(GenerationInstallation::open_existing(path.path(), &cancel, deadline()).is_err());
    assert!(
        installation
            .execution(&cancel, deadline())
            .is_err()
    );
    assert!(!execution.exists());
    assert_eq!(
        fs::read(path.path().join("installation")).unwrap(),
        bytes
    );
}

#[test]
fn identified_installation_does_not_repair_other_missing_authority_structures() {
    for name in ["authority.lock", "generations"] {
        let path = private();
        let cancel = Cancellation::default();
        let installation =
            GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
        let selected = path.path().join(name);
        if name == "generations" {
            fs::remove_dir(&selected).unwrap();
        } else {
            fs::remove_file(&selected).unwrap();
        }
        assert!(GenerationInstallation::initialize(path.path(), &cancel, deadline()).is_err());
        assert!(
            installation
                .execution(&cancel, deadline())
                .is_err()
        );
        assert!(!selected.exists());
    }
}

#[test]
fn replaced_execution_lock_and_installation_are_rejected_without_touching_replacements() {
    let parent = private();
    let path = parent.path().join("install");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let cancel = Cancellation::default();
    let installation = GenerationInstallation::initialize(&path, &cancel, deadline()).unwrap();
    let guard = installation
        .execution(&cancel, deadline())
        .unwrap();
    fs::rename(
        path.join("execution.lock"),
        path.join("old-execution.lock"),
    )
    .unwrap();
    fs::write(path.join("execution.lock"), b"replacement").unwrap();
    fs::set_permissions(
        path.join("execution.lock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    drop(guard);
    assert!(
        installation
            .execution(&cancel, deadline())
            .is_err()
    );
    assert_eq!(
        fs::read(path.join("execution.lock")).unwrap(),
        b"replacement"
    );
    fs::rename(&path, parent.path().join("original")).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        installation
            .execution(&cancel, deadline())
            .is_err()
    );
    assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
}
fn generation() -> (
    tempfile::TempDir,
    PreparedGeneration,
    Store,
    std::path::PathBuf,
) {
    let (temp, consumer) =
        crate::deployment::manifest::tests::prepared_service_payload_fixture_kind(
            &crate::runtime::tests::elf(2, None, &[], None, None),
            "",
            "Os",
        );
    let worker = temp.path().join("candidate-worker");
    fs::write(&worker, WORKER).unwrap();
    let generation = PreparedGeneration::freeze(
        consumer,
        super::super::LauncherIdentity::new(ContentDigest::sha256(WORKER), 1).unwrap(),
    )
    .unwrap();
    let store = Store::open(&temp.path().join("store")).unwrap();
    (temp, generation, store, worker)
}

#[test]
fn prepared_generation_reopens_without_project_or_worker_and_survives_gc() {
    let (temp, generation, store, worker) = generation();
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let opened = installation
        .prepare(&generation, &store, &worker, &cancel, deadline())
        .unwrap();
    let pin = opened.digest();
    assert_eq!(
        opened.canonical_bytes(),
        generation.canonical_bytes()
    );
    assert_eq!(opened.outputs().len(), 1);
    assert_eq!(opened.commands().len(), 1);
    let roots: Vec<_> = opened
        .retained_outputs()
        .values()
        .map(|output| output.root.clone())
        .collect();
    let id = installation.id().to_owned();
    let junk = ContentDigest::sha256(b"unretained junk");
    store
        .operation()
        .unwrap()
        .ingest(b"unretained junk".as_slice(), junk, 1024)
        .unwrap();
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert!(
        store
            .operation()
            .unwrap()
            .read_verified(junk, 1024)
            .unwrap()
            .is_none()
    );
    drop((opened, generation, installation));
    fs::remove_file(temp.path().join("main.srx")).unwrap();
    fs::remove_file(worker).unwrap();
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    let installation =
        GenerationInstallation::open_existing(path.path(), &cancel, deadline()).unwrap();
    assert_eq!(installation.id(), id);
    let reopened = installation
        .open(&store, pin, &cancel, deadline())
        .unwrap();
    assert_eq!(
        reopened
            .retained_outputs()
            .values()
            .map(|output| output.root.clone())
            .collect::<Vec<_>>(),
        roots
    );
    assert_eq!(
        reopened.manifest().configs["probe/nested/config"].text,
        "controlled"
    );
    assert_eq!(
        installation.list(&cancel, deadline()).unwrap()[0]
            .phase
            .as_ref()
            .unwrap(),
        &CandidatePhase::Prepared
    );
}

#[test]
fn repeated_preparation_is_idempotent_and_another_store_is_rejected() {
    let (_temp, generation, store, worker) = generation();
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let first = installation
        .prepare(&generation, &store, &worker, &cancel, deadline())
        .unwrap();
    let second = installation
        .prepare(&generation, &store, &worker, &cancel, deadline())
        .unwrap();
    assert_eq!(
        first.retained_outputs(),
        second.retained_outputs()
    );
    assert_eq!(
        installation
            .list(&cancel, deadline())
            .unwrap()
            .len(),
        1
    );
    let other = private();
    let foreign = Store::open(other.path()).unwrap();
    assert!(matches!(
        installation.prepare(
            &generation,
            &foreign,
            &worker,
            &cancel,
            deadline()
        ),
        Err(InstallationError::Invalid(
            "output belongs to another Store"
        ))
    ));
    assert!(
        installation
            .open(&foreign, first.digest(), &cancel, deadline())
            .is_err()
    );
}

#[test]
fn metadata_root_conflict_preserves_preparing_state_and_already_retained_outputs() {
    let (_temp, generation, store, worker) = generation();
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let pin = generation.digest();
    let operation = store.operation().unwrap();
    let junk = ContentDigest::sha256(b"foreign root");
    operation
        .ingest(b"foreign root".as_slice(), junk, 1024)
        .unwrap();
    let root = metadata_root(installation.id(), pin).unwrap();
    operation.publish_root(&root, &[junk]).unwrap();
    drop(operation);
    assert!(
        installation
            .prepare(&generation, &store, &worker, &cancel, deadline())
            .is_err()
    );
    assert_eq!(
        installation.list(&cancel, deadline()).unwrap()[0]
            .phase
            .as_ref()
            .unwrap(),
        &CandidatePhase::Preparing
    );
    assert!(
        installation
            .open(&store, pin, &cancel, deadline())
            .is_err()
    );
    for key in generation.manifest().outputs.keys() {
        assert!(
            store
                .operation()
                .unwrap()
                .build_references(&output_root(installation.id(), pin, key).unwrap())
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(
        store
            .operation()
            .unwrap()
            .build_references(&root)
            .unwrap(),
        Some(vec![junk])
    );
}

#[test]
fn cancellation_and_readonly_open_do_not_initialize_installations() {
    let path = private();
    let cancel = Cancellation::default();
    assert!(GenerationInstallation::open_existing(path.path(), &cancel, deadline()).is_err());
    assert_eq!(fs::read_dir(path.path()).unwrap().count(), 0);
    cancel.cancel();
    assert!(matches!(
        GenerationInstallation::initialize(path.path(), &cancel, deadline()),
        Err(InstallationError::Cancelled)
    ));
    assert_eq!(fs::read_dir(path.path()).unwrap().count(), 0);
}

#[test]
fn wrong_launcher_and_uncertain_publication_never_mark_candidate_prepared() {
    let (_temp, generation, store, worker) = generation();
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    fs::write(&worker, b"replaced candidate").unwrap();
    assert!(
        installation
            .prepare(&generation, &store, &worker, &cancel, deadline())
            .is_err()
    );
    assert_eq!(
        installation.list(&cancel, deadline()).unwrap()[0]
            .phase
            .as_ref()
            .unwrap(),
        &CandidatePhase::Preparing
    );
    fs::write(&worker, WORKER).unwrap();
    crate::platform::linux::fd::fail_next_lock_after_rename();
    assert!(matches!(
        installation.prepare(&generation, &store, &worker, &cancel, deadline()),
        Err(InstallationError::Uncertain(_))
    ));
    assert!(matches!(
        installation.list(&cancel, deadline()),
        Err(InstallationError::Uncertain(_))
    ));
    drop(installation);
    let reopened = GenerationInstallation::open_existing(path.path(), &cancel, deadline()).unwrap();
    // A visible state after an ambiguous final rename is verified on reopening;
    // no root/evidence was automatically deleted to pretend rollback succeeded.
    let candidate = reopened
        .open(&store, generation.digest(), &cancel, deadline())
        .unwrap();
    assert_eq!(candidate.digest(), generation.digest());
}

#[test]
fn private_installation_rejects_symlink_permissions_and_tampered_manifest() {
    let root = private();
    let target = private();
    let link = root.path().join("link");
    symlink(target.path(), &link).unwrap();
    let cancel = Cancellation::default();
    assert!(GenerationInstallation::initialize(&link, &cancel, deadline()).is_err());
    fs::set_permissions(target.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(GenerationInstallation::initialize(target.path(), &cancel, deadline()).is_err());
    let (_temp, generation, store, worker) = generation();
    let installation =
        GenerationInstallation::initialize(root.path(), &cancel, deadline()).unwrap();
    installation
        .prepare(&generation, &store, &worker, &cancel, deadline())
        .unwrap();
    fs::write(
        root.path()
            .join("generations")
            .join(generation.digest().to_string())
            .join("manifest"),
        b"corrupt",
    )
    .unwrap();
    assert!(
        installation
            .open(&store, generation.digest(), &cancel, deadline())
            .is_err()
    );
}

#[test]
fn imported_output_reopens_from_pinned_result_without_fabricating_a_receipt() {
    let (_temp, generation, store, _worker) = generation();
    let cancel = Cancellation::default();
    let source = generation
        .consumer()
        .outputs()
        .values()
        .next()
        .unwrap();
    let result = crate::result::ResultManifest::from_views(
        BTreeMap::from([("program".into(), source)]),
        BTreeMap::new(),
    )
    .unwrap();
    let result_pin = result.digest().unwrap();
    let admission = crate::result::admit_result(
        &store,
        &RootName::new("imported_fixture").unwrap(),
        &result,
        result_pin,
        &cancel,
    )
    .unwrap();
    let imported = admission
        .output("program")
        .unwrap()
        .open(&store, &cancel)
        .unwrap();
    let mut manifest = generation.manifest().clone();
    let (old_key, _) = manifest.outputs.pop_first().unwrap();
    let output = super::super::manifest::Output::from_identity(imported.identity());
    let key = output.key().unwrap();
    manifest.outputs.insert(key.clone(), output);
    let provenance = manifest.provenance.remove(&old_key).unwrap();
    manifest
        .provenance
        .insert(key.clone(), provenance);
    for command in manifest.commands.values_mut() {
        command.application.output.clone_from(&key);
    }
    let bytes = manifest.canonical_bytes().unwrap();
    let pin = ContentDigest::sha256(&bytes);
    let path = private();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    // Build an admitted Imported fixture using the exact durable record format;
    // the public prepare route above is exercised with Built outputs separately.
    let directory = installation.storage.candidate(pin, true).unwrap();
    installation
        .storage
        .write(directory.fd(), "manifest", &bytes)
        .unwrap();
    let mut record = Record {
        version: 1,
        installation: installation.id().into(),
        generation: pin.to_string(),
        phase: CandidatePhase::Preparing,
    };
    installation
        .storage
        .write(directory.fd(), "state", &record.bytes().unwrap())
        .unwrap();
    imported
        .retain(
            &output_root(installation.id(), pin, &key).unwrap(),
            &cancel,
        )
        .unwrap();
    let operation = store.operation().unwrap();
    operation
        .ingest(
            WORKER,
            ContentDigest::sha256(WORKER),
            MAX_LAUNCHER_BYTES,
        )
        .unwrap();
    operation
        .ingest(bytes.as_slice(), pin, MAX_MANIFEST_BYTES as u64)
        .unwrap();
    operation
        .publish_root(
            &metadata_root(installation.id(), pin).unwrap(),
            &metadata_references(pin, ContentDigest::sha256(WORKER)),
        )
        .unwrap();
    record.phase = CandidatePhase::Prepared;
    installation
        .storage
        .write(directory.fd(), "state", &record.bytes().unwrap())
        .unwrap();
    drop((operation, imported, admission, generation));
    let reopened = installation
        .open(&store, pin, &cancel, deadline())
        .unwrap();
    assert!(
        matches!(reopened.retained_outputs()[&key].identity.origin, OutputOrigin::Imported { manifest } if manifest == result_pin)
    );
    assert_eq!(reopened.commands().len(), 1);
}

#[test]
fn changed_installation_identity_and_registry_exhaustion_preserve_evidence() {
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let identity_path = path.path().join("installation");
    let original = fs::read(&identity_path).unwrap();
    fs::write(
        &identity_path,
        b"syrox-os-installation-v1\n11111111111111111111111111111111\n",
    )
    .unwrap();
    assert!(matches!(
        installation.list(&cancel, deadline()),
        Err(InstallationError::Invalid(
            "installation identity changed"
        ))
    ));
    fs::write(identity_path, original).unwrap();
    for number in 0..MAX_CANDIDATES {
        let pin = ContentDigest::sha256(format!("incomplete-{number}").as_bytes());
        fs::create_dir(
            path.path()
                .join("generations")
                .join(pin.to_string()),
        )
        .unwrap();
    }
    let pin = ContentDigest::sha256(b"one too many");
    assert!(matches!(
        installation.storage.candidate(pin, true),
        Err(InstallationError::Invalid(
            "candidate registry capacity exhausted"
        ))
    ));
    assert_eq!(
        installation
            .list(&cancel, deadline())
            .unwrap()
            .len(),
        MAX_CANDIDATES
    );
    assert!(
        !path
            .path()
            .join("generations")
            .join(pin.to_string())
            .exists()
    );
}

#[test]
fn incomplete_manifest_and_lost_installation_identity_are_never_overwritten() {
    let (_temp, generation, store, worker) = generation();
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let candidate = installation
        .storage
        .candidate(generation.digest(), true)
        .unwrap();
    installation
        .storage
        .write(
            candidate.fd(),
            "manifest",
            b"incomplete foreign evidence",
        )
        .unwrap();
    assert!(
        installation
            .prepare(&generation, &store, &worker, &cancel, deadline())
            .is_err()
    );
    assert_eq!(
        storage::read(candidate.fd(), "manifest", 1024).unwrap(),
        b"incomplete foreign evidence"
    );
    assert!(
        storage::read_optional(candidate.fd(), "state", 1024)
            .unwrap()
            .is_none()
    );
    fs::remove_file(path.path().join("installation")).unwrap();
    assert!(matches!(
        GenerationInstallation::initialize(path.path(), &cancel, deadline()),
        Err(InstallationError::Invalid(
            "installation identity missing while candidate evidence exists"
        ))
    ));
    assert!(!path.path().join("installation").exists());
}

fn binding_for(
    installation: &GenerationInstallation,
    retained: &RetainedGeneration,
) -> crate::deployment::os::launch_binding::LaunchBindingInput {
    let (process_key, policy) = retained
        .manifest()
        .processes
        .iter()
        .next()
        .unwrap();
    let command_key = &policy.command;
    let (service, process) = process_key.split_once('/').unwrap();
    let context = crate::deployment::os::launch_binding::OsLaunchContext::new(
        crate::systemd::SystemdScope::User {
            bus_socket: "/run/user/1000/bus".into(),
        },
        "/var/lib/syrox/store".into(),
        "/home/user/.config/systemd/user/syrox-os-probe.service".into(),
        1000,
        1000,
        Duration::from_secs(30),
        Duration::from_secs(10),
    )
    .unwrap();
    let context = context.with_restart(policy.restart).unwrap();
    crate::deployment::os::launch_binding::LaunchBindingInput {
        installation: installation.id().into(),
        generation: retained.digest(),
        service: service.into(),
        process: process.into(),
        command: command_key.rsplit('/').next().unwrap().into(),
        unit: crate::systemd::SystemdUnitName::new("syrox-os-probe.service").unwrap(),
        launcher: retained.manifest().launcher.clone(),
        spec: ContentDigest::sha256(b"prepared specification"),
        epoch: crate::deployment::os::activation::ExecutionEpoch {
            boot: crate::platform::linux::boot::BootId::parse(
                "11111111-1111-1111-1111-111111111111",
            )
            .unwrap(),
            manager: "manager-fingerprint".into(),
            scope: context.scope_key(),
        },
        context,
        configuration: "/private/installation/config/probe".into(),
        cwd: "/home/user/project".into(),
    }
}

#[test]
fn launch_publication_is_idempotent_reopens_offline_and_rejects_tampering() {
    use crate::deployment::os::launch_binding::OsLaunchBinding;
    let (temp, prepared, store, worker) = generation();
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let retained = installation
        .prepare(&prepared, &store, &worker, &cancel, deadline())
        .unwrap();
    let binding = OsLaunchBinding::new(binding_for(&installation, &retained)).unwrap();
    let pin = installation
        .publish_launch_binding(&retained, &binding, &cancel, deadline())
        .unwrap();
    assert_eq!(
        installation
            .publish_launch_binding(&retained, &binding, &cancel, deadline())
            .unwrap(),
        pin
    );
    // Publishing immutable choices does not create start authorization.
    assert!(!path.path().join("activation").exists());
    drop((retained, prepared, installation));
    fs::remove_file(temp.path().join("main.srx")).unwrap();
    fs::remove_file(worker).unwrap();
    let reopened = GenerationInstallation::open_existing(path.path(), &cancel, deadline()).unwrap();
    assert_eq!(
        reopened
            .read_launch_binding(pin, &cancel, deadline())
            .unwrap(),
        binding
    );
    let file = path.path().join(format!("launch-{pin}"));
    fs::write(&file, b"corrupt").unwrap();
    assert!(
        reopened
            .read_launch_binding(pin, &cancel, deadline())
            .is_err()
    );
    let reopened_generation = reopened
        .open(&store, binding.generation(), &cancel, deadline())
        .unwrap();
    assert!(
        reopened
            .publish_launch_binding(
                &reopened_generation,
                &binding,
                &cancel,
                deadline()
            )
            .is_err()
    );
    assert_eq!(fs::read(file).unwrap(), b"corrupt");
}

#[test]
fn launch_observation_distinguishes_absence_corruption_and_durable_existing_bytes() {
    use crate::deployment::os::launch_binding::OsLaunchBinding;
    use std::os::unix::fs::MetadataExt as _;
    let (_project, prepared, store, worker) = generation();
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let retained = installation
        .prepare(&prepared, &store, &worker, &cancel, deadline())
        .unwrap();
    let binding = OsLaunchBinding::new(binding_for(&installation, &retained)).unwrap();
    let pin = binding.digest().unwrap();
    let file = path.path().join(format!("launch-{pin}"));
    assert!(
        installation
            .observe_launch_binding(pin, &cancel, deadline())
            .unwrap()
            .is_none()
    );
    assert!(!file.exists());
    installation
        .publish_launch_binding(&retained, &binding, &cancel, deadline())
        .unwrap();
    let before = fs::metadata(&file).unwrap();
    assert_eq!(
        installation
            .observe_launch_binding(pin, &cancel, deadline())
            .unwrap(),
        Some(binding.clone())
    );
    let after = fs::metadata(&file).unwrap();
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.mtime(),
            before.mtime_nsec()
        ),
        (
            after.dev(),
            after.ino(),
            after.mtime(),
            after.mtime_nsec()
        )
    );
    assert_eq!(
        fs::read(&file).unwrap(),
        binding.canonical_bytes().unwrap()
    );
    fs::write(&file, b"corruption").unwrap();
    assert!(
        installation
            .observe_launch_binding(pin, &cancel, deadline())
            .is_err()
    );
    assert_eq!(fs::read(&file).unwrap(), b"corruption");
    fs::remove_file(&file).unwrap();
    symlink("installation", &file).unwrap();
    assert!(
        installation
            .observe_launch_binding(pin, &cancel, deadline())
            .is_err()
    );
    assert!(
        fs::symlink_metadata(&file)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn launch_publication_rejects_foreign_candidates_roles_and_replaced_authority() {
    use crate::deployment::os::launch_binding::OsLaunchBinding;
    let (_temp, prepared, store, worker) = generation();
    let path = private();
    let other_path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let other = GenerationInstallation::initialize(other_path.path(), &cancel, deadline()).unwrap();
    let retained = installation
        .prepare(&prepared, &store, &worker, &cancel, deadline())
        .unwrap();
    let binding = OsLaunchBinding::new(binding_for(&installation, &retained)).unwrap();
    assert!(
        other
            .publish_launch_binding(&retained, &binding, &cancel, deadline())
            .is_err()
    );
    let mut input = binding_for(&installation, &retained);
    input.command = "missing".into();
    let bad = OsLaunchBinding::new(input).unwrap();
    assert!(
        installation
            .publish_launch_binding(&retained, &bad, &cancel, deadline())
            .is_err()
    );
    let pin = installation
        .publish_launch_binding(&retained, &binding, &cancel, deadline())
        .unwrap();
    fs::rename(
        path.path().join("authority.lock"),
        path.path().join("old-authority"),
    )
    .unwrap();
    fs::write(path.path().join("authority.lock"), b"").unwrap();
    fs::set_permissions(
        path.path().join("authority.lock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(
        installation
            .read_launch_binding(pin, &cancel, deadline())
            .is_err()
    );
    assert!(
        installation
            .publish_launch_binding(&retained, &binding, &cancel, deadline())
            .is_err()
    );
}

#[test]
fn orphan_launch_evidence_prevents_installation_identity_recreation() {
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    drop(installation);
    fs::write(
        path.path().join("launch-incomplete"),
        b"partial publication",
    )
    .unwrap();
    fs::remove_file(path.path().join("installation")).unwrap();
    assert!(GenerationInstallation::initialize(path.path(), &cancel, deadline()).is_err());
    assert!(!path.path().join("installation").exists());
    assert_eq!(
        fs::read(path.path().join("launch-incomplete")).unwrap(),
        b"partial publication"
    );
}

#[test]
fn launch_registry_capacity_preserves_existing_bindings_and_refuses_new_ones() {
    use crate::deployment::os::launch_binding::OsLaunchBinding;
    let (_temp, prepared, store, worker) = generation();
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let retained = installation
        .prepare(&prepared, &store, &worker, &cancel, deadline())
        .unwrap();
    let binding = OsLaunchBinding::new(binding_for(&installation, &retained)).unwrap();
    let pin = installation
        .publish_launch_binding(&retained, &binding, &cancel, deadline())
        .unwrap();
    let existing = fs::read_dir(path.path()).unwrap().count();
    for index in existing..4096 {
        fs::write(
            path.path().join(format!("unfinished-{index}")),
            b"",
        )
        .unwrap();
    }
    assert_eq!(fs::read_dir(path.path()).unwrap().count(), 4096);
    assert_eq!(
        installation
            .read_launch_binding(pin, &cancel, deadline())
            .unwrap(),
        binding
    );
    assert_eq!(
        installation
            .publish_launch_binding(&retained, &binding, &cancel, deadline())
            .unwrap(),
        pin
    );
    let mut input = binding_for(&installation, &retained);
    input.spec = ContentDigest::sha256(b"another prepared specification");
    let next = OsLaunchBinding::new(input).unwrap();
    assert!(
        installation
            .publish_launch_binding(&retained, &next, &cancel, deadline())
            .is_err()
    );
    assert!(
        !path
            .path()
            .join(format!("launch-{}", next.digest().unwrap()))
            .exists()
    );
    assert_eq!(
        installation
            .read_launch_binding(pin, &cancel, deadline())
            .unwrap(),
        binding
    );
}

#[test]
fn generation_process_retention_keeps_metadata_launcher_outputs_and_views_until_fd_closes() {
    let (_project, prepared, store, worker) = generation();
    let path = private();
    let cancel = Cancellation::default();
    let installation =
        GenerationInstallation::initialize(path.path(), &cancel, deadline()).unwrap();
    let retained = installation
        .prepare(&prepared, &store, &worker, &cancel, deadline())
        .unwrap();
    let descriptor = retained.process_retention().unwrap();
    let manifest = retained.digest();
    let launcher = launcher_digest(retained.manifest()).unwrap();
    let artifact = retained
        .outputs()
        .values()
        .next()
        .unwrap()
        .artifact();
    let view = retained
        .outputs()
        .values()
        .next()
        .unwrap()
        .directory()
        .unwrap();
    let mut roots = store
        .operation()
        .unwrap()
        .managed_build_roots()
        .unwrap();
    roots.push(metadata_root(installation.id(), manifest).unwrap());
    roots.extend(
        retained
            .retained_outputs()
            .values()
            .map(|output| output.root.clone()),
    );
    roots.sort();
    roots.dedup();
    drop((retained, prepared, installation));
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            remove_roots: roots,
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    for pin in [manifest, launcher, artifact] {
        assert!(!report.removed_objects.contains(&pin));
        assert!(
            store
                .operation()
                .unwrap()
                .read_verified(pin, MAX_LAUNCHER_BYTES)
                .unwrap()
                .is_some()
        );
    }
    assert!(view.join("bin/run").exists());
    drop(descriptor);
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    for pin in [manifest, launcher, artifact] {
        assert!(report.removed_objects.contains(&pin));
    }
}

use super::*;
use crate::deployment::os::{LauncherIdentity, profile};

#[test]
fn profile_identity_and_operation_cas_fail_before_contacting_a_manager() {
    let Ok((uid, gid)) = profile::profile_credentials() else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let installation_path = root.path().join("installation");
    let cwd = root.path().join("work");
    let units = root.path().join("units");
    for path in [&installation_path, &cwd, &units] {
        profile::ensure_profile_directory(path).unwrap();
    }
    let cancel = Cancellation::default();
    let deadline = Instant::now() + Duration::from_secs(15);
    let installation =
        GenerationInstallation::initialize(&installation_path, &cancel, deadline).unwrap();
    let store_path = root.path().join("store");
    let store = Store::initialize(&store_path).unwrap();
    let worker = root.path().join("worker");
    std::fs::write(&worker, b"never executed").unwrap();
    let candidate = installation
        .prepare_empty(
            LauncherIdentity::new(ContentDigest::sha256(b"never executed"), 1).unwrap(),
            &store,
            &worker,
            &cancel,
            deadline,
        )
        .unwrap();
    let mut request = OsApplyRequest {
        installation: installation_path,
        store: store_path,
        units: units.clone(),
        cwd,
        candidate: candidate.digest(),
        expected: None,
        scope: SystemdScope::User {
            bus_socket: root.path().join("absent-bus"),
        },
        uid,
        gid,
        start_timeout: Duration::from_secs(30),
        stop_timeout: Duration::from_secs(5),
    };
    let mut authority = OsSelectionAuthority {
        installation: "incorrect-installation".into(),
        active_operation: None,
    };
    assert_eq!(
        apply_os_generation_with_authority(&request, &authority, false, &cancel, deadline)
            .unwrap_err()
            .stage,
        "profile installation identity comparison"
    );
    authority.installation = installation.id().into();
    let journal =
        ActivationJournal::open_existing(&request.installation, &cancel, deadline).unwrap();
    let epoch = ExecutionEpoch {
        boot: crate::platform::linux::boot::BootId::parse("11111111-1111-4111-8111-111111111111")
            .unwrap(),
        manager: "recorded-manager".into(),
        scope: "recorded-scope".into(),
    };
    let operation = journal
        .begin(&candidate, None, epoch.clone(), &cancel, deadline)
        .unwrap();
    request.expected = Some(candidate.digest());
    authority.active_operation = Some(operation);
    // A new selection of the same generation is an ABA change: comparing only
    // the desired digest would incorrectly accept the stale preparation.
    let newer = journal
        .begin(
            &candidate,
            Some(candidate.digest()),
            epoch,
            &cancel,
            deadline,
        )
        .unwrap();
    let before = serde_json::to_vec(&journal.snapshot(&cancel, deadline).unwrap()).unwrap();
    assert_eq!(
        apply_os_generation_with_authority(&request, &authority, false, &cancel, deadline)
            .unwrap_err()
            .stage,
        "profile active operation comparison"
    );
    assert_eq!(
        serde_json::to_vec(&journal.snapshot(&cancel, deadline).unwrap()).unwrap(),
        before
    );
    assert_eq!(std::fs::read_dir(&units).unwrap().count(), 0);
    let recovery = recovery::OsRecoveryRequest {
        installation: request.installation.clone(),
        store: request.store.clone(),
        units: request.units.clone(),
        cwd: request.cwd.clone(),
        operation: newer.clone(),
        new_boot: false,
        manager_changed: false,
        scope: request.scope.clone(),
        uid,
        gid,
        start_timeout: request.start_timeout,
        stop_timeout: request.stop_timeout,
    };
    assert_eq!(
        recovery::recover_os_generation_with_identity(
            &recovery,
            "incorrect-installation",
            &cancel,
            deadline
        )
        .unwrap_err()
        .stage(),
        "profile installation identity comparison"
    );
    authority.active_operation = Some(newer);
    request.expected = None;
    assert_eq!(
        apply_os_generation_with_authority(&request, &authority, false, &cancel, deadline)
            .unwrap_err()
            .stage,
        "desired generation comparison"
    );
}

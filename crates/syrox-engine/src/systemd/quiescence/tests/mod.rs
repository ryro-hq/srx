use super::*;
use crate::systemd::SystemdUnitName;

fn binding() -> UnitInvocation {
    UnitInvocation::new(
        SystemdUnitName::new("syrox-observe.service").unwrap(),
        [1; 16],
    )
    .unwrap()
}

#[test]
fn events_require_exact_populated_value_and_reject_missing_duplicate_or_unbounded_data() {
    assert!(!populated(b"populated 0\nfrozen 0\n").unwrap());
    assert!(populated(b"frozen 0\npopulated 1\nfuture_counter 12\n").unwrap());
    for bytes in [
        b"".as_slice(),
        b"frozen 0\n",
        b"populated 0\npopulated 1\n",
        b"populated 00\n",
        b"populated 2\n",
        b"populated -1\n",
        b"populated 0 extra\n",
        b"populated\n",
        b"populated 0\nunknown invalid\n",
        b"populated \xff\n",
    ] {
        assert!(populated(bytes).is_err(), "{bytes:?}");
    }
    assert!(populated(&vec![b' '; MAX_EVENTS_BYTES + 1]).is_err());
}

#[test]
fn manager_cgroup_paths_are_relative_to_verified_mount_without_alias_spelling() {
    assert_eq!(
        relative_group("/user.slice/unit.service").unwrap(),
        Path::new("user.slice/unit.service")
    );
    for path in [
        "",
        "/",
        "relative",
        "//unit",
        "/unit/",
        "/unit//nested",
        "/unit/../other",
        "/unit/./nested",
        "/unit\0bad",
    ] {
        assert!(relative_group(path).is_err(), "{path:?}");
    }
    assert!(relative_group(&format!("/{}", "x".repeat(4096))).is_err());
}

#[test]
fn ordinary_files_cannot_impersonate_cgroup_events() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("events");
    std::fs::write(&path, b"populated 0\n").unwrap();
    let directory = linux_fd::open_top_directory(temp.path()).unwrap();
    assert!(matches!(
        PinnedEvents::capture(directory.fd()),
        Err(QuiescenceError::Invalid(
            "kernel filesystem type differs"
        ))
    ));
}

#[test]
fn status_matching_requires_unit_invocation_and_cgroup_even_when_inactive() {
    let temp = tempfile::tempdir().unwrap();
    let directory = linux_fd::open_top_directory(temp.path()).unwrap();
    let identity = directory.metadata().identity();
    let marker = CgroupMarker {
        boot: BootId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap(),
        binding: binding(),
        control_group: "/user.slice/unit.service".into(),
        identity,
    };
    let mut status = SystemdUnitStatus {
        unit: binding().unit().clone(),
        invocation: vec![1; 16],
        active_state: "inactive".into(),
        sub_state: "dead".into(),
        control_group: "/user.slice/unit.service".into(),
        result: "success".into(),
        main_pid: 0,
        exec_main_code: 0,
        exec_main_status: 0,
    };
    assert!(status_matches(
        &marker,
        &status,
        EventsObservation::Empty
    ));
    status.invocation = vec![];
    assert!(!status_matches(
        &marker,
        &status,
        EventsObservation::Empty
    ));
    status.invocation = vec![2; 16];
    assert!(!status_matches(
        &marker,
        &status,
        EventsObservation::Empty
    ));
    status.invocation = vec![1; 16];
    status.control_group = "/replacement".into();
    assert!(!status_matches(
        &marker,
        &status,
        EventsObservation::Empty
    ));
    status.control_group = "/user.slice/unit.service".into();
    status.unit = SystemdUnitName::new("syrox-replacement.service").unwrap();
    assert!(!status_matches(
        &marker,
        &status,
        EventsObservation::Empty
    ));
    // A descriptor/marker built on an ordinary directory can never pass the
    // kernel-property read, even if its contents say populated=0.
    std::fs::write(
        temp.path().join("cgroup.events"),
        b"populated 0\n",
    )
    .unwrap();
    assert!(PinnedEvents::capture(directory.fd()).is_err());
}

#[test]
fn invocation_key_rejects_missing_identity_and_preserves_exact_nonzero_bytes() {
    let unit = SystemdUnitName::new("syrox-observe.service").unwrap();
    assert!(UnitInvocation::new(unit.clone(), [0; 16]).is_err());
    let mut invocation = [0; 16];
    invocation[15] = 1;
    let key = UnitInvocation::new(unit.clone(), invocation).unwrap();
    assert_eq!(key.unit(), &unit);
    assert_eq!(key.invocation(), &invocation);
    assert_ne!(key, binding());
}

#[test]
fn removed_cgroup_allows_cleared_path_only_for_exact_inactive_invocation() {
    let temp = tempfile::tempdir().unwrap();
    let directory = linux_fd::open_top_directory(temp.path()).unwrap();
    let marker = CgroupMarker {
        boot: BootId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap(),
        binding: binding(),
        control_group: "/user.slice/unit.service".into(),
        identity: directory.metadata().identity(),
    };
    let mut status = SystemdUnitStatus {
        unit: binding().unit().clone(),
        invocation: vec![1; 16],
        active_state: "inactive".into(),
        sub_state: "dead".into(),
        control_group: String::new(),
        result: "success".into(),
        main_pid: 0,
        exec_main_code: 0,
        exec_main_status: 0,
    };
    assert!(status_matches(
        &marker,
        &status,
        EventsObservation::Removed
    ));
    assert!(!status_matches(
        &marker,
        &status,
        EventsObservation::Empty
    ));
    status.active_state = "active".into();
    assert!(!status_matches(
        &marker,
        &status,
        EventsObservation::Removed
    ));
    status.active_state = "failed".into();
    assert!(status_matches(
        &marker,
        &status,
        EventsObservation::Removed
    ));
    status.main_pid = 12;
    assert!(!status_matches(
        &marker,
        &status,
        EventsObservation::Removed
    ));
    status.main_pid = 0;
    status.invocation = vec![2; 16];
    assert!(!status_matches(
        &marker,
        &status,
        EventsObservation::Removed
    ));
    status.invocation = vec![1; 16];
    status.control_group = "/user.slice/replacement.service".into();
    assert!(!status_matches(
        &marker,
        &status,
        EventsObservation::Removed
    ));
}

mod retirement;

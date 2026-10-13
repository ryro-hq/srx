use super::*;

#[test]
fn both_profiles_reject_malformed_envelopes_before_taking_channels() {
    for args in [
        vec![],
        vec![OsString::from("managed")],
        vec![OsString::from("x"); 4097],
        vec![OsString::from("x".repeat(1024 * 1024 + 1)); 5],
    ] {
        // SAFETY: every case is rejected by the initial envelope guard before
        // descriptor ownership, namespace mutation or process-global changes.
        assert!(unsafe { runtime_helper(&args) }.is_err());
        // SAFETY: the managed entry shares the same initial validation guard.
        assert!(unsafe { managed_runtime_helper(&args) }.is_err());
    }
}

#[test]
fn managed_profile_preserves_alias_rejection_without_consuming_caller_fd() {
    let file = tempfile::tempfile().unwrap();
    let fd = file.as_raw_fd();
    let args = [
        "monitor".into(),
        fd.to_string().into(),
        fd.to_string().into(),
        fd.to_string().into(),
        "body".into(),
    ];
    // SAFETY: aliased descriptors are rejected before from_raw_fd or namespace
    // creation, so the caller retains ownership of this existing regular file.
    let error = unsafe { managed_runtime_helper(&args) }.unwrap_err();
    assert!(error.to_string().contains("aliased"));
    assert!(file.metadata().is_ok());
}

#[test]
fn managed_working_mounts_do_not_clone_nested_host_mounts() {
    assert_eq!(
        runtime_tree_flags(MountKind::Working, true) & libc::AT_RECURSIVE,
        0
    );
    assert_ne!(
        runtime_tree_flags(MountKind::Working, false) & libc::AT_RECURSIVE,
        0
    );
    for kind in [
        MountKind::Output,
        MountKind::Configuration,
    ] {
        assert_ne!(
            runtime_tree_flags(kind, true) & libc::AT_RECURSIVE,
            0
        );
        assert_eq!(
            runtime_tree_flags(kind, true),
            runtime_tree_flags(kind, false)
        );
    }
}

#[test]
fn session_state_never_inherits_host_submounts() {
    assert_eq!(
        runtime_tree_flags(MountKind::State, true) & libc::AT_RECURSIVE,
        0
    );
}

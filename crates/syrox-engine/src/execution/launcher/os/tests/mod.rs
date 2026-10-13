mod restart;
use super::*;
#[test]
fn arguments_are_explicit_canonical_and_separate_from_shell() {
    let good = vec![
        "/private/install".into(),
        "/private/store".into(),
        ContentDigest::sha256(b"binding")
            .to_string()
            .into(),
    ];
    assert!(Arguments::parse(&good).is_ok());
    for paths in [
        ("relative", "/store"),
        ("/a/../b", "/store"),
        ("/a//b", "/store"),
        ("/a", "/a/store"),
    ] {
        let mut args = good.clone();
        args[0] = paths.0.into();
        args[1] = paths.1.into();
        assert!(Arguments::parse(&args).is_err());
    }
    assert!(Arguments::parse(&good[..2]).is_err());
    let mut args = good;
    args.push("shell-owner".into());
    assert!(Arguments::parse(&args).is_err());
}
#[test]
fn invocation_and_main_pid_evidence_are_independent() {
    let invocation = context::invocation("0123456789abcdef0123456789abcdef").unwrap();
    assert_eq!(
        context::hex(&invocation),
        "0123456789abcdef0123456789abcdef"
    );
    for invalid in [
        "",
        "00000000000000000000000000000000",
        "0123456789ABCDEF0123456789ABCDEF",
    ] {
        assert!(context::invocation(invalid).is_err());
    }
    let unit = crate::systemd::SystemdUnitName::new("syrox-os-test.service").unwrap();
    let mut status = SystemdUnitStatus {
        unit: unit.clone(),
        invocation: invocation.to_vec(),
        active_state: "activating".into(),
        sub_state: "start".into(),
        control_group: "/test".into(),
        result: String::new(),
        main_pid: 123,
        exec_main_code: 0,
        exec_main_status: 0,
    };
    assert!(validate_main(&status, &unit, &invocation, 123).is_ok());
    assert!(validate_main(&status, &unit, &invocation, 124).is_err());
    status.invocation[0] ^= 1;
    assert!(validate_main(&status, &unit, &invocation, 123).is_err());
    status.invocation = invocation.to_vec();
    status.active_state = "active".into();
    assert!(validate_main(&status, &unit, &invocation, 123).is_err());
}
#[test]
fn image_hash_is_bounded_and_cancellation_precedes_read() {
    let cancel = Cancellation::default();
    let deadline = Instant::now() + Duration::from_secs(1);
    assert_eq!(
        context::hash_reader(&b"worker"[..], 6, &cancel, deadline).unwrap(),
        ContentDigest::sha256(b"worker")
    );
    assert!(context::hash_reader(&b"worker"[..], 5, &cancel, deadline).is_err());
    cancel.cancel();
    assert!(context::hash_reader(&b"worker"[..], 6, &cancel, deadline).is_err());
}

#[test]
fn running_image_uses_numeric_pinned_proc_directory() {
    let file = context::running_image().unwrap();
    assert!(file.metadata().unwrap().is_file());
    assert!(file.metadata().unwrap().len() > 0);
}

#[test]
fn evidence_errors_expose_stage_without_persisted_contents() {
    let error = evidence("decode configuration")(io::Error::other("SECRET_ARGV_ENV"));
    assert_eq!(
        error.to_string(),
        "Os worker evidence failed: decode configuration"
    );
    assert!(!format!("{error:?}").contains("SECRET_ARGV_ENV"));
}

#[test]
fn payload_exit_and_signal_never_become_reserved_admission_denial() {
    use std::os::unix::process::ExitStatusExt as _;
    assert_eq!(
        payload_envelope(std::process::ExitStatus::from_raw(0)),
        0
    );
    for status in [
        1 << 8,
        78 << 8,
        255 << 8,
        libc::SIGTERM,
        libc::SIGKILL,
    ] {
        assert_eq!(
            payload_envelope(std::process::ExitStatus::from_raw(status)),
            1
        );
    }
    assert!(matches!(
        admission_error(crate::deployment::os::activation::ActivationError::StartDenied("revoked")),
        OsWorkerError::Denied("revoked")
    ));
    for error in [
        crate::deployment::os::activation::ActivationError::Invalid("uncertain"),
        crate::deployment::os::activation::ActivationError::Io(io::Error::other("write uncertain")),
    ] {
        assert!(!matches!(
            admission_error(error),
            OsWorkerError::Denied(_)
        ));
    }
}

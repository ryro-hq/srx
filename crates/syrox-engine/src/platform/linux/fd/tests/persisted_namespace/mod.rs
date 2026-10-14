use super::*;
use std::time::Duration;

#[test]
fn parser_rejects_duplicate_missing_and_unbounded_hierarchy() {
    assert!(field("NSpid: 3 1\nNSpid: 4 1\n", "NSpid:").is_err());
    assert!(field("Pid: 3\n", "NSpid:").is_err());
    assert!(numbers(&"1 ".repeat(33)).is_err());
    assert!(numbers("3 0").is_err());
    assert_eq!(numbers("3 2 1").unwrap(), [3, 2, 1]);
    assert!(start_time("7 (name) S 1", 8).is_err());
}
#[test]
fn ordinary_process_never_becomes_namespace_init_evidence() {
    let cancel = Cancellation::default();
    let current = pidfd_open(std::process::id()).unwrap();
    assert!(
        CapturedNamespace::capture(
            current.as_fd(),
            &cancel,
            Instant::now() + Duration::from_secs(3)
        )
        .is_err()
    );
    let file = std::fs::File::open("/dev/null").unwrap();
    assert!(
        CapturedNamespace::capture(
            file.as_fd(),
            &cancel,
            Instant::now() + Duration::from_secs(3)
        )
        .is_err()
    );
}
#[test]
fn cancellation_and_deadline_are_not_absence_evidence() {
    let cancel = Cancellation::default();
    cancel.cancel();
    let error = observer(&cancel, Instant::now() + Duration::from_secs(3)).unwrap_err();
    assert!(crate::cancellation::is_cancellation_io(&error));
    assert_eq!(
        observer(&Cancellation::default(), Instant::now())
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn pidfs_identity_survives_closing_every_descriptor_while_process_lives() {
    if super::super::retention_fork_tests::isolate_test(
        "platform::linux::fd::persisted_namespace::tests::pidfs_identity_survives_closing_every_descriptor_while_process_lives",
        "SYROX_PERSISTED_PIDFS_ISOLATED",
    ) {
        return;
    }
    // Reexec isolates this PID from other tests' descriptor holdings. The first
    // owned pidfd is closed before the second syscall; no cloned fd is retained.
    let expected = {
        let first = pidfd_open(std::process::id()).unwrap();
        assert!(!pidfd_exited(first.as_fd()).unwrap());
        Identity::read(first.as_fd()).unwrap()
    };
    let reopened = pidfd_open(std::process::id()).unwrap();
    assert_eq!(
        Identity::read(reopened.as_fd()).unwrap(),
        expected
    );
    assert!(!pidfd_exited(reopened.as_fd()).unwrap());
}

pub(crate) mod capture;
mod launcher;

mod parent;

mod peer;

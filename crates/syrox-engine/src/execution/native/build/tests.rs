use super::*;
use std::time::Duration;

#[test]
fn cancelled_or_expired_preparation_precedes_namespace_effects() {
    let cancellation = Cancellation::default();
    cancellation.cancel();
    assert!(crate::cancellation::is_cancellation_io(
        &check(
            &cancellation,
            Instant::now() + Duration::from_secs(1)
        )
        .unwrap_err()
    ));
    assert_eq!(
        check(
            &Cancellation::default(),
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap()
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn exec_acknowledgement_wins_over_immediate_namespace_exit() {
    let mut acknowledged = io::Cursor::new(b"e");
    assert!(
        execution_ack(&mut acknowledged, || panic!(
            "must consume exec ACK before exit readiness"
        ))
        .unwrap()
    );
    for bytes in [&b""[..], &b"m"[..]] {
        assert!(execution_ack(&mut io::Cursor::new(bytes), || Ok(true)).is_err());
    }
}

#[test]
fn unacknowledged_live_namespace_waits_but_exited_namespace_fails() {
    struct Pending;
    impl Read for Pending {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
    assert!(!execution_ack(&mut Pending, || Ok(false)).unwrap());
    assert!(execution_ack(&mut Pending, || Ok(true)).is_err());
}

#[test]
fn exec_ack_arriving_between_read_and_exit_poll_is_not_lost() {
    struct Raced(bool);
    impl Read for Raced {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if !self.0 {
                self.0 = true;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            bytes[0] = b'e';
            Ok(1)
        }
    }
    assert!(execution_ack(&mut Raced(false), || Ok(true)).unwrap());
}

#[test]
fn inherited_mount_source_is_reopened_with_the_pinned_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("source");
    std::fs::write(&path, b"pinned").unwrap();
    let pinned = File::open(&path).unwrap();
    let source = format!("/proc/self/fd/{}", pinned.as_raw_fd());
    let local = crate::execution::native::local_mount_source(Path::new(&source), false).unwrap();
    assert_eq!(
        local.metadata(),
        crate::platform::linux::fd::metadata(pinned.as_fd()).unwrap()
    );
    assert_ne!(local.fd().as_raw_fd(), pinned.as_raw_fd());
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    assert!(crate::execution::native::local_mount_source(Path::new(&source), false).is_err());
}

use super::*;
use std::io::{Read as _, Write as _};
use std::os::unix::process::CommandExt as _;
use std::process::Command;
use std::time::{Duration, Instant};

fn size() -> WindowSize {
    WindowSize {
        rows: 24,
        columns: 80,
        x_pixels: 0,
        y_pixels: 0,
    }
}
fn raw_pty() -> Pty {
    let pty = Pty::open(size(), None).unwrap();
    TerminalAttributes::read(pty.slave())
        .unwrap()
        .raw()
        .apply(pty.slave())
        .unwrap();
    pty
}
fn nonblocking(fd: BorrowedFd<'_>) {
    crate::platform::linux::fd::set_nonblocking(fd).unwrap();
}

#[test]
fn pty_is_cloexec_and_peer_is_descriptor_validated() {
    let pty = Pty::open(size(), None).unwrap();
    for fd in [pty.master(), pty.slave()] {
        // SAFETY: only queries each borrowed live descriptor.
        assert_ne!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
    assert!(pty.master().as_raw_fd() >= 3 && pty.slave().as_raw_fd() >= 3);
    validate_slave(pty.slave()).unwrap();
    assert!(validate_slave(pty.master()).is_err());
    assert!(validate_slave(tempfile::tempfile().unwrap().as_fd()).is_err());
    assert!(validate_slave(std::fs::File::open("/dev/null").unwrap().as_fd()).is_err());
    assert_eq!(WindowSize::read(pty.slave()).unwrap(), size());
    let resized = WindowSize {
        rows: 45,
        columns: 132,
        ..size()
    };
    resized.apply(pty.master()).unwrap();
    assert_eq!(WindowSize::read(pty.slave()).unwrap(), resized);
}

#[test]
fn guard_rejects_terminal_without_foreground_ownership() {
    let pty = Pty::open(size(), None).unwrap();
    let before = TerminalAttributes::read(pty.slave()).unwrap();
    assert!(TerminalGuard::enter(pty.slave()).is_err());
    let root = crate::platform::linux::fd::pidfd_open(std::process::id()).unwrap();
    assert!(
        suspend_foreground_observed(
            pty.slave(),
            root.as_fd(),
            &crate::cancellation::Cancellation::default()
        )
        .is_err()
    );
    let after = TerminalAttributes::read(pty.slave()).unwrap();
    assert_eq!(before.0.c_lflag, after.0.c_lflag);
}

#[test]
#[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
fn controlling_terminal_and_restore_child() {
    std::env::var_os("SYROX_TEST_TERMINAL_CHILD")
        .expect("parent test must supply the fixture environment");
    let stdin = io::stdin();
    // SAFETY: process-global queries; this helper owns its session.
    assert_eq!(unsafe { libc::tcgetpgrp(0) }, unsafe {
        libc::getpgrp()
    });
    let saved = TerminalAttributes::read(stdin.as_fd()).unwrap();
    {
        let mut guard = TerminalGuard::enter(stdin.as_fd()).unwrap();
        let raw = TerminalAttributes::read(stdin.as_fd()).unwrap();
        assert_eq!(
            raw.0.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG),
            0
        );
        guard.restore().unwrap();
        guard.restore().unwrap();
    }
    assert_eq!(
        TerminalAttributes::read(stdin.as_fd())
            .unwrap()
            .0
            .c_lflag,
        saved.0.c_lflag
    );
    {
        let _guard = TerminalGuard::enter(stdin.as_fd()).unwrap();
    }
    assert_eq!(
        TerminalAttributes::read(stdin.as_fd())
            .unwrap()
            .0
            .c_lflag,
        saved.0.c_lflag
    );
    // Relinquishing to an independent custodian must not perform restoration
    // implicitly through Drop. This only checks the local ioctl policy.
    TerminalGuard::enter(stdin.as_fd())
        .unwrap()
        .disarm_without_restore();
    assert!(
        saved
            .raw()
            .matches(&TerminalAttributes::read(stdin.as_fd()).unwrap())
    );
    saved.apply(stdin.as_fd()).unwrap();
    let mut guard = TerminalGuard::enter(stdin.as_fd()).unwrap();
    let mut divergent = TerminalAttributes::read(stdin.as_fd()).unwrap();
    divergent.0.c_cc[libc::VINTR] ^= 1;
    divergent.apply(stdin.as_fd()).unwrap();
    assert_eq!(
        guard.restore().unwrap_err().raw_os_error(),
        Some(libc::ESTALE)
    );
    assert!(divergent.matches(&TerminalAttributes::read(stdin.as_fd()).unwrap()));
    drop(guard);
    assert!(divergent.matches(&TerminalAttributes::read(stdin.as_fd()).unwrap()));
    saved.apply(stdin.as_fd()).unwrap();
    io::stdout()
        .write_all(b"terminal-ready\n")
        .unwrap();
}

#[test]
fn dedicated_child_establishes_controlling_tty_and_restores_raw_mode() {
    let pty = Pty::open(size(), None).unwrap();
    let slave = pty.slave().try_clone_to_owned().unwrap();
    let mut command = Command::new(crate::reexec_test_executable(
        "platform::linux::fd::terminal::tests::controlling_terminal_and_restore_child",
        true,
    ));
    command
        .args([
            "--ignored",
            "--exact",
            "platform::linux::fd::terminal::tests::controlling_terminal_and_restore_child",
            "--nocapture",
        ])
        .env("SYROX_TEST_TERMINAL_CHILD", "1");
    // SAFETY: pre_exec runs in the dedicated single-threaded child; the borrowed
    // slave stays live until spawn returns and the child has no group override.
    unsafe {
        command.pre_exec(move || establish_controlling_terminal(slave.as_fd()));
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut output = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        // SAFETY: live nonblocking master and writable buffer.
        let count = unsafe {
            libc::read(
                pty.master().as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if count > 0 {
            output.extend_from_slice(&buffer[..usize::try_from(count).unwrap()]);
        }
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "{}",
                String::from_utf8_lossy(&output)
            );
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("terminal helper timeout");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // Success from the child checks session ownership, explicit and Drop restore.
}

#[test]
fn relay_is_bidirectional_bounded_and_forwards_resize() {
    let inner = raw_pty();
    let outer = raw_pty();
    nonblocking(outer.slave());
    let mut payload = std::fs::File::from(inner.slave().try_clone_to_owned().unwrap());
    let mut terminal = std::fs::File::from(outer.master().try_clone_to_owned().unwrap());
    let cancellation = crate::cancellation::Cancellation::default();
    std::thread::scope(|scope| {
        let run = scope.spawn(|| {
            relay(
                inner.master(),
                outer.slave(),
                outer.slave(),
                RelayOptions {
                    buffer_bytes: 64,
                    deadline: Some(Instant::now() + Duration::from_secs(3)),
                    forward_resize: true,
                },
                &cancellation,
            )
            .unwrap()
        });
        terminal.write_all(b"request").unwrap();
        let mut input = [0; 7];
        // Make this test-only payload endpoint nonblocking as well, so a relay
        // regression cannot strand the harness in a blocking read.
        nonblocking(payload.as_fd());
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut filled = 0;
        while filled < input.len() && Instant::now() < deadline {
            match payload.read(&mut input[filled..]) {
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                result => panic!("unexpected payload read {result:?}"),
            }
        }
        assert_eq!(filled, input.len());
        assert_eq!(&input, b"request");
        payload.write_all(b"response").unwrap();
        let mut response = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        while response.len() < 8 && Instant::now() < deadline {
            let mut buffer = [0; 8];
            match terminal.read(&mut buffer) {
                Ok(count) => response.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                value => panic!("unexpected terminal read {value:?}"),
            }
        }
        assert_eq!(response, b"response");
        let resized = WindowSize {
            rows: 40,
            columns: 120,
            ..size()
        };
        resized.apply(outer.master()).unwrap();
        while WindowSize::read(inner.slave()).unwrap() != resized && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(WindowSize::read(inner.slave()).unwrap(), resized);
        cancellation.cancel();
        let result = run.join().unwrap();
        assert_eq!(result.reason, RelayExit::Cancelled);
        assert_eq!(result.bytes_to_payload, 7);
        assert_eq!(result.bytes_to_terminal, 8);
        assert!(result.pending_input <= 64 && result.pending_output <= 64);
    });
}

#[test]
fn relay_deadline_cancel_and_invalid_descriptors_are_explicit() {
    let inner = raw_pty();
    let outer = raw_pty();
    nonblocking(outer.slave());
    let cancellation = crate::cancellation::Cancellation::default();
    let options = RelayOptions {
        buffer_bytes: 16,
        deadline: Some(Instant::now() + Duration::from_millis(25)),
        forward_resize: false,
    };
    let result = relay(
        inner.master(),
        outer.slave(),
        outer.slave(),
        options,
        &cancellation,
    )
    .unwrap();
    assert_eq!(result.reason, RelayExit::Deadline);
    cancellation.cancel();
    assert_eq!(
        relay(
            inner.master(),
            outer.slave(),
            outer.slave(),
            RelayOptions {
                deadline: Some(Instant::now() + Duration::from_secs(1)),
                ..options
            },
            &cancellation
        )
        .unwrap()
        .reason,
        RelayExit::Cancelled
    );
    assert!(
        relay(
            inner.master(),
            outer.slave(),
            outer.slave(),
            RelayOptions {
                buffer_bytes: 65537,
                ..options
            },
            &cancellation
        )
        .is_err()
    );
    // Blocking payload slave is rejected rather than having its OFD flags changed.
    assert!(
        relay(
            inner.master(),
            inner.slave(),
            outer.slave(),
            options,
            &cancellation
        )
        .is_err()
    );
}

#[test]
fn relay_drains_slave_output_then_reports_pty_closed() {
    let inner = raw_pty();
    let outer = raw_pty();
    nonblocking(outer.slave());
    let (master, slave) = inner.into_parts();
    std::fs::File::from(slave)
        .write_all(b"last bytes")
        .unwrap();
    let result = relay(
        master.as_fd(),
        outer.slave(),
        outer.slave(),
        RelayOptions {
            buffer_bytes: 3,
            deadline: Some(Instant::now() + Duration::from_secs(1)),
            forward_resize: false,
        },
        &crate::cancellation::Cancellation::default(),
    )
    .unwrap();
    assert_eq!(result.reason, RelayExit::PtyClosed);
    assert_eq!(result.bytes_to_terminal, 10);
    assert_eq!(result.pending_output, 0);
}

#[test]
fn relay_preserves_final_burst_with_pending_input_after_slave_close() {
    let inner = raw_pty();
    let outer = raw_pty();
    nonblocking(outer.slave());
    let (master, slave) = inner.into_parts();
    let mut terminal = std::fs::File::from(outer.master().try_clone_to_owned().unwrap());
    let mut fill = std::fs::File::from(master.as_fd().try_clone_to_owned().unwrap());
    let mut filled = 0;
    loop {
        match fill.write(&[b'x'; 4096]) {
            Ok(count) => {
                filled += count;
                assert!(filled <= 65536);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            result => panic!("unexpected fill result {result:?}"),
        }
    }
    let queued = vec![b'i'; 8192];
    terminal.write_all(&queued).unwrap();
    let expected = vec![b'o'; 32768];
    let cancellation = crate::cancellation::Cancellation::default();
    std::thread::scope(|scope| {
        let producer = scope.spawn(|| {
            let mut payload = std::fs::File::from(slave);
            payload.write_all(&expected).unwrap();
        });
        let run = scope.spawn(|| {
            relay(
                master.as_fd(),
                outer.slave(),
                outer.slave(),
                RelayOptions {
                    buffer_bytes: 8192,
                    deadline: Some(Instant::now() + Duration::from_secs(3)),
                    forward_resize: false,
                },
                &cancellation,
            )
            .unwrap()
        });
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while received.len() < expected.len() && Instant::now() < deadline {
            let mut buffer = [0; 4096];
            match terminal.read(&mut buffer) {
                Ok(count) => received.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                value => panic!("unexpected terminal read {value:?}"),
            }
        }
        let result = run.join().unwrap();
        producer.join().unwrap();
        assert_eq!(received, expected);
        assert_eq!(result.reason, RelayExit::PtyClosed);
        assert_eq!(result.bytes_to_terminal, 32768);
        assert!(
            result.pending_input > 0,
            "input must remain pending when peer closes: {result:?}"
        );
    });
}

#[test]
fn custody_fingerprint_covers_flags_speeds_and_control_characters() {
    let pty = Pty::open(size(), None).unwrap();
    let original = TerminalAttributes::read(pty.slave()).unwrap();
    assert_eq!(
        original.fingerprint(),
        TerminalAttributes::read(pty.slave())
            .unwrap()
            .fingerprint()
    );
    let mut changed = original.clone();
    changed.0.c_cc[libc::VINTR] ^= 1;
    assert_ne!(original.fingerprint(), changed.fingerprint());
    changed = original.clone();
    let input = if original.speeds()[0] == libc::B9600 {
        libc::B19200
    } else {
        libc::B9600
    };
    // SAFETY: the setters update an initialized local termios with valid rates.
    checked(unsafe { libc::cfsetispeed(&raw mut changed.0, input) }).unwrap();
    assert_ne!(original.fingerprint(), changed.fingerprint());
    assert!(!original.matches(&changed));
    changed = original.clone();
    let output = if original.speeds()[1] == libc::B9600 {
        libc::B19200
    } else {
        libc::B9600
    };
    // SAFETY: the setter updates an initialized local termios with a valid rate.
    checked(unsafe { libc::cfsetospeed(&raw mut changed.0, output) }).unwrap();
    assert_ne!(original.fingerprint(), changed.fingerprint());
    assert!(!original.matches(&changed));
    changed = original.clone();
    changed.0.c_lflag ^= libc::ECHO;
    assert_ne!(original.fingerprint(), changed.fingerprint());
}

#[test]
fn relay_without_execution_deadline_polls_control_and_uses_its_own_stop_token() {
    let payload = raw_pty();
    let host = raw_pty();
    nonblocking(host.slave());
    let signals = crate::cancellation::Cancellation::default();
    let relay_stop = crate::cancellation::Cancellation::default();
    let mut ticks = 0;
    let result = relay_with_tick(
        payload.master(),
        host.slave(),
        host.slave(),
        RelayOptions {
            buffer_bytes: 1024,
            deadline: None,
            forward_resize: true,
        },
        &relay_stop,
        || {
            ticks += 1;
            if ticks == 3 {
                relay_stop.cancel();
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(result.reason, RelayExit::Cancelled);
    assert_eq!(ticks, 3);
    assert!(!signals.is_cancelled());
}

#[test]
fn master_validation_requires_real_nonblocking_readwrite_devpts_master() {
    let pty = Pty::open(size(), None).unwrap();
    validate_master(pty.master()).unwrap();
    assert!(validate_master(pty.slave()).is_err());
    assert!(validate_master(tempfile::tempfile().unwrap().as_fd()).is_err());
    assert!(validate_master(std::fs::File::open("/dev/null").unwrap().as_fd()).is_err());
    // SAFETY: this test exclusively owns the PTY OFD; changing its flags cannot
    // affect another process or a user's terminal.
    assert_eq!(
        unsafe {
            libc::fcntl(
                pty.master().as_raw_fd(),
                libc::F_SETFL,
                libc::O_RDWR,
            )
        },
        0
    );
    assert!(validate_master(pty.master()).is_err());
    nonblocking(pty.master());
    validate_master(pty.master()).unwrap();
}

#[test]
fn output_only_relay_drains_pty_without_consuming_redirected_stdin() {
    let outer = raw_pty();
    let inner = raw_pty();
    nonblocking(outer.slave());
    let (master, slave) = inner.into_parts();
    let mut slave = std::fs::File::from(slave);
    slave.write_all(b"output").unwrap();
    drop(slave);
    let mut pipe = [-1; 2];
    // SAFETY: two writable fd slots; successful pipe2 transfers fresh ownership.
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: pipe2 returned distinct, newly owned read and write descriptors.
    let mut input = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(pipe[0]) });
    // SAFETY: ownership of this independent write descriptor is transferred once.
    let mut writer = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(pipe[1]) });
    writer.write_all(b"in").unwrap();
    drop(writer);
    let result = relay_optional_input_with_tick(
        master.as_fd(),
        None,
        outer.slave(),
        RelayOptions {
            buffer_bytes: 64,
            deadline: Some(Instant::now() + Duration::from_secs(2)),
            forward_resize: true,
        },
        &crate::cancellation::Cancellation::default(),
        || Ok(()),
    )
    .unwrap();
    assert_eq!(result.reason, RelayExit::PtyClosed);
    assert_eq!(result.bytes_to_payload, 0);
    assert_eq!(result.bytes_to_terminal, 6);
    let mut unread = [0; 2];
    input.read_exact(&mut unread).unwrap();
    assert_eq!(&unread, b"in");
    let mut output = std::fs::File::from(outer.master().try_clone_to_owned().unwrap());
    let mut bytes = [0; 6];
    output.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"output");
}

#[test]
#[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
fn observed_pause_root_child() {
    std::env::var_os("SYROX_TEST_PAUSE_ROOT")
        .expect("parent test must supply the fixture environment");
    let mut byte = [0];
    let _ = io::stdin().read(&mut byte);
}

#[test]
fn exited_root_abandons_pause_without_foreground_or_terminal_access() {
    let mut child = Command::new(crate::reexec_test_executable(
        "platform::linux::fd::terminal::tests::observed_pause_root_child",
        true,
    ))
    .args([
        "--ignored",
        "--exact",
        "platform::linux::fd::terminal::tests::observed_pause_root_child",
    ])
    .env("SYROX_TEST_PAUSE_ROOT", "1")
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::null())
    .spawn()
    .unwrap();
    let root = crate::platform::linux::fd::pidfd_open(child.id()).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    let not_a_terminal = tempfile::tempfile().unwrap();
    let cancel = crate::cancellation::Cancellation::default();
    assert_eq!(
        suspend_foreground_observed(not_a_terminal.as_fd(), root.as_fd(), &cancel).unwrap(),
        ForegroundPauseOutcome::Abandoned
    );
    assert_eq!(
        pause_observation(root.as_fd(), &cancel, Some(false)).unwrap(),
        Some(ForegroundPauseOutcome::Abandoned)
    );
    assert!(!cancel.is_cancelled());
}

#[test]
fn settled_relay_drains_output_without_consuming_queued_terminal_input() {
    let outer = raw_pty();
    nonblocking(outer.slave());
    let mut user = std::fs::File::from(outer.master().try_clone_to_owned().unwrap());
    user.write_all(b"untouched").unwrap();
    let (master, slave) = raw_pty().into_parts();
    std::fs::File::from(slave)
        .write_all(b"final output")
        .unwrap();
    let cancel = crate::cancellation::Cancellation::default();
    let result = relay_controlled(
        master.as_fd(),
        Some(outer.slave()),
        outer.slave(),
        RelayOptions {
            buffer_bytes: 64,
            deadline: Some(Instant::now() + Duration::from_secs(1)),
            forward_resize: false,
        },
        &cancel,
        || Ok(RelayControl::Drain),
    )
    .unwrap();
    assert_eq!(result.reason, RelayExit::PtyClosed);
    assert_eq!(result.bytes_to_payload, 0);
    assert_eq!(result.bytes_to_terminal, 12);
    assert!(!cancel.is_cancelled());
    let mut original_input = std::fs::File::from(outer.slave().try_clone_to_owned().unwrap());
    let mut bytes = [0; 9];
    original_input.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"untouched");
    let mut output = [0; 12];
    user.read_exact(&mut output).unwrap();
    assert_eq!(&output, b"final output");
}

#[test]
fn terminal_reads_zero_unused_storage_and_keep_semantic_custody_stable() {
    let pty = Pty::open(size(), None).unwrap();
    let original = TerminalAttributes::read(pty.slave()).unwrap();
    for _ in 0..64 {
        let current = TerminalAttributes::read(pty.slave()).unwrap();
        assert!(original.matches(&current));
        assert_eq!(original.fingerprint(), current.fingerprint());
        // Linux x86_64 TCGETS supplies 19 control characters; libc reserves 32.
        #[cfg(target_arch = "x86_64")]
        assert!(
            current.0.c_cc[19..]
                .iter()
                .all(|character| *character == 0)
        );
    }
    #[cfg(target_env = "musl")]
    {
        let mut private_storage = original.clone();
        private_storage.0.__c_ispeed = u32::MAX;
        private_storage.0.__c_ospeed = u32::MAX;
        assert!(original.matches(&private_storage));
        assert_eq!(
            original.fingerprint(),
            private_storage.fingerprint()
        );
    }
}

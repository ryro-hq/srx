#![allow(unsafe_code)] // Dedicated child establishes its own controlling terminal.
use super::*;
use crate::platform::linux::fd::terminal::establish_controlling_terminal;
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::process::Command;
use std::time::Duration;

#[test]
fn redirection_and_unowned_terminal_are_rejected_without_changing_flags() {
    let file = tempfile::tempfile().unwrap();
    let flags = crate::platform::linux::fd::status_flags(file.as_fd()).unwrap();
    assert!(PreparedShellTerminal::prepare(file.as_fd(), file.as_fd()).is_err());
    assert_eq!(
        crate::platform::linux::fd::status_flags(file.as_fd()).unwrap(),
        flags
    );
    let pty = Pty::open(
        WindowSize {
            rows: 24,
            columns: 80,
            x_pixels: 0,
            y_pixels: 0,
        },
        None,
    )
    .unwrap();
    assert!(PreparedShellTerminal::prepare(pty.slave(), pty.slave()).is_err());
}

#[test]
#[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
fn prepared_terminal_child() {
    std::env::var_os("SYROX_PREPARED_TERMINAL_CHILD")
        .expect("parent test must supply the fixture environment");
    let stdin = io::stdin();
    let alias = File::open("/dev/tty").unwrap();
    let flags = crate::platform::linux::fd::status_flags(stdin.as_fd()).unwrap();
    let saved = TerminalAttributes::read(stdin.as_fd()).unwrap();
    let mut prepared = PreparedShellTerminal::prepare(stdin.as_fd(), alias.as_fd()).unwrap();
    assert_eq!(
        crate::platform::linux::fd::status_flags(stdin.as_fd()).unwrap(),
        flags
    );
    assert_ne!(
        crate::platform::linux::fd::status_flags(prepared.input.as_fd()).unwrap()
            & libc::O_NONBLOCK,
        0
    );
    // SAFETY: this is the adapter's exclusive OFD; changing it must not change stdin.
    assert_eq!(
        unsafe {
            libc::fcntl(
                prepared.input.as_raw_fd(),
                libc::F_SETFL,
                flags & !libc::O_NONBLOCK,
            )
        },
        0
    );
    assert_eq!(
        crate::platform::linux::fd::status_flags(stdin.as_fd()).unwrap(),
        flags
    );
    crate::platform::linux::fd::set_nonblocking(prepared.input.as_fd()).unwrap();
    assert_eq!(
        crate::platform::linux::fd::status_flags(stdin.as_fd()).unwrap(),
        flags
    );
    assert!(saved.matches(&TerminalAttributes::read(stdin.as_fd()).unwrap()));
    let slave = prepared.take_slave().unwrap();
    assert!(prepared.take_slave().is_err());
    let resized = WindowSize {
        rows: 43,
        columns: 109,
        x_pixels: 0,
        y_pixels: 0,
    };
    resized.apply(stdin.as_fd()).unwrap();
    let result = prepared
        .relay_local(
            &Cancellation::default(),
            Instant::now() + Duration::from_millis(40),
        )
        .unwrap();
    assert_eq!(result.reason, RelayExit::Deadline);
    assert_eq!(WindowSize::read(slave.as_fd()).unwrap(), resized);
    assert!(saved.matches(&TerminalAttributes::read(stdin.as_fd()).unwrap()));
    let cancel = Cancellation::default();
    let trigger = cancel.clone();
    let cancelling = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        trigger.cancel();
    });
    assert_eq!(
        prepared
            .relay_local(&cancel, Instant::now() + Duration::from_secs(1))
            .unwrap()
            .reason,
        RelayExit::Cancelled
    );
    cancelling.join().unwrap();
    assert!(saved.matches(&TerminalAttributes::read(stdin.as_fd()).unwrap()));
    drop(slave);
    assert_eq!(
        prepared
            .relay_local(
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap()
            .reason,
        RelayExit::PtyClosed
    );
    assert!(saved.matches(&TerminalAttributes::read(stdin.as_fd()).unwrap()));
    exercise_execution_adapter(stdin.as_fd(), alias.as_fd());
}

fn exercise_execution_adapter(input: BorrowedFd<'_>, output: BorrowedFd<'_>) {
    let cancelled = Cancellation::default();
    cancelled.cancel();
    let prepared = PreparedShellTerminal::prepare(input, output).unwrap();
    assert!(matches!(
        prepared.run_with(&cancelled, |_, _, _| panic!(
            "cancelled preflight called runtime"
        )),
        Err(crate::deployment::shell::SessionError::Cancelled)
    ));
    let signals = Cancellation::default();
    let saved = TerminalAttributes::read(input).unwrap();
    let prepared = PreparedShellTerminal::prepare(input, output).unwrap();
    let error = prepared
        .run_with(&signals, |_, _, _| {
            Err(crate::deployment::shell::SessionError::Supervision("prelaunch refused".to_owned()))
        })
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "managed Shell supervision failed: prelaunch refused"
    );
    assert!(!signals.is_cancelled());
    assert!(saved.matches(&TerminalAttributes::read(input).unwrap()));
    let prepared = PreparedShellTerminal::prepare(input, output).unwrap();
    let error = prepared
        .run_with(&signals, |_, _, _| {
            use std::os::unix::process::ExitStatusExt as _;
            Ok(std::process::ExitStatus::from_raw(0))
        })
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("before custody confirmation")
    );
    assert!(!signals.is_cancelled());
    let prepared = PreparedShellTerminal::prepare(input, output).unwrap();
    let error = prepared
        .run_with(&signals, |_, _, _| {
            panic!("controlled runtime panic")
        })
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("runtime thread panicked")
    );
    assert!(!signals.is_cancelled());
    assert!(saved.matches(&TerminalAttributes::read(input).unwrap()));
}

#[test]
fn foreground_preparation_preserves_flags_and_restores_after_relay() {
    let pty = Pty::open(
        WindowSize {
            rows: 24,
            columns: 80,
            x_pixels: 0,
            y_pixels: 0,
        },
        None,
    )
    .unwrap();
    let slave = pty.slave().try_clone_to_owned().unwrap();
    let mut command = Command::new(crate::reexec_test_executable(
        "deployment::shell::terminal::tests::prepared_terminal_child",
        true,
    ));
    command
        .args([
            "--ignored",
            "--exact",
            "deployment::shell::terminal::tests::prepared_terminal_child",
            "--nocapture",
        ])
        .env("SYROX_PREPARED_TERMINAL_CHILD", "1")
        .env("RUST_BACKTRACE", "0");
    // SAFETY: runs only in the dedicated pre-exec child; the owned slave stays live.
    unsafe {
        command.pre_exec(move || establish_controlling_terminal(slave.as_fd()));
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            if !status.success() {
                use std::io::Read as _;
                let mut output = Vec::new();
                let mut reader =
                    File::from(pty.master().try_clone_to_owned().unwrap()).take(64 * 1024);
                let _ = reader.read_to_end(&mut output);
                panic!(
                    "terminal child failed: {status}: {}",
                    String::from_utf8_lossy(&output)
                );
            }
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("terminal child exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

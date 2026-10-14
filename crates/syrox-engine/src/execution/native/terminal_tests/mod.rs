use super::*;
use crate::platform::linux::fd::terminal::{Pty, WindowSize};
use std::time::{Duration, Instant};

mod background;

#[test]
#[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
fn managed_terminal_child_has_session_foreground_and_restored_mask() {
    std::env::var_os("SYROX_MANAGED_TERMINAL_CHILD")
        .expect("parent test must supply the fixture environment");
    // SAFETY: read-only observations on this re-executed test child.
    unsafe {
        let group = libc::getpgrp();
        assert_eq!(libc::getsid(0), libc::getpid());
        assert_eq!(group, libc::getpid());
        for fd in 0..=2 {
            assert_eq!(libc::isatty(fd), 1);
            assert_eq!(libc::tcgetpgrp(fd), group);
        }
        let null = environment::open_null().unwrap();
        assert_eq!(libc::dup2(null.as_raw_fd(), 0), 0);
        assert_eq!(libc::isatty(0), 0);
        let controlling = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .unwrap();
        assert_eq!(libc::tcgetpgrp(controlling.as_raw_fd()), group);
        let mut mask: libc::sigset_t = std::mem::zeroed();
        assert_eq!(
            libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut mask),
            0
        );
        for signal in [
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGHUP,
            libc::SIGCHLD,
        ] {
            assert_eq!(libc::sigismember(&raw const mask, signal), 0);
        }
    }
}

#[test]
fn managed_terminal_setup_executes_without_reassigning_session_leader_group() {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let terminal = Pty::open(
        WindowSize {
            rows: 24,
            columns: 80,
            x_pixels: 0,
            y_pixels: 0,
        },
        None,
    )
    .unwrap();
    let slave = terminal.slave().try_clone_to_owned().unwrap();
    // SAFETY: sigemptyset initializes writable ABI-sized storage.
    let original = unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigemptyset(&raw mut mask), 0);
        mask
    };
    let mut command = Command::new(crate::reexec_test_executable(
        "execution::native::terminal_tests::managed_terminal_child_has_session_foreground_and_restored_mask",
        true,
    ));
    command.args([
        "--ignored", "--exact",
        "execution::native::terminal_tests::managed_terminal_child_has_session_foreground_and_restored_mask",
        "--nocapture",
    ]).env("SYROX_MANAGED_TERMINAL_CHILD", "1");
    // SAFETY: callback uses only descriptor/session/signal syscalls in the
    // dedicated pre-exec child; owned slave remains live until spawn completes.
    unsafe {
        command.pre_exec(move || configure_payload_child(Some(slave.as_raw_fd()), Some(original)));
    }
    let mut child = Child(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "managed PTY child assertions failed"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "managed PTY child deadline elapsed"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

use super::*;
use crate::platform::linux::fd::PreparedLaunch;

const MARKER: &str = "SYROX_BACKGROUND_TERMINAL_PROOF";
const SESSION: &str = "execution::native::terminal_tests::background::session_fixture";
const MONITOR: &str = "execution::native::terminal_tests::background::background_fixture";

struct Monitor {
    pidfd: Option<std::os::fd::OwnedFd>,
    pid: i32,
    reaped: bool,
}
impl Drop for Monitor {
    fn drop(&mut self) {
        if !self.reaped {
            if let Some(pidfd) = &self.pidfd {
                let _ = crate::platform::linux::fd::kill_pidfd(pidfd.as_fd());
            } else {
                // SAFETY: immediate post-spawn guard; this direct child has
                // not been waited for, so its numeric PID cannot be reused.
                unsafe {
                    libc::kill(self.pid, libc::SIGKILL);
                }
            }
            // SAFETY: waitpid only reaps this direct child. The signal above
            // uses a pinned process handle, never a potentially recycled PID.
            while unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) } < 0 {
                if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
        }
    }
}

struct Session(std::process::Child);
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn attributes(fd: i32) -> libc::termios {
    // SAFETY: tcgetattr initializes valid termios storage for this live fd.
    unsafe {
        let mut value: libc::termios = std::mem::zeroed();
        assert_eq!(libc::tcgetattr(fd, &raw mut value), 0);
        value
    }
}

#[test]
#[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
fn background_fixture() {
    std::env::var_os(MARKER).expect("parent test must supply the fixture environment");
    // SAFETY: this isolated fixture arranges death with its session parent.
    // The session ID survives parent death and closes the setup race.
    unsafe {
        let expected_parent = libc::getsid(0);
        assert_eq!(
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0),
            0
        );
        assert_eq!(libc::getppid(), expected_parent);
    }
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .unwrap();
    let fd = tty.as_raw_fd();
    // SAFETY: observations and signal-mask/ioctl operations affect only this
    // isolated re-executed fixture, never the parallel parent test harness.
    unsafe {
        assert_eq!(libc::getsid(0), libc::getppid());
        assert_eq!(libc::getpgrp(), libc::getpid());
        assert_ne!(libc::tcgetpgrp(fd), libc::getpgrp());
        assert_eq!(libc::tcgetpgrp(fd), libc::getppid());
        let mut mask: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigemptyset(&raw mut mask), 0);
        assert_eq!(libc::sigaddset(&raw mut mask, libc::SIGTTOU), 0);
        assert_eq!(
            libc::sigprocmask(
                libc::SIG_BLOCK,
                &raw const mask,
                std::ptr::null_mut()
            ),
            0
        );
        let mut restored = attributes(fd);
        restored.c_lflag ^= libc::ECHO;
        assert_eq!(
            libc::tcsetattr(fd, libc::TCSANOW, &raw const restored),
            0
        );
        assert_eq!(libc::tcgetpgrp(fd), libc::getppid());
    }
}

#[test]
#[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
fn session_fixture() {
    std::env::var_os(MARKER).expect("parent test must supply the fixture environment");
    let before = attributes(0);
    let mut changed = before;
    changed.c_lflag ^= libc::ECHO;
    // SAFETY: this isolated session owns its synthetic controlling terminal.
    assert_eq!(
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw const changed) },
        0
    );
    let executable = crate::reexec_test_executable(MONITOR, true);
    let mut launch = PreparedLaunch::new(executable.as_os_str()).unwrap();
    launch
        .args([
            "--ignored",
            "--exact",
            MONITOR,
            "--nocapture",
        ])
        .unwrap();
    let mut child = launch.spawn().unwrap();
    let mut monitor = Monitor {
        pidfd: None,
        pid: i32::try_from(child.id()).unwrap(),
        reaped: false,
    };
    monitor.pidfd = Some(crate::platform::linux::fd::pidfd_open(child.id()).unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            monitor.reaped = true;
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "background restorer timed out"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let restored = attributes(0);
    assert_eq!(before.c_lflag, restored.c_lflag);
    assert_eq!(before.c_iflag, restored.c_iflag);
    assert_eq!(before.c_oflag, restored.c_oflag);
    assert_eq!(before.c_cflag, restored.c_cflag);
    assert_eq!(before.c_cc, restored.c_cc);
}

#[test]
fn existing_monitor_spawn_preserves_tty_observation_and_background_restore() {
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
    let unrelated = Pty::open(
        WindowSize {
            rows: 30,
            columns: 100,
            x_pixels: 0,
            y_pixels: 0,
        },
        None,
    )
    .unwrap();
    let other_before = attributes(unrelated.slave().as_raw_fd());
    let slave = terminal.slave().try_clone_to_owned().unwrap();
    let mut command = Command::new(crate::reexec_test_executable(SESSION, true));
    command
        .args([
            "--ignored",
            "--exact",
            SESSION,
            "--nocapture",
        ])
        .env(MARKER, "1");
    // SAFETY: only async-signal-safe session/descriptor syscalls run pre-exec;
    // the owned descriptor remains valid for the entire callback.
    unsafe {
        command.pre_exec(move || configure_payload_child(Some(slave.as_raw_fd()), None));
    }
    let mut session = Session(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = session.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "session fixture timed out"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let other_after = attributes(unrelated.slave().as_raw_fd());
    assert_eq!(other_before.c_lflag, other_after.c_lflag);
    assert_eq!(other_before.c_cc, other_after.c_cc);
}

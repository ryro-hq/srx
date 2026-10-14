use super::{Event, SignalFd, wait_payload};
use std::io::{self, Read as _};
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const ROLE: &str = "SYROX_PROXY_TEST_ROLE";
const TEST: &str = "execution::native::proxy::tests::isolated_fixture";

#[test]
fn codec_preserves_signal_status_separately_from_exit_137() {
    let exited = ExitStatus::from_raw(137 << 8);
    let killed = ExitStatus::from_raw(libc::SIGKILL);
    assert_ne!(
        Event::Exited(exited).encode(),
        Event::Exited(killed).encode()
    );
    assert_eq!(exited.code(), Some(137));
    assert_eq!(killed.signal(), Some(libc::SIGKILL));
    for event in [
        Event::Exec,
        Event::Stopped(libc::SIGSTOP),
        Event::Continued,
        Event::Exited(exited),
        Event::Exited(killed),
        Event::Exited(ExitStatus::from_raw(0)),
    ] {
        assert_eq!(Event::decode(event.encode()).unwrap(), event);
    }
    for bytes in [
        [b'e', 1, 0, 0, 0],
        [b'c', 1, 0, 0, 0],
        [b's', 0, 0, 0, 0],
        [b's', 65, 0, 0, 0],
        [b'?', 0, 0, 0, 0],
        [b'x', 0x7f, 0x13, 0, 0],
        [b'x', 0xff, 0xff, 0, 0],
    ] {
        assert!(
            Event::decode(bytes).is_err(),
            "invalid event {bytes:?}"
        );
    }
}

struct Reaped(Child);
impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn command(role: &str) -> Command {
    let mut command = Command::new(crate::reexec_test_executable(TEST, true));
    command
        .args([
            "--ignored",
            "--exact",
            TEST,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROLE, role);
    command
}
fn isolated(role: &str) {
    let mut child = Reaped(command(role).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "isolated {role}: {status}");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "isolated {role} deadline"
        );
        // Polling delay only; success requires observed process exit.
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn event(channel: &mut UnixStream) -> io::Result<Event> {
    let deadline = Instant::now() + Duration::from_secs(5);
    channel.set_nonblocking(true)?;
    let mut bytes = [0; 5];
    let mut offset = 0;
    while offset < bytes.len() {
        match channel.read(&mut bytes[offset..]) {
            Ok(0) => return Err(io::Error::other("private event EOF")),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::other("private event deadline"));
                }
                super::super::managed::poll(&[channel.as_fd()], 20)?;
            }
            Err(error) => return Err(error),
        }
    }
    Event::decode(bytes)
}
fn principal(signals: &SignalFd, role: &str) -> Child {
    let original = signals.original();
    // SAFETY: getpid has no pointer arguments.
    let parent = unsafe { libc::getpid() };
    let mut child = command(role);
    child.stdin(Stdio::piped()).stdout(Stdio::null());
    // SAFETY: child-only async-signal-safe syscalls before exec. The isolated
    // owner is the only process allowed to collect this child's status.
    unsafe {
        child.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                || libc::getppid() != parent
                || libc::setpgid(0, 0) < 0
                || libc::sigprocmask(
                    libc::SIG_SETMASK,
                    &raw const original,
                    std::ptr::null_mut(),
                ) < 0
            {
                return Err(io::Error::other("principal setup failed"));
            }
            Ok(())
        });
    }
    child.spawn().unwrap()
}

#[test]
#[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
fn isolated_fixture() {
    let role = std::env::var(ROLE).expect("parent test must supply the fixture environment");
    if role == "principal-exit" {
        std::process::exit(137);
    }
    if role == "principal-wait" {
        let mut byte = [0];
        loop {
            match io::stdin().read(&mut byte) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                _ => break,
            }
        }
        std::process::exit(125);
    }
    let signals = SignalFd::new().unwrap();
    let (local, mut remote) = UnixStream::pair().unwrap();
    let child = principal(
        &signals,
        if role == "exit" {
            "principal-exit"
        } else {
            "principal-wait"
        },
    );
    let pid = i32::try_from(child.id()).unwrap();
    let broker_role = role.clone();
    let broker = std::thread::spawn(move || -> io::Result<()> {
        assert_eq!(event(&mut remote)?, Event::Exec);
        if broker_role == "eof" {
            return Ok(());
        }
        if broker_role == "signal" {
            // This fixture observes process status outside a PID namespace.
            // Its owner signals its unreaped child directly; the production
            // proxy channel retains the requirement that its init be PID 1.
            // SAFETY: pid identifies the owned, unreaped principal. The exec
            // event has been observed and no exit event has been consumed.
            super::super::checked(unsafe { libc::kill(pid, libc::SIGSTOP) }.into())?;
            assert_eq!(event(&mut remote)?, Event::Stopped(libc::SIGSTOP));
            // SAFETY: the same owned principal is stopped and unreaped.
            super::super::checked(unsafe { libc::kill(pid, libc::SIGCONT) }.into())?;
            assert_eq!(event(&mut remote)?, Event::Continued);
            // SAFETY: the continued principal remains owned and unreaped.
            super::super::checked(unsafe { libc::kill(pid, libc::SIGKILL) }.into())?;
        }
        let Event::Exited(status) = event(&mut remote)? else {
            panic!("missing exit event")
        };
        if broker_role == "signal" {
            assert_eq!(status.signal(), Some(libc::SIGKILL));
            assert_eq!(status.code(), None);
        } else {
            assert_eq!(status.code(), Some(137));
            assert_eq!(status.signal(), None);
        }
        Ok(())
    });
    let result = wait_payload(child, local, &signals);
    if result
        .as_ref()
        .is_err_and(|error| error.raw_os_error() == Some(libc::EPERM))
    {
        let (mut probe, _receiver) = UnixStream::pair().unwrap();
        probe.set_nonblocking(true).unwrap();
        eprintln!(
            "isolated wait_payload EPERM; independent Event::Exec send diagnostic: {:?}",
            super::send(&mut probe, Event::Exec)
        );
    }
    // Always join: a protocol error still closes the channel and reaps principal.
    let broker_result = broker.join().unwrap();
    // SAFETY: isolated test process owns only this principal; this targeted
    // wait observes cleanup without sending a signal to a possibly reused PID.
    let remaining = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
    let wait_error = io::Error::last_os_error();
    assert_eq!(remaining, -1);
    assert_eq!(wait_error.raw_os_error(), Some(libc::ECHILD));
    if role == "eof" {
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.to_string().contains("disconnected")),
            "{result:?}"
        );
    } else {
        let status = result.unwrap();
        if role == "signal" {
            assert_eq!(status.signal(), Some(libc::SIGKILL));
        } else {
            assert_eq!(status.code(), Some(137));
        }
    }
    broker_result.unwrap();
}

#[test]
fn exit_137_is_reported_as_exit_not_signal() {
    isolated("exit");
}
#[test]
fn stopped_continued_and_signal_exit_are_distinct_events() {
    isolated("signal");
}
#[test]
fn channel_eof_kills_and_reaps_the_principal() {
    isolated("eof");
}

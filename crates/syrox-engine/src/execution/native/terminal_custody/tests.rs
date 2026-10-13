use super::*;
use crate::platform::linux::fd::terminal::{Pty, WindowSize};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const MODE: &str = "SYROX_CUSTODY_FIXTURE_MODE";
const HEADER: &str = "SYROX_CUSTODY_FIXTURE_HEADER";
const BASE: &str = "execution::native::terminal_custody::tests::";

struct Reaped(Child);
impl Reaped {
    fn finish(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "custody child failed: {status}");
                return;
            }
            assert!(
                Instant::now() < deadline,
                "custody child deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn command(test: &str) -> Command {
    let mut command = Command::new(crate::reexec_test_executable(
        &format!("{BASE}{test}"),
        true,
    ));
    command.args([
        "--ignored",
        "--exact",
        &format!("{BASE}{test}"),
        "--nocapture",
    ]);
    command
}

fn monitor(mode: &str, remote: &UnixStream, tty: BorrowedFd<'_>) -> Reaped {
    let identity = frontend_identity().unwrap();
    let device = crate::platform::linux::fd::terminal::foreground_terminal(tty).unwrap();
    let header = [
        remote.as_raw_fd().to_string(),
        tty.as_raw_fd().to_string(),
        identity[0].to_string(),
        identity[1].to_string(),
        identity[2].to_string(),
        device.to_string(),
    ]
    .join(",");
    let mut child = command("monitor_fixture");
    child.env(MODE, mode).env(HEADER, header);
    let channel = remote.as_raw_fd();
    let tty = tty.as_raw_fd();
    // SAFETY: only the dedicated child changes group and inherited fd flags.
    unsafe {
        child.pre_exec(move || {
            checked(libc::setpgid(0, 0).into())?;
            checked(libc::fcntl(channel, libc::F_SETFD, 0).into())?;
            checked(libc::fcntl(tty, libc::F_SETFD, 0).into())
        });
    }
    Reaped(child.spawn().unwrap())
}

fn bounded_read(channel: &mut UnixStream, mut output: &mut [u8]) {
    channel.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !output.is_empty() {
        match channel.read(output) {
            Ok(0) => panic!("protocol EOF before complete record"),
            Ok(count) => output = &mut output[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "protocol read deadline"
                );
                ready(channel.as_fd(), 20).unwrap();
            }
            Err(error) => panic!("protocol read: {error}"),
        }
    }
}

fn ready_message(channel: &mut UnixStream, original: &TerminalAttributes) {
    let mut ready = [0; 33];
    bounded_read(channel, &mut ready);
    assert_eq!(ready[0], b'R');
    assert_eq!(&ready[1..], original.fingerprint().as_bytes());
}

#[test]
#[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
fn monitor_fixture() {
    let mode = std::env::var(MODE).expect("parent test must supply the fixture environment");
    let header: Vec<OsString> = std::env::var(HEADER)
        .unwrap()
        .split(',')
        .map(Into::into)
        .collect();
    // The protocol watches the parent's pidfd; killing it with PDEATHSIG would
    // defeat the restoration being proved. This child has no descendants and
    // receive/EOF or the parent's explicit guard always terminates it.
    let result = unsafe { Custody::receive(&header, &[]) };
    if let Err(error) = &result {
        eprintln!("custody receive ({mode}): {error}");
    }
    match mode.as_str() {
        "eof-ready" | "death-ready" => assert!(result.is_err()),
        "crossed-abort" => {
            let mut custody = result.unwrap();
            assert!(custody.activated());
            custody.namespace_settled().unwrap();
            assert!(custody.restored);
        }
        "eof-active" => {
            let mut custody = result.unwrap();
            assert!(custody.accept_abort().is_err());
            drop(custody);
        }
        "disarm" => {
            let mut custody = result.unwrap();
            custody.disarm_child();
            drop(custody);
        }
        _ => panic!("unknown custody fixture mode"),
    }
}

#[test]
#[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
fn session_fixture() {
    let mode = std::env::var(MODE).expect("parent test must supply the fixture environment");
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .unwrap();
    let original = TerminalAttributes::read(tty.as_fd()).unwrap();
    if mode == "death-ready" {
        death_before_activation(&tty, &original);
        return;
    }
    let (mut local, remote) = UnixStream::pair().unwrap();
    let mut child = monitor(&mode, &remote, tty.as_fd());
    drop(remote);
    ready_message(&mut local, &original);
    original.raw().apply(tty.as_fd()).unwrap();
    match mode.as_str() {
        "eof-ready" => drop(local),
        "crossed-abort" => {
            local.write_all(b"A").unwrap();
            let mut byte = [0];
            bounded_read(&mut local, &mut byte);
            assert_eq!(byte, *b"S");
            // B crosses a settlement already sent: it must not consume F's role.
            local.write_all(b"BF").unwrap();
            bounded_read(&mut local, &mut byte);
            assert_eq!(byte, *b"D");
        }
        "eof-active" => {
            local.write_all(b"A").unwrap();
            drop(local);
        }
        "disarm" => {
            local.write_all(b"A").unwrap();
        }
        _ => panic!("unknown session mode"),
    }
    child.finish();
    let after = TerminalAttributes::read(tty.as_fd()).unwrap();
    if mode == "disarm" {
        assert!(
            after.matches(&original.raw()),
            "init-copy drop restored terminal"
        );
        original.apply(tty.as_fd()).unwrap();
    } else {
        assert!(
            after.matches(&original),
            "custody failed to restore saved attributes"
        );
    }
}

fn isolated(mode: &str) {
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
    let mut child = command("session_fixture");
    child.env(MODE, mode);
    // SAFETY: read-only PID query before spawning the dedicated child.
    let parent = unsafe { libc::getpid() };
    // SAFETY: this dedicated test child alone acquires its synthetic tty.
    unsafe {
        child.pre_exec(move || {
            checked(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0).into())?;
            if libc::getppid() != parent {
                return Err(io::Error::other("test parent died"));
            }
            crate::platform::linux::fd::terminal::establish_controlling_terminal(slave.as_fd())
        });
    }
    let mut child = Reaped(child.spawn().unwrap());
    let mut transcript = Vec::new();
    let mut master = std::fs::File::from(pty.master().try_clone_to_owned().unwrap());
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let mut bytes = [0; 4096];
        loop {
            match master.read(&mut bytes) {
                Ok(0) => break,
                Ok(count) => {
                    assert!(
                        transcript.len() + count <= 64 * 1024,
                        "fixture diagnostic overflow"
                    );
                    transcript.extend_from_slice(&bytes[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => panic!("fixture PTY read: {error}"),
            }
        }
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "custody fixture {mode}: {status}\n{}",
                String::from_utf8_lossy(&transcript)
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fixture timed out: {}",
            String::from_utf8_lossy(&transcript)
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn abort_crossing_namespace_settled_still_requires_restore_request() {
    isolated("crossed-abort");
}
#[test]
fn eof_after_raw_before_activation_restores() {
    isolated("eof-ready");
}
#[test]
fn eof_after_activation_restores() {
    isolated("eof-active");
}
#[test]
fn disarmed_init_copy_does_not_restore() {
    isolated("disarm");
}

struct Adopted(OwnedFd);
impl Drop for Adopted {
    fn drop(&mut self) {
        let _ = crate::platform::linux::fd::kill_pidfd(self.0.as_fd());
        let _ = reap_monitor(self.0.as_fd());
    }
}

#[test]
#[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
fn dying_frontend_fixture() {
    assert_eq!(
        std::env::var(MODE).as_deref(),
        Ok("death-ready"),
        "parent test must select the death-ready fixture"
    );
    let report_fd: i32 = std::env::var("SYROX_CUSTODY_REPORT")
        .unwrap()
        .parse()
        .unwrap();
    // SAFETY: the isolated parent transferred this distinct live report socket.
    let mut report = unsafe { UnixStream::from_raw_fd(report_fd) };
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .unwrap();
    let original = TerminalAttributes::read(tty.as_fd()).unwrap();
    let (mut local, remote) = UnixStream::pair().unwrap();
    let child = monitor("death-ready", &remote, tty.as_fd());
    drop(remote);
    ready_message(&mut local, &original);
    original.raw().apply(tty.as_fd()).unwrap();
    report
        .write_all(&child.0.id().to_le_bytes())
        .unwrap();
    // The anchor SIGKILLs this process after receiving the monitor identity.
    // Keep all guards alive: only remote custody can restore after that signal.
    let mut byte = [0];
    let result = report.read_exact(&mut byte);
    panic!("frontend must be killed before activation: {result:?}");
}

fn death_before_activation(tty: &std::fs::File, original: &TerminalAttributes) {
    // SAFETY: only this re-executed fixture adopts its orphaned monitor child.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let (mut report, sent) = UnixStream::pair().unwrap();
    let fd = sent.as_raw_fd();
    let parent = unsafe { libc::getpid() };
    let mut frontend = command("dying_frontend_fixture");
    frontend
        .env(MODE, "death-ready")
        .env("SYROX_CUSTODY_REPORT", fd.to_string());
    // Keep the anchor's SID and foreground pgrp; a session leader's death would
    // revoke its terminal and would not test a surviving external session.
    unsafe {
        frontend.pre_exec(move || {
            checked(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0).into())?;
            if libc::getppid() != parent {
                return Err(io::Error::other("anchor died"));
            }
            checked(libc::fcntl(fd, libc::F_SETFD, 0).into())
        });
    }
    let mut frontend = Reaped(frontend.spawn().unwrap());
    drop(sent);
    let mut bytes = [0; 4];
    bounded_read(&mut report, &mut bytes);
    let adopted =
        Adopted(crate::platform::linux::fd::pidfd_open(u32::from_le_bytes(bytes)).unwrap());
    // std::Child still owns this unreaped direct child; kill cannot target a
    // recycled PID. Its guard also reaps on every failure below.
    frontend.0.kill().unwrap();
    let killed = frontend.0.wait().unwrap();
    assert_eq!(killed.signal(), Some(libc::SIGKILL));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !crate::platform::linux::fd::pidfd_exited(adopted.0.as_fd()).unwrap() {
        assert!(
            Instant::now() < deadline,
            "orphan monitor did not finish restoration"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    reap_monitor(adopted.0.as_fd()).unwrap();
    assert!(original.matches(&TerminalAttributes::read(tty.as_fd()).unwrap()));
}

#[test]
fn frontend_death_between_raw_and_activation_restores_in_surviving_session() {
    isolated("death-ready");
}

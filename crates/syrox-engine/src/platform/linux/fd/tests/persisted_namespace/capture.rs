#![allow(unsafe_code)] // Audited pre-exec syscalls and syscall-only clone child.

use super::*;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

const TEST: &str = "platform::linux::fd::persisted_namespace::tests::capture::namespace_record_survives_descriptor_close_and_observes_real_init_exit";
const MARKER: &str = "SYROX_NAMESPACE_CAPTURE_REEXEC";

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

struct Reexec(std::process::Child);
impl Drop for Reexec {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// Called only before exec. Strings and mapping bytes are prepared in the parent.
fn write_mapping(path: &std::ffi::CStr, bytes: &[u8]) -> io::Result<()> {
    // SAFETY: fixed NUL-terminated path; no allocator or locks after fork.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut offset = 0;
    let result = loop {
        if offset == bytes.len() {
            break Ok(());
        }
        // SAFETY: immutable parent-prepared bytes remain live in the child.
        let count = unsafe {
            libc::write(
                fd,
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break Err(error);
        }
        if count == 0 {
            break Err(io::Error::from_raw_os_error(libc::EIO));
        }
        offset += usize::try_from(count).expect("positive syscall count");
    };
    // SAFETY: fd is owned by this callback; preserve any primary write failure.
    let closed = unsafe { libc::close(fd) };
    result?;
    if closed < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn reexec(test: &str) -> bool {
    if std::env::var_os(MARKER).is_some() {
        return false;
    }
    let uid = crate::platform::linux::fd::effective_uid();
    let gid = crate::platform::linux::fd::effective_gid();
    let uid_map = format!("0 {uid} 1\n").into_bytes();
    let gid_map = format!("0 {gid} 1\n").into_bytes();
    let mut command = Command::new(crate::reexec_test_executable(test, false));
    command
        .args([
            "--exact",
            test,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MARKER, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    // SAFETY: only namespace/open/write/close syscalls and fixed error values;
    // no formatting, heap allocation, destructor execution or Rust payload here.
    unsafe {
        command.pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWUSER) < 0 {
                return Err(io::Error::last_os_error());
            }
            write_mapping(c"/proc/self/setgroups", b"deny")?;
            write_mapping(c"/proc/self/uid_map", &uid_map)?;
            write_mapping(c"/proc/self/gid_map", &gid_map)
        });
    }
    let mut child = Reexec(
        command
            .spawn()
            .expect("real user namespace preflight"),
    );
    let limit = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "real namespace capture assertions failed"
            );
            let mut stdout = Vec::new();
            io::Read::read_to_end(&mut child.0.stdout.take().unwrap(), &mut stdout).unwrap();
            crate::assert_reexec_result(&stdout, test);
            return true;
        }
        assert!(
            Instant::now() < limit,
            "namespace capture subprocess timeout"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub(crate) struct Init {
    pub(crate) pid: libc::pid_t,
    reaped: bool,
}
impl Init {
    pub(crate) fn wait(&mut self) {
        let limit = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            // SAFETY: this direct child has not been reaped or handed elsewhere.
            let result = unsafe { libc::waitpid(self.pid, &raw mut status, libc::WNOHANG) };
            if result == self.pid {
                self.reaped = true;
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 0);
                return;
            }
            if result < 0 {
                assert_eq!(
                    io::Error::last_os_error().kind(),
                    io::ErrorKind::Interrupted
                );
            }
            assert!(
                Instant::now() < limit,
                "namespace init failed to exit"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Init {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // SAFETY: unreaped direct child pins this PID even before pidfd_open.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        loop {
            // SAFETY: this guard is the sole waiter for its direct child.
            let result = unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) };
            if result >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
    }
}

pub(crate) fn spawn_init() -> (Init, OwnedFd) {
    let mut pipe = [-1; 2];
    // SAFETY: writable descriptor pair, transferred immediately into owned FDs.
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    let (reader, writer) = unsafe {
        (
            OwnedFd::from_raw_fd(pipe[0]),
            OwnedFd::from_raw_fd(pipe[1]),
        )
    };
    // SAFETY: fork-like clone without shared memory. The child below performs
    // only close/getpid/read/_exit syscalls: no Rust allocation, unwind or Drop.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::CLONE_NEWPID | libc::SIGCHLD,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
            0,
        )
    };
    if pid == 0 {
        // SAFETY: syscall-only child branch, never returns into the harness.
        unsafe {
            libc::close(pipe[1]);
            if libc::getpid() != 1 {
                libc::_exit(91);
            }
            let mut byte = 0_u8;
            loop {
                let count = libc::read(pipe[0], (&raw mut byte).cast(), 1);
                if count == 1 {
                    if byte == b'G' {
                        continue;
                    }
                    libc::_exit(if byte == b'X' {
                        0
                    } else {
                        92
                    });
                }
                if count == 0 {
                    libc::_exit(93);
                }
                if *libc::__errno_location() != libc::EINTR {
                    libc::_exit(94);
                }
            }
        }
    }
    assert!(
        pid > 0,
        "real PID namespace clone: {}",
        io::Error::last_os_error()
    );
    let child = Init {
        pid: libc::pid_t::try_from(pid).expect("kernel PID fits pid_t"),
        reaped: false,
    };
    drop(reader);
    (child, writer)
}

#[test]
fn namespace_record_survives_descriptor_close_and_observes_real_init_exit() {
    if reexec(TEST) {
        return;
    }
    let cancel = Cancellation::default();
    let (mut child, gate) = spawn_init();
    let record = {
        let descriptor = pidfd_open(child.pid.cast_unsigned()).unwrap();
        let captured = CapturedNamespace::capture(descriptor.as_fd(), &cancel, deadline()).unwrap();
        captured.revalidate(&cancel, deadline()).unwrap();
        let encoded = serde_json::to_vec(captured.record()).unwrap();
        assert!(serde_json::from_slice::<LauncherRecord>(&encoded).is_err());
        serde_json::from_slice::<NamespaceRecord>(&encoded).unwrap()
        // Both original and captured pidfds close here while init remains gated.
    };
    assert!(
        record
            .observe_exit(&cancel, deadline())
            .unwrap()
            .is_none()
    );
    // SAFETY: owned pipe writer; one-byte release is not an execution payload.
    assert_eq!(
        unsafe { libc::write(gate.as_raw_fd(), b"X".as_ptr().cast(), 1) },
        1
    );
    drop(gate);
    child.wait();
    let proof = record
        .observe_exit(&cancel, deadline())
        .unwrap()
        .expect("reaped real init");
    assert!(proof.matches(&record));
}

#[test]
fn historical_inventory_requires_each_real_namespace_to_exit() {
    const INVENTORY_TEST: &str = "platform::linux::fd::persisted_namespace::tests::capture::historical_inventory_requires_each_real_namespace_to_exit";
    if reexec(INVENTORY_TEST) {
        return;
    }
    let cancel = Cancellation::default();
    let (mut first, first_gate) = spawn_init();
    let first_record = capture_record(&first, &cancel);
    let (mut second, second_gate) = spawn_init();
    let second_record = capture_record(&second, &cancel);
    // No init pidfd remains open. The inventory is durable data, not a live FD set.
    let bytes = serde_json::to_vec(&[first_record, second_record]).unwrap();
    let records: [NamespaceRecord; 2] = serde_json::from_slice(&bytes).unwrap();
    for record in &records {
        assert!(
            record
                .observe_exit(&cancel, deadline())
                .unwrap()
                .is_none()
        );
    }

    release_init(&mut first, first_gate);
    let first_proof = records[0]
        .observe_exit(&cancel, deadline())
        .unwrap()
        .expect("first historical init exited");
    assert!(first_proof.matches(&records[0]));
    assert!(!first_proof.matches(&records[1]));
    assert!(
        records[1]
            .observe_exit(&cancel, deadline())
            .unwrap()
            .is_none()
    );

    release_init(&mut second, second_gate);
    let second_proof = records[1]
        .observe_exit(&cancel, deadline())
        .unwrap()
        .expect("second historical init exited");
    assert!(second_proof.matches(&records[1]));
    assert!(!second_proof.matches(&records[0]));
    assert!(
        records[0]
            .observe_exit(&cancel, deadline())
            .unwrap()
            .is_some()
    );
}

fn capture_record(child: &Init, cancel: &Cancellation) -> NamespaceRecord {
    let descriptor = pidfd_open(child.pid.cast_unsigned()).unwrap();
    let captured = CapturedNamespace::capture(descriptor.as_fd(), cancel, deadline()).unwrap();
    captured.revalidate(cancel, deadline()).unwrap();
    captured.record().clone()
}

fn release_init(child: &mut Init, gate: OwnedFd) {
    // SAFETY: owned pipe writer; the syscall-only init accepts one exit byte.
    assert_eq!(
        unsafe { libc::write(gate.as_raw_fd(), b"X".as_ptr().cast(), 1) },
        1
    );
    drop(gate);
    child.wait();
}

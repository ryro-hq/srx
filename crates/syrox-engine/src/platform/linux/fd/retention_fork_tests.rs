use super::*;
use crate::{store::ContentDigest, store::GcRequest, store::Store};
use std::fs::File;
use std::time::{Duration, Instant};

fn pipe() -> (File, File) {
    let mut descriptors = [-1; 2];
    // SAFETY: writable two-element array; successful pipe2 transfers both FDs.
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: successful pipe2 produced two distinct descriptors owned here.
    unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        )
    }
}
struct Child(libc::pid_t);
impl Child {
    fn wait(&mut self, deadline: Instant) -> i32 {
        let mut status = 0;
        loop {
            // SAFETY: only this guard owns the unreaped child PID.
            let result = unsafe { libc::waitpid(self.0, &raw mut status, libc::WNOHANG) };
            if result == self.0 {
                self.0 = 0;
                return status;
            }
            if result < 0 {
                assert_eq!(
                    io::Error::last_os_error().kind(),
                    io::ErrorKind::Interrupted
                );
            }
            assert!(
                Instant::now() < deadline,
                "forked child deadline elapsed"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: unreaped child cannot be replaced by another process.
            unsafe { libc::kill(self.0, libc::SIGKILL) };
            let mut status = 0;
            // SAFETY: after SIGKILL reap the same uniquely owned child.
            while unsafe { libc::waitpid(self.0, &raw mut status, 0) } < 0 {
                if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
        }
    }
}
fn receive(file: &mut File, deadline: Instant) {
    let timeout = deadline
        .saturating_duration_since(Instant::now())
        .as_millis();
    let mut descriptor = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: live descriptor, valid single-element writable array.
    assert_eq!(
        unsafe {
            libc::poll(
                &raw mut descriptor,
                1,
                i32::try_from(timeout).unwrap(),
            )
        },
        1
    );
    assert_ne!(descriptor.revents & libc::POLLIN, 0);
    file.read_exact(&mut [0]).unwrap();
}
fn collect(store: &Store) -> crate::store::GcReport {
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap()
}

#[test]
fn forked_child_retains_an_unrelated_cloexec_interest_until_exit() {
    if isolate_test(
        "platform::linux::fd::retention_fork_tests::forked_child_retains_an_unrelated_cloexec_interest_until_exit",
        "SYROX_FORK_RETENTION_ISOLATED",
    ) {
        return;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::initialize(&temporary.path().join("store")).unwrap();
    let operation = store.operation().unwrap();
    let digest = ContentDigest::sha256(b"forked retention");
    operation
        .ingest(&b"forked retention"[..], digest, 16)
        .unwrap();
    let interest = operation.retain_objects(&[digest], &[]).unwrap();
    let process = interest.process_retention().unwrap();
    // SAFETY: F_GETFD only inspects this live descriptor.
    assert_ne!(
        unsafe { libc::fcntl(process.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    drop(operation);
    let (mut ready, ready_writer) = pipe();
    let (release_reader, mut release) = pipe();
    let ready_fd = ready_writer.as_raw_fd();
    let release_fd = release_reader.as_raw_fd();
    let mut child = fork_waiting(ready_fd, release_fd);
    receive(&mut ready, deadline);
    drop((interest, process));
    assert!(
        collect(&store).removed_objects.is_empty(),
        "the child still owns the inherited process OFD"
    );
    release.write_all(b"x").unwrap();
    assert_eq!(child.wait(deadline), 0);
    assert_eq!(collect(&store).removed_objects, [digest]);
}

/// Caller must first isolate its harness; the child holds inherited descriptors
/// without running Rust code until the parent callback finishes. Cleanup also
/// kills/reaps the child if the callback panics.
pub(crate) fn with_forked_descriptors(while_child_holds: impl FnOnce()) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut ready, ready_writer) = pipe();
    let (release_reader, mut release) = pipe();
    let mut child = fork_waiting(
        ready_writer.as_raw_fd(),
        release_reader.as_raw_fd(),
    );
    receive(&mut ready, deadline);
    while_child_holds();
    release.write_all(b"x").unwrap();
    assert_eq!(child.wait(deadline), 0);
}

fn fork_waiting(ready_fd: i32, release_fd: i32) -> Child {
    // SAFETY: getpid has no memory preconditions.
    let parent = unsafe { libc::getpid() };
    // SAFETY: child performs only direct process/pipe syscalls, without
    // allocation, Rust destructors, assertions or locks in the forked harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            // If the outer timeout kills this harness, its child must not keep
            // the inherited interest or block forever on its own pipe writer.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != parent
            {
                libc::_exit(4);
            }
            let byte = b'r';
            if libc::write(ready_fd, (&raw const byte).cast(), 1) != 1 {
                libc::_exit(2);
            }
            let mut response = 0u8;
            if libc::read(release_fd, (&raw mut response).cast(), 1) != 1 {
                libc::_exit(3);
            }
            libc::_exit(0);
        }
    }
    Child(pid)
}

/// Run descriptor-lifetime assertions in a harness with no concurrent test forks.
pub(crate) fn isolate_test(name: &str, marker: &str) -> bool {
    struct ReapedChild(std::process::Child);
    impl Drop for ReapedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    if std::env::var_os(marker).is_some() {
        return false;
    }
    let mut child = ReapedChild(
        std::process::Command::new(crate::reexec_test_executable(name, false))
            .args(["--exact", name, "--nocapture"])
            .env(marker, "1")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "isolated retention assertions failed"
            );
            let mut stdout = Vec::new();
            Read::read_to_end(&mut child.0.stdout.take().unwrap(), &mut stdout).unwrap();
            crate::assert_reexec_result(&stdout, name);
            return true;
        }
        assert!(
            Instant::now() < deadline,
            "isolated retention process timed out"
        );
        // Waiting for process completion never retries collection or assertions.
        std::thread::sleep(Duration::from_millis(5));
    }
}

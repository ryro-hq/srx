use super::*;
use std::io::Write as _;
use std::process::{Command, Stdio};

const TEST: &str = "platform::linux::fd::persisted_namespace::tests::peer::peer_launcher_capture_brackets_identity_namespace_and_closed_descriptors";
const HELPER: &str = "SYROX_CAPTURE_LAUNCHER_PEER_TEST";
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn helper(path: &Path) {
    let cancel = Cancellation::default();
    let record = CapturedLauncher::capture_self(&cancel, deadline())
        .unwrap()
        .record()
        .clone();
    let (mut init, gate) = capture::spawn_init();
    std::fs::write(path.join("namespace"), init.pid.to_string()).unwrap();
    std::fs::write(
        path.join("record.tmp"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    std::fs::rename(path.join("record.tmp"), path.join("ready")).unwrap();
    let mut byte = [0];
    io::stdin().read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"X");
    std::fs::File::from(gate).write_all(b"X").unwrap();
    init.wait();
}
fn start(root: &Path) -> Child {
    let mut child = Child(
        Command::new(crate::reexec_test_executable(TEST, false))
            .args([
                "--exact",
                TEST,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(HELPER, root)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let end = deadline();
    while !root.join("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "peer failed before publication"
        );
        assert!(Instant::now() < end, "peer publication deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
    child
}

#[test]
fn peer_launcher_capture_brackets_identity_namespace_and_closed_descriptors() {
    if let Some(path) = std::env::var_os(HELPER) {
        helper(Path::new(&path));
        return;
    }
    if capture::reexec(TEST) {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut child = start(root.path());
    let cancel = Cancellation::default();
    let launcher_record = observe_peer(&child, root.path(), &cancel);
    // observe_peer drops every launcher pidfd, including the captured namespace's
    // parent copy, before this reopen. pidfs identity must remain per PID.
    let reopened = pidfd_open(child.0.id()).unwrap();
    let captured = CapturedLauncher::capture_peer(reopened.as_fd(), &cancel, deadline()).unwrap();
    assert_eq!(captured.record(), &launcher_record);
    captured.revalidate(&cancel, deadline()).unwrap();
    assert!(
        launcher_record
            .observe_exit(&cancel, deadline())
            .unwrap()
            .is_none()
    );
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"X")
        .unwrap();
    let end = deadline();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < end, "peer exit deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(captured.revalidate(&cancel, deadline()).is_err());
    assert!(CapturedLauncher::capture_peer(reopened.as_fd(), &cancel, deadline()).is_err());
    let proof = launcher_record
        .observe_exit(&cancel, deadline())
        .unwrap()
        .expect("real peer exited");
    assert!(proof.matches(&launcher_record));
    assert!(
        !proof.matches(
            CapturedLauncher::capture_self(&cancel, deadline())
                .unwrap()
                .record()
        )
    );
}
fn observe_peer(child: &Child, root: &Path, cancel: &Cancellation) -> LauncherRecord {
    let descriptor = pidfd_open(child.0.id()).unwrap();
    let captured = CapturedLauncher::capture_peer(descriptor.as_fd(), cancel, deadline()).unwrap();
    captured.revalidate(cancel, deadline()).unwrap();
    assert!(
        std::fs::metadata(root.join("ready"))
            .unwrap()
            .len()
            <= 4096
    );
    let self_record: LauncherRecord =
        serde_json::from_slice(&std::fs::read(root.join("ready")).unwrap()).unwrap();
    assert_eq!(captured.record(), &self_record);
    let namespace_pid = std::fs::read_to_string(root.join("namespace"))
        .unwrap()
        .parse()
        .unwrap();
    let namespace = pidfd_open(namespace_pid).unwrap();
    let child_namespace = CapturedNamespace::capture_child(
        namespace.as_fd(),
        descriptor.as_fd(),
        cancel,
        deadline(),
    )
    .unwrap();
    child_namespace
        .revalidate(cancel, deadline())
        .unwrap();
    assert!(
        CapturedLauncher::capture_peer(namespace.as_fd(), cancel, deadline()).is_err(),
        "another PID namespace is not a launcher in this observer"
    );
    let wrong = pidfd_open(std::process::id()).unwrap();
    assert!(
        CapturedNamespace::capture_child(
            namespace.as_fd(),
            wrong.as_fd(),
            cancel,
            deadline()
        )
        .is_err()
    );
    let ordinary = std::fs::File::open("/dev/null").unwrap();
    assert!(CapturedLauncher::capture_peer(ordinary.as_fd(), cancel, deadline()).is_err());
    let cancelled = Cancellation::default();
    cancelled.cancel();
    assert!(CapturedLauncher::capture_peer(descriptor.as_fd(), &cancelled, deadline()).is_err());
    assert!(CapturedLauncher::capture_peer(descriptor.as_fd(), cancel, Instant::now()).is_err());
    captured.record().clone()
}

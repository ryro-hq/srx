use super::*;
use std::io::Write as _;
use std::process::{Child, Command, Stdio};
const ROOT: &str = "SYROX_NAMESPACE_REMOTE_PARENT";
const TEST: &str = "platform::linux::fd::persisted_namespace::tests::parent::remote_parent_is_pinned_and_wrong_or_exited_parents_are_rejected";
const ENTRY: &str = "platform::linux::fd::persisted_namespace::tests::parent::launcher_entry";
struct Launcher(Child);
impl Drop for Launcher {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
#[test]
#[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
fn launcher_entry() {
    let path = std::env::var_os(ROOT).expect("parent test must supply the fixture environment");
    let (mut init, writer) = capture::spawn_init();
    std::fs::write(
        Path::new(&path).join("init.pending"),
        init.pid.to_string(),
    )
    .unwrap();
    std::fs::rename(
        Path::new(&path).join("init.pending"),
        Path::new(&path).join("init"),
    )
    .unwrap();
    let mut byte = [0];
    io::stdin().read_exact(&mut byte).unwrap();
    if byte == *b"X" {
        let mut writer = std::fs::File::from(writer);
        writer.write_all(b"X").unwrap();
        init.wait();
    } else {
        panic!("unexpected launcher control");
    }
}
#[test]
fn remote_parent_is_pinned_and_wrong_or_exited_parents_are_rejected() {
    if capture::reexec(TEST) {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let mut launcher = Launcher(
        Command::new(crate::reexec_test_executable(ENTRY, true))
            .args([
                "--ignored",
                "--exact",
                ENTRY,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ROOT, directory.path())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let parent = pidfd_open(launcher.0.id()).unwrap();
    let limit = deadline();
    let path = directory.path().join("init");
    while !path.exists() {
        assert!(
            launcher.0.try_wait().unwrap().is_none(),
            "launcher exited before init publication"
        );
        assert!(
            Instant::now() < limit,
            "init publication deadline"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let pid = std::fs::read_to_string(path)
        .unwrap()
        .parse()
        .unwrap();
    let namespace = pidfd_open(pid).unwrap();
    let cancel = Cancellation::default();
    let captured = CapturedNamespace::capture_child(
        namespace.as_fd(),
        parent.as_fd(),
        &cancel,
        deadline(),
    )
    .unwrap();
    captured.revalidate(&cancel, deadline()).unwrap();
    let myself = pidfd_open(std::process::id()).unwrap();
    assert!(
        CapturedNamespace::capture_child(
            namespace.as_fd(),
            myself.as_fd(),
            &cancel,
            deadline()
        )
        .is_err()
    );
    let (mut sibling, sibling_writer) = capture::spawn_init();
    let sibling_fd = pidfd_open(sibling.pid.try_into().unwrap()).unwrap();
    assert!(
        CapturedNamespace::capture_child(
            sibling_fd.as_fd(),
            parent.as_fd(),
            &cancel,
            deadline()
        )
        .is_err()
    );
    let mut writer = std::fs::File::from(sibling_writer);
    writer.write_all(b"X").unwrap();
    sibling.wait();
    // Drop all caller copies: captured owns both pins for revalidation.
    drop((myself, sibling_fd, writer, parent, namespace));
    captured.revalidate(&cancel, deadline()).unwrap();
    assert!(
        captured
            .record()
            .observe_exit(&cancel, deadline())
            .unwrap()
            .is_none()
    );
    launcher
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"X")
        .unwrap();
    let limit = deadline();
    loop {
        if let Some(status) = launcher.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < limit, "launcher exit deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(pidfd_exited(captured.parent.as_fd()).unwrap());
    assert!(
        CapturedNamespace::capture_child(
            captured.descriptor.as_fd(),
            captured.parent.as_fd(),
            &cancel,
            deadline()
        )
        .is_err()
    );
    assert!(captured.revalidate(&cancel, deadline()).is_err());
    assert!(
        captured
            .record()
            .observe_exit(&cancel, deadline())
            .unwrap()
            .is_some()
    );
}

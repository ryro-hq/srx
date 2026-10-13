use super::*;
use std::io::Write as _;
use std::process::{Command, Stdio};

const TEST: &str = "platform::linux::fd::persisted_namespace::tests::launcher::ordinary_launcher_identity_survives_closed_descriptors_and_exit";
const RECORD_PATH: &str = "SYROX_LAUNCHER_RECORD_TEST_PATH";

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child(path: &Path) {
    let cancel = Cancellation::default();
    let record = {
        let capture = CapturedLauncher::capture_self(&cancel, deadline()).unwrap();
        capture.revalidate(&cancel, deadline()).unwrap();
        let descriptor = pidfd_open(std::process::id()).unwrap();
        assert!(CapturedNamespace::capture(descriptor.as_fd(), &cancel, deadline()).is_err());
        capture.record().clone()
    };
    // All pidfds are closed before exposing the record to the observing parent.
    let bytes = serde_json::to_vec(&record).unwrap();
    assert!(serde_json::from_slice::<NamespaceRecord>(&bytes).is_err());
    let mut missing_role = serde_json::to_value(&record).unwrap();
    missing_role
        .as_object_mut()
        .unwrap()
        .remove("role");
    assert!(serde_json::from_value::<LauncherRecord>(missing_role).is_err());
    let mut wrong_role = serde_json::to_value(&record).unwrap();
    wrong_role["role"] = serde_json::json!("namespace_init");
    assert!(serde_json::from_value::<LauncherRecord>(wrong_role).is_err());
    let temporary = path.with_extension("writing");
    std::fs::write(&temporary, bytes).unwrap();
    std::fs::rename(temporary, path).unwrap();
    let mut byte = [0];
    io::stdin().read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"X");
}

#[test]
fn ordinary_launcher_identity_survives_closed_descriptors_and_exit() {
    if let Some(path) = std::env::var_os(RECORD_PATH) {
        child(Path::new(&path));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("record.json");
    let mut process = Child(
        Command::new(crate::reexec_test_executable(TEST, false))
            .args([
                "--exact",
                TEST,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(RECORD_PATH, &path)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let limit = Instant::now() + Duration::from_secs(15);
    while !path.exists() {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "launcher capture child failed"
        );
        assert!(
            Instant::now() < limit,
            "launcher record publication timed out"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(std::fs::metadata(&path).unwrap().len() <= 4096);
    let bytes = std::fs::read(&path).unwrap();
    let record: LauncherRecord = serde_json::from_slice(&bytes).unwrap();
    record.validate().unwrap();
    let cancel = Cancellation::default();
    assert!(
        record
            .observe_exit(&cancel, deadline())
            .unwrap()
            .is_none()
    );
    assert!(serde_json::from_slice::<NamespaceRecord>(&bytes).is_err());
    process
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"X")
        .unwrap();
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "launcher child assertions failed"
            );
            break;
        }
        assert!(Instant::now() < limit, "launcher exit timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
    let proof = record
        .observe_exit(&cancel, deadline())
        .unwrap()
        .expect("real launcher exited");
    assert!(proof.matches(&record));
    let current = CapturedLauncher::capture_self(&cancel, deadline()).unwrap();
    assert!(!proof.matches(current.record()));
}

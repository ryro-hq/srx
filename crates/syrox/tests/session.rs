//! Consultation must not initialize a session registry or a Store.
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;
use std::process::{Command, Output};

fn run(root: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(arguments)
        .current_dir(root)
        .env("HOME", root.join("unused-home"))
        .output()
        .unwrap()
}

fn private(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn session_list_never_initializes_missing_registry_or_authority() {
    let root = tempfile::tempdir().unwrap();
    let args = [
        "session",
        "list",
        "--session-state",
        "state",
        "--json",
    ];
    assert!(!run(root.path(), &args).status.success());
    assert!(!root.path().join("state").exists());
    private(&root.path().join("state"));
    assert!(!run(root.path(), &args).status.success());
    assert_eq!(
        fs::read_dir(root.path().join("state"))
            .unwrap()
            .count(),
        0
    );
    private(&root.path().join("state/journal"));
    assert!(!run(root.path(), &args).status.success());
    assert_eq!(
        fs::read_dir(root.path().join("state/journal"))
            .unwrap()
            .count(),
        0
    );
    let lock = root.path().join("state/journal/authority.lock");
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    let result = run(root.path(), &args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap(),
        serde_json::json!([])
    );
    assert!(!root.path().join("unused-home").exists());
}

#[test]
fn session_list_reports_incomplete_evidence_without_repair_or_following_symlinks() {
    let root = tempfile::tempdir().unwrap();
    private(&root.path().join("state"));
    private(&root.path().join("state/journal"));
    let lock = root.path().join("state/journal/authority.lock");
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    let id = "11111111111111111111111111111111";
    let incomplete = root.path().join("state/journal").join(id);
    private(&incomplete);
    let args = [
        "session",
        "list",
        "--session-state",
        "state",
        "--json",
    ];
    let result = run(root.path(), &args);
    assert_eq!(result.status.code(), Some(1));
    let rows: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(rows[0]["session"], id);
    assert!(rows[0]["error"].as_str().is_some());
    assert_eq!(fs::read_dir(&incomplete).unwrap().count(), 0);
    fs::remove_file(&lock).unwrap();
    fs::write(root.path().join("outside"), b"preserved").unwrap();
    symlink(root.path().join("outside"), &lock).unwrap();
    assert!(!run(root.path(), &args).status.success());
    assert_eq!(
        fs::read(root.path().join("outside")).unwrap(),
        b"preserved"
    );
}

#[test]
fn recovery_requires_explicit_manager_and_valid_session_before_state_access() {
    let root = tempfile::tempdir().unwrap();
    let no_bus = run(
        root.path(),
        &[
            "session",
            "recover",
            "invalid",
            "--session-state",
            "state",
        ],
    );
    assert_eq!(no_bus.status.code(), Some(2));
    let invalid = run(
        root.path(),
        &[
            "session",
            "recover",
            "invalid",
            "--session-state",
            "state",
            "--systemd-user-bus",
            "missing-bus",
            "--store",
            "missing-store",
        ],
    );
    assert_eq!(invalid.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("identifier"));
    assert!(!root.path().join("state").exists());
    assert!(!root.path().join("unused-home").exists());
}

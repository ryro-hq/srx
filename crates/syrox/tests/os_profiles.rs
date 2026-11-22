//! Profile configuration and offline journal operations require no manager or service.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::undocumented_unsafe_blocks,
        reason = "tests assert with unwrap and drive raw syscalls; non-test builds keep both lints"
    )
)]
use std::{
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output},
};
use syrox_engine::cancellation::Cancellation;

fn run(home: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(arguments)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_DATA_HOME", home.join("data"))
        .output()
        .unwrap()
}
fn success(home: &Path, arguments: &[&str]) -> serde_json::Value {
    let output = run(home, arguments);
    assert!(
        output.status.success(),
        "{arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn init_binds_identity_without_building_and_recorded_commands_work_offline() {
    if syrox_engine::deployment::services::profile::profile_credentials().is_err() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let project = home.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("main.srx"),
        "outputs { os: Services = Services { pkgs = []; services = []; }; }",
    )
    .unwrap();
    let reference = format!("{}#os", project.display());
    let report = success(
        home.path(),
        &[
            "services", "init", &reference, "--name", "web", "--user", "--json",
        ],
    );
    assert_eq!(report["applied"], false);
    assert_eq!(report["manager_verified"], false);
    let path = home.path().join("config/syrox/os/web.json");
    let profile = syrox_engine::deployment::services::profile::read_os_profile(&path).unwrap();
    assert_eq!(profile.version, 1);
    assert_eq!(report["installation"], profile.installation_id);
    let original_profile = std::fs::read(&path).unwrap();
    assert!(!profile.store.exists());
    assert_eq!(
        std::fs::read_dir(&profile.units).unwrap().count(),
        0
    );
    // Recorded operations must still work for an installation whose project
    // has not yet migrated its old type or standard-library lock.
    std::fs::write(
        project.join("main.srx"),
        "outputs { os: Os = Os { pkgs = []; services = []; }; }",
    )
    .unwrap();
    let status = success(
        home.path(),
        &[
            "services",
            "status",
            "--profile",
            "web",
            "--recorded",
            "--json",
        ],
    );
    assert_eq!(status["observation"], "journal");
    assert!(status["desired"].is_null());
    assert_eq!(
        success(
            home.path(),
            &[
                "services",
                "list",
                "--profile",
                "web",
                "--json"
            ]
        ),
        serde_json::json!([])
    );
    assert_eq!(
        success(
            home.path(),
            &[
                "services",
                "stop",
                "--profile",
                "web",
                "--json"
            ]
        )["changed"],
        false
    );
    assert_eq!(std::fs::read(&path).unwrap(), original_profile);
    let before = std::fs::read(&path).unwrap();
    assert!(
        !run(
            home.path(),
            &[
                "services", "init", &reference, "--name", "web"
            ]
        )
        .status
        .success()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!profile.store.exists());
    let moved = home.path().join("previous-installation");
    std::fs::rename(&profile.installation, moved).unwrap();
    syrox_engine::deployment::services::profile::ensure_profile_directory(&profile.installation).unwrap();
    syrox_engine::deployment::services::initialize_os_installation(
        &profile.installation,
        &Cancellation::default(),
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    )
    .unwrap();
    for command in [
        "status", "list", "stop", "apply", "recover",
    ] {
        let output = run(
            home.path(),
            &["services", command, "--profile", "web"],
        );
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("identity differs"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(!profile.store.exists());
}

#[test]
fn profile_execution_cannot_mix_explicit_authority_and_rejects_profile_symlinks() {
    if syrox_engine::deployment::services::profile::profile_credentials().is_err() {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let mixed = run(
        home.path(),
        &[
            "services",
            "apply",
            "--profile",
            "web",
            "--uid",
            "1000",
        ],
    );
    assert_eq!(mixed.status.code(), Some(2));
    let profiles = home.path().join("config/syrox/os");
    std::fs::create_dir_all(&profiles).unwrap();
    std::fs::set_permissions(&profiles, std::fs::Permissions::from_mode(0o700)).unwrap();
    let outside = home.path().join("outside.json");
    std::fs::write(&outside, "{}").unwrap();
    std::os::unix::fs::symlink(&outside, profiles.join("web.json")).unwrap();
    let output = run(
        home.path(),
        &[
            "services",
            "status",
            "--profile",
            "web",
            "--recorded",
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("symlink"));
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "{}");
}

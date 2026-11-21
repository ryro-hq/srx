//! Read-only system inspection needs no project, Store, utility or privilege.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::undocumented_unsafe_blocks,
        reason = "tests assert with unwrap and drive raw syscalls; non-test builds keep both lints"
    )
)]
use std::process::Command;

#[path = "system/plan.rs"]
mod plan;

#[test]
fn scratch_recovery_requires_explicit_target_and_canonical_authorization_before_io() {
    let temporary = tempfile::tempdir().unwrap();
    let id = "ab".repeat(16);
    for args in [
        vec![],
        vec!["--scratch-operation", &id],
        vec!["--workspace-operation", &id],
        vec![
            "--workspace-operation",
            "invalid",
            "--helper-socket",
            "/run/absent-helper.sock",
        ],
        vec![
            "--workspace-operation",
            &id,
            "--scratch-operation",
            &id,
            "--helper-socket",
            "/run/absent-helper.sock",
        ],
        vec![
            "--workspace-operation",
            &id,
            "--helper-socket",
            "/run/absent-helper.sock",
            "--apply-plan",
            "bad",
        ],
        vec![
            "--scratch-operation",
            "../device",
            "--helper-socket",
            "/run/absent-helper.sock",
        ],
        vec![
            "--scratch-operation",
            &id,
            "--helper-socket",
            "/run/absent-helper.sock",
            "--apply-plan",
            "not-a-hash",
        ],
        vec![
            "--scratch-operation",
            &id,
            "--helper-socket",
            "/run/absent-helper.sock",
            "--device",
            "/dev/sda",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_srx"))
            .args(["--std", "none", "system", "recover"])
            .args(args)
            .current_dir(temporary.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
    assert_eq!(
        std::fs::read_dir(temporary.path())
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn scratch_recovery_refuses_an_unprotected_endpoint_without_creating_project_or_store_state() {
    let temporary = tempfile::tempdir().unwrap();
    let endpoint = temporary.path().join("helper.sock");
    std::fs::write(&endpoint, b"preserved").unwrap();
    let id = "ab".repeat(16);
    for (operation, authorization) in [
        ("--scratch-operation", None),
        ("--scratch-operation", Some("01".repeat(32))),
        ("--workspace-operation", None),
        ("--workspace-operation", Some("01".repeat(32))),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_srx"));
        command
            .args([
                "--std",
                "none",
                "system",
                "recover",
                operation,
                &id,
                "--helper-socket",
            ])
            .arg(&endpoint)
            .arg("--json");
        if let Some(hash) = authorization {
            command.args(["--apply-plan", &hash]);
        }
        let output = command
            .current_dir(temporary.path())
            .env("PATH", "/nonexistent")
            .env("HOME", temporary.path().join("home"))
            .env("XDG_CONFIG_HOME", temporary.path().join("config"))
            .env("XDG_DATA_HOME", temporary.path().join("data"))
            .env("XDG_STATE_HOME", temporary.path().join("state"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    assert_eq!(std::fs::read(&endpoint).unwrap(), b"preserved");
    assert_eq!(
        std::fs::read_dir(temporary.path())
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn system_inspect_works_without_path_configuration_or_a_valid_project_and_creates_no_state() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("main.srx"),
        "@invalid project",
    )
    .unwrap();
    std::fs::write(
        directory.path().join("Syrox.lock"),
        "invalid lock",
    )
    .unwrap();
    for json in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_srx"));
        command.args(["--std", "none", "system", "inspect"]);
        if json {
            command.arg("--json");
        }
        let output = command
            .current_dir(directory.path())
            .env("PATH", "/nonexistent")
            .env("HOME", directory.path().join("home"))
            .env("XDG_CONFIG_HOME", directory.path().join("config"))
            .env("XDG_DATA_HOME", directory.path().join("data"))
            .env("XDG_STATE_HOME", directory.path().join("state"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if json {
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["observation"], "linux-kernel-interfaces");
            assert_eq!(report["digest"].as_str().unwrap().len(), 64);
            assert_eq!(report["inventory"]["version"], 1);
            assert!(
                !report["inventory"]["kernel_release"]
                    .as_str()
                    .unwrap()
                    .is_empty()
            );
            assert!(report["inventory"]["devices"].is_array());
            assert!(report["inventory"]["mounts"].is_array());
            assert!(report["inventory"]["kvm_device_present"].is_boolean());
        } else {
            let report = String::from_utf8(output.stdout).unwrap();
            assert!(report.starts_with("system inventory v1 sha256 "));
            assert!(report.contains("block devices:"));
            assert!(report.contains("in current namespace"));
        }
    }
    assert_eq!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .count(),
        2
    );
    assert_eq!(
        std::fs::read_to_string(directory.path().join("main.srx")).unwrap(),
        "@invalid project"
    );
    assert_eq!(
        std::fs::read_to_string(directory.path().join("Syrox.lock")).unwrap(),
        "invalid lock"
    );
}

#[test]
fn system_inspect_does_not_accept_project_paths_or_execution_flags() {
    for arguments in [
        vec!["system", "inspect", "--apply"],
        vec!["system", "inspect", ".#system"],
        vec![
            "system",
            "inspect",
            "--store",
            "/tmp/store",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_srx"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn builder_directory_inspection_reports_kernel_capacity_and_unavailable_quotas_without_state() {
    use std::os::unix::fs::MetadataExt as _;
    let directory = tempfile::tempdir().unwrap();
    let scratch = directory.path().join("scratch");
    std::fs::create_dir(&scratch).unwrap();
    let identity = std::fs::metadata(&scratch).unwrap();
    for json in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_srx"));
        command
            .args([
                "system",
                "inspect",
                "--builder-directory",
            ])
            .arg(&scratch);
        if json {
            command.arg("--json");
        }
        let output = command
            .current_dir(directory.path())
            .env("PATH", "/nonexistent")
            .env("HOME", directory.path().join("absent-home"))
            .env(
                "XDG_CONFIG_HOME",
                directory.path().join("absent-config"),
            )
            .env(
                "XDG_DATA_HOME",
                directory.path().join("absent-data"),
            )
            .env(
                "XDG_STATE_HOME",
                directory.path().join("absent-state"),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if json {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let builder = &value["builder_filesystem"];
            assert_eq!(builder["path"], scratch.to_str().unwrap());
            assert_eq!(builder["digest"].as_str().unwrap().len(), 64);
            assert_eq!(builder["observation"]["device"], identity.dev());
            assert_eq!(builder["observation"]["inode"], identity.ino());
            assert!(
                builder["observation"]["total_bytes"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
            assert!(matches!(
                builder["observation"]["project"]["status"].as_str(),
                Some("available" | "unavailable")
            ));
            assert!(matches!(
                builder["external_uuid"]["status"].as_str(),
                Some("available" | "unavailable")
            ));
            if builder["external_uuid"]["status"] == "available" {
                assert!(
                    (1..=16).contains(
                        &builder["external_uuid"]["value"]
                            .as_array()
                            .unwrap()
                            .len()
                    )
                );
            }
        } else {
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("builder directory"));
            assert!(text.contains("available_bytes="));
        }
    }
    assert_eq!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .count(),
        1
    );
    assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
}

#[test]
fn builder_inspection_rejects_missing_directories_files_and_final_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("file");
    std::fs::write(&file, b"unchanged").unwrap();
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(directory.path(), &link).unwrap();
    for path in [
        directory.path().join("missing"),
        file.clone(),
        link,
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_srx"))
            .args([
                "system",
                "inspect",
                "--json",
                "--builder-directory",
            ])
            .arg(path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("builder directory"));
    }
    assert_eq!(std::fs::read(&file).unwrap(), b"unchanged");
    assert_eq!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .count(),
        2
    );
}

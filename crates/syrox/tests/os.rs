//! Persistence checks do not execute the launcher or contact a service manager.
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};

fn run(binary: &Path, root: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .current_dir(root)
        .env("HOME", root.join("home"))
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()
        .unwrap()
}
fn success(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn fixture(root: &Path) -> std::path::PathBuf {
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let binary = bin.join("srx");
    if fs::hard_link(env!("CARGO_BIN_EXE_srx"), &binary).is_err() {
        fs::copy(env!("CARGO_BIN_EXE_srx"), &binary).unwrap();
    }
    // This fixture is authenticated and retained, never started. These tests
    // establish preparation/inspection only, not launcher or systemd readiness.
    fs::write(
        bin.join("syrox-worker"),
        b"inert retained launcher fixture",
    )
    .unwrap();
    fs::create_dir(root.join("installation")).unwrap();
    fs::set_permissions(
        root.join("installation"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    binary
}
fn project(binary: &Path, root: &Path, kind: &str, text: &str) {
    fs::write(root.join("main.srx"), format!(
        "outputs {{ system: std::{kind} = std::{kind} {{ pkgs = []; services = [std::Service {{ id = \"example\"; files = [std::ConfigFile {{ path = \"settings\"; text = \"{text}\"; }}]; }}]; }}; }}"
    )).unwrap();
    let locked = run(binary, root, &["project", "lock", "."]);
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
}

#[test]
fn os_prepares_reopens_and_diffs_after_project_and_launcher_are_removed() {
    let root = tempfile::tempdir().unwrap();
    let binary = fixture(root.path());
    project(&binary, root.path(), "Os", "first");
    let arguments = [
        "os",
        "prepare",
        ".#system",
        "--installation",
        "installation",
        "--store",
        "store",
        "--offline",
        "--json",
    ];
    let first = success(&run(&binary, root.path(), &arguments));
    assert_eq!(first["phase"], "prepared");
    assert_eq!(first["configurations"], 1);
    let candidate = root
        .path()
        .join("installation/generations")
        .join(first["pin"].as_str().unwrap());
    let retained_worker = candidate.join("launcher/worker");
    let retained_config = candidate.join("configuration/example/settings");
    assert_eq!(
        fs::read(&retained_worker).unwrap(),
        b"inert retained launcher fixture"
    );
    assert_eq!(fs::read(&retained_config).unwrap(), b"first");
    assert_eq!(
        fs::metadata(&retained_worker)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o500
    );
    assert_eq!(
        fs::metadata(&retained_config)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o400
    );
    let again = success(&run(&binary, root.path(), &arguments));
    assert_eq!(first, again);
    project(&binary, root.path(), "Os", "second");
    let second = success(&run(&binary, root.path(), &arguments));
    assert_ne!(first["pin"], second["pin"]);
    fs::remove_file(root.path().join("main.srx")).unwrap();
    fs::remove_file(root.path().join("Syrox.lock")).unwrap();
    fs::remove_file(root.path().join("bin/syrox-worker")).unwrap();
    assert_eq!(
        fs::read(&retained_worker).unwrap(),
        b"inert retained launcher fixture"
    );
    assert_eq!(fs::read(&retained_config).unwrap(), b"first");
    let pin = first["pin"].as_str().unwrap();
    let reopened = success(&run(
        &binary,
        root.path(),
        &[
            "os",
            "inspect",
            pin,
            "--installation",
            "installation",
            "--store",
            "store",
            "--json",
        ],
    ));
    assert_eq!(first, reopened);
    let entries = success(&run(
        &binary,
        root.path(),
        &[
            "os",
            "list",
            "--installation",
            "installation",
            "--json",
        ],
    ));
    assert_eq!(entries.as_array().unwrap().len(), 2);
    let diff = run(
        &binary,
        root.path(),
        &[
            "os",
            "diff",
            pin,
            second["pin"].as_str().unwrap(),
            "--installation",
            "installation",
            "--store",
            "store",
        ],
    );
    assert!(
        diff.status.success(),
        "{}",
        String::from_utf8_lossy(&diff.stderr)
    );
    let text = String::from_utf8(diff.stdout).unwrap();
    assert!(text.contains("Configuration"), "{text}");
    assert!(!text.contains("first") && !text.contains("second"));
}

#[test]
fn wrong_destination_and_untrusted_installation_fail_before_store_creation() {
    let root = tempfile::tempdir().unwrap();
    let binary = fixture(root.path());
    let args = [
        "os",
        "prepare",
        ".#system",
        "--installation",
        "installation",
        "--store",
        "store",
    ];
    project(&binary, root.path(), "Shell", "inert");
    let wrong = run(&binary, root.path(), &args);
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("requires an Os consumer"));
    assert!(
        !root
            .path()
            .join("installation/authority.lock")
            .exists()
    );
    assert!(!root.path().join("store").exists());
    project(&binary, root.path(), "Os", "inert");
    fs::set_permissions(
        root.path().join("installation"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let wrong = run(&binary, root.path(), &args);
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("0700"));
    assert!(!root.path().join("store").exists());
}

#[test]
fn inspection_never_initializes_missing_state_or_store() {
    let root = tempfile::tempdir().unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_srx"));
    for args in [
        vec![
            "os",
            "list",
            "--installation",
            "missing",
            "--json",
        ],
        vec![
            "os",
            "inspect",
            "invalid-pin",
            "--installation",
            "missing",
            "--store",
            "store",
        ],
        vec![
            "os",
            "inspect",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--installation",
            "missing",
            "--store",
            "store",
        ],
    ] {
        assert!(!run(binary, root.path(), &args).status.success());
        assert!(!root.path().join("missing").exists());
        assert!(!root.path().join("store").exists());
    }
}

#[test]
fn os_worker_rejects_invalid_arguments_before_opening_installation_or_store() {
    let root = tempfile::tempdir().unwrap();
    let installation = root.path().join("missing-installation");
    let store = root.path().join("missing-store");
    let output = Command::new(env!("CARGO_BIN_EXE_syrox-worker"))
        .arg("__os-service")
        .arg(&installation)
        .arg(&store)
        .arg("invalid-pin")
        .env_remove("INVOCATION_ID")
        .env_remove("NOTIFY_SOCKET")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid binding pin"));
    assert!(!installation.exists());
    assert!(!store.exists());
}

fn apply_arguments() -> Vec<&'static str> {
    vec![
        "os",
        "apply",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--installation",
        "/missing-installation",
        "--store",
        "/missing-store",
        "--units",
        "/missing-units",
        "--cwd",
        "/missing-work",
        "--uid",
        "1000",
        "--gid",
        "1000",
    ]
}

#[test]
fn os_apply_requires_explicit_manager_and_previous_generation() {
    let root = tempfile::tempdir().unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_srx"));
    for options in [
        vec![],
        vec!["--initial"],
        vec!["--systemd-system"],
        vec![
            "--initial",
            "--systemd-system",
            "--systemd-user-bus",
            "/missing-bus",
        ],
        vec![
            "--initial",
            "--systemd-system",
            "--expected",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
    ] {
        let mut args = apply_arguments();
        args.extend(options);
        let output = run(binary, root.path(), &args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn os_apply_rejects_invalid_timeouts_and_missing_credentials_during_parsing() {
    let root = tempfile::tempdir().unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_srx"));
    for (flag, value) in [
        ("--start-timeout-seconds", "0"),
        ("--start-timeout-seconds", "301"),
        ("--stop-timeout-seconds", "0"),
        ("--stop-timeout-seconds", "61"),
        ("--uid", "-1"),
    ] {
        let mut args = apply_arguments();
        args.extend([
            "--initial",
            "--systemd-system",
            flag,
            value,
        ]);
        let output = run(binary, root.path(), &args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for credential in ["--uid", "--gid"] {
        let mut args = apply_arguments();
        let index = args
            .iter()
            .position(|argument| *argument == credential)
            .unwrap();
        args.drain(index..index + 2);
        args.extend(["--initial", "--systemd-system"]);
        assert_eq!(
            run(binary, root.path(), &args).status.code(),
            Some(2)
        );
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn os_apply_refuses_credential_changes_before_creating_state() {
    let root = tempfile::tempdir().unwrap();
    let installation = root.path().join("installation");
    let store = root.path().join("store");
    let units = root.path().join("units");
    let cwd = root.path().join("work");
    let output = run(
        Path::new(env!("CARGO_BIN_EXE_srx")),
        root.path(),
        &[
            "os",
            "apply",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--installation",
            installation.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--units",
            units.to_str().unwrap(),
            "--cwd",
            cwd.to_str().unwrap(),
            "--initial",
            "--systemd-system",
            "--uid",
            "4294967295",
            "--gid",
            "4294967295",
            "--json",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("uid") || error.contains("UID") || error.contains("credentials"),
        "{error}"
    );
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn os_status_does_not_initialize_missing_installation() {
    let root = tempfile::tempdir().unwrap();
    let output = run(
        Path::new(env!("CARGO_BIN_EXE_srx")),
        root.path(),
        &[
            "os",
            "status",
            "--installation",
            "missing",
            "--json",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn os_status_reads_unselected_journal_without_store_or_project() {
    let root = tempfile::tempdir().unwrap();
    let binary = fixture(root.path());
    project(
        &binary,
        root.path(),
        "Os",
        "private fixture content",
    );
    success(&run(
        &binary,
        root.path(),
        &[
            "os",
            "prepare",
            ".#system",
            "--installation",
            "installation",
            "--store",
            "store",
            "--offline",
            "--json",
        ],
    ));
    fs::remove_dir_all(root.path().join("store")).unwrap();
    fs::remove_file(root.path().join("main.srx")).unwrap();
    fs::remove_file(root.path().join("Syrox.lock")).unwrap();
    fs::remove_file(root.path().join("bin/syrox-worker")).unwrap();
    let arguments = [
        "os",
        "status",
        "--installation",
        "installation",
        "--json",
    ];
    let output = run(&binary, root.path(), &arguments);
    let status = success(&output);
    assert_eq!(status["observation"], "journal");
    assert_eq!(status["installation"].as_str().unwrap().len(), 32);
    assert!(status["desired"].is_null());
    assert!(status["active_operation"].is_null());
    assert_eq!(status["bindings"], serde_json::json!([]));
    assert_eq!(status["pending_effects"], serde_json::json!([]));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private fixture content"));
    assert!(!root.path().join("store").exists());
    let text = run(
        &binary,
        root.path(),
        &arguments[..arguments.len() - 1],
    );
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.starts_with("journal "));
    assert!(text.contains("desired=none active_operation=none"));
}

fn recovery_arguments() -> Vec<&'static str> {
    let mut arguments = apply_arguments();
    arguments[1] = "recover";
    arguments[2] = "1234567890abcdef1234567890abcdef";
    arguments
}

#[test]
fn os_recover_requires_manager_credentials_and_valid_operation_without_cas_flags() {
    let root = tempfile::tempdir().unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_srx"));
    let mut cases = vec![recovery_arguments()];
    for extra in [
        vec![
            "--systemd-system",
            "--systemd-user-bus",
            "/missing-bus",
        ],
        vec!["--systemd-system", "--initial"],
        vec![
            "--systemd-system",
            "--new-boot",
            "--manager-changed",
        ],
        vec![
            "--systemd-system",
            "--expected",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        vec![
            "--systemd-system",
            "--start-timeout-seconds",
            "301",
        ],
        vec![
            "--systemd-system",
            "--stop-timeout-seconds",
            "0",
        ],
    ] {
        let mut arguments = recovery_arguments();
        arguments.extend(extra);
        cases.push(arguments);
    }
    for invalid in [
        "bad",
        "00000000000000000000000000000000",
        "ABCDEF0123456789abcdef0123456789",
        "1234567890abcdef1234567890abcdef00",
    ] {
        let mut arguments = recovery_arguments();
        arguments[2] = invalid;
        arguments.push("--systemd-system");
        cases.push(arguments);
    }
    for name in ["--uid", "--gid"] {
        let mut arguments = recovery_arguments();
        let index = arguments
            .iter()
            .position(|argument| *argument == name)
            .unwrap();
        arguments.drain(index..index + 2);
        arguments.push("--systemd-system");
        cases.push(arguments);
    }
    for arguments in cases {
        let output = run(binary, root.path(), &arguments);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn os_recover_refuses_changed_credentials_before_state_or_manager_access() {
    let root = tempfile::tempdir().unwrap();
    let paths = ["installation", "store", "units", "work"].map(|name| root.path().join(name));
    let output = run(
        Path::new(env!("CARGO_BIN_EXE_srx")),
        root.path(),
        &[
            "os",
            "recover",
            "1234567890abcdef1234567890abcdef",
            "--installation",
            paths[0].to_str().unwrap(),
            "--store",
            paths[1].to_str().unwrap(),
            "--units",
            paths[2].to_str().unwrap(),
            "--cwd",
            paths[3].to_str().unwrap(),
            "--uid",
            "4294967295",
            "--gid",
            "4294967295",
            "--systemd-system",
            "--json",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("credentials"));
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn os_abandon_requires_canonical_operation_and_installation() {
    let root = tempfile::tempdir().unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_srx"));
    for operation in [
        "bad",
        "00000000000000000000000000000000",
        "ABCDEF0123456789abcdef0123456789",
        "1234567890abcdef1234567890abcdef00",
    ] {
        let output = run(
            binary,
            root.path(),
            &[
                "os",
                "abandon",
                operation,
                "--installation",
                "missing",
                "--json",
            ],
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    let output = run(
        binary,
        root.path(),
        &[
            "os",
            "abandon",
            "1234567890abcdef1234567890abcdef",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn os_abandon_never_initializes_missing_installation() {
    let root = tempfile::tempdir().unwrap();
    let output = run(
        Path::new(env!("CARGO_BIN_EXE_srx")),
        root.path(),
        &[
            "os",
            "abandon",
            "1234567890abcdef1234567890abcdef",
            "--installation",
            "missing",
            "--json",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn os_rollback_requires_expected_and_explicit_manager_and_forbids_initial() {
    let root = tempfile::tempdir().unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_srx"));
    let expected = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    for options in [
        vec!["--systemd-system"],
        vec!["--expected", expected],
        vec![
            "--expected",
            expected,
            "--systemd-system",
            "--initial",
        ],
        vec![
            "--expected",
            expected,
            "--systemd-system",
            "--systemd-user-bus",
            "/missing-bus",
        ],
    ] {
        let mut arguments = apply_arguments();
        arguments[1] = "rollback";
        arguments.extend(options);
        let output = run(binary, root.path(), &arguments);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn os_rollback_uses_apply_credential_preflight_without_creating_state() {
    let root = tempfile::tempdir().unwrap();
    let mut arguments = apply_arguments();
    arguments[1] = "rollback";
    for option in ["--uid", "--gid"] {
        let index = arguments
            .iter()
            .position(|argument| *argument == option)
            .unwrap();
        arguments[index + 1] = "4294967295";
    }
    arguments.extend([
        "--expected",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--systemd-system",
        "--json",
    ]);
    let output = run(
        Path::new(env!("CARGO_BIN_EXE_srx")),
        root.path(),
        &arguments,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("credentials"));
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn epoch_recovery_flags_are_explicit_and_not_apply_or_rollback_flags() {
    let root = tempfile::tempdir().unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_srx"));
    for recovery_flag in ["--new-boot", "--manager-changed"] {
        let mut arguments = recovery_arguments();
        for flag in ["--uid", "--gid"] {
            let index = arguments
                .iter()
                .position(|value| *value == flag)
                .unwrap();
            arguments[index + 1] = "4294967295";
        }
        arguments.extend(["--systemd-system", recovery_flag]);
        let output = run(binary, root.path(), &arguments);
        assert_eq!(output.status.code(), Some(1), "{recovery_flag}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("credentials"));
        assert!(output.stdout.is_empty());
        for command in ["apply", "rollback"] {
            let mut arguments = apply_arguments();
            arguments[1] = command;
            arguments.extend([
                "--systemd-system",
                recovery_flag,
                "--expected",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ]);
            let output = run(binary, root.path(), &arguments);
            assert_eq!(
                output.status.code(),
                Some(2),
                "{command} {recovery_flag}"
            );
            assert!(output.stdout.is_empty());
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert!(
                diagnostic.contains("unexpected argument"),
                "{diagnostic}"
            );
            assert!(diagnostic.contains(recovery_flag), "{diagnostic}");
        }
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

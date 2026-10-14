//! Shell preflight must reject unsupported plans before initializing a Store.
use std::fs;
use std::process::{Command, Output};

fn run(root: &std::path::Path, arguments: &[&str]) -> Output {
    run_binary(
        std::path::Path::new(env!("CARGO_BIN_EXE_srx")),
        root,
        arguments,
    )
}

fn run_binary(binary: &std::path::Path, root: &std::path::Path, arguments: &[&str]) -> Output {
    Command::new(binary)
        .args(arguments)
        .current_dir(root)
        .env("HOME", root.join("home"))
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()
        .unwrap()
}

#[test]
fn shell_requires_an_explicit_execution_mode() {
    let root = tempfile::tempdir().unwrap();
    let result = run(
        root.path(),
        &["shell", ".#shell", "--command", "git"],
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--non-interactive"));
    assert!(!root.path().join("home").exists());
}

#[test]
fn shell_rejects_wrong_destination_and_missing_exposure_before_store() {
    for (kind, expected) in [
        ("Os", "not a Shell"),
        ("Shell", "no exposed command"),
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("main.srx"),
            format!(
                "outputs {{ selected: std::{kind} = std::{kind} {{ pkgs = []; services = []; }}; }}"
            ),
        )
        .unwrap();
        let locked = run(root.path(), &["project", "lock", "."]);
        assert!(
            locked.status.success(),
            "{}",
            String::from_utf8_lossy(&locked.stderr)
        );
        let result = run(
            root.path(),
            &[
                "shell",
                ".#selected",
                "--command",
                "git",
                "--non-interactive",
                "--store",
                "store",
            ],
        );
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!root.path().join("store").exists());
    }
}

#[test]
fn shell_rejects_unsupervised_processes_before_store() {
    let root = tempfile::tempdir().unwrap();
    process_project(root.path());
    let result = run(
        root.path(),
        &[
            "shell",
            ".#shell",
            "--command",
            "server",
            "--non-interactive",
            "--store",
            "store",
        ],
    );
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("require session supervision"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!root.path().join("store").exists());
}

fn process_project(root: &std::path::Path) {
    fs::write(root.join("main.srx"), r#"
        fn recipe() -> std::Recipe { std::Recipe {
            package = std::Package { id = "fixture"; dependencies = []; };
            acquisition = std::Option::Some(std::Acquisition { sources = [std::SourceRequest {
                url = "https://example.invalid/source";
                sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
                maximum_bytes = 1;
            }]; });
            build = std::Option::Some(std::autotools(std::BuildOptions { source_directory = "fixture"; timeout_seconds = 30; }));
            commands = [std::Command { name = "server"; output = "out"; path = "bin/server"; }];
        } }
        outputs {
            package: std::RecipeRef<std::Recipe> = std::recipe_ref(recipe);
            shell: std::Shell = std::Shell { pkgs = []; services = [std::Service {
                id = "server";
                commands = [std::ServiceCommand { name = "server"; command = std::recipe_command(package, "server"); expose = std::Option::Some("server"); }];
                processes = [std::ServiceProcess { id = "main"; command = "server"; }];
            }]; };
        }
    "#).unwrap();
    let locked = run(root, &["project", "lock", "."]);
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
}

#[test]
fn managed_flags_require_each_other_and_explicit_execution_mode() {
    for (arguments, expected) in [
        (
            vec![
                "shell",
                ".#shell",
                "--command",
                "server",
                "--non-interactive",
                "--session-state",
                "state",
            ],
            "--systemd-user-bus",
        ),
        (
            vec![
                "shell",
                ".#shell",
                "--command",
                "server",
                "--non-interactive",
                "--systemd-user-bus",
                "bus",
            ],
            "--session-state",
        ),
        (
            vec![
                "shell",
                ".#shell",
                "--command",
                "server",
                "--session-state",
                "state",
                "--systemd-user-bus",
                "bus",
            ],
            "--non-interactive",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let result = run(root.path(), &arguments);
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn managed_destination_and_exposure_are_checked_before_state_or_store() {
    for (kind, expected) in [
        ("Os", "not a Shell"),
        ("Shell", "no exposed command"),
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("main.srx"),
            format!(
                "outputs {{ selected: std::{kind} = std::{kind} {{ pkgs = []; services = []; }}; }}"
            ),
        )
        .unwrap();
        let locked = run(root.path(), &["project", "lock", "."]);
        assert!(
            locked.status.success(),
            "{}",
            String::from_utf8_lossy(&locked.stderr)
        );
        let result = run(
            root.path(),
            &[
                "shell",
                ".#selected",
                "--command",
                "server",
                "--non-interactive",
                "--session-state",
                "missing-state",
                "--systemd-user-bus",
                "missing-bus",
                "--store",
                "store",
            ],
        );
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!root.path().join("store").exists());
        assert!(!root.path().join("missing-state").exists());
    }
}

fn isolated_preflight_installation(root: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let executable = bin.join("srx");
    let candidate = env!("CARGO_BIN_EXE_srx");
    if fs::hard_link(candidate, &executable).is_err() {
        let mut stage = tempfile::NamedTempFile::new_in(&bin).unwrap();
        std::io::copy(
            &mut fs::File::open(candidate).unwrap(),
            stage.as_file_mut(),
        )
        .unwrap();
        stage
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o500))
            .unwrap();
        stage.as_file().sync_all().unwrap();
        // Close the writer before this name can be executed by another process.
        stage
            .into_temp_path()
            .persist_noclobber(&executable)
            .unwrap();
    }
    // Deliberately non-executable fixture bytes, not a worker candidate. Every
    // case must stop at read-only configuration validation before any launch.
    fs::write(
        bin.join("syrox-worker"),
        b"preflight-only regular file\n",
    )
    .unwrap();
    executable
}

#[test]
fn managed_processes_reach_configuration_preflight_without_realizing_a_package() {
    use std::os::unix::fs::PermissionsExt as _;
    for (case, mode, cwd, expected) in [
        ("missing-state", None, "cwd", "No such file"),
        (
            "permissive-state",
            Some(0o755),
            "cwd",
            "mode 0700",
        ),
        (
            "reserved-cwd",
            Some(0o700),
            "/proc",
            "working directory",
        ),
        (
            "missing-bus",
            Some(0o700),
            "cwd",
            "managed Shell supervision failed",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        process_project(root.path());
        let binary = isolated_preflight_installation(root.path());
        fs::create_dir(root.path().join("cwd")).unwrap();
        let state = root.path().join("state");
        if let Some(mode) = mode {
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(mode)).unwrap();
        }
        let result = run_binary(
            &binary,
            root.path(),
            &[
                "shell",
                ".#shell",
                "--command",
                "server",
                "--non-interactive",
                "--session-state",
                "state",
                "--systemd-user-bus",
                "missing-bus",
                "--store",
                "store",
                "--cwd",
                cwd,
                "--offline",
            ],
        );
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(!result.status.success(), "{case}");
        assert!(error.contains(expected), "{case}: {error}");
        assert!(
            !error.contains("require session supervision"),
            "managed processes rejected: {error}"
        );
        assert!(
            !root.path().join("store").exists(),
            "{case} created Store before preflight"
        );
        if let Some(mode) = mode {
            assert_eq!(
                fs::read_dir(&state).unwrap().count(),
                0,
                "{case} published state during preflight"
            );
            assert_eq!(
                fs::metadata(&state).unwrap().permissions().mode() & 0o7777,
                mode
            );
        } else {
            assert!(!state.exists());
        }
    }
}

#[test]
fn managed_state_and_working_directory_must_not_overlap_in_either_direction() {
    use std::os::unix::fs::PermissionsExt as _;
    for cwd in [".", "state", "state/nested"] {
        let root = tempfile::tempdir().unwrap();
        process_project(root.path());
        let binary = isolated_preflight_installation(root.path());
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        if cwd == "state/nested" {
            fs::create_dir(state.join("nested")).unwrap();
        }
        let before = fs::read_dir(&state).unwrap().count();
        let result = run_binary(
            &binary,
            root.path(),
            &[
                "shell",
                ".#shell",
                "--command",
                "server",
                "--non-interactive",
                "--session-state",
                "state",
                "--systemd-user-bus",
                "missing-bus",
                "--store",
                "store",
                "--cwd",
                cwd,
                "--offline",
            ],
        );
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(!result.status.success());
        assert!(
            error.contains("working directory overlaps managed session state"),
            "cwd={cwd}: {error}"
        );
        assert!(!root.path().join("store").exists());
        assert_eq!(fs::read_dir(&state).unwrap().count(), before);
    }
}

#[test]
fn interactive_mode_is_exclusive_and_requires_managed_ownership_and_command() {
    for (arguments, expected) in [
        (
            vec![
                "shell",
                ".#shell",
                "--command",
                "git",
                "--interactive",
                "--non-interactive",
            ],
            "cannot be used with",
        ),
        (
            vec![
                "shell",
                ".#shell",
                "--command",
                "git",
                "--interactive",
            ],
            "--session-state",
        ),
        (
            vec![
                "shell",
                ".#shell",
                "--command",
                "git",
                "--interactive",
                "--session-state",
                "state",
            ],
            "--systemd-user-bus",
        ),
        (
            vec![
                "shell",
                ".#shell",
                "--command",
                "git",
                "--interactive",
                "--systemd-user-bus",
                "bus",
            ],
            "--session-state",
        ),
        (
            vec![
                "shell",
                ".#shell",
                "--interactive",
                "--session-state",
                "state",
                "--systemd-user-bus",
                "bus",
            ],
            "--command",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let result = run(root.path(), &arguments);
        assert_eq!(result.status.code(), Some(2));
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(error.contains(expected), "{arguments:?}: {error}");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn interactive_redirection_fails_before_store_state_or_worker_preflight() {
    let root = tempfile::tempdir().unwrap();
    process_project(root.path());
    let result = run(
        root.path(),
        &[
            "shell",
            ".#shell",
            "--command",
            "server",
            "--interactive",
            "--session-state",
            "missing-state",
            "--systemd-user-bus",
            "missing-bus",
            "--store",
            "store",
            "--offline",
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(
        error.contains("same foreground terminal"),
        "{error}"
    );
    assert!(error.contains("--non-interactive"), "{error}");
    for path in [
        "store",
        "missing-state",
        "missing-bus",
        "home",
    ] {
        assert!(
            !root.path().join(path).exists(),
            "preflight created {path}"
        );
    }
}

#[test]
fn interactive_selection_is_validated_before_terminal_or_store() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("main.srx"),
        "outputs { shell: std::Shell = std::Shell { pkgs = []; services = []; }; }",
    )
    .unwrap();
    let locked = run(root.path(), &["project", "lock", "."]);
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    let result = run(
        root.path(),
        &[
            "shell",
            ".#shell",
            "--command",
            "missing",
            "--interactive",
            "--session-state",
            "state",
            "--systemd-user-bus",
            "bus",
            "--store",
            "store",
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(error.contains("no exposed command"), "{error}");
    assert!(!error.contains("foreground terminal"), "{error}");
    for path in ["store", "state", "bus"] {
        assert!(!root.path().join(path).exists());
    }
}

#[path = "shell/interactive.rs"]
mod interactive;

#[test]
fn session_state_requires_managed_profile_before_store_or_worker() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("main.srx"),
        r#"
        outputs { shell: std::Shell = std::Shell { pkgs = []; services = [
            std::Service { id = "cache"; state = std::ServiceState::Session; }
        ]; }; }
    "#,
    )
    .unwrap();
    let locked = run(root.path(), &["project", "lock", "."]);
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    let result = run(
        root.path(),
        &[
            "shell",
            ".#shell",
            "--command",
            "absent",
            "--non-interactive",
            "--store",
            "store",
        ],
    );
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("session state requires managed Shell")
    );
    assert!(!root.path().join("store").exists());
}

#[test]
fn shell_secret_preflight_rejects_direct_mode_and_missing_grants_without_effects() {
    for managed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        process_project(root.path());
        let path = root.path().join("main.srx");
        let text = fs::read_to_string(&path).unwrap().replace(
            "processes = [std::ServiceProcess { id = \"main\"; command = \"server\"; }];",
            "secrets = [\"token\"];",
        );
        fs::write(&path, text).unwrap();
        let locked = run(root.path(), &["project", "lock", "."]);
        assert!(
            locked.status.success(),
            "{}",
            String::from_utf8_lossy(&locked.stderr)
        );
        let mut arguments = vec![
            "shell",
            ".#shell",
            "--command",
            "server",
            "--non-interactive",
            "--store",
            "store",
        ];
        if managed {
            arguments.extend([
                "--session-state",
                "state",
                "--systemd-user-bus",
                "bus",
            ]);
        }
        let result = run(root.path(), &arguments);
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(!result.status.success());
        assert!(
            error.contains(if managed {
                "missing local grant"
            } else {
                "secret"
            }),
            "{error}"
        );
        for absent in ["store", "state", "bus"] {
            assert!(!root.path().join(absent).exists());
        }
    }
}

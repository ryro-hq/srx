//! Operational commands must retain the same source diagnostics as project check.
#![cfg(target_os = "linux")]

use std::{fs, process::Command};

#[test]
fn operational_commands_report_source_locations_before_realization() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path();
    let source = project.join("main.srx");
    let config = project.join("config.toml");
    fs::write(&config, "").unwrap();
    fs::write(
        &source,
        "outputs { os: Os = Os { pkgs = []; services = []; }; }",
    )
    .unwrap();
    let locked = Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(["project", "lock", "."])
        .current_dir(project)
        .output()
        .unwrap();
    assert!(locked.status.success(), "{locked:?}");

    for (text, code) in [
        ("let broken = ;", "srx.syntax.expected-expression"),
        ("let broken = @;", "srx.lexical"),
    ] {
        fs::write(&source, text).unwrap();
        for args in [
            vec!["info", ".#app"],
            vec!["info", ".", "--search", "app"],
            vec!["build", ".#app", "--dry-run"],
            vec!["build", ".", "--all", "--dry-run"],
            vec!["run", ".#app", "--command", "main"],
            vec![
                "shell",
                ".#shell",
                "--command",
                "main",
                "--non-interactive",
            ],
            vec![
                "os",
                "prepare",
                ".#os",
                "--installation",
                "installation",
                "--store",
                "store",
            ],
            vec![
                "project",
                "fetch",
                ".",
                "app",
                "0",
                "--store",
                "store",
                "--root",
                "source",
                "--allow-https",
                "https://example.invalid/source.tar.gz",
            ],
            vec![
                "project",
                "inspect-source",
                ".",
                "app",
                "0",
                "--store",
                "store",
            ],
        ] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_srx"));
            command.args(&args);
            if args[0] != "project" {
                command.arg("--config").arg(&config);
            }
            let output = command
                .current_dir(project)
                .env("XDG_DATA_HOME", project.join("data"))
                .output()
                .unwrap();
            let error = String::from_utf8(output.stderr).unwrap();
            assert_eq!(output.status.code(), Some(1), "{args:?}: {error}");
            assert!(error.contains(code), "{args:?}: {error}");
            assert!(error.contains("main.srx:1:"), "{args:?}: {error}");
            assert!(error.contains(text), "{args:?}: {error}");
            assert!(output.stdout.is_empty(), "{args:?}");
        }
        assert!(!project.join("store").exists());
        assert!(!project.join("installation").exists());
        assert!(!project.join("data").exists());
    }
}

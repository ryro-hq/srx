#![cfg(target_os = "linux")]

#[path = "support/github.rs"]
mod fixture;

#[test]
fn github_cli_reads_and_fetches_pinned_projects_offline_without_rewriting_the_lock() {
    let directory = tempfile::tempdir().unwrap();
    let main = r#"inputs { remote = "github:example/fixture"; } outputs { answer: remote::N = remote::answer(); }"#;
    let lock = fixture::prepare(
        directory.path(),
        main,
        "pub value N(int); pub fn answer() -> N { N(42) }",
        '1',
    );
    std::fs::write(directory.path().join("main.srx"), main).unwrap();
    std::fs::write(directory.path().join("Syrox.lock"), &lock).unwrap();
    for command in [
        vec!["lock", "--check"],
        vec!["lock", "--fetch"],
        vec!["check"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_srx"))
            .args(["--std", "none", "project"])
            .args(command)
            .arg(directory.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(directory.path().join("Syrox.lock")).unwrap(),
            lock
        );
    }
    // Imported values can be checked and fetched offline, but this fixture
    // deliberately does not define an authenticated deployment output.
    let plan = std::process::Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(["--std", "none", "project", "plan"])
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(!plan.status.success());
    assert!(String::from_utf8_lossy(&plan.stderr).contains("authenticated std::Os or std::Shell"));
    assert_eq!(
        std::fs::read_to_string(directory.path().join("Syrox.lock")).unwrap(),
        lock
    );
    std::fs::remove_dir_all(directory.path().join(".syrox")).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_srx"))
        .args([
            "--std", "none", "project", "lock", "--check",
        ])
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("lock --fetch"));
    assert!(!directory.path().join(".syrox").exists());
}

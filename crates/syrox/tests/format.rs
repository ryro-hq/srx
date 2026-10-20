use std::fs;
use std::io::Write as _;
use std::process::{Command, Stdio};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_srx"));
    command.arg("fmt");
    command
}

#[test]
fn formats_without_loading_project_and_check_never_writes() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("Syrox.toml"),
        "invalid project",
    )
    .unwrap();
    let path = directory.path().join("main.srx");
    let original = "// keep\nfn recur()->Missing{recur()}";
    fs::write(&path, original).unwrap();
    let formatted = command().arg(&path).output().unwrap();
    assert!(formatted.status.success(), "{formatted:?}");
    assert!(formatted.stderr.is_empty());
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    let failed_check = command()
        .arg(&path)
        .arg("--check")
        .output()
        .unwrap();
    assert!(!failed_check.status.success());
    assert!(failed_check.stdout.is_empty());
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    fs::write(&path, &formatted.stdout).unwrap();
    let check = command()
        .arg(&path)
        .arg("--check")
        .output()
        .unwrap();
    assert!(check.status.success());
    assert!(check.stdout.is_empty());
    assert_eq!(
        command().arg(path).output().unwrap().stdout,
        formatted.stdout
    );
}

#[test]
fn invalid_sources_never_emit_partial_formatted_text() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("invalid.srx");
    for bytes in [b"fn incomplete(".as_slice(), &[0xff]] {
        fs::write(&path, bytes).unwrap();
        let result = command().arg(&path).output().unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!result.stderr.is_empty());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn stdin_preserves_literal_bytes_and_file_inputs_are_bounded() {
    let mut child = command()
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"fn f()->Text{\"a  b\"} // end")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        result.stdout,
        b"fn f() -> Text {\n    \"a  b\"\n} // end\n"
    );

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.srx");
    fs::File::create(&path)
        .unwrap()
        .set_len(syrox_lang::MAX_SOURCE_BYTES as u64 + 1)
        .unwrap();
    for path in [
        path.as_path(),
        directory.path(),
        std::path::Path::new("/dev/null"),
    ] {
        let result = command().arg(path).output().unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("regular source file"));
    }
}

#[test]
fn formats_public_and_private_module_bindings_and_platform_conditions() {
    let mut child = command()
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"pub let target:Platform=pkgs.forPlatform{system=\"linux-x86_64\";libc=\"musl\";};let selected=if target.libc==\"musl\"{Recipe{}}else{std::Recipe{}};").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let formatted = String::from_utf8(output.stdout).unwrap();
    assert!(formatted.contains("pub let target: Platform"));
    assert!(formatted.contains("let selected = if"));
    assert!(formatted.contains("std::Recipe"));
}

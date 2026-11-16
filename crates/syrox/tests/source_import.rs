use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use syrox_engine::store::{ContentDigest, Store};

fn cli(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_srx"))
        .arg("project")
        .args(arguments)
        .output()
        .unwrap()
}

fn project(path: &Path, maximum: u64) {
    let digest = ContentDigest::sha256(b"source bytes");
    fs::write(
        path.join("main.srx"),
        format!(
            r#"
        fn make() -> Recipe {{ Recipe {{
            package = Package {{ id = "internal"; dependencies = []; }};
            acquisition = Option::Some(Acquisition {{ sources = [SourceRequest {{
                url = "https://unreachable.invalid/pinned.tar";
                sha256 = "{digest}"; maximum_bytes = {maximum};
            }}]; }});
        }} }}
        pub let alias = recipe_ref(make);
    "#
        ),
    )
    .unwrap();
    let locked = cli(&["lock", path.to_str().unwrap()]);
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
}

fn import(project: &Path, file: &Path, store: &Path, index: &str, root: &str) -> Output {
    cli(&[
        "import-source",
        project.to_str().unwrap(),
        "alias",
        index,
        "--file",
        file.to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
        "--root",
        root,
    ])
}

#[test]
fn relative_source_and_store_paths_use_the_command_directory_without_relaxing_store_validation() {
    let directory = tempfile::tempdir().unwrap();
    project(directory.path(), 12);
    fs::write(
        directory.path().join("payload.bin"),
        b"source bytes",
    )
    .unwrap();
    let run = |store: &str| {
        Command::new(env!("CARGO_BIN_EXE_srx"))
            .current_dir(directory.path())
            .args([
                "project",
                "import-source",
                ".",
                "alias",
                "0",
                "--file",
                "payload.bin",
                "--store",
                store,
                "--root",
                "relative_source",
            ])
            .output()
            .unwrap()
    };
    let result = run("relative-store");
    assert!(result.status.success(), "{result:?}");
    let path = directory.path().join("relative-store");
    let store = Store::open_existing(&path).unwrap();
    assert!(
        store
            .operation()
            .unwrap()
            .verify(ContentDigest::sha256(b"source bytes"))
            .unwrap()
            .is_some()
    );
    assert!(
        path.join("roots/retained/relative_source")
            .is_file()
    );
    let bad = run("absent-parent/../unexpected-store");
    assert!(!bad.status.success());
    assert!(!directory.path().join("absent-parent").exists());
    assert!(!directory.path().join("unexpected-store").exists());
}

#[test]
fn imported_source_is_retained_offline_without_changing_the_project_or_its_url() {
    let directory = tempfile::tempdir().unwrap();
    let source = tempfile::tempdir().unwrap();
    project(directory.path(), 12);
    let lock = fs::read(directory.path().join("Syrox.lock")).unwrap();
    let file = source.path().join("source with spaces");
    fs::write(&file, b"source bytes").unwrap();
    let store_path = source.path().join("store");
    let output = import(
        directory.path(),
        &file,
        &store_path,
        "0",
        "offline_source",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("(12 bytes"));
    let store = Store::open_existing(&store_path).unwrap();
    assert!(
        store
            .operation()
            .unwrap()
            .verify(ContentDigest::sha256(b"source bytes"))
            .unwrap()
            .is_some()
    );
    assert!(
        store_path
            .join("roots/retained/offline_source")
            .is_file()
    );
    assert_eq!(
        fs::read(directory.path().join("Syrox.lock")).unwrap(),
        lock
    );
    let plan = cli(&[
        "plan",
        directory.path().to_str().unwrap(),
    ]);
    assert!(plan.status.success());
    assert!(
        String::from_utf8_lossy(&plan.stdout).contains("https://unreachable.invalid/pinned.tar")
    );
    // A cached digest must not let a different selected file pass verification.
    fs::write(&file, b"forged bytes").unwrap();
    let bad = import(directory.path(), &file, &store_path, "0", "bad");
    assert!(!bad.status.success());
    assert!(!store_path.join("roots/retained/bad").exists());
}

#[test]
fn lock_drift_and_invalid_indices_are_rejected_before_source_or_store_access() {
    let directory = tempfile::tempdir().unwrap();
    project(directory.path(), 12);
    let store = directory.path().join("absent-store");
    let file = directory.path().join("absent-source");
    let invalid = import(directory.path(), &file, &store, "1", "source");
    assert!(!invalid.status.success());
    assert!(
        String::from_utf8_lossy(&invalid.stderr).contains("no acquisition source at that index")
    );
    assert!(!store.exists());
    fs::write(
        directory.path().join("main.srx"),
        "value Changed(int); outputs { changed: Changed = 1; }",
    )
    .unwrap();
    let drift = import(directory.path(), &file, &store, "0", "source");
    assert!(!drift.status.success());
    assert!(String::from_utf8_lossy(&drift.stderr).contains("drift"));
    assert!(!store.exists());
}

#[test]
fn symlinks_and_nonregular_files_are_refused_without_initializing_a_store() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    project(directory.path(), 12);
    let file = directory.path().join("source");
    fs::write(&file, b"source bytes").unwrap();
    let link = directory.path().join("link");
    symlink(&file, &link).unwrap();
    let parent = directory.path().join("parent-link");
    symlink(directory.path(), &parent).unwrap();
    let store = directory.path().join("absent-store");
    for selected in [
        link,
        parent.join("source"),
        directory.path().to_owned(),
    ] {
        assert!(
            !import(directory.path(), &selected, &store, "0", "source")
                .status
                .success()
        );
        assert!(!store.exists());
    }
}

#[test]
fn one_byte_over_the_locked_limit_never_publishes_an_object_or_root() {
    let directory = tempfile::tempdir().unwrap();
    project(directory.path(), 11);
    let file = directory.path().join("source");
    fs::write(&file, b"source bytes").unwrap();
    let path = directory.path().join("store");
    let output = import(directory.path(), &file, &path, "0", "source");
    assert!(!output.status.success());
    assert!(!path.join("roots/retained/source").exists());
    let store = Store::open_existing(&path).unwrap();
    assert!(
        store
            .operation()
            .unwrap()
            .verify(ContentDigest::sha256(b"source bytes"))
            .unwrap()
            .is_none()
    );
}

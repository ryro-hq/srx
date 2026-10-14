//! Public bundle transport and admission tests. Metadata ELF fixtures do not
//! pretend to execute; opted-in host tests cover the runtime process boundary.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[path = "bundle/fixtures.rs"]
mod fixtures;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use syrox_engine::{store::ContentDigest, store::RootName, store::Store};

fn invoke(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(arguments)
        .output()
        .unwrap()
}

fn import(store: &Path, file: &Path, root: &str, manifest: ContentDigest) -> Output {
    invoke(&[
        "bundle",
        "import",
        "--store",
        store.to_str().unwrap(),
        "--root",
        root,
        "--manifest-sha256",
        &manifest.to_string(),
        "--file",
        file.to_str().unwrap(),
    ])
}

#[test]
fn bundle_input_shape_is_rejected_before_creating_store() {
    let temporary = tempfile::tempdir().unwrap();
    let store = temporary.path().join("receiver");
    let oversized = temporary.path().join("oversized");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(syrox_engine::bundle::MAX_BUNDLE_BYTES + 1)
        .unwrap();
    for input in [
        Path::new("/dev/null"),
        temporary.path(),
        &oversized,
    ] {
        let result = import(
            &store,
            input,
            "imported",
            ContentDigest::sha256(b"manifest"),
        );
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("regular file"));
        assert!(!store.exists());
    }
}

#[test]
#[allow(unsafe_code)] // Create a named pipe fixture; no writer is ever opened.
fn fifo_bundle_without_a_writer_is_rejected_promptly() {
    use std::os::unix::ffi::OsStrExt as _;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    struct Reap(std::process::Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let temporary = tempfile::tempdir().unwrap();
    let fifo = temporary.path().join("input");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: name is a live NUL-terminated path in our private fixture directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let store = temporary.path().join("receiver");
    let mut child = Reap(
        Command::new(env!("CARGO_BIN_EXE_srx"))
            .args(["bundle", "import", "--store"])
            .arg(&store)
            .args([
                "--root",
                "imported",
                "--manifest-sha256",
            ])
            .arg(ContentDigest::sha256(b"manifest").to_string())
            .arg("--file")
            .arg(&fifo)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "bundle import blocked on FIFO"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!store.exists());
}

#[test]
fn malformed_bundle_import_never_publishes_a_root() {
    let help = invoke(&["bundle", "--help"]);
    assert!(
        help.status.success(),
        "{}",
        String::from_utf8_lossy(&help.stderr)
    );
    let temporary = tempfile::tempdir().unwrap();
    let store_path = temporary.path().join("store");
    Store::initialize(&store_path).unwrap();
    let input = temporary.path().join("bundle");
    let root = RootName::new("imported").unwrap();
    for bytes in [
        b"".as_slice(),
        b"truncated",
        b"syrox-bundle\n",
    ] {
        fs::write(&input, bytes).unwrap();
        let result = import(
            &store_path,
            &input,
            root.as_str(),
            ContentDigest::sha256(b"manifest"),
        );
        assert!(!result.status.success());
        assert!(references(&store_path, &root).is_none());
    }
}

struct Fixture {
    source: tempfile::TempDir,
    digest: ContentDigest,
    bytes: Vec<u8>,
    artifacts: Vec<ContentDigest>,
}

fn fixture() -> Fixture {
    use syrox_engine::{
        bundle::export_bundle, cancellation::Cancellation, result::ResultManifest,
        result::admit_result,
    };
    let source = tempfile::tempdir().unwrap();
    let store = Store::initialize(source.path()).unwrap();
    let app_action = ContentDigest::sha256(b"application identity, not a build action");
    let lib_action = ContentDigest::sha256(b"library identity, not a build action");
    let loader_action = ContentDigest::sha256(b"loader identity, not a build action");
    let data_action = ContentDigest::sha256(b"data identity, not a build action");
    let interpreter = format!("/syrox/store/{loader_action}/out/bin/loader");
    let runpath = format!("/syrox/store/{lib_action}/lib/usr/lib");
    let app = fixtures::elf(
        2,
        Some(&interpreter),
        &["libanswer.so.1"],
        None,
        Some(&runpath),
    );
    let lib = fixtures::elf(3, None, &[], Some("libanswer.so.1"), None);
    let loader = fixtures::elf(3, None, &[], None, None);
    let definitions = [
        (
            "app",
            app_action,
            "out",
            "bin/app",
            fixtures::artifact(&[("bin/app", true, &app)]),
        ),
        (
            "app2",
            app_action,
            "tools",
            "bin/other",
            fixtures::artifact(&[("bin/other", true, &app)]),
        ),
        (
            "data",
            data_action,
            "doc",
            "",
            fixtures::artifact(&[("readme", false, b"portable data")]),
        ),
        (
            "lib",
            lib_action,
            "lib",
            "",
            fixtures::artifact(&[("usr/lib/libanswer.so.1", true, &lib)]),
        ),
        (
            "loader",
            loader_action,
            "out",
            "bin/loader",
            fixtures::artifact(&[("bin/loader", true, &loader)]),
        ),
    ];
    let lease = store.operation().unwrap();
    let mut entries = Vec::new();
    let mut artifacts = Vec::new();
    for (key, action, output, _entry, bytes) in definitions {
        let artifact = ContentDigest::sha256(&bytes);
        lease
            .ingest(bytes.as_slice(), artifact, bytes.len() as u64)
            .unwrap();
        artifacts.push(artifact);
        entries.push(format!(r#""{key}":{{"action":"{action}","output":"{output}","artifact":"{artifact}","files":1}}"#));
    }
    drop(lease);
    let encoded = format!(
        "syrox-result-v2\n{{\"outputs\":{{{}}},\"commands\":{{\"alias\":{{\"application\":\"app2\",\"application_path\":\"bin/other\",\"loader\":\"loader\",\"loader_path\":\"bin/loader\",\"libraries\":[\"lib\"]}},\"main\":{{\"application\":\"app\",\"application_path\":\"bin/app\",\"loader\":\"loader\",\"loader_path\":\"bin/loader\",\"libraries\":[\"lib\"]}}}}}}\n",
        entries.join(",")
    );
    let manifest = ResultManifest::parse(encoded.as_bytes()).unwrap();
    let digest = manifest.digest().unwrap();
    let root = RootName::new("source_result").unwrap();
    let cancellation = Cancellation::default();
    let admitted = admit_result(&store, &root, &manifest, digest, &cancellation).unwrap();
    let runtime = admitted
        .command("main")
        .unwrap()
        .open(&store, &cancellation)
        .unwrap();
    assert_eq!(runtime.mounts().unwrap().len(), 3);
    drop(runtime);
    let mut bytes = Vec::new();
    export_bundle(&store, &root, digest, &mut bytes, &cancellation).unwrap();
    Fixture {
        source,
        digest,
        bytes,
        artifacts,
    }
}

#[test]
fn imported_dynamic_closure_and_data_reopen_without_sources_or_toolchain() {
    use syrox_engine::{cancellation::Cancellation, result::AdmittedResult};
    let fixture = fixture();
    let temporary = tempfile::tempdir().unwrap();
    let receiver = temporary.path().join("receiver");
    let input = temporary.path().join("bundle");
    fs::write(&input, &fixture.bytes).unwrap();
    // Destroy the producing Store before admission on the receiving side.
    fixture.source.close().unwrap();
    let imported = import(&receiver, &input, "received", fixture.digest);
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let store = Store::open(&receiver).unwrap();
    let root = RootName::new("received").unwrap();
    let cancellation = Cancellation::default();
    let admitted = AdmittedResult::open(&store, &root, fixture.digest, &cancellation).unwrap();
    for command in ["main", "alias"] {
        let runtime = admitted
            .command(command)
            .unwrap()
            .open(&store, &cancellation)
            .unwrap();
        assert_eq!(runtime.mounts().unwrap().len(), 3);
        assert!(runtime.entry().ends_with(if command == "main" {
            "/out/bin/app"
        } else {
            "/tools/bin/other"
        }));
    }
    let data = admitted
        .output("data")
        .unwrap()
        .open(&store, &cancellation)
        .unwrap();
    assert_eq!(
        data.read_file("readme", 64, &cancellation)
            .unwrap(),
        b"portable data"
    );
    let mut expected = fixture.artifacts;
    expected.push(fixture.digest);
    expected.sort();
    expected.dedup();
    assert_eq!(references(&receiver, &root).unwrap(), expected);
    let inspected = invoke(&[
        "bundle",
        "inspect",
        "--store",
        receiver.to_str().unwrap(),
        "--root",
        "received",
        "--manifest-sha256",
        &fixture.digest.to_string(),
    ]);
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
}

#[test]
fn wrong_digest_truncated_and_tampered_bundles_do_not_admit_results() {
    let fixture = fixture();
    let temporary = tempfile::tempdir().unwrap();
    let receiver = temporary.path().join("receiver");
    Store::initialize(&receiver).unwrap();
    let input = temporary.path().join("bundle");
    let root = RootName::new("rejected").unwrap();
    let mut corrupted = fixture.bytes.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xff;
    let header = b"syrox-runtime-bundle-v1\n".len();
    let manifest_length = u32::from_le_bytes(
        fixture.bytes[header..header + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut oversized_manifest = fixture.bytes.clone();
    oversized_manifest[header..header + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut oversized_artifact = fixture.bytes.clone();
    let length_offset = header + 4 + manifest_length + 4 + 32;
    oversized_artifact[length_offset..length_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut trailing = fixture.bytes.clone();
    trailing.extend_from_slice(b"unauthenticated trailing data");
    for (bytes, expected) in [
        (
            fixture.bytes.as_slice(),
            ContentDigest::sha256(b"wrong manifest"),
        ),
        (
            &fixture.bytes[..fixture.bytes.len() / 2],
            fixture.digest,
        ),
        (corrupted.as_slice(), fixture.digest),
        (oversized_manifest.as_slice(), fixture.digest),
        (oversized_artifact.as_slice(), fixture.digest),
        (trailing.as_slice(), fixture.digest),
    ] {
        fs::write(&input, bytes).unwrap();
        let result = import(&receiver, &input, root.as_str(), expected);
        assert!(!result.status.success());
        assert!(references(&receiver, &root).is_none());
    }
}

#[test]
fn cancellation_during_artifact_transport_is_neutral_and_does_not_publish() {
    use std::io::Cursor;
    use syrox_engine::{bundle::BundleError, bundle::import_bundle, cancellation::Cancellation};

    struct CancelPayload<'a> {
        input: Cursor<&'a [u8]>,
        payload_offset: u64,
        cancellation: &'a Cancellation,
    }
    impl std::io::Read for CancelPayload<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.input.position() >= self.payload_offset {
                self.cancellation.cancel();
            }
            self.input.read(buffer)
        }
    }

    let fixture = fixture();
    let destination = tempfile::tempdir().unwrap();
    let store = Store::initialize(destination.path()).unwrap();
    let root = RootName::new("cancelled_transport").unwrap();
    let cancellation = Cancellation::default();
    let header = b"syrox-runtime-bundle-v1\n".len();
    let manifest_size = u32::from_le_bytes(
        fixture.bytes[header..header + 4]
            .try_into()
            .unwrap(),
    );
    let mut input = CancelPayload {
        input: Cursor::new(&fixture.bytes),
        payload_offset: header as u64 + 4 + u64::from(manifest_size) + 4 + 40,
        cancellation: &cancellation,
    };
    assert!(matches!(
        import_bundle(
            &store,
            &root,
            fixture.digest,
            &mut input,
            &cancellation
        ),
        Err(BundleError::Cancelled)
    ));
    assert!(references(destination.path(), &root).is_none());
}

fn references(store: &Path, root: &RootName) -> Option<Vec<ContentDigest>> {
    let path = store.join("roots/retained").join(root.as_str());
    match fs::read_to_string(path) {
        Ok(bytes) => Some(
            bytes
                .lines()
                .filter_map(|line| line.strip_prefix("sha256="))
                .map(|hex| hex.parse().unwrap())
                .collect(),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("read test root: {error}"),
    }
}

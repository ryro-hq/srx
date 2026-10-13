use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use syrox_engine::{
    cancellation::Cancellation, result::ResultManifest, result::admit_result, store::ContentDigest,
    store::RootName, store::Store,
};

pub(super) const MAX_BINARY: u64 = 128 * 1024 * 1024;
pub(super) fn absolute(name: &str) -> PathBuf {
    let path =
        PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("explicit {name} required")));
    assert!(
        path.is_absolute()
            && !path
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir)),
        "{name} must be absolute without parent traversal"
    );
    path
}
pub(super) fn pinned(name: &str) -> Vec<u8> {
    let path = absolute(name);
    let digest: ContentDigest = std::env::var(format!("{name}_SHA256"))
        .expect("explicit binary SHA256 required")
        .parse()
        .unwrap();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .unwrap();
    let before = file.metadata().unwrap();
    assert!(before.is_file() && before.len() > 0 && before.len() <= MAX_BINARY);
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_BINARY + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    let after = file.metadata().unwrap();
    assert_eq!(before.len(), bytes.len() as u64);
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec()
        ),
        (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec()
        )
    );
    assert_eq!(
        ContentDigest::sha256(&bytes),
        digest,
        "candidate bytes differ from explicit pin"
    );
    require_static(&bytes);
    bytes
}
fn number(bytes: &[u8], offset: usize, width: usize) -> u64 {
    let mut result = [0_u8; 8];
    result[..width].copy_from_slice(
        bytes
            .get(offset..offset + width)
            .expect("bounded ELF field"),
    );
    u64::from_le_bytes(result)
}
/// Static `x86_64` ELF candidate shape only; no claims about ABI, symbols or tools.
fn require_static(bytes: &[u8]) {
    assert!(bytes.len() >= 64 && &bytes[..6] == b"\x7fELF\x02\x01");
    assert_eq!(number(bytes, 18, 2), 62);
    assert!(matches!(number(bytes, 16, 2), 2 | 3));
    let table = usize::try_from(number(bytes, 32, 8)).unwrap();
    let count = usize::try_from(number(bytes, 56, 2)).unwrap();
    assert!((1..=128).contains(&count));
    assert_eq!(number(bytes, 54, 2), 56);
    assert!(
        table
            .checked_add(count * 56)
            .is_some_and(|end| end <= bytes.len())
    );
    let entry = number(bytes, 24, 8);
    let mut executable = false;
    for index in 0..count {
        let at = table + index * 56;
        let kind = number(bytes, at, 4);
        assert_ne!(
            kind, 3,
            "host PT_INTERP is prohibited for gate binaries"
        );
        let offset = usize::try_from(number(bytes, at + 8, 8)).unwrap();
        let size = usize::try_from(number(bytes, at + 32, 8)).unwrap();
        assert!(
            offset
                .checked_add(size)
                .is_some_and(|end| end <= bytes.len())
        );
        if kind == 1 && number(bytes, at + 4, 4) & 1 != 0 {
            let address = number(bytes, at + 16, 8);
            executable |= entry != 0
                && entry >= address
                && address
                    .checked_add(size as u64)
                    .is_some_and(|end| entry < end);
        }
        if kind == 2 {
            assert_eq!(size % 16, 0);
            let mut terminated = false;
            for pair in bytes[offset..offset + size].as_chunks::<16>().0 {
                let tag = number(pair, 0, 8);
                if tag == 0 {
                    terminated = true;
                    break;
                }
                assert!(
                    !matches!(tag, 1 | 14 | 15 | 29),
                    "dynamic dependency/search directive in static gate binary"
                );
            }
            assert!(terminated);
        }
    }
    assert!(
        executable,
        "ELF entry must be in a file-backed executable LOAD"
    );
}
fn write_private(path: &Path, bytes: &[u8], mode: u32) {
    use std::io::Write as _;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    file.set_permissions(fs::Permissions::from_mode(mode))
        .unwrap();
}
pub(super) fn create() -> PathBuf {
    let cli = pinned("SYROX_INTERACTIVE_CLI");
    let worker = pinned("SYROX_INTERACTIVE_WORKER");
    let payload = pinned("SYROX_INTERACTIVE_PAYLOAD");
    let parent = absolute("SYROX_INTERACTIVE_PARENT");
    let parent_meta = fs::symlink_metadata(&parent).unwrap();
    // SAFETY: geteuid has no arguments or memory effects.
    assert!(
        parent_meta.is_dir()
            && parent_meta.mode() & 0o7777 == 0o700
            && parent_meta.uid() == unsafe { libc::geteuid() }
    );
    let root = tempfile::Builder::new()
        .prefix("tty-")
        .tempdir_in(&parent)
        .unwrap()
        .keep();
    eprintln!("interactive gate evidence: {}", root.display());
    for name in [
        "bin", "work", "state", "project", "home",
    ] {
        fs::create_dir(root.join(name)).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    write_private(&root.join("bin/srx"), &cli, 0o500);
    write_private(&root.join("bin/syrox-worker"), &worker, 0o500);
    let store = Store::initialize(&root.join("store")).unwrap();
    let artifact = super::bundle_fixture::artifact(&[("bin/payload", true, &payload)]);
    let artifact_pin = ContentDigest::sha256(&artifact);
    store
        .operation()
        .unwrap()
        .ingest(
            artifact.as_slice(),
            artifact_pin,
            artifact.len() as u64,
        )
        .unwrap();
    let action = ContentDigest::sha256(&payload);
    let wire = format!(
        "syrox-result-v2\n{{\"outputs\":{{\"payload\":{{\"action\":\"{action}\",\"output\":\"out\",\"artifact\":\"{artifact_pin}\",\"files\":1}}}},\"commands\":{{\"payload\":{{\"application\":\"payload\",\"application_path\":\"bin/payload\",\"loader\":null,\"loader_path\":null,\"libraries\":[]}}}}}}\n"
    );
    let manifest = ResultManifest::parse(wire.as_bytes()).unwrap();
    let pin = manifest.digest().unwrap();
    admit_result(
        &store,
        &RootName::new("terminal_gate").unwrap(),
        &manifest,
        pin,
        &Cancellation::default(),
    )
    .unwrap();
    fs::write(root.join("manifest-pin"), pin.to_string()).unwrap();
    fs::write(
        root.join("worker-pin"),
        ContentDigest::sha256(&worker).to_string(),
    )
    .unwrap();
    fs::write(root.join("project/main.srx"), format!(r#"
fn tool() -> std::Recipe {{ std::Recipe {{
 package = std::Package {{ id = "terminal-gate"; dependencies = []; }};
 imported = std::Option::Some(std::ImportedResult {{ root = "terminal_gate"; manifest = "{pin}"; entries = [std::ImportedOutput {{ output = "out"; key = "payload"; }}]; }});
 commands = [std::Command {{ name = "payload"; output = "out"; path = "bin/payload"; }}];
}} }}
outputs {{ shell: std::Shell = std::Shell {{ pkgs = [std::select_command(std::recipe_ref(tool), "out", "payload")]; services = []; }}; }}
"#)).unwrap();
    // Lock with the explicitly pinned CLI, before touching the manager.
    let mut lock = super::driver::GuardedChild::spawn(
        super::driver::command(&root)
            .args(["project", "lock", "."])
            .current_dir(root.join("project")),
    );
    assert!(
        lock.wait(std::time::Instant::now() + std::time::Duration::from_secs(30))
            .success()
    );
    // This fixture deliberately covers owner + foreground, not configured services.
    root
}
pub(super) fn verify_retained(root: &Path) {
    let store = Store::open_existing(&root.join("store")).unwrap();
    let pin = fs::read_to_string(root.join("manifest-pin"))
        .unwrap()
        .parse()
        .unwrap();
    let admitted = syrox_engine::result::AdmittedResult::open(
        &store,
        &RootName::new("terminal_gate").unwrap(),
        pin,
        &Cancellation::default(),
    )
    .unwrap();
    let closure = admitted
        .command("payload")
        .unwrap()
        .open(&store, &Cancellation::default())
        .unwrap();
    drop(closure);
    assert!(root.join("project/main.srx").is_file());
}

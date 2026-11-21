use super::*;

use crate::store::GcRequest;

use std::fs;

use std::os::unix::fs::{PermissionsExt as _, symlink};

use std::path::PathBuf;

use std::sync::{Arc, Barrier, mpsc};

use std::time::Duration;

mod collection;

mod identity;

mod index;

mod publication;

mod reuse;

const SOURCE: &[u8] = b"fixture source";

const TOOLCHAIN: &[u8] = b"syrox-host-toolchain\nfixture toolchain";

pub(crate) fn action() -> Action {
    Action {
        program: super::super::BuildProgram {
            profile: super::super::BuildProfile::HostBootstrap,
            resources: super::super::BuildResources::Standard,
            source_format: super::super::BuildSourceFormat::Gzip,
            outputs: vec!["out".into()],
            steps: vec![super::super::BuildStep::Directory(
                super::super::BuildPath::Work("source".into()),
            )],
        },
        source: ContentDigest::sha256(SOURCE),
        toolchain: Some(ContentDigest::sha256(TOOLCHAIN)),
        worker: ContentDigest::sha256(b"trusted worker"),
        directory: "fixture".into(),
        inputs: Vec::new(),
    }
}

fn description(action: &Action) -> BuildDescription<'_> {
    BuildDescription {
        source: action.source,
        program: &action.program,
        directory: &action.directory,
    }
}

pub(crate) fn retained(lease: &OperationLease, action: &Action, content: &[u8]) -> BuildResult {
    retained_at(lease, action, "bin/hello", content)
}

pub(crate) fn retained_at(
    lease: &OperationLease,
    action: &Action,
    path: &str,
    content: &[u8],
) -> BuildResult {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, content).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let mut artifact = Vec::new();
    artifact::pack(directory.path(), &mut artifact).unwrap();
    let receipt = Receipt::new(action, ContentDigest::sha256(&artifact), 1);
    let action_bytes = action.encode();
    let receipt_bytes = receipt.encode();
    for bytes in [
        SOURCE,
        TOOLCHAIN,
        &action_bytes,
        &artifact,
        &receipt_bytes,
    ] {
        lease
            .ingest(
                bytes,
                ContentDigest::sha256(bytes),
                bytes.len() as u64,
            )
            .unwrap();
    }
    let root = receipt.root();
    lease
        .publish_root(&root, &receipt.references())
        .unwrap();
    BuildResult {
        retention: lease
            .retain_objects(&receipt.references(), &[])
            .unwrap(),
        execution: BuildExecution::Built {
            operation: "test-producer".into(),
        },
        action: receipt.action,
        artifact: receipt.output("out").unwrap().artifact,
        receipt: receipt.digest(),
        toolchain: receipt.toolchain,
        files: receipt.output("out").unwrap().files,
        root,
    }
}

pub(crate) fn retained_with_library(
    lease: &OperationLease,
    action: &Action,
    content: &[u8],
    soname: &str,
    library: &[u8],
) -> BuildResult {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir_all(directory.path().join("bin")).unwrap();
    fs::create_dir_all(directory.path().join("usr/lib")).unwrap();
    fs::write(directory.path().join("bin/hello"), content).unwrap();
    fs::write(
        directory.path().join("usr/lib").join(soname),
        library,
    )
    .unwrap();
    fs::set_permissions(
        directory.path().join("bin/hello"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mut artifact = Vec::new();
    artifact::pack(directory.path(), &mut artifact).unwrap();
    let receipt = Receipt::new(action, ContentDigest::sha256(&artifact), 2);
    let action_bytes = action.encode();
    let receipt_bytes = receipt.encode();
    for bytes in [
        SOURCE,
        TOOLCHAIN,
        &action_bytes,
        &artifact,
        &receipt_bytes,
    ] {
        lease
            .ingest(
                bytes,
                ContentDigest::sha256(bytes),
                bytes.len() as u64,
            )
            .unwrap();
    }
    lease
        .publish_root(&receipt.root(), &receipt.references())
        .unwrap();
    BuildResult {
        retention: lease
            .retain_objects(&receipt.references(), &[])
            .unwrap(),
        execution: BuildExecution::Cached,
        action: action.digest(),
        artifact: receipt.output("out").unwrap().artifact,
        receipt: receipt.digest(),
        toolchain: receipt.toolchain,
        files: 2,
        root: receipt.root(),
    }
}

pub(crate) fn retained_with_library_alias(
    lease: &OperationLease,
    action: &Action,
    content: &[u8],
    soname: &str,
    versioned: &str,
    library: &[u8],
) -> BuildResult {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir_all(directory.path().join("bin")).unwrap();
    fs::create_dir_all(directory.path().join("usr/lib")).unwrap();
    fs::write(directory.path().join("bin/hello"), content).unwrap();
    fs::write(
        directory.path().join("usr/lib").join(versioned),
        library,
    )
    .unwrap();
    fs::write(
        directory.path().join("usr/lib/libdevel.so"),
        b"GROUP ( libanswer.so.1 )\n",
    )
    .unwrap();
    symlink(
        versioned,
        directory.path().join("usr/lib").join(soname),
    )
    .unwrap();
    fs::set_permissions(
        directory.path().join("bin/hello"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mut artifact = Vec::new();
    artifact::pack(directory.path(), &mut artifact).unwrap();
    let receipt = Receipt::new(action, ContentDigest::sha256(&artifact), 4);
    let action_bytes = action.encode();
    let receipt_bytes = receipt.encode();
    for bytes in [
        SOURCE,
        TOOLCHAIN,
        &action_bytes,
        &artifact,
        &receipt_bytes,
    ] {
        lease
            .ingest(
                bytes,
                ContentDigest::sha256(bytes),
                bytes.len() as u64,
            )
            .unwrap();
    }
    lease
        .publish_root(&receipt.root(), &receipt.references())
        .unwrap();
    BuildResult {
        retention: lease
            .retain_objects(&receipt.references(), &[])
            .unwrap(),
        execution: BuildExecution::Cached,
        action: action.digest(),
        artifact: receipt.output("out").unwrap().artifact,
        receipt: receipt.digest(),
        toolchain: receipt.toolchain,
        files: 4,
        root: receipt.root(),
    }
}

fn index_path(root: &Path, action: &Action) -> PathBuf {
    let digest = action.digest().to_string();
    root.join(".syrox-store/actions")
        .join(&digest[..2])
        .join(digest)
}

/// Two independently mountable outputs from one receipt for runtime closure tests.
pub(crate) fn retained_split_runtime(
    store: &Store,
    loader_bytes: &[u8],
    library_bytes: &[u8],
) -> (RootName, ContentDigest, ContentDigest) {
    use crate::build::records::NamedOutput;
    let mut action = action();
    action.directory = "split-loader-library".into();
    action.program.outputs = vec!["lib".into(), "out".into()];
    let pack = |path: &str, bytes: &[u8]| {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, bytes).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        let mut result = Vec::new();
        artifact::pack(directory.path(), &mut result).unwrap();
        result
    };
    let loader_artifact = pack("bin/hello", loader_bytes);
    let library_artifact = pack("usr/lib/libsplit.so.1", library_bytes);
    let receipt = Receipt::new(
        &action,
        ContentDigest::sha256(&loader_artifact),
        1,
    )
    .with_outputs(
        &action,
        BTreeMap::from([(
            "lib".into(),
            NamedOutput {
                artifact: ContentDigest::sha256(&library_artifact),
                files: 1,
            },
        )]),
    )
    .unwrap();
    let action_bytes = action.encode();
    let receipt_bytes = receipt.encode();
    let lease = store.operation().unwrap();
    for bytes in [
        &b"fixture source"[..],
        &b"syrox-host-toolchain\nfixture toolchain"[..],
        &action_bytes,
        &loader_artifact,
        &library_artifact,
        &receipt_bytes,
    ] {
        lease
            .ingest(
                bytes,
                ContentDigest::sha256(bytes),
                bytes.len() as u64,
            )
            .unwrap();
    }
    lease
        .publish_root(&receipt.root(), &receipt.references())
        .unwrap();
    drop(lease);
    (receipt.root(), receipt.digest(), action.digest())
}

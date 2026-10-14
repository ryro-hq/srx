//! Independently encoded v4 fixtures for public CLI/LSP tests; no network server
//! or test hook is present in the executable under test.
use std::fs;
use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};
use syrox_engine::{store::ContentDigest, store::RootName, store::Store};

pub fn prepare(root: &Path, consumer: &str, remote: &str, revision: char) -> String {
    let child = tempfile::tempdir().unwrap();
    fs::write(child.path().join("main.srx"), remote).unwrap();
    syrox_engine::project::lock_project(child.path()).unwrap();
    let child_lock = fs::read(child.path().join("Syrox.lock")).unwrap();
    let commit = revision.to_string().repeat(40);
    let prefix = format!("fixture-{commit}");
    let mut tar = member(
        "pax_global_header",
        format!("52 comment={commit}\n").as_bytes(),
        b'g',
    );
    tar.extend(member(&format!("{prefix}/"), b"", b'5'));
    tar.extend(member(
        &format!("{prefix}/main.srx"),
        remote.as_bytes(),
        b'0',
    ));
    tar.extend(member(
        &format!("{prefix}/Syrox.lock"),
        &child_lock,
        b'0',
    ));
    tar.extend_from_slice(&[0; 1024]);
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&tar).unwrap();
    let archive = gzip.finish().unwrap();
    let digest = ContentDigest::sha256(&archive);
    let store = Store::initialize(&root.join(".syrox/github")).unwrap();
    let lease = store.operation().unwrap();
    lease
        .ingest(archive.as_slice(), digest, archive.len() as u64)
        .unwrap();
    lease
        .publish_root(
            &RootName::new(format!("github-{digest}")).unwrap(),
            &[digest],
        )
        .unwrap();
    let mut project = Sha256::new();
    project.update(13_u64.to_be_bytes());
    project.update(b"syrox-project");
    project.update((consumer.len() as u64).to_be_bytes());
    project.update(32_u64.to_be_bytes());
    project.update(Sha256::digest(consumer.as_bytes()));
    project.update(0_u64.to_be_bytes());
    format!(
        "syrox-lock-v4\nhash sha256\nproject {:x}\nmain {} {}\ninputs 0\nstd absent\nedges 1\ngithub-edge {} {} {} {commit} {digest}\nassets 0\nend\n",
        project.finalize(),
        consumer.len(),
        ContentDigest::sha256(consumer.as_bytes()),
        hex(b"remote"),
        hex(b"github:example/fixture"),
        ContentDigest::sha256(&child_lock)
    )
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::new(), |mut result, byte| {
            write!(result, "{byte:02x}").unwrap();
            result
        })
}

fn member(path: &str, data: &[u8], kind: u8) -> Vec<u8> {
    let mut header = [0_u8; 512];
    header[..path.len()].copy_from_slice(path.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
    header[156] = kind;
    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(data);
    bytes.resize(bytes.len().div_ceil(512) * 512, 0);
    bytes
}

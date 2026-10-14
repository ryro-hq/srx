//! Static release pairs shared by build and kernel jobs.
//!
//! The bundle binds executable bytes to a target, toolchain and exact source
//! inventory. Import checks the complete inventory before replacing any locally
//! prepared release executable; libtest binaries keep their own preparation.

use super::{Result, common, snapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

#[path = "../../elf_release.rs"]
#[cfg_attr(test, allow(unused_imports))]
mod elf_release;

pub const TARGETS: [&str; 2] = [
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
];

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    schema: u32,
    target: String,
    rust: String,
    sources: BTreeMap<String, String>,
    binaries: BTreeMap<String, String>,
}

fn static_binary(path: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 128 * 1024 * 1024 {
        return Err("release candidate exceeds 128 MiB".into());
    }
    if !elf_release::static_x86_64(&bytes) {
        return Err(format!(
            "release candidate is not static ELF64/x86_64: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

pub fn record(root: &Path, directory: &Path, target: &str) -> Result<()> {
    if !TARGETS.contains(&target) {
        return Err("unsupported release target".into());
    }
    if directory.join("manifest.json").exists() {
        return Err("candidate manifest already exists".into());
    }
    let temporary = tempfile::tempdir()?;
    let sources = snapshot::snapshot(root, &temporary.path().join("sources"))?;
    let mut binaries = BTreeMap::new();
    for name in ["srx", "syrox-worker"] {
        let path = directory.join(name);
        static_binary(&path)?;
        binaries.insert(name.to_owned(), snapshot::digest(&path)?);
    }
    let rust = env!("CARGO_PKG_RUST_VERSION");
    let version = std::process::Command::new("rustc")
        .arg("--version")
        .output()?;
    if !version.status.success()
        || !String::from_utf8(version.stdout)?.starts_with(&format!("rustc {rust} "))
    {
        return Err("release manifest requires the pinned Rust compiler".into());
    }
    let manifest = Manifest {
        schema: 1,
        target: target.to_owned(),
        rust: rust.to_owned(),
        sources: serde_json::from_value(sources["files"].clone())?,
        binaries,
    };
    common::save(
        &directory.join("manifest.json"),
        &serde_json::to_value(manifest)?,
    )
}

#[derive(Debug)]
pub struct Bundle {
    pub target: String,
    pub paths: BTreeMap<String, PathBuf>,
    pub pins: BTreeMap<String, String>,
}

pub fn load(directory: &Path, sources: &BTreeMap<String, String>, rust: &str) -> Result<Bundle> {
    let mut bytes = Vec::new();
    fs::File::open(directory.join("manifest.json"))?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("release manifest exceeds 4 MiB".into());
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    if manifest.schema != 1
        || !TARGETS.contains(&manifest.target.as_str())
        || manifest.rust != rust
        || &manifest.sources != sources
    {
        return Err("release bundle target/toolchain/source identity differs".into());
    }
    if manifest
        .binaries
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != ["srx", "syrox-worker"]
    {
        return Err("release bundle must contain exactly CLI and worker pins".into());
    }
    let mut paths = BTreeMap::new();
    for (name, pin) in &manifest.binaries {
        let path = directory.join(name);
        if !snapshot::valid_digest(pin) || snapshot::digest(&path)? != *pin {
            return Err(format!("release bundle candidate changed: {name}").into());
        }
        static_binary(&path)?;
        paths.insert(name.clone(), path);
    }
    Ok(Bundle {
        target: manifest.target,
        paths,
        pins: manifest.binaries,
    })
}

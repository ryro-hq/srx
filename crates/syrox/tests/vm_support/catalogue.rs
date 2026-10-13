//! Run the catalogue's Rust tests against captured core sources and candidates.
use super::{
    Result, common,
    process::{self, Control},
};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            copy_tree(
                &entry.path(),
                &destination.join(entry.file_name()),
            )?;
        } else if entry.file_type()?.is_file() {
            fs::copy(entry.path(), destination.join(entry.file_name()))?;
        } else {
            return Err("catalogue fixture must contain regular files and directories".into());
        }
    }
    Ok(())
}

pub fn run(
    core: &Path,
    catalogue: &Path,
    candidates: &Path,
    evidence: &Path,
    control: &Control,
) -> Result<()> {
    let harness = evidence.join("catalog-harness");
    common::private(&harness)?;
    let engine = serde_json::to_string(&core.join("crates/syrox-engine"))?;
    let mut manifest = format!(
        "[workspace]\n[package]\nname = \"syrox-catalog-tests\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[dependencies]\nsyrox-engine = {{ path = {engine} }}\ntempfile = \"=3.23.0\"\nlibc = \"=1.0.0-alpha.4\"\nserde_json = \"1\"\n"
    );
    for name in [
        "packaging",
        "integrations",
        "bash",
        "managed_chain",
        "seed",
    ] {
        let path = catalogue.join("tests").join(format!("{name}.rs"));
        if !path.is_file() {
            return Err(format!("catalogue test missing: {}", path.display()).into());
        }
        write!(
            manifest,
            "[[test]]\nname = \"{name}\"\npath = {}\n",
            serde_json::to_string(&path)?
        )?;
    }
    fs::write(harness.join("Cargo.toml"), manifest)?;
    fs::copy(
        core.join("Cargo.lock"),
        harness.join("Cargo.lock"),
    )?;
    let fixture = harness.join("catalog");
    common::private(&fixture)?;
    fs::copy(
        catalogue.join("main.srx"),
        fixture.join("main.srx"),
    )?;
    for name in ["recipes", "assets", "integrations"] {
        copy_tree(&catalogue.join(name), &fixture.join(name))?;
    }
    let binary = candidates.join("srx");
    process::command(
        Command::new(&binary)
            .args(["project", "lock"])
            .arg(&fixture),
        &evidence.join("ecosystem-catalog-lock.log"),
        Duration::from_mins(2),
        control,
    )?;
    process::command(
        Command::new(&binary)
            .args(["build", ".#hello", "-f"])
            .arg(fixture.join("main.srx"))
            .arg("--dry-run"),
        &evidence.join("ecosystem-catalog-plan.log"),
        Duration::from_mins(2),
        control,
    )?;
    process::command(
        Command::new("cargo")
            .args([
                "generate-lockfile",
                "--offline",
                "--manifest-path",
            ])
            .arg(harness.join("Cargo.toml"))
            .current_dir(core),
        &evidence.join("ecosystem-catalog-resolve.log"),
        Duration::from_mins(2),
        control,
    )?;
    let effective_lock = super::snapshot::digest(&harness.join("Cargo.lock"))?;
    common::save(
        &evidence.join("ecosystem-catalog-lock.json"),
        &serde_json::json!({
            "source_lock_sha256":super::snapshot::digest(&core.join("Cargo.lock"))?,
            "effective_lock_sha256":effective_lock,
            "manifest_sha256":super::snapshot::digest(&harness.join("Cargo.toml"))?,
            "targets":["packaging","integrations","bash","managed_chain","seed"]
        }),
    )?;
    fs::copy(
        harness.join("Cargo.lock"),
        evidence.join("ecosystem-Cargo.lock"),
    )?;
    process::command(
        Command::new("cargo")
            .args([
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
            ])
            .arg(harness.join("Cargo.toml"))
            .current_dir(core)
            .env("SYROX_CATALOG", &fixture)
            .env("SYROX_CANDIDATE_BIN", &binary),
        &evidence.join("ecosystem-catalog.log"),
        Duration::from_mins(30),
        control,
    )?;
    if super::snapshot::digest(&harness.join("Cargo.lock"))? != effective_lock {
        return Err("catalogue effective Cargo lock changed during checks".into());
    }
    Ok(())
}

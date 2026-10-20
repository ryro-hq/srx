//! Publication requires every independently qualified matrix row.
use super::catalog_qualification::file_digest;
use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::Path,
};
use syrox_engine::{
    bundle::import_bundle,
    cancellation::Cancellation,
    catalog::{Catalog, CatalogLock, LOCK_FILE},
    project::{CheckConfiguration, check_project_lock_with},
    store::{ContentDigest, RootName, Store},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(super) fn release_manifest(
    path: &Path,
    evidence: &Path,
    output: &Path,
    checks: &CheckConfiguration,
) -> Result<String> {
    let catalog = Catalog::load(path)?;
    check_project_lock_with(path, checks)?;
    if catalog.schema == 2 {
        syrox_engine::project::check_catalog_with(path, &catalog, checks)?;
    }
    let previous: CatalogLock = serde_json::from_slice(&fs::read(path.join(LOCK_FILE))?)?;
    let mut lock = catalog.lock(path)?;
    lock.retain_previous(&previous, false)?;
    if lock != previous {
        return Err("catalog lock is stale".into());
    }
    let cancellation = Cancellation::default();
    let mut reports = Vec::new();
    let temporary = tempfile::tempdir()?;
    let receiver = Store::initialize(temporary.path())?;
    for entry in &lock.versions {
        let report: serde_json::Value = serde_json::from_slice(&fs::read(
            evidence.join(format!("{}.json", entry.identity)),
        )?)?;
        if report["schema"] != 1
            || report["identity"] != entry.identity
            || report["system"] != entry.package.system
            || report["version"] != entry.package.version
            || report["native_execution"] != true
            || report["offline_import_and_execution"] != true
            || (entry.package.name == "nginx" && report["service_preparation"] != true)
        {
            return Err("required combination lacks successful native qualification".into());
        }
        let bundle = evidence.join(format!("{}.bundle", entry.identity));
        if report["bundle_sha256"].as_str() != Some(file_digest(&bundle, &cancellation)?.as_str()) {
            return Err("qualification bundle changed content".into());
        }
        let pin = report["manifest"]
            .as_str()
            .ok_or("qualification has no manifest pin")?
            .parse::<ContentDigest>()?;
        let root = RootName::new(format!("qualification_{}", entry.identity))?;
        let admitted = import_bundle(
            &receiver,
            &root,
            pin,
            &mut File::open(bundle)?,
            &cancellation,
        )?;
        let app = admitted
            .manifest()
            .outputs()
            .get("application")
            .ok_or("qualification lacks application artifact")?;
        if report["action"].as_str() != Some(app.action.to_string().as_str())
            || report["artifact"].as_str() != Some(app.artifact.to_string().as_str())
        {
            return Err("qualification receipt differs from the distributed artifact".into());
        }
        if report["toolchain"]
            .as_str()
            .and_then(|pin| pin.parse::<ContentDigest>().ok())
            .is_none()
        {
            return Err("qualification lacks a verified toolchain identity".into());
        }
        reports.push(report);
    }
    let manifest = serde_json::json!({"schema":1,"catalog_lock_sha256":file_digest(&path.join(LOCK_FILE), &cancellation)?,"project_lock_sha256":file_digest(&path.join("Syrox.lock"), &cancellation)?,"packages":reports});
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())?;
    file.sync_all()?;
    Ok(format!(
        "verified all {} required combinations",
        lock.versions.len()
    ))
}

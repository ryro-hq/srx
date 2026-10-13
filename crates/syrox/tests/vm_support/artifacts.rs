use super::Result;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Executables in the shared Cargo target can be replaced by the next source
/// capture. Retain independent per-run copies before any gate is dispatched.
pub fn freeze(
    artifacts: &BTreeMap<String, PathBuf>,
    evidence: &Path,
    control: &super::process::Control,
) -> Result<BTreeMap<String, PathBuf>> {
    // Fixtures locate the worker one directory above Cargo's deps directory.
    // Preserve that relationship in independent evidence copies.
    let directory = evidence.join("libtests/fixtures");
    super::common::private(&directory)?;
    super::common::private(&directory.join("deps"))?;
    let required = artifacts.keys().cloned().collect::<Vec<_>>();
    let mut frozen = BTreeMap::new();
    for key in required {
        control.check()?;
        let source = artifacts
            .get(&key)
            .ok_or("registered target artifact missing")?;
        let copied = if key.contains('/') {
            directory
                .join("deps")
                .join(key.replace('/', "--"))
        } else {
            directory.join(&key)
        };
        super::snapshot::copy_candidate(source, &copied, 128 * 1024 * 1024)?;
        frozen.insert(key, copied);
    }
    Ok(frozen)
}

pub fn artifacts(output: &str) -> Result<BTreeMap<String, PathBuf>> {
    let mut artifacts = BTreeMap::new();
    for line in output.lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" {
            continue;
        }
        let Some(executable) = message["executable"].as_str() else {
            continue;
        };
        let name = message["target"]["name"]
            .as_str()
            .ok_or("Cargo target has no name")?;
        let is_test = message["profile"]["test"] == true;
        let key = if is_test && name == "syrox_engine" {
            "syrox-engine/lib".to_owned()
        } else if is_test && name == "syrox_lang" {
            "syrox-lang/lib".to_owned()
        } else if is_test
            && (message["target"]["kind"] == json!(["bin"])
                || message["target"]["kind"] == json!(["test"]))
        {
            format!("syrox/{name}")
        } else if !is_test && (name == "srx" || name == "syrox-worker") {
            name.to_owned()
        } else {
            continue;
        };
        if let Some(previous) = artifacts.insert(key.clone(), PathBuf::from(executable))
            && previous != Path::new(executable)
        {
            return Err(format!("ambiguous Cargo artifact: {key}").into());
        }
    }
    if artifacts.is_empty() {
        return Err("no executable Cargo artifacts".into());
    }
    Ok(artifacts)
}

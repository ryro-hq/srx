use super::{Result, common, snapshot};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub sdk: String,
    pub image: String,
    #[serde(default)]
    pub preparation_image: Option<String>,
    pub runtime: PathBuf,
    pub runtime_sha256: String,
    pub firmware: PathBuf,
    pub firmware_sha256: String,
    #[serde(default)]
    pub image_archive: Option<PathBuf>,
    #[serde(default)]
    pub image_archive_sha256: Option<String>,
    #[serde(default)]
    pub firmware_provenance: Option<Value>,
}

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("workspace")
        .to_owned()
}

pub fn config_path() -> PathBuf {
    std::env::var_os("SYROX_VM_CONFIG").map_or_else(
        || root().join("target/vm-config.json"),
        PathBuf::from,
    )
}

pub fn read_config() -> Result<Config> {
    let path = config_path();
    let config: Config = serde_json::from_slice(&fs::read(&path).map_err(|error| {
        format!(
            "VM configuration {}: {error}; use cargo test --test vm -- --prepare --help",
            path.display()
        )
    })?)?;
    config.validate()?;
    Ok(config)
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.sdk != common::SDK_VERSION {
            return Err("VM SDK must be pinned to 0.7.3".into());
        }
        let (_, digest) = self
            .image
            .rsplit_once("@sha256:")
            .ok_or("guest image must have an explicit OCI sha256 digest")?;
        if !snapshot::valid_digest(digest) {
            return Err("invalid guest image digest".into());
        }
        for (path, pin) in [
            (&self.runtime, &self.runtime_sha256),
            (&self.firmware, &self.firmware_sha256),
        ] {
            if !path.is_absolute()
                || !snapshot::valid_digest(pin)
                || snapshot::digest(path)? != *pin
            {
                return Err(format!(
                    "VM runtime/firmware pin differs: {}",
                    path.display()
                )
                .into());
            }
        }
        match (&self.image_archive, &self.image_archive_sha256) {
            (Some(path), Some(pin))
                if path.is_absolute()
                    && snapshot::valid_digest(pin)
                    && snapshot::digest(path)? == *pin => {}
            (None, None) => {}
            _ => return Err("local guest image archive pin differs".into()),
        }
        if let Some(image) = &self.preparation_image {
            let pin = image
                .rsplit_once("@sha256:")
                .map(|(_, pin)| pin)
                .or_else(|| image.strip_prefix("sha256:"));
            if !pin.is_some_and(snapshot::valid_digest) {
                return Err(
                    "preparation image requires an immutable Docker digest or image ID".into(),
                );
            }
        }
        // An ambient override takes precedence over the SDK setters. Refuse it
        // unless it resolves to the exact configured input.
        for (variable, expected) in [
            ("MSB_PATH", &self.runtime),
            ("MSB_LIBKRUNFW_PATH", &self.firmware),
        ] {
            if let Some(value) = std::env::var_os(variable)
                && PathBuf::from(value).canonicalize()? != expected.canonicalize()?
            {
                return Err(format!("{variable} overrides the pinned VM input").into());
            }
        }
        Ok(())
    }
}

pub fn doctor() -> Value {
    let mut checks = Vec::new();
    let platform = cfg!(all(target_os = "linux", target_arch = "x86_64"));
    checks.push(json!({"name":"platform","passed":platform,"detail":"Linux x86_64 required"}));
    let kvm = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm");
    checks.push(
        json!({"name":"kvm","passed":kvm.is_ok(),"detail":kvm.err().map(|error|error.to_string())}),
    );
    let resources = super::resources::host();
    checks.push(json!({"name":"resources","passed":resources.as_ref().is_ok_and(|value|value["ready"] == true),"detail":resources.unwrap_or_else(|error|json!(error.to_string()))}));
    let config = read_config();
    checks.push(json!({"name":"pins","passed":config.is_ok(),"detail":config.err().map(|error|error.to_string())}));
    json!({"ready":checks.iter().all(|check|check["passed"] == true),"checks":checks,
        "guest_qualification":"pending; host preflight is not VM evidence"})
}

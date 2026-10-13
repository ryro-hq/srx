//! Binding an invocation to the generation, process and context selected by apply.
//!
//! Paths help reopen resources. The invocation must still check content,
//! directories and journal authorization. A saved path neither proves ownership
//! nor permits file removal during recovery.

use super::{activation::ExecutionEpoch, manifest::LauncherIdentity};
use crate::{store::ContentDigest, systemd::SystemdUnitName};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

mod context;
pub(crate) use context::OsLaunchContext;

const HEADER: &[u8] = b"syrox-os-launch-v3\n";
pub(crate) const MAX_LAUNCH_BINDING_BYTES: usize = 32 * 1024;
#[derive(Debug, Error)]
#[error("invalid Os launch binding: {0}")]
pub(crate) struct LaunchBindingError(&'static str);
type Result<T> = std::result::Result<T, LaunchBindingError>;

#[derive(Debug)]
pub(crate) struct LaunchBindingInput {
    pub installation: String,
    pub generation: ContentDigest,
    pub service: String,
    pub process: String,
    pub command: String,
    pub unit: SystemdUnitName,
    pub launcher: LauncherIdentity,
    pub spec: ContentDigest,
    pub epoch: ExecutionEpoch,
    pub context: OsLaunchContext,
    /// Directory of this service alone, bound at /syrox/config/SERVICE.
    pub configuration: PathBuf,
    pub cwd: PathBuf,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resource {
    service: String,
    process: String,
    command: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    installation: String,
    generation: String,
    resource: Resource,
    unit: String,
    launcher: LauncherIdentity,
    spec: String,
    epoch: ExecutionEpoch,
    context: OsLaunchContext,
    configuration: String,
    cwd: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OsLaunchBinding(Record);
impl OsLaunchBinding {
    pub(crate) fn new(input: LaunchBindingInput) -> Result<Self> {
        let binding = Self(Record {
            version: 3,
            installation: input.installation,
            generation: input.generation.to_string(),
            resource: Resource {
                service: input.service,
                process: input.process,
                command: input.command,
            },
            unit: input.unit.as_str().into(),
            launcher: input.launcher,
            spec: input.spec.to_string(),
            epoch: input.epoch,
            context: input.context,
            configuration: path_text(&input.configuration)?.into(),
            cwd: path_text(&input.cwd)?.into(),
        });
        binding.validate()?;
        Ok(binding)
    }
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = HEADER.to_vec();
        serde_json::to_writer(&mut bytes, &self.0).map_err(|_| invalid("cannot encode binding"))?;
        if bytes.len() > MAX_LAUNCH_BINDING_BYTES {
            return Err(invalid("binding exceeds byte limit"));
        }
        Ok(bytes)
    }
    pub(crate) fn digest(&self) -> Result<ContentDigest> {
        Ok(ContentDigest::sha256(&self.canonical_bytes()?))
    }
    pub(crate) fn decode(bytes: &[u8], expected: ContentDigest) -> Result<Self> {
        if bytes.len() > MAX_LAUNCH_BINDING_BYTES {
            return Err(invalid("binding exceeds byte limit"));
        }
        if ContentDigest::sha256(bytes) != expected {
            return Err(invalid("binding pin differs"));
        }
        let json = bytes
            .strip_prefix(HEADER)
            .ok_or_else(|| invalid("unsupported binding domain"))?;
        let record = serde_json::from_slice(json).map_err(|_| invalid("malformed binding"))?;
        let binding = Self(record);
        if binding.canonical_bytes()? != bytes {
            return Err(invalid("noncanonical binding"));
        }
        Ok(binding)
    }
    fn validate(&self) -> Result<()> {
        let record = &self.0;
        if record.version != 3 || !installation_id(&record.installation) {
            return Err(invalid("invalid binding identity or version"));
        }
        digest(&record.generation)?;
        digest(&record.spec)?;
        digest(&record.launcher.digest)?;
        if record.launcher.protocol != 1 {
            return Err(invalid("unsupported launcher protocol"));
        }
        let resource = &record.resource;
        if !service_name(&resource.service) || !name(&resource.process) || !name(&resource.command)
        {
            return Err(invalid(
                "invalid service, process or command name",
            ));
        }
        SystemdUnitName::new(&record.unit).map_err(|_| invalid("invalid stable unit name"))?;
        record
            .epoch
            .validate()
            .map_err(|_| invalid("invalid execution epoch"))?;
        record.context.validate()?;
        if record.epoch.scope != record.context.scope_key()
            || record
                .context
                .fragment()
                .file_name()
                .and_then(|name| name.to_str())
                != Some(record.unit.as_str())
        {
            return Err(invalid(
                "operational context differs from epoch or unit",
            ));
        }
        let configuration = Path::new(&record.configuration);
        let cwd = Path::new(&record.cwd);
        path_text(configuration)?;
        path_text(cwd)?;
        if !crate::execution::resources::valid_managed_working_directory(cwd) {
            return Err(invalid("reserved managed working directory"));
        }
        if cwd.starts_with(configuration) || configuration.starts_with(cwd) {
            return Err(invalid(
                "configuration and working directory overlap",
            ));
        }
        if cwd.starts_with(record.context.store()) || record.context.store().starts_with(cwd) {
            return Err(invalid("Store and working directory overlap"));
        }
        let units = record
            .context
            .fragment()
            .parent()
            .ok_or_else(|| invalid("unit directory is absent"))?;
        if units.starts_with(cwd) || cwd.starts_with(units) {
            return Err(invalid(
                "unit directory and working directory overlap",
            ));
        }
        Ok(())
    }
    pub(crate) fn installation_id(&self) -> &str {
        &self.0.installation
    }
    pub(crate) fn generation(&self) -> ContentDigest {
        self.0
            .generation
            .parse()
            .expect("validated generation pin")
    }
    pub(crate) fn service(&self) -> &str {
        &self.0.resource.service
    }
    pub(crate) fn process(&self) -> &str {
        &self.0.resource.process
    }
    pub(crate) fn command(&self) -> &str {
        &self.0.resource.command
    }
    pub(crate) fn process_key(&self) -> String {
        format!("{}/{}", self.service(), self.process())
    }
    pub(crate) fn command_key(&self) -> String {
        super::manifest::command_key(Some(self.service()), self.command())
    }
    pub(crate) fn unit(&self) -> SystemdUnitName {
        SystemdUnitName::new(&self.0.unit).expect("validated unit name")
    }
    pub(crate) fn launcher(&self) -> &LauncherIdentity {
        &self.0.launcher
    }
    pub(crate) fn spec(&self) -> ContentDigest {
        self.0
            .spec
            .parse()
            .expect("validated specification pin")
    }
    pub(crate) fn epoch(&self) -> &ExecutionEpoch {
        &self.0.epoch
    }
    pub(crate) fn context(&self) -> &OsLaunchContext {
        &self.0.context
    }
    pub(crate) fn configuration(&self) -> &Path {
        Path::new(&self.0.configuration)
    }
    pub(crate) fn cwd(&self) -> &Path {
        Path::new(&self.0.cwd)
    }
}
fn path_text(path: &Path) -> Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid("non-UTF8 authorized path"))?;
    if !text.starts_with('/')
        || text.len() > 4096
        || text == "/"
        || text.chars().any(char::is_control)
        || text[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.len() > 255)
    {
        return Err(invalid(
            "authorized path is not canonical absolute text",
        ));
    }
    Ok(text)
}
fn installation_id(value: &str) -> bool {
    value.len() == 32
        && value.bytes().any(|b| b != b'0')
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn service_name(value: &str) -> bool {
    name(value)
        && value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && value.bytes().all(|b| !b.is_ascii_uppercase())
}
fn digest(value: &str) -> Result<()> {
    if value.parse::<ContentDigest>().is_ok() {
        Ok(())
    } else {
        Err(invalid("noncanonical content pin"))
    }
}
const fn invalid(message: &'static str) -> LaunchBindingError {
    LaunchBindingError(message)
}
#[cfg(test)]
mod tests;

//! Local builder ceilings and operational endpoints; parsing grants no effects.

use super::{
    ConfigurationError, ManagedBuildConfiguration, absolute_path, empty, invalid, required_string,
    table,
};
use crate::system::budget::{AdmittedBudget, BudgetError, BuildBudget, BuilderLimits};
use std::path::{Path, PathBuf};

/// Explicit System policy selected outside the project. The helper independently
/// authenticates callers and admits its own root-owned policy. This configuration
/// establishes neither privileged authority nor observed runtime enforcement.
#[derive(Clone, Debug)]
pub struct SystemBuildConfiguration {
    worker: ManagedBuildConfiguration,
    helper_socket: PathBuf,
    limits: BuilderLimits,
}

impl SystemBuildConfiguration {
    pub const fn worker(&self) -> &ManagedBuildConfiguration {
        &self.worker
    }
    pub fn helper_socket(&self) -> &Path {
        &self.helper_socket
    }
    pub const fn limits(&self) -> &BuilderLimits {
        &self.limits
    }

    /// Pure policy admission; executors still owe capacity, resource/namespace
    /// validation, helper authority, enforcement and settlement before publishing.
    pub fn admit(&self, request: BuildBudget) -> Result<AdmittedBudget, BudgetError> {
        self.limits.admit(request)
    }

    pub(super) fn parse(mut values: toml::Table) -> Result<Self, ConfigurationError> {
        let helper_socket = PathBuf::from(required_string(&mut values, "helper-socket")?);
        absolute_path(&helper_socket)?;
        let endpoint = helper_socket
            .to_str()
            .ok_or_else(|| invalid("build.system.helper-socket must be UTF-8"))?;
        if endpoint.len() > 107
            || !endpoint
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            || endpoint[1..]
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(invalid(
                "build.system.helper-socket requires a canonical literal Unix pathname of at most 107 bytes",
            ));
        }
        let mut maximum = table(&mut values, "maximum")?
            .ok_or_else(|| invalid("build.system.maximum is required"))?;
        let request = BuildBudget {
            memory_bytes: integer(&mut maximum, "memory-bytes")?,
            cpu_percent: u32_value(&mut maximum, "cpu-percent")?,
            processes: u32_value(&mut maximum, "processes")?,
            descriptors: u32_value(&mut maximum, "descriptors")?,
            scratch_bytes: integer(&mut maximum, "scratch-bytes")?,
            files: integer(&mut maximum, "files")?,
            output_bytes: integer(&mut maximum, "output-bytes")?,
            duration_seconds: u32_value(&mut maximum, "duration-seconds")?,
        };
        empty(&maximum)?;
        let limits = BuilderLimits::new(request)
            .map_err(|error| invalid(&format!("build.system.maximum: {error}")))?;
        // The same operational grammar is reused without selecting the ordinary
        // managed backend or inheriting its configuration/default profile.
        let worker = ManagedBuildConfiguration::parse(values).map_err(|error| match error {
            ConfigurationError::Invalid(message) => {
                invalid(&message.replace("build.managed", "build.system"))
            }
            other @ ConfigurationError::Io(_) => other,
        })?;
        Ok(Self {
            worker,
            helper_socket,
            limits,
        })
    }
}

fn integer(values: &mut toml::Table, name: &str) -> Result<u64, ConfigurationError> {
    match values.remove(name) {
        Some(toml::Value::Integer(value)) if value > 0 => {
            Ok(u64::try_from(value).expect("positive integer"))
        }
        _ => Err(invalid(&format!(
            "build.system.maximum.{name} must be an explicit positive integer"
        ))),
    }
}

fn u32_value(values: &mut toml::Table, name: &str) -> Result<u32, ConfigurationError> {
    u32::try_from(integer(values, name)?).map_err(|_| {
        invalid(&format!(
            "build.system.maximum.{name} exceeds u32"
        ))
    })
}

#[cfg(test)]
mod tests;

use super::{ConfigurationError, absolute_path, empty, invalid, required_string, string};
use crate::store::ContentDigest;
use std::path::{Path, PathBuf};

/// A missing selection may compile only under Prefer. Integrity failures never do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ArtifactPolicy {
    #[default]
    Compile,
    Prefer,
    Require,
}

#[derive(Clone, Debug, Default)]
pub struct ArtifactConfiguration {
    policy: ArtifactPolicy,
    descriptor: Option<(PathBuf, ContentDigest)>,
}

impl ArtifactConfiguration {
    pub(super) fn parse(mut table: toml::Table) -> Result<Self, ConfigurationError> {
        let policy = match string(&mut table, "policy")?
            .as_deref()
            .unwrap_or("compile")
        {
            "compile" => ArtifactPolicy::Compile,
            "prefer" => ArtifactPolicy::Prefer,
            "require" => ArtifactPolicy::Require,
            _ => {
                return Err(invalid(
                    "artifacts.policy must be compile, prefer or require",
                ));
            }
        };
        let descriptor =
            if table.contains_key("descriptor") || table.contains_key("descriptor-sha256") {
                let path = PathBuf::from(required_string(&mut table, "descriptor")?);
                absolute_path(&path)?;
                let pin = required_string(&mut table, "descriptor-sha256")?
                    .parse()
                    .map_err(|_| {
                        invalid("artifacts.descriptor-sha256 must be a lowercase SHA-256 digest")
                    })?;
                Some((path, pin))
            } else {
                None
            };
        if policy != ArtifactPolicy::Compile && descriptor.is_none() {
            return Err(invalid(
                "artifact selection requires a pinned descriptor",
            ));
        }
        empty(&table)?;
        Ok(Self {
            policy,
            descriptor,
        })
    }

    pub const fn policy(&self) -> ArtifactPolicy {
        self.policy
    }
    pub fn descriptor(&self) -> Option<(&Path, ContentDigest)> {
        self.descriptor
            .as_ref()
            .map(|(path, pin)| (path.as_path(), *pin))
    }
}

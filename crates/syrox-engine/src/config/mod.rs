//! Local configuration for Store, network and worker access.
//!
//! The user chooses these paths and permissions before the operation. Recipes
//! cannot read this file or change those choices during evaluation.

use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use crate::store::ContentDigest;

mod artifacts;
mod managed;
pub use artifacts::{ArtifactConfiguration, ArtifactPolicy};
pub(crate) mod secrets;
pub use managed::ManagedBuildConfiguration;
pub use secrets::ShellSecretSources;

const MAX_CONFIG_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct LocalCatalog {
    path: PathBuf,
    lock_digest: ContentDigest,
}

impl LocalCatalog {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub const fn lock_digest(&self) -> ContentDigest {
        self.lock_digest
    }
}

/// A bounded, explicitly loaded global policy, never merged with catalog or
/// project files. Host toolchain and network grants default to absent.
#[derive(Clone, Debug)]
pub struct UserConfiguration {
    store: PathBuf,
    catalog: Option<LocalCatalog>,
    host_toolchain: Option<PathBuf>,
    managed_build: Option<ManagedBuildConfiguration>,
    shell_secrets: ShellSecretSources,
    allow_https: Vec<String>,
    artifacts: ArtifactConfiguration,
}

impl UserConfiguration {
    /// Enumerated environment inputs: `HOME`, `XDG_CONFIG_HOME` and `XDG_DATA_HOME`.
    /// `path` overrides the optional default file and must exist when supplied.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigurationError> {
        Self::load_with_store(path, None)
    }

    /// Explicit Store selection does not require unrelated XDG data defaults.
    pub fn load_with_store(
        path: Option<&Path>,
        selected_store: Option<&Path>,
    ) -> Result<Self, ConfigurationError> {
        let default;
        let selected = if let Some(path) = path {
            path
        } else {
            default = xdg_path("XDG_CONFIG_HOME", ".config")?.join("syrox/config.toml");
            &default
        };
        let text = match read_config(selected) {
            Ok(text) => text,
            Err(ConfigurationError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound && path.is_none() =>
            {
                String::new()
            }
            Err(error) => return Err(error),
        };
        let default_store = match selected_store {
            Some(path) => Some(std::path::absolute(path)?),
            None => xdg_path("XDG_DATA_HOME", ".local/share")
                .ok()
                .map(|path| path.join("syrox/store")),
        };
        let mut user = Self::parse_inner(&text, default_store)?;
        if let Some(path) = selected_store {
            user.set_store(path.to_path_buf())?;
        }
        Ok(user)
    }

    pub fn parse(text: &str, default_store: PathBuf) -> Result<Self, ConfigurationError> {
        Self::parse_inner(text, Some(default_store))
    }

    fn parse_inner(text: &str, default_store: Option<PathBuf>) -> Result<Self, ConfigurationError> {
        if text.len() > MAX_CONFIG_BYTES {
            return Err(invalid("configuration exceeds 64 KiB"));
        }
        let mut root: toml::Table = text
            .parse()
            .map_err(|_| invalid("invalid TOML configuration"))?;
        let mut store = table(&mut root, "store")?.unwrap_or_default();
        let store_path = string(&mut store, "path")?
            .map(PathBuf::from)
            .or(default_store)
            .ok_or_else(|| invalid("set XDG_DATA_HOME or HOME, or configure store.path"))?;
        absolute_path(&store_path)?;
        empty(&store)?;
        let catalog = table(&mut root, "catalog")?
            .map(|mut catalog| {
                let path = PathBuf::from(required_string(&mut catalog, "path")?);
                absolute_path(&path)?;
                let lock_digest = required_string(&mut catalog, "lock-sha256")?
                    .parse()
                    .map_err(|_| {
                        invalid("catalog.lock-sha256 must be a lowercase SHA-256 digest")
                    })?;
                empty(&catalog)?;
                Ok::<_, ConfigurationError>(LocalCatalog {
                    path,
                    lock_digest,
                })
            })
            .transpose()?;
        let mut build = table(&mut root, "build")?.unwrap_or_default();
        let host_toolchain = string(&mut build, "host-toolchain")?.map(PathBuf::from);
        if host_toolchain
            .as_deref()
            .is_some_and(|path| path != Path::new("/usr"))
        {
            return Err(invalid(
                "build.host-toolchain currently supports only /usr",
            ));
        }
        let managed_build = table(&mut build, "managed")?
            .map(ManagedBuildConfiguration::parse)
            .transpose()?;
        empty(&build)?;
        let mut shell = table(&mut root, "shell")?.unwrap_or_default();
        let shell_secrets = table(&mut shell, "secrets")?
            .map(ShellSecretSources::parse)
            .transpose()?
            .unwrap_or_default();
        if !shell.is_empty() {
            return Err(invalid("unknown shell configuration key"));
        }
        let mut network = table(&mut root, "network")?.unwrap_or_default();
        let mut allow_https = Vec::new();
        if let Some(value) = network.remove("allow-https") {
            let toml::Value::Array(values) = value else {
                return Err(invalid(
                    "network.allow-https must be an array of exact URLs",
                ));
            };
            for value in values {
                let toml::Value::String(url) = value else {
                    return Err(invalid(
                        "network.allow-https entries must be strings",
                    ));
                };
                crate::acquire::https::validate_https_url(&url)
                    .map_err(|_| invalid("network.allow-https contains an invalid HTTPS URL"))?;
                allow_https.push(url);
            }
        }
        allow_https.sort();
        allow_https.dedup();
        empty(&network)?;
        let artifacts = table(&mut root, "artifacts")?
            .map(ArtifactConfiguration::parse)
            .transpose()?
            .unwrap_or_default();
        empty(&root)?;
        Ok(Self {
            store: store_path,
            catalog,
            host_toolchain,
            managed_build,
            shell_secrets,
            allow_https,
            artifacts,
        })
    }

    pub fn store(&self) -> &Path {
        &self.store
    }
    pub const fn artifacts(&self) -> &ArtifactConfiguration {
        &self.artifacts
    }
    pub const fn catalog(&self) -> Option<&LocalCatalog> {
        self.catalog.as_ref()
    }
    pub fn host_toolchain(&self) -> Option<&Path> {
        self.host_toolchain.as_deref()
    }
    pub const fn managed_build(&self) -> Option<&ManagedBuildConfiguration> {
        self.managed_build.as_ref()
    }
    pub const fn shell_secrets(&self) -> &ShellSecretSources {
        &self.shell_secrets
    }
    pub fn permits_https(&self, url: &str) -> bool {
        self.allow_https
            .iter()
            .any(|allowed| allowed == url)
    }

    pub fn set_store(&mut self, path: PathBuf) -> Result<(), ConfigurationError> {
        let path = std::path::absolute(path)?;
        absolute_path(&path)?;
        self.store = path;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("invalid user configuration: {0}")]
    Invalid(String),
    #[error("cannot read user configuration: {0}")]
    Io(#[from] std::io::Error),
}

fn invalid(message: &str) -> ConfigurationError {
    ConfigurationError::Invalid(message.to_owned())
}

fn table(table: &mut toml::Table, name: &str) -> Result<Option<toml::Table>, ConfigurationError> {
    match table.remove(name) {
        Some(toml::Value::Table(value)) => Ok(Some(value)),
        Some(_) => Err(invalid(&format!("{name} must be a table"))),
        None => Ok(None),
    }
}

fn string(table: &mut toml::Table, name: &str) -> Result<Option<String>, ConfigurationError> {
    match table.remove(name) {
        Some(toml::Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(invalid(&format!("{name} must be a string"))),
        None => Ok(None),
    }
}

fn required_string(table: &mut toml::Table, name: &str) -> Result<String, ConfigurationError> {
    string(table, name)?.ok_or_else(|| invalid(&format!("missing {name}")))
}

fn empty(table: &toml::Table) -> Result<(), ConfigurationError> {
    if let Some(key) = table.keys().next() {
        return Err(invalid(&format!("unknown key {key:?}")));
    }
    Ok(())
}

fn xdg_path(name: &str, fallback: &str) -> Result<PathBuf, ConfigurationError> {
    let path = if let Some(value) = std::env::var_os(name).filter(|v| !v.is_empty()) {
        PathBuf::from(value)
    } else {
        let home = std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| invalid(&format!("set {name} or HOME")))?;
        PathBuf::from(home).join(fallback)
    };
    absolute_path(&path)?;
    Ok(path)
}

fn absolute_path(path: &Path) -> Result<(), ConfigurationError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || path.components().count() > 64
        || path.as_os_str().len() > 4096
    {
        return Err(invalid(
            "paths must be bounded absolute paths without '..'",
        ));
    }
    Ok(())
}

fn read_config(path: &Path) -> Result<String, ConfigurationError> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read as _;
        let opened = crate::platform::linux::fd::open_top(path).map_err(|error| match error {
            crate::platform::linux::fd::OpenError::Other(error)
            | crate::platform::linux::fd::OpenError::Unsupported(error) => {
                ConfigurationError::Io(error)
            }
            crate::platform::linux::fd::OpenError::Symlink => {
                invalid("configuration path contains a symlink")
            }
        })?;
        if !opened.metadata().is_trusted_regular() {
            return Err(invalid(
                "configuration must be one user-owned regular file without group/other writes",
            ));
        }
        let mut bytes = Vec::new();
        opened
            .into_file()
            .take(MAX_CONFIG_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(invalid("configuration exceeds 64 KiB"));
        }
        String::from_utf8(bytes).map_err(|_| invalid("configuration must be UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_grants_are_exact_and_unknown_or_incomplete_policy_is_refused() {
        let config = UserConfiguration::parse(
            "[network]\nallow-https=['https://example.org/source']",
            "/home/user/data with spaces/store".into(),
        )
        .unwrap();
        assert!(config.permits_https("https://example.org/source"));
        assert!(!config.permits_https("https://example.org/source/other"));
        assert!(config.host_toolchain().is_none());
        assert!(UserConfiguration::parse("", "/home/user/store".into()).is_ok());
        for text in [
            "version=2",
            "version=1\nunknown=true",
            "[catalog]\npath='/catalog'",
            "[store]\npath='../store'",
            "[build]\nhost-toolchain='/'",
            "[network]\nallow-https=['http://example.org']",
        ] {
            assert!(
                UserConfiguration::parse(text, "/home/user/store".into()).is_err(),
                "{text}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_store_path_loads_without_data_home() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.toml");
        std::fs::write(
            &config,
            "[store]\npath='/tmp/opencode/explicit-store'\n",
        )
        .unwrap();
        // load_with_store uses the explicit selection before trying the XDG
        // default; no mutation of process-global environment is required.
        let override_path = directory.path().join("override");
        let user = UserConfiguration::load_with_store(Some(&config), Some(&override_path)).unwrap();
        assert_eq!(user.store(), override_path);
    }
}

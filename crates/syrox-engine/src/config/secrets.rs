use super::{ConfigurationError, invalid};
use crate::plan::PlanConsumer;
use std::{
    collections::BTreeMap,
    fmt,
    path::{Component, Path, PathBuf},
};

pub(crate) const MAX_SERVICE_SECRETS: usize = 32;
pub(crate) const MAX_CONSUMER_SECRETS: usize = 256;
const MAX_GRANTS: usize = 1024;

#[derive(Clone, Default)]
pub struct ShellSecretSources {
    entries: BTreeMap<(String, String), PathBuf>,
}
impl fmt::Debug for ShellSecretSources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShellSecretSources")
            .field("count", &self.entries.len())
            .finish_non_exhaustive()
    }
}
impl ShellSecretSources {
    pub fn new(
        entries: impl IntoIterator<Item = (String, String, PathBuf)>,
    ) -> Result<Self, ConfigurationError> {
        let mut result = Self::default();
        let mut total = 0usize;
        for (service, name, path) in entries {
            let text = path
                .to_str()
                .ok_or_else(|| invalid("invalid secret source path"))?;
            if !valid_name(&service)
                || !valid_name(&name)
                || text.len() > 4096
                || text.contains('\0')
                || !path.is_absolute()
                || path
                    .components()
                    .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
                || path.components().collect::<PathBuf>() != path
                || text.ends_with('/')
                || text.contains("//")
                || text
                    .split('/')
                    .any(|part| part == "." || part == "..")
            {
                return Err(invalid("invalid secret source grant"));
            }
            total = total.saturating_add(service.len() + name.len() + text.len());
            if result.entries.len() >= MAX_GRANTS || total > 64 * 1024 {
                return Err(invalid("secret source grants exceed bound"));
            }
            if result
                .entries
                .insert((service, name), path)
                .is_some()
            {
                return Err(invalid("duplicate secret source grant"));
            }
        }
        Ok(result)
    }
    /// Select only requested grants; unrelated global grants are never opened.
    pub fn for_consumer(&self, consumer: &PlanConsumer) -> Result<Self, ConfigurationError> {
        let mut selected = Self::default();
        for service in consumer.services() {
            for name in service.secrets() {
                let path = self
                    .source(service.id(), name)
                    .ok_or_else(|| invalid("missing local grant for declared secret"))?;
                if selected.entries.len() >= MAX_CONSUMER_SECRETS {
                    return Err(invalid("too many requested secrets"));
                }
                selected.entries.insert(
                    (service.id().into(), name.clone()),
                    path.to_path_buf(),
                );
            }
        }
        Ok(selected)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub(crate) fn source(&self, service: &str, name: &str) -> Option<&Path> {
        self.entries
            .get(&(service.into(), name.into()))
            .map(PathBuf::as_path)
    }
    pub(super) fn parse(table: toml::Table) -> Result<Self, ConfigurationError> {
        let mut entries = Vec::new();
        for (service, names) in table {
            let toml::Value::Table(names) = names else {
                return Err(invalid("secret grants must be tables by service"));
            };
            for (name, path) in names {
                let toml::Value::String(path) = path else {
                    return Err(invalid(
                        "secret source must be a local path string",
                    ));
                };
                if entries.len() >= MAX_GRANTS {
                    return Err(invalid("too many secret source grants"));
                }
                entries.push((service.clone(), name, PathBuf::from(path)));
            }
        }
        Self::new(entries)
    }
}
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && (name.as_bytes()[0].is_ascii_lowercase() || name.as_bytes()[0].is_ascii_digit())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UserConfiguration;
    #[test]
    fn parses_local_grants_without_opening_sources_and_redacts_debug_and_errors() {
        let user = UserConfiguration::parse(
            "[shell.secrets.service]\ntoken='/abs/sentinel-source'",
            "/store".into(),
        )
        .unwrap();
        assert_eq!(user.shell_secrets().len(), 1);
        assert_eq!(
            user.shell_secrets().source("service", "token"),
            Some(Path::new("/abs/sentinel-source"))
        );
        assert!(!format!("{user:?}").contains("sentinel-source"));
        for source in [
            "relative",
            "/abs/../sentinel-source",
            "/abs//sentinel-source",
            "/abs/./sentinel-source",
            "/abs/sentinel-source/",
        ] {
            let text = format!("[shell.secrets.service]\ntoken='{source}'");
            let error = UserConfiguration::parse(&text, "/store".into()).unwrap_err();
            assert!(!error.to_string().contains("sentinel"));
        }
        for text in [
            "[shell.secrets.service]\ntoken='/sentinel'\ntoken='/sentinel'",
            "[shell.secrets.service]\ntoken=['/sentinel']",
            "[shell.secrets.service]\ntoken='/sentinel",
        ] {
            assert!(
                !UserConfiguration::parse(text, "/store".into())
                    .unwrap_err()
                    .to_string()
                    .contains("sentinel")
            );
        }
    }
    #[test]
    fn constructor_rejects_duplicates_invalid_names_and_unbounded_iterators() {
        let grant = || {
            (
                "service".into(),
                "token".into(),
                PathBuf::from("/abs/source"),
            )
        };
        assert!(ShellSecretSources::new([grant(), grant()]).is_err());
        for name in ["", ".", "..", "UPPER", "x/y"] {
            assert!(
                ShellSecretSources::new([("service".into(), name.into(), "/source".into())])
                    .is_err()
            );
        }
        assert!(
            ShellSecretSources::new((0..).map(|n| (
                "service".into(),
                format!("key{n}"),
                "/source".into()
            )))
            .is_err()
        );
    }
}

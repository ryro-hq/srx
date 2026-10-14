use super::{ConfigurationError, absolute_path, empty, invalid, required_string, string};
use crate::{store::ContentDigest, systemd::SystemdScope};
use std::path::{Path, PathBuf};

/// Explicit operational inputs for managed builds. Parsing establishes no
/// filesystem ownership, manager authority or executable admission.
#[derive(Clone, Debug)]
pub struct ManagedBuildConfiguration {
    worker: PathBuf,
    worker_digest: ContentDigest,
    scope: SystemdScope,
    socket_parent: PathBuf,
}

impl ManagedBuildConfiguration {
    pub fn worker(&self) -> &Path {
        &self.worker
    }
    pub const fn worker_digest(&self) -> ContentDigest {
        self.worker_digest
    }
    pub const fn scope(&self) -> &SystemdScope {
        &self.scope
    }
    pub fn socket_parent(&self) -> &Path {
        &self.socket_parent
    }

    pub(super) fn parse(mut values: toml::Table) -> Result<Self, ConfigurationError> {
        let worker = path(required_string(&mut values, "worker")?)?;
        let worker_digest = required_string(&mut values, "worker-sha256")?
            .parse()
            .map_err(|_| {
                invalid("build.managed.worker-sha256 must be a lowercase SHA-256 digest")
            })?;
        let selected_scope = required_string(&mut values, "scope")?;
        let user_bus = string(&mut values, "user-bus")?;
        let scope = match (selected_scope.as_str(), user_bus) {
            ("user", Some(bus)) => SystemdScope::User {
                bus_socket: path(bus)?,
            },
            ("user", None) => {
                return Err(invalid(
                    "build.managed.user-bus is required for user scope",
                ));
            }
            ("system", None) => SystemdScope::System,
            ("system", Some(_)) => {
                return Err(invalid(
                    "build.managed.user-bus is forbidden for system scope",
                ));
            }
            _ => {
                return Err(invalid(
                    "build.managed.scope must be user or system",
                ));
            }
        };
        let socket_parent = path(required_string(&mut values, "socket-parent")?)?;
        empty(&values)?;
        Ok(Self {
            worker,
            worker_digest,
            scope,
            socket_parent,
        })
    }
}

fn path(value: String) -> Result<PathBuf, ConfigurationError> {
    if value.chars().any(char::is_control) {
        return Err(invalid(
            "build.managed paths cannot contain control characters",
        ));
    }
    let path = PathBuf::from(value);
    absolute_path(&path)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UserConfiguration;

    const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    fn system() -> String {
        format!(
            "[build.managed]\nworker='/explicit/worker'\nworker-sha256='{PIN}'\nscope='system'\nsocket-parent='/explicit/private-sockets'\n"
        )
    }
    fn parse(text: &str) -> Result<UserConfiguration, ConfigurationError> {
        UserConfiguration::parse(text, "/explicit/store".into())
    }

    #[test]
    fn absent_managed_policy_does_not_infer_worker_or_scope() {
        assert!(parse("").unwrap().managed_build().is_none());
        assert!(
            parse("[build]\nhost-toolchain='/usr'")
                .unwrap()
                .managed_build()
                .is_none()
        );
    }

    #[test]
    fn complete_policy_is_pure_and_preserves_explicit_scope_and_paths() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent");
        let text = system().replace("/explicit", absent.to_str().unwrap());
        let user = parse(&text).unwrap();
        let managed = user.managed_build().unwrap();
        assert_eq!(managed.worker(), absent.join("worker"));
        assert_eq!(managed.worker_digest().to_string(), PIN);
        assert_eq!(
            managed.socket_parent(),
            absent.join("private-sockets")
        );
        assert_eq!(managed.scope(), &SystemdScope::System);
        assert!(!absent.exists());
        assert!(user.host_toolchain().is_none());

        let text = system().replace(
            "scope='system'",
            "scope='user'\nuser-bus='/explicit/private-bus'",
        );
        let user = parse(&text).unwrap();
        assert_eq!(
            user.managed_build().unwrap().scope(),
            &SystemdScope::User {
                bus_socket: "/explicit/private-bus".into()
            }
        );
        let mixed = parse(&format!("[build]\nhost-toolchain='/usr'\n{text}")).unwrap();
        assert_eq!(mixed.host_toolchain(), Some(Path::new("/usr")));
        assert!(mixed.managed_build().is_some());
    }

    #[test]
    fn policy_is_complete_and_rejects_unknown_keys_or_wrong_types() {
        for field in [
            "worker",
            "worker-sha256",
            "scope",
            "socket-parent",
        ] {
            let text = system()
                .lines()
                .filter(|line| !line.starts_with(&format!("{field}=")))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(parse(&text).is_err(), "missing {field}");
        }
        for text in [
            "[build.managed]".to_owned(),
            "[build]\nmanaged='worker'".to_owned(),
            format!("{}fallback=true", system()),
            format!("{}[build.managed.extra]\nenabled=true", system()),
            system().replace(
                "worker='/explicit/worker'",
                "worker=['/explicit/worker']",
            ),
            system().replace("scope='system'", "scope=1"),
        ] {
            assert!(parse(&text).is_err(), "{text}");
        }
    }

    #[test]
    fn scope_requires_exact_user_endpoint_and_forbids_implicit_authority() {
        for scope in ["user", "session", "auto", "User", ""] {
            assert!(
                parse(&system().replace("scope='system'", &format!("scope='{scope}'"))).is_err()
            );
        }
        assert!(parse(&format!("{}user-bus='/bus'", system())).is_err());
        for endpoint in [
            "relative",
            "unix:path=/bus",
            "/parent/../bus",
            "",
        ] {
            let text = system().replace(
                "scope='system'",
                &format!("scope='user'\nuser-bus='{endpoint}'"),
            );
            assert!(parse(&text).is_err());
        }
    }

    #[test]
    fn pins_and_paths_are_bounded_and_lexically_valid() {
        for pin in [
            "",
            "abc",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert!(
                parse(&system().replace(PIN, pin)).is_err(),
                "{pin}"
            );
        }
        for field in ["worker", "socket-parent"] {
            for value in ["relative", "", "/a/../b"] {
                let mut table: toml::Table = system().parse().unwrap();
                table["build"]["managed"][field] = toml::Value::String(value.into());
                assert!(
                    ManagedBuildConfiguration::parse(
                        table["build"]["managed"]
                            .as_table()
                            .unwrap()
                            .clone()
                    )
                    .is_err(),
                    "{field}: {value}"
                );
            }
            for value in [
                "/a\0b".into(),
                format!("/{}", "a".repeat(4096)),
                format!("/{}", "a/".repeat(65)),
            ] {
                let mut table: toml::Table = system().parse().unwrap();
                table["build"]["managed"][field] = toml::Value::String(value);
                assert!(
                    ManagedBuildConfiguration::parse(
                        table["build"]["managed"]
                            .as_table()
                            .unwrap()
                            .clone()
                    )
                    .is_err()
                );
            }
        }
    }
}

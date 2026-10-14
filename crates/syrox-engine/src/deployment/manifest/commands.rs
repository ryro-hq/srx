use crate::result::valid_name;
use std::collections::BTreeMap;

use super::{ConsumerCommandKey, DeploymentError};

pub(crate) const MAX_PUBLIC_COMMANDS: usize = 1024;
pub(crate) const MAX_PUBLIC_COMMAND_NAME_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct PreparedCommandIndex<'a> {
    exposures: &'a BTreeMap<String, ConsumerCommandKey>,
}

impl<'a> PreparedCommandIndex<'a> {
    pub(crate) fn new(
        exposures: &'a BTreeMap<String, ConsumerCommandKey>,
    ) -> Result<Self, DeploymentError> {
        if exposures.len() > MAX_PUBLIC_COMMANDS {
            return Err(DeploymentError::CommandNamespace(
                "too many aliases",
            ));
        }
        let mut bytes = 0_usize;
        for (name, (service, command)) in exposures {
            if !valid_name(name)
                || !valid_name(command)
                || service
                    .as_ref()
                    .is_some_and(|name| !valid_name(name))
            {
                return Err(DeploymentError::CommandNamespace("invalid alias"));
            }
            bytes += name.len();
            if bytes > MAX_PUBLIC_COMMAND_NAME_BYTES {
                return Err(DeploymentError::CommandNamespace(
                    "alias byte limit",
                ));
            }
        }
        Ok(Self {
            exposures,
        })
    }

    pub(crate) fn names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.exposures.keys().map(String::as_str)
    }
    pub(crate) fn resolve(&self, alias: &str) -> Option<&ConsumerCommandKey> {
        self.exposures.get(alias)
    }

    /// Coordinator-only representation. The public context carries its digest,
    /// never this mapping; the broker retains the actual prepared authority.
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = b"syrox-shell-command-index-v1\n".to_vec();
        for (alias, (service, command)) in self.exposures {
            append(&mut bytes, alias);
            bytes.push(u8::from(service.is_some()));
            if let Some(service) = service {
                append(&mut bytes, service);
            }
            append(&mut bytes, command);
        }
        bytes
    }

    pub(crate) fn digest(&self) -> crate::store::ContentDigest {
        crate::store::ContentDigest::sha256(&self.canonical_bytes())
    }
}

fn append(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::{MAX_PUBLIC_COMMANDS, PreparedCommandIndex};
    use crate::deployment::manifest::{ConsumerCommandKey, DeploymentError};
    use std::collections::BTreeMap;

    fn root() -> ConsumerCommandKey {
        (None, "run".into())
    }

    #[test]
    fn complete_public_index_preserves_service_aliases_and_private_keys() {
        let source = crate::deployment::manifest::tests::configured_source(
            "std::CommandArgument::File(\"git/config\")",
            "",
            "std::Option::Some(\"git\")",
            "",
        )
        .replace(
            "pkgs = []; services",
            "pkgs = [std::select_command(first, \"out\", \"run\")]; services",
        );
        let (temp, plan) = crate::deployment::manifest::tests::prepared(&source);
        let selected = crate::deployment::manifest::select_consumer(&plan, "shell").unwrap();
        let index = PreparedCommandIndex::new(selected.exposures()).unwrap();
        assert_eq!(index.names().collect::<Vec<_>>(), ["git", "run"]);
        assert_eq!(index.resolve("run"), Some(&root()));
        assert_eq!(
            index.resolve("git"),
            Some(&(Some("git".into()), "configured".into()))
        );
        assert!(index.resolve("configured").is_none());
        assert!(index.resolve("git/config").is_none());
        assert!(!temp.path().join("store").exists());
    }

    #[test]
    fn aliases_are_bounded_before_directory_or_runtime_preparation() {
        let mut exposures = (0..MAX_PUBLIC_COMMANDS)
            .map(|index| (format!("cmd{index}"), root()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            PreparedCommandIndex::new(&exposures)
                .unwrap()
                .names()
                .len(),
            MAX_PUBLIC_COMMANDS
        );
        exposures.insert("one-more".into(), root());
        assert!(matches!(
            PreparedCommandIndex::new(&exposures),
            Err(DeploymentError::CommandNamespace(
                "too many aliases"
            ))
        ));
        let exact = (0..512)
            .map(|index| (format!("{index:03}{}", "a".repeat(125)), root()))
            .collect::<BTreeMap<_, _>>();
        assert!(PreparedCommandIndex::new(&exact).is_ok());
        let mut excessive = exact;
        excessive.insert("x".into(), root());
        assert!(matches!(
            PreparedCommandIndex::new(&excessive),
            Err(DeploymentError::CommandNamespace(
                "alias byte limit"
            ))
        ));
    }

    #[test]
    fn directory_names_cannot_escape_or_override_a_path_component() {
        for name in [
            "",
            ".",
            "..",
            "a/b",
            "/absolute",
            "a\\b",
            "é",
            "a\0b",
        ] {
            let exposures = BTreeMap::from([(name.into(), root())]);
            assert!(
                PreparedCommandIndex::new(&exposures).is_err(),
                "{name:?}"
            );
        }
        let exposures = BTreeMap::from([("a".repeat(129), root())]);
        assert!(PreparedCommandIndex::new(&exposures).is_err());
        assert!(
            PreparedCommandIndex::new(&BTreeMap::new())
                .unwrap()
                .names()
                .next()
                .is_none()
        );
    }

    #[test]
    fn index_pin_binds_private_resolution_even_when_public_names_are_identical() {
        let first = BTreeMap::from([("public".into(), root())]);
        let second = BTreeMap::from([(
            "public".into(),
            (Some("service".into()), "run".into()),
        )]);
        let first = PreparedCommandIndex::new(&first).unwrap();
        let second = PreparedCommandIndex::new(&second).unwrap();
        assert_eq!(
            first.names().collect::<Vec<_>>(),
            second.names().collect::<Vec<_>>()
        );
        assert_ne!(first.digest(), second.digest());
        assert_eq!(
            first.digest(),
            crate::store::ContentDigest::sha256(&first.canonical_bytes())
        );
    }
}

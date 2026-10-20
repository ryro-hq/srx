use super::{
    Catalog, CatalogError, CatalogLock, INDEX_FILE, LockedVersion,
    files::{bounded_file, invalid},
    model::MAX_ENTRIES,
};
use crate::store::ContentDigest;
use std::{collections::BTreeMap, path::Path};
use syrox_lang::{
    source::Source,
    syntax::{ItemKind, TypeKind, analyze},
};

impl Catalog {
    pub fn lock(&self, root: &Path) -> Result<CatalogLock, CatalogError> {
        self.lock_with_standard(
            root,
            &crate::project::AuthenticatedStandardLibrary::bundled(),
        )
    }

    pub(crate) fn lock_with_standard(
        &self,
        root: &Path,
        library: &crate::project::AuthenticatedStandardLibrary,
    ) -> Result<CatalogLock, CatalogError> {
        self.validate()?;
        if self.schema == 2 {
            self.generate_releases(root, true)?;
        }
        let mut versions = Vec::new();
        for package in &self.packages {
            let mut inputs = BTreeMap::new();
            if self.schema == 2 {
                if !package.toolchain.is_empty() {
                    let bytes = bounded_file(root, &package.toolchain)?;
                    let text = std::str::from_utf8(&bytes)
                        .map_err(|_| invalid("toolchain is not UTF-8"))?;
                    let toolchain: toml::Value =
                        toml::from_str(text).map_err(|error| invalid(error.to_string()))?;
                    if toolchain
                        .get("build_system")
                        .and_then(toml::Value::as_str)
                        != Some("linux-x86_64-gnu")
                        || toolchain
                            .get("result_system")
                            .and_then(toml::Value::as_str)
                            != Some(package.system.as_str())
                    {
                        return Err(invalid(format!(
                            "toolchain {} must declare build_system linux-x86_64-gnu and result_system {}",
                            package.toolchain, package.system
                        )));
                    }
                }
                inputs.insert(
                    "@host-systemd".to_owned(),
                    ContentDigest::sha256(
                        &serde_json::to_vec(
                            &crate::systemd::interface_contract()
                                .map_err(|error| invalid(error.to_string()))?,
                        )
                        .map_err(|error| invalid(error.to_string()))?,
                    )
                    .to_string(),
                );
                inputs.insert(
                    "main.srx".to_owned(),
                    ContentDigest::sha256(&bounded_file(root, "main.srx")?).to_string(),
                );
                let standard: BTreeMap<_, _> = library
                    .sources()
                    .map(|source| {
                        (
                            source.name().to_owned(),
                            ContentDigest::sha256(source.text().as_bytes()).to_string(),
                        )
                    })
                    .collect();
                let encoded =
                    serde_json::to_vec(&standard).map_err(|error| invalid(error.to_string()))?;
                inputs.insert(
                    "@standard-library".to_owned(),
                    ContentDigest::sha256(&encoded).to_string(),
                );
            }
            for path in [
                &package.recipe,
                &package.source,
                &package.contract,
                &package.toolchain,
            ]
            .into_iter()
            .filter(|path| !path.is_empty())
            {
                inputs.insert(
                    path.clone(),
                    ContentDigest::sha256(&bounded_file(root, path)?).to_string(),
                );
            }
            if let Some(path) = &package.qualification {
                let qualification = super::Qualification::load(root, package)?;
                for path in std::iter::once(path.as_str()).chain(qualification.files()) {
                    inputs.insert(
                        path.to_owned(),
                        ContentDigest::sha256(&bounded_file(root, path)?).to_string(),
                    );
                }
            }
            for path in &package.recipe_inputs {
                inputs.insert(
                    path.clone(),
                    ContentDigest::sha256(&bounded_file(root, path)?).to_string(),
                );
            }
            let channel = self
                .channels
                .iter()
                .find(|channel| channel.name == package.name)
                .expect("validated channel");
            if let Some(key_file) = &channel.key_file {
                let key_pin = ContentDigest::sha256(&bounded_file(root, key_file)?).to_string();
                inputs.insert(key_file.clone(), key_pin.clone());
                let authority = serde_json::to_vec(&(&channel.signing_key, key_file, key_pin))
                    .map_err(|error| invalid(error.to_string()))?;
                inputs.insert(
                    "@signing-authority".to_owned(),
                    ContentDigest::sha256(&authority).to_string(),
                );
            }
            let recipe = bounded_file(root, &package.recipe)?;
            let text = std::str::from_utf8(&recipe).map_err(|_| invalid("recipe is not UTF-8"))?;
            let source = Source::new(package.recipe.as_str(), text)
                .map_err(|error| invalid(error.to_string()))?;
            let parsed = analyze(&source).map_err(|_| invalid("recipe syntax is invalid"))?;
            let found =
                parsed.items.iter().any(|item| match &item.kind {
                    ItemKind::Function(function) if function.name.text == package.factory => {
                        let contract_module = Path::new(&package.contract)
                            .file_stem()
                            .and_then(|stem| stem.to_str());
                        let contract_matches =
                            function.result.as_ref().is_some_and(|result| {
                                let TypeKind::Named {
                                    path,
                                    arguments,
                                } = &result.kind
                                else {
                                    return false;
                                };
                                let [argument] = arguments.as_slice() else {
                                    return false;
                                };
                                let TypeKind::Named {
                                    path: contract,
                                    arguments,
                                } = &argument.kind
                                else {
                                    return false;
                                };
                                path.segments
                                    .last()
                                    .is_some_and(|segment| segment.text == "PackageRef")
                                    && arguments.is_empty()
                                    && contract.segments.last().is_some_and(|segment| {
                                        segment.text == package.contract_type
                                    })
                                    && contract.segments.iter().rev().nth(1).is_some_and(
                                        |segment| Some(segment.text.as_str()) == contract_module,
                                    )
                            });
                        if function.is_static() && function.inferred_result() {
                            return true;
                        }
                        if !contract_matches {
                            return false;
                        }
                        true
                    }
                    _ => false,
                });
            if !found {
                return Err(invalid(format!(
                    "{} has no factory matching its version, variant and ABI",
                    package.recipe
                )));
            }
            let pins = bounded_file(root, &package.source)?;
            let pins = std::str::from_utf8(&pins)
                .map_err(|_| invalid("source declaration is not UTF-8"))?;
            if !pins.contains(&format!("\"{}\"", package.source_url))
                || !pins.contains(&format!("\"{}\"", package.source_sha256))
            {
                return Err(invalid(
                    "source declaration differs from index pins",
                ));
            }
            let contract = bounded_file(root, &package.contract)?;
            let contract = Source::new(
                package.contract.as_str(),
                std::str::from_utf8(&contract).map_err(|_| invalid("contract is not UTF-8"))?,
            )
            .map_err(|error| invalid(error.to_string()))?;
            if !analyze(&contract).map_err(|_| invalid("contract syntax is invalid"))?.items.iter().any(|item| matches!(&item.kind, ItemKind::Struct(structure) if structure.name.text == package.contract_type)) {
                return Err(invalid("configuration contract type is absent"));
            }
            let encoded = serde_json::to_vec(&(package, &inputs))
                .map_err(|error| invalid(error.to_string()))?;
            versions.push(LockedVersion {
                package: package.clone(),
                inputs,
                identity: ContentDigest::sha256(&encoded).to_string(),
            });
        }
        versions.sort_by(|left, right| left.identity.cmp(&right.identity));
        Ok(CatalogLock {
            schema: 1,
            index_sha256: ContentDigest::sha256(&bounded_file(root, INDEX_FILE)?).to_string(),
            versions,
            retained: Vec::new(),
        })
    }
}

impl CatalogLock {
    pub fn retain_previous(
        &mut self,
        previous: &Self,
        accept_key_change: bool,
    ) -> Result<(), CatalogError> {
        for old in &previous.versions {
            let current = self
                .versions
                .iter()
                .find(|new| {
                    new.package.name == old.package.name
                        && new.package.version == old.package.version
                        && new.package.variant == old.package.variant
                        && new.package.system == old.package.system
                })
                .ok_or_else(|| {
                    invalid("registered versions, variants and ABIs cannot be removed")
                })?;
            if current.package.source_url != old.package.source_url
                || current.package.source_sha256 != old.package.source_sha256
                || current.package.signature_url != old.package.signature_url
            {
                return Err(invalid(
                    "existing upstream content cannot be replaced",
                ));
            }
            if !accept_key_change
                && old.inputs.iter().any(|(path, pin)| {
                    (path.starts_with("keys/") || path == "@signing-authority")
                        && current.inputs.get(path) != Some(pin)
                })
            {
                return Err(invalid(
                    "signing key bytes changed; explicit --accept-key-change is required",
                ));
            }
        }
        self.retained = previous
            .versions
            .iter()
            .chain(&previous.retained)
            .filter(|old| {
                !self
                    .versions
                    .iter()
                    .any(|current| current.identity == old.identity)
            })
            .cloned()
            .collect();
        self.retained
            .sort_by(|left, right| left.identity.cmp(&right.identity));
        self.retained
            .dedup_by(|left, right| left == right);
        if self.retained.len() > MAX_ENTRIES {
            return Err(invalid("retained revision limit exceeded"));
        }
        self.preserves(previous)
    }
    pub fn encode(&self) -> Result<Vec<u8>, CatalogError> {
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|error| invalid(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Recipe or toolchain changes retain prior identities; source replacement
    /// and signing-key rotation require a separately reviewed inventory change.
    pub fn preserves(&self, previous: &Self) -> Result<(), CatalogError> {
        for old in previous.versions.iter().chain(&previous.retained) {
            let found = self
                .versions
                .iter()
                .chain(&self.retained)
                .any(|new| new.identity == old.identity && new == old);
            if !found {
                return Err(invalid(format!(
                    "catalog would discard retained identity {}",
                    old.identity
                )));
            }
        }
        Ok(())
    }

    pub fn matrix(&self) -> serde_json::Value {
        serde_json::json!({"include": self.versions.iter().map(|entry| serde_json::json!({
            "name": entry.package.name, "version": entry.package.version,
            "variant": entry.package.variant, "system": entry.package.system,
            "export": entry.package.export, "identity": entry.identity,
            "target": if entry.package.system.ends_with("-musl") { "x86_64-unknown-linux-musl" } else { "x86_64-unknown-linux-gnu" },
        })).collect::<Vec<_>>()})
    }
}

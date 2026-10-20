use super::{
    Catalog, CatalogError, INDEX_FILE,
    files::{bounded_file, component, digest, invalid},
    model::MAX_ENTRIES,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

impl Catalog {
    pub fn load(root: &Path) -> Result<Self, CatalogError> {
        let bytes = bounded_file(root, INDEX_FILE)?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| invalid("catalog index is not UTF-8"))?;
        let result: Self = toml::from_str(text).map_err(|error| invalid(error.to_string()))?;
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), CatalogError> {
        if !matches!(self.schema, 1 | 2)
            || self.packages.is_empty()
            || self.packages.len() > MAX_ENTRIES
            || self.channels.len() > MAX_ENTRIES
        {
            return Err(invalid("unsupported schema or inventory limit"));
        }
        let mut channels = BTreeMap::new();
        for channel in &self.channels {
            if !component(&channel.name) || channels.insert(&channel.name, channel).is_some() {
                return Err(invalid("invalid or duplicate release channel"));
            }
            let origin = crate::acquire::https::validate_https_url(&channel.origin)
                .map_err(|error| invalid(error.to_string()))?;
            let releases = crate::acquire::https::validate_https_url(&channel.releases)
                .map_err(|error| invalid(error.to_string()))?;
            if origin.host_str() != releases.host_str()
                || origin.port_or_known_default() != releases.port_or_known_default()
            {
                return Err(invalid(
                    "release feed must belong to its fixed origin",
                ));
            }
            if !component(&channel.archive_prefix) || !component(&channel.archive_suffix) {
                return Err(invalid("invalid archive spelling"));
            }
            if let Some(key) = &channel.signing_key
                && (!matches!(key.len(), 40 | 64)
                    || !key.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                return Err(invalid("signing key must be a fixed fingerprint"));
            }
            if channel.signing_key.is_some() != channel.key_file.is_some() {
                return Err(invalid(
                    "signing fingerprint and key file must be pinned together",
                ));
            }
            if !matches!(
                channel.release_policy.as_str(),
                "numeric" | "even-minor"
            ) {
                return Err(invalid("unknown stable release policy"));
            }
        }
        let mut keys = BTreeSet::new();
        let mut sources = BTreeMap::new();
        for package in &self.packages {
            if ![
                &package.name,
                &package.version,
                &package.variant,
                &package.export,
                &package.factory,
                &package.contract_type,
            ]
            .iter()
            .all(|value| component(value))
            {
                return Err(invalid("invalid package identity component"));
            }
            if !matches!(
                package.system.as_str(),
                "linux-x86_64-gnu" | "linux-x86_64-musl"
            ) {
                return Err(invalid("unsupported package ABI"));
            }
            if !keys.insert((
                &package.name,
                &package.version,
                &package.variant,
                &package.system,
            )) {
                return Err(invalid("duplicate package combination"));
            }
            if !digest(&package.source_sha256)
                || package.source_maximum_bytes == 0
                || package.source_maximum_bytes > crate::store::MAX_STORE_BLOB_BYTES
            {
                return Err(invalid("invalid source pin"));
            }
            let channel = channels
                .get(&package.name)
                .ok_or_else(|| invalid("package has no official release channel"))?;
            let source = crate::acquire::https::validate_https_url(&package.source_url)
                .map_err(|error| invalid(error.to_string()))?;
            let origin =
                url::Url::parse(&channel.origin).map_err(|error| invalid(error.to_string()))?;
            if source.host_str() != origin.host_str()
                || source.port_or_known_default() != origin.port_or_known_default()
            {
                return Err(invalid("source is outside its official origin"));
            }
            if channel.signing_key.is_some() && package.signature_url.is_none() {
                return Err(invalid(
                    "signed channel requires a detached signature",
                ));
            }
            if let Some(signature) = &package.signature_url {
                let signature = crate::acquire::https::validate_https_url(signature)
                    .map_err(|error| invalid(error.to_string()))?;
                if signature.host_str() != origin.host_str()
                    || signature.port_or_known_default() != origin.port_or_known_default()
                {
                    return Err(invalid(
                        "signature is outside its official origin",
                    ));
                }
            }
            let pin = (
                &package.source_url,
                &package.source_sha256,
                package.source_maximum_bytes,
                &package.signature_url,
                &package.source,
            );
            if sources
                .insert((&package.name, &package.version), pin)
                .is_some_and(|old| old != pin)
            {
                return Err(invalid(
                    "one version has inconsistent upstream content",
                ));
            }
        }
        for (name, version) in &self.defaults {
            if !self
                .packages
                .iter()
                .any(|package| &package.name == name && &package.version == version)
            {
                return Err(invalid("default refers to an unknown version"));
            }
        }
        Ok(())
    }
}

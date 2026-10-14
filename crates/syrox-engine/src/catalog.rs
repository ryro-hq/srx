//! Version inventory, source provenance and reproducible catalog matrices.
//!
//! Catalog admission is pure. A matrix describes required builds; it never
//! establishes availability or authorizes publication of an unbuilt artifact.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::store::ContentDigest;
use syrox_lang::{
    source::Source,
    syntax::{ItemKind, StringPart, TypeKind, analyze},
};

pub const INDEX_FILE: &str = "catalog.toml";
pub const LOCK_FILE: &str = "Catalog.lock";
const MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: u32,
    pub defaults: BTreeMap<String, String>,
    pub channels: Vec<Channel>,
    pub packages: Vec<PackageVersion>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    pub name: String,
    pub releases: String,
    pub origin: String,
    pub archive_prefix: String,
    pub archive_suffix: String,
    pub signing_key: Option<String>,
    pub key_file: Option<String>,
    pub release_policy: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageVersion {
    pub name: String,
    pub version: String,
    pub variant: String,
    pub system: String,
    pub source_url: String,
    pub source_sha256: String,
    pub source_maximum_bytes: u64,
    pub signature_url: Option<String>,
    pub recipe: String,
    pub factory: String,
    pub export: String,
    pub source: String,
    pub contract: String,
    pub contract_type: String,
    pub toolchain: String,
    #[serde(default)]
    pub recipe_inputs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LockedVersion {
    pub package: PackageVersion,
    pub inputs: BTreeMap<String, String>,
    pub identity: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CatalogLock {
    pub schema: u32,
    pub index_sha256: String,
    pub versions: Vec<LockedVersion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained: Vec<LockedVersion>,
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("catalog I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("invalid catalog: {0}")]
    Invalid(String),
}

fn invalid(message: impl Into<String>) -> CatalogError {
    CatalogError::Invalid(message.into())
}

fn bounded_file(root: &Path, name: &str) -> Result<Vec<u8>, CatalogError> {
    let path = Path::new(name);
    if path.as_os_str().is_empty()
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(invalid(
            "catalog paths must be relative without traversal",
        ));
    }
    let mut full = root.to_path_buf();
    for part in path.components() {
        full.push(part);
        if fs::symlink_metadata(&full)?
            .file_type()
            .is_symlink()
        {
            return Err(invalid("catalog paths cannot contain symlinks"));
        }
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(full)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("catalog input is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("catalog input exceeds byte limit"));
    }
    Ok(bytes)
}

fn component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Catalog {
    pub fn updates(&self) -> Result<Vec<(String, String)>, CatalogError> {
        let mut result = Vec::new();
        for channel in &self.channels {
            let bytes = download(&channel.releases, MAX_BYTES, &channel.origin)?;
            let html =
                std::str::from_utf8(&bytes).map_err(|_| invalid("release feed is not UTF-8"))?;
            if let Some(version) = channel.latest(html) {
                if !self
                    .packages
                    .iter()
                    .any(|entry| entry.name == channel.name && entry.version == version)
                {
                    result.push((channel.name.clone(), version));
                }
            } else {
                return Err(invalid(
                    "release feed contains no stable archives",
                ));
            }
        }
        Ok(result)
    }

    pub fn verify_sources(&self, root: &Path) -> Result<Vec<String>, CatalogError> {
        self.validate()?;
        let mut checked = BTreeSet::new();
        let mut evidence = Vec::new();
        for package in &self.packages {
            if !checked.insert((&package.name, &package.version)) {
                continue;
            }
            let channel = self
                .channels
                .iter()
                .find(|channel| channel.name == package.name)
                .expect("validated channel");
            let bytes = download(
                &package.source_url,
                package.source_maximum_bytes,
                &channel.origin,
            )?;
            if ContentDigest::sha256(&bytes).to_string() != package.source_sha256 {
                return Err(invalid(
                    "existing upstream version has changed content",
                ));
            }
            if let Some(signature) = &package.signature_url {
                let signature = download(signature, 64 * 1024, &channel.origin)?;
                verify_signature(root, channel, &bytes, &signature)?;
                evidence.push(format!(
                    "{} {} sha256={} signing-key={}",
                    package.name,
                    package.version,
                    package.source_sha256,
                    channel.signing_key.as_deref().unwrap_or_default()
                ));
            } else {
                evidence.push(format!(
                    "{} {} sha256={} provenance=official-https",
                    package.name, package.version, package.source_sha256
                ));
            }
        }
        Ok(evidence)
    }

    /// Append a signed stable release, keeping default selection and old files.
    /// Qualification of the generated recipe remains a mandatory CI operation.
    pub fn add_version(
        &mut self,
        root: &Path,
        name: &str,
        version: &str,
    ) -> Result<(), CatalogError> {
        self.validate()?;
        if version.split('.').count() < 2
            || version
                .split('.')
                .any(|part| part.parse::<u64>().is_err())
            || version.len() > 64
        {
            return Err(invalid(
                "version must be an exact numbered stable release",
            ));
        }
        if self
            .packages
            .iter()
            .any(|entry| entry.name == name && entry.version == version)
        {
            return Err(invalid(
                "version is already registered; existing source content is immutable",
            ));
        }
        let channel = self
            .channels
            .iter()
            .find(|channel| channel.name == name)
            .ok_or_else(|| invalid("unknown official channel"))?;
        if channel.release_policy == "even-minor"
            && !version
                .split('.')
                .nth(1)
                .and_then(|part| part.parse::<u64>().ok())
                .is_some_and(|minor| minor.is_multiple_of(2))
        {
            return Err(invalid("version is outside the stable channel"));
        }
        let templates: Vec<_> = self
            .packages
            .iter()
            .filter(|entry| entry.name == name && self.defaults.get(name) == Some(&entry.version))
            .cloned()
            .collect();
        if templates.is_empty() {
            return Err(invalid(
                "new package requires an explicitly reviewed initial recipe and contract",
            ));
        }
        let first = &templates[0];
        let source_url = first.source_url.replace(&first.version, version);
        let bytes = download(
            &source_url,
            first.source_maximum_bytes,
            &channel.origin,
        )?;
        let hash = ContentDigest::sha256(&bytes).to_string();
        let signature_url = first
            .signature_url
            .as_ref()
            .map(|url| url.replace(&first.version, version));
        if let Some(signature_url) = &signature_url {
            verify_signature(
                root,
                channel,
                &bytes,
                &download(signature_url, 64 * 1024, &channel.origin)?,
            )?;
        } else if channel.signing_key.is_some() {
            return Err(invalid("signed release lacks a signature"));
        }
        let mut pending = BTreeMap::new();
        let mut entries = Vec::new();
        for template in templates {
            let old_stem = template.version.replace('.', "_");
            let new_stem = version.replace('.', "_");
            let mut entry = template.clone();
            version.clone_into(&mut entry.version);
            entry.source_url.clone_from(&source_url);
            entry.source_sha256.clone_from(&hash);
            entry.signature_url.clone_from(&signature_url);
            entry.recipe = template.recipe.replace(&old_stem, &new_stem);
            entry.source = template.source.replace(&old_stem, &new_stem);
            entry.export = template.export.replace(&old_stem, &new_stem);
            if entry.recipe == template.recipe
                || entry.source == template.source
                || entry.export == template.export
            {
                return Err(invalid(
                    "recipe and source paths must include the immutable version",
                ));
            }
            let mut substitutions = vec![
                (template.version.clone(), version.to_owned()),
                (old_stem, new_stem),
                (template.source_sha256.clone(), hash.clone()),
            ];
            entry.recipe_inputs.clear();
            for path in &template.recipe_inputs {
                let input = bounded_file(root, path)?;
                if Path::new(path)
                    .extension()
                    .is_some_and(|extension| extension == "srx")
                    && std::str::from_utf8(&input)
                        .is_ok_and(|text| text.contains(&template.version))
                {
                    let stem = path.strip_suffix(".srx").expect("suffix tested");
                    let updated = format!("{stem}_{}.srx", version.replace('.', "_"));
                    substitutions.push((
                        Path::new(path)
                            .file_stem()
                            .expect("canonical input")
                            .to_string_lossy()
                            .into_owned(),
                        Path::new(&updated)
                            .file_stem()
                            .expect("canonical input")
                            .to_string_lossy()
                            .into_owned(),
                    ));
                    pending.insert(updated.clone(), input);
                    entry.recipe_inputs.push(updated);
                } else {
                    entry.recipe_inputs.push(path.clone());
                }
            }
            for (old, new) in [
                (&template.recipe, &entry.recipe),
                (&template.source, &entry.source),
            ] {
                pending.insert(new.clone(), bounded_file(root, old)?);
            }
            for path in std::iter::once(&entry.recipe)
                .chain(std::iter::once(&entry.source))
                .chain(
                    entry
                        .recipe_inputs
                        .iter()
                        .filter(|path| !template.recipe_inputs.contains(path)),
                )
            {
                let bytes = pending.get_mut(path).expect("staged input");
                let mut text =
                    String::from_utf8(bytes.clone()).map_err(|_| invalid("recipe is not UTF-8"))?;
                for (old, new) in &substitutions {
                    text = text.replace(old, new);
                }
                *bytes = text.into_bytes();
            }
            entries.push(entry);
        }
        let mut next = self.clone();
        next.packages.extend(entries);
        next.validate()?;
        for path in pending.keys() {
            if root.join(path).exists() {
                return Err(invalid(
                    "addition would overwrite a retained recipe",
                ));
            }
        }
        // Admit new files first; the inventory commit is last. No old file is rewritten.
        for (path, bytes) in pending {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(root.join(path))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        let index = toml::to_string_pretty(&next).map_err(|error| invalid(error.to_string()))?;
        let mut staged = tempfile::NamedTempFile::new_in(root)?;
        staged.write_all(index.as_bytes())?;
        staged.as_file().sync_all()?;
        staged
            .persist(root.join(INDEX_FILE))
            .map_err(|error| CatalogError::Io(error.error))?;
        *self = next;
        Ok(())
    }

    pub fn load(root: &Path) -> Result<Self, CatalogError> {
        let bytes = bounded_file(root, INDEX_FILE)?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| invalid("catalog index is not UTF-8"))?;
        let result: Self = toml::from_str(text).map_err(|error| invalid(error.to_string()))?;
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.schema != 1
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

    pub fn lock(&self, root: &Path) -> Result<CatalogLock, CatalogError> {
        self.validate()?;
        let mut versions = Vec::new();
        for package in &self.packages {
            let mut inputs = BTreeMap::new();
            for path in [
                &package.recipe,
                &package.source,
                &package.contract,
                &package.toolchain,
            ] {
                inputs.insert(
                    path.clone(),
                    ContentDigest::sha256(&bounded_file(root, path)?).to_string(),
                );
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
            let expected = [
                &package.name,
                &package.version,
                &package.variant,
                &package.system,
            ];
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
                        if !contract_matches {
                            return false;
                        }
                        function.package.as_ref().is_some_and(|identity| {
                            identity
                                .iter()
                                .zip(expected)
                                .all(|(literal, value)| {
                                    literal
                                        .parts
                                        .iter()
                                        .all(|part| matches!(part, StringPart::Text { .. }))
                                        && literal.source == format!("\"{value}\"")
                                })
                        })
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

impl Channel {
    /// Only numbered stable archives are accepted. HTML markup and prereleases
    /// cannot become version components or paths in a generated catalog entry.
    pub fn latest(&self, html: &str) -> Option<String> {
        html.split(&self.archive_prefix)
            .skip(1)
            .filter_map(|suffix| {
                let end = suffix.find(&self.archive_suffix)?;
                let version = &suffix[..end];
                if version.len() > 64 {
                    return None;
                }
                let numbers: Vec<u64> = version
                    .split('.')
                    .map(str::parse)
                    .collect::<Result<_, _>>()
                    .ok()?;
                if numbers.len() < 2
                    || numbers.len() > 4
                    || (self.release_policy == "even-minor" && !numbers[1].is_multiple_of(2))
                {
                    return None;
                }
                Some((numbers, version.to_owned()))
            })
            .max_by(|left, right| left.0.cmp(&right.0))
            .map(|(_, version)| version)
    }
}

fn download(url: &str, limit: u64, origin: &str) -> Result<Vec<u8>, CatalogError> {
    let host = url::Url::parse(origin).map_err(|error| invalid(error.to_string()))?;
    let host = host
        .host_str()
        .ok_or_else(|| invalid("origin has no host"))?;
    crate::acquire::https::download_authenticated(
        crate::acquire::https::DownloadRequest {
            url,
            maximum_bytes: limit,
            policy: crate::acquire::https::HttpsTransportPolicy::default(),
            test_certificate: None,
            accept: None,
            hosts: Some(&[host]),
        },
        std::time::Instant::now(),
        &crate::cancellation::Cancellation::default(),
    )
    .map_err(|error| invalid(error.to_string()))
}

fn verify_signature(
    root: &Path,
    channel: &Channel,
    archive: &[u8],
    signature: &[u8],
) -> Result<(), CatalogError> {
    let fingerprint = channel
        .signing_key
        .as_deref()
        .ok_or_else(|| invalid("signature has no previously pinned signing key"))?;
    let key_file = channel
        .key_file
        .as_deref()
        .ok_or_else(|| invalid("signature has no pinned key file"))?;
    let home = tempfile::tempdir()?;
    let key = home.path().join("key.asc");
    let source = home.path().join("source");
    let detached = home.path().join("signature");
    fs::write(&key, bounded_file(root, key_file)?)?;
    fs::write(&source, archive)?;
    fs::write(&detached, signature)?;
    let import = std::process::Command::new("gpg")
        .arg("--no-autostart")
        .args(["--no-options", "--batch", "--homedir"])
        .arg(home.path())
        .arg("--import")
        .arg(key)
        .output()?;
    if !import.status.success() {
        return Err(invalid("pinned key import failed"));
    }
    let verification = std::process::Command::new("gpg")
        .args([
            "--no-options",
            "--batch",
            "--no-auto-key-retrieve",
            "--homedir",
        ])
        .arg(home.path())
        .args(["--status-fd", "1", "--verify"])
        .arg(detached)
        .arg(source)
        .output()?;
    let status = std::str::from_utf8(&verification.stdout)
        .map_err(|_| invalid("invalid verifier status"))?;
    let valid = status.lines().any(|line| {
        line.strip_prefix("[GNUPG:] VALIDSIG ")
            .is_some_and(|fields| fields.split_whitespace().last() == Some(fingerprint))
    });
    if !verification.status.success() || !valid {
        return Err(invalid(
            "signature rejected or signing key changed",
        ));
    }
    Ok(())
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

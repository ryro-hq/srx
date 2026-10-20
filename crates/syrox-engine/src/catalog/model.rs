use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io};
use thiserror::Error;

pub const INDEX_FILE: &str = "catalog.toml";
pub const LOCK_FILE: &str = "Catalog.lock";
pub(super) const MAX_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const MAX_ENTRIES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(try_from = "CatalogDocument", into = "CatalogDocument")]
pub struct Catalog {
    pub schema: u32,
    pub defaults: BTreeMap<String, String>,
    pub channels: Vec<Channel>,
    pub packages: Vec<PackageVersion>,
}

/// The index records upstream bytes once per release; locks retain expanded rows.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogDocument {
    schema: u32,
    defaults: BTreeMap<String, String>,
    channels: Vec<Channel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    releases: Option<Vec<Release>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    packages: Option<Vec<PackageVersion>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Release {
    name: String,
    version: String,
    source_url: String,
    source_sha256: String,
    source_maximum_bytes: u64,
    signature_url: Option<String>,
    source: String,
    combinations: Vec<Combination>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Combination {
    variant: String,
    system: String,
    recipe: String,
    factory: String,
    export: String,
    contract: String,
    contract_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    toolchain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    qualification: Option<String>,
    #[serde(default)]
    recipe_inputs: Vec<String>,
}

impl TryFrom<CatalogDocument> for Catalog {
    type Error = CatalogError;
    fn try_from(document: CatalogDocument) -> Result<Self, Self::Error> {
        let packages = match (
            document.schema,
            document.releases,
            document.packages,
        ) {
            (1, None, Some(packages)) => packages,
            (2, Some(releases), None) => {
                let mut seen = std::collections::BTreeSet::new();
                let mut packages = Vec::new();
                for release in releases {
                    if !seen.insert((release.name.clone(), release.version.clone()))
                        || release.combinations.is_empty()
                    {
                        return Err(super::files::invalid(
                            "release must appear once with explicit combinations",
                        ));
                    }
                    for combination in release.combinations {
                        if packages.len() >= MAX_ENTRIES {
                            return Err(super::files::invalid("inventory limit"));
                        }
                        packages.push(PackageVersion {
                            name: release.name.clone(),
                            version: release.version.clone(),
                            source_url: release.source_url.clone(),
                            source_sha256: release.source_sha256.clone(),
                            source_maximum_bytes: release.source_maximum_bytes,
                            signature_url: release.signature_url.clone(),
                            source: release.source.clone(),
                            variant: combination.variant,
                            system: combination.system,
                            recipe: combination.recipe,
                            factory: combination.factory,
                            export: combination.export,
                            contract: combination.contract,
                            contract_type: combination.contract_type,
                            toolchain: combination.toolchain,
                            qualification: combination.qualification,
                            recipe_inputs: combination.recipe_inputs,
                        });
                    }
                }
                packages
            }
            _ => {
                return Err(super::files::invalid(
                    "unsupported or mixed inventory schema",
                ));
            }
        };
        let catalog = Self {
            schema: document.schema,
            defaults: document.defaults,
            channels: document.channels,
            packages,
        };
        catalog.validate()?;
        Ok(catalog)
    }
}

impl From<Catalog> for CatalogDocument {
    fn from(catalog: Catalog) -> Self {
        if catalog.schema == 1 {
            return Self {
                schema: 1,
                defaults: catalog.defaults,
                channels: catalog.channels,
                releases: None,
                packages: Some(catalog.packages),
            };
        }
        let mut releases: BTreeMap<(String, String), Release> = BTreeMap::new();
        for package in catalog.packages {
            let release = releases
                .entry((package.name.clone(), package.version.clone()))
                .or_insert_with(|| Release {
                    name: package.name,
                    version: package.version,
                    source_url: package.source_url,
                    source_sha256: package.source_sha256,
                    source_maximum_bytes: package.source_maximum_bytes,
                    signature_url: package.signature_url,
                    source: package.source,
                    combinations: Vec::new(),
                });
            release.combinations.push(Combination {
                variant: package.variant,
                system: package.system,
                recipe: package.recipe,
                factory: package.factory,
                export: package.export,
                contract: package.contract,
                contract_type: package.contract_type,
                toolchain: package.toolchain,
                qualification: package.qualification,
                recipe_inputs: package.recipe_inputs,
            });
        }
        Self {
            schema: 2,
            defaults: catalog.defaults,
            channels: catalog.channels,
            releases: Some(releases.into_values().collect()),
            packages: None,
        }
    }
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub toolchain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification: Option<String>,
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

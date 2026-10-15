//! Generated release values contain no construction or service implementation.
use super::{
    Catalog, CatalogError,
    files::{bounded_file, invalid},
};
use crate::store::ContentDigest;
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    io::Write as _,
    path::{Component, Path},
};

impl Catalog {
    pub(super) fn release_data(
        &self,
        root: &Path,
    ) -> Result<BTreeMap<String, Vec<u8>>, CatalogError> {
        self.validate()?;
        let mut families: BTreeMap<&str, Vec<_>> = BTreeMap::new();
        for package in &self.packages {
            families
                .entry(&package.name)
                .or_default()
                .push(package);
        }
        let mut generated = BTreeMap::new();
        for (name, mut packages) in families {
            packages.sort_by_key(|package| {
                (
                    &package.version,
                    &package.variant,
                    &package.system,
                )
            });
            let source_path = &packages[0].source;
            if packages
                .iter()
                .any(|package| &package.source != source_path)
            {
                return Err(invalid(
                    "a package must have one generated release data module",
                ));
            }
            let mut text = String::from(
                "// Generated from catalog.toml. Selection, construction and services belong to package modules.\n\npub fn source(const version: std::PackagePinText) -> support::Source {\nmatch version {\n",
            );
            let mut previous = None;
            for package in &packages {
                if previous == Some(&package.version) {
                    continue;
                }
                previous = Some(&package.version);
                writeln!(text, "{} => support::Source {{ version = {}; url = {}; sha256 = {}; maximum_bytes = {}; }},", quoted(&package.version)?, quoted(&package.version)?, quoted(&package.source_url)?, quoted(&package.source_sha256)?, package.source_maximum_bytes).expect("String write");
            }
            text.push_str("}\n}\n\npub fn compatibility(const version: std::PackagePinText, const variant: std::PackagePinText, const system: std::PackagePinText) -> support::Compatibility {\nmatch version {\n");
            let versions: std::collections::BTreeSet<_> = packages
                .iter()
                .map(|package| &package.version)
                .collect();
            for version in versions {
                writeln!(text, "{} => match variant {{", quoted(version)?).expect("String write");
                let variants: std::collections::BTreeSet<_> = packages
                    .iter()
                    .filter(|package| &package.version == version)
                    .map(|package| &package.variant)
                    .collect();
                for variant in variants {
                    writeln!(text, "{} => match system {{", quoted(variant)?)
                        .expect("String write");
                    for package in packages.iter().filter(|package| {
                        &package.version == version && &package.variant == variant
                    }) {
                        let pin = ContentDigest::sha256(&bounded_file(root, &package.contract)?)
                            .to_string();
                        let id = Path::new(&package.contract)
                            .file_stem()
                            .and_then(|stem| stem.to_str())
                            .ok_or_else(|| invalid("contract requires a module name"))?;
                        writeln!(
                            text,
                            "{} => support::Compatibility {{ id = {}; pin = {}; }},",
                            quoted(&package.system)?,
                            quoted(id)?,
                            quoted(&pin)?
                        )
                        .expect("String write");
                    }
                    text.push_str("},\n");
                }
                text.push_str("},\n");
            }
            text.push_str("}\n}\n");
            let source = syrox_lang::source::Source::new(name, text)
                .map_err(|error| invalid(error.to_string()))?;
            let formatted = syrox_lang::formatter::format_source(&source)
                .map_err(|error| invalid(error.to_string()))?;
            if generated
                .insert(source_path.clone(), formatted.into_bytes())
                .is_some()
            {
                return Err(invalid(
                    "packages cannot share a generated data module",
                ));
            }
        }
        Ok(generated)
    }

    pub fn generate_releases(&self, root: &Path, check: bool) -> Result<(), CatalogError> {
        if self.schema != 2 {
            return Err(invalid("release generation requires schema 2"));
        }
        for (path, bytes) in self.release_data(root)? {
            if check {
                if bounded_file(root, &path)? != bytes {
                    return Err(invalid(format!(
                        "generated release data is stale: {path}"
                    )));
                }
                continue;
            }
            let relative = Path::new(&path);
            if !relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
            {
                return Err(invalid(
                    "release path must be relative without traversal",
                ));
            }
            let parent = relative
                .parent()
                .ok_or_else(|| invalid("release data requires a parent directory"))?;
            let mut directory = root.to_path_buf();
            for part in parent.components() {
                directory.push(part);
                if !fs::symlink_metadata(&directory)?.is_dir() {
                    return Err(invalid(
                        "release directory must be a real directory",
                    ));
                }
            }
            let mut staged = tempfile::NamedTempFile::new_in(&directory)?;
            staged.write_all(&bytes)?;
            staged.as_file().sync_all()?;
            staged
                .persist(root.join(relative))
                .map_err(|error| CatalogError::Io(error.error))?;
        }
        Ok(())
    }
}

fn quoted(value: &str) -> Result<String, CatalogError> {
    serde_json::to_string(value).map_err(|error| invalid(error.to_string()))
}

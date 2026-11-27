use super::{
    Catalog, CatalogError, Channel, INDEX_FILE,
    files::{bounded_file, invalid},
    model::MAX_BYTES,
    provenance::{download, verify_signature},
};
use crate::store::ContentDigest;
use std::{collections::BTreeMap, fs, io::Write as _, path::Path};

fn stable_version(version: &str) -> Option<Vec<u64>> {
    if version.len() > 64 {
        return None;
    }
    let numbers = version
        .split('.')
        .map(|part| {
            if part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            part.parse().ok()
        })
        .collect::<Option<Vec<_>>>()?;
    (2..=4)
        .contains(&numbers.len())
        .then_some(numbers)
}

impl Catalog {
    fn newer_than_registered(&self, name: &str, version: &[u64]) -> bool {
        self.packages
            .iter()
            .filter(|package| package.name == name)
            .filter_map(|package| stable_version(&package.version))
            .all(|registered| registered.as_slice() < version)
    }

    pub fn updates(&self) -> Result<Vec<(String, String)>, CatalogError> {
        let mut result = Vec::new();
        for channel in &self.channels {
            if channel.signing_key.is_none() {
                continue;
            }
            let bytes = download(&channel.releases, MAX_BYTES, channel)
                .map_err(|error| invalid(format!("{} release feed: {error}", channel.name)))?;
            let html =
                std::str::from_utf8(&bytes).map_err(|_| invalid("release feed is not UTF-8"))?;
            if let Some(version) = channel.latest(html) {
                if stable_version(&version)
                    .is_some_and(|parts| self.newer_than_registered(&channel.name, &parts))
                {
                    result.push((channel.name.clone(), version));
                }
            } else {
                return Err(invalid(format!(
                    "{} release feed contains no stable archives",
                    channel.name
                )));
            }
        }
        Ok(result)
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
        let version_parts = stable_version(version)
            .ok_or_else(|| invalid("version must be an exact numbered stable release"))?;
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
        if channel.signing_key.is_none() || channel.key_file.is_none() {
            return Err(invalid(
                "catalog add requires a pinned signing authority",
            ));
        }
        if channel.release_policy == "even-minor" && !version_parts[1].is_multiple_of(2) {
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
        let signature_url = first
            .signature_url
            .as_ref()
            .map(|url| url.replace(&first.version, version))
            .ok_or_else(|| invalid("catalog add requires a detached signature"))?;
        let source_url = first.source_url.replace(&first.version, version);
        if source_url == first.source_url || first.signature_url.as_ref() == Some(&signature_url) {
            return Err(invalid(
                "source and signature URLs must be version-specific",
            ));
        }
        let bytes = download(&source_url, first.source_maximum_bytes, channel)?;
        let hash = ContentDigest::sha256(&bytes).to_string();
        verify_signature(
            root,
            channel,
            &bytes,
            &download(&signature_url, 64 * 1024, channel)?,
        )?;
        let signature_url = Some(signature_url);
        if self.schema == 2 {
            let mut next = self.clone();
            for mut entry in templates {
                version.clone_into(&mut entry.version);
                entry.source_url.clone_from(&source_url);
                entry.source_sha256.clone_from(&hash);
                entry.signature_url.clone_from(&signature_url);
                next.packages.push(entry);
            }
            next.validate()?;
            next.generate_releases(root, false)?;
            let index =
                toml::to_string_pretty(&next).map_err(|error| invalid(error.to_string()))?;
            let mut staged = tempfile::NamedTempFile::new_in(root)?;
            staged.write_all(index.as_bytes())?;
            staged.as_file().sync_all()?;
            staged
                .persist(root.join(INDEX_FILE))
                .map_err(|error| CatalogError::Io(error.error))?;
            *self = next;
            return Ok(());
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
}

impl Channel {
    /// Only numbered stable archives are accepted. HTML markup and prereleases
    /// cannot become version components or paths in a generated catalog entry.
    pub fn latest(&self, html: &str) -> Option<String> {
        let (prefix, suffix_end) = if self.release_policy == "github-release-tag" {
            (
                format!("/releases/tag/{}", self.archive_prefix),
                "\"",
            )
        } else {
            (
                self.archive_prefix.clone(),
                self.archive_suffix.as_str(),
            )
        };
        html.split(&prefix)
            .skip(1)
            .filter_map(|suffix| {
                let (version, _) = suffix.split_once(suffix_end)?;
                let numbers = stable_version(version)?;
                if self.release_policy == "even-minor" && !numbers[1].is_multiple_of(2) {
                    return None;
                }
                Some((numbers, version.to_owned()))
            })
            .max_by(|left, right| left.0.cmp(&right.0))
            .map(|(_, version)| version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_versions_compare_numerically_and_exclude_aliases() {
        for invalid in [
            "1",
            "1.02",
            "+1.2",
            "1..2",
            "1.2rc2",
            "1.2.3.4.5",
        ] {
            assert!(stable_version(invalid).is_none(), "{invalid}");
        }
        assert!(stable_version("1.10.0") > stable_version("1.2.9"));
    }
}

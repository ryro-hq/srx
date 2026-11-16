//! Deterministic system-tree composition from explicit component manifests.
//!
//! This module never discovers or reads host files. A file source identifies the
//! component, relative path, logical content pin and size that an image writer
//! must independently verify. Composition does not install an image or run tools.

use crate::budget::AdmittedBudget;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

mod initramfs;
pub use initramfs::{ArchiveError, ComponentReader, WrittenArchive};

const MAX_ENTRIES: usize = 1_000_000;
const MAX_PATH_BYTES: usize = 4096;
const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSource {
    pub component: String,
    pub path: String,
    pub content_sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileMetadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Entry {
    Directory {
        metadata: FileMetadata,
    },
    File {
        metadata: FileMetadata,
        source: FileSource,
    },
    Symlink {
        uid: u32,
        gid: u32,
        target: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentEntry {
    pub path: String,
    pub entry: Entry,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentManifest {
    /// Pinned identity of the authenticated input artifact, never a package label.
    pub identity_sha256: String,
    pub entries: Vec<ComponentEntry>,
}

/// A borrowed path kind for checking declarations before component contents
/// have been built. This carries neither artifact identity nor file authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutKind<'a> {
    Directory,
    File,
    Symlink(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayoutEntry<'a> {
    pub path: &'a str,
    pub kind: LayoutKind<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposedEntry {
    pub entry: Entry,
    pub origins: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SystemTree {
    version: u32,
    entries: BTreeMap<String, ComposedEntry>,
    content_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImageError {
    #[error("invalid component identity or file content pin")]
    Identity,
    #[error("image path {0:?} is not canonical")]
    Path(String),
    #[error("image path {0:?} is declared more than once")]
    DuplicatePath(String),
    #[error("image path {path:?} collides between components {first} and {second}")]
    Collision {
        path: String,
        first: String,
        second: String,
    },
    #[error("image path {path:?} has no declared directory parent {parent:?}")]
    Parent {
        path: String,
        parent: String,
    },
    #[error("image path {0:?} has invalid ownership or permissions")]
    Metadata(String),
    #[error("image exceeds its admitted {0} budget")]
    Budget(&'static str),
    #[error("symlink at {0:?} escapes the image root, is cyclic, or has an invalid target")]
    Symlink(String),
    #[error("system tree manifest is malformed, noncanonical or uses an unsupported version")]
    Manifest,
}

impl SystemTree {
    pub const fn version(&self) -> u32 {
        self.version
    }
    pub fn entries(&self) -> &BTreeMap<String, ComposedEntry> {
        &self.entries
    }
    pub const fn content_bytes(&self) -> u64 {
        self.content_bytes
    }

    /// Canonical, versioned metadata. File contents remain in authenticated
    /// components. This encoding also defines the tree's SHA-256 identity.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = b"syrox-system-tree-v1\n".to_vec();
        serde_json::to_writer(&mut bytes, self).expect("serializable tree metadata");
        bytes
    }

    /// Revalidate an untrusted tree before any content is opened. No unchecked
    /// deserialization constructor is exposed for `SystemTree`.
    pub fn parse(bytes: &[u8], budget: &AdmittedBudget) -> Result<Self, ImageError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EncodedTree {
            version: u32,
            entries: BTreeMap<String, ComposedEntry>,
            content_bytes: u64,
        }
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(ImageError::Budget("metadata bytes"));
        }
        let fields: EncodedTree = serde_json::from_slice(
            bytes
                .strip_prefix(b"syrox-system-tree-v1\n")
                .ok_or(ImageError::Manifest)?,
        )
        .map_err(|_| ImageError::Manifest)?;
        if fields.version != 1 || fields.entries.len() > MAX_ENTRIES {
            return Err(ImageError::Manifest);
        }
        let mut components = BTreeMap::<String, Vec<ComponentEntry>>::new();
        let mut declarations = 0;
        for (path, item) in fields.entries {
            if item.origins.is_empty() {
                return Err(ImageError::Manifest);
            }
            for origin in item.origins {
                declarations += 1;
                if declarations > MAX_ENTRIES {
                    return Err(ImageError::Budget("entry count"));
                }
                components
                    .entry(origin)
                    .or_default()
                    .push(ComponentEntry {
                        path: path.clone(),
                        entry: item.entry.clone(),
                    });
            }
        }
        let components: Vec<_> = components
            .into_iter()
            .map(|(identity_sha256, entries)| ComponentManifest {
                identity_sha256,
                entries,
            })
            .collect();
        let validated = Self::compose(&components, budget)?;
        if validated.content_bytes != fields.content_bytes || validated.canonical_bytes() != bytes {
            return Err(ImageError::Manifest);
        }
        Ok(validated)
    }

    /// Merge explicit entries. Only identical directory metadata can be shared;
    /// files and links must have one unambiguous producer, even if bytes match.
    pub fn compose(
        components: &[ComponentManifest],
        budget: &AdmittedBudget,
    ) -> Result<Self, ImageError> {
        if components.len() > MAX_ENTRIES {
            return Err(ImageError::Budget("component count"));
        }
        let mut entries: BTreeMap<String, ComposedEntry> = BTreeMap::new();
        let mut components_seen = BTreeSet::new();
        let mut content_bytes = 0_u64;
        let mut metadata_bytes = 0_usize;
        let mut declared = 0_u64;
        for component in components {
            if !valid_digest(&component.identity_sha256)
                || !components_seen.insert(component.identity_sha256.as_str())
            {
                return Err(ImageError::Identity);
            }
            let mut own_paths = BTreeSet::new();
            for item in &component.entries {
                declared += 1;
                // Charge declarations as well as unique entries: repeated empty
                // directories cannot hide unbounded input work behind merging.
                if declared > MAX_ENTRIES as u64 {
                    return Err(ImageError::Budget("entry count"));
                }
                if !canonical_absolute(&item.path) {
                    return Err(ImageError::Path(item.path.clone()));
                }
                metadata_bytes = metadata_bytes
                    .checked_add(item.path.len() + component.identity_sha256.len())
                    .ok_or(ImageError::Budget("metadata bytes"))?;
                if !own_paths.insert(item.path.as_str()) {
                    return Err(collision(
                        &item.path,
                        &component.identity_sha256,
                        &component.identity_sha256,
                    ));
                }
                match &item.entry {
                    Entry::Directory {
                        metadata,
                    } => validate_metadata(&item.path, *metadata)?,
                    Entry::File {
                        metadata,
                        source,
                    } => {
                        validate_metadata(&item.path, *metadata)?;
                        if source.component != component.identity_sha256
                            || !valid_digest(&source.content_sha256)
                        {
                            return Err(ImageError::Identity);
                        }
                        if !canonical_relative(&source.path) {
                            return Err(ImageError::Path(source.path.clone()));
                        }
                        metadata_bytes = metadata_bytes
                            .checked_add(
                                source.path.len()
                                    + source.content_sha256.len()
                                    + source.component.len(),
                            )
                            .ok_or(ImageError::Budget("metadata bytes"))?;
                        content_bytes = content_bytes
                            .checked_add(source.size_bytes)
                            .ok_or(ImageError::Budget("output bytes"))?;
                        if content_bytes > budget.request().output_bytes {
                            return Err(ImageError::Budget("output bytes"));
                        }
                    }
                    Entry::Symlink {
                        uid,
                        gid,
                        target,
                    } => {
                        if *uid == u32::MAX || *gid == u32::MAX {
                            return Err(ImageError::Metadata(item.path.clone()));
                        }
                        metadata_bytes = metadata_bytes
                            .checked_add(target.len())
                            .ok_or(ImageError::Budget("metadata bytes"))?;
                        validate_target_text(&item.path, target)?;
                    }
                }
                if metadata_bytes > MAX_METADATA_BYTES {
                    return Err(ImageError::Budget("metadata bytes"));
                }
                if let Some(existing) = entries.get_mut(&item.path) {
                    if matches!((&existing.entry, &item.entry), (Entry::Directory { metadata: first }, Entry::Directory { metadata: second }) if first == second)
                    {
                        existing
                            .origins
                            .insert(component.identity_sha256.clone());
                    } else {
                        return Err(collision(
                            &item.path,
                            existing
                                .origins
                                .first()
                                .expect("entry has an origin"),
                            &component.identity_sha256,
                        ));
                    }
                } else {
                    if entries.len() as u64 >= budget.request().files {
                        return Err(ImageError::Budget("files"));
                    }
                    entries.insert(
                        item.path.clone(),
                        ComposedEntry {
                            entry: item.entry.clone(),
                            origins: BTreeSet::from([component.identity_sha256.clone()]),
                        },
                    );
                }
            }
        }
        validate_layout(entries.iter().map(|(path, item)| LayoutEntry {
            path,
            kind: match &item.entry {
                Entry::Directory {
                    ..
                } => LayoutKind::Directory,
                Entry::File {
                    ..
                } => LayoutKind::File,
                Entry::Symlink {
                    target,
                    ..
                } => LayoutKind::Symlink(target),
            },
        }))?;
        let tree = Self {
            version: 1,
            entries,
            content_bytes,
        };
        if tree.canonical_bytes().len() > MAX_METADATA_BYTES {
            return Err(ImageError::Budget("metadata bytes"));
        }
        Ok(tree)
    }

    /// The version domain, complete ownership/link metadata and every producer
    /// and content identity enter the tree pin. No host timestamps are included.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Every field is numeric or a checked UTF-8 string; serialization cannot
        // fail. JSON's escaping is part of this versioned canonical encoding.
        hasher.update(self.canonical_bytes());
        hasher.finalize().into()
    }
}

/// Validate destination paths, explicit directory parents and contained link
/// traversal without reading files or inventing component/content pins.
pub fn validate_layout<'a>(
    items: impl IntoIterator<Item = LayoutEntry<'a>>,
) -> Result<(), ImageError> {
    let mut entries = BTreeMap::new();
    let mut metadata_bytes = 0_usize;
    for item in items {
        if entries.len() >= MAX_ENTRIES {
            return Err(ImageError::Budget("entry count"));
        }
        if !canonical_absolute(item.path) {
            return Err(ImageError::Path(item.path.into()));
        }
        let link_bytes = match item.kind {
            LayoutKind::Symlink(target) => {
                validate_target_text(item.path, target)?;
                target.len()
            }
            _ => 0,
        };
        metadata_bytes = metadata_bytes
            .checked_add(item.path.len() + link_bytes)
            .ok_or(ImageError::Budget("metadata bytes"))?;
        if metadata_bytes > MAX_METADATA_BYTES {
            return Err(ImageError::Budget("metadata bytes"));
        }
        if entries.insert(item.path, item.kind).is_some() {
            return Err(ImageError::DuplicatePath(item.path.into()));
        }
    }
    if !matches!(entries.get("/"), Some(LayoutKind::Directory)) {
        return Err(ImageError::Parent {
            path: "/".into(),
            parent: "/".into(),
        });
    }
    for path in entries
        .keys()
        .copied()
        .filter(|path| *path != "/")
    {
        let parent = parent(path);
        if !matches!(entries.get(parent), Some(LayoutKind::Directory)) {
            return Err(ImageError::Parent {
                path: path.into(),
                parent: parent.into(),
            });
        }
    }
    let lookup = |path: &str| entries.get(path).copied();
    for (path, kind) in &entries {
        if let LayoutKind::Symlink(target) = kind {
            validate_link(path, target, &lookup)?;
        }
    }
    Ok(())
}

fn validate_metadata(path: &str, metadata: FileMetadata) -> Result<(), ImageError> {
    if metadata.uid == u32::MAX || metadata.gid == u32::MAX || metadata.mode & !0o7777 != 0 {
        Err(ImageError::Metadata(path.into()))
    } else {
        Ok(())
    }
}

fn canonical_absolute(path: &str) -> bool {
    path == "/"
        || (path.starts_with('/') && path.len() <= MAX_PATH_BYTES && canonical_relative(&path[1..]))
}

fn canonical_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path.len() <= MAX_PATH_BYTES
        && path.split('/').all(|part| {
            !part.is_empty() && !matches!(part, "." | "..") && !part.chars().any(char::is_control)
        })
}

fn valid_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parent(path: &str) -> &str {
    let index = path.rfind('/').expect("canonical absolute path");
    if index == 0 {
        "/"
    } else {
        &path[..index]
    }
}

fn collision(path: &str, first: &str, second: &str) -> ImageError {
    ImageError::Collision {
        path: path.into(),
        first: first.into(),
        second: second.into(),
    }
}

fn validate_target_text(path: &str, target: &str) -> Result<(), ImageError> {
    if target.is_empty() || target.len() > MAX_PATH_BYTES || target.chars().any(char::is_control) {
        Err(ImageError::Symlink(path.into()))
    } else {
        Ok(())
    }
}

fn validate_link<'a>(
    path: &str,
    target: &str,
    lookup: &impl Fn(&str) -> Option<LayoutKind<'a>>,
) -> Result<(), ImageError> {
    validate_target_text(path, target)?;
    let mut current: Vec<String> = if target.starts_with('/') {
        vec![]
    } else {
        parent(path)
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let mut pending: VecDeque<String> = target.split('/').map(str::to_owned).collect();
    let mut hops = 1;
    while let Some(part) = pending.pop_front() {
        match part.as_str() {
            "" | "." => continue,
            ".." => {
                if current.pop().is_none() {
                    return Err(ImageError::Symlink(path.into()));
                }
                continue;
            }
            _ => current.push(part),
        }
        let prefix = format!("/{}", current.join("/"));
        if prefix.len() > MAX_PATH_BYTES {
            return Err(ImageError::Symlink(path.into()));
        }
        match lookup(&prefix) {
            Some(LayoutKind::Symlink(target)) => {
                hops += 1;
                if hops > 40 {
                    return Err(ImageError::Symlink(path.into()));
                }
                current.pop();
                if target.starts_with('/') {
                    current.clear();
                }
                let expanded = current
                    .iter()
                    .chain(&pending)
                    .map(|part| part.len() + 1)
                    .sum::<usize>()
                    + target
                        .split('/')
                        .map(|part| part.len() + 1)
                        .sum::<usize>();
                if expanded > MAX_PATH_BYTES {
                    return Err(ImageError::Symlink(path.into()));
                }
                for part in target.split('/').rev() {
                    pending.push_front(part.into());
                }
            }
            Some(LayoutKind::File) if !pending.is_empty() => {
                return Err(ImageError::Symlink(path.into()));
            }
            _ => {}
        }
    }
    // A dangling or runtime-provided target is valid, and never causes host I/O.
    // Resolve '..' only after following preceding links, as Linux pathwalk does.
    Ok(())
}

#[cfg(test)]
mod tests;

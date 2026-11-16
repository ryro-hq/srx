use super::{DeviceNumber, InventoryError, Path, Result, invalid};
use serde::Serialize;
use std::collections::BTreeSet;

const MAX_MOUNTS: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Mount {
    pub id: u64,
    pub parent_id: u64,
    pub device: DeviceNumber,
    /// Filesystem path, or a namespace handle such as net:[...] for nsfs mounts.
    pub root: String,
    pub target: String,
    pub filesystem: String,
    pub source: String,
    pub read_only: bool,
}

pub(super) fn parse(text: &str, path: &Path) -> Result<Vec<Mount>> {
    let mut result = Vec::new();
    let mut ids = BTreeSet::new();
    for line in text.lines() {
        if result.len() >= MAX_MOUNTS {
            return Err(InventoryError::Limit("mount count"));
        }
        if line.len() > 65_536 {
            return Err(InventoryError::Limit("mount line bytes"));
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let separator = fields
            .iter()
            .position(|field| *field == "-")
            .ok_or_else(|| invalid(path, "mountinfo separator is missing"))?;
        if separator < 6 || fields.len() != separator + 4 {
            return Err(invalid(path, "malformed mountinfo fields"));
        }
        let id = fields[0]
            .parse()
            .map_err(|_| invalid(path, "invalid mount id"))?;
        let parent_id = fields[1]
            .parse()
            .map_err(|_| invalid(path, "invalid parent mount id"))?;
        if !ids.insert(id) {
            return Err(invalid(path, "duplicate mount id"));
        }
        let options: Vec<_> = fields[5].split(',').collect();
        let read_only = options.contains(&"ro");
        if read_only == options.contains(&"rw") {
            return Err(invalid(
                path,
                "missing or conflicting mount write mode",
            ));
        }
        let root = unescape(fields[3], path)?;
        let target = unescape(fields[4], path)?;
        let namespace_root = fields[separator + 1] == "nsfs"
            && root.split_once(":[").is_some_and(|(kind, rest)| {
                !kind.is_empty()
                    && kind.bytes().all(|byte| byte.is_ascii_lowercase())
                    && rest.strip_suffix(']').is_some_and(|inode| {
                        !inode.is_empty() && inode.bytes().all(|byte| byte.is_ascii_digit())
                    })
            });
        if (!root.starts_with('/') && !namespace_root) || !target.starts_with('/') {
            return Err(invalid(
                path,
                "mount targets must be absolute and roots must be filesystem paths or nsfs handles",
            ));
        }
        result.push(Mount {
            id,
            parent_id,
            device: DeviceNumber::parse(fields[2], path)?,
            root,
            target,
            read_only,
            filesystem: fields[separator + 1].into(),
            source: unescape(fields[separator + 2], path)?,
        });
    }
    result.sort_by_key(|mount| mount.id);
    Ok(result)
}

fn unescape(text: &str, path: &Path) -> Result<String> {
    let mut output = Vec::with_capacity(text.len());
    let mut remaining = text.as_bytes();
    while let Some((&byte, tail)) = remaining.split_first() {
        if byte != b'\\' {
            output.push(byte);
            remaining = tail;
            continue;
        }
        if remaining.len() < 4 {
            return Err(invalid(path, "truncated mountinfo escape"));
        }
        output.push(match &remaining[1..4] {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err(invalid(path, "invalid mountinfo escape")),
        });
        remaining = &remaining[4..];
    }
    String::from_utf8(output).map_err(|_| invalid(path, "non-UTF-8 mount path"))
}

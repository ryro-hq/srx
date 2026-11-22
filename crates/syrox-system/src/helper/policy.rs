use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use syrox_system::{
    budget::{BuildBudget, BuilderLimits},
    descriptor::{
        self,
        pinned_tool::{PinnedTool, ToolPin},
    },
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
    pub version: u32,
    pub client_uid: u32,
    pub client_gid: u32,
    pub maximum: BuildBudget,
    pub maximum_operations: u32,
    pub state_directory: PathBuf,
    pub formatter: Tool,
    pub checker: Tool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tool {
    path: PathBuf,
    sha256: String,
    size_bytes: u64,
}

/// Formatter and checker pinned from the policy for one authorized operation.
#[derive(Debug)]
pub(super) struct PinnedTools {
    pub formatter: PinnedTool,
    pub checker: PinnedTool,
}

impl Policy {
    /// Pins the formatter, then the checker, against their policy digests.
    pub fn snapshot_tools(&self) -> io::Result<PinnedTools> {
        Ok(PinnedTools {
            formatter: self.formatter.snapshot()?,
            checker: self.checker.snapshot()?,
        })
    }

    pub fn load(path: &Path) -> io::Result<(Self, [u8; 32])> {
        let file = trusted(path, false)?;
        let mut bytes = Vec::new();
        file.take(65_537).read_to_end(&mut bytes)?;
        if bytes.len() > 65_536 {
            return Err(refused("helper policy exceeds 64 KiB"));
        }
        let policy: Self = serde_json::from_slice(&bytes)?;
        if policy.version != 1 || !(1..=64).contains(&policy.maximum_operations) {
            return Err(refused(
                "unsupported helper policy version or operation ceiling",
            ));
        }
        BuilderLimits::new(policy.maximum).map_err(io::Error::other)?;
        Ok((policy, Sha256::digest(&bytes).into()))
    }
}

impl Tool {
    pub fn snapshot(&self) -> io::Result<PinnedTool> {
        let sha256 = digest(&self.sha256)?;
        PinnedTool::snapshot(
            trusted(&self.path, false)?,
            ToolPin {
                sha256,
                size_bytes: self.size_bytes,
            },
            || Ok(()),
        )
    }
}

pub(super) fn digest(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(refused("expected lowercase SHA-256"));
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| refused("invalid SHA-256"))?;
    }
    Ok(digest)
}

/// All ancestors must be root-owned and protected against replacement. Sticky
/// root-owned temporary directories are admitted, but the selected state itself
/// must be private. No symlink or user-owned ancestor is accepted.
pub(super) fn trusted(path: &Path, directory: bool) -> io::Result<File> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(refused(
            "helper policy paths must be bounded absolute paths",
        ));
    }
    let mut current = descriptor::open_resolved(
        None,
        Path::new("/"),
        true,
        libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    )?;
    let components = path.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let last = index + 1 == components.len();
                current = descriptor::open_resolved(
                    Some(current.as_fd()),
                    Path::new(name),
                    !last || directory,
                    libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
                )?;
                let metadata = current.metadata()?;
                let writable = metadata.mode() & 0o022 != 0;
                let sticky_parent = !last && metadata.is_dir() && metadata.mode() & 0o1000 != 0;
                if metadata.uid() != 0
                    || (writable && !sticky_parent)
                    || (last && !directory && !metadata.is_file())
                {
                    return Err(refused(
                        "helper input is not protected by root ownership",
                    ));
                }
            }
            _ => {
                return Err(refused(
                    "helper paths cannot contain traversal components",
                ));
            }
        }
    }
    let metadata = current.metadata()?;
    if directory && (!metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700)
    {
        return Err(refused(
            "helper state requires an existing root-owned 0700 directory",
        ));
    }
    Ok(current)
}

pub(super) fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

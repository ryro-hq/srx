use super::super::policy::refused;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use syrox_encoding::formats;
use syrox_system::descriptor;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub uid: u32,
    pub mode: u32,
    pub links: u64,
}

impl Identity {
    pub fn read(file: &File, owner: u32, directory: bool) -> io::Result<Self> {
        let m = file.metadata()?;
        if m.uid() != owner
            || (directory && (!m.is_dir() || m.mode() & 0o7777 != 0o700))
            || (!directory && (!m.is_file() || m.mode() & 0o7777 != 0o600 || m.nlink() != 1))
        {
            return Err(refused(
                "recovery evidence has unexpected ownership, type, mode or links",
            ));
        }
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            uid: m.uid(),
            mode: m.mode(),
            links: m.nlink(),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub version: u32,
    pub state: String,
    pub details: serde_json::Value,
}

pub(super) struct Evidence {
    pub directory: File,
    pub identity: Identity,
    pub records: Vec<Record>,
    pub sha256: String,
}

pub(super) fn open(directory: &File, name: &str, is_dir: bool) -> io::Result<File> {
    descriptor::open_resolved(
        Some(directory.as_fd()),
        Path::new(name),
        is_dir,
        libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    )
}

pub(super) fn load(state: &File, name: &str) -> io::Result<Evidence> {
    let owner = state.metadata()?.uid(); // production state is independently root-authorized.
    let directory = open(state, name, true)?;
    let identity = Identity::read(&directory, owner, true)?;
    let mut names = Vec::new();
    let mut resources = Vec::new();
    for (count, entry) in
        std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))?.enumerate()
    {
        if count >= 64 {
            return Err(refused("excessive recovery entries"));
        }
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| refused("invalid evidence name"))?;
        if Path::new(&name)
            .extension()
            .is_some_and(|ext| ext == "json")
        {
            names.push(name);
        } else {
            resources.push(name);
        }
    }
    names.sort();
    let mut hash = Sha256::new();
    hash.update(formats::PRIVATE_SCRATCH_JOURNAL_LINE);
    let mut records = Vec::new();
    for (sequence, name) in names.iter().enumerate() {
        let file = open(&directory, name, false)?;
        Identity::read(&file, owner, false)?;
        let mut bytes = Vec::new();
        file.take(65_537).read_to_end(&mut bytes)?;
        if bytes.len() > 65_536 {
            return Err(refused("excessive recovery record"));
        }
        let record: Record = serde_json::from_slice(&bytes)?;
        if record.version != 1
            || *name != format!("{sequence:04}-{}.json", record.state)
            || !matches!(
                record.state.as_str(),
                "authorized"
                    | "allocate-intent"
                    | "image-allocated"
                    | "tool-intent"
                    | "tool-result"
                    | "loop-select-intent"
                    | "loop-configure-intent"
                    | "mount-intent"
                    | "assign-owner-intent"
                    | "offered"
                    | "loop-release-intent"
                    | "loop-release-observed"
                    | "released"
                    | "uncertain"
                    | "response-undelivered"
                    | "reconciled"
            )
        {
            return Err(refused(
                "unsupported or nonconsecutive recovery journal",
            ));
        }
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name.as_bytes());
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(&bytes);
        records.push(record);
    }
    if records
        .first()
        .is_none_or(|r| r.state != "authorized")
    {
        return Err(refused("missing original scratch authorization"));
    }
    let workspace = records[0].details["request"]["operation"] == "prepare_workspace";
    for name in resources {
        let allowed = if workspace {
            matches!(
                name.as_str(),
                "scratch.img"
                    | "output.img"
                    | "scratch-format"
                    | "scratch-check-before"
                    | "scratch-check-after"
                    | "output-format"
                    | "output-check-before"
                    | "output-check-after"
            )
        } else {
            matches!(
                name.as_str(),
                "scratch.img" | "format" | "check-before" | "check-after"
            )
        };
        if !allowed {
            return Err(refused("unknown recovery evidence entry"));
        }
    }
    Ok(Evidence {
        directory,
        identity,
        records,
        sha256: syrox_encoding::hex(&hash.finalize()),
    })
}

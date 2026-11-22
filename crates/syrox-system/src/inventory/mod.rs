//! Bounded, read-only observations of Linux block devices and the mount namespace.
//!
//! Sources are fixed kernel interfaces; no utilities are executed and no block
//! devices are opened. Paths in the result are diagnostic. The observations are
//! neither an atomic snapshot nor proof that an unmounted disk is unused.

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read as _};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use syrox_encoding::formats;

mod mounts;
pub use mounts::Mount;

const MAX_DEVICES: usize = 4096;
const MAX_ENTRIES: usize = 65_536;
const MAX_READS: usize = 65_536;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_FIELD_BYTES: usize = 4096;
const MAX_MOUNTINFO_BYTES: usize = 8 * 1024 * 1024;
const SECTOR_BYTES: u64 = 512;

#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    #[error("system inventory I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid kernel observation at {path}: {reason}")]
    Invalid {
        path: PathBuf,
        reason: &'static str,
    },
    #[error("system inventory exceeded its {0} limit")]
    Limit(&'static str),
    #[error("block device {0} changed during inspection; inspect again")]
    Changed(String),
    #[error("system inventory cancelled")]
    Cancelled,
    #[error("system inventory encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, InventoryError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DeviceNumber {
    pub major: u32,
    pub minor: u32,
}

impl std::fmt::Display for DeviceNumber {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.major, self.minor)
    }
}

impl DeviceNumber {
    fn parse(text: &str, path: &Path) -> Result<Self> {
        let invalid = || {
            invalid(
                path,
                "expected a canonical major:minor device number",
            )
        };
        let (major, minor) = text.split_once(':').ok_or_else(invalid)?;
        let value = Self {
            major: major.parse().map_err(|_| invalid())?,
            minor: minor.parse().map_err(|_| invalid())?,
        };
        if value.to_string() != text {
            return Err(invalid());
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceIdentity {
    pub wwid: Option<String>,
    pub serial: Option<String>,
    pub model: Option<String>,
    pub device_mapper_uuid: Option<String>,
    pub partition_uuid: Option<String>,
    /// Changes when a disk instance is replaced, including some loop rebindings.
    pub disk_sequence: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Partition {
    pub number: u32,
    pub parent: DeviceNumber,
    pub start_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BlockDevice {
    pub name: String,
    pub number: DeviceNumber,
    pub diagnostic_path: PathBuf,
    pub sysfs_path: PathBuf,
    pub device_node_matches: bool,
    pub identity: DeviceIdentity,
    pub capacity_bytes: u64,
    pub logical_block_bytes: u64,
    pub physical_block_bytes: u64,
    pub read_only: bool,
    pub removable: bool,
    pub partition: Option<Partition>,
    /// Devices backed by this device, e.g. a device-mapper or RAID holder.
    pub holders: Vec<String>,
    /// Backing devices for this block device; partition parentage is separate.
    pub slaves: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SystemInventory {
    pub version: u32,
    pub inspector_architecture: String,
    pub kernel_release: String,
    pub boot_id: String,
    pub uefi_present: bool,
    /// Metadata observation only; availability of KVM ioctls is not tested.
    pub kvm_device_present: bool,
    pub devices: Vec<BlockDevice>,
    /// Only mounts visible in the inspecting process's mount namespace.
    pub mounts: Vec<Mount>,
}

impl SystemInventory {
    /// Stable serialization for the same observations, including a version domain.
    /// The digest identifies evidence, without conferring device authority.
    pub fn fingerprint(&self) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(formats::SYSTEM_INVENTORY_LINE);
        hasher.update(serde_json::to_vec(self)?);
        let mut result = String::with_capacity(64);
        for byte in hasher.finalize() {
            write!(result, "{byte:02x}").expect("String writes cannot fail");
        }
        Ok(result)
    }
}

/// Inspect fixed Linux kernel interfaces without project/configuration loading.
pub fn inspect() -> Result<SystemInventory> {
    inspect_with_cancellation(|| false)
}

pub fn inspect_with_cancellation(mut cancelled: impl FnMut() -> bool) -> Result<SystemInventory> {
    inspect_at(
        &Roots {
            sys: "/sys".into(),
            proc: "/proc".into(),
            dev: "/dev".into(),
        },
        &mut cancelled,
    )
}

struct Roots {
    sys: PathBuf,
    proc: PathBuf,
    dev: PathBuf,
}

struct Reader<'a> {
    bytes: usize,
    reads: usize,
    entries: usize,
    cancelled: &'a mut dyn FnMut() -> bool,
}

impl Reader<'_> {
    fn check(&mut self) -> Result<()> {
        if (self.cancelled)() {
            Err(InventoryError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn text(&mut self, path: &Path, maximum: usize) -> Result<Option<String>> {
        self.check()?;
        self.reads += 1;
        if self.reads > MAX_READS {
            return Err(InventoryError::Limit("file reads"));
        }
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(io_error(path, source)),
        };
        let mut bytes = Vec::new();
        let admitted = maximum.min(MAX_BYTES.saturating_sub(self.bytes));
        file.take(admitted as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| io_error(path, source))?;
        self.check()?;
        self.bytes += bytes.len();
        if bytes.len() > admitted {
            return Err(InventoryError::Limit("observation bytes"));
        }
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| invalid(path, "expected UTF-8 kernel text"))
    }

    fn required(&mut self, path: &Path) -> Result<String> {
        self.text(path, MAX_FIELD_BYTES)?
            .ok_or_else(|| invalid(path, "required kernel field is missing"))
            .map(|text| text.trim().to_owned())
    }

    fn optional(&mut self, path: &Path) -> Result<Option<String>> {
        Ok(self
            .text(path, MAX_FIELD_BYTES)?
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty()))
    }

    fn number(&mut self, path: &Path) -> Result<u64> {
        parse_number(&self.required(path)?, path)
    }

    fn boolean(&mut self, path: &Path) -> Result<bool> {
        match self.required(path)?.as_str() {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(invalid(path, "expected 0 or 1")),
        }
    }

    fn names(&mut self, path: &Path, maximum: usize) -> Result<Vec<String>> {
        self.check()?;
        let mut result = Vec::new();
        for entry in fs::read_dir(path).map_err(|source| io_error(path, source))? {
            self.check()?;
            self.entries += 1;
            if self.entries > MAX_ENTRIES || result.len() >= maximum {
                return Err(InventoryError::Limit("directory entries"));
            }
            let entry = entry.map_err(|source| io_error(path, source))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid(path, "non-UTF-8 device name"))?;
            if !valid_name(&name) {
                return Err(invalid(path, "unsafe device name"));
            }
            result.push(name);
        }
        result.sort();
        Ok(result)
    }
}

fn inspect_at(roots: &Roots, cancelled: &mut dyn FnMut() -> bool) -> Result<SystemInventory> {
    let mut reader = Reader {
        bytes: 0,
        reads: 0,
        entries: 0,
        cancelled,
    };
    reader.check()?;
    let kernel_release = reader.required(&roots.proc.join("sys/kernel/osrelease"))?;
    let boot_id = reader.required(&roots.proc.join("sys/kernel/random/boot_id"))?;
    if !valid_boot_id(&boot_id) {
        return Err(invalid(&roots.proc, "invalid boot identity"));
    }
    let sys = fs::canonicalize(&roots.sys).map_err(|source| io_error(&roots.sys, source))?;
    let class = roots.sys.join("class/block");
    let names = reader.names(&class, MAX_DEVICES)?;
    let mut devices = Vec::new();
    let mut numbers = BTreeSet::new();
    for name in &names {
        let device = read_device(roots, &sys, &class, name, &mut reader)?;
        if !numbers.insert(device.number) {
            return Err(InventoryError::Changed(name.clone()));
        }
        devices.push(device);
    }
    for device in &devices {
        if device
            .holders
            .iter()
            .chain(&device.slaves)
            .any(|name| names.binary_search(name).is_err())
            || device
                .partition
                .as_ref()
                .is_some_and(|partition| !numbers.contains(&partition.parent))
        {
            return Err(InventoryError::Changed(device.name.clone()));
        }
    }
    let mount_path = roots.proc.join("self/mountinfo");
    let mountinfo = reader
        .text(&mount_path, MAX_MOUNTINFO_BYTES)?
        .ok_or_else(|| {
            invalid(
                &mount_path,
                "mount namespace information is missing",
            )
        })?;
    let mounts = mounts::parse(&mountinfo, &mount_path)?;
    if names != reader.names(&class, MAX_DEVICES)? {
        return Err(InventoryError::Changed("device inventory".into()));
    }
    let uefi_present = is_directory(&roots.sys.join("firmware/efi"))?;
    let kvm_device_present = match fs::metadata(roots.dev.join("kvm")) {
        Ok(metadata) => metadata.file_type().is_char_device(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(source) => return Err(io_error(&roots.dev.join("kvm"), source)),
    };
    reader.check()?;
    Ok(SystemInventory {
        version: 1,
        inspector_architecture: std::env::consts::ARCH.into(),
        kernel_release,
        boot_id,
        uefi_present,
        kvm_device_present,
        devices,
        mounts,
    })
}

fn read_device(
    roots: &Roots,
    sys: &Path,
    class: &Path,
    name: &str,
    reader: &mut Reader<'_>,
) -> Result<BlockDevice> {
    let path =
        fs::canonicalize(class.join(name)).map_err(|source| io_error(&class.join(name), source))?;
    if !path.starts_with(sys) {
        return Err(invalid(
            &path,
            "block-device symlink leaves sysfs",
        ));
    }
    let number = DeviceNumber::parse(&reader.required(&path.join("dev"))?, &path)?;
    let sectors = reader.number(&path.join("size"))?;
    let capacity_bytes = sector_bytes(sectors, &path)?;
    let read_only = reader.boolean(&path.join("ro"))?;
    let uevent = reader.required(&path.join("uevent"))?;
    let properties = properties(&uevent, &path)?;
    if properties.get("DEVNAME").copied() != Some(name)
        || properties.get("MAJOR").copied() != Some(number.major.to_string().as_str())
        || properties.get("MINOR").copied() != Some(number.minor.to_string().as_str())
    {
        return Err(InventoryError::Changed(name.into()));
    }
    let partition_number = reader.optional(&path.join("partition"))?;
    let (partition, disk_path) = if let Some(partition_number) = partition_number {
        let parent = path
            .parent()
            .ok_or_else(|| invalid(&path, "partition has no parent"))?;
        let partition_number = u32::try_from(parse_number(&partition_number, &path)?)
            .map_err(|_| invalid(&path, "partition number exceeds u32"))?;
        if partition_number == 0 || properties.get("DEVTYPE").copied() != Some("partition") {
            return Err(invalid(&path, "inconsistent partition metadata"));
        }
        let partition = Partition {
            number: partition_number,
            parent: DeviceNumber::parse(&reader.required(&parent.join("dev"))?, parent)?,
            start_bytes: sector_bytes(reader.number(&path.join("start"))?, &path)?,
        };
        (Some(partition), parent)
    } else {
        if properties.get("DEVTYPE").copied() != Some("disk") {
            return Err(invalid(&path, "unsupported block device type"));
        }
        (None, path.as_path())
    };
    let logical_block_bytes = reader.number(&disk_path.join("queue/logical_block_size"))?;
    let physical_block_bytes = reader.number(&disk_path.join("queue/physical_block_size"))?;
    if logical_block_bytes == 0 || physical_block_bytes == 0 {
        return Err(invalid(&path, "zero block size"));
    }
    let disk_sequence = reader
        .optional(&disk_path.join("diskseq"))?
        .map(|text| parse_number(&text, disk_path))
        .transpose()?;
    let identity = DeviceIdentity {
        wwid: match reader.optional(&disk_path.join("wwid"))? {
            Some(value) => Some(value),
            None => reader.optional(&disk_path.join("device/wwid"))?,
        },
        serial: serial(reader, disk_path)?,
        model: reader.optional(&disk_path.join("device/model"))?,
        device_mapper_uuid: reader.optional(&disk_path.join("dm/uuid"))?,
        partition_uuid: properties
            .get("PARTUUID")
            .map(|text| (*text).to_owned()),
        disk_sequence,
    };
    let holders = reader.names(&path.join("holders"), MAX_DEVICES)?;
    let slaves = if partition.is_some() {
        Vec::new()
    } else {
        reader.names(&path.join("slaves"), MAX_DEVICES)?
    };
    let diagnostic_path = roots.dev.join(name);
    let device_node_matches = match fs::metadata(&diagnostic_path) {
        Ok(metadata) => {
            metadata.file_type().is_block_device()
                && libc::major(metadata.rdev()) == number.major
                && libc::minor(metadata.rdev()) == number.minor
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(source) => return Err(io_error(&diagnostic_path, source)),
    };
    let removable = reader.boolean(&disk_path.join("removable"))?;
    if fs::canonicalize(class.join(name)).map_err(|source| io_error(&class.join(name), source))?
        != path
        || reader.required(&path.join("dev"))? != number.to_string()
        || reader.number(&path.join("size"))? != sectors
        || reader.boolean(&path.join("ro"))? != read_only
        || reader.required(&path.join("uevent"))? != uevent
        || reader
            .optional(&disk_path.join("diskseq"))?
            .map(|text| parse_number(&text, disk_path))
            .transpose()?
            != disk_sequence
        || serial(reader, disk_path)? != identity.serial
    {
        return Err(InventoryError::Changed(name.into()));
    }
    Ok(BlockDevice {
        name: name.into(),
        number,
        diagnostic_path,
        sysfs_path: path,
        device_node_matches,
        identity,
        capacity_bytes,
        logical_block_bytes,
        physical_block_bytes,
        read_only,
        removable,
        partition,
        holders,
        slaves,
    })
}

fn serial(reader: &mut Reader<'_>, disk: &Path) -> Result<Option<String>> {
    // Drivers expose serial either on the disk (virtio-blk) or its device.
    // Conflicting providers are ambiguous evidence, never a selector fallback.
    let device_serial = reader.optional(&disk.join("device/serial"))?;
    let disk_serial = reader.optional(&disk.join("serial"))?;
    if let (Some(device), Some(disk_value)) = (&device_serial, &disk_serial)
        && device != disk_value
    {
        return Err(invalid(
            disk,
            "conflicting disk/device serial observations",
        ));
    }
    Ok(device_serial.or(disk_serial))
}

fn properties<'a>(text: &'a str, path: &Path) -> Result<BTreeMap<&'a str, &'a str>> {
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| invalid(path, "malformed uevent field"))?;
        if result.insert(key, value).is_some() {
            return Err(invalid(path, "duplicate uevent field"));
        }
    }
    Ok(result)
}

fn parse_number(text: &str, path: &Path) -> Result<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(
            path,
            "expected an unsigned decimal integer",
        ));
    }
    text.parse()
        .map_err(|_| invalid(path, "unsigned integer overflow"))
}

fn sector_bytes(sectors: u64, path: &Path) -> Result<u64> {
    sectors
        .checked_mul(SECTOR_BYTES)
        .ok_or_else(|| invalid(path, "sector count overflows byte capacity"))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-!".contains(&byte))
}

fn valid_boot_id(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

fn is_directory(path: &Path) -> Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error(path, source)),
    }
}

fn invalid(path: &Path, reason: &'static str) -> InventoryError {
    InventoryError::Invalid {
        path: path.to_owned(),
        reason,
    }
}

fn io_error(path: &Path, source: io::Error) -> InventoryError {
    InventoryError::Io {
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests;

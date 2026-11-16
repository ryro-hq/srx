//! Deterministic GPT RAW images from explicitly identified partition streams.
//!
//! This library opens no paths or devices. It follows UEFI's GPT 1.0 layout:
//! <https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html>.
//! A valid image is not evidence of a filesystem, firmware boot or installation.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt, io};

mod format;
mod writer;
pub use writer::{PartitionReader, WrittenDisk};

const ENTRIES: usize = 128;
const ENTRY_BYTES: usize = 128;
const TABLE_BYTES: usize = ENTRIES * ENTRY_BYTES;

/// UUID bytes in canonical textual order, not GPT's mixed-endian wire order.
/// Zero is representable but refused for active disk/partition identities/types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Guid(pub [u8; 16]);

impl fmt::Display for Guid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if [4, 6, 8, 10].contains(&index) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Partition {
    /// GPT entry number, 1 through 128; independent of physical ordering.
    pub number: u32,
    pub partition_type: Guid,
    pub guid: Guid,
    pub start_bytes: u64,
    pub size_bytes: u64,
    /// At most 35 UTF-16 code units, followed by an explicit zero terminator.
    pub name: String,
    /// UEFI bits 0..2 and type-specific bits 48..63; reserved bits must be zero.
    pub attributes: u64,
    /// Exact payload length; the rest of this partition is filled with zeros.
    pub image_bytes: u64,
    pub image_sha256: [u8; 32],
}

/// An unchecked request. Deserialization confers no layout or write authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskSpec {
    pub bytes: u64,
    pub logical_block_bytes: u32,
    pub guid: Guid,
    pub partitions: Vec<Partition>,
}

/// Validated geometry, with GPT entries ordered by their explicit numbers.
/// It cannot be deserialized or modified without another validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskLayout {
    spec: DiskSpec,
    first_usable: u64,
    last_usable: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    #[error("invalid GPT image layout: {0}")]
    Layout(&'static str),
    #[error("RAW image exceeds the admitted {0} budget")]
    Budget(&'static str),
    #[error("partition {0} does not match its declared length and SHA-256")]
    Content(u32),
    #[error("RAW image operation cancelled")]
    Cancelled,
    #[error("RAW image exceeded its duration budget")]
    Deadline,
    #[error("RAW image I/O failed: {0}")]
    Io(#[from] io::Error),
}

impl DiskSpec {
    pub fn validate(mut self) -> Result<DiskLayout, DiskError> {
        let block = u64::from(self.logical_block_bytes);
        if !matches!(block, 512 | 4096) || !self.bytes.is_multiple_of(block) {
            return Err(DiskError::Layout(
                "512/4096-byte logical blocks and a whole-block disk are required",
            ));
        }
        if self.guid.0 == [0; 16] || self.partitions.is_empty() || self.partitions.len() > ENTRIES {
            return Err(DiskError::Layout(
                "a nonzero disk GUID and 1..128 partitions are required",
            ));
        }
        let table_blocks = TABLE_BYTES as u64 / block;
        let first_usable = 2 + table_blocks;
        let last_usable = (self.bytes / block)
            .checked_sub(table_blocks + 2)
            .filter(|last| *last >= first_usable)
            .ok_or(DiskError::Layout(
                "disk cannot hold both GPT copies and a usable block",
            ))?;
        self.partitions
            .sort_by_key(|partition| partition.number);
        let mut identities = BTreeSet::from([self.guid]);
        let mut previous_number = 0;
        let mut extents = Vec::with_capacity(self.partitions.len());
        for partition in &self.partitions {
            if partition.number <= previous_number || u64::from(partition.number) > ENTRIES as u64 {
                return Err(DiskError::Layout(
                    "GPT entry numbers must be distinct and within 1..128",
                ));
            }
            previous_number = partition.number;
            if partition.partition_type.0 == [0; 16]
                || partition.guid.0 == [0; 16]
                || !identities.insert(partition.guid)
            {
                return Err(DiskError::Layout(
                    "active GUIDs must be nonzero and disk/partition identities distinct",
                ));
            }
            if partition.name.len() > 140
                || partition.name.chars().any(char::is_control)
                || partition.name.encode_utf16().count() > 35
                || partition.attributes & 0x0000_ffff_ffff_fff8 != 0
            {
                return Err(DiskError::Layout(
                    "invalid partition name or reserved attribute bits",
                ));
            }
            let end = partition
                .start_bytes
                .checked_add(partition.size_bytes)
                .ok_or(DiskError::Layout("partition extent overflow"))?;
            if partition.size_bytes == 0
                || !partition.start_bytes.is_multiple_of(block)
                || !partition.size_bytes.is_multiple_of(block)
                || partition.start_bytes / block < first_usable
                || end / block > last_usable + 1
                || partition.image_bytes > partition.size_bytes
            {
                return Err(DiskError::Layout(
                    "partition must be aligned, within usable LBAs and contain its image",
                ));
            }
            extents.push((partition.start_bytes, end));
        }
        extents.sort_unstable();
        if extents
            .windows(2)
            .any(|pair| pair[0].1 > pair[1].0)
        {
            return Err(DiskError::Layout("partition extents overlap"));
        }
        Ok(DiskLayout {
            spec: self,
            first_usable,
            last_usable,
        })
    }
}

impl DiskLayout {
    pub const fn specification(&self) -> &DiskSpec {
        &self.spec
    }
    pub const fn first_usable_lba(&self) -> u64 {
        self.first_usable
    }
    pub const fn last_usable_lba(&self) -> u64 {
        self.last_usable
    }
}

#[cfg(test)]
mod tests;

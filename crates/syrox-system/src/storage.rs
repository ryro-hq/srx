//! Pure validation and target binding for the initial provisioning storage graph.
//!
//! The result is a plan, not device authority. Capacity accounting here establishes
//! declared bounds; tool-specific metadata, exclusive-use checks and actual opened
//! devices must be verified by the provisioner before any destructive operation.

use crate::inventory::{BlockDevice, SystemInventory};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_NODES: usize = 4096;
const ALIGNMENT: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskSelector {
    pub wwid: Option<String>,
    pub serial: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionKind {
    Esp,
    LinuxData,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RaidLevel {
    Raid1,
    Raid10,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemKind {
    Ext4,
    Fat32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Resource {
    Disk {
        selector: DiskSelector,
    },
    Partition {
        disk: String,
        start_bytes: u64,
        size_bytes: u64,
        partition_kind: PartitionKind,
    },
    Raid {
        members: Vec<String>,
        level: RaidLevel,
        usable_bytes: u64,
    },
    Luks2 {
        source: String,
        credential: String,
        usable_bytes: u64,
    },
    VolumeGroup {
        sources: Vec<String>,
        usable_bytes: u64,
    },
    LogicalVolume {
        group: String,
        size_bytes: u64,
    },
    Filesystem {
        source: String,
        filesystem: FilesystemKind,
    },
    Mount {
        filesystem: String,
        target: String,
        read_only: bool,
    },
}

impl Resource {
    fn references(&self) -> Vec<&str> {
        match self {
            Self::Disk {
                ..
            } => vec![],
            Self::Partition {
                disk,
                ..
            } => vec![disk],
            Self::Raid {
                members,
                ..
            } => members.iter().map(String::as_str).collect(),
            Self::Luks2 {
                source,
                ..
            }
            | Self::Filesystem {
                source,
                ..
            } => vec![source],
            Self::VolumeGroup {
                sources,
                ..
            } => sources.iter().map(String::as_str).collect(),
            Self::LogicalVolume {
                group,
                ..
            } => vec![group],
            Self::Mount {
                filesystem,
                ..
            } => vec![filesystem],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageNode {
    pub id: String,
    pub resource: Resource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageLayout {
    pub nodes: Vec<StorageNode>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("storage observation cannot be encoded: {0}")]
    Evidence(String),
    #[error("storage layout must contain 1..={MAX_NODES} uniquely named nodes")]
    NodeSet,
    #[error("storage node {node} references unknown resource {target}")]
    Reference {
        node: String,
        target: String,
    },
    #[error("storage graph contains a cycle involving {0}")]
    Cycle(String),
    #[error("storage node {node} has an unsupported or conflicting composition: {reason}")]
    Composition {
        node: String,
        reason: &'static str,
    },
    #[error("storage node {node} has insufficient or invalid capacity: {reason}")]
    Capacity {
        node: String,
        reason: &'static str,
    },
    #[error("disk selector for {0} must declare a nonempty WWID or serial")]
    Selector(String),
    #[error("no observed disk matches storage node {0}")]
    MissingDisk(String),
    #[error("more than one observed disk matches storage node {0}")]
    AmbiguousDisk(String),
    #[error("physical disk {0} was selected more than once")]
    DuplicateDisk(String),
    #[error("disk {0} is read-only")]
    ReadOnly(String),
    #[error("disk {disk} has an observed active resource {resource}")]
    InUse {
        disk: String,
        resource: String,
    },
    #[error("partitions {first} and {second} overlap")]
    Overlap {
        first: String,
        second: String,
    },
    #[error("mount target {0} is invalid or duplicated")]
    MountTarget(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiskBinding {
    pub node: String,
    pub observed: BlockDevice,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlannedStorageNode {
    pub id: String,
    pub capacity_bytes: u64,
    pub resource: Resource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StoragePlan {
    pub inventory_fingerprint: String,
    /// Dependencies precede users, deterministically ordered by resource id.
    pub nodes: Vec<PlannedStorageNode>,
    pub disks: Vec<DiskBinding>,
    /// Only references are included; secret values never enter the graph.
    pub credentials: Vec<String>,
}

impl StorageLayout {
    pub fn plan(&self, inventory: &SystemInventory) -> Result<StoragePlan, StorageError> {
        let mut disks = Vec::new();
        let mut selected = BTreeSet::new();
        let (nodes, credentials) = self.analyze(|id, selector| {
            let disk = resolve_disk(id, selector, inventory)?;
            if !selected.insert(disk.number) {
                return Err(StorageError::DuplicateDisk(disk.name.clone()));
            }
            if disk.read_only {
                return Err(StorageError::ReadOnly(disk.name.clone()));
            }
            reject_observed_use(disk, inventory)?;
            disks.push(DiskBinding {
                node: id.into(),
                observed: disk.clone(),
            });
            Ok(disk.capacity_bytes)
        })?;
        Ok(StoragePlan {
            inventory_fingerprint: inventory
                .fingerprint()
                .map_err(|error| StorageError::Evidence(error.to_string()))?,
            nodes,
            disks,
            credentials,
        })
    }

    /// Check declared graph semantics without consulting a machine. This cannot
    /// establish disk existence, uniqueness, capacity or exclusive availability;
    /// `plan` must still bind and verify real inventory before provisioning.
    pub fn validate_structure(&self) -> Result<(), StorageError> {
        self.analyze(|id, selector| {
            validate_selector(id, selector)?;
            Ok(u64::MAX)
        })?;
        Ok(())
    }

    fn analyze(
        &self,
        mut disk_capacity: impl FnMut(&str, &DiskSelector) -> Result<u64, StorageError>,
    ) -> Result<(Vec<PlannedStorageNode>, Vec<String>), StorageError> {
        let index = self.index()?;
        let order = topological(&index)?;
        let mut capacities = BTreeMap::new();
        let mut credentials = BTreeSet::new();
        let mut consumers = BTreeMap::new();
        let mut partitions: BTreeMap<&str, Vec<(u64, u64, &str)>> = BTreeMap::new();
        let mut volumes: BTreeMap<&str, u64> = BTreeMap::new();
        let mut mount_targets = BTreeSet::new();
        let mut nodes = Vec::new();
        for id in order {
            let resource = &index[id].resource;
            let composition = |reason| StorageError::Composition {
                node: id.into(),
                reason,
            };
            let capacity = |reason| StorageError::Capacity {
                node: id.into(),
                reason,
            };
            for dependency in resource.references() {
                if !matches!(
                    resource,
                    Resource::Partition { .. } | Resource::LogicalVolume { .. }
                ) && consumers.insert(dependency, id).is_some()
                {
                    return Err(composition(
                        "a block resource cannot have multiple independent consumers",
                    ));
                }
            }
            let size = match resource {
                Resource::Disk {
                    selector,
                } => disk_capacity(id, selector)?,
                Resource::Partition {
                    disk,
                    start_bytes,
                    size_bytes,
                    partition_kind,
                } => {
                    if !matches!(
                        index[disk.as_str()].resource,
                        Resource::Disk { .. }
                    ) {
                        return Err(composition("GPT partitions require a disk"));
                    }
                    if *start_bytes < ALIGNMENT
                        || *start_bytes % ALIGNMENT != 0
                        || *size_bytes == 0
                        || *size_bytes % ALIGNMENT != 0
                    {
                        return Err(capacity(
                            "GPT data regions require positive 1 MiB alignment and leading metadata space",
                        ));
                    }
                    let end = start_bytes
                        .checked_add(*size_bytes)
                        .ok_or_else(|| capacity("partition extent overflow"))?;
                    if end
                        .checked_add(ALIGNMENT)
                        .is_none_or(|bound| bound > capacities[disk.as_str()])
                    {
                        return Err(capacity(
                            "partition exceeds disk capacity or trailing GPT reserve",
                        ));
                    }
                    if *partition_kind == PartitionKind::Esp && *size_bytes < 64 * ALIGNMENT {
                        return Err(capacity(
                            "the initial ESP profile requires at least 64 MiB",
                        ));
                    }
                    partitions
                        .entry(disk)
                        .or_default()
                        .push((*start_bytes, end, id));
                    *size_bytes
                }
                Resource::Raid {
                    members,
                    level,
                    usable_bytes,
                } => {
                    let expected = match level {
                        RaidLevel::Raid1 => 2,
                        RaidLevel::Raid10 => 4,
                    };
                    if members.len() != expected
                        || members.iter().collect::<BTreeSet<_>>().len() != expected
                    {
                        return Err(composition(
                            "RAID1 needs two distinct members and RAID10 needs four",
                        ));
                    }
                    if members.iter().any(|member| {
                        !matches!(
                            index[member.as_str()].resource,
                            Resource::Partition {
                                partition_kind: PartitionKind::LinuxData,
                                ..
                            }
                        )
                    }) {
                        return Err(composition(
                            "initial RAID members must be GPT Linux-data partitions",
                        ));
                    }
                    let parent_disks: BTreeSet<_> = members
                        .iter()
                        .map(|member| {
                            let Resource::Partition {
                                disk,
                                ..
                            } = &index[member.as_str()].resource
                            else {
                                unreachable!("validated partition members")
                            };
                            disk
                        })
                        .collect();
                    if parent_disks.len() != expected {
                        return Err(composition(
                            "RAID members must reside on distinct physical disks",
                        ));
                    }
                    let minimum = members
                        .iter()
                        .map(|member| capacities[member.as_str()])
                        .min()
                        .expect("validated member count");
                    let bound = minimum
                        .checked_mul(match level {
                            RaidLevel::Raid1 => 1,
                            RaidLevel::Raid10 => 2,
                        })
                        .ok_or_else(|| capacity("RAID capacity overflow"))?;
                    check_usable(*usable_bytes, bound).map_err(capacity)?;
                    *usable_bytes
                }
                Resource::Luks2 {
                    source,
                    credential,
                    usable_bytes,
                } => {
                    if !data_source(&index[source.as_str()].resource) {
                        return Err(composition(
                            "LUKS2 requires a data partition or RAID",
                        ));
                    }
                    if !valid_id(credential) {
                        return Err(composition(
                            "credential must be a bounded reference name",
                        ));
                    }
                    credentials.insert(credential.clone());
                    check_usable(*usable_bytes, capacities[source.as_str()]).map_err(capacity)?;
                    *usable_bytes
                }
                Resource::VolumeGroup {
                    sources,
                    usable_bytes,
                } => {
                    if sources.is_empty()
                        || sources.len() > 64
                        || sources.iter().collect::<BTreeSet<_>>().len() != sources.len()
                    {
                        return Err(composition(
                            "volume groups require 1..=64 distinct physical volumes",
                        ));
                    }
                    let mut bound = 0_u64;
                    for source in sources {
                        if !data_source(&index[source.as_str()].resource)
                            && !matches!(
                                index[source.as_str()].resource,
                                Resource::Luks2 { .. }
                            )
                        {
                            return Err(composition(
                                "physical volumes require data partitions, RAID or LUKS2",
                            ));
                        }
                        bound = bound
                            .checked_add(capacities[source.as_str()])
                            .ok_or_else(|| capacity("volume group capacity overflow"))?;
                    }
                    check_usable(*usable_bytes, bound).map_err(capacity)?;
                    *usable_bytes
                }
                Resource::LogicalVolume {
                    group,
                    size_bytes,
                } => {
                    if !matches!(
                        index[group.as_str()].resource,
                        Resource::VolumeGroup { .. }
                    ) {
                        return Err(composition(
                            "logical volumes require a volume group",
                        ));
                    }
                    if *size_bytes == 0 || *size_bytes % ALIGNMENT != 0 {
                        return Err(capacity(
                            "logical volumes require a positive size aligned to 1 MiB",
                        ));
                    }
                    let assigned = volumes.entry(group).or_default();
                    *assigned = assigned
                        .checked_add(*size_bytes)
                        .ok_or_else(|| capacity("logical volume capacity overflow"))?;
                    if *assigned > capacities[group.as_str()] {
                        return Err(capacity(
                            "logical volumes overcommit their volume group",
                        ));
                    }
                    *size_bytes
                }
                Resource::Filesystem {
                    source,
                    filesystem,
                } => {
                    let parent = &index[source.as_str()].resource;
                    let is_esp = matches!(
                        parent,
                        Resource::Partition {
                            partition_kind: PartitionKind::Esp,
                            ..
                        }
                    );
                    if (*filesystem == FilesystemKind::Fat32) != is_esp {
                        return Err(composition(
                            "ESP requires FAT32; initial data filesystems require ext4",
                        ));
                    }
                    if !matches!(
                        parent,
                        Resource::Partition { .. }
                            | Resource::Raid { .. }
                            | Resource::Luks2 { .. }
                            | Resource::LogicalVolume { .. }
                    ) {
                        return Err(composition(
                            "filesystem requires a supported block volume",
                        ));
                    }
                    capacities[source.as_str()]
                }
                Resource::Mount {
                    filesystem,
                    target,
                    ..
                } => {
                    if !matches!(
                        index[filesystem.as_str()].resource,
                        Resource::Filesystem { .. }
                    ) {
                        return Err(composition("mount requires a filesystem"));
                    }
                    if !valid_mount(target) || !mount_targets.insert(target.as_str()) {
                        return Err(StorageError::MountTarget(target.clone()));
                    }
                    capacities[filesystem.as_str()]
                }
            };
            capacities.insert(id, size);
            nodes.push(PlannedStorageNode {
                id: id.into(),
                capacity_bytes: size,
                resource: resource.clone(),
            });
        }
        for extents in partitions.values_mut() {
            extents.sort_unstable();
            for pair in extents.windows(2) {
                if pair[0].1 > pair[1].0 {
                    return Err(StorageError::Overlap {
                        first: pair[0].2.into(),
                        second: pair[1].2.into(),
                    });
                }
            }
        }
        Ok((nodes, credentials.into_iter().collect()))
    }

    fn index(&self) -> Result<BTreeMap<&str, &StorageNode>, StorageError> {
        if self.nodes.is_empty() || self.nodes.len() > MAX_NODES {
            return Err(StorageError::NodeSet);
        }
        let mut index = BTreeMap::new();
        for node in &self.nodes {
            if !valid_id(&node.id) || index.insert(node.id.as_str(), node).is_some() {
                return Err(StorageError::NodeSet);
            }
        }
        for node in &self.nodes {
            let references = node.resource.references();
            if references.len() > 64 {
                return Err(StorageError::Composition {
                    node: node.id.clone(),
                    reason: "too many resource references",
                });
            }
            for target in references {
                if !index.contains_key(target) {
                    return Err(StorageError::Reference {
                        node: node.id.clone(),
                        target: target.into(),
                    });
                }
            }
        }
        Ok(index)
    }
}

fn topological<'a>(
    index: &BTreeMap<&'a str, &'a StorageNode>,
) -> Result<Vec<&'a str>, StorageError> {
    let mut pending = BTreeMap::new();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut ready = BTreeSet::new();
    for (id, node) in index {
        let references = node.resource.references();
        pending.insert(*id, references.len());
        if references.is_empty() {
            ready.insert(*id);
        }
        for reference in references {
            dependents.entry(reference).or_default().push(*id);
        }
    }
    let mut result = Vec::new();
    while let Some(id) = ready.pop_first() {
        result.push(id);
        for dependent in dependents.get(id).into_iter().flatten() {
            let count = pending
                .get_mut(dependent)
                .expect("validated dependency");
            *count -= 1;
            if *count == 0 {
                ready.insert(dependent);
            }
        }
    }
    if result.len() != index.len() {
        return Err(StorageError::Cycle(
            pending
                .into_iter()
                .find(|(_, count)| *count != 0)
                .expect("unfinished graph")
                .0
                .into(),
        ));
    }
    Ok(result)
}

fn validate_selector(id: &str, selector: &DiskSelector) -> Result<(), StorageError> {
    if (selector.wwid.is_none() && selector.serial.is_none())
        || selector
            .wwid
            .iter()
            .chain(&selector.serial)
            .any(|value| {
                value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control)
            })
    {
        return Err(StorageError::Selector(id.into()));
    }
    Ok(())
}

fn resolve_disk<'a>(
    id: &str,
    selector: &DiskSelector,
    inventory: &'a SystemInventory,
) -> Result<&'a BlockDevice, StorageError> {
    validate_selector(id, selector)?;
    let mut matches = inventory.devices.iter().filter(|device| {
        device.partition.is_none()
            && selector
                .wwid
                .as_ref()
                .is_none_or(|value| device.identity.wwid.as_ref() == Some(value))
            && selector
                .serial
                .as_ref()
                .is_none_or(|value| device.identity.serial.as_ref() == Some(value))
    });
    let disk = matches
        .next()
        .ok_or_else(|| StorageError::MissingDisk(id.into()))?;
    if matches.next().is_some() {
        return Err(StorageError::AmbiguousDisk(id.into()));
    }
    Ok(disk)
}

fn reject_observed_use(
    disk: &BlockDevice,
    inventory: &SystemInventory,
) -> Result<(), StorageError> {
    let mut visited = BTreeSet::new();
    let mut pending = VecDeque::from([disk.number]);
    while let Some(number) = pending.pop_front() {
        if !visited.insert(number) {
            continue;
        }
        if let Some(mount) = inventory
            .mounts
            .iter()
            .find(|mount| mount.device == number)
        {
            return Err(StorageError::InUse {
                disk: disk.name.clone(),
                resource: format!("mount {} at {:?}", mount.id, mount.target),
            });
        }
        for device in &inventory.devices {
            if device.number == number && !device.holders.is_empty() {
                return Err(StorageError::InUse {
                    disk: disk.name.clone(),
                    resource: format!("holders {:?}", device.holders),
                });
            }
            if device
                .partition
                .as_ref()
                .is_some_and(|partition| partition.parent == number)
            {
                pending.push_back(device.number);
            }
        }
    }
    Ok(())
}

fn check_usable(requested: u64, bound: u64) -> Result<(), &'static str> {
    if requested == 0 || !requested.is_multiple_of(ALIGNMENT) || requested >= bound {
        Err(
            "usable capacity must be positive, 1 MiB aligned and leave metadata headroom below its backing bound",
        )
    } else {
        Ok(())
    }
}

fn data_source(resource: &Resource) -> bool {
    matches!(
        resource,
        Resource::Partition {
            partition_kind: PartitionKind::LinuxData,
            ..
        } | Resource::Raid { .. }
    )
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

fn valid_mount(target: &str) -> bool {
    target == "/"
        || (target.starts_with('/')
            && target.len() <= 4096
            && target[1..].split('/').all(|component| {
                !component.is_empty()
                    && !matches!(component, "." | "..")
                    && !component.chars().any(char::is_control)
            }))
}

#[cfg(test)]
mod tests;

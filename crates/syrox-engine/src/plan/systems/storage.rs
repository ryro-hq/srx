use super::{
    BTreeSet, Decoder, FilesystemKind, PlanDataCompatibility, PlanError, PlanPersistentVolume,
    StorageLayout, Value, absolute, name,
};
use crate::system::storage::{DiskSelector, PartitionKind, RaidLevel, Resource, StorageNode};

pub(super) struct StorageSelection {
    pub(super) layout: StorageLayout,
    pub(super) root_a: String,
    pub(super) root_b: String,
    pub(super) esp: Vec<String>,
    pub(super) persistent: Vec<PlanPersistentVolume>,
}

impl Decoder<'_, '_> {
    pub(super) fn filesystem(&mut self, value: &Value) -> Result<FilesystemKind, PlanError> {
        match self.variant(value, "FilesystemKind")? {
            (0, []) => Ok(FilesystemKind::Ext4),
            (1, []) => Ok(FilesystemKind::Fat32),
            _ => Err(self.error("filesystem", "unsupported filesystem kind")),
        }
    }
    fn storage_resource(&mut self, value: &Value) -> Result<Resource, PlanError> {
        Ok(match self.variant(value, "StorageResource")? {
            (0, [value]) => {
                let disk = self.fields(value, "DiskResource", &["selector"])?;
                let fields = self.fields(&disk[0].1, "DiskSelector", &["wwid", "serial"])?;
                Resource::Disk {
                    selector: DiskSelector {
                        wwid: self
                            .optional(&fields[0].1)?
                            .map(|value| self.string(value, "SystemText"))
                            .transpose()?,
                        serial: self
                            .optional(&fields[1].1)?
                            .map(|value| self.string(value, "SystemText"))
                            .transpose()?,
                    },
                }
            }
            (1, [value]) => {
                let fields = self.fields(
                    value,
                    "PartitionResource",
                    &[
                        "disk",
                        "start_bytes",
                        "size_bytes",
                        "partition_kind",
                    ],
                )?;
                Resource::Partition {
                    disk: self.string(&fields[0].1, "StorageNodeId")?,
                    start_bytes: self.number(&fields[1].1, "SystemBytes")?,
                    size_bytes: self.number(&fields[2].1, "SystemBytes")?,
                    partition_kind: match self.variant(&fields[3].1, "PartitionKind")? {
                        (0, []) => PartitionKind::Esp,
                        (1, []) => PartitionKind::LinuxData,
                        _ => return Err(self.error("partition", "unsupported partition kind")),
                    },
                }
            }
            (2, [value]) => {
                let fields = self.fields(
                    value,
                    "RaidResource",
                    &["members", "level", "usable_bytes"],
                )?;
                Resource::Raid {
                    members: self.node_ids(&fields[0].1)?,
                    level: match self.variant(&fields[1].1, "RaidLevel")? {
                        (0, []) => RaidLevel::Raid1,
                        (1, []) => RaidLevel::Raid10,
                        _ => return Err(self.error("raid", "unsupported RAID level")),
                    },
                    usable_bytes: self.number(&fields[2].1, "SystemBytes")?,
                }
            }
            (3, [value]) => {
                let fields = self.fields(
                    value,
                    "Luks2Resource",
                    &["source", "credential", "usable_bytes"],
                )?;
                Resource::Luks2 {
                    source: self.string(&fields[0].1, "StorageNodeId")?,
                    credential: self.string(&fields[1].1, "CredentialReference")?,
                    usable_bytes: self.number(&fields[2].1, "SystemBytes")?,
                }
            }
            (4, [value]) => {
                let fields = self.fields(
                    value,
                    "VolumeGroupResource",
                    &["sources", "usable_bytes"],
                )?;
                Resource::VolumeGroup {
                    sources: self.node_ids(&fields[0].1)?,
                    usable_bytes: self.number(&fields[1].1, "SystemBytes")?,
                }
            }
            (5, [value]) => {
                let fields = self.fields(
                    value,
                    "LogicalVolumeResource",
                    &["group", "size_bytes"],
                )?;
                Resource::LogicalVolume {
                    group: self.string(&fields[0].1, "StorageNodeId")?,
                    size_bytes: self.number(&fields[1].1, "SystemBytes")?,
                }
            }
            (6, [value]) => {
                let fields = self.fields(
                    value,
                    "FilesystemResource",
                    &["source", "filesystem"],
                )?;
                Resource::Filesystem {
                    source: self.string(&fields[0].1, "StorageNodeId")?,
                    filesystem: self.filesystem(&fields[1].1)?,
                }
            }
            (7, [value]) => {
                let fields = self.fields(
                    value,
                    "MountResource",
                    &["filesystem", "target", "read_only"],
                )?;
                Resource::Mount {
                    filesystem: self.string(&fields[0].1, "StorageNodeId")?,
                    target: self.string(&fields[1].1, "SystemPath")?,
                    read_only: self.boolean(&fields[2].1)?,
                }
            }
            _ => return Err(self.error("storage", "unsupported resource")),
        })
    }
    pub(super) fn node_ids(&mut self, value: &Value) -> Result<Vec<String>, PlanError> {
        let values = self.list(value, "storage.references", 64)?;
        let mut result = self.budget.collection::<String>(values.len())?;
        for value in values {
            result.push(self.string(value, "StorageNodeId")?);
        }
        Ok(result)
    }
    pub(super) fn storage(&mut self, value: &Value) -> Result<StorageSelection, PlanError> {
        let fields = self.fields(
            value,
            "SystemStorage",
            &[
                "nodes",
                "esp",
                "root_a",
                "root_b",
                "persistent",
            ],
        )?;
        let values = self.list(&fields[0].1, "storage.nodes", 4096)?;
        let mut nodes = self
            .budget
            .collection::<StorageNode>(values.len())?;
        for value in values {
            let fields = self.fields(value, "StorageNode", &["id", "device"])?;
            nodes.push(StorageNode {
                id: self.string(&fields[0].1, "StorageNodeId")?,
                resource: self.storage_resource(&fields[1].1)?,
            });
        }
        let storage = StorageLayout {
            nodes,
        };
        storage
            .validate_structure()
            .map_err(|error| self.error("storage", error.to_string()))?;
        let root_a = self.string(&fields[2].1, "StorageNodeId")?;
        let root_b = self.string(&fields[3].1, "StorageNodeId")?;
        let is_fs = |id: &str, kind| {
            storage.nodes.iter().any(|node| node.id == id && matches!(node.resource, Resource::Filesystem { filesystem, .. } if filesystem == kind))
        };
        if root_a == root_b
            || !is_fs(&root_a, FilesystemKind::Ext4)
            || !is_fs(&root_b, FilesystemKind::Ext4)
        {
            return Err(self.error(
                "storage.roots",
                "A/B roots must be distinct declared ext4 filesystems",
            ));
        }
        let esp = self.node_ids(&fields[1].1)?;
        if esp.is_empty()
            || esp.iter().collect::<BTreeSet<_>>().len() != esp.len()
            || esp
                .iter()
                .any(|id| !is_fs(id, FilesystemKind::Fat32))
        {
            return Err(self.error(
                "storage.esp",
                "expected distinct declared ESP filesystems",
            ));
        }
        let mut targets = BTreeSet::new();
        let mut filesystems = BTreeSet::new();
        let values = self.list(&fields[4].1, "storage.persistent", 4096)?;
        let mut persistent = self
            .budget
            .collection::<PlanPersistentVolume>(values.len())?;
        for volume in values {
            let fields = self.fields(
                volume,
                "PersistentVolume",
                &["filesystem", "target", "compatibility"],
            )?;
            let filesystem = self.string(&fields[0].1, "StorageNodeId")?;
            let target = self.string(&fields[1].1, "SystemPath")?;
            if !is_fs(&filesystem, FilesystemKind::Ext4)
                || filesystem == root_a
                || filesystem == root_b
                || !filesystems.insert(filesystem.clone())
                || !absolute(&target)
                || target == "/"
                || [
                    "/usr",
                    "/etc",
                    "/boot",
                    "/bin",
                    "/sbin",
                    "/lib",
                    "/lib64",
                    "/syrox/store",
                    "/syrox/generations",
                ]
                .iter()
                .any(|prefix| {
                    target == *prefix
                        || target
                            .strip_prefix(prefix)
                            .is_some_and(|rest| rest.starts_with('/'))
                })
                || !targets.insert(target.clone())
            {
                return Err(self.error(
                    "storage.persistent",
                    "invalid or conflicting persistent filesystem/target",
                ));
            }
            let compatibility = match self.variant(&fields[2].1, "DataCompatibility")? {
                (0, []) => PlanDataCompatibility::Shared,
                (1, [value]) => {
                    let compatibility = self.string(value, "SystemName")?;
                    if !name(&compatibility) {
                        return Err(self.error(
                            "storage.persistent",
                            "invalid compatibility identity",
                        ));
                    }
                    PlanDataCompatibility::Versioned(compatibility)
                }
                _ => {
                    return Err(self.error(
                        "storage.persistent",
                        "invalid compatibility policy",
                    ));
                }
            };
            persistent.push(PlanPersistentVolume {
                filesystem,
                target,
                compatibility,
            });
        }
        Ok(StorageSelection {
            layout: storage,
            root_a,
            root_b,
            esp,
            persistent,
        })
    }
}

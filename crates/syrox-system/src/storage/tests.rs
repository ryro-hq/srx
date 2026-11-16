use super::*;
use crate::inventory::{DeviceIdentity, DeviceNumber, Mount, Partition};

const MIB: u64 = 1024 * 1024;

fn disk(index: u32) -> BlockDevice {
    BlockDevice {
        name: format!("vd{index}"),
        number: DeviceNumber {
            major: 8,
            minor: index * 16,
        },
        diagnostic_path: format!("/dev/vd{index}").into(),
        sysfs_path: format!("/sys/devices/block/vd{index}").into(),
        device_node_matches: true,
        identity: DeviceIdentity {
            wwid: Some(format!("wwid-{index}")),
            serial: Some(format!("serial-{index}")),
            model: Some("fixture".into()),
            device_mapper_uuid: None,
            partition_uuid: None,
            disk_sequence: Some(u64::from(index) + 1),
        },
        capacity_bytes: 4096 * MIB,
        logical_block_bytes: 512,
        physical_block_bytes: 4096,
        read_only: false,
        removable: false,
        partition: None,
        holders: vec![],
        slaves: vec![],
    }
}

fn inventory(count: u32) -> SystemInventory {
    SystemInventory {
        version: 1,
        inspector_architecture: "x86_64".into(),
        kernel_release: "test".into(),
        boot_id: "11111111-2222-3333-4444-555555555555".into(),
        uefi_present: true,
        kvm_device_present: false,
        devices: (0..count).map(disk).collect(),
        mounts: vec![],
    }
}

fn node(id: &str, resource: Resource) -> StorageNode {
    StorageNode {
        id: id.into(),
        resource,
    }
}

fn disks(count: u32) -> Vec<StorageNode> {
    let mut nodes = Vec::new();
    for index in 0..count {
        nodes.push(node(
            &format!("disk{index}"),
            Resource::Disk {
                selector: DiskSelector {
                    wwid: Some(format!("wwid-{index}")),
                    serial: None,
                },
            },
        ));
        nodes.push(node(
            &format!("esp{index}"),
            Resource::Partition {
                disk: format!("disk{index}"),
                start_bytes: MIB,
                size_bytes: 64 * MIB,
                partition_kind: PartitionKind::Esp,
            },
        ));
        nodes.push(node(
            &format!("data{index}"),
            Resource::Partition {
                disk: format!("disk{index}"),
                start_bytes: 65 * MIB,
                size_bytes: 2048 * MIB,
                partition_kind: PartitionKind::LinuxData,
            },
        ));
        nodes.push(node(
            &format!("bootfs{index}"),
            Resource::Filesystem {
                source: format!("esp{index}"),
                filesystem: FilesystemKind::Fat32,
            },
        ));
    }
    nodes
}

fn plain() -> StorageLayout {
    let mut nodes = disks(1);
    nodes.push(node(
        "rootfs",
        Resource::Filesystem {
            source: "data0".into(),
            filesystem: FilesystemKind::Ext4,
        },
    ));
    nodes.push(node(
        "root",
        Resource::Mount {
            filesystem: "rootfs".into(),
            target: "/".into(),
            read_only: true,
        },
    ));
    nodes.push(node(
        "boot",
        Resource::Mount {
            filesystem: "bootfs0".into(),
            target: "/boot".into(),
            read_only: false,
        },
    ));
    StorageLayout {
        nodes,
    }
}

fn layered(count: u32) -> StorageLayout {
    let mut nodes = disks(count);
    let (source, bound) = if count == 1 {
        ("data0".into(), 2048 * MIB)
    } else {
        let level = match count {
            2 => RaidLevel::Raid1,
            4 => RaidLevel::Raid10,
            _ => panic!("fixture member count"),
        };
        let bound = if count == 2 {
            1900 * MIB
        } else {
            3800 * MIB
        };
        nodes.push(node(
            "raid",
            Resource::Raid {
                members: (0..count)
                    .map(|index| format!("data{index}"))
                    .collect(),
                level,
                usable_bytes: bound,
            },
        ));
        ("raid".into(), bound)
    };
    nodes.push(node(
        "encrypted",
        Resource::Luks2 {
            source,
            credential: "root_unlock".into(),
            usable_bytes: bound - 100 * MIB,
        },
    ));
    nodes.push(node(
        "vg",
        Resource::VolumeGroup {
            sources: vec!["encrypted".into()],
            usable_bytes: bound - 200 * MIB,
        },
    ));
    for slot in ["a", "b"] {
        nodes.push(node(
            &format!("root_{slot}"),
            Resource::LogicalVolume {
                group: "vg".into(),
                size_bytes: 800 * MIB,
            },
        ));
        nodes.push(node(
            &format!("fs_{slot}"),
            Resource::Filesystem {
                source: format!("root_{slot}"),
                filesystem: FilesystemKind::Ext4,
            },
        ));
    }
    StorageLayout {
        nodes,
    }
}

#[test]
fn disk_and_required_encrypted_raid_stacks_validate_without_effects() {
    let single = plain().plan(&inventory(1)).unwrap();
    assert_eq!(single.disks.len(), 1);
    assert!(single.credentials.is_empty());
    for count in [1, 2, 4] {
        let plan = layered(count).plan(&inventory(count)).unwrap();
        assert_eq!(u32::try_from(plan.disks.len()).unwrap(), count);
        assert_eq!(plan.credentials, ["root_unlock"]);
        assert_eq!(
            plan.inventory_fingerprint,
            inventory(count).fingerprint().unwrap()
        );
        assert_eq!(
            plan.nodes
                .iter()
                .find(|node| node.id == "fs_b")
                .unwrap()
                .capacity_bytes,
            800 * MIB
        );
        let positions: BTreeMap<_, _> = plan
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.id.as_str(), index))
            .collect();
        for node in &plan.nodes {
            for reference in node.resource.references() {
                assert!(positions[reference] < positions[node.id.as_str()]);
            }
        }
    }
}

#[test]
fn declaration_validation_needs_no_inventory_and_does_not_claim_observed_capacity() {
    for layout in [
        plain(),
        layered(1),
        layered(2),
        layered(4),
    ] {
        layout.validate_structure().unwrap();
        assert!(matches!(
            layout.plan(&inventory(0)),
            Err(StorageError::MissingDisk(_))
        ));
    }
    let mut small = inventory(1);
    small.devices[0].capacity_bytes = 64 * MIB;
    assert!(matches!(
        plain().plan(&small),
        Err(StorageError::Capacity { .. })
    ));
    let mut missing = plain();
    missing.nodes.push(node(
        "bad",
        Resource::Filesystem {
            source: "missing".into(),
            filesystem: FilesystemKind::Ext4,
        },
    ));
    assert!(matches!(
        missing.validate_structure(),
        Err(StorageError::Reference { .. })
    ));
    let mut overlapping = plain();
    overlapping.nodes.push(node(
        "overlap",
        Resource::Partition {
            disk: "disk0".into(),
            start_bytes: MIB,
            size_bytes: 128 * MIB,
            partition_kind: PartitionKind::LinuxData,
        },
    ));
    assert!(matches!(
        overlapping.validate_structure(),
        Err(StorageError::Overlap { .. })
    ));
}

#[test]
fn declaration_order_does_not_change_the_validated_plan() {
    let mut layout = layered(4);
    let expected = layout.plan(&inventory(4)).unwrap();
    layout.nodes.reverse();
    assert_eq!(layout.plan(&inventory(4)).unwrap(), expected);
}

#[test]
fn unknown_references_cycles_duplicates_and_unsafe_names_fail_before_device_binding() {
    let mut layout = plain();
    layout.nodes.push(node(
        "bad",
        Resource::Filesystem {
            source: "absent".into(),
            filesystem: FilesystemKind::Ext4,
        },
    ));
    assert!(matches!(
        layout.plan(&inventory(0)),
        Err(StorageError::Reference { .. })
    ));
    layout.nodes.pop();
    layout.nodes.push(layout.nodes[0].clone());
    assert_eq!(
        layout.plan(&inventory(0)),
        Err(StorageError::NodeSet)
    );
    let cycle = StorageLayout {
        nodes: vec![
            node(
                "a",
                Resource::Filesystem {
                    source: "b".into(),
                    filesystem: FilesystemKind::Ext4,
                },
            ),
            node(
                "b",
                Resource::Filesystem {
                    source: "a".into(),
                    filesystem: FilesystemKind::Ext4,
                },
            ),
        ],
    };
    assert!(matches!(
        cycle.plan(&inventory(0)),
        Err(StorageError::Cycle(_))
    ));
    let mut invalid = plain();
    invalid.nodes[0].id = "../../disk".into();
    assert_eq!(
        invalid.plan(&inventory(1)),
        Err(StorageError::NodeSet)
    );
}

#[test]
fn selectors_need_identity_and_reject_ambiguity_or_repeated_physical_targets() {
    let mut layout = plain();
    layout.nodes[0].resource = Resource::Disk {
        selector: DiskSelector {
            wwid: None,
            serial: None,
        },
    };
    assert!(matches!(
        layout.plan(&inventory(1)),
        Err(StorageError::Selector(_))
    ));
    assert!(matches!(
        plain().plan(&inventory(0)),
        Err(StorageError::MissingDisk(_))
    ));
    let mut duplicated = inventory(2);
    duplicated.devices[1].identity.wwid = duplicated.devices[0].identity.wwid.clone();
    assert!(matches!(
        plain().plan(&duplicated),
        Err(StorageError::AmbiguousDisk(_))
    ));
    let mut repeated = plain();
    repeated.nodes.push(node(
        "alias",
        Resource::Disk {
            selector: DiskSelector {
                wwid: None,
                serial: Some("serial-0".into()),
            },
        },
    ));
    assert!(matches!(
        repeated.plan(&inventory(1)),
        Err(StorageError::DuplicateDisk(_))
    ));
    let mut renamed = inventory(1);
    renamed.devices[0].name = "renamed-diagnostic".into();
    renamed.devices[0].diagnostic_path = "/dev/other".into();
    assert_eq!(
        plain().plan(&renamed).unwrap().disks[0]
            .observed
            .number,
        disk(0).number
    );
}

#[test]
fn observed_read_only_mounts_and_active_holders_block_provisioning_plans() {
    let mut observed = inventory(1);
    observed.devices[0].read_only = true;
    assert!(matches!(
        plain().plan(&observed),
        Err(StorageError::ReadOnly(_))
    ));
    observed.devices[0].read_only = false;
    let mut partition = disk(0);
    partition.number.minor = 1;
    partition.partition = Some(Partition {
        number: 1,
        parent: disk(0).number,
        start_bytes: MIB,
    });
    observed.devices.push(partition);
    observed.mounts.push(Mount {
        id: 10,
        parent_id: 9,
        device: DeviceNumber {
            major: 8,
            minor: 1,
        },
        root: "/".into(),
        target: "/data".into(),
        filesystem: "ext4".into(),
        source: "/dev/previous-partition".into(),
        read_only: true,
    });
    assert!(matches!(
        plain().plan(&observed),
        Err(StorageError::InUse { .. })
    ));
    observed.mounts.clear();
    observed.devices[1].holders.push("dm-0".into());
    assert!(matches!(
        plain().plan(&observed),
        Err(StorageError::InUse { .. })
    ));
}

#[test]
fn partition_overlap_alignment_and_gpt_reserves_are_checked() {
    let mut layout = plain();
    layout.nodes.push(node(
        "overlap",
        Resource::Partition {
            disk: "disk0".into(),
            start_bytes: 100 * MIB,
            size_bytes: MIB,
            partition_kind: PartitionKind::LinuxData,
        },
    ));
    assert!(matches!(
        layout.plan(&inventory(1)),
        Err(StorageError::Overlap { .. })
    ));
    for (start_bytes, size_bytes) in [
        (0, MIB),
        (MIB + 512, MIB),
        (MIB, 512),
        (4095 * MIB, MIB),
        (u64::MAX - 511, 1024),
    ] {
        let mut invalid = StorageLayout {
            nodes: disks(1),
        };
        invalid.nodes[2].resource = Resource::Partition {
            disk: "disk0".into(),
            start_bytes,
            size_bytes,
            partition_kind: PartitionKind::LinuxData,
        };
        assert!(matches!(
            invalid.plan(&inventory(1)),
            Err(StorageError::Capacity { .. })
        ));
    }
}

#[test]
fn raid_requires_supported_member_counts_and_separate_physical_disks() {
    let mut layout = layered(2);
    let raid = layout
        .nodes
        .iter_mut()
        .find(|node| node.id == "raid")
        .unwrap();
    if let Resource::Raid {
        members,
        ..
    } = &mut raid.resource
    {
        members.pop();
    }
    assert!(matches!(
        layout.plan(&inventory(2)),
        Err(StorageError::Composition { .. })
    ));
    let mut same_disk = layered(2);
    let partition = same_disk
        .nodes
        .iter_mut()
        .find(|node| node.id == "data1")
        .unwrap();
    partition.resource = Resource::Partition {
        disk: "disk0".into(),
        start_bytes: 2200 * MIB,
        size_bytes: 1000 * MIB,
        partition_kind: PartitionKind::LinuxData,
    };
    assert!(matches!(
        same_disk.plan(&inventory(2)),
        Err(StorageError::Composition { .. })
    ));
}

#[test]
fn layer_capacity_headroom_and_volume_group_allocation_cannot_be_overcommitted() {
    for id in ["raid", "encrypted", "vg", "root_a"] {
        let mut layout = layered(2);
        let node = layout
            .nodes
            .iter_mut()
            .find(|node| node.id == id)
            .unwrap();
        match &mut node.resource {
            Resource::Raid {
                usable_bytes,
                ..
            } => *usable_bytes = 2048 * MIB,
            Resource::Luks2 {
                usable_bytes,
                ..
            } => *usable_bytes = 1900 * MIB,
            Resource::VolumeGroup {
                usable_bytes,
                ..
            } => *usable_bytes = 1800 * MIB,
            Resource::LogicalVolume {
                size_bytes,
                ..
            } => *size_bytes = 1000 * MIB,
            _ => unreachable!(),
        }
        assert!(
            matches!(
                layout.plan(&inventory(2)),
                Err(StorageError::Capacity { .. })
            ),
            "{id}"
        );
    }
}

#[test]
fn unsupported_compositions_and_duplicate_consumption_are_rejected() {
    let mut layout = plain();
    layout.nodes.push(node(
        "other_fs",
        Resource::Filesystem {
            source: "data0".into(),
            filesystem: FilesystemKind::Ext4,
        },
    ));
    assert!(matches!(
        layout.plan(&inventory(1)),
        Err(StorageError::Composition { .. })
    ));
    let mut wrong_esp = plain();
    wrong_esp
        .nodes
        .iter_mut()
        .find(|node| node.id == "bootfs0")
        .unwrap()
        .resource = Resource::Filesystem {
        source: "esp0".into(),
        filesystem: FilesystemKind::Ext4,
    };
    assert!(matches!(
        wrong_esp.plan(&inventory(1)),
        Err(StorageError::Composition { .. })
    ));
    let raw_disk = StorageLayout {
        nodes: vec![
            disks(1).remove(0),
            node(
                "filesystem",
                Resource::Filesystem {
                    source: "disk0".into(),
                    filesystem: FilesystemKind::Ext4,
                },
            ),
        ],
    };
    assert!(matches!(
        raw_disk.plan(&inventory(1)),
        Err(StorageError::Composition { .. })
    ));
}

#[test]
fn mount_targets_are_canonical_and_unique_and_credentials_remain_references() {
    for target in [
        "relative", "/a//b", "/a/../b", "/a/", "/a\0b",
    ] {
        let mut layout = plain();
        layout
            .nodes
            .iter_mut()
            .find(|node| node.id == "root")
            .unwrap()
            .resource = Resource::Mount {
            filesystem: "rootfs".into(),
            target: target.into(),
            read_only: true,
        };
        assert!(matches!(
            layout.plan(&inventory(1)),
            Err(StorageError::MountTarget(_))
        ));
    }
    let mut layout = plain();
    layout
        .nodes
        .iter_mut()
        .find(|node| node.id == "boot")
        .unwrap()
        .resource = Resource::Mount {
        filesystem: "bootfs0".into(),
        target: "/".into(),
        read_only: false,
    };
    assert!(matches!(
        layout.plan(&inventory(1)),
        Err(StorageError::MountTarget(_))
    ));
    let mut layout = layered(1);
    if let Resource::Luks2 {
        credential,
        ..
    } = &mut layout
        .nodes
        .iter_mut()
        .find(|node| node.id == "encrypted")
        .unwrap()
        .resource
    {
        *credential = "password=plain text".into();
    }
    assert!(matches!(
        layout.plan(&inventory(1)),
        Err(StorageError::Composition { .. })
    ));
}

#[test]
fn raw_device_paths_are_not_a_disk_selector_contract() {
    assert!(serde_json::from_str::<DiskSelector>(r#"{"path":"/dev/sda"}"#).is_err());
    let layout = layered(4);
    let encoded = serde_json::to_vec(&layout).unwrap();
    assert_eq!(
        serde_json::from_slice::<StorageLayout>(&encoded).unwrap(),
        layout
    );
}

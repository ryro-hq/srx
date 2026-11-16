use super::*;
use std::os::unix::fs::symlink;

struct Fixture {
    directory: tempfile::TempDir,
    roots: Roots,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let roots = Roots {
            sys: directory.path().join("sys"),
            proc: directory.path().join("proc"),
            dev: directory.path().join("dev"),
        };
        fs::create_dir_all(roots.sys.join("class/block")).unwrap();
        fs::create_dir_all(&roots.dev).unwrap();
        let fixture = Self {
            directory,
            roots,
        };
        fixture.write("proc/sys/kernel/osrelease", "6.18.0-test\n");
        fixture.write(
            "proc/sys/kernel/random/boot_id",
            "11111111-2222-3333-4444-555555555555\n",
        );
        fixture.write(
            "proc/self/mountinfo",
            "30 29 8:1 / / rw - ext4 /dev/vda1 rw\n",
        );
        fixture
    }

    fn write(&self, name: &str, value: &str) {
        let path = self.directory.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value).unwrap();
    }

    fn disk(&self, name: &str, number: &str, sectors: u64) -> PathBuf {
        let path = self.roots.sys.join("devices/block").join(name);
        for directory in ["holders", "slaves", "queue", "device"] {
            fs::create_dir_all(path.join(directory)).unwrap();
        }
        for (field, value) in [
            ("dev", number.to_owned()),
            ("size", sectors.to_string()),
            ("ro", "0".into()),
            ("diskseq", "7".into()),
            ("removable", "0".into()),
            ("queue/logical_block_size", "512".into()),
            ("queue/physical_block_size", "4096".into()),
            ("wwid", format!("wwid-{name}")),
            ("device/serial", format!("serial-{name}")),
            ("device/model", "test disk".into()),
        ] {
            fs::write(path.join(field), format!("{value}\n")).unwrap();
        }
        let (major, minor) = number.split_once(':').unwrap();
        fs::write(
            path.join("uevent"),
            format!("MAJOR={major}\nMINOR={minor}\nDEVNAME={name}\nDEVTYPE=disk\nDISKSEQ=7\n"),
        )
        .unwrap();
        symlink(
            &path,
            self.roots.sys.join("class/block").join(name),
        )
        .unwrap();
        path
    }

    fn partition(&self, parent: &Path, name: &str, number: &str, start: u64, size: u64) -> PathBuf {
        let path = parent.join(name);
        fs::create_dir_all(path.join("holders")).unwrap();
        for (field, value) in [
            ("dev", number.to_owned()),
            ("size", size.to_string()),
            ("start", start.to_string()),
            ("ro", "0".into()),
            ("partition", "1".into()),
        ] {
            fs::write(path.join(field), format!("{value}\n")).unwrap();
        }
        let (major, minor) = number.split_once(':').unwrap();
        fs::write(path.join("uevent"), format!("MAJOR={major}\nMINOR={minor}\nDEVNAME={name}\nDEVTYPE=partition\nDISKSEQ=7\nPARTUUID=part-{name}\n")).unwrap();
        symlink(
            &path,
            self.roots.sys.join("class/block").join(name),
        )
        .unwrap();
        path
    }

    fn inspect(&self) -> Result<SystemInventory> {
        inspect_at(&self.roots, &mut || false)
    }
}

#[test]
fn disk_partition_identity_and_mount_observations_are_sorted_and_use_512_byte_sectors() {
    let fixture = Fixture::new();
    let second = fixture.disk("vdb", "8:16", 200_000);
    let first = fixture.disk("vda", "8:0", 100_000);
    fixture.partition(&first, "vda1", "8:1", 2048, 40_000);
    fs::write(first.join("queue/logical_block_size"), "4096\n").unwrap();
    fs::write(
        second.join("device/serial"),
        "  padded serial   \n",
    )
    .unwrap();
    let report = fixture.inspect().unwrap();
    assert_eq!(
        report
            .devices
            .iter()
            .map(|device| device.name.as_str())
            .collect::<Vec<_>>(),
        ["vda", "vda1", "vdb"]
    );
    assert_eq!(report.devices[0].capacity_bytes, 100_000 * 512);
    assert_eq!(report.devices[1].capacity_bytes, 40_000 * 512);
    assert_eq!(report.devices[1].logical_block_bytes, 4096);
    let partition = report.devices[1].partition.as_ref().unwrap();
    assert_eq!(partition.start_bytes, 2048 * 512);
    assert_eq!(partition.parent, report.devices[0].number);
    assert_eq!(
        report.devices[1]
            .identity
            .partition_uuid
            .as_deref(),
        Some("part-vda1")
    );
    assert_eq!(
        report.devices[1].identity.serial.as_deref(),
        Some("serial-vda")
    );
    assert_eq!(report.devices[1].identity.disk_sequence, Some(7));
    assert_eq!(
        report.devices[2].identity.serial.as_deref(),
        Some("padded serial")
    );
    assert!(
        report
            .devices
            .iter()
            .all(|device| !device.device_node_matches)
    );
    assert_eq!(report.mounts[0].device, report.devices[1].number);
    assert!(!report.uefi_present);
    assert!(!report.kvm_device_present);
}

#[test]
fn stacked_devices_expose_holders_and_slaves_without_assuming_path_authority() {
    let fixture = Fixture::new();
    let disk = fixture.disk("vda", "8:0", 100_000);
    let partition = fixture.partition(&disk, "vda1", "8:1", 2048, 40_000);
    let mapper = fixture.disk("dm-0", "253:0", 39_000);
    fs::create_dir(mapper.join("dm")).unwrap();
    fs::write(mapper.join("dm/uuid"), "CRYPT-LUKS2-test\n").unwrap();
    symlink(&mapper, partition.join("holders/dm-0")).unwrap();
    symlink(&partition, mapper.join("slaves/vda1")).unwrap();
    let report = fixture.inspect().unwrap();
    assert_eq!(report.devices[0].name, "dm-0");
    assert_eq!(report.devices[0].slaves, ["vda1"]);
    assert_eq!(
        report.devices[0]
            .identity
            .device_mapper_uuid
            .as_deref(),
        Some("CRYPT-LUKS2-test")
    );
    assert_eq!(report.devices[2].holders, ["dm-0"]);
    // A regular file with the expected diagnostic name is not a block node.
    fs::write(fixture.roots.dev.join("vda"), b"not a device").unwrap();
    assert!(!fixture.inspect().unwrap().devices[1].device_node_matches);
}

#[test]
fn fingerprints_bind_geometry_identity_namespace_and_boot_evidence() {
    let fixture = Fixture::new();
    let disk = fixture.disk("vda", "8:0", 100_000);
    let original = fixture.inspect().unwrap().fingerprint().unwrap();
    assert_eq!(
        original,
        fixture.inspect().unwrap().fingerprint().unwrap()
    );
    for (field, changed, before) in [
        ("size", "100001", "100000"),
        ("ro", "1", "0"),
        ("diskseq", "8", "7"),
        ("device/serial", "replacement", "serial-vda"),
    ] {
        fs::write(disk.join(field), changed).unwrap();
        assert_ne!(
            original,
            fixture.inspect().unwrap().fingerprint().unwrap(),
            "{field}"
        );
        fs::write(disk.join(field), before).unwrap();
    }
    fixture.write(
        "proc/self/mountinfo",
        "30 29 8:1 / / ro - ext4 /dev/vda1 rw\n",
    );
    assert_ne!(
        original,
        fixture.inspect().unwrap().fingerprint().unwrap()
    );
    fixture.write(
        "proc/sys/kernel/random/boot_id",
        "aaaaaaaa-2222-3333-4444-555555555555\n",
    );
    assert_ne!(
        original,
        fixture.inspect().unwrap().fingerprint().unwrap()
    );
}

#[test]
fn virtio_disk_serial_is_observed_on_disk_and_inherited_by_partitions() {
    let fixture = Fixture::new();
    let disk = fixture.disk("vda", "8:0", 100_000);
    fs::remove_file(disk.join("device/serial")).unwrap();
    fs::write(disk.join("serial"), "  virtio-plan-disk  \n").unwrap();
    fixture.partition(&disk, "vda1", "8:1", 2048, 40_000);
    let observed = fixture.inspect().unwrap();
    assert_eq!(observed.devices.len(), 2);
    for device in &observed.devices {
        assert_eq!(
            device.identity.serial.as_deref(),
            Some("virtio-plan-disk")
        );
    }
    let before = observed.fingerprint().unwrap();
    fs::write(disk.join("serial"), "replacement").unwrap();
    assert_ne!(
        fixture.inspect().unwrap().fingerprint().unwrap(),
        before
    );
}

#[test]
fn serial_sources_must_agree_when_both_are_present() {
    let fixture = Fixture::new();
    let disk = fixture.disk("vda", "8:0", 100_000);
    let before = fixture.inspect().unwrap().fingerprint().unwrap();
    fs::write(disk.join("serial"), "serial-vda\n").unwrap();
    assert_eq!(
        fixture.inspect().unwrap().fingerprint().unwrap(),
        before
    );
    fs::write(disk.join("serial"), "conflicting-serial\n").unwrap();
    assert!(matches!(
        fixture.inspect(),
        Err(InventoryError::Invalid {
            reason: "conflicting disk/device serial observations",
            ..
        })
    ));
}

#[test]
fn absent_optional_identity_is_explicit_and_required_fields_fail_closed() {
    let fixture = Fixture::new();
    let disk = fixture.disk("vda", "8:0", 1);
    for field in [
        "wwid",
        "device/serial",
        "device/model",
        "diskseq",
    ] {
        fs::remove_file(disk.join(field)).unwrap();
    }
    let report = fixture.inspect().unwrap();
    assert_eq!(report.devices[0].identity.wwid, None);
    assert_eq!(report.devices[0].identity.serial, None);
    assert_eq!(report.devices[0].identity.disk_sequence, None);
    fs::remove_file(disk.join("size")).unwrap();
    assert!(matches!(
        fixture.inspect(),
        Err(InventoryError::Invalid { .. })
    ));
}

#[test]
fn duplicate_device_numbers_dangling_relationships_and_sysfs_escapes_are_rejected() {
    let fixture = Fixture::new();
    fixture.disk("vda", "8:0", 1);
    let other = fixture.disk("vdb", "8:0", 1);
    assert!(matches!(
        fixture.inspect(),
        Err(InventoryError::Changed(_))
    ));
    fs::remove_file(fixture.roots.sys.join("class/block/vdb")).unwrap();
    symlink(
        &other,
        fixture
            .roots
            .sys
            .join("class/block/vda/holders/ghost"),
    )
    .unwrap();
    assert!(matches!(
        fixture.inspect(),
        Err(InventoryError::Changed(_))
    ));
    fs::remove_file(
        fixture
            .roots
            .sys
            .join("class/block/vda/holders/ghost"),
    )
    .unwrap();
    symlink(
        &fixture.roots.dev,
        fixture.roots.sys.join("class/block/escape"),
    )
    .unwrap();
    assert!(matches!(
        fixture.inspect(),
        Err(InventoryError::Invalid { .. })
    ));
}

#[test]
fn malformed_numeric_fields_overflow_and_oversized_sources_never_produce_a_report() {
    let fixture = Fixture::new();
    let disk = fixture.disk("vda", "8:0", 10);
    for value in [
        "-1",
        "18446744073709551616",
        "18446744073709551615",
        "1a",
    ] {
        fs::write(disk.join("size"), value).unwrap();
        assert!(matches!(
            fixture.inspect(),
            Err(InventoryError::Invalid { .. })
        ));
    }
    fs::write(disk.join("size"), "10").unwrap();
    fs::write(
        disk.join("device/serial"),
        vec![b'x'; MAX_FIELD_BYTES + 1],
    )
    .unwrap();
    assert!(matches!(
        fixture.inspect(),
        Err(InventoryError::Limit(_))
    ));
}

#[test]
fn cancellation_and_mid_read_device_replacement_are_observed() {
    let fixture = Fixture::new();
    assert!(matches!(
        inspect_at(&fixture.roots, &mut || true),
        Err(InventoryError::Cancelled)
    ));
    let disk = fixture.disk("vda", "8:0", 10);
    let mut calls = 0;
    let mut cancelled = || {
        calls += 1;
        if calls == 18 {
            fs::write(disk.join("size"), "11").unwrap();
        }
        false
    };
    let mut reader = Reader {
        bytes: 0,
        reads: 0,
        entries: 0,
        cancelled: &mut cancelled,
    };
    assert!(matches!(
        read_device(
            &fixture.roots,
            &fixture.roots.sys,
            &fixture.roots.sys.join("class/block"),
            "vda",
            &mut reader
        ),
        Err(InventoryError::Changed(_))
    ));
}

#[test]
fn mountinfo_escapes_unicode_and_namespace_write_mode_are_preserved() {
    let text = "31 30 253:0 /apps\\040data /mnt/área\u{a0}de\\040dados ro shared:7 - ext4 /dev/mapper/data rw\n30 29 8:1 / / rw - ext4 /dev/vda1 rw\n32 30 0:7 / /back\\134slash\\011tab\\012line rw - tmpfs none rw\n";
    let mounts = mounts::parse(text, Path::new("mountinfo")).unwrap();
    assert_eq!(
        mounts
            .iter()
            .map(|mount| mount.id)
            .collect::<Vec<_>>(),
        [30, 31, 32]
    );
    assert_eq!(mounts[1].root, "/apps data");
    assert_eq!(mounts[1].target, "/mnt/área\u{a0}de dados");
    assert!(mounts[1].read_only);
    assert_eq!(mounts[2].target, "/back\\slash\ttab\nline");
}

#[test]
fn malformed_or_ambiguous_mountinfo_is_rejected() {
    for text in [
        "bad",
        "30 29 8:1 / / rw ext4 /dev/vda1 rw",
        "30 29 8:1 / / ro,rw - ext4 /dev/vda1 rw",
        "30 29 8:1 / /xx\\777 rw - ext4 /dev/vda1 rw",
        "30 29 8:1 / /xx\\04 rw - ext4 /dev/vda1 rw",
        "30 29 8:1 / relative rw - ext4 /dev/vda1 rw",
        "30 29 08:1 / / rw - ext4 /dev/vda1 rw",
        "30 29 8:1 / / rw - ext4 /dev/vda1 rw\n30 29 8:1 / / rw - ext4 /dev/vda1 rw",
    ] {
        assert!(
            mounts::parse(text, Path::new("mountinfo")).is_err(),
            "{text}"
        );
    }
}

#[test]
fn pinned_namespace_mounts_preserve_the_kernel_handle_instead_of_treating_it_as_a_path() {
    let mounts = mounts::parse("773 768 0:5 net:[4026533122] /run/docker/netns/container ro,nosuid,nodev master:352 - nsfs nsfs rw\n", Path::new("mountinfo")).unwrap();
    assert_eq!(mounts[0].root, "net:[4026533122]");
    assert_eq!(mounts[0].target, "/run/docker/netns/container");
    assert!(mounts[0].read_only);
    assert!(
        mounts::parse(
            "773 768 0:5 net:[4026533122] /run/docker/netns/container ro - ext4 /dev/root rw\n",
            Path::new("mountinfo")
        )
        .is_err()
    );
}

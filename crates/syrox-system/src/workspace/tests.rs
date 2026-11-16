use super::*;
use crate::budget::{BuildBudget, BuilderLimits};
use std::os::unix::fs::PermissionsExt as _;

fn request() -> BuildBudget {
    BuildBudget {
        memory_bytes: 134_217_728,
        cpu_percent: 100,
        processes: 16,
        descriptors: 128,
        scratch_bytes: 134_217_728,
        files: 1000,
        output_bytes: 67_108_864,
        duration_seconds: 180,
    }
}
fn admit(request: BuildBudget) -> AdmittedBudget {
    BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap()
}
fn layout() -> WorkspaceLayout {
    WorkspaceLayout::from_budget(&admit(request())).unwrap()
}

#[test]
fn geometry_and_global_inode_split_are_deterministic_and_separately_bounded() {
    let parent = admit(request());
    let layout = WorkspaceLayout::from_budget(&parent).unwrap();
    assert_eq!(layout.budget(), &parent);
    assert_eq!(layout.storage_bytes(), 201_326_592);
    assert_eq!(
        layout.scratch_geometry().image_bytes(),
        request().scratch_bytes
    );
    assert_eq!(
        layout.output_geometry().image_bytes(),
        request().output_bytes
    );
    assert_eq!(layout.scratch_geometry().requested_inodes(), 656);
    assert_eq!(layout.output_geometry().requested_inodes(), 320);
    assert!(
        layout.scratch_geometry().requested_inodes() + layout.output_geometry().requested_inodes()
            <= parent.request().files
    );
    assert_eq!(
        layout,
        WorkspaceLayout::from_budget(&parent).unwrap()
    );
}

#[test]
fn canonical_layout_identity_matches_an_independent_binary_fixture() {
    let layout = layout();
    assert_eq!(layout.canonical_bytes().len(), 161);
    // Python hashlib/struct: domain + policy SHA + eight u64 budget values +
    // scratch bytes/inodes/output bytes/inodes, all little endian.
    assert_eq!(
        layout.digest(),
        [
            0x6c, 0xcd, 0x00, 0xb5, 0x64, 0xbc, 0xb3, 0xdd, 0xf8, 0x0a, 0x52, 0x8c, 0xa0, 0x8d,
            0xd2, 0xfd, 0xf3, 0x34, 0x27, 0xf2, 0x4c, 0x3d, 0x4a, 0x3e, 0x22, 0x02, 0xe2, 0x3c,
            0xe0, 0x33, 0x11, 0x30
        ]
    );
}

#[test]
fn output_larger_than_scratch_preserves_parent_policy_without_forging_a_child_admission() {
    let request = BuildBudget {
        scratch_bytes: 67_108_864,
        output_bytes: 134_217_728,
        ..request()
    };
    let parent = admit(request);
    let layout = WorkspaceLayout::from_budget(&parent).unwrap();
    assert!(layout.output_geometry().image_bytes() > parent.request().scratch_bytes);
    assert_eq!(
        layout.budget().policy_fingerprint(),
        parent.policy_fingerprint()
    );
    assert_eq!(layout.scratch_geometry().requested_inodes(), 320);
    assert_eq!(layout.output_geometry().requested_inodes(), 656);
}

#[test]
fn unsupported_volume_sizes_alignment_and_inode_ratios_fail_pure_preflight() {
    for bad in [
        BuildBudget {
            scratch_bytes: 67_108_863,
            ..request()
        },
        BuildBudget {
            output_bytes: 1_048_576,
            ..request()
        },
        BuildBudget {
            output_bytes: 67_108_865,
            ..request()
        },
        BuildBudget {
            scratch_bytes: 128 * 1024 * 1024 * 1024 + 4096,
            ..request()
        },
        BuildBudget {
            files: 16,
            ..request()
        },
    ] {
        assert!(WorkspaceLayout::from_budget(&admit(bad)).is_err());
    }
    // The old one-volume geometry still admits its independently selected
    // scratch. A small output is not retroactively a legacy scratch restriction.
    let small = BuildBudget {
        output_bytes: 1_048_576,
        ..request()
    };
    assert!(Geometry::new(small.scratch_bytes, small.files).is_ok());
}

#[test]
fn large_positive_integer_requests_do_not_overflow_the_proportional_split() {
    let request = BuildBudget {
        files: u64::MAX,
        scratch_bytes: 128 * 1024 * 1024 * 1024,
        output_bytes: 128 * 1024 * 1024 * 1024,
        ..request()
    };
    let layout = WorkspaceLayout::from_budget(&admit(request)).unwrap();
    assert!(u32::try_from(layout.scratch_geometry().requested_inodes()).is_ok());
    assert!(u32::try_from(layout.output_geometry().requested_inodes()).is_ok());
    assert!(
        layout
            .scratch_geometry()
            .requested_inodes()
            .checked_add(layout.output_geometry().requested_inodes())
            .unwrap()
            <= request.files
    );
}

#[test]
fn every_admitted_dimension_and_policy_change_affects_the_layout_identity() {
    let original = request();
    let maximum = BuildBudget {
        memory_bytes: original.memory_bytes * 2,
        cpu_percent: original.cpu_percent * 2,
        processes: original.processes * 2,
        descriptors: original.descriptors * 2,
        scratch_bytes: original.scratch_bytes * 2,
        files: original.files * 2,
        output_bytes: original.output_bytes * 2,
        duration_seconds: original.duration_seconds * 2,
    };
    let policy = BuilderLimits::new(maximum).unwrap();
    let baseline = WorkspaceLayout::from_budget(&policy.admit(original).unwrap()).unwrap();
    for i in 0..8 {
        let mut other = original;
        match i {
            0 => other.memory_bytes += 1,
            1 => other.cpu_percent += 1,
            2 => other.processes += 1,
            3 => other.descriptors += 1,
            4 => other.scratch_bytes += 4096,
            5 => other.files += 1,
            6 => other.output_bytes += 4096,
            7 => other.duration_seconds += 1,
            _ => unreachable!(),
        }
        assert_ne!(
            baseline.digest(),
            WorkspaceLayout::from_budget(&policy.admit(other).unwrap())
                .unwrap()
                .digest()
        );
    }
    let other_policy = WorkspaceLayout::from_budget(&admit(original)).unwrap();
    assert_eq!(
        baseline.scratch_geometry(),
        other_policy.scratch_geometry()
    );
    assert_eq!(
        baseline.output_geometry(),
        other_policy.output_geometry()
    );
    assert_ne!(baseline.digest(), other_policy.digest());
}

#[test]
fn received_regular_files_and_plain_directories_never_supply_workspace_authority() {
    let layout = layout();
    let observation = WorkspaceObservation {
        layout_sha256: layout.digest(),
        scratch: WorkspaceVolumeObservation {
            device: 1,
            inode: 2,
            filesystem_bytes: layout.scratch.image_bytes(),
            inodes: layout.scratch.requested_inodes(),
        },
        output: WorkspaceVolumeObservation {
            device: 2,
            inode: 2,
            filesystem_bytes: layout.output.image_bytes(),
            inodes: layout.output.requested_inodes(),
        },
    };
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("untouched");
    std::fs::write(&marker, b"preserved").unwrap();
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        ReceivedWorkspace::from_authorized_roots(
            &layout,
            &observation,
            File::open(&marker).unwrap(),
            File::open(&marker).unwrap()
        )
        .is_err()
    );
    assert!(
        ReceivedWorkspace::from_authorized_roots(
            &layout,
            &observation,
            File::open(directory.path()).unwrap(),
            File::open(directory.path()).unwrap()
        )
        .is_err()
    );
    assert_eq!(std::fs::read(marker).unwrap(), b"preserved");
}

#[test]
fn observation_rejects_mixed_layouts_aliased_devices_and_over_budget_roles() {
    let layout = layout();
    let original = WorkspaceObservation {
        layout_sha256: layout.digest(),
        scratch: WorkspaceVolumeObservation {
            device: 1,
            inode: 2,
            filesystem_bytes: layout.scratch.image_bytes(),
            inodes: layout.scratch.requested_inodes(),
        },
        output: WorkspaceVolumeObservation {
            device: 2,
            inode: 2,
            filesystem_bytes: layout.output.image_bytes(),
            inodes: layout.output.requested_inodes(),
        },
    };
    original.validate(&layout).unwrap();
    for i in 0..6 {
        let mut other = original;
        match i {
            0 => other.layout_sha256[0] ^= 1,
            1 => other.output.device = other.scratch.device,
            2 => other.scratch.inode = 3,
            3 => other.output.filesystem_bytes += 1,
            4 => other.scratch.inodes += 1,
            5 => other.output.inodes = 0,
            _ => unreachable!(),
        }
        assert!(other.validate(&layout).is_err());
    }
    let mut value = serde_json::to_value(original).unwrap();
    value["unrecognized"] = true.into();
    assert!(serde_json::from_value::<WorkspaceObservation>(value).is_err());
}

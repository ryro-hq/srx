use super::*;

#[test]
fn external_uuid_observation_is_stable_and_changes_no_files() {
    let temporary = tempfile::tempdir().unwrap();
    let file = File::open(temporary.path()).unwrap();
    let first = external_uuid(&file);
    match first {
        Ok(uuid) => {
            assert!((1..=16).contains(&uuid.as_bytes().len()));
            assert_eq!(external_uuid(&file).unwrap(), uuid);
            assert_eq!(uuid.to_string().len(), 2 * uuid.as_bytes().len());
            assert_eq!(
                serde_json::to_value(&uuid)
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .len(),
                uuid.as_bytes().len()
            );
        }
        Err(error) => assert!(
            error.raw_os_error().is_some(),
            "unsupported query must retain its kernel error: {error}"
        ),
    }
    assert_eq!(
        std::fs::read_dir(temporary.path())
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        external_uuid(&tempfile::tempfile().unwrap())
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn directory_capacity_observation_changes_no_files_and_keeps_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = File::open(temporary.path()).unwrap();
    let before = directory.metadata().unwrap();
    let observed = observe(&directory).unwrap();
    assert_eq!(observed.device, before.dev());
    assert_eq!(observed.inode, before.ino());
    assert!(observed.total_bytes > 0);
    assert!(observed.available_bytes <= observed.total_bytes);
    assert!(observed.available_inodes <= observed.total_inodes);
    assert_eq!(
        std::fs::read_dir(temporary.path())
            .unwrap()
            .count(),
        0
    );
    let json = serde_json::to_value(observed).unwrap();
    assert!(matches!(
        json["project"]["status"].as_str(),
        Some("available" | "unavailable")
    ));
}

#[test]
fn regular_file_is_not_treated_as_a_builder_directory() {
    let file = tempfile::tempfile().unwrap();
    assert_eq!(
        observe(&file).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn fingerprint_binds_identity_capacity_and_quota_observations() {
    let temporary = tempfile::tempdir().unwrap();
    let observed = observe(&File::open(temporary.path()).unwrap()).unwrap();
    let original = observed.fingerprint().unwrap();
    assert_eq!(original.len(), 64);
    assert_eq!(observed.clone().fingerprint().unwrap(), original);
    let mut changed = observed.clone();
    changed.inode ^= 1;
    assert_ne!(changed.fingerprint().unwrap(), original);
    changed = observed.clone();
    changed.available_bytes ^= 1;
    assert_ne!(changed.fingerprint().unwrap(), original);
    changed = observed;
    changed.project = Observation::Available {
        value: ProjectObservation {
            id: 123,
            children_inherit_project: true,
            state: Observation::Available {
                value: ProjectQuotaState {
                    accounting: true,
                    enforcement: false,
                },
            },
            limits: Observation::Available {
                value: ProjectQuotaLimits {
                    hard_bytes: None,
                    hard_inodes: Some(1000),
                    used_bytes: 0,
                    used_inodes: 1,
                },
            },
        },
    };
    let accounting = changed.fingerprint().unwrap();
    if let Observation::Available {
        value: project,
    } = &mut changed.project
    {
        project.state = Observation::Available {
            value: ProjectQuotaState {
                accounting: true,
                enforcement: true,
            },
        };
    }
    assert_ne!(changed.fingerprint().unwrap(), accounting);
}

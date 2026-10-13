use super::*;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt as _;

pub(super) fn fixture() -> ServiceSpec {
    let prefix = format!("/syrox/store/{}/out", "a".repeat(64));
    ServiceSpec {
        mounts: vec![
            ServiceMount {
                kind: ServiceMountKind::Output,
                slot: 0,
                target: prefix.clone(),
            },
            ServiceMount {
                kind: ServiceMountKind::Working,
                slot: 1,
                target: "/work".into(),
            },
        ],
        masked_store: Some("/work/store".into()),
        cwd: "/work".into(),
        locale: Some(format!("{prefix}/lib/locale/C.utf8")),
        environment: BTreeMap::from([("APP_SETTING".into(), "public".into())]),
        program: format!("{prefix}/bin/run"),
        arguments: vec!["hello".into()],
    }
}
pub(super) fn resources() -> (tempfile::TempDir, Vec<OwnedFd>, File) {
    let temp = tempfile::tempdir().unwrap();
    for directory in ["output", "working"] {
        fs::create_dir(temp.path().join(directory)).unwrap();
    }
    let descriptors = ["output", "working"]
        .into_iter()
        .map(|directory| OwnedFd::from(File::open(temp.path().join(directory)).unwrap()))
        .collect();
    let path = temp.path().join("retention");
    fs::write(&path, b"lease").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let retention = File::open(path).unwrap();
    (temp, descriptors, retention)
}

#[test]
fn retention_handoff_accepts_the_real_immutable_store_interest() {
    use std::os::fd::AsFd as _;
    let temporary = tempfile::tempdir().unwrap();
    let store = crate::store::Store::initialize(&temporary.path().join("store")).unwrap();
    let interest = store
        .operation()
        .unwrap()
        .retain_objects(&[], &[])
        .unwrap();
    let retention = interest.process_retention().unwrap();
    assert_eq!(
        crate::platform::linux::fd::metadata(retention.as_fd())
            .unwrap()
            .mode()
            & 0o7777,
        0o400
    );
    validate_retention(retention.as_fd()).unwrap();
}

#[test]
fn retention_handoff_refuses_writable_shared_or_linked_descriptors() {
    use std::os::fd::AsFd as _;
    let (temporary, _, retention) = resources();
    let path = temporary.path().join("retention");
    for mode in [0o600, 0o640, 0o444, 0o000, 0o4400] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            validate_retention(retention.as_fd()).is_err(),
            "accepted mode {mode:o}"
        );
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    fs::hard_link(&path, temporary.path().join("second-link")).unwrap();
    assert!(validate_retention(retention.as_fd()).is_err());
    fs::remove_file(temporary.path().join("second-link")).unwrap();
    validate_retention(retention.as_fd()).unwrap();
}
#[test]
fn canonical_body_contains_slots_and_worker_rewrites_only_local_descriptors() {
    let spec = fixture();
    let bytes = spec.canonical_bytes().unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("/proc/self/fd/"));
    assert_eq!(
        ServiceSpec::decode(&bytes, spec.digest().unwrap()).unwrap(),
        spec
    );
    let (_temp, descriptors, _retention) = resources();
    let request = spec.worker_request(&descriptors).unwrap();
    assert_eq!(
        request.mounts[0].source,
        std::path::PathBuf::from(format!(
            "/proc/self/fd/{}",
            descriptors[0].as_raw_fd()
        ))
    );
    assert_eq!(request.arguments, [OsString::from("hello")]);
    assert_eq!(request.terminal, None);
}
#[test]
fn body_rejects_wrong_pin_extra_bytes_duplicate_fields_and_unsupported_versions() {
    let spec = fixture();
    let bytes = spec.canonical_bytes().unwrap();
    assert!(ServiceSpec::decode(&bytes, ContentDigest::sha256(b"wrong")).is_err());
    let text = String::from_utf8(bytes).unwrap();
    for invalid in [
        format!("{text}\n"),
        text.replace("syrox-service-body-v1", "syrox-service-body-v2"),
        text.replace("\"slot\":0", "\"slot\":0,\"slot\":0"),
        text.replace("\"slot\":0", "\"slot\":0,\"unknown\":0"),
    ] {
        assert!(
            ServiceSpec::decode(
                invalid.as_bytes(),
                ContentDigest::sha256(invalid.as_bytes())
            )
            .is_err()
        );
    }
}
#[test]
fn descriptor_roles_counts_and_aliases_are_checked_before_worker_request() {
    let (_temp, mut descriptors, retention) = resources();
    let mut spec = fixture();
    spec.mounts[0].slot = 1;
    assert!(spec.validate().is_err());
    spec = fixture();
    assert!(spec.worker_request(&descriptors[..1]).is_err());
    descriptors[1] = descriptors[0].try_clone().unwrap();
    assert!(spec.worker_request(&descriptors).is_err());
    descriptors[1] = retention.into();
    assert!(spec.worker_request(&descriptors).is_err());
}
#[test]
fn runtime_contract_is_shared_and_large_arguments_are_not_silently_cut_to_packet_size() {
    let mut spec = fixture();
    spec.arguments = vec!["x".repeat(MAX_SERVICE_ARGUMENT_BYTES); MAX_SERVICE_ARGUMENTS];
    let bytes = spec.canonical_bytes().unwrap();
    assert!(bytes.len() > 4096);
    assert_eq!(
        ServiceSpec::decode(&bytes, spec.digest().unwrap())
            .unwrap()
            .arguments
            .len(),
        256
    );
    spec.arguments.push(String::new());
    assert!(spec.validate().is_err());
    spec = fixture();
    spec.environment
        .insert("LD_PRELOAD".into(), "bad".into());
    assert!(spec.validate().is_err());
    spec = fixture();
    spec.environment
        .insert("PATH".into(), "/host".into());
    assert!(spec.validate().is_err());
    spec = fixture();
    spec.masked_store = Some("/elsewhere".into());
    assert!(spec.validate().is_err());
    spec = fixture();
    spec.program = "/usr/bin/sh".into();
    assert!(spec.validate().is_err());
    spec = fixture();
    spec.cwd = "/syrox/store".into();
    assert!(spec.validate().is_err());
    spec = fixture();
    spec.locale = Some("/usr/lib/locale".into());
    assert!(spec.validate().is_err());
}
#[test]
fn decoder_bounds_structure_and_total_body_before_deserializing() {
    let bytes = format!(
        "syrox-service-body-v1\n{}0{}",
        "[".repeat(9),
        "]".repeat(9)
    );
    assert!(matches!(
        ServiceSpec::decode(
            bytes.as_bytes(),
            ContentDigest::sha256(bytes.as_bytes())
        ),
        Err(ServiceSpecError::Invalid(
            "service body structural budget exceeded"
        ))
    ));
    let bytes = vec![0; MAX_SPEC_BYTES + 1];
    assert!(ServiceSpec::decode(&bytes, ContentDigest::sha256(b"unused")).is_err());
}

#[test]
fn configuration_descriptor_is_revalidated_before_worker_request() {
    let (temp, mut descriptors, _retention) = resources();
    let directory = temp.path().join("configuration");
    fs::create_dir(&directory).unwrap();
    let file = directory.join("settings");
    fs::write(&file, b"public").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
    descriptors.push(File::open(&directory).unwrap().into());
    let mut spec = fixture();
    spec.mounts.push(ServiceMount {
        kind: ServiceMountKind::Configuration,
        slot: 2,
        target: "/syrox/config/test".into(),
    });
    spec.worker_request(&descriptors).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(spec.worker_request(&descriptors).is_err());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn managed_working_directory_preserves_private_proc_dev_and_tmp_roots() {
    for cwd in [
        "/",
        "/tmp",
        "/tmp/",
        "/proc",
        "/proc/self",
        "/sys",
        "/sys/fs/cgroup",
        "/dev",
        "/dev/pts/1",
    ] {
        let mut spec = fixture();
        spec.cwd = cwd.into();
        spec.mounts[1].target = cwd.into();
        spec.masked_store = None;
        assert!(
            matches!(
                spec.validate(),
                Err(ServiceSpecError::Invalid(
                    "working directory overlaps a managed runtime filesystem"
                ))
            ),
            "{cwd}"
        );
        // A valid body digest cannot authorize an invalid managed mount layout.
        let mut bytes = HEADER.to_vec();
        bytes.extend(serde_json::to_vec(&spec).unwrap());
        assert!(ServiceSpec::decode(&bytes, ContentDigest::sha256(&bytes)).is_err());
    }
    for cwd in [
        "/tmp/fixture",
        "/tmp/fixture/nested",
        "/work",
        "/device",
        "/process",
    ] {
        let mut spec = fixture();
        spec.cwd = cwd.into();
        spec.mounts[1].target = cwd.into();
        spec.masked_store = None;
        spec.validate().unwrap();
        let bytes = spec.canonical_bytes().unwrap();
        assert_eq!(
            ServiceSpec::decode(&bytes, ContentDigest::sha256(&bytes)).unwrap(),
            spec
        );
    }
}

#[test]
fn cgroup_filesystem_detection_is_independent_of_pathname() {
    assert!(managed_control_filesystem(0x6367_7270));
    assert!(managed_control_filesystem(0x0027_e0eb));
    assert!(!managed_control_filesystem(0xef53));
    assert!(!managed_control_filesystem(0x0102_1994));
}

#[test]
fn secret_descriptor_roles_require_seals_and_do_not_authenticate_secret_bytes() {
    let mut spec = fixture();
    spec.mounts.push(ServiceMount {
        kind: ServiceMountKind::Secret,
        slot: 2,
        target: "/syrox/secrets/service/token".into(),
    });
    let pin = spec.digest().unwrap();
    let (temp, mut descriptors, _retention) = resources();
    let path = temp.path().join("private-source-name");
    fs::write(&path, b"private-content-first").unwrap();
    let file = crate::platform::linux::fd::sealed_file::snapshot(
        File::open(&path).unwrap(),
        &crate::cancellation::Cancellation::default(),
        65536,
    )
    .unwrap();
    descriptors.push(file.into());
    let request = spec.worker_request(&descriptors).unwrap();
    assert_eq!(
        request.mounts[2].kind,
        crate::execution::configuration::MountKind::Secret
    );
    let body = spec.canonical_bytes().unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("private-content"));
    assert!(!String::from_utf8_lossy(&body).contains("private-source"));
    fs::write(&path, b"private-content-second").unwrap();
    descriptors[2] = crate::platform::linux::fd::sealed_file::snapshot(
        File::open(&path).unwrap(),
        &crate::cancellation::Cancellation::default(),
        65536,
    )
    .unwrap()
    .into();
    spec.worker_request(&descriptors).unwrap();
    assert_eq!(spec.digest().unwrap(), pin);
    descriptors[2] = File::open(&path).unwrap().into();
    assert!(spec.worker_request(&descriptors).is_err());
    spec.mounts[2].target = "/syrox/secrets/service/../token".into();
    assert!(spec.validate().is_err());
}

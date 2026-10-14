use super::*;
use crate::platform::linux::boot::BootId;
use std::os::unix::ffi::OsStringExt as _;

fn input() -> LaunchBindingInput {
    let context = OsLaunchContext::new(
        crate::systemd::SystemdScope::User {
            bus_socket: "/run/user/1000/bus".into(),
        },
        "/var/lib/syrox/store".into(),
        "/home/user/.config/systemd/user/syrox-os-install-nginx.service".into(),
        1000,
        1000,
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(10),
    )
    .unwrap();
    LaunchBindingInput {
        installation: "11111111111111111111111111111111".into(),
        generation: ContentDigest::sha256(b"generation"),
        service: "nginx".into(),
        process: "Server_1".into(),
        command: "run".into(),
        unit: SystemdUnitName::new("syrox-os-install-nginx.service").unwrap(),
        launcher: LauncherIdentity::new(ContentDigest::sha256(b"launcher"), 1).unwrap(),
        spec: ContentDigest::sha256(b"spec"),
        epoch: ExecutionEpoch {
            boot: BootId::parse("11111111-1111-1111-1111-111111111111").unwrap(),
            manager: "authenticated-manager-identity".into(),
            scope: context.scope_key(),
        },
        context,
        configuration: "/var/lib/syrox/installation/config/nginx".into(),
        cwd: "/home/user/project".into(),
    }
}
fn encoded(record: &Record) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    bytes.extend(serde_json::to_vec(record).unwrap());
    bytes
}
fn rejects_record(record: &Record) {
    let bytes = encoded(record);
    assert!(OsLaunchBinding::decode(&bytes, ContentDigest::sha256(&bytes)).is_err());
}

#[test]
fn canonical_binding_preserves_role_names_and_explicit_paths() {
    let binding = OsLaunchBinding::new(input()).unwrap();
    let bytes = binding.canonical_bytes().unwrap();
    assert_eq!(
        OsLaunchBinding::decode(&bytes, binding.digest().unwrap()).unwrap(),
        binding
    );
    assert_eq!(binding.process_key(), "nginx/Server_1");
    assert_eq!(binding.command_key(), "service/nginx/run");
    assert_eq!(
        binding.configuration(),
        Path::new("/var/lib/syrox/installation/config/nginx")
    );
    assert_eq!(binding.cwd(), Path::new("/home/user/project"));
    assert_eq!(
        binding.generation(),
        ContentDigest::sha256(b"generation")
    );
    assert_eq!(binding.spec(), ContentDigest::sha256(b"spec"));
    assert_eq!(binding.unit(), input().unit);
    assert_eq!(binding.installation_id(), input().installation);
    assert_eq!(binding.epoch(), &input().epoch);
    assert_eq!(binding.launcher(), &input().launcher);
    // No filesystem lookups: nonexistent authorized choices remain data.
    let mut candidate = input();
    candidate.configuration = "/nonexistent/syrox/config/nginx".into();
    assert!(OsLaunchBinding::new(candidate).is_ok());
}

#[test]
fn binding_rejects_pin_domain_truncation_noncanonical_and_unknown_fields() {
    let binding = OsLaunchBinding::new(input()).unwrap();
    let bytes = binding.canonical_bytes().unwrap();
    assert!(OsLaunchBinding::decode(&bytes, ContentDigest::sha256(b"other")).is_err());
    for size in [0, HEADER.len() - 1, bytes.len() - 1] {
        let truncated = &bytes[..size];
        assert!(OsLaunchBinding::decode(truncated, ContentDigest::sha256(truncated)).is_err());
    }
    let mut other_domain = bytes.clone();
    other_domain[0] = b'x';
    assert!(
        OsLaunchBinding::decode(
            &other_domain,
            ContentDigest::sha256(&other_domain)
        )
        .is_err()
    );
    let mut spaced = bytes.clone();
    spaced.push(b'\n');
    assert!(OsLaunchBinding::decode(&spaced, ContentDigest::sha256(&spaced)).is_err());
    let mut unknown = serde_json::to_value(&binding.0).unwrap();
    unknown["authorized"] = serde_json::json!(true);
    let mut unknown_bytes = HEADER.to_vec();
    unknown_bytes.extend(serde_json::to_vec(&unknown).unwrap());
    assert!(
        OsLaunchBinding::decode(
            &unknown_bytes,
            ContentDigest::sha256(&unknown_bytes)
        )
        .is_err()
    );
    let oversized = vec![b' '; MAX_LAUNCH_BINDING_BYTES + 1];
    assert!(OsLaunchBinding::decode(&oversized, ContentDigest::sha256(&oversized)).is_err());
}

#[test]
fn binding_validates_versions_names_digest_and_epoch_without_losing_process_grammar() {
    let binding = OsLaunchBinding::new(input()).unwrap();
    let mut bad = binding.0.clone();
    bad.version = 2;
    rejects_record(&bad);
    bad.version = 4;
    rejects_record(&bad);
    bad = binding.0.clone();
    bad.launcher.protocol = 2;
    rejects_record(&bad);
    bad = binding.0.clone();
    bad.generation = "sha256:wrong".into();
    rejects_record(&bad);
    bad = binding.0.clone();
    bad.epoch.manager.clear();
    rejects_record(&bad);
    for id in [
        "00000000000000000000000000000000",
        "ABCDEF11111111111111111111111111",
    ] {
        bad = binding.0.clone();
        bad.installation = id.into();
        rejects_record(&bad);
    }
    for service in ["Nginx", "_nginx", "nginx/sub", ".."] {
        let mut candidate = input();
        candidate.service = service.into();
        assert!(OsLaunchBinding::new(candidate).is_err());
    }
    for process in ["..", "", "server/sub"] {
        let mut candidate = input();
        candidate.process = process.into();
        assert!(OsLaunchBinding::new(candidate).is_err());
    }
    let mut candidate = input();
    candidate.process = "_Worker.UPPER-1".into();
    candidate.command = "_Command.UPPER-1".into();
    assert!(OsLaunchBinding::new(candidate).is_ok());
}

#[test]
fn binding_paths_are_canonical_separated_and_obey_managed_cwd_policy() {
    for cwd in [
        "relative",
        "/",
        "/tmp",
        "/proc",
        "/proc/self",
        "/dev/null",
        "/sys",
        "/sys/fs",
        "/home//project",
        "/home/./project",
        "/home/../project",
        "/home/project/",
        "/home/new\nline",
    ] {
        let mut candidate = input();
        candidate.cwd = cwd.into();
        assert!(
            OsLaunchBinding::new(candidate).is_err(),
            "accepted {cwd:?}"
        );
    }
    for cwd in [
        "/var/lib/syrox/installation/config/nginx",
        "/var/lib/syrox",
        "/var/lib/syrox/installation/config/nginx/child",
    ] {
        let mut candidate = input();
        candidate.cwd = cwd.into();
        assert!(OsLaunchBinding::new(candidate).is_err());
    }
    let mut candidate = input();
    candidate.cwd = "/tmp/explicit-project".into();
    assert!(OsLaunchBinding::new(candidate).is_ok());
    let mut candidate = input();
    candidate.configuration = PathBuf::from(std::ffi::OsString::from_vec(
        b"/private/non-utf8-\xff".to_vec(),
    ));
    assert!(OsLaunchBinding::new(candidate).is_err());
    let mut candidate = input();
    candidate.configuration = format!("/private/{}", "x".repeat(256)).into();
    assert!(OsLaunchBinding::new(candidate).is_err());
}

#[test]
fn identity_changes_include_configuration_command_epoch_and_launcher() {
    let original = OsLaunchBinding::new(input())
        .unwrap()
        .digest()
        .unwrap();
    let mut configuration = input();
    configuration.configuration = "/var/lib/syrox/installation/config/new-nginx".into();
    let mut command = input();
    command.command = "other".into();
    let mut epoch = input();
    epoch.epoch.manager = "another-authenticated-manager".into();
    let mut launcher = input();
    launcher.launcher = LauncherIdentity::new(ContentDigest::sha256(b"new launcher"), 1).unwrap();
    for changed in [configuration, command, epoch, launcher] {
        assert_ne!(
            OsLaunchBinding::new(changed)
                .unwrap()
                .digest()
                .unwrap(),
            original
        );
    }
}

#[test]
fn operational_context_is_authenticated_and_legacy_bindings_are_refused() {
    let binding = OsLaunchBinding::new(input()).unwrap();
    assert_eq!(binding.context().uid(), 1000);
    assert_eq!(binding.context().gid(), 1000);
    assert_eq!(
        binding.context().store(),
        Path::new("/var/lib/syrox/store")
    );
    assert_eq!(binding.context().scope(), input().context.scope());
    let original = binding.digest().unwrap();
    let mut modified = input();
    modified.context = OsLaunchContext::new(
        crate::systemd::SystemdScope::System,
        "/var/lib/syrox/another-store".into(),
        "/etc/systemd/system/syrox-os-install-nginx.service".into(),
        1001,
        1002,
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(20),
    )
    .unwrap();
    assert!(OsLaunchBinding::new(modified).is_err()); // stale epoch scope
    let mut modified = input();
    modified.context = OsLaunchContext::new(
        crate::systemd::SystemdScope::System,
        "/var/lib/syrox/another-store".into(),
        "/etc/systemd/system/syrox-os-install-nginx.service".into(),
        1001,
        1002,
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(20),
    )
    .unwrap();
    modified.epoch.scope = modified.context.scope_key();
    assert_ne!(
        OsLaunchBinding::new(modified)
            .unwrap()
            .digest()
            .unwrap(),
        original
    );
    let mut legacy = binding.canonical_bytes().unwrap();
    legacy[HEADER.len() - 2] = b'1';
    assert!(OsLaunchBinding::decode(&legacy, ContentDigest::sha256(&legacy)).is_err());
    let mut record = serde_json::to_value(&binding.0).unwrap();
    record.as_object_mut().unwrap().remove("context");
    let mut missing = HEADER.to_vec();
    missing.extend(serde_json::to_vec(&record).unwrap());
    assert!(OsLaunchBinding::decode(&missing, ContentDigest::sha256(&missing)).is_err());
}

#[test]
fn context_rejects_root_ids_fractional_timeouts_and_operational_path_conflicts() {
    for (uid, gid, start, stop) in [
        (
            0,
            1000,
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(10),
        ),
        (
            1000,
            0,
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(10),
        ),
        (
            1000,
            1000,
            std::time::Duration::from_nanos(1),
            std::time::Duration::from_secs(10),
        ),
        (
            1000,
            1000,
            std::time::Duration::from_secs(301),
            std::time::Duration::from_secs(10),
        ),
        (
            1000,
            1000,
            std::time::Duration::from_secs(30),
            std::time::Duration::ZERO,
        ),
    ] {
        assert!(
            OsLaunchContext::new(
                crate::systemd::SystemdScope::System,
                "/store".into(),
                "/units/syrox-os-install-nginx.service".into(),
                uid,
                gid,
                start,
                stop
            )
            .is_err()
        );
    }
    for path in [
        "/var/lib/syrox/store",
        "/var/lib/syrox/store/sub",
        "/var/lib",
        "/home/user/.config/systemd/user",
        "/home/user/.config/systemd/user/sub",
    ] {
        let mut changed = input();
        changed.cwd = path.into();
        assert!(OsLaunchBinding::new(changed).is_err());
    }
    let mut changed = input();
    changed.unit = SystemdUnitName::new("syrox-other.service").unwrap();
    assert!(OsLaunchBinding::new(changed).is_err());
}

#[test]
fn restart_policy_is_pinned_and_required_on_reopen() {
    let original = OsLaunchBinding::new(input()).unwrap();
    let mut changed = input();
    changed.context = changed
        .context
        .with_restart(
            crate::execution::restart::ProcessRestart::OnFailure(
                crate::execution::restart::RestartLimits::new(2, 30, 4).unwrap(),
            ),
        )
        .unwrap();
    let changed = OsLaunchBinding::new(changed).unwrap();
    assert_ne!(
        original.digest().unwrap(),
        changed.digest().unwrap()
    );
    let mut value = serde_json::to_value(&changed.0).unwrap();
    value["context"]
        .as_object_mut()
        .unwrap()
        .remove("restart");
    assert!(serde_json::from_value::<Record>(value).is_err());
}

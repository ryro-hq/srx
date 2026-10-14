use super::*;
use crate::{
    config::UserConfiguration, project::AuthenticatedStandardLibrary, project::CheckConfiguration,
    store::Store,
};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

fn configuration(kind: &str) -> (tempfile::TempDir, PreparedConsumer) {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("main.srx"),
        format!(
            r#"
        outputs {{ selected: std::{kind} = std::{kind} {{ pkgs = []; services = [
            std::Service {{ id = "config"; files = [std::ConfigFile {{
                path = "nested/settings"; text = "controlled configuration";
            }}]; }}
        ]; }}; }}
    "#
        ),
    )
    .unwrap();
    let checks = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    };
    crate::project::lock_project_with(root.path(), &checks).unwrap();
    let plan =
        crate::project::prepare_project_consumer_with(root.path(), &checks, "selected").unwrap();
    let user = UserConfiguration::parse("", root.path().join("store")).unwrap();
    let prepared = crate::deployment::manifest::prepare_consumer(
        plan,
        "selected",
        &user,
        Path::new("absent-worker"),
        true,
        &Cancellation::default(),
        |_, _| panic!("configuration cannot build"),
    )
    .unwrap();
    (root, prepared)
}

#[test]
fn os_is_rejected_before_private_directory_or_manager_access() {
    let (root, prepared) = configuration("Os");
    let journal_path = root.path().join("journal");
    fs::create_dir(&journal_path).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Arc::new(SessionJournal::open(&journal_path).unwrap());
    let store = Store::initialize(&root.path().join("store")).unwrap();
    let lease = store
        .operation()
        .unwrap()
        .retain_objects(&[], &[])
        .unwrap();
    let private = root.path().join("must-not-be-created");
    let result = ManagedShellSession::start(
        prepared,
        &ManagedShellStart {
            secrets: &crate::config::ShellSecretSources::default(),
            worker: Path::new("missing-worker"),
            worker_digest: ContentDigest::sha256(b"missing"),
            bus_socket: Path::new("missing-bus"),
            private_directory: &private,
            journal: &journal,
            retention: &lease,
            cwd: Path::new("missing-cwd"),
        },
        &Cancellation::default(),
        Instant::now() + Duration::from_secs(1),
    );
    assert!(matches!(result, Err(SessionError::NotShell)));
    assert!(!private.exists());
    assert!(
        journal
            .session_ids(
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap()
            .is_empty()
    );
}

#[test]
fn operation_manifest_authenticates_snapshot_configuration_and_working_directory() {
    let (_root, prepared) = configuration("Shell");
    let first_launcher = LauncherIdentity::new(ContentDigest::sha256(b"first worker"), 1).unwrap();
    let second_launcher =
        LauncherIdentity::new(ContentDigest::sha256(b"second worker"), 1).unwrap();
    let (snapshot, _) = shell_snapshot(&prepared, first_launcher).unwrap();
    let (changed_snapshot, _) = shell_snapshot(&prepared, second_launcher).unwrap();
    let snapshot = snapshot.as_slice();
    let first = session_manifest(
        &boot(),
        snapshot,
        Path::new("/private/config-a"),
        Path::new("/work/a"),
    )
    .unwrap();
    let again = session_manifest(
        &boot(),
        snapshot,
        Path::new("/private/config-a"),
        Path::new("/work/a"),
    )
    .unwrap();
    assert_eq!(first, again);
    for changed in [
        session_manifest(
            &boot(),
            &changed_snapshot,
            Path::new("/private/config-a"),
            Path::new("/work/a"),
        )
        .unwrap(),
        session_manifest(
            &boot(),
            snapshot,
            Path::new("/private/config-b"),
            Path::new("/work/a"),
        )
        .unwrap(),
        session_manifest(
            &boot(),
            snapshot,
            Path::new("/private/config-a"),
            Path::new("/work/b"),
        )
        .unwrap(),
    ] {
        assert_ne!(
            ContentDigest::sha256(&first),
            ContentDigest::sha256(&changed)
        );
    }
    let body = first
        .strip_prefix(b"syrox-shell-operation-v2\n")
        .unwrap();
    let newline = body
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body[..newline]).unwrap();
    assert_eq!(json["configuration"], "/private/config-a");
    assert_eq!(json["cwd"], "/work/a");
    assert_eq!(&body[newline + 1..], snapshot);
    assert!(
        session_manifest(
            &boot(),
            snapshot,
            Path::new(&"a".repeat(16 * 1024)),
            Path::new("/work")
        )
        .is_err()
    );
}

#[test]
fn preparation_consumes_literal_arguments_and_declared_configuration_descriptors() {
    use crate::execution::resources::ServiceMountKind;
    use std::os::fd::AsRawFd as _;
    let (root, prepared) = crate::deployment::manifest::tests::prepared_static_service_fixture();
    let cancel = Cancellation::default();
    let files = SessionFiles::new(prepared.consumer(), &cancel).unwrap();
    let shell = ShellSession {
        secrets: super::super::secrets::SessionSecrets::default(),
        prepared,
        files,
        state: None,
    };
    let launches = prepare_services(&shell, root.path(), &cancel).unwrap();
    assert_eq!(launches.len(), 1);
    let service = &launches[0];
    assert_eq!(service.role, "service:probe:worker");
    assert_eq!(
        service.restart,
        crate::execution::restart::ProcessRestart::Never
    );
    let launch = &service.prepared;
    assert_eq!(
        launch.spec.arguments,
        [
            "literal;$HOME",
            "/syrox/config/probe/nested/config"
        ]
    );
    assert_eq!(
        launch.spec.environment["APP_CONFIG"],
        "/syrox/config/probe/nested/config"
    );
    assert_eq!(launch.spec.cwd, root.path().to_str().unwrap());
    let config = launch
        .spec
        .mounts
        .iter()
        .find(|mount| mount.kind == ServiceMountKind::Configuration)
        .unwrap();
    assert_eq!(config.target, "/syrox/config/probe");
    let path = PathBuf::from(format!(
        "/proc/self/fd/{}",
        launch.descriptors[usize::from(config.slot)].as_raw_fd()
    ));
    assert_eq!(
        fs::read_to_string(path.join("nested/config")).unwrap(),
        "controlled"
    );
    assert_eq!(
        fs::metadata(path.join("nested/config"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o400
    );
    drop(launches);
    shell.close().unwrap();
}

#[test]
fn reserved_working_directory_fails_before_configuration_and_manager_access() {
    let (root, prepared) = configuration("Shell");
    let journal_path = root.path().join("journal");
    fs::create_dir(&journal_path).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Arc::new(SessionJournal::open(&journal_path).unwrap());
    let store = Store::initialize(&root.path().join("store")).unwrap();
    let lease = store
        .operation()
        .unwrap()
        .retain_objects(&[], &[])
        .unwrap();
    let private = root.path().join("must-not-be-created");
    let result = ManagedShellSession::start(
        prepared,
        &ManagedShellStart {
            secrets: &crate::config::ShellSecretSources::default(),
            worker: Path::new("missing-worker"),
            worker_digest: ContentDigest::sha256(b"missing"),
            bus_socket: Path::new("missing-bus"),
            private_directory: &private,
            journal: &journal,
            retention: &lease,
            cwd: Path::new("/proc/self"),
        },
        &Cancellation::default(),
        Instant::now() + Duration::from_secs(1),
    );
    assert!(
        matches!(result, Err(SessionError::Supervision(message)) if message.contains("working directory"))
    );
    assert!(!private.exists());
    assert!(
        journal
            .session_ids(
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap()
            .is_empty()
    );
}

fn explicit_candidate(variable: &str) -> (PathBuf, Vec<u8>) {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let path = PathBuf::from(std::env::var_os(variable).expect("explicit candidate required"));
    assert!(path.is_absolute());
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .unwrap();
    assert!(file.metadata().unwrap().is_file());
    let mut bytes = Vec::new();
    file.take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 128 * 1024 * 1024);
    eprintln!(
        "{variable} {} sha256={}",
        path.display(),
        ContentDigest::sha256(&bytes)
    );
    (path, bytes)
}

fn service_payload_arguments() -> String {
    let peer = crate::execution::transport::Peer::current();
    [
        "config-wait".into(),
        "/syrox/config/probe/nested/config".into(),
        "controlled".into(),
        "witness".into(),
        peer.uid.to_string(),
        peer.gid.to_string(),
    ]
    .iter()
    .map(|argument| {
        format!(
            "std::CommandArgument::Literal({})",
            serde_json::to_string(argument).unwrap()
        )
    })
    .collect::<Vec<_>>()
    .join(", ")
}

fn collect_live_shell(store: &Store, artifacts: &[(ContentDigest, PathBuf)]) {
    let junk = b"unrelated managed Shell garbage";
    let digest = ContentDigest::sha256(junk);
    let roots = {
        let operation = store.operation().unwrap();
        operation
            .ingest(junk.as_slice(), digest, junk.len() as u64)
            .unwrap();
        operation.managed_build_roots().unwrap()
    };
    assert!(!roots.is_empty());
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            remove_roots: roots,
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert!(report.failures.is_empty() && !report.uncertain);
    assert!(report.removed_objects.contains(&digest));
    for (artifact, view) in artifacts {
        assert!(!report.removed_objects.contains(artifact));
        assert!(view.join("bin/run").is_file());
    }
}

#[test]
#[ignore = "requires explicit SYROX_OWNER_WORKER, SYROX_SESSION_PAYLOAD, SYROX_SYSTEMD_USER_BUS and authorized namespace-capable user manager"]
fn managed_shell_starts_configured_service_and_closes_after_namespace_settlement() {
    let (worker, worker_bytes) = explicit_candidate("SYROX_OWNER_WORKER");
    let (_, payload) = explicit_candidate("SYROX_SESSION_PAYLOAD");
    let bus =
        PathBuf::from(std::env::var_os("SYROX_SYSTEMD_USER_BUS").expect("explicit bus required"));
    assert!(bus.is_absolute());
    let (temporary, prepared) =
        crate::deployment::manifest::tests::prepared_service_payload_fixture(
            &payload,
            &service_payload_arguments(),
        );
    // Preserve all artifacts before any manager boundary, including panic/error paths.
    let root = temporary.keep();
    eprintln!("managed Shell gate evidence {}", root.display());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal_path = root.join("journal");
    let private = root.join("private");
    for path in [&journal_path, &private] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let journal = Arc::new(SessionJournal::open(&journal_path).unwrap());
    let store = Store::initialize(&root.join("store")).unwrap();
    let interests = prepared
        .outputs()
        .values()
        .map(crate::result::MaterializedArtifact::object_lease)
        .collect::<Vec<_>>();
    let operation = ObjectLease::combine(&interests).unwrap();
    let artifacts = prepared
        .outputs()
        .values()
        .map(|output| (output.artifact(), output.directory().unwrap()))
        .collect::<Vec<_>>();
    let cancel = Cancellation::default();
    let deadline = || Instant::now() + Duration::from_secs(30);
    let working = root.join("work");
    fs::create_dir(&working).unwrap();
    let witness = working.join("witness");
    fs::write(&witness, b"").unwrap();
    let session = ManagedShellSession::start(
        prepared,
        &ManagedShellStart {
            secrets: &crate::config::ShellSecretSources::default(),
            worker: &worker,
            worker_digest: ContentDigest::sha256(&worker_bytes),
            bus_socket: &bus,
            private_directory: &private,
            journal: &journal,
            retention: &operation,
            cwd: &working,
        },
        &cancel,
        deadline(),
    )
    .unwrap();
    drop(operation);
    let configuration = session.shell.files.path().to_path_buf();
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let until = deadline();
        while fs::read(&witness).unwrap() != b"CONFIG_READY\n" {
            assert!(
                Instant::now() < until,
                "application configuration readiness timeout"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(session.services.role_count(), 1);
        assert!(!session.services.namespaces_settled());
        assert!(configuration.is_dir());
        collect_live_shell(&store, &artifacts);
    }));
    // Always request real settlement, even if a readiness/assertion above failed.
    session
        .close(&journal, &cancel, deadline())
        .unwrap();
    if let Err(error) = observed {
        std::panic::resume_unwind(error);
    }
    assert!(!configuration.exists());
    assert_eq!(
        fs::read(&witness).unwrap(),
        b"CONFIG_TERM_REAPED\n"
    );
    let mut maintenance = store.maintenance().unwrap();
    let report = maintenance
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    crate::result::clear_materializations(&mut maintenance).unwrap();
    assert!(report.failures.is_empty() && !report.uncertain);
    for (artifact, view) in artifacts {
        assert!(report.removed_objects.contains(&artifact));
        assert!(!view.exists());
    }
    fs::remove_dir_all(root).unwrap();
}

fn boot() -> BootId {
    BootId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap()
}

#[path = "state.rs"]
mod state;

mod path;
mod secrets;

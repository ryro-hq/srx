use super::super::{ManagedShellSession, ManagedShellStart};
use crate::execution::journal::SessionJournal;
use crate::{
    cancellation::Cancellation, config::ShellSecretSources, result::MaterializedArtifact,
    store::ContentDigest, store::ObjectLease,
};
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn candidate(name: &str) -> (PathBuf, Vec<u8>) {
    let path = PathBuf::from(std::env::var_os(name).expect("explicit candidate required"));
    assert!(path.is_absolute());
    let pin: ContentDigest = std::env::var(format!("{name}_SHA256"))
        .expect("explicit SHA256 required")
        .parse()
        .unwrap();
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
    assert_eq!(ContentDigest::sha256(&bytes), pin);
    crate::runtime::validate_static_worker_image(&bytes).unwrap();
    (path, bytes)
}

fn source(text: &str) -> String {
    let services = ["alpha", "beta"]
        .into_iter()
        .map(|id| {
            let other = if id == "alpha" { "beta" } else { "alpha" };
            format!(r#"std::Service {{
                id = "{id}"; secrets = ["token"];
                files = [std::ConfigFile {{ path = "settings"; text = "{id}-configuration"; }}];
                commands = [std::ServiceCommand {{
                    name = "helper"; command = std::recipe_command(first, "run");
                    expose = std::Option::Some("{id}");
                    arguments = [std::CommandArgument::Literal("context"), std::CommandArgument::Literal("{id}"),
                        std::CommandArgument::File("settings"), std::CommandArgument::SecretFile("token"),
                        std::CommandArgument::Literal("{other}")];
                }}];
            }}"#)
        })
        .collect::<Vec<_>>()
        .join(",");
    let begin = text.find("services = [").unwrap();
    // The controlled fixture has exactly one Shell followed by its outputs close.
    let text = format!(
        "{}services = [{services}]; }}; }}",
        &text[..begin]
    );
    text.replace(
        "pkgs = [];",
        "pkgs = [std::select_command(first, \"out\", \"run\")];",
    )
}

fn directory(path: &std::path::Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
#[ignore = "requires pinned SYROX_OWNER_WORKER and SYROX_PATH_PAYLOAD, explicit SYROX_SYSTEMD_USER_BUS, user manager and authorized IPC/user/PID/mount namespaces"]
fn managed_path_root_services_pipeline_redirection_and_private_resources() {
    let (worker, worker_bytes) = candidate("SYROX_OWNER_WORKER");
    let (_, payload) = candidate("SYROX_PATH_PAYLOAD");
    let bus = PathBuf::from(std::env::var_os("SYROX_SYSTEMD_USER_BUS").expect("explicit bus"));
    assert!(bus.is_absolute());
    let (temporary, prepared) =
        crate::deployment::manifest::tests::prepared_service_payload_fixture_with_source(
            &payload,
            "",
            "Shell",
            None,
            |text| source(&text),
        );
    let root = temporary.keep();
    eprintln!("controlled PATH gate evidence {}", root.display());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let working = root.join("work");
    let private = root.join("private");
    let journal_path = root.join("journal");
    for path in [&working, &private, &journal_path] {
        directory(path);
    }
    let grants = ["alpha", "beta"].map(|service| {
        let path = root.join(format!("{service}-secret-source"));
        fs::write(&path, format!("{service}-private-fixture")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        (service.into(), "token".into(), path)
    });
    let secrets = ShellSecretSources::new(grants).unwrap();
    let journal = Arc::new(SessionJournal::open(&journal_path).unwrap());
    let leases = prepared
        .outputs()
        .values()
        .map(MaterializedArtifact::object_lease)
        .collect::<Vec<_>>();
    let retention = ObjectLease::combine(&leases).unwrap();
    let cancel = Cancellation::default();
    let session = ManagedShellSession::start(
        prepared,
        &ManagedShellStart {
            worker: &worker,
            worker_digest: ContentDigest::sha256(&worker_bytes),
            bus_socket: &bus,
            private_directory: &private,
            journal: &journal,
            retention: &retention,
            cwd: &working,
            secrets: &secrets,
        },
        &cancel,
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    drop(retention);
    let observation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let status = session
            .run_command("run", &["suite".into()], &cancel)
            .unwrap();
        assert_eq!(status.code(), Some(0));
        assert_eq!(
            fs::read(working.join("path-success")).unwrap(),
            b"SYROX_PATH_V1 SUITE ROOT SERVICES PIPE REDIRECT STATUS ISOLATION OK\n"
        );
        assert_eq!(
            fs::read(working.join("redirect-witness")).unwrap(),
            b"SYROX_PATH_V1 HELPER alpha ARGV OK\nSYROX_PATH_V1 DRIVER STATUS OK\n"
        );
    }));
    // Closure requires real namespace settlement even if a witness/assertion failed.
    session
        .close(
            &journal,
            &Cancellation::default(),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    if let Err(error) = observation {
        std::panic::resume_unwind(error);
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn controlled_path_gate_prepares_root_and_two_private_service_aliases() {
    let mut payload = crate::runtime::tests::elf(2, None, &[], None, None);
    payload[24..32].copy_from_slice(&0x0040_0100_u64.to_le_bytes());
    payload[68..72].copy_from_slice(&5_u32.to_le_bytes());
    let (_root, prepared) =
        crate::deployment::manifest::tests::prepared_service_payload_fixture_with_source(
            &payload,
            "",
            "Shell",
            None,
            |text| source(&text),
        );
    assert_eq!(
        prepared
            .exposures()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["alpha", "beta", "run"]
    );
    assert_eq!(prepared.consumer().services().len(), 2);
    assert!(
        prepared
            .consumer()
            .services()
            .iter()
            .all(|service| service.processes().is_empty())
    );
}

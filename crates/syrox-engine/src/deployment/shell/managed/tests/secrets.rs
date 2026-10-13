use super::*;
use std::os::unix::fs::MetadataExt as _;

struct Instance {
    session: Option<ManagedShellSession>,
    journal: Arc<SessionJournal>,
}
impl Instance {
    fn start(
        root: &Path,
        worker: &Path,
        pin: ContentDigest,
        bus: &Path,
        payload: &[u8],
        source: &Path,
        cancel: &Cancellation,
    ) -> Self {
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let (project, prepared) =
            crate::deployment::manifest::tests::prepared_service_payload_fixture_with_source(
                payload,
                r#"std::CommandArgument::Literal("secret"), std::CommandArgument::SecretFile("token")"#,
                "Shell",
                Some(&root.join("store")),
                |text| {
                    text
                .replace("id = \"probe\";", "id = \"probe\"; secrets = [\"token\"];")
                .replace("name = \"serve\";", "name = \"serve\"; expose = std::Option::Some(\"secret\");")
                .replace("processes = [std::ServiceProcess { id = \"worker\"; command = \"serve\"; }];", "processes = [];")
                },
            );
        let project = project.keep();
        fs::write(
            root.join("project-evidence"),
            project.as_os_str().as_encoded_bytes(),
        )
        .unwrap();
        let journal_path = root.join("journal");
        let private = root.join("private");
        let cwd = root.join("work");
        for path in [&journal_path, &private, &cwd] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal = Arc::new(SessionJournal::open(&journal_path).unwrap());
        let retention = ObjectLease::combine(
            &prepared
                .outputs()
                .values()
                .map(crate::result::MaterializedArtifact::object_lease)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let secrets = crate::config::ShellSecretSources::new([(
            "probe".into(),
            "token".into(),
            source.to_owned(),
        )])
        .unwrap();
        let session = ManagedShellSession::start(
            prepared,
            &ManagedShellStart {
                worker,
                worker_digest: pin,
                bus_socket: bus,
                private_directory: &private,
                journal: &journal,
                retention: &retention,
                cwd: &cwd,
                secrets: &secrets,
            },
            cancel,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
        Self {
            session: Some(session),
            journal,
        }
    }
    fn run(&self, version: &str, cancel: &Cancellation) {
        assert!(
            self.session
                .as_ref()
                .unwrap()
                .run_command("secret", &[version.into()], cancel)
                .unwrap()
                .success()
        );
    }
    fn close(&mut self) {
        self.session
            .take()
            .unwrap()
            .close(
                &self.journal,
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap();
    }
}
impl Drop for Instance {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            eprintln!(
                "exact-session cleanup: {:?}",
                session.close(
                    &self.journal,
                    &Cancellation::default(),
                    Instant::now() + Duration::from_secs(30)
                )
            );
        }
    }
}
#[test]
#[ignore = "explicit static SYROX_OWNER_WORKER/SYROX_SESSION_PAYLOAD + _SHA256, SYROX_SYSTEMD_USER_BUS, owned0700 SYROX_SESSION_SECRET_PARENT; real manager and namespace runner"]
fn secret_snapshot_rotation_isolated_between_sessions_and_delivered_readonly() {
    let (_, worker) = state::candidate("SYROX_OWNER_WORKER");
    let (_, payload) = state::candidate("SYROX_SESSION_PAYLOAD");
    let bus = PathBuf::from(std::env::var_os("SYROX_SYSTEMD_USER_BUS").unwrap());
    let parent = PathBuf::from(std::env::var_os("SYROX_SESSION_SECRET_PARENT").unwrap());
    let meta = fs::symlink_metadata(&parent).unwrap();
    assert!(
        bus.is_absolute()
            && parent.is_absolute()
            && meta.is_dir()
            && meta.mode() & 0o7777 == 0o700
            && meta.uid() == crate::platform::linux::fd::effective_uid()
    );
    let root = tempfile::Builder::new()
        .prefix("secret-gate-")
        .tempdir_in(parent)
        .unwrap()
        .keep();
    eprintln!("Secret gate evidence {}", root.display());
    let worker_path = state::copy_worker(&root, &worker);
    let pin = ContentDigest::sha256(&worker);
    let source = root.join("public-fixture-source");
    fs::write(&source, b"syrox-secret-fixture-v1\n").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    let cancel = Cancellation::default();
    let _deadline = state::Deadline::start(&cancel);
    let mut first = Instance::start(
        &root.join("a"),
        &worker_path,
        pin,
        &bus,
        &payload,
        &source,
        &cancel,
    );
    first.run("1", &cancel);
    fs::write(&source, b"syrox-secret-fixture-v2\n").unwrap();
    first.run("1", &cancel);
    let mut second = Instance::start(
        &root.join("b"),
        &worker_path,
        pin,
        &bus,
        &payload,
        &source,
        &cancel,
    );
    second.run("2", &cancel);
    first.close();
    second.run("2", &cancel);
    second.close();
    assert!(!cancel.is_cancelled());
}

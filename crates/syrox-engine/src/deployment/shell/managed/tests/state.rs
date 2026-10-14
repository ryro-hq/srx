use super::*;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::sync::mpsc;

pub(super) struct Deadline {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Deadline {
    pub(super) fn start(cancel: &Cancellation) -> Self {
        let cancel = cancel.clone();
        let (stop, signal) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            if signal
                .recv_timeout(Duration::from_secs(90))
                .is_err()
            {
                cancel.cancel();
            }
        });
        Self {
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}
impl Drop for Deadline {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
struct Instance {
    session: Option<ManagedShellSession>,
    journal: Arc<SessionJournal>,
    state: PathBuf,
}
impl Instance {
    fn start(
        root: &Path,
        worker: &Path,
        worker_pin: ContentDigest,
        bus: &Path,
        payload: &[u8],
        cancel: &Cancellation,
    ) -> Self {
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let (project, prepared) =
            crate::deployment::manifest::tests::prepared_service_payload_fixture_with_source(
                payload,
                r#"std::CommandArgument::Literal("state"), std::CommandArgument::StateDirectory"#,
                "Shell",
                Some(&root.join("store")),
                |source| {
                    source.replace("id = \"probe\";", "id = \"probe\"; state = std::ServiceState::Session;")
                .replace("name = \"serve\";", "name = \"serve\"; expose = std::Option::Some(\"state\");")
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
        let session = ManagedShellSession::start(
            prepared,
            &ManagedShellStart {
                secrets: &crate::config::ShellSecretSources::default(),
                worker,
                worker_digest: worker_pin,
                bus_socket: bus,
                private_directory: &private,
                journal: &journal,
                retention: &retention,
                cwd: &cwd,
            },
            cancel,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
        let state = session
            .shell
            .state
            .as_ref()
            .unwrap()
            .path()
            .to_owned();
        assert_eq!(session.services.role_count(), 0);
        Self {
            session: Some(session),
            journal,
            state,
        }
    }
    fn run(&self, expected: u32, cancel: &Cancellation) {
        assert!(
            self.session
                .as_ref()
                .unwrap()
                .run_command("state", &[expected.to_string().into()], cancel)
                .unwrap()
                .success()
        );
        assert_eq!(
            fs::read_to_string(self.state.join("probe/counter")).unwrap(),
            format!("{}\n", expected + 1)
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
        assert!(
            !self.state.exists(),
            "state removed only after confirmed close"
        );
    }
}
impl Drop for Instance {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            let result = session.close(
                &self.journal,
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(30),
            );
            eprintln!(
                "exact-session cleanup: {result:?}; evidence {}",
                self.state.display()
            );
        }
    }
}
pub(super) fn candidate(variable: &str) -> (PathBuf, Vec<u8>) {
    let (path, bytes) = explicit_candidate(variable);
    let expected: ContentDigest = std::env::var(format!("{variable}_SHA256"))
        .expect("explicit candidate digest required")
        .parse()
        .unwrap();
    assert_eq!(ContentDigest::sha256(&bytes), expected);
    crate::runtime::validate_static_worker_image(&bytes).unwrap();
    (path, bytes)
}
pub(super) fn copy_worker(root: &Path, bytes: &[u8]) -> PathBuf {
    let path = root.join("worker");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(&path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    file.set_permissions(fs::Permissions::from_mode(0o500))
        .unwrap();
    path
}
#[test]
#[ignore = "explicit static SYROX_OWNER_WORKER/SYROX_SESSION_PAYLOAD plus matching _SHA256, SYROX_SYSTEMD_USER_BUS and owned0700 SYROX_SESSION_STATE_PARENT; real namespace/manager runner required"]
fn session_state_persists_between_commands_isolates_sessions_and_closes_after_settlement() {
    let (_, worker) = candidate("SYROX_OWNER_WORKER");
    let (_, payload) = candidate("SYROX_SESSION_PAYLOAD");
    let bus = PathBuf::from(std::env::var_os("SYROX_SYSTEMD_USER_BUS").unwrap());
    let parent = PathBuf::from(std::env::var_os("SYROX_SESSION_STATE_PARENT").unwrap());
    assert!(bus.is_absolute() && parent.is_absolute());
    let metadata = fs::symlink_metadata(&parent).unwrap();
    assert!(
        metadata.is_dir()
            && metadata.mode() & 0o7777 == 0o700
            && metadata.uid() == crate::platform::linux::fd::effective_uid()
    );
    let root = tempfile::Builder::new()
        .prefix("state-gate-")
        .tempdir_in(&parent)
        .unwrap()
        .keep();
    eprintln!("Session state gate evidence {}", root.display());
    let worker_path = copy_worker(&root, &worker);
    let pin = ContentDigest::sha256(&worker);
    let cancel = Cancellation::default();
    let _deadline = Deadline::start(&cancel);
    let mut first = Instance::start(
        &root.join("a"),
        &worker_path,
        pin,
        &bus,
        &payload,
        &cancel,
    );
    let mut second = Instance::start(
        &root.join("b"),
        &worker_path,
        pin,
        &bus,
        &payload,
        &cancel,
    );
    assert_ne!(first.state, second.state);
    first.run(0, &cancel);
    first.run(1, &cancel);
    second.run(0, &cancel);
    first.close();
    assert!(second.state.is_dir());
    second.run(1, &cancel);
    second.close();
    assert!(
        !cancel.is_cancelled(),
        "gate exhausted its execution deadline"
    );
    // Retained diagnostic directories and Store roots are not state data cleanup.
}

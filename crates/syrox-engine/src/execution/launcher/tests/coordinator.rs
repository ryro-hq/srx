use super::*;
use crate::execution::journal::{AttemptPhase, SessionPhase};
use crate::{store::GcRequest, store::ObjectLease, store::Store, systemd::SystemdJobResult};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};

const MANIFEST: &[u8] = b"owner-only coordinator host fixture v1\n";
const FIXTURE: &str = "execution::launcher::coordinator::tests::owner_coordinator_child_fixture";

const RETAINED_BYTES: &[u8] = b"owner retained object";
fn owner_interest(store: &Store) -> ObjectLease {
    let operation = store.operation().unwrap();
    let pin = ContentDigest::sha256(RETAINED_BYTES);
    operation
        .ingest(RETAINED_BYTES, pin, RETAINED_BYTES.len() as u64)
        .unwrap();
    operation.retain_objects(&[pin], &[]).unwrap()
}

fn collect_owner_garbage(store: &Store) {
    let junk = b"unrelated owner gate garbage";
    let junk_pin = ContentDigest::sha256(junk);
    store
        .operation()
        .unwrap()
        .ingest(junk.as_slice(), junk_pin, junk.len() as u64)
        .unwrap();
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(report.failures.is_empty() && !report.uncertain);
    assert_eq!(report.removed_objects, [junk_pin]);
    assert!(
        store
            .operation()
            .unwrap()
            .read_verified(ContentDigest::sha256(RETAINED_BYTES), 1024)
            .unwrap()
            .is_some()
    );
}

fn collect_released_owner(store: &Store) -> bool {
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(report.failures.is_empty() && !report.uncertain);
    report
        .removed_objects
        .contains(&ContentDigest::sha256(RETAINED_BYTES))
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn worker_bytes(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 128 * 1024 * 1024);
    bytes
}

fn private(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

struct Gate {
    directory: tempfile::TempDir,
    worker: PathBuf,
    bus: PathBuf,
}
impl Gate {
    fn new() -> Self {
        let source = PathBuf::from(
            std::env::var_os("SYROX_OWNER_WORKER").expect("explicit candidate worker required"),
        );
        let bus = PathBuf::from(
            std::env::var_os("SYROX_SYSTEMD_USER_BUS").expect("explicit user bus required"),
        );
        assert!(source.is_absolute() && bus.is_absolute());
        let metadata = fs::metadata(&source).unwrap();
        assert!(metadata.is_file() && metadata.len() <= 128 * 1024 * 1024);
        assert_ne!(metadata.permissions().mode() & 0o111, 0);
        let directory = tempfile::Builder::new()
            .prefix("srx-own-")
            .tempdir()
            .unwrap();
        fs::set_permissions(
            directory.path(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let worker = directory.path().join("worker");
        let bytes = worker_bytes(&source);
        fs::write(&worker, &bytes).unwrap();
        fs::set_permissions(&worker, fs::Permissions::from_mode(0o500)).unwrap();
        let digest = ContentDigest::sha256(&bytes);
        assert_eq!(
            ContentDigest::sha256(&worker_bytes(&worker)),
            digest
        );
        eprintln!(
            "owner candidate {} sha256 {digest}",
            source.display()
        );
        private(&directory.path().join("journal"));
        private(&directory.path().join("ipc"));
        Self {
            directory,
            worker,
            bus,
        }
    }

    fn finish(self, result: std::thread::Result<()>) {
        let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.cleanup()));
        if result.is_err() || cleanup.is_err() {
            let path = self.directory.keep();
            eprintln!(
                "owner gate evidence retained at {}",
                path.display()
            );
        }
        if let Err(payload) = cleanup {
            std::panic::resume_unwind(payload);
        }
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    fn journal(&self) -> SessionJournal {
        SessionJournal::open(&self.directory.path().join("journal")).unwrap()
    }

    fn manager(&self) -> SystemdManager {
        SystemdManager::connect(
            SystemdScope::User {
                bus_socket: self.bus.clone(),
            },
            Duration::from_secs(5),
            &Cancellation::default(),
        )
        .unwrap()
    }

    // Called even after failed start/assertions: IDs are durably created before
    // starting the deterministic owner unit. Unknown/incomplete evidence stays.
    fn cleanup(&self) {
        let cancel = Cancellation::default();
        let journal = self.journal();
        let mut manager = self.manager();
        for id in journal.session_ids(&cancel, deadline()).unwrap() {
            let unit = SystemdUnitName::new(format!("syrox-owner-{id}.service")).unwrap();
            let Some(observed) = manager
                .query(&unit, Duration::from_secs(5), &cancel)
                .unwrap()
            else {
                continue;
            };
            if observed.active_state == "inactive" {
                continue;
            }
            let state = journal
                .snapshot(&id, &cancel, deadline())
                .unwrap();
            let binding = state
                .attempts
                .iter()
                .find_map(|attempt| attempt.binding.as_ref())
                .expect("cannot safely clean owner without recorded invocation");
            assert_eq!(binding.unit(), &unit);
            assert_eq!(
                binding.invocation().as_slice(),
                observed.invocation,
                "refuse cleanup of replacement invocation"
            );
            journal
                .begin_closing(&id, "host gate cleanup", &cancel, deadline())
                .unwrap();
            match manager.stop(&unit, Duration::from_secs(5), &cancel) {
                Ok(job) => assert_done(
                    &manager
                        .wait_job(&job, Duration::from_secs(10), &cancel)
                        .unwrap(),
                ),
                Err(error) => assert!(
                    manager
                        .query(&unit, Duration::from_secs(5), &cancel)
                        .unwrap()
                        .is_none(),
                    "owner cleanup failed: {error}"
                ),
            }
        }
        let path = self.directory.path().join("store");
        if path.exists() {
            let store = Store::open(&path).unwrap();
            assert!(
                store.maintenance().is_ok(),
                "owner gate cleanup could not acquire the maintenance barrier"
            );
        }
    }
}

fn assert_done(completion: &SystemdJobCompletion) {
    assert!(
        matches!(
            completion,
            SystemdJobCompletion::Observed {
                result: SystemdJobResult::Done
            }
        ),
        "{completion:?}"
    );
}

#[test]
#[allow(unsafe_code)] // Constructs one adversarial FIFO in a private test directory.
fn candidate_snapshot_rejects_symlink_directory_and_fifo_without_blocking() {
    let directory = tempfile::tempdir().unwrap();
    private(&directory.path().join("ipc"));
    let worker = directory.path().join("worker");
    fs::write(&worker, b"controlled snapshot bytes").unwrap();
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&worker, &link).unwrap();
    let session = SessionId::parse("11111111111111111111111111111111").unwrap();
    let pin = ContentDigest::sha256(b"controlled snapshot bytes");
    for source in [&link, &directory.path().to_path_buf()] {
        assert!(
            snapshot_worker(
                source,
                pin,
                &directory.path().join("ipc"),
                &session,
                &Cancellation::default(),
                deadline()
            )
            .is_err()
        );
    }
    let fifo = directory.path().join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated pathname in our private temporary directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = snapshot_worker(
            &fifo,
            pin,
            &directory.path().join("ipc"),
            &session,
            &Cancellation::default(),
            deadline(),
        );
        let _ = send.send(result.is_err());
    });
    // A blocking-open regression fails this watchdog instead of hanging CI.
    // The detached failing reader owns its temporary directory until process exit.
    assert!(
        receive
            .recv_timeout(Duration::from_secs(2))
            .expect("FIFO source open blocked")
    );
    worker.join().unwrap();
}

#[test]
#[ignore = "requires explicit SYROX_OWNER_WORKER and SYROX_SYSTEMD_USER_BUS with authorized user manager"]
fn owner_retains_store_rejects_replay_and_closes_admission_before_stop() {
    let gate = Gate::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let store = Store::initialize(&gate.directory.path().join("store")).unwrap();
        let lease = owner_interest(&store);
        let journal = gate.journal();
        let cancel = Cancellation::default();
        let mut owner = start_owner(
            OwnerStart {
                worker: &gate.worker,
                worker_digest: ContentDigest::sha256(&worker_bytes(&gate.worker)),
                bus_socket: &gate.bus,
                private_directory: &gate.directory.path().join("ipc"),
                manifest: MANIFEST,
                pin: ContentDigest::sha256(MANIFEST),
                retention: &lease,
            },
            &journal,
            &cancel,
            deadline(),
        )
        .unwrap();
        drop(lease);
        drop(owner.retention.take());
        let mut manager = gate.manager();
        let status = manager
            .query_fd_store(
                owner.binding.unit(),
                Duration::from_secs(5),
                &cancel,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            status.invocation.as_slice(),
            owner.binding.invocation()
        );
        assert_eq!(status.count, 1);
        assert_eq!(status.max, 1);
        assert_eq!(status.notify_access, "main");
        collect_owner_garbage(&store);
        let state = journal
            .snapshot(&owner.session, &cancel, deadline())
            .unwrap();
        assert_eq!(state.phase, SessionPhase::Authorized);
        assert_eq!(state.attempts.len(), 1);
        assert_eq!(state.attempts[0].phase, AttemptPhase::Consumed);
        assert!(
            journal
                .consume_attempt(
                    &owner.session,
                    &owner.attempt,
                    ContentDigest::sha256(MANIFEST),
                    &owner.binding,
                    &cancel,
                    deadline()
                )
                .is_err()
        );
        assert_done(
            &owner
                .close(&journal, &cancel, deadline())
                .unwrap(),
        );
        assert_eq!(
            journal
                .snapshot(&owner.session, &cancel, deadline())
                .unwrap()
                .phase,
            SessionPhase::Closing
        );
        drop(owner);
        assert!(collect_released_owner(&store));
    }));
    gate.finish(result);
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        // Child owns its unreaped PID; no numeric process-group signalling.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires explicit SYROX_OWNER_WORKER and SYROX_SYSTEMD_USER_BUS with authorized user manager"]
fn coordinator_death_closes_owner_and_recovery_does_not_restart_it() {
    let gate = Gate::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let store = Store::initialize(&gate.directory.path().join("store")).unwrap();
        let mut child = ChildGuard(
            Command::new(crate::reexec_test_executable(FIXTURE, true))
                .args([
                    "--exact",
                    FIXTURE,
                    "--ignored",
                    "--nocapture",
                ])
                .env(
                    "SYROX_OWNER_TEST_DIRECTORY",
                    gate.directory.path(),
                )
                .env("SYROX_OWNER_WORKER", &gate.worker)
                .env("SYROX_SYSTEMD_USER_BUS", &gate.bus)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let ready = gate.directory.path().join("ready");
        let end = deadline();
        while !ready.exists() {
            assert!(
                Instant::now() < end,
                "coordinator startup deadline"
            );
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "coordinator failed before readiness"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let session = SessionId::parse(fs::read_to_string(ready).unwrap().trim()).unwrap();
        let unit = SystemdUnitName::new(format!("syrox-owner-{session}.service")).unwrap();
        collect_owner_garbage(&store);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let mut manager = gate.manager();
        let cancel = Cancellation::default();
        let end = deadline();
        loop {
            let status = manager
                .query(&unit, Duration::from_secs(2), &cancel)
                .unwrap();
            if status.is_none_or(|status| status.active_state == "inactive")
                && collect_released_owner(&store)
            {
                break;
            }
            assert!(
                Instant::now() < end,
                "owner failed to exit/release after coordinator death"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let journal = gate.journal();
        // Abrupt death cannot publish Closing. Recovery closes admission only.
        assert_eq!(
            journal
                .snapshot(&session, &cancel, deadline())
                .unwrap()
                .phase,
            SessionPhase::Authorized
        );
        assert_eq!(
            journal
                .recover(&session, &cancel, deadline())
                .unwrap()
                .phase,
            SessionPhase::Closing
        );
        assert!(
            manager
                .query(&unit, Duration::from_secs(2), &cancel)
                .unwrap()
                .is_none_or(|s| s.active_state == "inactive")
        );
    }));
    gate.finish(result);
}

#[test]
#[ignore = "internal subprocess fixture; run through coordinator_death gate"]
fn owner_coordinator_child_fixture() {
    let directory = PathBuf::from(
        std::env::var_os("SYROX_OWNER_TEST_DIRECTORY").expect("parent gate directory"),
    );
    let worker = PathBuf::from(std::env::var_os("SYROX_OWNER_WORKER").unwrap());
    let bus = PathBuf::from(std::env::var_os("SYROX_SYSTEMD_USER_BUS").unwrap());
    let store = Store::open(&directory.join("store")).unwrap();
    let lease = owner_interest(&store);
    let journal = SessionJournal::open(&directory.join("journal")).unwrap();
    let owner = start_owner(
        OwnerStart {
            worker: &worker,
            worker_digest: ContentDigest::sha256(&worker_bytes(&worker)),
            bus_socket: &bus,
            private_directory: &directory.join("ipc"),
            manifest: MANIFEST,
            pin: ContentDigest::sha256(MANIFEST),
            retention: &lease,
        },
        &journal,
        &Cancellation::default(),
        deadline(),
    )
    .unwrap();
    drop(lease);
    fs::write(
        directory.join("ready.tmp"),
        owner.session.as_str(),
    )
    .unwrap();
    fs::rename(
        directory.join("ready.tmp"),
        directory.join("ready"),
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(90));
    drop(owner);
    panic!("parent did not terminate coordinator fixture within deadline");
}

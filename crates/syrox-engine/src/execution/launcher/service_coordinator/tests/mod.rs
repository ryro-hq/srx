use super::*;
mod restart;
use crate::execution::journal::SessionJournal;
use crate::execution::launcher::coordinator::{OwnerStart, start_owner};
use crate::runtime::launch_preparation::prepare_runtime_launch;
use crate::{
    result::ResultManifest, result::admit_result, runtime::RuntimeConfiguration,
    store::ContentDigest, store::GcRequest, store::ObjectLease, store::RootName, store::Store,
    systemd::SystemdScope,
};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONFIGURATION: &str = "managed service configuration\n";
const GENERATION: &[u8] = b"controlled service generation v1\n";

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

#[test]
fn service_roles_are_specific_bounded_and_cannot_reuse_owner_authority() {
    for role in [
        "service:nginx:server",
        "service:git-2.55:config",
        "service:a_b:c.d",
        "service:nginx:_Worker",
        "service:nginx:Main",
    ] {
        validate_role(role).unwrap();
    }
    for role in [
        "owner",
        "service",
        "service::server",
        "service:nginx:",
        "service:nginx:server:other",
        "service:../nginx:server",
        "service:Nginx:server",
        "service:nginx:server\n",
        "service:nginx:server\0",
    ] {
        assert!(validate_role(role).is_err(), "accepted {role:?}");
    }
    assert!(validate_role(&format!("service:{}:server", "a".repeat(129))).is_err());
    assert!(
        validate_role(&format!(
            "service:{}:{}",
            "a".repeat(128),
            "b".repeat(128)
        ))
        .is_ok()
    );
}

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn explicit_bytes(variable: &str) -> (PathBuf, Vec<u8>) {
    let path = PathBuf::from(std::env::var_os(variable).expect("explicit candidate path required"));
    assert!(path.is_absolute());
    let mut bytes = Vec::new();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .unwrap();
    assert!(file.metadata().unwrap().is_file());
    file.take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 128 * 1024 * 1024);
    eprintln!(
        "{variable} {} sha256 {}",
        path.display(),
        ContentDigest::sha256(&bytes)
    );
    (path, bytes)
}

fn import_payload(store: &Store, payload: &[u8]) -> crate::runtime::RuntimeClosure {
    // Host gates supply actual candidate bytes; the Store-only GC regression
    // never executes its metadata fixture. Admission verifies the declared
    // ELF closure without source/compiler/build receipts in this Store.
    let mut artifact = b"syrox-artifact\n".to_vec();
    artifact.extend(1u32.to_le_bytes());
    artifact.extend(7u16.to_le_bytes());
    artifact.extend(b"bin/run");
    artifact.push(1);
    artifact.extend(
        u64::try_from(payload.len())
            .unwrap()
            .to_le_bytes(),
    );
    artifact.extend(payload);
    let artifact_pin = ContentDigest::sha256(&artifact);
    let action = ContentDigest::sha256(payload);
    let operation = store.operation().unwrap();
    operation
        .ingest(
            artifact.as_slice(),
            artifact_pin,
            u64::try_from(artifact.len()).unwrap(),
        )
        .unwrap();
    drop(operation);
    let bytes = format!(
        "syrox-result-v2\n{{\"outputs\":{{\"app\":{{\"action\":\"{action}\",\"output\":\"out\",\"artifact\":\"{artifact_pin}\",\"files\":1}}}},\"commands\":{{\"service\":{{\"application\":\"app\",\"application_path\":\"bin/run\",\"loader\":null,\"loader_path\":null,\"libraries\":[]}}}}}}\n"
    );
    let manifest = ResultManifest::parse(bytes.as_bytes()).unwrap();
    admit_result(
        store,
        &RootName::new("service_fixture").unwrap(),
        &manifest,
        manifest.digest().unwrap(),
        &Cancellation::default(),
    )
    .unwrap()
    .command("service")
    .unwrap()
    .open(store, &Cancellation::default())
    .unwrap()
}

fn collect_unrelated_during_service(store: &Store, artifact: ContentDigest, view: &Path) {
    let junk = b"unrelated service garbage";
    let junk_pin = ContentDigest::sha256(junk);
    store
        .operation()
        .unwrap()
        .ingest(junk.as_slice(), junk_pin, junk.len() as u64)
        .unwrap();
    let report = {
        let mut maintenance = store.maintenance().unwrap();
        let report = maintenance
            .garbage_collect(&GcRequest {
                collect: true,
                remove_roots: vec![RootName::new("service_fixture").unwrap()],
                ..GcRequest::default()
            })
            .unwrap();
        assert!(report.failures.is_empty() && !report.uncertain);
        crate::result::clear_materializations(&mut maintenance).unwrap();
        report
    }; // Release exclusive maintenance before opening a verification operation.
    assert!(report.failures.is_empty() && !report.uncertain);
    assert!(report.removed_objects.contains(&junk_pin));
    assert!(!report.removed_objects.contains(&artifact));
    assert!(
        view.join("bin/run").is_file(),
        "GC removed a live runtime view"
    );
    assert!(
        store
            .operation()
            .unwrap()
            .read_verified(artifact, 128 * 1024 * 1024)
            .unwrap()
            .is_some()
    );
}

fn collect_settled_service(store: &Store, artifact: ContentDigest, view: &Path) {
    let mut maintenance = store.maintenance().unwrap();
    let report = maintenance
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(report.failures.is_empty() && !report.uncertain);
    assert!(report.removed_objects.contains(&artifact));
    crate::result::clear_materializations(&mut maintenance).unwrap();
    assert!(
        !view.exists(),
        "settled unrooted view remained retained"
    );
}

#[test]
fn gc_helpers_protect_live_view_then_reclaim_objects_and_cache() {
    // No process is launched: this regression checks the host gate's actual
    // maintenance sequence, not kernel settlement or systemd readiness.
    if crate::platform::linux::fd::retention_fork_tests::isolate_test(
        "execution::launcher::service_coordinator::tests::gc_helpers_protect_live_view_then_reclaim_objects_and_cache",
        "SYROX_SERVICE_GC_HELPERS_ISOLATED",
    ) {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let store = Store::initialize(&root.path().join("store")).unwrap();
    let closure = import_payload(
        &store,
        &crate::runtime::tests::elf(2, None, &[], None, None),
    );
    let artifact = closure.application().output.artifact();
    let view = closure.application().output.directory().unwrap();
    collect_unrelated_during_service(&store, artifact, &view);
    drop(closure);
    collect_settled_service(&store, artifact, &view);
}

fn configuration(path: &Path) -> RuntimeConfiguration {
    private_directory(path);
    fs::write(path.join("config"), CONFIGURATION).unwrap();
    fs::set_permissions(
        path.join("config"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o500)).unwrap();
    RuntimeConfiguration::new(
        "probe",
        File::open(path).unwrap(),
        BTreeMap::from([(
            "APP_CONFIG".into(),
            "/syrox/config/probe/config".into(),
        )]),
    )
    .unwrap()
}

fn witness_free(path: &Path) -> bool {
    crate::platform::linux::fd::flock(
        File::open(path).unwrap().as_fd(),
        crate::platform::linux::fd::FlockMode::ExclusiveNonblocking,
    )
    .unwrap()
}

fn wait_marker(path: &Path, expected: &[u8]) {
    let end = deadline();
    loop {
        if fs::read(path).unwrap() == expected {
            return;
        }
        assert!(
            Instant::now() < end,
            "service marker did not become {expected:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct Gate {
    root: tempfile::TempDir,
    worker: PathBuf,
    worker_pin: ContentDigest,
    bus: PathBuf,
    payload: Vec<u8>,
}
impl Gate {
    fn new() -> Self {
        let (_, worker) = explicit_bytes("SYROX_OWNER_WORKER");
        let (_, payload) = explicit_bytes("SYROX_SESSION_PAYLOAD");
        let bus = PathBuf::from(
            std::env::var_os("SYROX_SYSTEMD_USER_BUS").expect("explicit user bus required"),
        );
        assert!(bus.is_absolute());
        let root = tempfile::Builder::new()
            .prefix("srx-svc-")
            .tempdir()
            .unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let worker_path = root.path().join("worker");
        fs::write(&worker_path, &worker).unwrap();
        fs::set_permissions(&worker_path, fs::Permissions::from_mode(0o500)).unwrap();
        for name in [
            "journal",
            "owner-ipc",
            "service-ipc",
            "working",
        ] {
            private_directory(&root.path().join(name));
        }
        Self {
            root,
            worker: worker_path,
            worker_pin: ContentDigest::sha256(&worker),
            bus,
            payload,
        }
    }

    fn journal(&self) -> SessionJournal {
        SessionJournal::open(&self.root.path().join("journal")).unwrap()
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

    fn cleanup(&self) {
        let journal = self.journal();
        let cancel = Cancellation::default();
        let mut manager = self.manager();
        for id in journal.session_ids(&cancel, deadline()).unwrap() {
            let snapshot = journal
                .begin_closing(
                    &id,
                    "service host gate cleanup",
                    &cancel,
                    deadline(),
                )
                .unwrap();
            for attempt in snapshot
                .attempts
                .iter()
                .filter(|a| a.role != "owner")
                .chain(
                    snapshot
                        .attempts
                        .iter()
                        .filter(|a| a.role == "owner"),
                )
            {
                let Some(binding) = &attempt.binding else {
                    // An unbound attempted start cannot be safely targeted by name.
                    panic!("unbound startup retained for manual reconciliation");
                };
                let Some(status) = manager
                    .query(binding.unit(), Duration::from_secs(5), &cancel)
                    .unwrap()
                else {
                    continue;
                };
                if status.active_state == "inactive" {
                    continue;
                }
                // Earlier attempts remain in the journal after a restart. A
                // recorded successor is handled by its own exact binding below;
                // this does not authorize stopping an unrecorded replacement.
                if status.invocation != binding.invocation()
                    && snapshot.attempts.iter().any(|candidate| {
                        candidate.binding.as_ref().is_some_and(|next| {
                            next.unit() == binding.unit() && status.invocation == next.invocation()
                        })
                    })
                {
                    continue;
                }
                assert_eq!(
                    status.invocation,
                    binding.invocation(),
                    "refuse stopping replacement service invocation"
                );
                let job = manager
                    .stop(binding.unit(), Duration::from_secs(5), &cancel)
                    .unwrap();
                assert_done(
                    &manager
                        .wait_job(&job, Duration::from_secs(10), &cancel)
                        .unwrap(),
                );
            }
        }
        let store = self.root.path().join("store");
        if store.exists() {
            assert!(
                Store::open(&store).unwrap().maintenance().is_ok(),
                "service cleanup retains Store interests"
            );
        }
    }

    fn finish(self, result: std::thread::Result<()>) {
        let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.cleanup()));
        if result.is_err() || cleanup.is_err() {
            let path = self.root.keep();
            eprintln!(
                "service gate evidence retained at {}",
                path.display()
            );
        } else {
            let config = self.root.path().join("configuration");
            if config.exists() {
                fs::set_permissions(config, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        if let Err(payload) = cleanup {
            std::panic::resume_unwind(payload);
        }
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
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

fn stop_service_and_owner(
    owner: &mut OwnerHandle,
    service: &mut ServiceGroup,
    journal: &SessionJournal,
    cancel: &Cancellation,
    stop_owner_first: bool,
) {
    if stop_owner_first {
        let completion = owner.close(journal, cancel, deadline()).unwrap();
        assert_done(&completion);
        let end = deadline();
        while !service.namespaces_settled() {
            assert!(
                Instant::now() < end,
                "namespace survived owner stop"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        service
            .settle_after_owner_stop(owner, &completion, cancel, deadline())
            .unwrap();
        assert!(service.namespaces_settled());
    } else {
        journal
            .begin_closing(
                &owner.session,
                "explicit service stop test",
                cancel,
                deadline(),
            )
            .unwrap();
        service.close(cancel, deadline()).unwrap();
        assert!(service.namespaces_settled());
        assert_done(&owner.close(journal, cancel, deadline()).unwrap());
    }
}

fn assert_remote_retention(gate: &Gate, service: &ServiceGroup, cancel: &Cancellation) {
    let mut manager = gate.manager();
    let retained = manager
        .query_fd_store(
            service.authority().roles()[0].unit(),
            Duration::from_secs(5),
            cancel,
        )
        .unwrap()
        .unwrap();
    let snapshot = gate
        .journal()
        .snapshot(
            service.authority().roles()[0].session(),
            cancel,
            deadline(),
        )
        .unwrap();
    let head = snapshot.roles.first().unwrap();
    let binding = snapshot
        .attempts
        .iter()
        .find(|attempt| attempt.id == head.head)
        .unwrap()
        .binding
        .as_ref()
        .unwrap();
    assert_eq!(retained.invocation, binding.invocation());
    assert_eq!(retained.count, 1);
}

fn service_arguments(witness: &Path) -> Vec<std::ffi::OsString> {
    vec![
        "config-wait".into(),
        "/syrox/config/probe/config".into(),
        CONFIGURATION.into(),
        witness.as_os_str().to_owned(),
        Peer::current().uid.to_string().into(),
        Peer::current().gid.to_string().into(),
    ]
}

fn assert_service_replay_rejected(
    journal: &SessionJournal,
    service: &ServiceGroup,
    cancel: &Cancellation,
) {
    let state = journal
        .snapshot(
            service.authority().roles()[0].session(),
            cancel,
            deadline(),
        )
        .unwrap();
    let attempt = state
        .attempts
        .iter()
        .find(|a| a.id == state.roles[0].head)
        .unwrap();
    assert_eq!(
        attempt.phase,
        crate::execution::journal::AttemptPhase::Consumed
    );
    assert!(
        journal
            .consume_attempt(
                service.authority().roles()[0].session(),
                &attempt.id,
                ContentDigest::sha256(GENERATION),
                attempt.binding.as_ref().unwrap(),
                cancel,
                deadline()
            )
            .is_err()
    );
}

fn service_gate(stop_owner_first: bool) {
    let gate = Gate::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let store = Store::initialize(&gate.root.path().join("store")).unwrap();
        let closure = import_payload(&store, &gate.payload);
        let config = configuration(&gate.root.path().join("configuration"));
        let cwd = gate.root.path().join("working");
        let witness = cwd.join("witness");
        fs::write(&witness, b"").unwrap();
        let cancel = Cancellation::default();
        let prepared = prepare_runtime_launch(
            &closure,
            &service_arguments(&witness),
            &cwd,
            &config,
            &cancel,
        )
        .unwrap();
        let operation =
            ObjectLease::combine(&[closure.application().output.object_lease()]).unwrap();
        let artifact = closure.application().output.artifact();
        let view = closure.application().output.directory().unwrap();
        let journal = Arc::new(gate.journal());
        let mut owner = start_owner(
            OwnerStart {
                worker: &gate.worker,
                worker_digest: gate.worker_pin,
                bus_socket: &gate.bus,
                private_directory: &gate.root.path().join("owner-ipc"),
                manifest: GENERATION,
                pin: ContentDigest::sha256(GENERATION),
                retention: &operation,
            },
            &journal,
            &cancel,
            deadline(),
        )
        .unwrap();
        let mut service = ServiceGroup::start(
            &owner,
            vec![ServiceRoleStart {
                role: "service:probe:server".into(),
                prepared,
                restart: crate::execution::restart::ProcessRestart::Never,
            }],
            &gate.root.path().join("service-ipc"),
            Arc::clone(&journal),
            &cancel,
            deadline(),
        )
        .unwrap();
        drop((operation, closure));
        // systemd READY confirms exec; application readiness is this independent witness.
        wait_marker(&witness, b"CONFIG_READY\n");
        assert!(!witness_free(&witness));
        assert!(!service.namespaces_settled());
        collect_unrelated_during_service(&store, artifact, &view);
        assert_remote_retention(&gate, &service, &cancel);
        assert_service_replay_rejected(&journal, &service, &cancel);
        assert!(
            service.close(&cancel, deadline()).is_err(),
            "close requires durable Closing"
        );
        assert!(!service.namespaces_settled());
        assert!(!witness_free(&witness));
        stop_service_and_owner(
            &mut owner,
            &mut service,
            &journal,
            &cancel,
            stop_owner_first,
        );
        assert_eq!(
            fs::read(&witness).unwrap(),
            b"CONFIG_TERM_REAPED\n"
        );
        assert!(witness_free(&witness));
        drop((service, owner, config));
        collect_settled_service(&store, artifact, &view);
    }));
    gate.finish(result);
}

#[test]
#[ignore = "requires explicit SYROX_OWNER_WORKER, SYROX_SESSION_PAYLOAD and SYROX_SYSTEMD_USER_BUS; namespace-capable authorized user manager"]
fn owner_stop_terminates_configured_service_and_reaps_its_child() {
    service_gate(true);
}

#[test]
#[ignore = "requires explicit SYROX_OWNER_WORKER, SYROX_SESSION_PAYLOAD and SYROX_SYSTEMD_USER_BUS; namespace-capable authorized user manager"]
fn explicit_service_stop_settles_namespace_before_releasing_retention() {
    service_gate(false);
}

#[test]
fn settlement_never_promotes_missing_jobs_or_replaced_active_units() {
    assert!(
        completed(&SystemdJobCompletion::Unobserved {
            status: None
        })
        .is_err()
    );
    assert!(
        completed(&SystemdJobCompletion::Observed {
            result: SystemdJobResult::Failed
        })
        .is_err()
    );
    assert!(
        completed(&SystemdJobCompletion::Observed {
            result: SystemdJobResult::Done
        })
        .is_ok()
    );
    let binding = AttemptBinding::new(
        SystemdUnitName::new("syrox-test.service").unwrap(),
        [1; 16],
    )
    .unwrap();
    let mut status = SystemdUnitStatus {
        unit: binding.unit().clone(),
        invocation: vec![1; 16],
        active_state: "inactive".into(),
        sub_state: "dead".into(),
        control_group: String::new(),
        result: "success".into(),
        main_pid: 0,
        exec_main_code: 0,
        exec_main_status: 0,
    };
    assert!(inactive_or_absent(None, &binding).is_ok());
    assert!(inactive_or_absent(Some(&status), &binding).is_ok());
    status.active_state = "active".into();
    assert!(inactive_or_absent(Some(&status), &binding).is_err());
    status.active_state = "inactive".into();
    status.invocation = vec![2; 16];
    assert!(inactive_or_absent(Some(&status), &binding).is_err());
    status.invocation = vec![1; 16];
    status.unit = SystemdUnitName::new("syrox-other.service").unwrap();
    assert!(inactive_or_absent(Some(&status), &binding).is_err());
}

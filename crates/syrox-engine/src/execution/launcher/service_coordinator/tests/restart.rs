use super::*;
use crate::execution::journal::AttemptPhase;

fn pinned_gate() -> Gate {
    let gate = Gate::new();
    for (variable, actual) in [
        ("SYROX_OWNER_WORKER_SHA256", gate.worker_pin),
        (
            "SYROX_SESSION_PAYLOAD_SHA256",
            ContentDigest::sha256(&gate.payload),
        ),
    ] {
        let expected: ContentDigest = std::env::var(variable)
            .expect("explicit candidate SHA256 required")
            .parse()
            .unwrap();
        assert_eq!(
            actual, expected,
            "candidate pin differs: {variable}"
        );
    }
    gate
}
fn release(cwd: &Path, number: usize) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(cwd.join(format!("release.{number}")))
        .unwrap();
    std::io::Write::write_all(&mut file, b"X").unwrap();
    file.sync_all().unwrap();
}
fn wait_state(
    manager: &mut SystemdManager,
    unit: &SystemdUnitName,
    predicate: impl Fn(&SystemdUnitStatus) -> bool,
) -> SystemdUnitStatus {
    let end = deadline();
    loop {
        if let Some(status) = manager
            .query(
                unit,
                Duration::from_secs(1),
                &Cancellation::default(),
            )
            .unwrap()
            && predicate(&status)
        {
            return status;
        }
        assert!(
            Instant::now() < end,
            "required manager state was not observed"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn restart_marker(path: &Path, expected: &[u8]) {
    let end = deadline();
    loop {
        match fs::read(path) {
            Ok(bytes) if bytes == expected => return,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("restart marker read failed: {error}"),
        }
        assert!(
            Instant::now() < end,
            "restart marker was not observed"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn head(
    journal: &SessionJournal,
    service: &ServiceGroup,
) -> crate::execution::journal::SessionSnapshot {
    journal
        .snapshot(
            service.authority().roles()[0].session(),
            &Cancellation::default(),
            deadline(),
        )
        .unwrap()
}

fn exercise(close_in_interval: bool) {
    let gate = pinned_gate();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run(&gate, close_in_interval);
    }));
    gate.finish(result);
}
fn run(gate: &Gate, close_in_interval: bool) {
    let cancel = Cancellation::default();
    let store = Store::initialize(&gate.root.path().join("store")).unwrap();
    let closure = import_payload(&store, &gate.payload);
    let artifact = closure.application().output.artifact();
    let view = closure.application().output.directory().unwrap();
    let retained = ObjectLease::combine(&[closure.application().output.object_lease()]).unwrap();
    let cwd = gate.root.path().join("working");
    let config = configuration(&gate.root.path().join("configuration"));
    let prepared = prepare_runtime_launch(
        &closure,
        &[
            "restart78".into(),
            "witness".into(),
            "release".into(),
        ],
        &cwd,
        &config,
        &cancel,
    )
    .unwrap();
    let spec = prepared.spec.digest().unwrap();
    let journal = Arc::new(gate.journal());
    let mut owner = start_owner(
        OwnerStart {
            worker: &gate.worker,
            worker_digest: gate.worker_pin,
            bus_socket: &gate.bus,
            private_directory: &gate.root.path().join("owner-ipc"),
            manifest: GENERATION,
            pin: ContentDigest::sha256(GENERATION),
            retention: &retained,
        },
        &journal,
        &cancel,
        deadline(),
    )
    .unwrap();
    let mut services = ServiceGroup::start(
        &owner,
        vec![ServiceRoleStart {
            role: "service:probe:restart".into(),
            prepared,
            restart: crate::execution::restart::ProcessRestart::OnFailure(
                crate::execution::restart::RestartLimits::new(1, 60, 2).unwrap(),
            ),
        }],
        &gate.root.path().join("service-ipc"),
        Arc::clone(&journal),
        &cancel,
        deadline(),
    )
    .unwrap();
    drop((closure, retained));
    restart_marker(&cwd.join("witness.1"), b"SYROX_RESTART_V1 1\n");
    let first = head(&journal, &services);
    assert_eq!(first.roles[0].binding.command(), spec);
    let first_head = first.roles[0].head.clone();
    let first_attempt = first
        .attempts
        .iter()
        .find(|attempt| attempt.id == first_head)
        .unwrap();
    assert_eq!(first_attempt.phase, AttemptPhase::Consumed);
    let first_binding = first_attempt.binding.clone().unwrap();
    let unit = first_binding.unit().clone();
    let mut manager = gate.manager();
    release(&cwd, 1);
    wait_state(&mut manager, &unit, |status| {
        status.active_state == "activating" && status.sub_state == "auto-restart"
    });
    if close_in_interval {
        journal
            .begin_closing(
                &owner.session,
                "gate closes restart interval",
                &cancel,
                deadline(),
            )
            .unwrap();
    }
    // This selectively collects garbage and removes the only imported root.
    // Owner/template/durable interests may jointly protect these bytes; this
    // gate does not attribute protection to the manager FD store alone.
    collect_unrelated_during_service(&store, artifact, &view);
    if !close_in_interval {
        verify_successor(
            gate,
            &journal,
            &services,
            &first,
            &unit,
            &mut manager,
        );
        journal
            .begin_closing(
                &owner.session,
                "gate closes rate-limited role",
                &cancel,
                deadline(),
            )
            .unwrap();
    }
    stop_service_and_owner(&mut owner, &mut services, &journal, &cancel, true);
    assert!(
        !cwd.join(if close_in_interval {
            "witness.2"
        } else {
            "witness.3"
        })
        .exists()
    );
    drop((services, owner, config));
    collect_settled_service(&store, artifact, &view);
}

#[test]
#[ignore = "real authorized user systemd and namespace/IPC required; explicit SYROX_OWNER_WORKER/_SHA256, SYROX_SESSION_PAYLOAD/_SHA256, SYROX_SYSTEMD_USER_BUS; restart78 fixture, no fallback"]
fn payload_78_restarts_with_distinct_admission_then_hits_burst_limit() {
    exercise(false);
}

#[test]
#[ignore = "real authorized user systemd and namespace/IPC required; explicit SYROX_OWNER_WORKER/_SHA256, SYROX_SESSION_PAYLOAD/_SHA256, SYROX_SYSTEMD_USER_BUS; restart78 fixture, no fallback"]
fn durable_closing_in_restart_interval_prevents_next_payload() {
    exercise(true);
}

fn verify_successor(
    gate: &Gate,
    journal: &SessionJournal,
    services: &ServiceGroup,
    first: &crate::execution::journal::SessionSnapshot,
    unit: &SystemdUnitName,
    manager: &mut SystemdManager,
) {
    let cwd = gate.root.path().join("working");
    let first_head = first.roles[0].head.clone();
    let first_binding = first
        .attempts
        .iter()
        .find(|attempt| attempt.id == first_head)
        .unwrap()
        .binding
        .as_ref()
        .unwrap();
    restart_marker(&cwd.join("witness.2"), b"SYROX_RESTART_V1 2\n");
    let second = head(journal, services);
    assert_ne!(second.roles[0].head, first_head);
    assert_eq!(second.roles[0].binding, first.roles[0].binding);
    let previous = second
        .attempts
        .iter()
        .find(|attempt| attempt.id == first_head)
        .unwrap();
    assert_eq!(previous.phase, AttemptPhase::Settled);
    let next = second
        .attempts
        .iter()
        .find(|attempt| attempt.id == second.roles[0].head)
        .unwrap();
    assert_eq!(next.phase, AttemptPhase::Consumed);
    assert_ne!(
        next.binding.as_ref().unwrap().invocation(),
        first_binding.invocation()
    );
    assert_eq!(
        fs::read(gate.root.path().join("configuration/config")).unwrap(),
        CONFIGURATION.as_bytes()
    );
    release(&cwd, 2);
    // v257 retains the preceding payload's exit-code result when a later
    // automatic start hits the limit. Require a permanent failed state and
    // prove refusal of a new start through its exact manager job instead.
    wait_state(manager, unit, |status| {
        status.active_state == "failed"
            && status.sub_state == "failed"
            && status.main_pid == 0
            && matches!(
                status.result.as_str(),
                "start-limit-hit" | "exit-code"
            )
    });
    match manager.start_unit(
        unit,
        Duration::from_secs(10),
        &Cancellation::default(),
    ) {
        Ok(job) => assert!(matches!(
            manager
                .wait_job(
                    &job,
                    Duration::from_secs(10),
                    &Cancellation::default()
                )
                .unwrap(),
            SystemdJobCompletion::Observed {
                result: SystemdJobResult::Failed
            }
        )),
        Err(SystemdError::Remote {
            name,
            ..
        }) => {
            assert_eq!(name, "org.freedesktop.systemd1.StartLimitHit");
        }
        Err(error) => panic!("start-limit refusal was not observed: {error}"),
    }
    assert_eq!(
        manager
            .query(
                unit,
                Duration::from_secs(10),
                &Cancellation::default()
            )
            .unwrap()
            .unwrap()
            .main_pid,
        0
    );
    assert!(
        !cwd.join("witness.3").exists(),
        "third payload bypassed start limit"
    );
}

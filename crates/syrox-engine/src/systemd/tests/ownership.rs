use super::*;

fn start_gate_unit(
    manager: &mut SystemdManager,
    unit: SystemdUnitName,
    owner: Option<SystemdUnitName>,
) {
    // This gate tests manager dependencies only. /usr/bin/sleep is a declared
    // host fixture, not a package or launcher accepted by deployment.
    let mut service = SystemdService::new(unit, "/usr/bin/sleep".into());
    service.arguments = vec!["30".into()];
    service.runtime_max = Some(Duration::from_secs(30));
    service.bound_to = owner;
    let cancellation = Cancellation::default();
    let timeout = Duration::from_secs(5);
    let job = manager
        .start_transient(&service, timeout, &cancellation)
        .unwrap();
    assert!(matches!(
        manager
            .wait_job(&job, timeout, &cancellation)
            .unwrap(),
        SystemdJobCompletion::Observed {
            result: SystemdJobResult::Done
        }
    ));
}

#[test]
#[ignore = "requires SYROX_SYSTEMD_USER_BUS, authorized manager >=250 and /usr/bin/sleep"]
fn stopping_owner_stops_bound_unit_and_preserves_independent_unit() {
    let bus_socket = std::env::var_os("SYROX_SYSTEMD_USER_BUS")
        .expect("explicit user bus socket")
        .into();
    let timeout = Duration::from_secs(5);
    let cancellation = Cancellation::default();
    let mut manager = SystemdManager::connect(
        SystemdScope::User {
            bus_socket,
        },
        timeout,
        &cancellation,
    )
    .unwrap();
    let serial = CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    let names: Vec<_> = ["owner", "member", "independent"]
        .into_iter()
        .map(|role| {
            SystemdUnitName::new(format!(
                "syrox-binding-{}-{serial}-{role}.service",
                std::process::id()
            ))
            .unwrap()
        })
        .collect();
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        start_gate_unit(&mut manager, names[0].clone(), None);
        start_gate_unit(
            &mut manager,
            names[1].clone(),
            Some(names[0].clone()),
        );
        start_gate_unit(&mut manager, names[2].clone(), None);
        for unit in &names {
            assert_eq!(
                manager
                    .query(unit, timeout, &cancellation)
                    .unwrap()
                    .unwrap()
                    .active_state,
                "active"
            );
        }
        let stop = manager
            .stop(&names[0], timeout, &cancellation)
            .unwrap();
        assert!(matches!(
            manager
                .wait_job(&stop, timeout, &cancellation)
                .unwrap(),
            SystemdJobCompletion::Observed {
                result: SystemdJobResult::Done
            }
        ));
        // The owner stop job completes after the ordered dependent stop. An
        // absent transient unit is also expected once CollectMode unloads it.
        for unit in &names[..2] {
            let status = manager
                .query(unit, timeout, &cancellation)
                .unwrap();
            assert!(status.is_none_or(|state| state.active_state == "inactive"));
        }
        assert_eq!(
            manager
                .query(&names[2], timeout, &cancellation)
                .unwrap()
                .unwrap()
                .active_state,
            "active"
        );
    }));
    // Clean every attempted unit even after a failed assertion or uncertain
    // start. RuntimeMax bounds a manager/transport failure during cleanup.
    let mut cleanup_error = None;
    for unit in names.iter().rev() {
        match manager.stop(unit, timeout, &Cancellation::default()) {
            Ok(job) => match manager.wait_job(&job, timeout, &Cancellation::default()) {
                Ok(SystemdJobCompletion::Observed {
                    result: SystemdJobResult::Done,
                }) => {}
                Ok(_) => {
                    cleanup_error.get_or_insert(SystemdError::Protocol(
                        "cleanup stop was not confirmed",
                    ));
                }
                Err(error) => {
                    cleanup_error.get_or_insert(error);
                }
            },
            Err(error) if error.absent_unit() => {}
            Err(error) => {
                cleanup_error.get_or_insert(error);
            }
        }
    }
    if let Err(payload) = observed {
        std::panic::resume_unwind(payload);
    }
    assert!(
        cleanup_error.is_none(),
        "cleanup failed: {cleanup_error:?}"
    );
}

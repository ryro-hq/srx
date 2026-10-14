use super::properties::{Value, service};
use super::*;

#[test]
fn manager_identity_separates_bus_restarts_owners_and_scopes() {
    let scope = SystemdScope::User {
        bus_socket: "/run/user/1000/bus".into(),
    };
    let first = SystemdManagerIdentity::new(
        scope.clone(),
        "0123456789abcdef0123456789abcdef".into(),
        ":1.2".into(),
    )
    .unwrap();
    let again = SystemdManagerIdentity::new(
        scope.clone(),
        first.bus_guid().into(),
        first.owner().into(),
    )
    .unwrap();
    assert_eq!(first, again);
    for changed in [
        SystemdManagerIdentity::new(
            scope.clone(),
            "1123456789abcdef0123456789abcdef".into(),
            first.owner().into(),
        )
        .unwrap(),
        SystemdManagerIdentity::new(scope, first.bus_guid().into(), ":1.3".into()).unwrap(),
        SystemdManagerIdentity::new(
            SystemdScope::System,
            first.bus_guid().into(),
            first.owner().into(),
        )
        .unwrap(),
    ] {
        assert_ne!(first.fingerprint(), changed.fingerprint());
    }
}

mod ownership;

#[test]
fn names_paths_and_local_bus_authorities_are_bounded() {
    for name in [
        "sshd.service",
        "syrox-.service",
        "syrox-a.scope",
        "syrox-a/b.service",
        "syrox-a.service\0",
    ] {
        assert!(SystemdUnitName::new(name).is_err(), "{name:?}");
    }
    assert!(SystemdUnitName::new(format!("syrox-{}.service", "a".repeat(128))).is_err());
    let scope = SystemdScope::User {
        bus_socket: "/run/user/1000/name,semi;percent%".into(),
    };
    assert_eq!(
        scope.address().unwrap(),
        "unix:path=/run/user/1000/name%2csemi%3bpercent%25"
    );
    assert!(
        SystemdScope::User {
            bus_socket: "relative".into()
        }
        .address()
        .is_err()
    );
    assert!(
        SystemdScope::User {
            bus_socket: "/run/../tmp/bus".into()
        }
        .address()
        .is_err()
    );
    assert_eq!(
        SystemdScope::System.address().unwrap(),
        "unix:path=/run/dbus/system_bus_socket"
    );
}

#[test]
fn transient_properties_keep_literal_argv_and_process_ownership_contract() {
    let mut request = SystemdService::new(
        SystemdUnitName::new("syrox-test.service").unwrap(),
        "/usr/bin/printf".into(),
    );
    request.arguments = vec!["$HOME %i ; not a shell".into()];
    request
        .environment
        .insert("LANG".into(), "C.UTF-8".into());
    request.runtime_max = Some(Duration::from_secs(60));
    request.memory_max = Some(128 * 1024 * 1024);
    request.tasks_max = Some(32);
    let values: BTreeMap<_, _> = service(&request).unwrap().into_iter().collect();
    assert_eq!(values["Type"], Value::String("exec".into()));
    assert_eq!(values["ExitType"], Value::String("cgroup".into()));
    assert_eq!(
        values["KillMode"],
        Value::String("control-group".into())
    );
    assert_eq!(values["TimeoutStopUSec"], Value::U64(2_000_000));
    assert_eq!(values["RuntimeMaxUSec"], Value::U64(60_000_000));
    let Value::Exec {
        executable,
        argv,
    } = &values["ExecStartEx"]
    else {
        panic!("typed execution property")
    };
    assert_eq!(executable, "/usr/bin/printf");
    assert_eq!(
        argv,
        &[
            "/usr/bin/printf",
            "$HOME %i ; not a shell"
        ]
    );
    assert_eq!(values["ExecStartEx"].signature(), "a(sasas)");
}

#[test]
fn malformed_arguments_environment_and_timeouts_are_rejected_before_ipc() {
    let mut request = SystemdService::new(
        SystemdUnitName::new("syrox-test.service").unwrap(),
        "/usr/bin/true".into(),
    );
    request.arguments.push("nul\0".into());
    assert!(service(&request).is_err());
    request.arguments.clear();
    request
        .environment
        .insert("BAD=NAME".into(), "value".into());
    assert!(service(&request).is_err());
    request.environment.clear();
    request.arguments = vec!["x".repeat(4096); 17];
    assert!(service(&request).is_err());
    request.arguments.clear();
    request.stop_timeout = Duration::ZERO;
    assert!(service(&request).is_err());
    request.stop_timeout = Duration::from_secs(2);
    request.tasks_max = Some(u64::MAX);
    assert!(service(&request).is_err());
}

#[test]
fn bound_units_require_ordering_and_cannot_bind_to_themselves() {
    let unit = SystemdUnitName::new("syrox-member.service").unwrap();
    let owner = SystemdUnitName::new("syrox-owner.service").unwrap();
    let mut request = SystemdService::new(unit.clone(), "/declared/launcher".into());
    request.bound_to = Some(owner.clone());
    let values: BTreeMap<_, _> = service(&request).unwrap().into_iter().collect();
    assert_eq!(
        values["BindsTo"],
        Value::Strings(vec![owner.as_str().into()])
    );
    assert_eq!(
        values["After"],
        Value::Strings(vec![owner.as_str().into()])
    );
    assert_eq!(values["Restart"], Value::String("no".into()));
    request.bound_to = Some(unit);
    assert!(service(&request).is_err());
}

#[test]
fn accepted_job_identity_and_terminal_result_are_distinct() {
    assert!(valid_job_path("/org/freedesktop/systemd1/job/42"));
    for path in [
        "/org/freedesktop/systemd1/job/0",
        "/org/freedesktop/systemd1/job/042",
        "/org/freedesktop/systemd1/job/-1",
        "/wrong/42",
    ] {
        assert!(!valid_job_path(path));
    }
    assert_eq!(
        SystemdJobResult::parse("done".into()),
        SystemdJobResult::Done
    );
    assert_eq!(
        SystemdJobResult::parse("canceled".into()),
        SystemdJobResult::Cancelled
    );
    assert_eq!(
        SystemdJobResult::parse("new-result".into()),
        SystemdJobResult::Other("new-result".into())
    );
    assert!(!matches!(
        SystemdJobCompletion::Unobserved {
            status: None
        },
        SystemdJobCompletion::Observed {
            result: SystemdJobResult::Done,
            ..
        }
    ));
}

#[test]
fn cancellation_and_deadlines_are_checked_before_connect_or_mutation() {
    let token = Cancellation::default();
    assert!(Budget::new(Duration::ZERO, &token).is_err());
    assert!(Budget::new(MAX_OPERATION + Duration::from_secs(1), &token).is_err());
    token.cancel();
    assert!(matches!(
        SystemdManager::connect(
            SystemdScope::System,
            Duration::from_secs(1),
            &token
        ),
        Err(SystemdError::Cancelled)
    ));
    let error = SystemdError::MutationUncertain {
        unit: "syrox-test.service".into(),
        source: Box::new(SystemdError::Cancelled),
    };
    assert!(
        error
            .to_string()
            .contains("reconcile before replay")
    );
}

#[test]
#[ignore = "requires SYROX_SYSTEMD_USER_BUS, a real user systemd manager >=250, and authorized IPC"]
fn real_user_manager_start_query_reconnect_and_stop_gate() {
    let path = PathBuf::from(
        std::env::var_os("SYROX_SYSTEMD_USER_BUS").expect("explicit user bus socket"),
    );
    let token = Cancellation::default();
    let timeout = Duration::from_secs(5);
    let mut manager = SystemdManager::connect(
        SystemdScope::User {
            bus_socket: path,
        },
        timeout,
        &token,
    )
    .unwrap();
    let unit = SystemdUnitName::new(format!(
        "syrox-ipc-gate-{}-{}.service",
        std::process::id(),
        CONNECTION_ID.fetch_add(1, Ordering::Relaxed)
    ))
    .unwrap();
    let mut request = SystemdService::new(unit.clone(), "/usr/bin/sleep".into());
    request.arguments.push("30".into());
    request.runtime_max = Some(Duration::from_secs(30));
    let started = manager
        .start_transient(&request, timeout, &token)
        .unwrap();
    let result = || {
        assert!(matches!(
            manager
                .wait_job(&started, timeout, &token)
                .unwrap(),
            SystemdJobCompletion::Observed {
                result: SystemdJobResult::Done,
                ..
            }
        ));
        let status = manager
            .query(&unit, timeout, &token)
            .unwrap()
            .unwrap();
        assert_eq!(status.active_state, "active");
        assert_ne!(status.main_pid, 0);
        assert!(!status.control_group.is_empty());
        manager.reconnect(timeout, &token).unwrap();
        assert!(matches!(
            manager
                .wait_job(&started, timeout, &token)
                .unwrap(),
            SystemdJobCompletion::Unobserved {
                status: Some(_),
                ..
            }
        ));
    };
    // Always try cleanup even when a gate assertion fails; RuntimeMax is a second bound.
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(result));
    let stopped = manager
        .stop(&unit, timeout, &Cancellation::default())
        .unwrap();
    assert!(matches!(
        manager
            .wait_job(&stopped, timeout, &Cancellation::default())
            .unwrap(),
        SystemdJobCompletion::Observed {
            result: SystemdJobResult::Done,
            ..
        }
    ));
    if let Err(payload) = observed {
        std::panic::resume_unwind(payload);
    }
}

/// Provision an inert persistent oneshot unit separately. This gate intentionally
/// does not publish unit files or claim byte identity of the supplied definition.
#[test]
#[ignore = "requires explicit SYROX_SYSTEMD_USER_BUS and SYROX_SYSTEMD_PERSISTENT_UNIT inert oneshot fixture"]
fn real_persistent_unit_reload_start_and_completion_gate() {
    let socket = PathBuf::from(std::env::var_os("SYROX_SYSTEMD_USER_BUS").expect("explicit bus"));
    let unit = SystemdUnitName::new(
        std::env::var("SYROX_SYSTEMD_PERSISTENT_UNIT").expect("explicit inert unit"),
    )
    .unwrap();
    assert!(
        unit.as_str()
            .starts_with("syrox-persistent-gate-")
    );
    let cancellation = Cancellation::default();
    let timeout = Duration::from_secs(10);
    let mut manager = SystemdManager::connect(
        SystemdScope::User {
            bus_socket: socket,
        },
        timeout,
        &cancellation,
    )
    .unwrap();
    let identity = manager
        .observe_identity(timeout, &cancellation)
        .unwrap();
    if let Some(status) = manager
        .query(&unit, timeout, &cancellation)
        .unwrap()
    {
        assert_eq!(
            status.active_state, "inactive",
            "fixture must initially be inactive"
        );
    }
    manager.reload(timeout, &cancellation).unwrap();
    assert_eq!(
        manager
            .observe_identity(timeout, &cancellation)
            .unwrap(),
        identity
    );
    let job = manager
        .start_unit(&unit, timeout, &cancellation)
        .unwrap();
    assert!(matches!(
        manager
            .wait_job(&job, timeout, &cancellation)
            .unwrap(),
        SystemdJobCompletion::Observed {
            result: SystemdJobResult::Done
        }
    ));
    let status = manager
        .query(&unit, timeout, &cancellation)
        .unwrap();
    assert!(
        status.is_none_or(|status| status.active_state == "inactive" && status.main_pid == 0),
        "fixture must be an inert oneshot without RemainAfterExit"
    );
    manager.reconnect(timeout, &cancellation).unwrap();
    assert!(matches!(
        manager
            .wait_job(&job, timeout, &cancellation)
            .unwrap(),
        SystemdJobCompletion::Unobserved { .. }
    ));
}

#[test]
fn recorded_job_absence_requires_exact_typed_evidence() {
    let path = "/org/freedesktop/systemd1/job/42";
    assert!(!recorded_job_reply(path, Ok(path.into())).unwrap());
    assert!(
        recorded_job_reply(
            path,
            Ok("/org/freedesktop/systemd1/job/43".into())
        )
        .is_err()
    );
    for name in [
        "org.freedesktop.systemd1.NoSuchJob",
        "org.freedesktop.DBus.Error.UnknownObject",
        "org.freedesktop.DBus.Error.AccessDenied",
    ] {
        let result = recorded_job_reply(
            path,
            Err(SystemdError::Remote {
                name: name.into(),
                message: String::new(),
            }),
        );
        if name == "org.freedesktop.systemd1.NoSuchJob" {
            assert!(result.unwrap());
        } else {
            assert!(result.is_err());
        }
    }
    for invalid in [
        "/job/42",
        "/org/freedesktop/systemd1/job/0",
        "/org/freedesktop/systemd1/job/042",
        "/org/freedesktop/systemd1/job/4294967296",
    ] {
        assert!(job_id(invalid).is_none());
    }
}

#[test]
fn idle_unit_requires_no_job_and_strict_absence_evidence() {
    for active in [
        "inactive",
        "failed",
        "active",
        "activating",
        "deactivating",
    ] {
        for job in [
            (0, "/".into()),
            (1, "/org/freedesktop/systemd1/job/1".into()),
        ] {
            let snapshot = UnitIdleSnapshot {
                path: "/org/freedesktop/systemd1/unit/test".into(),
                active: active.into(),
                job,
            };
            assert_eq!(
                snapshot.idle(),
                matches!(active, "inactive" | "failed") && snapshot.job.0 == 0
            );
        }
    }
    for name in [
        "org.freedesktop.systemd1.NoSuchUnit",
        "org.freedesktop.DBus.Error.UnknownObject",
        "org.freedesktop.DBus.Error.AccessDenied",
    ] {
        let result = strict_unit_path(Err(SystemdError::Remote {
            name: name.into(),
            message: String::new(),
        }));
        if name == "org.freedesktop.systemd1.NoSuchUnit" {
            assert_eq!(result.unwrap(), None);
        } else {
            assert!(result.is_err());
        }
    }
    assert!(strict_unit_path(Ok("/org/freedesktop/systemd1/unit/".into())).is_err());
}

#[test]
fn native_build_limits_encode_quota_and_both_process_limits_without_changing_defaults() {
    let mut request = SystemdService::new(
        SystemdUnitName::new("syrox-build-limits.service").unwrap(),
        "/declared/worker".into(),
    );
    let baseline = service(&request).unwrap();
    for cpu_percent in [1, 100, 200, u32::MAX] {
        request.build_limits = Some(SystemdBuildLimits {
            cpu_percent,
            nofile: 4096,
            file_size: 8 * 1024 * 1024 * 1024,
        });
        let extended = service(&request).unwrap();
        assert_eq!(&extended[..baseline.len()], baseline);
        let values: BTreeMap<_, _> = extended
            .into_iter()
            .skip(baseline.len())
            .collect();
        assert_eq!(values.len(), 8);
        for (name, expected) in [
            (
                "CPUQuotaPerSecUSec",
                u64::from(cpu_percent) * 10_000,
            ),
            ("LimitNOFILE", 4096),
            ("LimitNOFILESoft", 4096),
            ("LimitFSIZE", 8 * 1024 * 1024 * 1024),
            ("LimitFSIZESoft", 8 * 1024 * 1024 * 1024),
            ("MemorySwapMax", 0),
            ("LimitCORE", 0),
            ("LimitCORESoft", 0),
        ] {
            assert_eq!(values[name], Value::U64(expected));
            assert_eq!(values[name].signature(), "t");
            assert!(!baseline.iter().any(|(key, _)| *key == name));
        }
    }
    request.build_limits = None;
    assert_eq!(service(&request).unwrap(), baseline);
}

#[test]
fn invalid_native_build_limits_are_refused_before_ipc() {
    let mut request = SystemdService::new(
        SystemdUnitName::new("syrox-build-limits.service").unwrap(),
        "/declared/worker".into(),
    );
    let valid = SystemdBuildLimits {
        cpu_percent: 100,
        nofile: 256,
        file_size: 1024,
    };
    for invalid in [
        SystemdBuildLimits {
            cpu_percent: 0,
            ..valid
        },
        SystemdBuildLimits {
            nofile: 0,
            ..valid
        },
        SystemdBuildLimits {
            nofile: u64::MAX,
            ..valid
        },
        SystemdBuildLimits {
            file_size: 0,
            ..valid
        },
        SystemdBuildLimits {
            file_size: u64::MAX,
            ..valid
        },
    ] {
        request.build_limits = Some(invalid);
        assert!(matches!(
            service(&request),
            Err(SystemdError::Invalid(_))
        ));
    }
}

#[test]
fn explicit_credentials_are_paired_numeric_and_default_to_no_transition() {
    let mut request = SystemdService::new(
        SystemdUnitName::new("syrox-credentials.service").unwrap(),
        "/declared/worker".into(),
    );
    assert!(
        !service(&request)
            .unwrap()
            .iter()
            .any(|(name, _)| matches!(*name, "User" | "Group"))
    );
    request.credentials = Some(SystemdCredentials {
        uid: 1000,
        gid: 1001,
    });
    let values: BTreeMap<_, _> = service(&request).unwrap().into_iter().collect();
    assert_eq!(values["User"], Value::String("1000".into()));
    assert_eq!(values["Group"], Value::String("1001".into()));
    for (uid, gid) in [
        (0, 1000),
        (1000, 0),
        (u32::MAX, 1000),
        (1000, u32::MAX),
    ] {
        request.credentials = Some(SystemdCredentials {
            uid,
            gid,
        });
        assert!(service(&request).is_err());
    }
}

#[test]
fn transient_restart_requires_owned_notify_and_keeps_start_limits_explicit() {
    let mut request = SystemdService::new(
        SystemdUnitName::new("syrox-restart.service").unwrap(),
        "/declared/launcher".into(),
    );
    assert_eq!(
        request.restart,
        crate::execution::restart::ProcessRestart::Never
    );
    request.restart = crate::execution::restart::ProcessRestart::OnFailure(
        crate::execution::restart::RestartLimits::new(2, 30, 4).unwrap(),
    );
    assert!(service(&request).is_err());
    request.profile = SystemdServiceProfile::Notify {
        fd_store_max: 1,
        start_timeout: Duration::from_secs(5),
    };
    assert!(service(&request).is_err());
    request.bound_to = Some(SystemdUnitName::new("syrox-owner.service").unwrap());
    let properties = service(&request).unwrap();
    let count = properties.len();
    let values: BTreeMap<_, _> = properties.into_iter().collect();
    assert_eq!(values.len(), count, "duplicate property names");
    assert_eq!(
        values["Restart"],
        Value::String("on-failure".into())
    );
    assert_eq!(values["RestartUSec"], Value::U64(2_000_000));
    assert_eq!(
        values["StartLimitIntervalUSec"],
        Value::U64(30_000_000)
    );
    assert_eq!(values["StartLimitBurst"], Value::U32(4));
    assert_eq!(
        values["StartLimitAction"],
        Value::String("none".into())
    );
    assert_eq!(
        values["FileDescriptorStorePreserve"],
        Value::String("no".into())
    );
    assert_eq!(
        values["RestartPreventExitStatus"],
        Value::ExitStatuses {
            codes: vec![78],
            signals: vec![]
        }
    );
    for name in [
        "RestartForceExitStatus",
        "SuccessExitStatus",
    ] {
        assert_eq!(
            values[name],
            Value::ExitStatuses {
                codes: vec![],
                signals: vec![]
            }
        );
    }
    request.profile = SystemdServiceProfile::Notify {
        fd_store_max: 2,
        start_timeout: Duration::from_secs(5),
    };
    assert!(service(&request).is_err());
    request.profile = SystemdServiceProfile::Notify {
        fd_store_max: 1,
        start_timeout: Duration::from_secs(5),
    };
    request.build_limits = Some(SystemdBuildLimits {
        cpu_percent: 100,
        nofile: 64,
        file_size: 1024,
    });
    assert!(
        service(&request).is_err(),
        "builds cannot opt into service restart"
    );
}

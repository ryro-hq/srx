use super::loaded::{Property, Value, observe};
use super::{
    Budget, SERVICE_INTERFACE, SystemdError, SystemdManager, SystemdManagerIdentity, SystemdScope,
    SystemdService, SystemdServiceProfile, SystemdUnitStatus, UNIT_INTERFACE,
};
use crate::{cancellation::Cancellation, store::ContentDigest, systemd::SystemdUnitName};
use std::time::Duration;

pub(crate) struct ObservedServiceUnit {
    pub(crate) manager: SystemdManagerIdentity,
    pub(crate) status: SystemdUnitStatus,
    pub(crate) contract: ContentDigest,
}
impl SystemdManager {
    pub(crate) fn observe_service_unit(
        &mut self,
        service: &SystemdService,
        unit: &SystemdUnitName,
        invocation: &[u8; 16],
        main_pid: u32,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<ObservedServiceUnit, SystemdError> {
        if service.unit != *unit {
            return Err(changed());
        }
        let expected = properties(service, &self.scope)?;
        let budget = Budget::new(timeout, cancellation)?;
        let manager = self.observe_identity_with(&budget)?;
        let before = self
            .query_with(&service.unit, &budget)?
            .ok_or_else(changed)?;
        validate_binding(&before, unit, invocation, main_pid)?;
        let mut call = self.bus.manager_method("GetUnit")?;
        call.string(service.unit.as_str())?;
        let path = self.bus.call(call, &budget)?.single_object()?;
        if !path.starts_with("/org/freedesktop/systemd1/unit/") {
            return Err(changed());
        }
        self.bus.watch_loaded(&path, &budget)?;
        let revision = self.bus.configuration_revision();
        let first = observe(self, &path, &expected, &budget)?;
        let second = observe(self, &path, &expected, &budget)?;
        let after = self
            .query_with(&service.unit, &budget)?
            .ok_or_else(changed)?;
        validate_binding(&after, unit, invocation, main_pid)?;
        validate_bracket(
            &before,
            &after,
            first == second,
            manager == self.observe_identity_with(&budget)?,
            revision == self.bus.configuration_revision(),
        )?;
        let mut bytes = b"syrox-observed-shell-service-v1\n".to_vec();
        bytes.extend(
            serde_json::to_vec(&(
                manager.fingerprint().to_string(),
                service.unit.as_str(),
                first,
            ))
            .map_err(|_| changed())?,
        );
        budget.check()?;
        Ok(ObservedServiceUnit {
            manager,
            status: after,
            contract: ContentDigest::sha256(&bytes),
        })
    }
}
fn changed() -> SystemdError {
    SystemdError::Protocol("Shell service contract or invocation differs or changed")
}
fn validate_binding(
    status: &SystemdUnitStatus,
    unit: &SystemdUnitName,
    invocation: &[u8; 16],
    main_pid: u32,
) -> Result<(), SystemdError> {
    if main_pid <= 1
        || status.unit != *unit
        || status.main_pid != main_pid
        || status.invocation != invocation
        || !matches!(
            status.active_state.as_str(),
            "activating" | "active"
        )
    {
        return Err(changed());
    }
    Ok(())
}
fn validate_bracket(
    before: &SystemdUnitStatus,
    after: &SystemdUnitStatus,
    properties_equal: bool,
    manager_equal: bool,
    revision_equal: bool,
) -> Result<(), SystemdError> {
    if !properties_equal
        || !manager_equal
        || !revision_equal
        || before.unit != after.unit
        || before.main_pid != after.main_pid
        || before.invocation != after.invocation
        || before.control_group != after.control_group
    {
        return Err(changed());
    }
    Ok(())
}
pub(super) fn properties(
    service: &SystemdService,
    scope: &SystemdScope,
) -> Result<Vec<Property>, SystemdError> {
    if !matches!(
        service.profile,
        SystemdServiceProfile::Notify {
            fd_store_max: 1,
            ..
        }
    ) || service.bound_to.is_none()
        || service.build_limits.is_some()
    {
        return Err(SystemdError::Invalid(
            "expected owner-bound Shell notify service with FD store capacity one",
        ));
    }
    let mut result = super::properties::observed_transient(service)?;
    // The request mapper checks explicit BindsTo exactly. After also contains
    // narrowly enumerated implicit dependencies; it is replaced below.
    result.retain(|property| property.name != "After");
    for (interface, name, expected) in [
        (
            UNIT_INTERFACE,
            "DropInPaths",
            Value::Strings(vec![]),
        ),
        (
            UNIT_INTERFACE,
            "DefaultDependencies",
            Value::Bool(true),
        ),
        (SERVICE_INTERFACE, "ControlPID", Value::U32(0)),
    ] {
        result.push(Property {
            interface,
            name,
            expected,
            extra: vec![],
        });
    }
    dependencies(service, scope, &mut result);
    Ok(result)
}
fn dependencies(service: &SystemdService, scope: &SystemdScope, result: &mut Vec<Property>) {
    // systemd v257 service_add_default_dependencies/unit_set_default_slice;
    // same bounded default dependency profile used by persistent Os contracts.
    // No arbitrary mounted-path or administrator-added unit is accepted.
    let system = matches!(scope, SystemdScope::System);
    let slice = if system {
        "system.slice"
    } else {
        "app.slice"
    };
    let owner = service
        .bound_to
        .as_ref()
        .expect("profile checked")
        .as_str();
    for (name, required, extra) in [
        (
            "Requires",
            vec![
                if system {
                    "sysinit.target"
                } else {
                    "basic.target"
                },
                slice,
            ],
            vec!["-.mount", "systemd-journald.socket"],
        ),
        (
            "After",
            if system {
                vec![
                    owner,
                    "sysinit.target",
                    "basic.target",
                    slice,
                ]
            } else {
                vec![owner, "basic.target", slice]
            },
            vec!["-.mount", "systemd-journald.socket"],
        ),
        (
            "Before",
            vec!["shutdown.target"],
            vec![if system {
                "multi-user.target"
            } else {
                "default.target"
            }],
        ),
        ("Conflicts", vec!["shutdown.target"], vec![]),
        ("Wants", vec![], vec!["systemd-journald.socket"]),
    ] {
        let mut required: Vec<String> = required.into_iter().map(str::to_owned).collect();
        required.sort();
        result.push(Property {
            interface: UNIT_INTERFACE,
            name,
            expected: Value::Strings(required),
            extra: extra.into_iter().map(str::to_owned).collect(),
        });
    }
    result.push(Property {
        interface: SERVICE_INTERFACE,
        name: "Slice",
        expected: Value::Text(slice.into()),
        extra: vec![],
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        execution::restart::ProcessRestart, execution::restart::RestartLimits,
        systemd::SystemdUnitName,
    };

    fn service() -> SystemdService {
        let mut service = SystemdService::new(
            SystemdUnitName::new("syrox-role-test.service").unwrap(),
            "/private/worker".into(),
        );
        service.profile = SystemdServiceProfile::Notify {
            fd_store_max: 1,
            start_timeout: Duration::from_secs(30),
        };
        service.bound_to = Some(SystemdUnitName::new("syrox-owner-test.service").unwrap());
        service
    }
    fn user() -> SystemdScope {
        SystemdScope::User {
            bus_socket: "/private/bus".into(),
        }
    }
    fn property<'a>(properties: &'a [Property], name: &str) -> &'a Property {
        properties
            .iter()
            .find(|property| property.name == name)
            .unwrap()
    }
    fn accepts(properties: &[Property], name: &str, value: &Value) -> bool {
        super::super::loaded::validate(property(properties, name), value).is_ok()
    }
    #[test]
    fn shell_restart_observation_checks_exact_emitted_policy_without_build_limits() {
        let mut service = service();
        service.restart = ProcessRestart::OnFailure(RestartLimits::new(2, 60, 3).unwrap());
        let properties = properties(&service, &user()).unwrap();
        for (name, value) in [
            ("Type", Value::Text("notify".into())),
            ("NotifyAccess", Value::Text("main".into())),
            ("FileDescriptorStoreMax", Value::U32(1)),
            (
                "FileDescriptorStorePreserve",
                Value::Text("no".into()),
            ),
            ("Restart", Value::Text("on-failure".into())),
            ("RestartUSec", Value::U64(2_000_000)),
            ("StartLimitIntervalUSec", Value::U64(60_000_000)),
            ("StartLimitBurst", Value::U32(3)),
            (
                "RestartPreventExitStatus",
                Value::ExitStatuses {
                    codes: vec![78],
                    signals: vec![],
                },
            ),
            (
                "RestartForceExitStatus",
                Value::ExitStatuses {
                    codes: vec![],
                    signals: vec![],
                },
            ),
            (
                "SuccessExitStatus",
                Value::ExitStatuses {
                    codes: vec![],
                    signals: vec![],
                },
            ),
        ] {
            assert!(accepts(&properties, name, &value), "{name}");
        }
        assert!(
            !properties
                .iter()
                .any(|property| property.name == "CPUQuotaPerSecUSec")
        );
        assert!(!accepts(
            &properties,
            "FileDescriptorStorePreserve",
            &Value::Text("restart".into())
        ));
        assert!(!accepts(
            &properties,
            "StartLimitBurst",
            &Value::U32(4)
        ));
        assert!(!accepts(
            &properties,
            "RestartPreventExitStatus",
            &Value::ExitStatuses {
                codes: vec![],
                signals: vec![libc::SIGTERM]
            }
        ));
        assert!(!accepts(
            &properties,
            "SuccessExitStatus",
            &Value::ExitStatuses {
                codes: vec![78],
                signals: vec![]
            }
        ));
        assert_eq!(
            property(&properties, "StartLimitBurst").interface,
            UNIT_INTERFACE
        );
    }
    #[test]
    fn never_preserves_existing_request_and_incompatible_profiles_are_refused() {
        let mut service = service();
        let properties = properties(&service, &user()).unwrap();
        assert!(accepts(
            &properties,
            "Restart",
            &Value::Text("no".into())
        ));
        assert!(
            !properties
                .iter()
                .any(|property| property.name == "FileDescriptorStorePreserve")
        );
        service.bound_to = None;
        assert!(super::properties(&service, &user()).is_err());
        service = self::service();
        service.profile = SystemdServiceProfile::Exec;
        assert!(super::properties(&service, &user()).is_err());
        service.profile = SystemdServiceProfile::Notify {
            fd_store_max: 2,
            start_timeout: Duration::from_secs(30),
        };
        assert!(super::properties(&service, &user()).is_err());
    }
    #[test]
    fn hooks_dropins_control_processes_and_foreign_dependencies_are_refused() {
        let service = service();
        let properties = properties(&service, &user()).unwrap();
        for name in [
            "ExecConditionEx",
            "ExecStartPreEx",
            "ExecStartPostEx",
            "ExecReloadEx",
            "ExecStopEx",
            "ExecStopPostEx",
        ] {
            assert!(accepts(
                &properties,
                name,
                &Value::Empty("a(sasasttttuii)".into())
            ));
            assert!(!accepts(
                &properties,
                name,
                &Value::Exec(vec![super::super::loaded::ExecSpec {
                    path: "/foreign/program".into(),
                    argv: vec!["program".into()],
                    flags: vec![],
                }])
            ));
        }
        assert!(!accepts(
            &properties,
            "DropInPaths",
            &Value::Strings(vec!["/foreign.conf".into()])
        ));
        assert!(!accepts(
            &properties,
            "ControlPID",
            &Value::U32(42)
        ));
        let Value::Strings(after) = &property(&properties, "After").expected else {
            panic!()
        };
        let mut allowed = after.clone();
        allowed.push("systemd-journald.socket".into());
        assert!(accepts(
            &properties,
            "After",
            &Value::Strings(allowed.clone())
        ));
        allowed.push("foreign.target".into());
        assert!(!accepts(
            &properties,
            "After",
            &Value::Strings(allowed)
        ));
        let mut missing = after.clone();
        missing.retain(|name| name != service.bound_to.as_ref().unwrap().as_str());
        assert!(!accepts(
            &properties,
            "After",
            &Value::Strings(missing)
        ));
        assert!(!accepts(
            &properties,
            "BindsTo",
            &Value::Strings(vec![])
        ));
    }
    #[test]
    fn scope_defaults_are_explicit_and_do_not_accept_the_other_scope() {
        let service = service();
        let user = properties(&service, &user()).unwrap();
        let system = properties(&service, &SystemdScope::System).unwrap();
        assert!(accepts(
            &user,
            "Slice",
            &Value::Text("app.slice".into())
        ));
        assert!(accepts(
            &system,
            "Slice",
            &Value::Text("system.slice".into())
        ));
        assert!(!accepts(
            &user,
            "Requires",
            &property(&system, "Requires").expected
        ));
        assert!(!accepts(
            &system,
            "After",
            &property(&user, "After").expected
        ));
    }
    fn status() -> (SystemdUnitStatus, SystemdUnitName, [u8; 16]) {
        let unit = service().unit;
        let invocation = [7; 16];
        (
            SystemdUnitStatus {
                unit: unit.clone(),
                invocation: invocation.to_vec(),
                active_state: "activating".into(),
                sub_state: "start".into(),
                control_group: "/user/test".into(),
                result: "success".into(),
                main_pid: 42,
                exec_main_code: 0,
                exec_main_status: 0,
            },
            unit,
            invocation,
        )
    }
    #[test]
    fn invocation_pid_and_configuration_drift_are_refused() {
        let (before, unit, invocation) = status();
        validate_binding(&before, &unit, &invocation, 42).unwrap();
        assert!(validate_binding(&before, &unit, &invocation, 43).is_err());
        assert!(validate_binding(&before, &unit, &invocation, 1).is_err());
        for field in [0, 1, 2, 3] {
            let mut after = before.clone();
            match field {
                0 => after.invocation[0] = 8,
                1 => after.main_pid = 43,
                2 => after.control_group.push_str("-other"),
                _ => after.unit = SystemdUnitName::new("syrox-other.service").unwrap(),
            }
            assert!(validate_bracket(&before, &after, true, true, true).is_err());
        }
        for flags in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            assert!(validate_bracket(&before, &before, flags.0, flags.1, flags.2).is_err());
        }
        let mut inactive = before.clone();
        inactive.active_state = "inactive".into();
        assert!(validate_binding(&inactive, &unit, &invocation, 42).is_err());
        validate_bracket(&before, &before, true, true, true).unwrap();
    }
}

use super::loaded::observe;
use super::properties::observed_transient;
use super::{
    Budget, SystemdError, SystemdManager, SystemdManagerIdentity, SystemdService, SystemdUnitStatus,
};
use crate::{cancellation::Cancellation, store::ContentDigest};
use std::time::Duration;

pub(crate) struct ObservedBuildUnit {
    pub(crate) manager: SystemdManagerIdentity,
    pub(crate) status: SystemdUnitStatus,
    pub(crate) contract: ContentDigest,
}
impl SystemdManager {
    pub(crate) fn observe_build_unit(
        &mut self,
        service: &SystemdService,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<ObservedBuildUnit, SystemdError> {
        let expected = observed_transient(service)?;
        let budget = Budget::new(timeout, cancellation)?;
        let manager = self.observe_identity_with(&budget)?;
        let before = self
            .query_with(&service.unit, &budget)?
            .ok_or_else(changed)?;
        active_binding(&before)?;
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
        active_binding(&after)?;
        if first != second
            || !same_binding(&before, &after)
            || self.observe_identity_with(&budget)? != manager
            || self.bus.configuration_revision() != revision
        {
            return Err(changed());
        }
        let mut bytes = b"syrox-observed-build-unit-v1\n".to_vec();
        bytes.extend(serde_json::to_vec(&first).map_err(|_| changed())?);
        budget.check()?;
        Ok(ObservedBuildUnit {
            manager,
            status: after,
            contract: ContentDigest::sha256(&bytes),
        })
    }
}
fn changed() -> SystemdError {
    SystemdError::Protocol("build unit observation differs or changed")
}
fn active_binding(status: &SystemdUnitStatus) -> Result<(), SystemdError> {
    if status.main_pid <= 1
        || status.invocation.len() != 16
        || status.invocation.iter().all(|byte| *byte == 0)
        || !matches!(
            status.active_state.as_str(),
            "activating" | "active"
        )
    {
        return Err(changed());
    }
    Ok(())
}
fn same_binding(first: &SystemdUnitStatus, second: &SystemdUnitStatus) -> bool {
    first.unit == second.unit
        && first.main_pid == second.main_pid
        && first.invocation == second.invocation
        && first.control_group == second.control_group
}

#[cfg(test)]
use super::{SERVICE_INTERFACE, loaded::Value};
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        systemd::SystemdBuildLimits, systemd::SystemdServiceProfile, systemd::SystemdUnitName,
    };
    #[test]
    fn build_contract_requires_native_limits_and_no_extra_exec_hooks() {
        let mut service = SystemdService::new(
            SystemdUnitName::new("syrox-build-test.service").unwrap(),
            "/private/worker".into(),
        );
        service.profile = SystemdServiceProfile::Notify {
            fd_store_max: 1,
            start_timeout: Duration::from_secs(30),
        };
        service.build_limits = Some(SystemdBuildLimits {
            cpu_percent: 200,
            nofile: 4096,
            file_size: 1024,
        });
        let observed = observed_transient(&service).unwrap();
        let value = |name| {
            &observed
                .iter()
                .find(|p| p.name == name)
                .unwrap()
                .expected
        };
        assert_eq!(
            value("CPUQuotaPerSecUSec"),
            &Value::U64(2_000_000)
        );
        assert_eq!(value("FileDescriptorStoreMax"), &Value::U32(1));
        assert_eq!(
            value("FileDescriptorStorePreserve"),
            &Value::Text("no".into())
        );
        assert_eq!(
            observed
                .iter()
                .find(|p| p.name == "FileDescriptorStorePreserve")
                .unwrap()
                .interface,
            SERVICE_INTERFACE
        );
        assert_eq!(value("Transient"), &Value::Bool(true));
        assert_eq!(
            value("EnvironmentFiles"),
            &Value::Empty("a(sb)".into())
        );
        assert_eq!(
            value("ExecStartPreEx"),
            &Value::Empty("a(sasasttttuii)".into())
        );
    }
    #[test]
    fn inactive_missing_pid_and_changed_invocation_are_not_a_build_binding() {
        let status = SystemdUnitStatus {
            unit: SystemdUnitName::new("syrox-build-test.service").unwrap(),
            invocation: vec![1; 16],
            active_state: "activating".into(),
            sub_state: "start".into(),
            control_group: "/user/test".into(),
            result: "success".into(),
            main_pid: 42,
            exec_main_code: 0,
            exec_main_status: 0,
        };
        active_binding(&status).unwrap();
        let mut changed = status.clone();
        changed.invocation[0] = 2;
        assert!(!same_binding(&status, &changed));
        changed = status.clone();
        changed.main_pid = 43;
        assert!(!same_binding(&status, &changed));
        changed = status.clone();
        changed.active_state = "inactive".into();
        assert!(active_binding(&changed).is_err());
        changed = status.clone();
        changed.main_pid = 0;
        assert!(active_binding(&changed).is_err());
        changed = status;
        changed.invocation.fill(0);
        assert!(active_binding(&changed).is_err());
    }

    #[test]
    fn observed_credentials_are_exact_and_not_duplicated_by_empty_defaults() {
        let mut service = SystemdService::new(
            SystemdUnitName::new("syrox-build-test.service").unwrap(),
            "/private/worker".into(),
        );
        service.credentials = Some(crate::systemd::SystemdCredentials {
            uid: 1000,
            gid: 1001,
        });
        let observed = observed_transient(&service).unwrap();
        for (name, expected) in [("User", "1000"), ("Group", "1001")] {
            let matching: Vec<_> = observed
                .iter()
                .filter(|property| property.name == name)
                .collect();
            assert_eq!(matching.len(), 1);
            assert_eq!(matching[0].expected, Value::Text(expected.into()));
        }
    }

    #[test]
    fn shell_notify_does_not_inherit_build_fdstore_policy() {
        let mut service = SystemdService::new(
            SystemdUnitName::new("syrox-shell-policy.service").unwrap(),
            "/private/worker".into(),
        );
        service.profile = SystemdServiceProfile::Notify {
            fd_store_max: 1,
            start_timeout: Duration::from_secs(30),
        };
        assert!(
            !super::super::properties::service(&service)
                .unwrap()
                .iter()
                .any(|(name, _)| *name == "FileDescriptorStorePreserve")
        );
    }
}

use super::{AttemptId, AttemptPhase, OwnershipError, SessionJournal, record, roles, storage};
use crate::execution::service_evidence::{
    CapturedServiceLauncher, CapturedServiceProcesses, ObservedSessionOwnerAlive,
};
use crate::platform::linux::fd::persisted_namespace::{LauncherRecord, NamespaceRecord};
use crate::{cancellation::Cancellation, store::ContentDigest};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceProcessRecord {
    #[serde(with = "manager_pin")]
    pub(crate) manager: ContentDigest,
    pub(crate) launcher: LauncherRecord,
    #[serde(deserialize_with = "required_option")]
    pub(crate) namespace: Option<NamespaceRecord>,
    pub(crate) gate_used: bool,
}
pub(super) fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
impl ServiceProcessRecord {
    pub(crate) fn from_captured(captured: &CapturedServiceProcesses) -> Self {
        Self {
            manager: captured.manager().fingerprint(),
            launcher: captured.launcher_record().clone(),
            namespace: Some(captured.namespace_record().clone()),
            gate_used: true,
        }
    }
}
mod manager_pin {
    use crate::store::ContentDigest;
    use serde::{Deserialize as _, Deserializer, Serializer};
    pub(super) fn serialize<S: Serializer>(
        value: &ContentDigest,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ContentDigest, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}
impl SessionJournal {
    /// Persist the independently authenticated launcher before sending the
    /// attempt challenge. No serialized record supplied by a caller is admitted.
    pub(crate) fn authorize_service_attempt(
        &self,
        captured: &CapturedServiceLauncher,
        owner: &ObservedSessionOwnerAlive,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), OwnershipError> {
        let _authority = self.storage.lock(cancel, deadline)?;
        let role = captured.role();
        let (directory, mut state) = self.load(role.session())?;
        roles::require_owner(&state, role, owner)?;
        roles::retention::require_retained(&state, captured.attempt())?;
        let binding = record::Binding::from(captured.binding());
        if state
            .attempts
            .values()
            .any(|attempt| attempt.binding.as_ref() == Some(&binding))
        {
            return Err(invalid());
        }
        require_role(&state, role, captured.attempt())?;
        let entry = state
            .attempts
            .get_mut(captured.attempt().as_str())
            .ok_or_else(invalid)?;
        if entry.phase != AttemptPhase::Prepared
            || entry.binding.is_some()
            || entry.service_processes.is_some()
        {
            return Err(invalid());
        }
        captured.revalidate(cancel, deadline)?;
        entry.binding = Some(binding);
        entry.phase = AttemptPhase::Authorized;
        entry.service_processes = Some(ServiceProcessRecord {
            manager: captured.manager().fingerprint(),
            launcher: captured.launcher_record().clone(),
            namespace: None,
            gate_used: false,
        });
        if state.phase == super::SessionPhase::Pending {
            state.phase = super::SessionPhase::Authorized;
        }
        state.advance()?;
        storage::check(cancel, deadline)?;
        owner.revalidate()?;
        self.storage
            .write(directory.fd(), "state", &state.encode()?)
    }

    /// Persist the exact namespace and consume the gate before the single bounded
    /// send. A failed callback may have delivered COMMIT and is never replayed.
    pub(crate) fn with_service_namespace_gate<T>(
        &self,
        captured: &CapturedServiceProcesses,
        owner: &ObservedSessionOwnerAlive,
        cancel: &Cancellation,
        deadline: Instant,
        action: impl FnOnce() -> std::io::Result<T>,
    ) -> Result<T, OwnershipError> {
        let _authority = self.storage.lock(cancel, deadline)?;
        let role = captured.role();
        let (directory, mut state) = self.load(role.session())?;
        roles::require_owner(&state, role, owner)?;
        roles::retention::require_retained(&state, captured.attempt())?;
        require_role(&state, role, captured.attempt())?;
        let entry = state
            .attempts
            .get_mut(captured.attempt().as_str())
            .ok_or_else(invalid)?;
        if entry.phase != AttemptPhase::Consumed
            || entry.binding.as_ref() != Some(&record::Binding::from(captured.binding()))
        {
            return Err(invalid());
        }
        let processes = entry
            .service_processes
            .as_mut()
            .ok_or_else(invalid)?;
        if processes.gate_used
            || processes.namespace.is_some()
            || processes.launcher != *captured.launcher_record()
            || processes.manager != captured.manager().fingerprint()
        {
            return Err(invalid());
        }
        captured.revalidate(cancel, deadline)?;
        processes.namespace = Some(captured.namespace_record().clone());
        processes.gate_used = true;
        state.advance()?;
        storage::check(cancel, deadline)?;
        owner.revalidate()?;
        self.storage
            .write(directory.fd(), "state", &state.encode()?)?;
        // The save may take time. Revalidate at the last boundary; failure keeps
        // the gate spent and the immutable evidence for conservative recovery.
        captured.revalidate(cancel, deadline)?;
        owner.revalidate()?;
        storage::check(cancel, deadline)?;
        Ok(action()?)
    }
}
fn invalid() -> OwnershipError {
    OwnershipError::State("service process admission evidence differs or was used")
}
fn require_role(
    state: &record::Record,
    expected: &super::RoleBinding,
    attempt: &AttemptId,
) -> Result<(), OwnershipError> {
    let role = state
        .roles
        .get(expected.name())
        .ok_or_else(invalid)?;
    if role.binding()? != *expected || role.head != attempt.as_str() || !role.authorized {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn refuse_generic(
    state: &record::Record,
    attempt: &AttemptId,
) -> Result<(), OwnershipError> {
    let entry = state
        .attempts
        .get(attempt.as_str())
        .ok_or_else(invalid)?;
    if state.roles.contains_key(&entry.role) {
        return Err(OwnershipError::State(
            "registered service role requires captured process admission",
        ));
    }
    Ok(())
}
pub(super) fn require_consumable(
    state: &record::Record,
    attempt: &AttemptId,
) -> Result<(), OwnershipError> {
    let entry = state
        .attempts
        .get(attempt.as_str())
        .ok_or_else(invalid)?;
    if state.roles.contains_key(&entry.role) {
        let processes = entry
            .service_processes
            .as_ref()
            .ok_or_else(invalid)?;
        if processes.gate_used || processes.namespace.is_some() {
            return Err(invalid());
        }
    }
    Ok(())
}
pub(super) fn validate(state: &record::Record) -> Result<(), OwnershipError> {
    for attempt in state.attempts.values() {
        let service = state.roles.contains_key(&attempt.role);
        if let Some(processes) = &attempt.service_processes {
            if !service || attempt.binding.is_none() || attempt.phase == AttemptPhase::Prepared {
                return Err(invalid());
            }
            processes.launcher.validate()?;
            if processes.gate_used != processes.namespace.is_some() {
                return Err(invalid());
            }
            if processes.gate_used
                && !matches!(
                    attempt.phase,
                    AttemptPhase::Consumed | AttemptPhase::Settled
                )
            {
                return Err(invalid());
            }
            if let Some(namespace) = &processes.namespace {
                namespace.validate()?;
                if namespace.boot() != processes.launcher.boot() {
                    return Err(invalid());
                }
            }
        } else if service
            && matches!(
                attempt.phase,
                AttemptPhase::Authorized | AttemptPhase::Consumed | AttemptPhase::Settled
            )
        {
            return Err(invalid());
        }
        if service
            && attempt.phase == AttemptPhase::Settled
            && !attempt
                .service_processes
                .as_ref()
                .is_some_and(|processes| processes.gate_used)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! These are codec/classification tests, not constructed exit capabilities.
    use super::*;

    fn encoded_launcher() -> serde_json::Value {
        serde_json::json!({
            "role": "launcher",
            "inventory_version": 1,
            "process": {
                "boot": "11111111-1111-1111-1111-111111111111",
                "observer_init": {"device": 1, "inode": 1},
                "pid": 2,
                "init": {"device": 1, "inode": 2},
                "start": 1
            }
        })
    }
    fn encoded_processes() -> serde_json::Value {
        serde_json::json!({
            "manager": ContentDigest::sha256(b"manager").to_string(),
            "launcher": encoded_launcher(),
            "namespace": null,
            "gate_used": false
        })
    }
    #[test]
    fn service_record_requires_all_fields_and_canonical_manager_pin() {
        let value = encoded_processes();
        let decoded: ServiceProcessRecord = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        for key in [
            "manager",
            "launcher",
            "namespace",
            "gate_used",
        ] {
            let mut incomplete = value.clone();
            incomplete.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<ServiceProcessRecord>(incomplete).is_err());
        }
        for pin in [
            "x".to_owned(),
            "A".repeat(64),
            "0".repeat(65),
        ] {
            let mut malformed = value.clone();
            malformed["manager"] = pin.into();
            assert!(serde_json::from_value::<ServiceProcessRecord>(malformed).is_err());
        }
        let mut extra = value;
        extra["settled"] = true.into();
        assert!(serde_json::from_value::<ServiceProcessRecord>(extra).is_err());
    }
}

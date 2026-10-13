use super::super::{AttemptId, AttemptPhase, OwnershipError, SessionJournal, record, storage};
use super::{RoleBinding, RoleRecord, invalid, require_owner};
use crate::execution::service_evidence::{
    ObservedServiceAttemptSettlement, ObservedSessionOwnerAlive,
};
use crate::store::DurableInterest;
use crate::{cancellation::Cancellation, store::ContentDigest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RoleRetentionIdentity {
    pub(crate) first: AttemptId,
    pub(crate) pin: ContentDigest,
    pub(crate) store_anchor: ContentDigest,
}
impl RoleRetentionIdentity {
    pub(crate) fn new(first: AttemptId, pin: ContentDigest, store_anchor: ContentDigest) -> Self {
        Self {
            first,
            pin,
            store_anchor,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RoleRetentionPhase {
    Unprepared,
    Intent,
    Retained,
    Retiring,
    Retired,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RoleRetentionSnapshot {
    pub(crate) phase: RoleRetentionPhase,
    pub(crate) identity: Option<RoleRetentionIdentity>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetentionRecord {
    phase: RoleRetentionPhase,
    identity: Option<StoredIdentity>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIdentity {
    first: String,
    pin: String,
    store_anchor: String,
}
impl StoredIdentity {
    fn from_identity(value: &RoleRetentionIdentity) -> Self {
        Self {
            first: value.first.to_string(),
            pin: value.pin.to_string(),
            store_anchor: value.store_anchor.to_string(),
        }
    }
    fn data(&self) -> Result<RoleRetentionIdentity, OwnershipError> {
        let result = RoleRetentionIdentity::new(
            AttemptId::parse(&self.first)?,
            self.pin.parse().map_err(|_| invalid())?,
            self.store_anchor.parse().map_err(|_| invalid())?,
        );
        if Self::from_identity(&result) != *self {
            return Err(invalid());
        }
        Ok(result)
    }
}
impl RetentionRecord {
    pub(super) fn unprepared() -> Self {
        Self {
            phase: RoleRetentionPhase::Unprepared,
            identity: None,
        }
    }
    pub(super) fn snapshot(&self) -> Result<RoleRetentionSnapshot, OwnershipError> {
        Ok(RoleRetentionSnapshot {
            phase: self.phase,
            identity: self
                .identity
                .as_ref()
                .map(StoredIdentity::data)
                .transpose()?,
        })
    }
    fn identity(&self) -> Result<RoleRetentionIdentity, OwnershipError> {
        self.identity.as_ref().ok_or_else(invalid)?.data()
    }
}

impl SessionJournal {
    /// Intent precedes publication. The identity cannot be retargeted, even if
    /// the publication result is lost. This method is not execution admission.
    pub(crate) fn begin_role_retention(
        &self,
        role: &RoleBinding,
        identity: &RoleRetentionIdentity,
        owner: &ObservedSessionOwnerAlive,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), OwnershipError> {
        let _authority = self.storage.lock(cancel, deadline)?;
        let (directory, mut state) = self.load(role.session())?;
        require_owner(&state, role, owner)?;
        let entry = state
            .roles
            .get_mut(role.name())
            .ok_or_else(invalid)?;
        if entry.binding()? != *role
            || entry.retention.phase != RoleRetentionPhase::Unprepared
            || entry.head != identity.first.as_str()
        {
            return Err(invalid());
        }
        let first = state
            .attempts
            .get(identity.first.as_str())
            .ok_or_else(invalid)?;
        if first.role != role.name()
            || first.phase != AttemptPhase::Prepared
            || first.predecessor.is_some()
        {
            return Err(invalid());
        }
        entry.retention = RetentionRecord {
            phase: RoleRetentionPhase::Intent,
            identity: Some(StoredIdentity::from_identity(identity)),
        };
        state.advance()?;
        storage::check(cancel, deadline)?;
        owner.revalidate()?;
        self.storage
            .write(directory.fd(), "state", &state.encode()?)
    }

    /// Confirmation consumes an actual published hold's identity, not a caller
    /// assertion that publication succeeded. Uncertain publication stays Intent.
    pub(crate) fn confirm_role_retention(
        &self,
        role: &RoleBinding,
        hold: &DurableInterest,
        owner: &ObservedSessionOwnerAlive,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), OwnershipError> {
        let _authority = self.storage.lock(cancel, deadline)?;
        let (directory, mut state) = self.load(role.session())?;
        require_owner(&state, role, owner)?;
        let entry = state
            .roles
            .get_mut(role.name())
            .ok_or_else(invalid)?;
        if entry.binding()? != *role || entry.retention.phase != RoleRetentionPhase::Intent {
            return Err(invalid());
        }
        matches_hold(&entry.retention.identity()?, hold)?;
        hold.verify_current_checked(|| {
            if cancel.is_cancelled() || Instant::now() >= deadline {
                return Err(std::io::Error::other(
                    "role retention confirmation interrupted",
                ));
            }
            Ok(())
        })
        .map_err(OwnershipError::Store)?;
        entry.retention.phase = RoleRetentionPhase::Retained;
        state.advance()?;
        storage::check(cancel, deadline)?;
        owner.revalidate()?;
        self.storage
            .write(directory.fd(), "state", &state.encode()?)
    }

    /// The caller also reconciles manager idle state. Every historical attempt
    /// must independently carry genuine launcher/init exit evidence. Retiring
    /// remains durable on any removal or journal failure; absence is not success.
    pub(crate) fn retire_role_retention(
        &self,
        role: &RoleBinding,
        proofs: &[ObservedServiceAttemptSettlement],
        hold: DurableInterest,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), OwnershipError> {
        let _authority = self.storage.lock(cancel, deadline)?;
        let (directory, mut state) = self.load(role.session())?;
        if state.phase != super::super::SessionPhase::Closing {
            return Err(invalid());
        }
        let entry = state.roles.get(role.name()).ok_or_else(invalid)?;
        if entry.binding()? != *role
            || entry.authorized
            || entry.retention.phase != RoleRetentionPhase::Retained
        {
            return Err(invalid());
        }
        matches_hold(&entry.retention.identity()?, &hold)?;
        validate_proofs(&state, role, proofs)?;
        state
            .roles
            .get_mut(role.name())
            .ok_or_else(invalid)?
            .retention
            .phase = RoleRetentionPhase::Retiring;
        state.advance()?;
        storage::check(cancel, deadline)?;
        self.storage
            .write(directory.fd(), "state", &state.encode()?)?;
        hold.retire_checked(|| {
            if cancel.is_cancelled() || Instant::now() >= deadline {
                return Err(std::io::Error::other(
                    "role retention retirement interrupted",
                ));
            }
            Ok(())
        })
        .map_err(OwnershipError::Store)?;
        let entry = state
            .roles
            .get_mut(role.name())
            .ok_or_else(invalid)?;
        entry.retention.phase = RoleRetentionPhase::Retired;
        let head = entry.head.clone();
        state
            .attempts
            .get_mut(&head)
            .ok_or_else(invalid)?
            .phase = AttemptPhase::Settled;
        state.advance()?;
        storage::check(cancel, deadline)?;
        self.storage
            .write(directory.fd(), "state", &state.encode()?)
    }
}
fn matches_hold(
    identity: &RoleRetentionIdentity,
    hold: &DurableInterest,
) -> Result<(), OwnershipError> {
    if hold.execution() != identity.first.as_str()
        || hold.digest() != identity.pin
        || hold.store_anchor() != identity.store_anchor
    {
        return Err(invalid());
    }
    Ok(())
}
fn validate_proofs(
    state: &record::Record,
    role: &RoleBinding,
    proofs: &[ObservedServiceAttemptSettlement],
) -> Result<(), OwnershipError> {
    let attempts: Vec<_> = state
        .attempts
        .iter()
        .filter(|(_, attempt)| attempt.role == role.name())
        .collect();
    if attempts.is_empty() || attempts.len() != proofs.len() {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    for proof in proofs {
        if proof.role() != role || !seen.insert(proof.attempt().as_str()) {
            return Err(invalid());
        }
        let attempt = state
            .attempts
            .get(proof.attempt().as_str())
            .ok_or_else(invalid)?;
        if attempt.role != role.name()
            || !matches!(
                attempt.phase,
                AttemptPhase::Consumed | AttemptPhase::Settled
            )
            || attempt.binding.as_ref() != Some(&record::Binding::from(proof.binding()))
            || attempt
                .service_processes
                .as_ref()
                .is_none_or(|records| !records.gate_used || !proof.matches_processes(records))
        {
            return Err(invalid());
        }
    }
    if attempts
        .iter()
        .any(|(id, _)| !seen.contains(id.as_str()))
    {
        return Err(invalid());
    }
    Ok(())
}
/// Enforced by generic authorize/consume/gate callers, but never sufficient for
/// execution without their independent owner/binding/revocation checks.
pub(in crate::execution::journal) fn require_retained(
    state: &record::Record,
    attempt: &AttemptId,
) -> Result<(), OwnershipError> {
    let attempt = state
        .attempts
        .get(attempt.as_str())
        .ok_or_else(invalid)?;
    if let Some(role) = state.roles.get(&attempt.role)
        && role.retention.phase != RoleRetentionPhase::Retained
    {
        return Err(OwnershipError::State(
            "service role lacks confirmed durable retention",
        ));
    }
    Ok(())
}
pub(super) fn validate(
    state: &record::Record,
    role: &RoleRecord,
    first: &str,
) -> Result<(), OwnershipError> {
    let retention = role.retention.snapshot()?;
    if state.phase == super::super::SessionPhase::Closed
        && retention.phase != RoleRetentionPhase::Retired
    {
        return Err(invalid());
    }
    if (retention.phase == RoleRetentionPhase::Unprepared) != retention.identity.is_none() {
        return Err(invalid());
    }
    if let Some(identity) = retention.identity
        && identity.first.as_str() != first
    {
        return Err(invalid());
    }
    let attempts = || {
        state
            .attempts
            .values()
            .filter(|attempt| attempt.role == role.name)
    };
    match retention.phase {
        RoleRetentionPhase::Unprepared | RoleRetentionPhase::Intent => {
            if role.head != first
                || attempts().any(|attempt| {
                    !matches!(
                        attempt.phase,
                        AttemptPhase::Prepared | AttemptPhase::Revoked
                    )
                })
            {
                return Err(invalid());
            }
        }
        RoleRetentionPhase::Retained => {}
        RoleRetentionPhase::Retiring | RoleRetentionPhase::Retired => {
            if !matches!(
                state.phase,
                super::super::SessionPhase::Closing | super::super::SessionPhase::Closed
            ) || attempts().any(|attempt| {
                !matches!(
                    attempt.phase,
                    AttemptPhase::Consumed | AttemptPhase::Settled
                )
            }) {
                return Err(invalid());
            }
            if retention.phase == RoleRetentionPhase::Retired
                && attempts().any(|attempt| attempt.phase != AttemptPhase::Settled)
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::journal::{AttemptBinding, SessionId};
    use crate::{execution::restart::ProcessRestart, systemd::SystemdUnitName};

    fn fixture() -> (record::Record, RoleBinding, AttemptId) {
        let session = SessionId::parse(&"1".repeat(32)).unwrap();
        let first = AttemptId::parse(&"2".repeat(32)).unwrap();
        let owner_id = AttemptId::parse(&"3".repeat(32)).unwrap();
        let pin = ContentDigest::sha256(b"manifest");
        let owner = AttemptBinding::new(
            SystemdUnitName::new("syrox-owner.service").unwrap(),
            [1; 16],
        )
        .unwrap();
        let role = RoleBinding::new(
            session.clone(),
            "service",
            pin,
            pin,
            SystemdUnitName::new("syrox-service.service").unwrap(),
            owner.clone(),
            ProcessRestart::Never,
        )
        .unwrap();
        let mut attempts = std::collections::BTreeMap::new();
        attempts.insert(
            owner_id.to_string(),
            record::Attempt {
                role: "owner".into(),
                phase: AttemptPhase::Consumed,
                binding: Some((&owner).into()),
                predecessor: None,
                service_processes: None,
            },
        );
        attempts.insert(
            first.to_string(),
            record::Attempt {
                role: role.name().into(),
                phase: AttemptPhase::Prepared,
                binding: None,
                predecessor: None,
                service_processes: None,
            },
        );
        let mut roles = std::collections::BTreeMap::new();
        roles.insert(
            role.name().into(),
            RoleRecord::from_binding(&role, &first),
        );
        (
            record::Record {
                session: session.to_string(),
                manifest: pin.to_string(),
                phase: record::SessionPhase::Running,
                revision: 0,
                reason: None,
                attempts,
                roles,
                executions: std::collections::BTreeMap::new(),
            },
            role,
            first,
        )
    }
    fn identity(first: &AttemptId) -> StoredIdentity {
        StoredIdentity::from_identity(&RoleRetentionIdentity::new(
            first.clone(),
            ContentDigest::sha256(b"hold"),
            ContentDigest::sha256(b"store"),
        ))
    }
    #[test]
    fn mandatory_retention_and_first_attempt_binding_are_validated() {
        let (mut state, role, first) = fixture();
        let canonical = state.encode().unwrap();
        record::Record::parse(&canonical).unwrap();
        let mut json = serde_json::to_value(&state).unwrap();
        json["roles"][role.name()]
            .as_object_mut()
            .unwrap()
            .remove("retention");
        assert!(serde_json::from_value::<record::Record>(json).is_err());
        let entry = state.roles.get_mut(role.name()).unwrap();
        entry.retention = RetentionRecord {
            phase: RoleRetentionPhase::Intent,
            identity: Some(identity(&first)),
        };
        state.encode().unwrap();
        state
            .roles
            .get_mut(role.name())
            .unwrap()
            .retention
            .identity
            .as_mut()
            .unwrap()
            .first = "4".repeat(32);
        assert!(state.encode().is_err());
    }
    #[test]
    fn intent_cannot_admit_and_retirement_cannot_appear_in_open_session() {
        let (mut state, role, first) = fixture();
        assert!(require_retained(&state, &first).is_err());
        state
            .roles
            .get_mut(role.name())
            .unwrap()
            .retention = RetentionRecord {
            phase: RoleRetentionPhase::Intent,
            identity: Some(identity(&first)),
        };
        assert!(require_retained(&state, &first).is_err());
        state
            .roles
            .get_mut(role.name())
            .unwrap()
            .retention
            .phase = RoleRetentionPhase::Retained;
        require_retained(&state, &first).unwrap();
        for phase in [
            RoleRetentionPhase::Retiring,
            RoleRetentionPhase::Retired,
        ] {
            state
                .roles
                .get_mut(role.name())
                .unwrap()
                .retention
                .phase = phase;
            assert!(state.encode().is_err());
            assert!(require_retained(&state, &first).is_err());
        }
    }
    #[test]
    fn incomplete_history_and_empty_proofs_never_authorize_retirement() {
        let (state, role, _) = fixture();
        assert!(validate_proofs(&state, &role, &[]).is_err());
        let mut state = state;
        state.phase = record::SessionPhase::Closing;
        let entry = state.roles.get_mut(role.name()).unwrap();
        entry.authorized = false;
        entry.retention.phase = RoleRetentionPhase::Retiring;
        entry.retention.identity = Some(identity(&AttemptId::parse(&entry.head).unwrap()));
        // Prepared/Revoked is not evidence that no namespace exists.
        assert!(state.encode().is_err());
    }

    #[test]
    fn closed_session_refuses_every_unfinished_retention_phase() {
        for phase in [
            RoleRetentionPhase::Unprepared,
            RoleRetentionPhase::Intent,
            RoleRetentionPhase::Retained,
            RoleRetentionPhase::Retiring,
        ] {
            let (mut state, role, first) = fixture();
            state.phase = record::SessionPhase::Closed;
            state
                .attempts
                .get_mut(first.as_str())
                .unwrap()
                .phase = AttemptPhase::Revoked;
            let entry = state.roles.get_mut(role.name()).unwrap();
            entry.authorized = false;
            entry.retention.phase = phase;
            entry.retention.identity =
                (phase != RoleRetentionPhase::Unprepared).then(|| identity(&first));
            assert!(state.encode().is_err());
        }
    }

    #[test]
    fn registered_role_cannot_bypass_process_admission_or_omit_record_field() {
        let (state, role, first) = fixture();
        assert!(super::super::super::processes::refuse_generic(&state, &first).is_err());
        assert!(super::super::super::processes::require_consumable(&state, &first).is_err());
        let owner = state
            .attempts
            .iter()
            .find(|(_, entry)| entry.role == "owner")
            .unwrap()
            .0;
        super::super::super::processes::refuse_generic(&state, &AttemptId::parse(owner).unwrap())
            .unwrap();
        let mut value = serde_json::to_value(&state).unwrap();
        value["attempts"][first.as_str()]
            .as_object_mut()
            .unwrap()
            .remove("service_processes");
        assert!(serde_json::from_value::<record::Record>(value).is_err());
        assert!(state.roles.contains_key(role.name()));
    }

    #[test]
    fn authorized_and_consumed_roles_require_persisted_launcher_evidence() {
        let (mut state, role, first) = fixture();
        for phase in [
            AttemptPhase::Authorized,
            AttemptPhase::Consumed,
            AttemptPhase::Settled,
        ] {
            let entry = state.attempts.get_mut(first.as_str()).unwrap();
            entry.phase = phase;
            entry.binding = Some(record::Binding::from(
                &AttemptBinding::new(role.unit().clone(), [2; 16]).unwrap(),
            ));
            assert!(super::super::super::processes::validate(&state).is_err());
        }
    }
}

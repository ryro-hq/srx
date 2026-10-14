use super::{
    AttemptBinding, AttemptId, AttemptPhase, OwnershipError, SessionId, SessionJournal, record,
    storage,
};
use crate::execution::service_evidence::{
    ObservedServiceAttemptSettlement, ObservedSessionOwnerAlive,
};
use crate::{
    cancellation::Cancellation, execution::restart::ProcessRestart, store::ContentDigest,
    systemd::SystemdUnitName,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Instant;

pub(crate) mod retention;

/// Comparison data, never proof of current ownership or permission to execute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RoleBinding {
    session: SessionId,
    name: String,
    manifest: ContentDigest,
    command: ContentDigest,
    unit: SystemdUnitName,
    owner: AttemptBinding,
    restart: ProcessRestart,
}
impl RoleBinding {
    pub(crate) fn new(
        session: SessionId,
        name: &str,
        manifest: ContentDigest,
        command: ContentDigest,
        unit: SystemdUnitName,
        owner: AttemptBinding,
        restart: ProcessRestart,
    ) -> Result<Self, OwnershipError> {
        record::valid_text(name, super::ROLE_BYTES)?;
        if name == "owner" || unit == *owner.unit() {
            return Err(OwnershipError::Invalid(
                "service role cannot be its owner",
            ));
        }
        Ok(Self {
            session,
            name: name.into(),
            manifest,
            command,
            unit,
            owner,
            restart,
        })
    }
    /// Stable pin excludes mutable authorization and the current attempt head.
    pub(crate) fn digest(&self) -> ContentDigest {
        let mut bytes = b"syrox-service-role-v1\n".to_vec();
        for field in [
            self.session.as_str(),
            self.name(),
            &self.manifest.to_string(),
            &self.command.to_string(),
            self.unit.as_str(),
            self.owner.unit().as_str(),
        ] {
            bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        bytes.extend_from_slice(self.owner.invocation());
        match self.restart {
            ProcessRestart::Never => bytes.push(0),
            ProcessRestart::OnFailure(limits) => {
                bytes.push(1);
                for value in [
                    limits.delay_seconds(),
                    limits.window_seconds(),
                    limits.burst(),
                ] {
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
        ContentDigest::sha256(&bytes)
    }
    pub(crate) fn command(&self) -> ContentDigest {
        self.command
    }
    pub(crate) fn restart(&self) -> ProcessRestart {
        self.restart
    }
    pub(crate) fn session(&self) -> &SessionId {
        &self.session
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn manifest(&self) -> ContentDigest {
        self.manifest
    }
    pub(crate) fn unit(&self) -> &SystemdUnitName {
        &self.unit
    }
    pub(crate) fn owner(&self) -> &AttemptBinding {
        &self.owner
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleRecord {
    session: String,
    name: String,
    manifest: String,
    command: String,
    unit: String,
    owner: record::Binding,
    restart: ProcessRestart,
    pub authorized: bool,
    pub(super) head: String,
    retention: retention::RetentionRecord,
}
impl RoleRecord {
    fn from_binding(role: &RoleBinding, first: &AttemptId) -> Self {
        Self {
            session: role.session.to_string(),
            name: role.name.clone(),
            manifest: role.manifest.to_string(),
            command: role.command.to_string(),
            unit: role.unit.as_str().into(),
            owner: (&role.owner).into(),
            restart: role.restart,
            authorized: true,
            head: first.to_string(),
            retention: retention::RetentionRecord::unprepared(),
        }
    }
    pub(super) fn binding(&self) -> Result<RoleBinding, OwnershipError> {
        RoleBinding::new(
            SessionId::parse(&self.session)?,
            &self.name,
            self.manifest.parse().map_err(|_| invalid())?,
            self.command.parse().map_err(|_| invalid())?,
            SystemdUnitName::new(self.unit.clone()).map_err(|_| invalid())?,
            self.owner.data()?,
            self.restart,
        )
    }
}
fn invalid() -> OwnershipError {
    OwnershipError::Invalid("service role history differs")
}

impl SessionJournal {
    /// Register the initial prepared role while the independently observed owner
    /// is alive. Policy is comparison data from the trusted preparer, not an API
    /// for changing a role after registration.
    pub(crate) fn register_role(
        &self,
        role: &RoleBinding,
        first: &AttemptId,
        owner: &ObservedSessionOwnerAlive,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), OwnershipError> {
        let _authority = self.storage.lock(cancel, deadline)?;
        let (directory, mut state) = self.load(role.session())?;
        require_owner(&state, role, owner)?;
        let entry = state
            .attempts
            .get(first.as_str())
            .ok_or_else(invalid)?;
        if entry.role != role.name
            || entry.phase != AttemptPhase::Prepared
            || entry.predecessor.is_some()
            || state.roles.contains_key(role.name())
        {
            return Err(invalid());
        }
        state.roles.insert(
            role.name.clone(),
            RoleRecord::from_binding(role, first),
        );
        state.advance()?;
        storage::check(cancel, deadline)?;
        owner.revalidate()?;
        self.storage
            .write(directory.fd(), "state", &state.encode()?)
    }

    /// Definitive policy refusal is emitted only while the durable role/head
    /// still agrees. A read/lock/cancellation failure is never a denial reply.
    pub(crate) fn with_forbidden_successor<T>(
        &self,
        role: &RoleBinding,
        previous: &AttemptId,
        cancel: &Cancellation,
        deadline: Instant,
        deny: impl FnOnce() -> std::io::Result<T>,
    ) -> Result<T, OwnershipError> {
        let _authority = self.storage.lock(cancel, deadline)?;
        let (_, state) = self.load(role.session())?;
        let entry = state.roles.get(role.name()).ok_or_else(invalid)?;
        if role.restart() != ProcessRestart::Never
            || entry.binding()? != *role
            || entry.head != previous.as_str()
            || state
                .attempts
                .get(previous.as_str())
                .is_none_or(|attempt| attempt.phase != AttemptPhase::Consumed)
        {
            return Err(invalid());
        }
        storage::check(cancel, deadline)?;
        Ok(deny()?)
    }

    /// Requires monotonic exit evidence for the complete prior service attempt.
    /// Owner liveness is a snapshot, not a future guarantee: authorization and
    /// the final gate must independently revalidate the owner and role again.
    pub(crate) fn prepare_successor(
        &self,
        role: &RoleBinding,
        previous: &ObservedServiceAttemptSettlement,
        owner: &ObservedSessionOwnerAlive,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<AttemptId, OwnershipError> {
        let _authority = self.storage.lock(cancel, deadline)?;
        let (directory, mut state) = self.load(role.session())?;
        require_owner(&state, role, owner)?;
        if role.restart == ProcessRestart::Never || previous.role() != role {
            return Err(OwnershipError::State(
                "role policy or settlement differs",
            ));
        }
        let registered = state.roles.get(role.name()).ok_or_else(invalid)?;
        if !registered.authorized
            || registered.binding()? != *role
            || registered.head != previous.attempt().as_str()
        {
            return Err(invalid());
        }
        let old = state
            .attempts
            .get(previous.attempt().as_str())
            .ok_or_else(invalid)?;
        if old.role != role.name
            || old.phase != AttemptPhase::Consumed
            || old.binding.as_ref() != Some(&record::Binding::from(previous.binding()))
            || old
                .service_processes
                .as_ref()
                .is_none_or(|records| !previous.matches_processes(records))
        {
            return Err(invalid());
        }
        if state.attempts.len() >= super::MAX_SESSION_ATTEMPTS {
            return Err(OwnershipError::State(
                "attempt capacity exhausted; history retained",
            ));
        }
        let next = fresh_attempt(&state)?;
        state
            .attempts
            .get_mut(previous.attempt().as_str())
            .ok_or_else(invalid)?
            .phase = AttemptPhase::Settled;
        state.attempts.insert(
            next.to_string(),
            record::Attempt {
                role: role.name.clone(),
                phase: AttemptPhase::Prepared,
                binding: None,
                predecessor: Some(previous.attempt().to_string()),
                service_processes: None,
            },
        );
        state
            .roles
            .get_mut(role.name())
            .ok_or_else(invalid)?
            .head = next.to_string();
        state.advance()?;
        storage::check(cancel, deadline)?;
        owner.revalidate()?;
        self.storage
            .write(directory.fd(), "state", &state.encode()?)?;
        Ok(next)
    }
}
fn fresh_attempt(state: &record::Record) -> Result<AttemptId, OwnershipError> {
    for _ in 0..64 {
        let id = AttemptId::fresh()?;
        if !state.attempts.contains_key(id.as_str()) {
            return Ok(id);
        }
    }
    Err(OwnershipError::Invalid(
        "attempt entropy collision budget",
    ))
}
pub(super) fn require_owner(
    state: &record::Record,
    role: &RoleBinding,
    owner: &ObservedSessionOwnerAlive,
) -> Result<(), OwnershipError> {
    state.require_open()?;
    if state.session != role.session.as_str()
        || state.pin()? != role.manifest
        || owner.session() != role.session()
        || owner.manifest() != role.manifest
        || owner.binding() != role.owner()
        || !state.attempts.values().any(|attempt| {
            attempt.role == "owner"
                && attempt.phase == AttemptPhase::Consumed
                && attempt.binding.as_ref() == Some(&record::Binding::from(role.owner()))
        })
    {
        return Err(OwnershipError::State(
            "owner admission or role pin differs",
        ));
    }
    owner.revalidate()
}

pub(super) fn validate(state: &record::Record) -> Result<(), OwnershipError> {
    for (name, entry) in &state.roles {
        let role = entry.binding()?;
        if name != role.name()
            || state.session != role.session.as_str()
            || state.pin()? != role.manifest
            || entry.authorized
                == matches!(
                    state.phase,
                    super::SessionPhase::Closing | super::SessionPhase::Closed
                )
        {
            return Err(invalid());
        }
        if !state.attempts.values().any(|attempt| {
            attempt.role == "owner"
                && attempt.phase == AttemptPhase::Consumed
                && attempt.binding.as_ref() == Some(&entry.owner)
        }) {
            return Err(invalid());
        }
        let mut current = Some(entry.head.as_str());
        let mut seen = BTreeSet::new();
        let mut first = entry.head.as_str();
        while let Some(id) = current {
            if !seen.insert(id) {
                return Err(invalid());
            }
            let attempt = state.attempts.get(id).ok_or_else(invalid)?;
            if attempt.role != *name
                || (id != entry.head && attempt.phase != AttemptPhase::Settled)
                || attempt
                    .binding
                    .as_ref()
                    .is_some_and(|binding| binding.unit != entry.unit)
            {
                return Err(invalid());
            }
            first = id;
            current = attempt.predecessor.as_deref();
        }
        retention::validate(state, entry, first)?;
        if seen.len() > 1 && role.restart == ProcessRestart::Never {
            return Err(invalid());
        }
        if state
            .attempts
            .iter()
            .filter(|(_, attempt)| attempt.role == *name)
            .any(|(id, _)| !seen.contains(id.as_str()))
        {
            return Err(invalid());
        }
    }
    if state.attempts.values().any(|attempt| {
        (attempt.predecessor.is_some() || attempt.phase == AttemptPhase::Settled)
            && !state.roles.contains_key(&attempt.role)
    }) {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub(crate) struct RoleSnapshot {
    pub binding: RoleBinding,
    pub head: AttemptId,
    pub authorized: bool,
    pub retention: retention::RoleRetentionSnapshot,
}
pub(super) fn snapshots(state: &record::Record) -> Result<Vec<RoleSnapshot>, OwnershipError> {
    state
        .roles
        .values()
        .map(|role| {
            Ok(RoleSnapshot {
                binding: role.binding()?,
                head: AttemptId::parse(&role.head)?,
                retention: role.retention.snapshot()?,
                authorized: role.authorized,
            })
        })
        .collect()
}

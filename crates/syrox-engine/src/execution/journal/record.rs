use super::{AttemptBinding, AttemptId, OwnershipError, SessionId};
use crate::store::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const MAX_BYTES: usize = 1024 * 1024;
const HEADER: &[u8] = b"syrox-session-state-v2\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SessionPhase {
    Pending,
    Authorized,
    Running,
    Closing,
    Closed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AttemptPhase {
    Prepared,
    Authorized,
    Consumed,
    Settled,
    Revoked,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub unit: String,
    pub invocation: [u8; 16],
}
impl Binding {
    pub fn data(&self) -> Result<AttemptBinding, OwnershipError> {
        AttemptBinding::new(
            crate::systemd::SystemdUnitName::new(self.unit.clone())
                .map_err(|_| OwnershipError::Invalid("invalid unit binding"))?,
            self.invocation,
        )
    }
}
impl From<&AttemptBinding> for Binding {
    fn from(binding: &AttemptBinding) -> Self {
        Self {
            unit: binding.unit.as_str().into(),
            invocation: binding.invocation,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attempt {
    pub role: String,
    pub phase: AttemptPhase,
    pub binding: Option<Binding>,
    pub predecessor: Option<String>,
    #[serde(deserialize_with = "super::processes::required_option")]
    pub service_processes: Option<super::processes::ServiceProcessRecord>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub session: String,
    pub manifest: String,
    pub phase: SessionPhase,
    pub revision: u64,
    pub reason: Option<String>,
    pub attempts: BTreeMap<String, Attempt>,
    pub roles: BTreeMap<String, super::roles::RoleRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub executions: BTreeMap<String, super::execution::ExecutionRecord>,
}
impl Record {
    pub fn encode(&self) -> Result<Vec<u8>, OwnershipError> {
        self.validate()?;
        let mut bytes = HEADER.to_vec();
        bytes.extend(
            serde_json::to_vec(self)
                .map_err(|_| OwnershipError::Invalid("state encoding failed"))?,
        );
        if bytes.len() > MAX_BYTES {
            return Err(OwnershipError::Invalid(
                "state exceeds byte bound",
            ));
        }
        Ok(bytes)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, OwnershipError> {
        if bytes.len() > MAX_BYTES {
            return Err(OwnershipError::Invalid(
                "state exceeds byte bound",
            ));
        }
        let json = bytes
            .strip_prefix(HEADER)
            .ok_or(OwnershipError::Invalid(
                "unsupported state version",
            ))?;
        let record: Self = serde_json::from_slice(json)
            .map_err(|_| OwnershipError::Invalid("invalid session state"))?;
        if record.encode()? != bytes {
            return Err(OwnershipError::Invalid(
                "noncanonical session state",
            ));
        }
        Ok(record)
    }
    pub fn pin(&self) -> Result<ContentDigest, OwnershipError> {
        self.manifest
            .parse()
            .map_err(|_| OwnershipError::Invalid("invalid manifest pin"))
    }
    fn validate(&self) -> Result<(), OwnershipError> {
        SessionId::parse(&self.session)?;
        super::execution::validate_records(self)?;
        super::roles::validate(self)?;
        super::processes::validate(self)?;
        self.pin()?;
        if self.attempts.len() > super::MAX_SESSION_ATTEMPTS {
            return Err(OwnershipError::Invalid("invalid state bounds"));
        }
        if let Some(reason) = &self.reason {
            valid_text(reason, 1024)?;
        }
        let mut roles = BTreeSet::new();
        let mut bindings = BTreeSet::new();
        if !matches!(
            self.phase,
            SessionPhase::Closing | SessionPhase::Closed
        ) && self.reason.is_some()
        {
            return Err(OwnershipError::Invalid(
                "open session carries a closing reason",
            ));
        }
        for (id, attempt) in &self.attempts {
            AttemptId::parse(id)?;
            valid_text(&attempt.role, super::ROLE_BYTES)?;
            if !roles.insert(attempt.role.as_str()) && !self.roles.contains_key(&attempt.role) {
                return Err(OwnershipError::Invalid("duplicate attempt role"));
            }
            if self.phase == SessionPhase::Pending && attempt.phase != AttemptPhase::Prepared {
                return Err(OwnershipError::Invalid(
                    "pending session contains an admitted or revoked attempt",
                ));
            }
            if !matches!(
                self.phase,
                SessionPhase::Closing | SessionPhase::Closed
            ) && attempt.phase == AttemptPhase::Revoked
            {
                return Err(OwnershipError::Invalid(
                    "open session contains revoked attempt",
                ));
            }

            if let Some(binding) = &attempt.binding {
                binding.data()?;
                if !bindings.insert((&binding.unit, binding.invocation)) {
                    return Err(OwnershipError::Invalid(
                        "duplicate invocation binding",
                    ));
                }
            }
            if matches!(
                attempt.phase,
                AttemptPhase::Authorized | AttemptPhase::Consumed | AttemptPhase::Settled
            ) && attempt.binding.is_none()
            {
                return Err(OwnershipError::Invalid(
                    "admitted attempt has no binding",
                ));
            }
            if attempt.phase == AttemptPhase::Prepared && attempt.binding.is_some() {
                return Err(OwnershipError::Invalid(
                    "prepared attempt already bound",
                ));
            }
            if matches!(
                self.phase,
                SessionPhase::Closing | SessionPhase::Closed
            ) && matches!(
                attempt.phase,
                AttemptPhase::Prepared | AttemptPhase::Authorized
            ) {
                return Err(OwnershipError::Invalid(
                    "closed admission retains an authorization",
                ));
            }
        }
        if matches!(
            self.phase,
            SessionPhase::Authorized | SessionPhase::Running
        ) && !self.attempts.values().any(|attempt| {
            matches!(
                attempt.phase,
                AttemptPhase::Authorized | AttemptPhase::Consumed
            )
        }) {
            return Err(OwnershipError::Invalid(
                "active admission phase has no admitted attempt",
            ));
        }
        Ok(())
    }
    pub fn advance(&mut self) -> Result<(), OwnershipError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(OwnershipError::Invalid("revision exhausted"))?;
        Ok(())
    }
    pub fn require_open(&self) -> Result<(), OwnershipError> {
        if matches!(
            self.phase,
            SessionPhase::Closing | SessionPhase::Closed
        ) {
            Err(OwnershipError::State(
                "session admission is closed",
            ))
        } else {
            Ok(())
        }
    }
}
pub(super) fn valid_text(text: &str, maximum: usize) -> Result<(), OwnershipError> {
    if text.is_empty() || text.len() > maximum || text.chars().any(char::is_control) {
        Err(OwnershipError::Invalid(
            "invalid bounded session text",
        ))
    } else {
        Ok(())
    }
}

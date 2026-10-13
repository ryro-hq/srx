//! Admissão de uma sessão antes de liberar os gates de execução.
//!
//! Uma admissão bem-sucedida precisa estar persistida antes de liberar o payload.
//! Bindings guardam dados para comparação; não provam sozinhos quem controla
//! o manager ou se um processo encerrou. Recuperar o journal não reinicia a sessão.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use crate::{cancellation::Cancellation, store::ContentDigest, systemd::SystemdUnitName};
use thiserror::Error;

pub(crate) const MAX_SESSIONS: usize = 1024;
pub(crate) const ROLE_BYTES: usize = 272;
pub(crate) const MAX_SESSION_ATTEMPTS: usize = 1024;
pub(crate) const MAX_SESSION_MANIFEST_BYTES: usize = 64 * 1024 * 1024 + 16 * 1024;

/// Preflight the complete caller envelope before manager or journal effects.
pub(crate) fn validate_manifest(bytes: &[u8], pin: ContentDigest) -> Result<(), OwnershipError> {
    validate_manifest_size(bytes.len())?;
    if ContentDigest::sha256(bytes) != pin {
        return Err(OwnershipError::Invalid("manifest pin mismatch"));
    }
    Ok(())
}
fn validate_manifest_size(size: usize) -> Result<(), OwnershipError> {
    if size == 0 || size > MAX_SESSION_MANIFEST_BYTES {
        return Err(OwnershipError::Invalid(
            "manifest size bound exceeded",
        ));
    }
    Ok(())
}

pub(crate) mod execution;
pub(crate) mod processes;
mod record;
pub(crate) mod roles;
pub(crate) use roles::RoleBinding;
mod storage;
pub(crate) use record::{AttemptPhase, SessionPhase};

#[cfg(test)]
mod tests;

#[derive(Debug, Error)]
pub(crate) enum OwnershipError {
    #[error("invalid session authority: {0}")]
    Invalid(&'static str),
    #[error("session admission refused: {0}")]
    State(&'static str),
    #[error("session publication outcome is uncertain: {0}")]
    Uncertain(&'static str),
    #[error("session operation cancelled")]
    Cancelled,
    #[error("session authority deadline exceeded")]
    Deadline,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Store(crate::store::StoreError),
}

macro_rules! identity {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub(crate) struct $name(String);
        impl $name {
            pub(crate) fn parse(text: &str) -> Result<Self, OwnershipError> {
                if text.len() != 32
                    || text
                        .bytes()
                        .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
                    || text.bytes().all(|byte| byte == b'0')
                {
                    return Err(OwnershipError::Invalid(
                        "expected nonzero canonical 128-bit identifier",
                    ));
                }
                Ok(Self(text.into()))
            }
            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }
            fn fresh() -> Result<Self, OwnershipError> {
                for _ in 0..64 {
                    let name = crate::platform::linux::fd::operation_name()?;
                    if let Ok(id) = Self::parse(name.strip_prefix("op-").ok_or(
                        OwnershipError::Invalid("invalid entropy identifier"),
                    )?) {
                        return Ok(id);
                    }
                }
                Err(OwnershipError::Invalid(
                    "identifier entropy retry exhausted",
                ))
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}
identity!(SessionId);
identity!(AttemptId);
identity!(ExecutionId);

/// Claimed identity to compare against independent launcher/manager evidence.
/// Constructing this value does not authenticate a unit or authorize a gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttemptBinding {
    unit: SystemdUnitName,
    invocation: [u8; 16],
}
impl AttemptBinding {
    pub(crate) fn new(unit: SystemdUnitName, invocation: [u8; 16]) -> Result<Self, OwnershipError> {
        if invocation == [0; 16] {
            return Err(OwnershipError::Invalid("zero invocation binding"));
        }
        Ok(Self {
            unit,
            invocation,
        })
    }
    pub(crate) const fn unit(&self) -> &SystemdUnitName {
        &self.unit
    }
    pub(crate) const fn invocation(&self) -> &[u8; 16] {
        &self.invocation
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AttemptSnapshot {
    pub id: AttemptId,
    pub role: String,
    pub phase: AttemptPhase,
    pub binding: Option<AttemptBinding>,
    pub service_processes: Option<processes::ServiceProcessRecord>,
}
#[derive(Clone, Debug)]
pub(crate) struct SessionSnapshot {
    pub pin: ContentDigest,
    pub phase: SessionPhase,
    pub revision: u64,
    pub attempts: Vec<AttemptSnapshot>,
    #[cfg(test)]
    pub executions: Vec<execution::ExecutionSnapshot>,
    pub roles: Vec<roles::RoleSnapshot>,
}

#[derive(Debug)]
pub(crate) struct SessionJournal {
    storage: storage::Storage,
}
impl SessionJournal {
    /// The installation provides an existing owned directory with mode 0700.
    /// A permanent lock inode serializes mutation across all processes/handles.
    pub(crate) fn open(directory: &Path) -> Result<Self, OwnershipError> {
        Ok(Self {
            storage: storage::Storage::open(directory)?,
        })
    }
    /// Open existing evidence without creating even the authority lock.
    pub(crate) fn open_existing(directory: &Path) -> Result<Self, OwnershipError> {
        Ok(Self {
            storage: storage::Storage::open_existing(directory)?,
        })
    }

    pub(crate) fn create(
        &self,
        manifest: &[u8],
        pin: ContentDigest,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<SessionId, OwnershipError> {
        validate_manifest(manifest, pin)?;
        let _authority = self.storage.lock(cancellation, deadline)?;
        if self.storage.ids(cancellation, deadline)?.len() >= MAX_SESSIONS {
            return Err(OwnershipError::State(
                "session registry capacity exhausted; evidence retained",
            ));
        }
        for _ in 0..64 {
            let id = SessionId::fresh()?;
            let Some(directory) = self.storage.create_directory(&id)? else {
                continue;
            };
            storage::check(cancellation, deadline)?;
            self.storage
                .write(directory.fd(), "manifest", manifest)?;
            let record = record::Record {
                session: id.to_string(),
                manifest: pin.to_string(),
                phase: SessionPhase::Pending,
                revision: 0,
                reason: None,
                attempts: BTreeMap::new(),
                roles: BTreeMap::new(),
                executions: BTreeMap::new(),
            };
            storage::check(cancellation, deadline)?;
            self.storage
                .write(directory.fd(), "state", &record.encode()?)?;
            return Ok(id);
        }
        Err(OwnershipError::Invalid(
            "session ID collision retries exhausted",
        ))
    }
    pub(crate) fn prepare_attempt(
        &self,
        id: &SessionId,
        role: &str,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<AttemptId, OwnershipError> {
        record::valid_text(role, ROLE_BYTES)?;
        let _authority = self.storage.lock(cancellation, deadline)?;
        let (directory, mut state) = self.load(id)?;
        state.require_open()?;
        if state.attempts.len() >= MAX_SESSION_ATTEMPTS {
            return Err(OwnershipError::State(
                "attempt capacity exhausted",
            ));
        }
        // Until settlement verification exists, one logical role cannot be
        // re-admitted: a consumed attempt may still have a running process.
        if state
            .attempts
            .values()
            .any(|attempt| attempt.role == role)
        {
            return Err(OwnershipError::State(
                "role already has an attempt",
            ));
        }
        let mut fresh = None;
        for _ in 0..64 {
            let attempt = AttemptId::fresh()?;
            if !state.attempts.contains_key(attempt.as_str()) {
                fresh = Some(attempt);
                break;
            }
        }
        let attempt = fresh.ok_or(OwnershipError::Invalid(
            "attempt ID collision retries exhausted",
        ))?;
        state.attempts.insert(
            attempt.to_string(),
            record::Attempt {
                role: role.into(),
                phase: AttemptPhase::Prepared,
                binding: None,
                predecessor: None,
                service_processes: None,
            },
        );
        state.advance()?;
        storage::check(cancellation, deadline)?;
        self.storage
            .write(directory.fd(), "state", &state.encode()?)?;
        Ok(attempt)
    }
    pub(crate) fn authorize_attempt(
        &self,
        id: &SessionId,
        attempt: &AttemptId,
        binding: &AttemptBinding,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), OwnershipError> {
        let _authority = self.storage.lock(cancellation, deadline)?;
        let (directory, mut state) = self.load(id)?;
        state.require_open()?;
        processes::refuse_generic(&state, attempt)?;
        roles::retention::require_retained(&state, attempt)?;
        let binding = record::Binding::from(binding);
        if state
            .attempts
            .values()
            .any(|attempt| attempt.binding.as_ref() == Some(&binding))
        {
            return Err(OwnershipError::State(
                "invocation already bound to an attempt",
            ));
        }
        let entry = state
            .attempts
            .get_mut(attempt.as_str())
            .ok_or(OwnershipError::State("unknown attempt"))?;
        if entry.phase != AttemptPhase::Prepared {
            return Err(OwnershipError::State("attempt is not prepared"));
        }
        entry.binding = Some(binding);
        entry.phase = AttemptPhase::Authorized;
        if state.phase == SessionPhase::Pending {
            state.phase = SessionPhase::Authorized;
        }
        state.advance()?;
        storage::check(cancellation, deadline)?;
        self.storage
            .write(directory.fd(), "state", &state.encode()?)
    }
    pub(crate) fn consume_attempt(
        &self,
        id: &SessionId,
        attempt: &AttemptId,
        pin: ContentDigest,
        expected_binding: &AttemptBinding,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), OwnershipError> {
        let _authority = self.storage.lock(cancellation, deadline)?;
        let (directory, mut state) = self.load(id)?;
        state.require_open()?;
        processes::require_consumable(&state, attempt)?;
        roles::retention::require_retained(&state, attempt)?;
        if state.pin()? != pin {
            return Err(OwnershipError::State(
                "launcher manifest pin differs",
            ));
        }
        let entry = state
            .attempts
            .get_mut(attempt.as_str())
            .ok_or(OwnershipError::State("unknown attempt"))?;
        if entry.phase != AttemptPhase::Authorized
            || entry.binding.as_ref() != Some(&record::Binding::from(expected_binding))
        {
            return Err(OwnershipError::State(
                "attempt already used, revoked or binding differs",
            ));
        }
        entry.phase = AttemptPhase::Consumed;
        state.advance()?;
        storage::check(cancellation, deadline)?;
        self.storage
            .write(directory.fd(), "state", &state.encode()?)?;
        Ok(())
    }
    /// Serialize a final gate send with revocation. The action must use the same
    /// cancellation and deadline for its bounded I/O and must not call this journal.
    /// It runs once; an error may mean that the peer received the gate. No state is
    /// reset and neither this method nor recovery retries the action.
    #[allow(clippy::too_many_arguments)] // Journal admission needs explicit session, execution, manifest and bounded-I/O authority.
    pub(crate) fn with_consumed_attempt<T>(
        &self,
        id: &SessionId,
        attempt: &AttemptId,
        pin: ContentDigest,
        expected_binding: &AttemptBinding,
        cancellation: &Cancellation,
        deadline: Instant,
        action: impl FnOnce() -> std::io::Result<T>,
    ) -> Result<T, OwnershipError> {
        let _authority = self.storage.lock(cancellation, deadline)?;
        let (_, state) = self.load(id)?;
        state.require_open()?;
        processes::refuse_generic(&state, attempt)?;
        roles::retention::require_retained(&state, attempt)?;
        if state.pin()? != pin {
            return Err(OwnershipError::State(
                "launcher manifest pin differs",
            ));
        }
        let entry = state
            .attempts
            .get(attempt.as_str())
            .ok_or(OwnershipError::State("unknown attempt"))?;
        if entry.phase != AttemptPhase::Consumed
            || entry.binding.as_ref() != Some(&record::Binding::from(expected_binding))
        {
            return Err(OwnershipError::State(
                "attempt is not consumed or binding differs",
            ));
        }
        storage::check(cancellation, deadline)?;
        Ok(action()?)
    }
    /// Persist revocation BEFORE requesting `StopUnit`. Consumed attempts remain
    /// recorded because they may have passed the gate or still be starting.
    pub(crate) fn begin_closing(
        &self,
        id: &SessionId,
        reason: &str,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<SessionSnapshot, OwnershipError> {
        record::valid_text(reason, 1024)?;
        let _authority = self.storage.lock(cancellation, deadline)?;
        let (directory, mut state) = self.load(id)?;
        if !matches!(
            state.phase,
            SessionPhase::Closing | SessionPhase::Closed
        ) {
            state.phase = SessionPhase::Closing;
            state.reason = Some(reason.into());
            for role in state.roles.values_mut() {
                role.authorized = false;
            }
            for attempt in state.attempts.values_mut() {
                if matches!(
                    attempt.phase,
                    AttemptPhase::Prepared | AttemptPhase::Authorized
                ) {
                    attempt.phase = AttemptPhase::Revoked;
                }
            }
            state.advance()?;
            storage::check(cancellation, deadline)?;
            self.storage
                .write(directory.fd(), "state", &state.encode()?)?;
        }
        snapshot(&state)
    }
    /// Conservative recovery only closes admission. It neither resurrects units
    /// nor declares quiescence, removes evidence, or releases retained interests.
    pub(crate) fn recover(
        &self,
        id: &SessionId,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<SessionSnapshot, OwnershipError> {
        self.begin_closing(
            id,
            "recovery requires manager and process reconciliation",
            cancellation,
            deadline,
        )
    }
    /// Includes incomplete session directories left by failed creation. Opening
    /// their snapshot may fail; recovery must preserve these entries as evidence.
    pub(crate) fn session_ids(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Vec<SessionId>, OwnershipError> {
        let _authority = self.storage.lock(cancellation, deadline)?;
        self.storage.ids(cancellation, deadline)
    }
    pub(crate) fn snapshot(
        &self,
        id: &SessionId,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<SessionSnapshot, OwnershipError> {
        let _authority = self.storage.lock(cancellation, deadline)?;
        let (_, state) = self.load(id)?;
        snapshot(&state)
    }
    #[cfg(test)]
    pub(crate) fn manifest(
        &self,
        id: &SessionId,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Vec<u8>, OwnershipError> {
        let _authority = self.storage.lock(cancellation, deadline)?;
        let (_, _, bytes) = self.load_with_manifest(id)?;
        Ok(bytes)
    }
    /// One locked observation and one bounded manifest read for recovery clients.
    pub(crate) fn snapshot_with_manifest(
        &self,
        id: &SessionId,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(SessionSnapshot, Vec<u8>), OwnershipError> {
        let _authority = self.storage.lock(cancellation, deadline)?;
        let (_, state, bytes) = self.load_with_manifest(id)?;
        storage::check(cancellation, deadline)?;
        Ok((snapshot(&state)?, bytes))
    }
    fn load(
        &self,
        id: &SessionId,
    ) -> Result<
        (
            crate::platform::linux::fd::OpenedPath,
            record::Record,
        ),
        OwnershipError,
    > {
        let (directory, state, _) = self.load_with_manifest(id)?;
        Ok((directory, state))
    }
    fn load_with_manifest(
        &self,
        id: &SessionId,
    ) -> Result<
        (
            crate::platform::linux::fd::OpenedPath,
            record::Record,
            Vec<u8>,
        ),
        OwnershipError,
    > {
        let directory = self.storage.directory(id)?;
        let state = record::Record::parse(&storage::Storage::read(directory.fd(), "state")?)?;
        if state.session != id.as_str() {
            return Err(OwnershipError::Invalid(
                "session directory identity differs",
            ));
        }
        let manifest = storage::Storage::read(directory.fd(), "manifest")?;
        validate_manifest(&manifest, state.pin()?)?;
        Ok((directory, state, manifest))
    }
}
fn snapshot(state: &record::Record) -> Result<SessionSnapshot, OwnershipError> {
    Ok(SessionSnapshot {
        pin: state.pin()?,
        phase: state.phase,
        revision: state.revision,
        #[cfg(test)]
        executions: execution::snapshots(state)?,
        roles: roles::snapshots(state)?,
        attempts: state
            .attempts
            .iter()
            .map(|(id, attempt)| {
                Ok(AttemptSnapshot {
                    id: AttemptId::parse(id)?,
                    role: attempt.role.clone(),
                    phase: attempt.phase,
                    service_processes: attempt.service_processes.clone(),
                    binding: attempt
                        .binding
                        .as_ref()
                        .map(record::Binding::data)
                        .transpose()?,
                })
            })
            .collect::<Result<_, OwnershipError>>()?,
    })
}

//! Observations of a service's pinned processes.
//!
//! `MainPID` identifies the monitor of a specific namespace init. This does not
//! prove that the cgroup is empty. Settlement must also check the namespace and
//! retained resources before releasing them.

use crate::execution::journal::{
    AttemptBinding, AttemptId, OwnershipError, RoleBinding, SessionId,
};
use crate::execution::transport::Peer;
use crate::{
    cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest,
    systemd::SystemdManager,
};
use crate::{systemd::SystemdError, systemd::SystemdManagerIdentity, systemd::SystemdService};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::time::Duration;
use std::time::Instant;
use thiserror::Error;

pub(crate) struct ObservedServiceAttemptSettlement {
    role: RoleBinding,
    attempt: AttemptId,
    binding: AttemptBinding,
    processes: crate::execution::journal::processes::ServiceProcessRecord,
}
impl ObservedServiceAttemptSettlement {
    pub(crate) fn matches_processes(
        &self,
        records: &crate::execution::journal::processes::ServiceProcessRecord,
    ) -> bool {
        &self.processes == records
    }
    pub(crate) fn role(&self) -> &RoleBinding {
        &self.role
    }
    pub(crate) fn attempt(&self) -> &AttemptId {
        &self.attempt
    }
    pub(crate) fn binding(&self) -> &AttemptBinding {
        &self.binding
    }
}

/// A live pinned owner and a fresh matching manager observation. Its liveness
/// must be checked again at admission/gate; it is never a future promise.
pub(crate) struct ObservedSessionOwnerAlive {
    session: SessionId,
    manifest: ContentDigest,
    binding: AttemptBinding,
    process: OwnedFd,
}
impl ObservedSessionOwnerAlive {
    #[cfg(test)]
    pub(crate) fn fixture(
        session: SessionId,
        manifest: ContentDigest,
        binding: AttemptBinding,
        process: OwnedFd,
    ) -> Self {
        Self {
            session,
            manifest,
            binding,
            process,
        }
    }
    pub(crate) fn session(&self) -> &SessionId {
        &self.session
    }
    pub(crate) fn manifest(&self) -> ContentDigest {
        self.manifest
    }
    pub(crate) fn binding(&self) -> &AttemptBinding {
        &self.binding
    }
    pub(crate) fn revalidate(&self) -> Result<(), OwnershipError> {
        if linux_fd::pidfd_exited(self.process.as_fd())? {
            return Err(OwnershipError::State(
                "pinned session owner exited",
            ));
        }
        Ok(())
    }
}
pub(crate) fn observe_live_owner(
    owner: &OwnerObservation<'_>,
    manager: &mut SystemdManager,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<ObservedSessionOwnerAlive, EvidenceError> {
    require_live(owner.process)?;
    observe_owner(manager, owner.binding, cancel, deadline)?;
    let status = manager
        .query(owner.binding.unit(), remaining(deadline)?, cancel)?
        .ok_or(EvidenceError::State("owner vanished"))?;
    same_invocation(&status, owner.binding)?;
    if status.active_state != "active" || status.main_pid != owner.main_pid {
        return Err(EvidenceError::State(
            "pinned owner MainPID or lifecycle differs",
        ));
    }
    require_live(owner.process)?;
    Ok(ObservedSessionOwnerAlive {
        session: owner.session.clone(),
        manifest: owner.manifest,
        binding: owner.binding.clone(),
        process: owner.process.try_clone_to_owned()?,
    })
}
pub(crate) fn observe_processes(
    captured: &CapturedServiceProcesses,
) -> Result<Option<ObservedServiceAttemptSettlement>, EvidenceError> {
    if !captured.exited()? {
        return Ok(None);
    }
    Ok(Some(ObservedServiceAttemptSettlement {
        role: captured.role().clone(),
        attempt: captured.attempt().clone(),
        binding: captured.binding().clone(),
        processes: crate::execution::journal::processes::ServiceProcessRecord::from_captured(
            captured,
        ),
    }))
}
/// Recover exit evidence for the exact durable attempt inventory. A missing
/// namespace never proves that the pre-handoff fork window was empty.
pub(crate) fn observe_recorded_processes(
    role: &RoleBinding,
    attempt: &AttemptId,
    binding: &AttemptBinding,
    records: &crate::execution::journal::processes::ServiceProcessRecord,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<Option<ObservedServiceAttemptSettlement>, EvidenceError> {
    let Some(namespace) = &records.namespace else {
        return Ok(None);
    };
    let Some(launcher_exit) = records.launcher.observe_exit(cancel, deadline)? else {
        return Ok(None);
    };
    let Some(namespace_exit) = namespace.observe_exit(cancel, deadline)? else {
        return Ok(None);
    };
    if !launcher_exit.matches(&records.launcher) || !namespace_exit.matches(namespace) {
        return Err(EvidenceError::State(
            "recorded service process evidence differs",
        ));
    }
    Ok(Some(ObservedServiceAttemptSettlement {
        role: role.clone(),
        attempt: attempt.clone(),
        binding: binding.clone(),
        processes: records.clone(),
    }))
}
pub(crate) fn require_live(process: BorrowedFd<'_>) -> Result<(), EvidenceError> {
    if linux_fd::pidfd_exited(process)? {
        return Err(EvidenceError::State(
            "pinned service launcher exited",
        ));
    }
    Ok(())
}

mod processes;
pub(crate) use processes::{CapturedServiceLauncher, CapturedServiceProcesses};

#[derive(Debug, Error)]
pub(crate) enum EvidenceError {
    #[error(transparent)]
    Journal(#[from] OwnershipError),
    #[error(transparent)]
    Manager(#[from] SystemdError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("service state refused: {0}")]
    State(&'static str),
}
pub(crate) struct OwnerObservation<'a> {
    pub session: &'a SessionId,
    pub manifest: ContentDigest,
    pub binding: &'a AttemptBinding,
    pub process: BorrowedFd<'a>,
    pub main_pid: u32,
}
pub(crate) struct ServiceObservation<'a> {
    pub service: &'a SystemdService,
    pub role: &'a RoleBinding,
    pub attempt: &'a AttemptId,
    pub binding: &'a AttemptBinding,
    pub launcher: BorrowedFd<'a>,
    pub peer: Peer,
    pub epoch: &'a SystemdManagerIdentity,
}
fn remaining(deadline: Instant) -> Result<Duration, EvidenceError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or(EvidenceError::State("service deadline exceeded"))
}
fn same_invocation(
    status: &crate::systemd::SystemdUnitStatus,
    binding: &AttemptBinding,
) -> Result<(), EvidenceError> {
    if status.unit != *binding.unit() || status.invocation != binding.invocation() {
        return Err(EvidenceError::State("unit invocation changed"));
    }
    Ok(())
}
fn observe_owner(
    manager: &mut SystemdManager,
    binding: &AttemptBinding,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<(), EvidenceError> {
    let status = manager
        .query(binding.unit(), remaining(deadline)?, cancel)?
        .ok_or(EvidenceError::State("owner vanished"))?;
    same_invocation(&status, binding)?;
    if status.active_state != "active" {
        return Err(EvidenceError::State("owner is not active"));
    }
    Ok(())
}

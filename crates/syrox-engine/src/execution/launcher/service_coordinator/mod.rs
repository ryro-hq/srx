//! Admite serviços depois de conferir autorização, retenção e namespace.
//!
//! O gate do payload só é liberado quando essas etapas estão concluídas. Para
//! admitir serviços dependentes, `READY` precisa acompanhar a confirmação de
//! exec; uma mensagem isolada não indica que o serviço está pronto.

use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::coordinator::OwnerHandle;
use super::service_spec::ServiceSpecError;
use super::transport::Peer;
use crate::execution::journal::{AttemptBinding, AttemptId, OwnershipError, SessionId};
use crate::{
    cancellation::Cancellation, systemd::SystemdError, systemd::SystemdJobCompletion,
    systemd::SystemdJobResult, systemd::SystemdManager, systemd::SystemdUnitName,
    systemd::SystemdUnitStatus,
};
use thiserror::Error;

mod admission;
use admission::{Admission, admit_attempt};
mod pending;
pub(crate) use pending::ServicePending;
mod pump;
pub(crate) mod settlement;
pub(crate) use pump::{ServiceAuthority, ServiceGroup, ServiceRoleStart};

struct ServiceOwner {
    session: SessionId,
    manifest: crate::store::ContentDigest,
    binding: AttemptBinding,
    process: OwnedFd,
    main_pid: u32,
    bus: PathBuf,
    worker: PathBuf,
}
impl ServiceOwner {
    fn capture(owner: &OwnerHandle) -> Result<Self, ServiceError> {
        settlement::require_live(owner.process())?;
        Ok(Self {
            session: owner.session.clone(),
            manifest: owner.manifest_pin(),
            binding: owner.binding.clone(),
            process: owner.process().try_clone_to_owned()?,
            main_pid: owner.main_pid(),
            bus: owner.bus_socket().into(),
            worker: owner.worker_snapshot().into(),
        })
    }
}

#[derive(Debug, Error)]
pub(crate) enum ServiceError {
    #[error(transparent)]
    Journal(#[from] OwnershipError),
    #[error(transparent)]
    Manager(#[from] SystemdError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("service {stage} failed: {source}")]
    AdmissionIo {
        stage: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Spec(#[from] ServiceSpecError),
    #[error(transparent)]
    Worker(#[from] super::service::ServiceWorkerError),
    #[error(transparent)]
    Runtime(#[from] crate::runtime::RuntimeError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error("service state refused: {0}")]
    State(&'static str),
}

struct ServiceAttempt {
    processes: settlement::CapturedServiceProcesses,
    attempt: AttemptId,
    namespace: OwnedFd,
    launcher: OwnedFd,
}

fn observe_owner(
    manager: &mut SystemdManager,
    binding: &AttemptBinding,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(), ServiceError> {
    let status = manager
        .query(binding.unit(), remaining(deadline)?, cancellation)?
        .ok_or(ServiceError::State("owner vanished"))?;
    same_invocation(&status, binding)?;
    if status.active_state != "active" {
        return Err(ServiceError::State("owner is not active"));
    }
    Ok(())
}
fn observe_main(
    manager: &mut SystemdManager,
    unit: &SystemdUnitName,
    peer: Peer,
    binding: Option<&AttemptBinding>,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<SystemdUnitStatus, ServiceError> {
    let status = manager
        .query(unit, remaining(deadline)?, cancellation)?
        .ok_or(ServiceError::State("service vanished"))?;
    if &status.unit != unit
        || status.main_pid != peer.pid
        || !matches!(
            status.active_state.as_str(),
            "activating" | "active"
        )
        || binding.is_some_and(|binding| status.invocation != binding.invocation())
    {
        return Err(ServiceError::State(
            "service main PID, invocation or lifecycle differs",
        ));
    }
    Ok(status)
}
fn same_invocation(
    status: &SystemdUnitStatus,
    binding: &AttemptBinding,
) -> Result<(), ServiceError> {
    if &status.unit != binding.unit() || status.invocation != binding.invocation() {
        return Err(ServiceError::State(
            "service invocation was replaced",
        ));
    }
    Ok(())
}
fn stop_bound(
    manager: &mut SystemdManager,
    binding: &AttemptBinding,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(), ServiceError> {
    let Some(status) = manager.query(binding.unit(), remaining(deadline)?, cancellation)? else {
        return Ok(());
    };
    same_invocation(&status, binding)?;
    let job = manager.stop(binding.unit(), remaining(deadline)?, cancellation)?;
    completed(&manager.wait_job(&job, remaining(deadline)?, cancellation)?)
}

#[cfg(test)]
fn inactive_or_absent(
    status: Option<&SystemdUnitStatus>,
    binding: &AttemptBinding,
) -> Result<(), ServiceError> {
    if let Some(status) = status {
        same_invocation(status, binding)?;
        if status.active_state != "inactive" {
            return Err(ServiceError::State(
                "unit has not reached inactive state",
            ));
        }
    }
    Ok(())
}

fn completed(completion: &SystemdJobCompletion) -> Result<(), ServiceError> {
    if matches!(
        completion,
        SystemdJobCompletion::Observed {
            result: SystemdJobResult::Done
        }
    ) {
        Ok(())
    } else {
        Err(ServiceError::State(
            "manager job did not complete successfully",
        ))
    }
}
pub(crate) fn validate_role(role: &str) -> Result<(), ServiceError> {
    if role.len() > crate::execution::journal::ROLE_BYTES {
        return Err(ServiceError::State("service role exceeds bound"));
    }
    let parts = role.split(':').collect::<Vec<_>>();
    let valid = parts.len() == 3
        && parts[0] == "service"
        && crate::config::secrets::valid_name(parts[1])
        && crate::result::valid_name(parts[2]);
    if valid {
        Ok(())
    } else {
        Err(ServiceError::State(
            "invalid service process role",
        ))
    }
}

fn remaining(deadline: Instant) -> Result<Duration, ServiceError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(ServiceError::State("service deadline expired"))
}

#[cfg(test)]
mod tests;

impl From<crate::execution::service_evidence::EvidenceError> for ServiceError {
    fn from(error: crate::execution::service_evidence::EvidenceError) -> Self {
        use crate::execution::service_evidence::EvidenceError;
        match error {
            EvidenceError::Journal(error) => Self::Journal(error),
            EvidenceError::Manager(error) => Self::Manager(error),
            EvidenceError::Io(error) => Self::Io(error),
            EvidenceError::State(reason) => Self::State(reason),
        }
    }
}

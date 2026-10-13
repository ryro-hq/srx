use crate::platform::linux::boot::{BootError, BootId};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::execution::journal::{
    AttemptSnapshot, OwnershipError, SessionId, SessionJournal, SessionPhase,
};
use crate::{
    cancellation::Cancellation, store::ContentDigest, systemd::SystemdError, systemd::SystemdJob,
    systemd::SystemdJobCompletion, systemd::SystemdJobResult, systemd::SystemdManager,
    systemd::SystemdScope, systemd::SystemdUnitName, systemd::SystemdUnitStatus,
};

const CALL_BUDGET: Duration = Duration::from_secs(2);
const MAX_DIAGNOSTIC_CHARACTERS: usize = 1024;

mod retention;
mod retirement;
pub use retention::{RoleRetentionRecovery, RoleRetentionRecoveryOutcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStage {
    Connection,
    Query,
    Stop,
    Completion,
    Budget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptRecoveryOutcome {
    /// A matching invocation's Stop job was observed completing successfully.
    /// This is not proof that every reader or namespace has settled.
    ObservedStop,
    Absent,
    Conflict,
    Unbound,
    Failed {
        stage: RecoveryStage,
        message: String,
    },
}

#[derive(Clone, Debug)]
pub struct AttemptRecovery {
    pub id: String,
    pub role: String,
    pub unit: Option<SystemdUnitName>,
    pub invocation: Option<[u8; 16]>,
    pub outcome: AttemptRecoveryOutcome,
}

#[derive(Clone, Debug)]
pub struct ShellRecoveryReport {
    pub session: String,
    pub pin: ContentDigest,
    /// Inert recovery hint. Never authority to delete configuration.
    pub configuration_hint: PathBuf,
    pub attempts: Vec<AttemptRecovery>,
    /// Reopening authenticates retention only; it is not a process exit proof.
    pub retention: Vec<RoleRetentionRecovery>,
    /// Always true until independent namespace/cgroup settlement is available.
    pub needs_reconciliation: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RecoveryError {
    #[error(transparent)]
    Boot(#[from] BootError),
    #[error("Shell session belongs to another boot; journal and configuration preserved")]
    PreviousBoot,
    #[error(transparent)]
    Journal(#[from] OwnershipError),
    #[error("invalid Shell recovery evidence: {0}")]
    Record(String),
    #[error("Shell recovery requires durable Closing")]
    NotClosing,
    #[error("Shell recovery requires an explicit absolute bus path")]
    BusPath,
}

pub(crate) fn recover_shell(
    journal: &SessionJournal,
    session: &SessionId,
    bus: &Path,
    store: &Path,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<ShellRecoveryReport, RecoveryError> {
    if !bus.is_absolute()
        || bus.to_str().is_none()
        || bus
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(RecoveryError::BusPath);
    }
    let boot = BootId::current(cancellation, deadline)?;
    let (mut report, evidence) = recover_with(
        journal,
        session,
        &boot,
        cancellation,
        deadline,
        |timeout| {
            SystemdManager::connect(
                SystemdScope::User {
                    bus_socket: bus.into(),
                },
                timeout,
                cancellation,
            )
        },
    )?;
    // Revocation and exact-invocation stops precede Store inspection, so a bad
    // Store path cannot prevent closing admission to the recorded session.
    report.retention = retention::inspect(&evidence.roles, store, cancellation, deadline);
    retirement::Recovery {
        journal,
        snapshot: &evidence,
        bus,
        store,
        cancel: cancellation,
        deadline,
    }
    .retire(&mut report.retention);
    Ok(report)
}

trait Manager {
    type Job;
    fn query(
        &mut self,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<Option<SystemdUnitStatus>, SystemdError>;
    fn stop(
        &mut self,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<Self::Job, SystemdError>;
    fn wait(
        &mut self,
        job: &Self::Job,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<SystemdJobCompletion, SystemdError>;
}
impl Manager for SystemdManager {
    type Job = SystemdJob;
    fn query(
        &mut self,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<Option<SystemdUnitStatus>, SystemdError> {
        self.query(unit, timeout, cancellation)
    }
    fn stop(
        &mut self,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<Self::Job, SystemdError> {
        self.stop(unit, timeout, cancellation)
    }
    fn wait(
        &mut self,
        job: &Self::Job,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<SystemdJobCompletion, SystemdError> {
        self.wait_job(job, timeout, cancellation)
    }
}

fn recover_with<M: Manager>(
    journal: &SessionJournal,
    session: &SessionId,
    boot: &BootId,
    cancellation: &Cancellation,
    deadline: Instant,
    connect: impl FnOnce(Duration) -> Result<M, SystemdError>,
) -> Result<
    (
        ShellRecoveryReport,
        crate::execution::journal::SessionSnapshot,
    ),
    RecoveryError,
> {
    let (initial, manifest) = journal.snapshot_with_manifest(session, cancellation, deadline)?;
    let record = super::record::decode(&manifest, initial.pin).map_err(|error| {
        // Parsing errors may quote malformed input; configuration is not diagnostic text.
        RecoveryError::Record(match error {
            super::record::RecordError::Invalid(reason) => reason.into(),
            super::record::RecordError::Encoding(_) => "invalid record metadata encoding".into(),
            super::record::RecordError::Snapshot(_) => {
                "invalid authenticated Shell snapshot".into()
            }
        })
    })?;
    if record.boot() != boot {
        return Err(RecoveryError::PreviousBoot);
    }
    // Recovery's returned snapshot includes any attempt authorized before the
    // durable Closing transition. Never act on the earlier stale attempt list.
    let closing = journal.recover(session, cancellation, deadline)?;
    if closing.phase != SessionPhase::Closing || closing.pin != initial.pin {
        return Err(RecoveryError::NotClosing);
    }
    let mut manager = if closing
        .attempts
        .iter()
        .any(|attempt| attempt.binding.is_some())
    {
        Some(match budget(cancellation, deadline) {
            Ok(timeout) => {
                connect(timeout).map_err(|error| failure(RecoveryStage::Connection, &error))
            }
            Err(error) => Err(error),
        })
    } else {
        None
    };
    let attempts = closing
        .attempts
        .iter()
        .cloned()
        .map(|attempt| {
            let outcome = if attempt.binding.is_none() {
                AttemptRecoveryOutcome::Unbound
            } else {
                match manager
                    .as_mut()
                    .expect("bound attempts initialize manager")
                {
                    Ok(manager) => recover_attempt(manager, &attempt, cancellation, deadline),
                    Err(error) => error.clone(),
                }
            };
            AttemptRecovery {
                id: attempt.id.to_string(),
                role: attempt.role,
                unit: attempt
                    .binding
                    .as_ref()
                    .map(|binding| binding.unit().clone()),
                invocation: attempt
                    .binding
                    .as_ref()
                    .map(|binding| *binding.invocation()),
                outcome,
            }
        })
        .collect();
    Ok((
        ShellRecoveryReport {
            session: session.to_string(),
            pin: initial.pin,
            configuration_hint: record.configuration().into(),
            attempts,
            retention: Vec::new(),
            needs_reconciliation: true,
        },
        closing,
    ))
}

fn recover_attempt<M: Manager>(
    manager: &mut M,
    attempt: &AttemptSnapshot,
    cancellation: &Cancellation,
    deadline: Instant,
) -> AttemptRecoveryOutcome {
    let binding = attempt
        .binding
        .as_ref()
        .expect("only persisted bindings may reach manager");
    let mut run = || -> Result<AttemptRecoveryOutcome, AttemptRecoveryOutcome> {
        let status = manager
            .query(
                binding.unit(),
                budget(cancellation, deadline)?,
                cancellation,
            )
            .map_err(|error| failure(RecoveryStage::Query, &error))?;
        let Some(status) = status else {
            return Ok(AttemptRecoveryOutcome::Absent);
        };
        if &status.unit != binding.unit() || status.invocation != binding.invocation() {
            return Ok(AttemptRecoveryOutcome::Conflict);
        }
        // No retry after an uncertain Stop reply, even if the connection could
        // be restored. Another attempt is separately queried and authenticated.
        let job = manager
            .stop(
                binding.unit(),
                budget(cancellation, deadline)?,
                cancellation,
            )
            .map_err(|error| failure(RecoveryStage::Stop, &error))?;
        let completion = manager
            .wait(
                &job,
                budget(cancellation, deadline)?,
                cancellation,
            )
            .map_err(|error| failure(RecoveryStage::Completion, &error))?;
        match completion {
            SystemdJobCompletion::Observed {
                result: SystemdJobResult::Done,
            } => Ok(AttemptRecoveryOutcome::ObservedStop),
            SystemdJobCompletion::Observed {
                result,
            } => Err(failure(
                RecoveryStage::Completion,
                &format!("Stop job completed with {result:?}"),
            )),
            SystemdJobCompletion::Unobserved {
                ..
            } => Err(failure(
                RecoveryStage::Completion,
                &"Stop job completion was not observed",
            )),
        }
    };
    run().unwrap_or_else(|outcome| outcome)
}
fn budget(
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<Duration, AttemptRecoveryOutcome> {
    if cancellation.is_cancelled() {
        return Err(failure(
            RecoveryStage::Budget,
            &"recovery caller cancelled",
        ));
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .map(|duration| duration.min(CALL_BUDGET))
        .ok_or_else(|| {
            failure(
                RecoveryStage::Budget,
                &"recovery deadline expired",
            )
        })
}
fn diagnostic(error: &impl std::fmt::Display) -> String {
    error
        .to_string()
        .chars()
        .take(MAX_DIAGNOSTIC_CHARACTERS)
        .collect()
}
fn failure(stage: RecoveryStage, error: &impl std::fmt::Display) -> AttemptRecoveryOutcome {
    AttemptRecoveryOutcome::Failed {
        stage,
        message: diagnostic(error),
    }
}

#[cfg(test)]
mod tests;

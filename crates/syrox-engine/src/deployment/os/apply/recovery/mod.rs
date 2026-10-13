//! Reconciling interrupted effects with observed installation state.
//!
//! A call may have succeeded even when its reply was lost. Ordinary reconciliation
//! queries state without issuing Start, Stop or Reload. If the manager changed,
//! the dedicated path revokes old authority before an authorized Stop. Retained
//! roots stay held throughout recovery.

use super::{
    manager::ApplyManager,
    preparation::{PreparedResource, ResourcePreparation, reopen_resources},
};
use crate::deployment::os::{
    activation::{ActivationJournal, ActivationSnapshot},
    installation::{ExecutionGuard, GenerationInstallation, RetainedGeneration},
    launch_binding::OsLaunchContext,
    paths::OsExecutionPaths,
    unit_files::UnitFiles,
};
use crate::{
    cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest,
    store::Store, systemd::SystemdScope,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
pub(super) mod coordinator;
pub(crate) mod manager_change;

#[derive(Debug)]
pub struct OsRecoveryRequest {
    pub installation: PathBuf,
    pub store: PathBuf,
    pub units: PathBuf,
    pub cwd: PathBuf,
    pub operation: String,
    /// Explicitly fence requests from a different, previously recorded Linux boot.
    pub new_boot: bool,
    /// Explicit same-boot revocation and namespace reconciliation after a manager change.
    pub manager_changed: bool,
    pub scope: SystemdScope,
    pub uid: u32,
    pub gid: u32,
    pub start_timeout: Duration,
    pub stop_timeout: Duration,
}
#[derive(Debug, thiserror::Error)]
#[error("Os recovery failed during {stage}{detail}; retained evidence was preserved", detail = .source.as_ref().map(|error| format!(": {error}")).unwrap_or_default())]
pub struct OsRecoveryError {
    stage: &'static str,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
impl OsRecoveryError {
    pub const fn stage(&self) -> &'static str {
        self.stage
    }
}
impl From<&'static str> for OsRecoveryError {
    fn from(stage: &'static str) -> Self {
        failure(stage)
    }
}
fn failure(stage: &'static str) -> OsRecoveryError {
    OsRecoveryError {
        stage,
        source: None,
    }
}
fn failure_with(
    stage: &'static str,
    source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
) -> OsRecoveryError {
    OsRecoveryError {
        stage,
        source: Some(source.into()),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OsRecoveryState {
    Observed,
    /// The local publication target is durably not established.
    NotApplied,
    /// A prior boot ended; this does not establish successful effect completion.
    BootFenced,
    ManagerFenced,
    Pending,
}
impl OsRecoveryState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::NotApplied => "not_applied",
            Self::BootFenced => "boot_fenced",
            Self::ManagerFenced => "manager_fenced",
            Self::Pending => "pending",
        }
    }
}
#[derive(Debug)]
pub struct OsRecoveryEffect {
    pub effect: String,
    pub resource: String,
    pub kind: &'static str,
    pub state: OsRecoveryState,
    pub stage: Option<&'static str>,
    /// Original failure details for this pending effect; never execution authority.
    pub error: Option<String>,
}
#[derive(Debug)]
pub struct OsRecoveryReport {
    pub operation: String,
    pub candidate: ContentDigest,
    pub effects: Vec<OsRecoveryEffect>,
    pub needs_reconciliation: bool,
}

/// Reconcile the selected operation without retrying uncertain effects.
/// Explicit manager-change recovery may submit one durably authorized Stop.
/// No result is a claim of application health or permission to retire roots.
pub fn recover_os_generation(
    request: &OsRecoveryRequest,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsRecoveryReport, OsRecoveryError> {
    let context = execution_context(request, cancellation, deadline)?;
    let mut opened = OpenedRecovery::open(request, cancellation, deadline)?;
    let recorded_epoch = opened.snapshot.operations[&request.operation]
        .epoch
        .clone();
    let (mut manager, epoch) =
        super::observe_manager(&request.scope, &context, cancellation, deadline)
            .map_err(|error| failure_with(error.stage, error))?;
    if request.manager_changed {
        if request.new_boot {
            return Err(failure("recovery modes are mutually exclusive"));
        }
        return manager_change::reconcile(
            &opened,
            request,
            &epoch,
            &mut manager,
            cancellation,
            deadline,
        );
    }
    if request.new_boot {
        if epoch.boot == recorded_epoch.boot || epoch.scope != recorded_epoch.scope {
            return Err(failure(
                "new boot requires changed boot and identical scope",
            ));
        }
    } else if epoch != recorded_epoch {
        return Err(failure(
            "operation epoch requires separate recovery",
        ));
    }
    let resources = opened.resources(request, cancellation, deadline)?;
    let units = UnitFiles::open_existing(
        &request.units,
        opened.installation.id(),
        cancellation,
        deadline,
    )
    .map_err(|source| failure_with("open existing unit publisher", source))?;
    opened
        .paths
        .revalidate(cancellation, deadline)
        .map_err(|source| failure_with("execution paths changed", source))?;
    if request.new_boot {
        opened
            .journal
            .fence_previous_boot(&request.operation, &epoch, cancellation, deadline)
            .map_err(|source| failure_with("fence previous boot", source))?;
        opened.snapshot = opened
            .journal
            .snapshot(cancellation, deadline)
            .map_err(|source| failure_with("read fenced operation", source))?;
    }
    let driver = ApplyManager {
        manager: &mut manager,
        journal: &opened.journal,
        operation: &request.operation,
        epoch: &recorded_epoch,
        cancellation,
        deadline,
    };
    Ok(coordinator::reconcile(
        driver,
        &opened.installation,
        &opened.paths,
        &units,
        &resources,
        &opened.snapshot,
        opened.candidate.digest(),
    ))
}

struct OpenedRecovery {
    installation: GenerationInstallation,
    paths: OsExecutionPaths,
    store: Store,
    journal: ActivationJournal,
    candidate: RetainedGeneration,
    snapshot: ActivationSnapshot,
    _execution: ExecutionGuard,
}
impl OpenedRecovery {
    fn open(
        request: &OsRecoveryRequest,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self, OsRecoveryError> {
        let paths = OsExecutionPaths::open(
            &request.installation,
            &request.store,
            &request.cwd,
            cancel,
            deadline,
        )
        .map_err(|source| failure_with("execution paths", source))?;
        let installation =
            GenerationInstallation::open_existing(paths.installation(), cancel, deadline)
                .map_err(|source| failure_with("open installation", source))?;
        let execution = installation
            .execution(cancel, deadline)
            .map_err(|source| failure_with("acquire installation execution authority", source))?;
        let journal = ActivationJournal::open_existing(paths.installation(), cancel, deadline)
            .map_err(|source| failure_with("open activation journal", source))?;
        let snapshot = journal
            .snapshot(cancel, deadline)
            .map_err(|source| failure_with("read activation journal", source))?;
        let operation = snapshot
            .operations
            .get(&request.operation)
            .ok_or_else(|| failure("unknown operation"))?;
        let selected = snapshot.active_operation.as_deref() == Some(&request.operation)
            && snapshot.desired.as_deref() == Some(&operation.candidate);
        let abandoned_boot_recovery = request.new_boot
            && operation.abandoned
            && snapshot.active_operation.is_none()
            && snapshot.desired.is_none()
            && snapshot.last_abandoned.as_deref() == Some(&request.operation);
        if !selected && !abandoned_boot_recovery {
            return Err(failure("operation is no longer selected"));
        }
        let pin = operation
            .candidate
            .parse()
            .map_err(|source| failure_with("invalid candidate identity", source))?;
        let store = Store::open_existing(paths.store())
            .map_err(|source| failure_with("open existing Store", source))?;
        let candidate = installation
            .open(&store, pin, cancel, deadline)
            .map_err(|source| failure_with("open retained candidate", source))?;
        Ok(Self {
            installation,
            paths,
            store,
            journal,
            candidate,
            snapshot,
            _execution: execution,
        })
    }
    fn resources(
        &self,
        request: &OsRecoveryRequest,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<BTreeMap<String, PreparedResource>, OsRecoveryError> {
        reopen_resources(
            &ResourcePreparation {
                installation: &self.installation,
                generation: &self.candidate,
                store: &self.store,
                paths: &self.paths,
                units: &request.units,
                epoch: &self.snapshot.operations[&request.operation].epoch,
                scope: request.scope.clone(),
                uid: request.uid,
                gid: request.gid,
                start_timeout: request.start_timeout,
                stop_timeout: request.stop_timeout,
            },
            cancel,
            deadline,
        )
        .map_err(|source| failure_with("reopen retained execution choices", source))
    }
}

fn execution_context(
    request: &OsRecoveryRequest,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsLaunchContext, OsRecoveryError> {
    if request.uid == 0
        || request.gid == 0
        || request.uid == u32::MAX
        || request.gid == u32::MAX
        || request.uid != linux_fd::real_uid()
        || request.uid != linux_fd::effective_uid()
        || request.gid != linux_fd::real_gid()
        || request.gid != linux_fd::effective_gid()
    {
        return Err(failure("credentials"));
    }
    if request.operation.len() != 32
        || request.operation.bytes().all(|byte| byte == b'0')
        || !request
            .operation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(failure("operation identity"));
    }
    super::remaining(cancellation, deadline).map_err(|error| failure_with(error.stage, error))?;
    OsLaunchContext::new(
        request.scope.clone(),
        request.store.clone(),
        request.units.join("scope.service"),
        request.uid,
        request.gid,
        request.start_timeout,
        request.stop_timeout,
    )
    .map_err(|source| failure_with("execution context", source))
}

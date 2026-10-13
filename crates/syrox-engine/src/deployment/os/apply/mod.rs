//! Aplica uma geração registrando o efeito de cada recurso.
//!
//! O resultado pode ser parcial. Um recurso aplicado não torna a geração inteira
//! aplicada nem libera a coleta de uma geração antiga. Cada execução precisa
//! chegar ao seu fechamento antes de soltar os recursos que ainda usa.

use super::{
    activation::{ActivationJournal, ActivationSnapshot, ExecutionEpoch},
    installation::GenerationInstallation,
    launch_binding::OsLaunchContext,
    paths::OsExecutionPaths,
    unit_files::UnitFiles,
};
use crate::{cancellation::Cancellation, store::ContentDigest, systemd::SystemdScope};
use crate::{platform::linux::fd as linux_fd, store::Store, systemd::SystemdManager};
use std::path::PathBuf;
use std::time::{Duration, Instant};
mod conservation;
mod coordinator;
mod manager;
mod preparation;
pub(crate) mod recovery;

/// Apply an already retained candidate using an explicitly selected manager.
/// Success reports observations per resource, never cleanup or application health.
pub fn apply_os_generation(
    request: &OsApplyRequest,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsApplyReport, OsApplyError> {
    execute_generation(request, false, cancellation, deadline)
}

/// Restore an explicitly selected retained generation. This uses the same
/// ownership, stop/start and retention rules as apply; it does not reverse data
/// migrations or promise health of the complete generation.
pub fn rollback_os_generation(
    request: &OsRollbackRequest,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsApplyReport, OsApplyError> {
    if request.target == request.expected {
        return Err(failure(
            "rollback target equals desired generation",
        ));
    }
    let apply = OsApplyRequest {
        installation: request.installation.clone(),
        store: request.store.clone(),
        units: request.units.clone(),
        cwd: request.cwd.clone(),
        candidate: request.target,
        expected: Some(request.expected),
        scope: request.scope.clone(),
        uid: request.uid,
        gid: request.gid,
        start_timeout: request.start_timeout,
        stop_timeout: request.stop_timeout,
    };
    execute_generation(&apply, true, cancellation, deadline)
}

fn execute_generation(
    request: &OsApplyRequest,
    rollback: bool,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsApplyReport, OsApplyError> {
    let context = execution_context(request, cancellation, deadline)?;
    let paths = OsExecutionPaths::open(
        &request.installation,
        &request.store,
        &request.cwd,
        cancellation,
        deadline,
    )
    .map_err(|_| failure("execution paths"))?;
    let installation =
        GenerationInstallation::open_existing(paths.installation(), cancellation, deadline)
            .map_err(|_| failure("open installation"))?;
    let _execution = installation
        .execution(cancellation, deadline)
        .map_err(|_| failure("acquire installation execution authority"))?;
    let store = Store::open_existing(paths.store()).map_err(|_| failure("open Store"))?;
    let candidate = installation
        .open(&store, request.candidate, cancellation, deadline)
        .map_err(|_| failure("open retained candidate"))?;
    let journal = ActivationJournal::open_existing(paths.installation(), cancellation, deadline)
        .map_err(|_| failure("open activation journal"))?;
    let snapshot = journal
        .snapshot(cancellation, deadline)
        .map_err(|_| failure("read activation journal"))?;
    selection_preflight(&snapshot, request.expected)?;
    let (mut manager, epoch) = observe_manager(&request.scope, &context, cancellation, deadline)?;
    epoch_preflight(&snapshot, &epoch)?;
    let input = preparation::ResourcePreparation {
        installation: &installation,
        generation: &candidate,
        store: &store,
        paths: &paths,
        units: &request.units,
        epoch: &epoch,
        scope: request.scope.clone(),
        uid: request.uid,
        gid: request.gid,
        start_timeout: request.start_timeout,
        stop_timeout: request.stop_timeout,
    };
    let resources = preparation::prepare_resources(&input, cancellation, deadline)
        .map_err(|_| failure("prepare resources"))?;
    let preserved = conservation::prepare_conservation(
        &input,
        &resources,
        &snapshot,
        cancellation,
        deadline,
    )
    .map_err(|_| failure("verify prior execution choices"))?;
    let units = UnitFiles::open(
        &request.units,
        installation.id(),
        cancellation,
        deadline,
    )
    .map_err(|_| failure("open unit publisher"))?;
    units
        .check_capacity(
            &resources
                .values()
                .map(|resource| resource.contract.unit().clone())
                .collect::<Vec<_>>(),
            cancellation,
            deadline,
        )
        .map_err(|_| failure("unit publication capacity or ownership"))?;
    paths
        .revalidate(cancellation, deadline)
        .map_err(|_| failure("execution paths changed"))?;
    let operation = if rollback {
        journal.begin_rollback(
            &candidate,
            request
                .expected
                .ok_or_else(|| failure("rollback requires desired generation"))?,
            epoch.clone(),
            cancellation,
            deadline,
        )
    } else {
        journal.begin(
            &candidate,
            request.expected,
            epoch.clone(),
            cancellation,
            deadline,
        )
    }
    .map_err(|_| failure("select desired generation"))?;
    let driver = manager::ApplyManager {
        manager: &mut manager,
        journal: &journal,
        operation: &operation,
        epoch: &epoch,
        cancellation,
        deadline,
    };
    Ok(coordinator::apply(
        driver,
        &installation,
        &candidate,
        &paths,
        &units,
        &resources,
        &preserved,
    ))
}

fn selection_preflight(
    snapshot: &ActivationSnapshot,
    expected: Option<ContentDigest>,
) -> Result<(), OsApplyError> {
    if snapshot.desired != expected.map(|pin| pin.to_string()) {
        return Err(failure("desired generation comparison"));
    }
    if snapshot
        .operations
        .values()
        .any(|operation| !operation.terminal())
    {
        return Err(failure("prior effects require reconciliation"));
    }
    Ok(())
}

fn epoch_preflight(
    snapshot: &ActivationSnapshot,
    epoch: &ExecutionEpoch,
) -> Result<(), OsApplyError> {
    if snapshot.operations.values().any(|operation| {
        operation.epoch.scope != epoch.scope
            || (operation.epoch.boot != epoch.boot
                && !snapshot.boot_fenced(&operation.epoch, epoch)
                && !snapshot.manager_fenced(&operation.epoch, epoch))
    }) || snapshot.bindings.values().any(|binding| {
        binding.epoch != *epoch
            && !snapshot.boot_fenced(&binding.epoch, epoch)
            && !snapshot.manager_fenced(&binding.epoch, epoch)
    }) {
        return Err(failure("prior epoch requires explicit recovery"));
    }
    Ok(())
}

fn observe_manager(
    scope: &SystemdScope,
    context: &OsLaunchContext,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(SystemdManager, ExecutionEpoch), OsApplyError> {
    let mut manager = SystemdManager::connect(
        scope.clone(),
        remaining(cancellation, deadline)?,
        cancellation,
    )
    .map_err(|_| failure("connect manager"))?;
    let identity = manager
        .observe_identity(remaining(cancellation, deadline)?, cancellation)
        .map_err(|_| failure("observe manager"))?;
    let epoch = ExecutionEpoch {
        boot: crate::platform::linux::boot::BootId::current(cancellation, deadline)
            .map_err(|_| failure("observe boot"))?,
        manager: identity.fingerprint().to_string(),
        scope: context.scope_key(),
    };
    Ok((manager, epoch))
}

fn execution_context(
    request: &OsApplyRequest,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsLaunchContext, OsApplyError> {
    if request.uid == 0
        || request.gid == 0
        || request.uid != linux_fd::real_uid()
        || request.uid != linux_fd::effective_uid()
        || request.gid != linux_fd::real_gid()
        || request.gid != linux_fd::effective_gid()
        || request.uid == u32::MAX
        || request.gid == u32::MAX
    {
        return Err(failure("credentials"));
    }
    remaining(cancellation, deadline)?;
    OsLaunchContext::new(
        request.scope.clone(),
        request.store.clone(),
        request.units.join("scope.service"),
        request.uid,
        request.gid,
        request.start_timeout,
        request.stop_timeout,
    )
    .map_err(|_| failure("execution context"))
}

fn remaining(cancellation: &Cancellation, deadline: Instant) -> Result<Duration, OsApplyError> {
    if cancellation.is_cancelled() {
        return Err(failure("cancellation"));
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| failure("deadline"))
}

#[derive(Debug)]
pub struct OsRollbackRequest {
    pub installation: PathBuf,
    pub store: PathBuf,
    pub units: PathBuf,
    pub cwd: PathBuf,
    pub target: ContentDigest,
    pub expected: ContentDigest,
    pub scope: SystemdScope,
    pub uid: u32,
    pub gid: u32,
    pub start_timeout: Duration,
    pub stop_timeout: Duration,
}
#[derive(Debug)]
pub struct OsApplyRequest {
    pub installation: PathBuf,
    pub store: PathBuf,
    pub units: PathBuf,
    pub cwd: PathBuf,
    pub candidate: ContentDigest,
    pub expected: Option<ContentDigest>,
    pub scope: SystemdScope,
    pub uid: u32,
    pub gid: u32,
    pub start_timeout: Duration,
    pub stop_timeout: Duration,
}
#[derive(Debug, thiserror::Error)]
#[error("Os application failed during {stage}; retained evidence was preserved")]
pub struct OsApplyError {
    stage: &'static str,
}
fn failure(stage: &'static str) -> OsApplyError {
    OsApplyError {
        stage,
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsApplyResourceState {
    Started,
    Stopped,
    Unchanged,
    Pending,
}
impl OsApplyResourceState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Stopped => "stopped",
            Self::Unchanged => "unchanged",
            Self::Pending => "pending",
        }
    }
}
#[derive(Debug)]
pub struct OsApplyResource {
    pub resource: String,
    pub unit: String,
    pub state: OsApplyResourceState,
    pub stage: Option<&'static str>,
}
#[derive(Debug)]
pub struct OsApplyReport {
    pub operation: String,
    pub candidate: ContentDigest,
    pub resources: Vec<OsApplyResource>,
    pub needs_reconciliation: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_rejects_same_selection_and_invalid_credentials_before_filesystem_effects() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let pin = ContentDigest::sha256(b"same");
        let mut request = OsRollbackRequest {
            installation: missing.clone(),
            store: missing.clone(),
            units: missing.clone(),
            cwd: missing.clone(),
            target: pin,
            expected: pin,
            scope: SystemdScope::System,
            uid: u32::MAX,
            gid: u32::MAX,
            start_timeout: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(5),
        };
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(10);
        let error = rollback_os_generation(&request, &cancel, deadline).unwrap_err();
        assert_eq!(
            error.stage,
            "rollback target equals desired generation"
        );
        request.target = ContentDigest::sha256(b"different");
        let error = rollback_os_generation(&request, &cancel, deadline).unwrap_err();
        assert_eq!(error.stage, "credentials");
        assert!(!missing.exists());
    }
}

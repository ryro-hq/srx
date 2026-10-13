use super::{
    BuildError, BuildResult, CapturedManagedBuildOutput, CommittedManagedBuild,
    ManagedBuildHandshake, ManagedBuildServiceSpecification, ObservedManagedBuildBinding,
    PreparedManagedBuild,
    cgroup::{ManagedCgroupObservation, PinnedManagedBuildCgroup},
    handshake::same_binding,
    supervision::observe_managed_build_binding,
};
use crate::build::managed::remaining_timeout as remaining;
use crate::{
    cancellation::Cancellation, platform::linux::boot::BootId, platform::linux::fd as linux_fd,
    systemd::SystemdJob, systemd::SystemdJobCompletion, systemd::SystemdJobResult,
    systemd::SystemdManager, systemd::SystemdUnitReference, systemd::SystemdUnitStatus,
};
use std::{
    os::fd::{AsFd as _, OwnedFd},
    path::Path,
    time::{Duration, Instant},
};
const PREPARATION: Duration = Duration::from_secs(30);
const CLEANUP: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Settlement {
    Pending,
    Processes,
    Complete,
}

// Advance before entering transport: a failed send may already have delivered
// descriptors. Only the first phase can settle without a namespace pidfd.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResourceTransfer {
    NotSent,
    MayHaveReachedWorker,
}
impl ResourceTransfer {
    fn namespace_settled(self, exited: Option<bool>) -> bool {
        match exited {
            Some(exited) => exited,
            None => self == Self::NotSent,
        }
    }
}

/// In-process evidence issued only after this owner confirms terminal settlement.
/// The journal binds its durable encoding to the exact final attempt snapshot.
pub(in crate::build) struct ManagedBuildSettlement {
    context: super::journal::managed::ManagedAttemptContext,
    nonce: crate::store::ContentDigest,
}
impl ManagedBuildSettlement {
    pub(in crate::build) fn context(&self) -> &super::journal::managed::ManagedAttemptContext {
        &self.context
    }
    pub(in crate::build) const fn nonce(&self) -> crate::store::ContentDigest {
        self.nonce
    }
    #[cfg(test)]
    pub(in crate::build) fn for_test(
        context: super::journal::managed::ManagedAttemptContext,
        nonce: crate::store::ContentDigest,
    ) -> Self {
        Self {
            context,
            nonce,
        }
    }
}
/// Keep this single-use owner and its borrowed preparation until settlement.
pub struct ManagedBuildExecution<'a> {
    prepared: &'a PreparedManagedBuild,
    specification: ManagedBuildServiceSpecification,
    handshake: Option<ManagedBuildHandshake<'a>>,
    binding: Option<ObservedManagedBuildBinding>,
    reference: Option<SystemdUnitReference>,
    cgroup: Option<PinnedManagedBuildCgroup>,
    namespace: Option<OwnedFd>,
    committed: Option<CommittedManagedBuild<'a>>,
    captured: Option<CapturedManagedBuildOutput>,
    start: Option<SystemdJob>,
    stop: Option<SystemdJob>,
    started: bool,
    stop_attempted: bool,
    resources: ResourceTransfer,
    settlement: Settlement,
}
impl std::fmt::Debug for ManagedBuildExecution<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedBuildExecution")
            .field("specification", &self.specification)
            .field("started", &self.started)
            .field("settlement", &self.settlement)
            .finish_non_exhaustive()
    }
}
impl<'a> ManagedBuildExecution<'a> {
    /// Prepare the listener and Awaiting record; does not issue Start.
    pub fn prepare(
        prepared: &'a PreparedManagedBuild,
        manager: &mut SystemdManager,
        directory: &Path,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self, BuildError> {
        let handshake =
            ManagedBuildHandshake::begin(prepared, manager, directory, cancel, deadline)?;
        let specification = handshake.specification().clone();
        Ok(Self {
            prepared,
            specification,
            handshake: Some(handshake),
            binding: None,
            reference: None,
            cgroup: None,
            namespace: None,
            committed: None,
            captured: None,
            start: None,
            stop: None,
            started: false,
            stop_attempted: false,
            resources: ResourceTransfer::NotSent,
            settlement: Settlement::Pending,
        })
    }
    /// Start once; publish only after separately observed manager/process settlement.
    #[cfg(test)]
    pub fn run(
        &mut self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
    ) -> Result<BuildResult, BuildError> {
        self.run_controlled(manager, cancel, cancel)
    }
    pub(in crate::build) fn run_controlled(
        &mut self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        publication: &dyn super::cancellation::BuildControl,
    ) -> Result<BuildResult, BuildError> {
        if self.started || self.settlement != Settlement::Pending {
            return Err(BuildError::InvalidRequest);
        }
        match self.drive(manager, cancel, publication) {
            Ok(result) => Ok(result),
            Err(primary) => match self.cancel_and_settle(manager) {
                Ok(()) => Err(primary),
                Err(_) => Err(BuildError::Settlement {
                    stage: self.prepared.layout().staging,
                    reason: "managed attempt remains unconfirmed; keep its execution owner",
                    primary: Some(Box::new(primary)),
                }),
            },
        }
    }
    fn drive(
        &mut self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        publication: &dyn super::cancellation::BuildControl,
    ) -> Result<BuildResult, BuildError> {
        cancel.check()?;
        let deadline = Instant::now() + PREPARATION;
        self.check_epoch(manager, cancel, deadline)?;
        self.prepared
            .authorize_manager_start(&self.specification, cancel, deadline)?;
        let start_budget = remaining(cancel, deadline)?;
        self.started = true; // A lost Start reply must never permit a replay.
        self.start = Some(
            manager
                .start_transient(self.specification.service(), start_budget, cancel)
                .map_err(manager_error)?,
        );
        self.wait_started(manager, cancel, deadline)?;
        self.pin_worker(manager, cancel, deadline)?;
        let authenticated = self
            .handshake
            .take()
            .ok_or(BuildError::InvalidRequest)?
            .accept(manager, cancel, deadline)?;
        require_same_binding(self.binding.as_ref(), authenticated.binding())?;
        self.resources = ResourceTransfer::MayHaveReachedWorker;
        let namespace = authenticated
            .send_resources(manager, cancel, deadline)?
            .observe_retention(manager, cancel, deadline)?
            .observe_namespace(manager, cancel, deadline)?;
        self.namespace = Some(
            namespace
                .namespace_identity()
                .pidfd()
                .try_clone_to_owned()?,
        );
        self.committed = Some(namespace.authorize_execution(manager, cancel, deadline)?);
        let execution_deadline =
            Instant::now() + Duration::from_secs(u64::from(self.prepared.timeout_seconds()) + 5);
        self.captured = Some(
            self.committed
                .as_mut()
                .expect("committed attempt")
                .collect_output(cancel, execution_deadline)?,
        );
        // Drain before awaiting the notify job. Short builds may already be inactive.
        let deadline = Instant::now() + CLEANUP;
        let completion = manager
            .wait_job(
                self.start.as_ref().expect("accepted start"),
                remaining(cancel, deadline)?,
                cancel,
            )
            .map_err(manager_error)?;
        if !matches!(
            completion,
            SystemdJobCompletion::Observed {
                result: SystemdJobResult::Done,
                ..
            }
        ) {
            return Err(BuildError::Execution(
                "managed start job did not complete successfully".into(),
            ));
        }
        self.settle(manager, cancel, deadline, true)?;
        self.release_reference(manager, cancel, deadline)?;
        self.complete(cancel, deadline)?;
        let captured = self.captured.take().ok_or(BuildError::Output)?;
        self.prepared
            .publish_captured(captured, cancel, publication)
    }
    fn pin_worker(
        &mut self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        // This observation does not change Awaiting to Bound. Save every pin as
        // it is acquired so a later Hello failure retains cleanup evidence.
        let binding = observe_managed_build_binding(
            self.prepared,
            &self.specification,
            manager,
            cancel,
            deadline,
        )?;
        self.binding = Some(binding.duplicate_evidence());
        self.reference = Some(
            manager
                .reference_unit(
                    &binding.context().unit,
                    remaining(cancel, deadline)?,
                    cancel,
                )
                .map_err(manager_error)?,
        );
        self.cgroup = Some(PinnedManagedBuildCgroup::capture(
            self.prepared,
            &self.specification,
            &binding,
            manager,
            cancel,
            deadline,
        )?);
        Ok(())
    }
    fn wait_started(
        &self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        loop {
            self.check_epoch(manager, cancel, deadline)?;
            if let Some(status) = manager
                .query(
                    &self.specification.context().unit,
                    remaining(cancel, deadline)?,
                    cancel,
                )
                .map_err(manager_error)?
            {
                if matches!(
                    status.active_state.as_str(),
                    "inactive" | "failed"
                ) {
                    return Err(BuildError::Execution(
                        "managed worker exited before Hello".into(),
                    ));
                }
                if status.main_pid > 1
                    && status.invocation.len() == 16
                    && status.invocation.iter().any(|byte| *byte != 0)
                {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    /// Revoke before Stop, using a cleanup token independent of caller cancellation.
    /// A Stop with an uncertain reply is never repeated on this owner.
    pub fn cancel_and_settle(&mut self, manager: &mut SystemdManager) -> Result<(), BuildError> {
        if self.settlement == Settlement::Complete {
            return Ok(());
        }
        let cancel = Cancellation::default();
        let deadline = Instant::now() + CLEANUP;
        if self.settlement == Settlement::Processes {
            self.release_reference(manager, &cancel, deadline)?;
            return self.complete(&cancel, deadline);
        }
        self.prepared
            .revoke_manager_attempt(&cancel, deadline)?;
        if !self.started {
            self.settlement = Settlement::Processes;
            return self.complete(&cancel, deadline);
        }
        let status = self.owned_status(manager, &cancel, deadline)?;
        if !inactive(&status) && !self.stop_attempted {
            self.stop_attempted = true;
            self.stop = Some(
                manager
                    .stop(
                        &self.specification.context().unit,
                        remaining(&cancel, deadline)?,
                        &cancel,
                    )
                    .map_err(manager_error)?,
            );
        }
        if let Some(job) = &self.stop {
            manager
                .wait_job(job, remaining(&cancel, deadline)?, &cancel)
                .map_err(manager_error)?;
        }
        self.settle(manager, &cancel, deadline, false)?;
        self.release_reference(manager, &cancel, deadline)?;
        self.complete(&cancel, deadline)
    }
    fn complete(&mut self, cancel: &Cancellation, deadline: Instant) -> Result<(), BuildError> {
        if self.settlement != Settlement::Processes || self.reference.is_some() {
            return Err(BuildError::InputChanged);
        }
        let proof = ManagedBuildSettlement {
            context: self.specification.context().clone(),
            nonce: crate::store::ContentDigest::sha256(self.specification.nonce().as_bytes()),
        };
        self.prepared
            .record_settlement(&proof, cancel, deadline)?;
        self.settlement = Settlement::Complete;
        Ok(())
    }
    fn check_epoch(
        &self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        let context = self.specification.context();
        if BootId::current(cancel, deadline)
            .map_err(|error| match error {
                crate::platform::linux::boot::BootError::Cancelled => BuildError::Cancelled,
                error => BuildError::Cache(error.to_string()),
            })?
            .as_str()
            != context.boot
            || manager
                .observe_identity(remaining(cancel, deadline)?, cancel)
                .map_err(manager_error)?
                .fingerprint()
                != context.manager
        {
            return Err(BuildError::InputChanged);
        }
        Ok(())
    }
    fn owned_status(
        &self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<SystemdUnitStatus, BuildError> {
        self.check_epoch(manager, cancel, deadline)?;
        manager
            .verify_unit_reference(
                self.reference
                    .as_ref()
                    .ok_or(BuildError::InputChanged)?,
                remaining(cancel, deadline)?,
                cancel,
            )
            .map_err(manager_error)?;
        let binding = self
            .binding
            .as_ref()
            .ok_or(BuildError::InputChanged)?;
        let status = manager
            .query(
                &binding.context().unit,
                remaining(cancel, deadline)?,
                cancel,
            )
            .map_err(manager_error)?
            .ok_or(BuildError::InputChanged)?;
        if status.unit != binding.context().unit || status.invocation != *binding.invocation() {
            return Err(BuildError::InputChanged);
        }
        self.check_epoch(manager, cancel, deadline)?;
        Ok(status)
    }
    fn settle(
        &mut self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
        success: bool,
    ) -> Result<(), BuildError> {
        loop {
            let before = self.owned_status(manager, cancel, deadline)?;
            let binding = self
                .binding
                .as_ref()
                .ok_or(BuildError::InputChanged)?;
            let namespace_exited = self
                .namespace
                .as_ref()
                .map(|namespace| linux_fd::pidfd_exited(namespace.as_fd()))
                .transpose()?;
            let cgroup = self
                .cgroup
                .as_mut()
                .ok_or(BuildError::InputChanged)?;
            if !cgroup.matches_binding(binding) {
                return Err(BuildError::InputChanged);
            }
            let processes_exited =
                self.resources.namespace_settled(namespace_exited) && cgroup.worker_exited()?;
            let quiet = match cgroup.observe(manager, cancel, deadline)? {
                ManagedCgroupObservation::Empty(proof)
                | ManagedCgroupObservation::Removed(proof) => {
                    proof.matches_binding(binding) && proof.worker_exited()?
                }
                ManagedCgroupObservation::Pending(reason) => {
                    if Instant::now() >= deadline {
                        return Err(BuildError::Cache(format!(
                            "managed cgroup remains pending: {reason:?}"
                        )));
                    }
                    false
                }
            };
            let store = manager
                .query_fd_store(
                    &binding.context().unit,
                    remaining(cancel, deadline)?,
                    cancel,
                )
                .map_err(manager_error)?;
            let fd_empty = store.is_some_and(|store| {
                store.invocation == *binding.invocation()
                    && store.count == 0
                    && store.max == 2
                    && store.notify_access == "main"
            });
            // This fresh observation also reconciles a Stop reply whose job
            // could not be parsed, provided the same connection remains valid.
            let idle = manager
                .unit_idle_without_job(
                    &binding.context().unit,
                    remaining(cancel, deadline)?,
                    cancel,
                )
                .map_err(manager_error)?;
            let after = self.owned_status(manager, cancel, deadline)?;
            if before == after && inactive(&after) && processes_exited && quiet && fd_empty && idle
            {
                if success && !successful(&after) {
                    return Err(BuildError::Execution(
                        "managed worker unit reported failure".into(),
                    ));
                }
                self.settlement = Settlement::Processes;
                return Ok(());
            }
            remaining(cancel, deadline)?;
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn release_reference(
        &mut self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        if let Some(reference) = self.reference.as_mut() {
            manager
                .unreference_unit(reference, remaining(cancel, deadline)?, cancel)
                .map_err(manager_error)?;
        }
        self.reference = None;
        Ok(())
    }
}
fn require_same_binding(
    expected: Option<&ObservedManagedBuildBinding>,
    actual: &ObservedManagedBuildBinding,
) -> Result<(), BuildError> {
    if expected.is_some_and(|expected| same_binding(expected, actual)) {
        Ok(())
    } else {
        Err(BuildError::InputChanged)
    }
}
fn inactive(status: &SystemdUnitStatus) -> bool {
    matches!(
        status.active_state.as_str(),
        "inactive" | "failed"
    ) && status.main_pid == 0
}
fn successful(status: &SystemdUnitStatus) -> bool {
    inactive(status)
        && status.active_state == "inactive"
        && status.result == "success"
        && status.exec_main_code == 1
        && status.exec_main_status == 0
}
fn manager_error(error: crate::systemd::SystemdError) -> BuildError {
    match error {
        crate::systemd::SystemdError::Cancelled => BuildError::Cancelled,
        crate::systemd::SystemdError::Deadline => BuildError::Timeout,
        error => BuildError::Cache(error.to_string()),
    }
}

use super::ManagedBuildInputs;
use crate::{
    config::ManagedBuildConfiguration,
    store::{RootName, Store},
};

impl ManagedBuildInputs {
    /// Execute with explicitly pinned worker bytes and manager configuration.
    /// On uncertain settlement the journal is preserved for reconciliation;
    /// returning an error never authorizes another attempt or staging cleanup.
    pub fn execute(
        self,
        store: &Store,
        configuration: &ManagedBuildConfiguration,
        root: Option<&RootName>,
        cancellation: &Cancellation,
    ) -> Result<BuildResult, BuildError> {
        cancellation.check()?;
        if !self.source_interest.same_store(store)?
            || self.action.worker != configuration.worker_digest()
        {
            return Err(BuildError::InputChanged);
        }
        crate::runtime::validate_static_worker_image(&self.worker)
            .map_err(|_| BuildError::InvalidRequest)?;
        let action = self.action.clone();
        let timeout = self.timeout_seconds;
        crate::build::shared::realize_owned(
            store,
            &action,
            timeout,
            root,
            cancellation,
            |operation, producer| {
                with_pre_handshake_cleanup(&operation, |handshake_attempted| {
                    crate::build::cancellation::with_managed_cancellation(producer, |cancel| {
                        let prepared = self.stage_in(std::sync::Arc::clone(&operation), cancel)?;
                        let mut manager = SystemdManager::connect(
                            configuration.scope().clone(),
                            Duration::from_secs(30),
                            cancel,
                        )
                        .map_err(manager_error)?;
                        // From this boundary onward even an error can have installed
                        // managed admission evidence; preserve it for reconciliation.
                        *handshake_attempted = true;
                        let mut execution = ManagedBuildExecution::prepare(
                            &prepared,
                            &mut manager,
                            configuration.socket_parent(),
                            cancel,
                            Instant::now() + Duration::from_secs(30),
                        )?;
                        execution.run_controlled(&mut manager, cancel, producer)
                    })
                })
            },
        )
    }
}

// A marker here tracks local control flow only, never remote settlement. Once
// handshake preparation is attempted, this helper cannot authorize cleanup.
fn with_pre_handshake_cleanup<T>(
    operation: &crate::build::journal::Operation,
    work: impl FnOnce(&mut bool) -> Result<T, BuildError>,
) -> Result<T, BuildError> {
    let mut handshake_attempted = false;
    let result = work(&mut handshake_attempted);
    match result {
        Err(primary) if !handshake_attempted => Err(match operation.clean_stage() {
            Ok(()) => primary,
            Err(cleanup) => BuildError::FailureAndJournal {
                primary: Box::new(primary),
                journal: cleanup.to_string(),
            },
        }),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd::SystemdUnitName;

    fn completed() -> SystemdUnitStatus {
        SystemdUnitStatus {
            unit: SystemdUnitName::new("syrox-build-status.service").unwrap(),
            invocation: vec![1; 16],
            active_state: "inactive".into(),
            sub_state: "dead".into(),
            control_group: String::new(),
            result: "success".into(),
            main_pid: 0,
            exec_main_code: libc::CLD_EXITED,
            exec_main_status: 0,
        }
    }
    #[test]
    fn successful_exit_requires_inactive_unit_and_no_remaining_main_process() {
        let status = completed();
        assert!(inactive(&status));
        assert!(successful(&status));
        for state in [
            "active",
            "activating",
            "deactivating",
            "reloading",
            "maintenance",
        ] {
            let mut status = completed();
            status.active_state = state.into();
            // A saved exit-zero result is insufficient while the unit is live or
            // transitioning, even when MainPID is temporarily zero.
            assert!(!inactive(&status), "{state}");
            assert!(!successful(&status), "{state}");
        }
        let mut status = completed();
        status.main_pid = 123;
        assert!(!inactive(&status));
        assert!(!successful(&status));
    }
    #[test]
    fn cleanup_eligibility_does_not_promote_failed_or_signalled_builds_to_success() {
        let mut status = completed();
        status.active_state = "failed".into();
        assert!(inactive(&status));
        assert!(!successful(&status));
        status.main_pid = 123;
        assert!(!inactive(&status));
        for result in [
            "exit-code",
            "signal",
            "timeout",
            "oom-kill",
            "resources",
            "",
        ] {
            let mut status = completed();
            status.result = result.into();
            assert!(inactive(&status));
            assert!(!successful(&status), "{result}");
        }
        for code in [
            0,
            libc::CLD_KILLED,
            libc::CLD_DUMPED,
            libc::CLD_STOPPED,
            libc::CLD_CONTINUED,
        ] {
            let mut status = completed();
            status.exec_main_code = code;
            assert!(!successful(&status), "wait code {code}");
        }
        for exit in [1, 15, 137, 255] {
            let mut status = completed();
            status.exec_main_status = exit;
            assert!(!successful(&status), "exit status {exit}");
        }
    }

    #[test]
    fn missing_namespace_is_safe_only_before_any_resource_transfer() {
        // A failed send does not report how many descriptors reached the worker.
        // It therefore has the same requirements as a completed resource transfer.
        assert!(ResourceTransfer::NotSent.namespace_settled(None));
        assert!(!ResourceTransfer::MayHaveReachedWorker.namespace_settled(None));
        for phase in [
            ResourceTransfer::NotSent,
            ResourceTransfer::MayHaveReachedWorker,
        ] {
            assert!(!phase.namespace_settled(Some(false)));
            assert!(phase.namespace_settled(Some(true)));
        }
    }

    fn observed_worker() -> ObservedManagedBuildBinding {
        ObservedManagedBuildBinding::for_test(
            journal::managed::ManagedAttemptContext {
                action: crate::store::ContentDigest::sha256(b"action"),
                worker: crate::store::ContentDigest::sha256(b"worker"),
                boot: "11111111-1111-1111-1111-111111111111".into(),
                manager: crate::store::ContentDigest::sha256(b"manager"),
                scope: "system".into(),
                unit: SystemdUnitName::new("syrox-build-status.service").unwrap(),
                uid: 1000,
                gid: 1000,
            },
            "11111111111111111111111111111111".into(),
            [1; 16],
            42,
            crate::store::ContentDigest::sha256(b"contract"),
        )
    }

    #[test]
    fn hello_cannot_replace_preobserved_worker_or_supply_missing_authority() {
        let expected = observed_worker();
        assert!(require_same_binding(Some(&expected), &expected.duplicate_evidence()).is_ok());
        assert!(require_same_binding(None, &expected).is_err());
        for change in 0..9 {
            let mut context = expected.context().clone();
            let mut invocation = *expected.invocation();
            let mut pid = expected.main_pid();
            let mut nonce = expected.nonce().to_owned();
            let mut contract = expected.contract();
            match change {
                0 => context.unit = SystemdUnitName::new("syrox-build-other.service").unwrap(),
                1 => context.boot = "22222222-2222-2222-2222-222222222222".into(),
                2 => context.manager = crate::store::ContentDigest::sha256(b"another manager"),
                3 => context.action = crate::store::ContentDigest::sha256(b"another action"),
                4 => context.worker = crate::store::ContentDigest::sha256(b"another worker"),
                5 => invocation = [2; 16],
                6 => pid += 1,
                7 => nonce = "22222222222222222222222222222222".into(),
                8 => contract = crate::store::ContentDigest::sha256(b"another service contract"),
                _ => unreachable!(),
            }
            let actual =
                ObservedManagedBuildBinding::for_test(context, nonce, invocation, pid, contract);
            assert!(
                require_same_binding(Some(&expected), &actual).is_err(),
                "change {change}"
            );
        }
    }

    fn pinned_host_worker() -> Vec<u8> {
        const MAXIMUM: u64 = 128 * 1024 * 1024;
        use std::io::Read as _;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        let path = std::path::PathBuf::from(
            std::env::var_os("SYROX_MANAGED_WORKER")
                .expect("explicit static worker candidate required"),
        );
        assert!(path.is_absolute());
        let text =
            std::env::var("SYROX_MANAGED_WORKER_SHA256").expect("explicit worker SHA256 required");
        let pin: crate::store::ContentDigest = text.parse().expect("canonical worker SHA256");
        assert_eq!(pin.to_string(), text);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .expect("regular candidate worker");
        let before = file.metadata().unwrap();
        assert!(before.is_file() && before.len() <= MAXIMUM);
        let mut bytes = Vec::new();
        (&file)
            .take(MAXIMUM + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        let after = file.metadata().unwrap();
        assert!(bytes.len() as u64 <= MAXIMUM);
        assert_eq!(bytes.len() as u64, before.len());
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            )
        );
        assert_eq!(crate::store::ContentDigest::sha256(&bytes), pin);
        crate::runtime::validate_static_worker_image(&bytes)
            .expect("real static ELF worker required");
        bytes
    }

    #[test]
    #[ignore = "requires pinned static worker, private socket parent, Linux pidfs/user namespaces and systemd user >=254 with unit refs and cgroup settlement"]
    fn host_managed_directory_build_publishes_verified_artifact_without_toolchain() {
        let worker = pinned_host_worker();
        let sockets = std::path::PathBuf::from(
            std::env::var_os("SYROX_MANAGED_SOCKET_PARENT")
                .expect("explicit private short socket directory required"),
        );
        assert!(sockets.is_absolute());
        // Listener validation enforces ownership/mode 0700 and the full Unix path
        // bound. The test does not create or repair this external directory.
        let temporary = tempfile::tempdir().unwrap();
        let source = b"offline managed smoke source";
        let digest = crate::store::ContentDigest::sha256(source);
        std::fs::write(
            temporary.path().join("main.srx"),
            format!(
                r#"
            mod factories::recipe {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{
                package = std::Package {{ id = "managed-proof"; dependencies = []; }};
                acquisition = std::Option::Some(std::Acquisition {{ sources = [
                    std::SourceRequest {{ url = "https://example.invalid/offline-source";
                        sha256 = "{digest}"; maximum_bytes = 1024; }}
                ]; }});
                build = std::Option::Some(std::Build {{
                    profile = std::BuildProfile::Managed; source_directory = "source-1";
                    timeout_seconds = 120; source_format = std::BuildSourceFormat::Raw;
                    steps = [
                        std::BuildStep::Directory(std::BuildPath::Output("out", "proof")),
                        std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "proof/source"))
                    ];
                }});
            }} }} }} pub publish(factories, recipe): std::Recipe;
        "#
            ),
        )
        .unwrap();
        let checks = crate::project::CheckConfiguration {
            standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
            ..crate::project::CheckConfiguration::default()
        };
        crate::project::lock_project_with(temporary.path(), &checks).unwrap();
        let plan =
            crate::project::plan_project_package_with(temporary.path(), &checks, "recipe").unwrap();
        let request = plan.builds().next().unwrap().request();
        let store = Store::initialize(&temporary.path().join("store")).unwrap();
        store
            .operation()
            .unwrap()
            .ingest(&source[..], digest, source.len() as u64)
            .unwrap();
        let cancel = Cancellation::default();
        let prepared = crate::build::managed::preparation::prepare_managed_build(
            &plan, &request, &store, &worker, &cancel,
        )
        .unwrap();
        let scope = crate::systemd::SystemdScope::User {
            bus_socket: std::path::PathBuf::from(format!("/run/user/{}/bus", linux_fd::real_uid())),
        };
        let mut manager = SystemdManager::connect(scope, Duration::from_secs(30), &cancel).unwrap();
        let mut execution = ManagedBuildExecution::prepare(
            &prepared,
            &mut manager,
            &sockets,
            &cancel,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
        let result = match execution.run(&mut manager, &cancel) {
            Ok(result) => result,
            Err(error) => {
                let preserved = temporary.keep();
                panic!(
                    "managed host gate failed; evidence retained at {}: {error}",
                    preserved.display()
                );
            }
        };
        assert_eq!(result.toolchain, None);
        assert_eq!(result.action, prepared.action_digest());
        let view =
            crate::result::materialize_artifact(&store, &result.root, result.receipt).unwrap();
        view.verify_view(&cancel).unwrap();
        assert!(view.directory().unwrap().join("proof").is_dir());
        assert_eq!(
            std::fs::read(view.directory().unwrap().join("proof/source")).unwrap(),
            source
        );
        assert_eq!(view.artifact(), result.artifact);
    }

    use crate::build::{cache, journal, shared};

    #[test]
    fn bridge_precheck_cancellation_cleans_unstarted_shared_operation() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::initialize(&directory.path().join("store")).unwrap();
        let action = cache::tests::action();
        let cancellation = Cancellation::default();
        let result = shared::realize_owned(
            &store,
            &action,
            30,
            None,
            &cancellation,
            |operation, producer| {
                cancellation.cancel();
                with_pre_handshake_cleanup(&operation, |_handshake_attempted| {
                    crate::build::cancellation::with_managed_cancellation(producer, |_cancel| {
                        panic!("cancelled precheck must not enter preparation");
                    })
                })
            },
        );
        assert!(matches!(result, Err(BuildError::Cancelled)));
        let report = journal::recover(&store).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(
            report.entries[0].state,
            crate::build::BuildRecoveryState::Recovered
        );
    }
}

use crate::deployment::os::activation::{ActivationJournal, EffectKind, ExecutionEpoch};
use crate::deployment::os::launch_binding::OsLaunchBinding;
use crate::systemd::persistent::OsUnitContract;
use crate::{
    cancellation::Cancellation, store::ContentDigest, systemd::SystemdFdStoreObserved,
    systemd::SystemdJob, systemd::SystemdJobCompletion, systemd::SystemdJobResult,
    systemd::SystemdManager, systemd::SystemdUnitName, systemd::SystemdUnitStatus,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
#[error("Os manager effect failed during {stage}{detail}", detail = .source.as_ref().map(|error| format!(": {error}")).unwrap_or_default())]
pub(super) struct ApplyManagerError {
    stage: &'static str,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
impl ApplyManagerError {
    const fn new(stage: &'static str) -> Self {
        Self {
            stage,
            source: None,
        }
    }
    pub(in crate::deployment::os::apply) fn caused_by(
        stage: &'static str,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            stage,
            source: Some(source.into()),
        }
    }
    #[cfg(test)]
    pub(super) const fn for_test(stage: &'static str) -> Self {
        Self::new(stage)
    }
}

type Result<T> = std::result::Result<T, ApplyManagerError>;
type Observation = (
    Option<String>,
    Vec<(SystemdUnitName, ContentDigest)>,
);
#[derive(Debug, PartialEq, Eq)]
pub(super) enum EffectStatus {
    Observed {
        invocation: Option<String>,
    },
    Uncertain {
        stage: &'static str,
        error: Option<String>,
    },
}
#[derive(Debug)]
pub(super) struct EffectOutcome {
    pub effect: String,
    pub state: EffectStatus,
    pub loaded: Vec<(SystemdUnitName, ContentDigest)>,
}
/// Internal to the apply coordinator. The real adapter is the only production
/// implementation; tests inject replies while using the durable journal itself.
pub(super) trait Manager {
    type Job;
    fn unit_idle_without_job(
        &mut self,
        unit: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<bool>;
    fn epoch(&mut self, expected: &ExecutionEpoch, budget: &Budget<'_>) -> Result<()>;
    fn query(
        &mut self,
        unit: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<Option<SystemdUnitStatus>>;
    fn fd_store(
        &mut self,
        unit: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<Option<SystemdFdStoreObserved>>;
    fn recorded_job_absent(&mut self, path: &str, budget: &Budget<'_>) -> Result<bool>;
    fn loaded(&mut self, contract: &OsUnitContract, budget: &Budget<'_>) -> Result<ContentDigest>;
    fn reload(&mut self, budget: &Budget<'_>) -> Result<()>;
    fn start(&mut self, unit: &SystemdUnitName, budget: &Budget<'_>) -> Result<Self::Job>;
    fn stop(&mut self, unit: &SystemdUnitName, budget: &Budget<'_>) -> Result<Self::Job>;
    fn job_path(job: &Self::Job) -> &str;
    fn wait(&mut self, job: &Self::Job, budget: &Budget<'_>) -> Result<SystemdJobCompletion>;
}
pub(super) struct Budget<'a> {
    cancellation: &'a Cancellation,
    deadline: Instant,
}
impl Budget<'_> {
    fn remaining(&self) -> Result<Duration> {
        if self.cancellation.is_cancelled() {
            return Err(ApplyManagerError::new("operation cancelled"));
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(ApplyManagerError::new(
                "operation deadline expired",
            ))
    }
}
impl Manager for SystemdManager {
    type Job = SystemdJob;
    fn unit_idle_without_job(
        &mut self,
        unit: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<bool> {
        self.unit_idle_without_job(unit, budget.remaining()?, budget.cancellation)
            .map_err(|source| ApplyManagerError::caused_by("observe idle unit without job", source))
    }
    fn epoch(&mut self, expected: &ExecutionEpoch, budget: &Budget<'_>) -> Result<()> {
        let identity = self
            .observe_identity(budget.remaining()?, budget.cancellation)
            .map_err(|source| ApplyManagerError::caused_by("observe manager identity", source))?;
        let boot =
            crate::platform::linux::boot::BootId::current(budget.cancellation, budget.deadline)
                .map_err(|source| ApplyManagerError::caused_by("observe boot identity", source))?;
        if identity.fingerprint().to_string() != expected.manager || boot != expected.boot {
            return Err(ApplyManagerError::new("manager epoch changed"));
        }
        Ok(())
    }
    fn query(
        &mut self,
        unit: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<Option<SystemdUnitStatus>> {
        self.query(unit, budget.remaining()?, budget.cancellation)
            .map_err(|source| ApplyManagerError::caused_by("query unit", source))
    }
    fn fd_store(
        &mut self,
        unit: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<Option<SystemdFdStoreObserved>> {
        self.query_fd_store(unit, budget.remaining()?, budget.cancellation)
            .map_err(|source| ApplyManagerError::caused_by("query descriptor store", source))
    }
    fn recorded_job_absent(&mut self, path: &str, budget: &Budget<'_>) -> Result<bool> {
        self.recorded_job_absent(path, budget.remaining()?, budget.cancellation)
            .map_err(|source| ApplyManagerError::caused_by("observe recorded stop job", source))
    }
    fn loaded(&mut self, contract: &OsUnitContract, budget: &Budget<'_>) -> Result<ContentDigest> {
        self.observe_os_unit(contract, budget.remaining()?, budget.cancellation)
            .map(|observed| observed.fingerprint())
            .map_err(|error| {
                eprintln!(
                    "Os loaded unit {}: {error}",
                    contract.unit().as_str()
                );
                ApplyManagerError::caused_by("observe loaded unit", error)
            })
    }
    fn reload(&mut self, budget: &Budget<'_>) -> Result<()> {
        self.reload(budget.remaining()?, budget.cancellation)
            .map_err(|source| ApplyManagerError::caused_by("reload manager", source))
    }
    fn start(&mut self, unit: &SystemdUnitName, budget: &Budget<'_>) -> Result<Self::Job> {
        self.start_unit(unit, budget.remaining()?, budget.cancellation)
            .map_err(|source| ApplyManagerError::caused_by("submit start", source))
    }
    fn stop(&mut self, unit: &SystemdUnitName, budget: &Budget<'_>) -> Result<Self::Job> {
        self.stop(unit, budget.remaining()?, budget.cancellation)
            .map_err(|source| ApplyManagerError::caused_by("submit stop", source))
    }
    fn job_path(job: &Self::Job) -> &str {
        job.path()
    }
    fn wait(&mut self, job: &Self::Job, budget: &Budget<'_>) -> Result<SystemdJobCompletion> {
        self.wait_job(job, budget.remaining()?, budget.cancellation)
            .map_err(|source| ApplyManagerError::caused_by("observe job completion", source))
    }
}

pub(super) struct ApplyManager<'a, M: Manager = SystemdManager> {
    pub manager: &'a mut M,
    pub journal: &'a ActivationJournal,
    pub operation: &'a str,
    pub epoch: &'a ExecutionEpoch,
    pub cancellation: &'a Cancellation,
    pub deadline: Instant,
}
impl<M: Manager> ApplyManager<'_, M> {
    pub(super) fn verify_boot_idle(&mut self, unit: &SystemdUnitName) -> Result<bool> {
        let budget = Budget {
            cancellation: self.cancellation,
            deadline: self.deadline,
        };
        self.manager.epoch(self.epoch, &budget)?;
        let idle = self
            .manager
            .unit_idle_without_job(unit, &budget)?;
        self.manager.epoch(self.epoch, &budget)?;
        Ok(idle)
    }
    fn plan(&mut self, resource: &str, kind: EffectKind, target: ContentDigest) -> Result<String> {
        let budget = Budget {
            cancellation: self.cancellation,
            deadline: self.deadline,
        };
        budget.remaining()?;
        self.manager.epoch(self.epoch, &budget)?;
        let snapshot = self
            .journal
            .snapshot(self.cancellation, self.deadline)
            .map_err(|source| ApplyManagerError::caused_by("read activation journal", source))?;
        if snapshot
            .operations
            .get(self.operation)
            .is_none_or(|op| &op.epoch != self.epoch)
        {
            return Err(ApplyManagerError::new("operation epoch differs"));
        }
        self.journal
            .plan_effect(
                self.operation,
                resource,
                kind,
                None,
                target,
                self.cancellation,
                self.deadline,
            )
            .map_err(|source| ApplyManagerError::caused_by("persist effect intent", source))
    }
    fn finish(
        &self,
        effect: String,
        target: ContentDigest,
        result: Result<Observation>,
    ) -> EffectOutcome {
        match result {
            Ok((invocation, loaded)) => {
                if let Err(source) = self.journal.record_observed(
                    self.operation,
                    &effect,
                    target,
                    invocation.as_deref(),
                    self.cancellation,
                    self.deadline,
                ) {
                    return self.uncertain(
                        effect,
                        ApplyManagerError::caused_by("persist observed effect", source),
                    );
                }
                EffectOutcome {
                    effect,
                    state: EffectStatus::Observed {
                        invocation,
                    },
                    loaded,
                }
            }
            Err(error) => self.uncertain(effect, error),
        }
    }
    fn uncertain(&self, effect: String, error: ApplyManagerError) -> EffectOutcome {
        // Failure to persist Unknown leaves Intent/Accepted, both unresolved.
        let _ = self.journal.record_unknown(
            self.operation,
            &effect,
            self.cancellation,
            self.deadline,
        );
        EffectOutcome {
            effect,
            state: EffectStatus::Uncertain {
                stage: error.stage,
                error: error.source.map(|source| source.to_string()),
            },
            loaded: Vec::new(),
        }
    }
    fn accepted(&self, effect: &str, job: &M::Job) -> Result<()> {
        self.journal
            .record_accepted(
                self.operation,
                effect,
                M::job_path(job),
                self.cancellation,
                self.deadline,
            )
            .map_err(|source| ApplyManagerError::caused_by("persist accepted job", source))
    }
    pub(super) fn stop(
        &mut self,
        resource: &str,
        unit: &SystemdUnitName,
        expected_invocation: &[u8; 16],
        target: ContentDigest,
    ) -> Result<EffectOutcome> {
        if expected_invocation.iter().all(|byte| *byte == 0) {
            return Err(ApplyManagerError::new(
                "empty expected invocation",
            ));
        }
        let effect = self.plan(resource, EffectKind::Stop, target)?;
        let result = (|| {
            let budget = Budget {
                cancellation: self.cancellation,
                deadline: self.deadline,
            };
            let Some(status) = self.manager.query(unit, &budget)? else {
                self.manager.epoch(self.epoch, &budget)?;
                return Ok((None, Vec::new()));
            };
            if &status.unit != unit || status.invocation != expected_invocation {
                return Err(ApplyManagerError::new("stop invocation conflict"));
            }
            self.manager.epoch(self.epoch, &budget)?;
            let job = self.manager.stop(unit, &budget)?;
            self.accepted(&effect, &job)?;
            completed(&self.manager.wait(&job, &budget)?)?;
            self.manager.epoch(self.epoch, &budget)?;
            if let Some(current) = self.manager.query(unit, &budget)?
                && (&current.unit != unit
                    || current.invocation != expected_invocation
                    || !matches!(
                        current.active_state.as_str(),
                        "inactive" | "failed"
                    ))
            {
                return Err(ApplyManagerError::new(
                    "stop state conflicts after completion",
                ));
            }
            Ok((
                Some(invocation_hex(expected_invocation)),
                Vec::new(),
            ))
        })();
        Ok(self.finish(effect, target, result))
    }
    pub(super) fn reload(
        &mut self,
        resource: &str,
        target: ContentDigest,
        contracts: &[&OsUnitContract],
    ) -> Result<EffectOutcome> {
        if contracts.is_empty() || contracts.len() > 1024 || reload_target(contracts) != target {
            return Err(ApplyManagerError::new("invalid reload batch"));
        }
        let mut units = std::collections::BTreeSet::new();
        if contracts
            .iter()
            .any(|contract| !units.insert(contract.unit()))
        {
            return Err(ApplyManagerError::new("duplicate reload unit"));
        }
        let effect = self.plan(resource, EffectKind::Reload, target)?;
        let result = (|| {
            let budget = Budget {
                cancellation: self.cancellation,
                deadline: self.deadline,
            };
            self.manager.reload(&budget)?;
            let mut loaded = Vec::with_capacity(contracts.len());
            for contract in contracts {
                budget.remaining()?;
                loaded.push((
                    contract.unit().clone(),
                    self.manager.loaded(contract, &budget)?,
                ));
            }
            self.manager.epoch(self.epoch, &budget)?;
            Ok((None, loaded))
        })();
        Ok(self.finish(effect, target, result))
    }
    /// Read-only observation for an identical authorized binding. It never
    /// adopts another invocation, records an effect, or repairs stale authority.
    pub(super) fn verify_running(
        &mut self,
        resource: &str,
        binding: &OsLaunchBinding,
        contract: &OsUnitContract,
        expected_invocation: &[u8; 16],
    ) -> Result<bool> {
        Ok(self
            .running_evidence(resource, binding, contract, expected_invocation)?
            .is_some())
    }
    fn running_evidence(
        &mut self,
        resource: &str,
        binding: &OsLaunchBinding,
        contract: &OsUnitContract,
        expected_invocation: &[u8; 16],
    ) -> Result<Option<ContentDigest>> {
        let target = binding
            .digest()
            .map_err(|source| ApplyManagerError::caused_by("invalid launch binding", source))?;
        if resource != binding.process_key()
            || binding.epoch() != self.epoch
            || contract.unit() != &binding.unit()
            || contract.scope() != &binding.context().scope()
            || contract.binding() != target
            || expected_invocation.iter().all(|byte| *byte == 0)
        {
            return Err(ApplyManagerError::new(
                "running contract differs from binding",
            ));
        }
        let budget = Budget {
            cancellation: self.cancellation,
            deadline: self.deadline,
        };
        self.manager.epoch(self.epoch, &budget)?;
        let unit = binding.unit();
        let Some(status) = self.manager.query(&unit, &budget)? else {
            return Ok(None);
        };
        if status.unit != unit || status.invocation != expected_invocation {
            return Err(ApplyManagerError::new(
                "running invocation conflict",
            ));
        }
        if matches!(
            status.active_state.as_str(),
            "inactive" | "failed"
        ) {
            return Ok(None);
        }
        if status.active_state != "active" || status.sub_state != "running" || status.main_pid == 0
        {
            return Err(ApplyManagerError::new(
                "running invocation is transitioning",
            ));
        }
        let loaded = self.manager.loaded(contract, &budget)?;
        let fd = self
            .manager
            .fd_store(&unit, &budget)?
            .ok_or(ApplyManagerError::new("running FD store absent"))?;
        if fd.invocation != expected_invocation
            || fd.count != 1
            || fd.max != 1
            || fd.notify_access != "main"
        {
            return Err(ApplyManagerError::new("running FD store differs"));
        }
        if !self
            .journal
            .start_gate_used(
                resource,
                target,
                &invocation_hex(expected_invocation),
                self.epoch,
                self.cancellation,
                self.deadline,
            )
            .map_err(|source| ApplyManagerError::caused_by("read start gate evidence", source))?
        {
            return Err(ApplyManagerError::new(
                "running gate evidence absent",
            ));
        }
        if self.manager.loaded(contract, &budget)? != loaded {
            return Err(ApplyManagerError::new(
                "loaded running contract changed",
            ));
        }
        self.manager.epoch(self.epoch, &budget)?;
        let current = self
            .manager
            .query(&unit, &budget)?
            .ok_or(ApplyManagerError::new("running unit disappeared"))?;
        if current.unit != unit
            || current.invocation != expected_invocation
            || current.main_pid != status.main_pid
            || current.active_state != "active"
            || current.sub_state != "running"
        {
            return Err(ApplyManagerError::new(
                "running invocation changed",
            ));
        }
        Ok(Some(loaded))
    }
    pub(super) fn start(
        &mut self,
        resource: &str,
        binding: &OsLaunchBinding,
        contract: &OsUnitContract,
    ) -> Result<EffectOutcome> {
        let target = binding
            .digest()
            .map_err(|source| ApplyManagerError::caused_by("invalid launch binding", source))?;
        if resource != binding.process_key()
            || binding.epoch() != self.epoch
            || contract.unit() != &binding.unit()
            || contract.scope() != &binding.context().scope()
            || contract.binding() != target
        {
            return Err(ApplyManagerError::new(
                "start contract differs from binding",
            ));
        }
        let effect = self.plan(resource, EffectKind::Start, target)?;
        let result = self.start_effect(&effect, resource, binding, contract, target);
        Ok(self.finish(effect, target, result))
    }
    fn start_effect(
        &mut self,
        effect: &str,
        resource: &str,
        binding: &OsLaunchBinding,
        contract: &OsUnitContract,
        target: ContentDigest,
    ) -> Result<Observation> {
        let budget = Budget {
            cancellation: self.cancellation,
            deadline: self.deadline,
        };
        let unit = binding.unit();
        let previous = self.manager.query(&unit, &budget)?;
        if previous.as_ref().is_some_and(|status| {
            status.unit != unit
                || !matches!(
                    status.active_state.as_str(),
                    "inactive" | "failed"
                )
        }) {
            return Err(ApplyManagerError::new(
                "start requires inactive or absent unit",
            ));
        }
        let loaded = self.manager.loaded(contract, &budget)?;
        self.manager.epoch(self.epoch, &budget)?;
        let job = self.manager.start(&unit, &budget)?;
        self.accepted(effect, &job)?;
        completed(&self.manager.wait(&job, &budget)?)?;
        self.manager.epoch(self.epoch, &budget)?;
        let status = self
            .manager
            .query(&unit, &budget)?
            .ok_or(ApplyManagerError::new("started unit disappeared"))?;
        let invocation: [u8; 16] = status
            .invocation
            .as_slice()
            .try_into()
            .map_err(|source| ApplyManagerError::caused_by("invalid started invocation", source))?;
        if status.unit != unit
            || status.active_state != "active"
            || status.sub_state != "running"
            || status.main_pid == 0
            || invocation.iter().all(|byte| *byte == 0)
            || previous
                .as_ref()
                .is_some_and(|old| old.invocation == invocation)
        {
            return Err(ApplyManagerError::new(
                "started invocation not active",
            ));
        }
        let fd = self
            .manager
            .fd_store(&unit, &budget)?
            .ok_or(ApplyManagerError::new("started FD store absent"))?;
        if fd.invocation != invocation || fd.count != 1 || fd.max != 1 || fd.notify_access != "main"
        {
            return Err(ApplyManagerError::new("started FD store differs"));
        }
        let text = invocation_hex(&invocation);
        if !self
            .journal
            .start_gate_used(
                resource,
                target,
                &text,
                self.epoch,
                self.cancellation,
                self.deadline,
            )
            .map_err(|source| ApplyManagerError::caused_by("read start gate evidence", source))?
        {
            return Err(ApplyManagerError::new(
                "start gate was not consumed",
            ));
        }
        if self.manager.loaded(contract, &budget)? != loaded {
            return Err(ApplyManagerError::new(
                "loaded start contract changed",
            ));
        }
        self.manager.epoch(self.epoch, &budget)?;
        let final_status = self
            .manager
            .query(&unit, &budget)?
            .ok_or(ApplyManagerError::new("started unit disappeared"))?;
        if final_status.invocation != invocation
            || final_status.main_pid != status.main_pid
            || final_status.active_state != "active"
            || final_status.sub_state != "running"
            || final_status.unit != unit
        {
            return Err(ApplyManagerError::new(
                "started invocation changed",
            ));
        }
        Ok((Some(text), vec![(unit, loaded)]))
    }
}
fn completed(completion: &SystemdJobCompletion) -> Result<()> {
    match completion {
        SystemdJobCompletion::Observed {
            result: SystemdJobResult::Done,
        } => Ok(()),
        _ => Err(ApplyManagerError::new(
            "job completion not confirmed successful",
        )),
    }
}
fn invocation_hex(invocation: &[u8; 16]) -> String {
    let mut text = String::with_capacity(32);
    for byte in invocation {
        write!(text, "{byte:02x}").expect("String write");
    }
    text
}
/// Identity of the desired rendered batch, distinct from effective observations.
pub(super) fn reload_target(contracts: &[&OsUnitContract]) -> ContentDigest {
    let sorted: BTreeMap<_, _> = contracts
        .iter()
        .map(|contract| (contract.unit().as_str(), contract.file_digest()))
        .collect();
    let mut hash = Sha256::new();
    hash.update(b"syrox-os-reload-target-v1\n");
    for (unit, pin) in sorted {
        hash.update(unit.as_bytes());
        hash.update([0]);
        hash.update(pin.to_string().as_bytes());
        hash.update([0]);
    }
    ContentDigest::from_sha256_hash(hash.finalize().into())
}
mod recovery;
#[cfg(test)]
mod tests;

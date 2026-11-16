//! Map an authenticated System action to finite manager limits and observe them.
//!
//! This adapter neither starts a unit nor authenticates its executable. Disk and
//! inode enforcement, worker handoff, settlement and receipts remain separate.

use super::{BuildError, SystemBuildAction};
use crate::{
    cancellation::Cancellation,
    store::ContentDigest,
    system::budget::{AdmittedBudget, BuilderCapacity},
    systemd::{
        SystemdBuildLimits, SystemdManager, SystemdService, SystemdUnitName, SystemdUnitStatus,
    },
};
use std::time::{Duration, Instant};

/// Requested process/cgroup properties bound to one System action. Construction
/// and application are pure; neither establishes actual resource enforcement.
#[derive(Clone, Copy, Debug)]
pub struct SystemBuildServiceLimits {
    action: ContentDigest,
    budget: AdmittedBudget,
    process: SystemdBuildLimits,
}

/// Historical manager observations of a complete service description. This is
/// not worker-image authentication, execution authorization or settlement proof.
#[derive(Debug)]
pub struct SystemBuildUnitObservation {
    action: ContentDigest,
    manager: ContentDigest,
    contract: ContentDigest,
    status: SystemdUnitStatus,
}

impl SystemBuildAction {
    pub fn service_limits(&self) -> Result<SystemBuildServiceLimits, BuildError> {
        let budget = *self.budget();
        let request = budget.request();
        // systemd/rlimit use UINT64_MAX as infinity. Pure admission permits
        // integer ceilings, but this execution adapter must never emit infinity.
        if [
            request.memory_bytes,
            request.scratch_bytes,
            request.output_bytes,
        ]
        .contains(&u64::MAX)
        {
            return Err(BuildError::InvalidRequest);
        }
        Ok(SystemBuildServiceLimits {
            action: self.digest(),
            budget,
            process: SystemdBuildLimits {
                cpu_percent: request.cpu_percent,
                nofile: u64::from(request.descriptors),
                // An intermediate may exceed the entire output allocation.
                // Per-filesystem/aggregate limits must be enforced separately.
                file_size: request.scratch_bytes.max(request.output_bytes),
            },
        })
    }
}

impl SystemBuildServiceLimits {
    pub const fn action_digest(&self) -> ContentDigest {
        self.action
    }

    pub const fn budget(&self) -> &AdmittedBudget {
        &self.budget
    }

    /// Check all capacity dimensions before changing any service field. Only
    /// resource properties are updated: executable, arguments, identity, restart
    /// policy, environment, profile and dependencies remain caller selections.
    /// The supplied capacity is an observation, never helper/manager authority.
    pub fn apply(
        &self,
        service: &mut SystemdService,
        capacity: BuilderCapacity,
    ) -> Result<(), BuildError> {
        self.budget.check_capacity(capacity)?;
        let request = self.budget.request();
        service.memory_max = Some(request.memory_bytes);
        service.tasks_max = Some(u64::from(request.processes));
        service.runtime_max = Some(Duration::from_secs(u64::from(
            request.duration_seconds,
        )));
        service.build_limits = Some(self.process);
        Ok(())
    }

    /// Compare requested resources without contacting a manager or changing a
    /// unit. No ordinary Standard/Large profile values are consulted.
    pub fn verify_service(&self, service: &SystemdService) -> Result<(), BuildError> {
        let request = self.budget.request();
        if service.memory_max != Some(request.memory_bytes)
            || service.tasks_max != Some(u64::from(request.processes))
            || service.runtime_max
                != Some(Duration::from_secs(u64::from(
                    request.duration_seconds,
                )))
            || service.build_limits != Some(self.process)
        {
            return Err(BuildError::InputChanged);
        }
        Ok(())
    }

    /// Independently read the complete transient-service contract twice, bracketed
    /// by the same live invocation and manager identity under one deadline. This
    /// checks more than the numeric limits, including exec hooks and environment.
    /// It does not prove that the executable is the action's selected worker,
    /// inspect current kernel cgroup values, or cover disk/inode enforcement.
    pub fn observe_unit(
        &self,
        service: &SystemdService,
        manager: &mut SystemdManager,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<SystemBuildUnitObservation, BuildError> {
        cancellation.check()?;
        self.verify_service(service)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(BuildError::InvalidRequest)?;
        let observed = manager
            .observe_build_unit(service, remaining, cancellation)
            .map_err(|error| match error {
                crate::systemd::SystemdError::Cancelled => BuildError::Cancelled,
                _ => BuildError::Cache(error.to_string()),
            })?;
        Ok(SystemBuildUnitObservation {
            action: self.action,
            manager: observed.manager.fingerprint(),
            contract: observed.contract,
            status: observed.status,
        })
    }
}

impl SystemBuildUnitObservation {
    pub const fn action_digest(&self) -> ContentDigest {
        self.action
    }
    pub const fn manager_digest(&self) -> ContentDigest {
        self.manager
    }
    pub const fn contract_digest(&self) -> ContentDigest {
        self.contract
    }
    pub const fn status(&self) -> &SystemdUnitStatus {
        &self.status
    }
    pub fn unit(&self) -> &SystemdUnitName {
        &self.status.unit
    }
}

#[cfg(test)]
mod tests;

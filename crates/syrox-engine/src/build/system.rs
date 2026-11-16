//! Authenticated component inputs and action identities for complete System builds.
//!
//! This preparation is separate from ordinary Managed execution. It binds the
//! selected System budget, program, source and retained inputs without launching
//! a worker, creating an operation, allocating scratch or publishing a receipt.
//! A System executor must still authenticate its helper/resources, enforce the
//! budget and settle processes before publishing outputs.

use super::{
    BuildError, BuildProfile, BuildSpecification,
    managed::{preparation, source::Source},
    records::{Action, BuildDescription, InputIdentity},
};
use crate::{
    cancellation::Cancellation,
    config::SystemBuildConfiguration,
    plan::{Plan, PlanPackageId, PlanPackageSelection, PlanService, PlanSystem},
    result::MaterializedArtifact,
    store::{ContentDigest, ObjectLease, Store},
    system::budget::AdmittedBudget,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::fd::OwnedFd,
};

mod records;
pub use records::SystemBuildAction;
mod limits;
pub use limits::{SystemBuildServiceLimits, SystemBuildUnitObservation};
mod scratch;
pub use scratch::SystemBuildScratch;
#[cfg(target_arch = "x86_64")]
mod workspace;
#[cfg(target_arch = "x86_64")]
pub use workspace::SystemBuildWorkspace;
#[cfg(target_arch = "x86_64")]
pub(crate) mod namespace;
#[cfg(target_arch = "x86_64")]
pub use namespace::{PreparedSystemBuildNamespace, SystemBuildNamespaceResources};
mod input_descriptors;
mod resources;
#[cfg(target_arch = "x86_64")]
mod source_archive;
pub use resources::SystemBuildInputResources;
mod input_transfer;
pub use input_transfer::{SystemBuildInputPeer, SystemBuildInputTransfer};

/// Owns verified source/input custody without a global Store barrier. There is
/// no conversion to an ordinary Managed attempt or implicit execution method.
pub struct SystemBuildInputs {
    action: SystemBuildAction,
    source: Source,
    worker: Vec<u8>,
    inputs: Vec<MaterializedArtifact>,
    interest: ObjectLease,
    configuration: SystemBuildConfiguration,
}

impl std::fmt::Debug for SystemBuildInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemBuildInputs")
            .field("action", &self.action.digest())
            .finish_non_exhaustive()
    }
}

impl SystemBuildInputs {
    pub const fn action(&self) -> &SystemBuildAction {
        &self.action
    }
    pub const fn source_size(&self) -> u64 {
        self.source.size()
    }

    /// Rehash the source and verify every retained input view. A successful
    /// inspection is not a worker handshake, execution gate or settlement proof.
    pub fn revalidate(&self, cancellation: &Cancellation) -> Result<(), BuildError> {
        cancellation.check()?;
        drop(self.interest.operation()?);
        self.source.verify(cancellation)?;
        if ContentDigest::sha256(&self.worker) != self.action.worker_digest()
            || self.inputs.len() != self.action.selected_inputs().len()
        {
            return Err(BuildError::InputChanged);
        }
        for (input, expected) in self
            .inputs
            .iter()
            .zip(self.action.selected_inputs())
        {
            input
                .verify_view(cancellation)
                .map_err(|e| super::materialization_error(&e))?;
            if InputIdentity::from(input.identity()) != *expected {
                return Err(BuildError::InputChanged);
            }
        }
        Ok(())
    }

    /// Descriptor-based handoff material only. The caller retains this owner and
    /// must independently authenticate the receiver, action and current bytes.
    pub fn source_descriptor(&self, cancellation: &Cancellation) -> Result<OwnedFd, BuildError> {
        self.revalidate(cancellation)?;
        Ok(self.source.duplicate_readonly_descriptor()?)
    }
}

/// Prepare one component belonging to the selected System's declared closure.
/// The System's admitted budget replaces ordinary recipe profile ceilings and
/// attempt timeout for this distinct execution context. The recipe program,
/// source directory, source identity and selected input declarations remain exact.
/// Ordinary `prepare_managed_build_inputs` keeps all existing caps and identities.
pub fn prepare_system_build_inputs(
    plan: &Plan,
    system: &str,
    request: &BuildSpecification,
    store: &Store,
    configuration: &SystemBuildConfiguration,
    worker: &[u8],
    cancellation: &Cancellation,
) -> Result<SystemBuildInputs, BuildError> {
    cancellation.check()?;
    let system = plan
        .systems()
        .find(|s| s.name == system)
        .ok_or(BuildError::UnsupportedInputs)?;
    let budget = configuration.admit(system.budget)?;
    if !belongs_to_system(plan, system, &request.package) {
        return Err(BuildError::UnsupportedInputs);
    }
    request.program.validate()?;
    if request.program.profile != BuildProfile::Managed
        || worker.is_empty()
        || worker.len() > 128 * 1024 * 1024
        || ContentDigest::sha256(worker) != configuration.worker().worker_digest()
    {
        return Err(BuildError::InvalidRequest);
    }
    crate::runtime::validate_static_worker_image(worker).map_err(|_| BuildError::InvalidRequest)?;
    let declared = plan
        .builds()
        .find(|b| b.package() == &request.package)
        .ok_or(BuildError::UnsupportedInputs)?;
    if declared.program() != &request.program
        || declared.source_directory() != request.source_directory
        || declared.timeout_seconds() != request.timeout_seconds
        || declared.inputs().len() != request.inputs.len()
    {
        return Err(BuildError::UnsupportedInputs);
    }
    let description = BuildDescription::from_plan(plan, &request.package)?;
    let source_limit = plan
        .acquisitions()
        .find(|a| a.package() == &request.package)
        .and_then(|a| a.sources().next())
        .ok_or(BuildError::UnsupportedInputs)?
        .maximum_bytes()
        .min(crate::store::MAX_STORE_BLOB_BYTES)
        .min(budget.request().scratch_bytes);
    let mut template = Action::new(
        request,
        description.source,
        None,
        ContentDigest::sha256(worker),
    );
    let operation = store.operation()?;
    let reader = operation
        .open_verified_checked(description.source, source_limit, || {
            cancellation
                .check()
                .map_err(|_| crate::cancellation::cancellation_io())
        })
        .map_err(|e| {
            if cancellation.is_cancelled() {
                BuildError::Cancelled
            } else {
                e.into()
            }
        })?
        .ok_or(BuildError::MissingSource)?;
    let source = Source::capture(
        &reader,
        description.source,
        source_limit,
        cancellation,
    )?;
    let inputs = preparation::prepare_inputs_with_policy(
        plan,
        request,
        store,
        &operation,
        &mut template,
        cancellation,
        preparation::InputPolicy::System,
    )?;
    let action = SystemBuildAction::new(template, source_limit, budget)?;
    let interest = operation.retain_objects(&[description.source], &[])?;
    drop((reader, operation));
    let prepared = SystemBuildInputs {
        action,
        source,
        worker: worker.to_vec(),
        inputs,
        interest,
        configuration: configuration.clone(),
    };
    prepared.revalidate(cancellation)?;
    Ok(prepared)
}

fn belongs_to_system(plan: &Plan, system: &PlanSystem, package: &PlanPackageId) -> bool {
    let mut pending = vec![
        &system.kernel.image.output.package,
        &system.kernel.configuration.output.package,
        &system.kernel.modules.package,
        &system.kernel.headers.package,
    ];
    pending.extend(system.userspace.iter().map(|o| &o.package));
    pending.extend(
        system
            .layout
            .exposures
            .iter()
            .map(|e| &e.source.output.package),
    );
    pending.extend(
        system
            .services
            .pkgs()
            .iter()
            .map(PlanPackageSelection::package),
    );
    pending.extend(
        system
            .services
            .services()
            .iter()
            .flat_map(PlanService::pkgs)
            .map(PlanPackageSelection::package),
    );
    let packages = plan
        .packages()
        .map(|p| (p.id(), p))
        .collect::<BTreeMap<_, _>>();
    let builds = plan
        .builds()
        .map(|b| (b.package(), b))
        .collect::<BTreeMap<_, _>>();
    let mut visited = BTreeSet::new();
    while let Some(next) = pending.pop() {
        if !visited.insert(next) {
            continue;
        }
        if next == package {
            return true;
        }
        if let Some(p) = packages.get(next) {
            pending.extend(p.dependencies());
        }
        if let Some(b) = builds.get(next) {
            pending.extend(b.inputs().iter().map(|i| &i.package));
        }
    }
    false
}

#[cfg(test)]
mod tests;

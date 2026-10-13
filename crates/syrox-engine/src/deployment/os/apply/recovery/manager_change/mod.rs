use super::{
    OpenedRecovery, OsRecoveryEffect, OsRecoveryError, OsRecoveryReport, OsRecoveryRequest,
    OsRecoveryState, failure,
};
use crate::deployment::os::activation::{
    ActivationSnapshot, EffectKind, EffectState, ExecutionEpoch,
    manager_change::{ClosedProcessInventory, ExitedNamespaces, ResourceExecution},
};
use crate::systemd::quiescence::{
    CgroupEmptyObservation, CgroupObservation, PendingReason, PinnedUnitCgroup, UnitInvocation,
};
use crate::{
    cancellation::Cancellation, store::ContentDigest, systemd::SystemdManager,
    systemd::SystemdUnitReference,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
mod invocation;
mod observation;
use invocation::ObservedInvocation;
mod resources;
use resources::HistoricalResources;

type Result<T> = std::result::Result<T, &'static str>;
/// Constructed only after live authenticated reconciliation. Neither a boolean
/// nor deserialized state can be supplied as a substitute for the kernel proofs.
pub(crate) struct ManagerEpochSettlement {
    change: String,
    transition: ContentDigest,
    namespaces: ExitedNamespaces,
    groups: BTreeMap<String, ResourceSettlement>,
    closed_inventory: Option<ClosedProcessInventory>,
    unstarted: BTreeSet<String>,
}
enum ResourceSettlement {
    Cgroup(CgroupEmptyObservation),
    /// Not cgroup removal: the separately held opaque proof covers every
    /// pre-fork launcher and every admitted namespace in the revoked epoch.
    ClosedInventory {
        invocation: [u8; 16],
    },
    ReloadedClosedInventory,
}
impl ManagerEpochSettlement {
    pub(crate) fn into_change(self, state: &ActivationSnapshot) -> Option<String> {
        self.matches(state).then_some(self.change)
    }
    pub(crate) fn matches(&self, state: &ActivationSnapshot) -> bool {
        let Some(record) = state.manager_changes.get(&self.change) else {
            return false;
        };
        if !self.namespaces.matches(state, &self.change)
            || record.resources.len() != self.groups.len() + self.unstarted.len()
            || transition_pin(state, &self.change).ok() != Some(self.transition)
        {
            return false;
        }
        if record.resources.is_empty() && !state.changed_epoch_never_started(&self.change) {
            return false;
        }
        record.resources.iter().all(|(name, resource)| {
            if self.unstarted.contains(name) {
                return state.changed_execution(&self.change, name).ok()
                    == Some(ResourceExecution::NeverStarted);
            }
            let Some(group) = self.groups.get(name) else {
                return false;
            };
            let marker = match group {
                ResourceSettlement::Cgroup(proof) => proof.marker(),
                ResourceSettlement::ClosedInventory {
                    invocation,
                } => {
                    return resource
                        .invocations
                        .contains_key(&invocation::encode(invocation))
                        && self
                            .closed_inventory
                            .as_ref()
                            .is_some_and(|proof| proof.matches(state, &self.change));
                }
                ResourceSettlement::ReloadedClosedInventory => {
                    return self
                        .closed_inventory
                        .as_ref()
                        .is_some_and(|proof| proof.matches(state, &self.change));
                }
            };
            resource
                .invocations
                .contains_key(&invocation::encode(marker.binding().invocation()))
                && marker.binding().unit().as_str() == resource.binding.unit
                && marker.boot() == &record.previous.boot
        })
    }
}
fn transition_pin(state: &ActivationSnapshot, change: &str) -> Result<ContentDigest> {
    let record = state
        .manager_changes
        .get(change)
        .ok_or("unknown manager transition")?;
    serde_json::to_vec(record)
        .map(|bytes| ContentDigest::sha256(&bytes))
        .map_err(|_| "encode transition identity")
}

pub(super) fn reconcile(
    opened: &OpenedRecovery,
    request: &OsRecoveryRequest,
    current: &ExecutionEpoch,
    manager: &mut SystemdManager,
    cancel: &Cancellation,
    deadline: Instant,
) -> std::result::Result<OsRecoveryReport, OsRecoveryError> {
    let change = opened
        .journal
        .begin_manager_change(&request.operation, current, cancel, deadline)
        .map_err(|_| failure("revoke prior manager authority"))?;
    let snapshot = opened
        .journal
        .snapshot(cancel, deadline)
        .map_err(|_| failure("read manager transition"))?;
    let result = if snapshot.manager_changes[&change].settled {
        Ok(())
    } else {
        Reconciler {
            opened,
            request,
            current,
            manager,
            cancel,
            deadline,
            change: &change,
        }
        .run(&snapshot)
    };
    let after = opened
        .journal
        .snapshot(cancel, deadline)
        .map_err(|_| failure("read reconciled manager transition"))?;
    Ok(report(
        opened,
        request,
        &after,
        &change,
        result.err(),
    ))
}
struct Reconciler<'a> {
    opened: &'a OpenedRecovery,
    request: &'a OsRecoveryRequest,
    current: &'a ExecutionEpoch,
    manager: &'a mut SystemdManager,
    cancel: &'a Cancellation,
    deadline: Instant,
    change: &'a str,
}
struct PinnedResource {
    reference: SystemdUnitReference,
    group: Option<PinnedUnitCgroup>,
    unit: crate::systemd::SystemdUnitName,
    observation: ObservedInvocation,
}
impl Reconciler<'_> {
    fn remaining(&self) -> Result<Duration> {
        self.cancel
            .check()
            .map_err(|_| "manager recovery cancelled")?;
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or("manager recovery deadline")
    }
    fn finish_empty(&mut self, snapshot: &ActivationSnapshot) -> Result<()> {
        if !snapshot.changed_epoch_never_started(self.change) {
            return Err("manager transition has unresolved start inventory");
        }
        let namespaces = self
            .opened
            .journal
            .observe_changed_namespaces(self.change, self.cancel, self.deadline)
            .map_err(|_| "observe empty execution inventory")?
            .ok_or("execution inventory is incomplete")?;
        self.epoch()?;
        let proof = ManagerEpochSettlement {
            change: self.change.into(),
            transition: transition_pin(snapshot, self.change)?,
            namespaces,
            groups: BTreeMap::new(),
            closed_inventory: None,
            unstarted: BTreeSet::new(),
        };
        self.opened
            .journal
            .finish_manager_change(proof, self.cancel, self.deadline)
            .map_err(|_| "persist unstarted manager transition")
    }

    fn pin_resources(
        &mut self,
        snapshot: &ActivationSnapshot,
        historical: &HistoricalResources,
    ) -> Result<(
        BTreeMap<String, PinnedResource>,
        BTreeMap<String, SystemdUnitReference>,
    )> {
        let transition = &snapshot.manager_changes[self.change];
        let units = crate::deployment::os::unit_files::UnitFiles::open_existing(
            &self.request.units,
            self.opened.installation.id(),
            self.cancel,
            self.deadline,
        )
        .map_err(|_| "open existing unit publication")?;
        let mut pins = BTreeMap::new();
        let mut unstarted_references = BTreeMap::new();
        for (name, resource) in &transition.resources {
            let contract = &historical.contracts[name];
            if units
                .observe(contract.unit(), self.cancel, self.deadline)
                .map_err(|_| "observe historical unit publication")?
                != Some(contract.file_digest())
            {
                return Err("historical unit publication differs");
            }
            match snapshot
                .changed_execution(self.change, name)
                .map_err(|_| "classify historical execution")?
            {
                ResourceExecution::NeverStarted => {
                    self.loaded(contract)?;
                    let reference = self
                        .manager
                        .reference_unit(contract.unit(), self.remaining()?, self.cancel)
                        .map_err(|_| "reference unstarted unit")?;
                    self.idle_without_cgroup(&reference, contract)?;
                    unstarted_references.insert(name.clone(), reference);
                    continue;
                }
                ResourceExecution::Incomplete => {
                    return Err("historical start evidence is incomplete");
                }
                ResourceExecution::Started => {}
            }
            let pinned = self.pin_started(name, resource, contract)?;
            pins.insert(name.clone(), pinned);
        }
        Ok((pins, unstarted_references))
    }
    fn pin_started(
        &mut self,
        name: &str,
        resource: &crate::deployment::os::activation::manager_change::ChangedResource,
        contract: &crate::systemd::persistent::OsUnitContract,
    ) -> Result<PinnedResource> {
        self.loaded(contract)?;
        let reference = self
            .manager
            .reference_unit(contract.unit(), self.remaining()?, self.cancel)
            .map_err(|_| "reference prior unit")?;
        let status = self
            .manager
            .query(contract.unit(), self.remaining()?, self.cancel)
            .map_err(|_| "query cgroup before pin")?
            .ok_or("prior unit disappeared")?;
        if status.unit != *contract.unit() {
            return Err("queried unit differs");
        }
        let observation = ObservedInvocation::select(&status.invocation, &resource.invocations)?;
        if observation == ObservedInvocation::Reloaded && !status.control_group.is_empty() {
            return Err("reloaded unit unexpectedly has a cgroup");
        }
        let group = if status.control_group.is_empty() {
            // This absence grants nothing. Only the independent, complete
            // kernel process inventory can discharge this route below.
            None
        } else {
            let ObservedInvocation::Historical(invocation) = observation else {
                return Err("reloaded unit has a cgroup");
            };
            let binding = UnitInvocation::new(contract.unit().clone(), invocation)
                .map_err(|_| "invalid selected invocation")?;
            Some(
                PinnedUnitCgroup::capture(self.manager, &binding, self.cancel, self.deadline)
                    .map_err(|_| "pin prior cgroup")?,
            )
        };
        let pinned = PinnedResource {
            reference,
            group,
            unit: contract.unit().clone(),
            observation,
        };
        self.stop(name, contract, &pinned)?;
        Ok(pinned)
    }
    fn run(&mut self, snapshot: &ActivationSnapshot) -> Result<()> {
        self.epoch()?;
        if snapshot.manager_changes[self.change]
            .resources
            .is_empty()
        {
            return self.finish_empty(snapshot);
        }
        let historical = HistoricalResources::open(
            self.opened,
            snapshot,
            self.change,
            &self.request.units,
            self.cancel,
            self.deadline,
        )?;
        let (mut pins, mut unstarted_references) = self.pin_resources(snapshot, &historical)?;
        let namespaces = self
            .opened
            .journal
            .observe_changed_namespaces(self.change, self.cancel, self.deadline)
            .map_err(|_| "namespace exit observation unavailable")?
            .ok_or("namespace exit evidence incomplete")?;
        let closed_inventory = if pins.values().any(|pin| pin.group.is_none()) {
            Some(
                self.opened
                    .journal
                    .observe_closed_process_inventory(self.change, self.cancel, self.deadline)
                    .map_err(|_| "closed process inventory observation unavailable")?
                    .ok_or("pre-fork launcher or namespace inventory incomplete")?,
            )
        } else {
            None
        };
        let mut groups = BTreeMap::new();
        for (name, pinned) in &pins {
            self.check(pinned, &historical.contracts[name])?;
            if !self
                .manager
                .unit_idle_without_job(&pinned.unit, self.remaining()?, self.cancel)
                .map_err(|_| "observe current unit job")?
            {
                return Err("unit or job is not idle");
            }
            let observed = if let Some(group) = &pinned.group {
                match group
                    .observe_empty(self.manager, self.cancel, self.deadline)
                    .map_err(|_| "observe pinned cgroup")?
                {
                    CgroupObservation::Empty(proof) | CgroupObservation::Removed(proof) => {
                        ResourceSettlement::Cgroup(proof)
                    }
                    CgroupObservation::Pending(reason) => return Err(pending_reason(&reason)),
                }
            } else {
                self.closed_inventory_idle(pinned, &historical.contracts[name])?;
                match pinned.observation {
                    ObservedInvocation::Historical(invocation) => {
                        ResourceSettlement::ClosedInventory {
                            invocation,
                        }
                    }
                    ObservedInvocation::Reloaded => ResourceSettlement::ReloadedClosedInventory,
                }
            };
            self.check(pinned, &historical.contracts[name])?;
            groups.insert(name.clone(), observed);
        }
        let mut unstarted = BTreeSet::new();
        for (name, reference) in &unstarted_references {
            self.idle_without_cgroup(reference, &historical.contracts[name])?;
            unstarted.insert(name.clone());
        }
        for reference in unstarted_references.values_mut() {
            self.manager
                .unreference_unit(reference, self.remaining()?, self.cancel)
                .map_err(|_| "release unstarted unit reference")?;
        }
        for pinned in pins.values_mut() {
            self.manager
                .unreference_unit(
                    &mut pinned.reference,
                    self.remaining()?,
                    self.cancel,
                )
                .map_err(|_| "release prior unit reference")?;
        }
        self.epoch()?;
        let latest = self
            .opened
            .journal
            .snapshot(self.cancel, self.deadline)
            .map_err(|_| "read final transition")?;
        let proof = ManagerEpochSettlement {
            change: self.change.into(),
            transition: transition_pin(&latest, self.change)?,
            namespaces,
            groups,
            closed_inventory,
            unstarted,
        };
        self.opened
            .journal
            .finish_manager_change(proof, self.cancel, self.deadline)
            .map_err(|_| "persist manager settlement")
    }
}
fn report(
    opened: &OpenedRecovery,
    request: &OsRecoveryRequest,
    state: &ActivationSnapshot,
    change: &str,
    error: Option<&'static str>,
) -> OsRecoveryReport {
    let transition = &state.manager_changes[change];
    let mut effects: Vec<_> = transition
        .resources
        .keys()
        .map(|resource| OsRecoveryEffect {
            effect: change.into(),
            resource: resource.clone(),
            kind: "manager_change",
            state: if transition.settled {
                OsRecoveryState::ManagerFenced
            } else {
                OsRecoveryState::Pending
            },
            stage: error,
        })
        .collect();
    if effects.is_empty() {
        effects.push(OsRecoveryEffect {
            effect: change.into(),
            resource: "manager".into(),
            kind: "manager_change",
            state: if transition.settled {
                OsRecoveryState::ManagerFenced
            } else {
                OsRecoveryState::Pending
            },
            stage: error,
        });
    }
    for (id, effect) in &state.operations[&request.operation].effects {
        if effect.kind == EffectKind::Publish
            && !matches!(
                effect.state,
                EffectState::Observed { .. } | EffectState::NotApplied
            )
        {
            effects.push(OsRecoveryEffect {
                effect: id.clone(),
                resource: effect.resource.clone(),
                kind: "publish",
                state: OsRecoveryState::Pending,
                stage: Some("publication reconciliation remains required"),
            });
        }
    }
    let pending = effects
        .iter()
        .any(|effect| effect.state == OsRecoveryState::Pending);
    OsRecoveryReport {
        operation: request.operation.clone(),
        candidate: opened.candidate.digest(),
        effects,
        needs_reconciliation: pending,
    }
}

fn pending_reason(reason: &PendingReason) -> &'static str {
    match reason {
        PendingReason::UnitAbsent => "cgroup unit absent",
        PendingReason::BindingOrPathChanged => "cgroup binding or path changed",
        PendingReason::CgroupUnavailable => "pinned cgroup unavailable",
        PendingReason::CgroupReplaced => "pinned cgroup replaced",
        PendingReason::BootChanged => "cgroup observation boot changed",
        PendingReason::ManagerChanged => "cgroup observation manager changed",
        PendingReason::UnitNotIdle => "cgroup unit not idle",
        PendingReason::ObservationChanged => "cgroup observation changed",
        PendingReason::Populated => "pinned cgroup populated",
        PendingReason::FdStoreUnavailable => "fdstore unavailable",
        PendingReason::FdStoreNotEmpty => "fdstore not empty",
    }
}

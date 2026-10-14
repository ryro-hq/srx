use super::{ActivationJournal, ActivationSnapshot, ExecutionEpoch, Result, invalid};
use crate::platform::linux::fd::persisted_namespace::{LauncherExitProof, NamespaceExitProof};
use crate::{cancellation::Cancellation, store::ContentDigest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagerChange {
    pub previous: ExecutionEpoch,
    pub current: ExecutionEpoch,
    pub operation: String,
    /// Includes historical attempts, not only the currently published binding.
    pub attempts: BTreeSet<String>,
    pub resources: BTreeMap<String, ChangedResource>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub settled: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChangedResource {
    pub binding: super::record::Binding,
    pub invocations: BTreeMap<String, String>,
    pub stop: StopState,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum StopState {
    Revoked,
    /// Persisted before transport; crash, error or lost reply never permits replay.
    Intent {
        invocation: String,
    },
    Accepted {
        invocation: String,
        job: String,
    },
    Unknown {
        invocation: String,
    },
}
/// Every recorded init exited. This alone says nothing about manager jobs,
/// cgroups or FDSTORE, and is deliberately not an epoch settlement proof.
pub(crate) struct ExitedNamespaces {
    change: String,
    proofs: BTreeMap<String, NamespaceExitProof>,
}
impl ExitedNamespaces {
    pub(crate) fn matches(&self, state: &ActivationSnapshot, change: &str) -> bool {
        let Some(record) = state.manager_changes.get(change) else {
            return false;
        };
        self.change == change
            && self.proofs.len() == record.attempts.len()
            && record.attempts.iter().all(|id| {
                state
                    .attempts
                    .get(id)
                    .and_then(|attempt| attempt.namespace.as_ref())
                    .zip(self.proofs.get(id))
                    .is_some_and(|(namespace, proof)| proof.matches(namespace))
            })
    }
}
/// All authenticated pre-fork launchers and every namespace they admitted have
/// exited. Missing namespace records deliberately prevent this proof.
pub(crate) struct ClosedProcessInventory {
    namespaces: ExitedNamespaces,
    launchers: BTreeMap<String, LauncherExitProof>,
}
impl ClosedProcessInventory {
    pub(crate) fn matches(&self, state: &ActivationSnapshot, change: &str) -> bool {
        self.namespaces.matches(state, change)
            && self
                .launchers
                .keys()
                .eq(self.namespaces.proofs.keys())
            && self.launchers.iter().all(|(id, proof)| {
                state
                    .attempts
                    .get(id)
                    .and_then(|attempt| attempt.launcher.as_ref())
                    .is_some_and(|record| proof.matches(record))
            })
    }
}
impl ActivationJournal {
    pub(crate) fn begin_manager_change(
        &self,
        operation: &str,
        current: &ExecutionEpoch,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<String> {
        current.validate()?;
        self.mutate(cancel, deadline, |state| {
            let selected = state
                .operations
                .get(operation)
                .ok_or_else(|| invalid("unknown operation"))?;
            if state.active_operation.as_deref() != Some(operation)
                || state.desired.as_deref() != Some(selected.candidate.as_str())
            {
                return Err(invalid(
                    "manager recovery operation is not selected",
                ));
            }
            let previous = selected.epoch.clone();
            validate_epochs(&previous, current)?;
            let key = epoch_key(&previous)?;
            if let Some(existing) = state.manager_changes.get(&key) {
                if existing.current != *current || existing.operation != operation {
                    return Err(invalid("manager recovery target changed"));
                }
                return Ok(key);
            }
            let mut resources = BTreeMap::new();
            for (resource, binding) in &state.bindings {
                if binding.epoch != previous {
                    continue;
                }
                let invocations = super::admitted_invocations(state, resource, &previous)?;
                let mut revoked = binding.clone();
                revoked.authorized = false;
                resources.insert(
                    resource.clone(),
                    ChangedResource {
                        binding: revoked,
                        invocations,
                        stop: StopState::Revoked,
                    },
                );
            }
            let attempts = state
                .attempts
                .iter()
                .filter(|(_, attempt)| attempt.epoch == previous)
                .map(|(id, _)| id.clone())
                .collect();
            for binding in state
                .bindings
                .values_mut()
                .filter(|binding| binding.epoch == previous)
            {
                binding.authorized = false;
            }
            state.manager_changes.insert(
                key.clone(),
                ManagerChange {
                    previous,
                    current: current.clone(),
                    operation: operation.into(),
                    attempts,
                    resources,
                    settled: false,
                },
            );
            Ok(key)
        })
    }
    pub(crate) fn observe_changed_namespaces(
        &self,
        change: &str,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Option<ExitedNamespaces>> {
        let state = self.snapshot(cancel, deadline)?;
        let record = state
            .manager_changes
            .get(change)
            .ok_or_else(|| invalid("unknown manager transition"))?;
        let mut proofs = BTreeMap::new();
        for id in &record.attempts {
            let attempt = state
                .attempts
                .get(id)
                .ok_or_else(|| invalid("missing startup attempt"))?;
            // A legacy or incomplete startup is not evidence that no init existed.
            let Some(namespace) = &attempt.namespace else {
                return Ok(None);
            };
            let Some(proof) = namespace.observe_exit(cancel, deadline)? else {
                return Ok(None);
            };
            proofs.insert(id.clone(), proof);
        }
        let proof = ExitedNamespaces {
            change: change.into(),
            proofs,
        };
        let after = self.snapshot(cancel, deadline)?;
        if !proof.matches(&after, change) {
            return Err(invalid("startup inventory changed"));
        }
        Ok(Some(proof))
    }
    pub(crate) fn observe_closed_process_inventory(
        &self,
        change: &str,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Option<ClosedProcessInventory>> {
        let Some(namespaces) = self.observe_changed_namespaces(change, cancel, deadline)? else {
            return Ok(None);
        };
        let state = self.snapshot(cancel, deadline)?;
        if !namespaces.matches(&state, change) {
            return Err(invalid("startup inventory changed"));
        }
        let mut launchers = BTreeMap::new();
        for id in namespaces.proofs.keys() {
            let Some(record) = state.attempts[id].launcher.as_ref() else {
                return Ok(None);
            };
            let Some(proof) = record.observe_exit(cancel, deadline)? else {
                return Ok(None);
            };
            launchers.insert(id.clone(), proof);
        }
        let proof = ClosedProcessInventory {
            namespaces,
            launchers,
        };
        if !proof.matches(&self.snapshot(cancel, deadline)?, change) {
            return Err(invalid("startup inventory changed"));
        }
        Ok(Some(proof))
    }
    pub(crate) fn intent_changed_stop(
        &self,
        change: &str,
        resource: &str,
        invocation: &str,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<bool> {
        self.mutate(cancel, deadline, |state| {
            let entry = state
                .manager_changes
                .get_mut(change)
                .and_then(|change| change.resources.get_mut(resource))
                .ok_or_else(|| invalid("unknown changed resource"))?;
            if !entry.invocations.contains_key(invocation) {
                return Err(invalid("resource lacks recorded invocation"));
            }
            if let Some(selected) = entry.stop.invocation() {
                if selected != invocation {
                    return Err(invalid("stop invocation cannot be retargeted"));
                }
                return Ok(false);
            }
            entry.stop = StopState::Intent {
                invocation: invocation.into(),
            };
            Ok(true)
        })
    }
    pub(crate) fn changed_stop_reply(
        &self,
        change: &str,
        resource: &str,
        invocation: &str,
        job: Option<&str>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        self.mutate(cancel, deadline, |state| {
            let entry = state
                .manager_changes
                .get_mut(change)
                .and_then(|change| change.resources.get_mut(resource))
                .ok_or_else(|| invalid("unknown changed resource"))?;
            if !matches!(&entry.stop, StopState::Intent { invocation: selected } if selected == invocation) {
                return Err(invalid("stop reply lacks exclusive intent"));
            }
            entry.stop = job.map_or_else(|| StopState::Unknown { invocation: invocation.into() }, |job| StopState::Accepted {
                invocation: invocation.into(), job: job.into(),
            });
            Ok(())
        })
    }
}
fn validate_epochs(previous: &ExecutionEpoch, current: &ExecutionEpoch) -> Result<()> {
    previous.validate()?;
    current.validate()?;
    if previous.boot != current.boot
        || previous.scope != current.scope
        || previous.manager == current.manager
    {
        return Err(invalid(
            "manager recovery requires same boot and scope with changed manager",
        ));
    }
    Ok(())
}
fn epoch_key(epoch: &ExecutionEpoch) -> Result<String> {
    let bytes = serde_json::to_vec(epoch).map_err(|_| invalid("cannot encode epoch"))?;
    Ok(ContentDigest::sha256(&bytes).to_string())
}

impl ActivationSnapshot {
    pub(crate) fn manager_history(&self, change: &str) -> Result<BTreeSet<(String, String)>> {
        let transition = self
            .manager_changes
            .get(change)
            .ok_or_else(|| invalid("unknown manager transition"))?;
        transition
            .attempts
            .iter()
            .map(|id| {
                self.attempts
                    .get(id)
                    .map(|attempt| (attempt.resource.clone(), attempt.binding.clone()))
                    .ok_or_else(|| invalid("missing historical startup"))
            })
            .collect()
    }
    pub(crate) fn manager_fenced(
        &self,
        previous: &ExecutionEpoch,
        current: &ExecutionEpoch,
    ) -> bool {
        epoch_key(previous)
            .ok()
            .and_then(|key| self.manager_changes.get(&key))
            .is_some_and(|change| {
                change.settled && change.previous == *previous && change.current == *current
            })
    }
}
impl ActivationJournal {
    pub(crate) fn finish_manager_change(
        &self,
        proof: crate::deployment::os::apply::recovery::manager_change::ManagerEpochSettlement,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        self.mutate(cancel, deadline, |state| {
            let key = proof
                .into_change(state)
                .ok_or_else(|| invalid("manager settlement evidence differs"))?;
            let change = state
                .manager_changes
                .get_mut(&key)
                .ok_or_else(|| invalid("unknown manager transition"))?;
            change.settled = true;
            for operation in state
                .operations
                .values_mut()
                .filter(|op| op.epoch == change.previous)
            {
                for effect in operation.effects.values_mut() {
                    if effect.kind == super::EffectKind::Publish {
                        continue;
                    }
                    let job = match &effect.state {
                        super::EffectState::Intent | super::EffectState::Unknown => None,
                        super::EffectState::Accepted {
                            job,
                        } => Some(job.clone()),
                        _ => continue,
                    };
                    effect.state = super::EffectState::ManagerFenced {
                        epoch: change.current.clone(),
                        job,
                    };
                }
            }
            Ok(())
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResourceExecution {
    NeverStarted,
    Started,
    Incomplete,
}
impl ActivationSnapshot {
    pub(crate) fn changed_execution(
        &self,
        change: &str,
        resource: &str,
    ) -> Result<ResourceExecution> {
        let transition = self
            .manager_changes
            .get(change)
            .ok_or_else(|| invalid("unknown manager transition"))?;
        let entry = transition
            .resources
            .get(resource)
            .ok_or_else(|| invalid("unknown historical resource"))?;
        if !entry.invocations.is_empty() {
            return Ok(ResourceExecution::Started);
        }
        let attempt = self
            .attempts
            .values()
            .any(|attempt| attempt.epoch == transition.previous && attempt.resource == resource);
        let intent = self.operations.values().any(|op| {
            op.epoch == transition.previous
                && op.effects.values().any(|effect| {
                    effect.kind == super::EffectKind::Start && effect.resource == resource
                })
        });
        Ok(if !attempt && !intent {
            ResourceExecution::NeverStarted
        } else {
            ResourceExecution::Incomplete
        })
    }
    pub(crate) fn changed_epoch_never_started(&self, change: &str) -> bool {
        self.manager_changes
            .get(change)
            .is_some_and(|transition| {
                transition.attempts.is_empty()
                    && !self.operations.values().any(|op| {
                        op.epoch == transition.previous
                            && op.effects.values().any(|effect| {
                                matches!(
                                    effect.kind,
                                    super::EffectKind::Start | super::EffectKind::Stop
                                )
                            })
                    })
            })
    }
}
impl StopState {
    fn invocation(&self) -> Option<&str> {
        match self {
            Self::Revoked => None,
            Self::Intent {
                invocation,
            }
            | Self::Accepted {
                invocation,
                ..
            }
            | Self::Unknown {
                invocation,
            } => Some(invocation),
        }
    }
}
mod validate;
pub(super) use validate::validate;

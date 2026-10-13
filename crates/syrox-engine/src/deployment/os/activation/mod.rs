//! Journal dos efeitos planejados e observados ao aplicar uma geração.
//!
//! Um `Intent` registra que o efeito foi planejado. Se a resposta se perder,
//! a recuperação confere o que aconteceu antes de continuar; ler o registro
//! não manda repetir a chamada. Este journal guarda estado, sem chamar o manager
//! ou liberar as raízes da geração por conta própria.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::time::Instant;

use super::installation::{InstallationError, RetainedGeneration, storage::Storage};
use super::launch_binding::OsLaunchBinding;
use crate::{cancellation::Cancellation, store::ContentDigest, systemd::SystemdUnitName};
use thiserror::Error;
pub(crate) mod manager_change;
mod record;
pub(crate) use record::{
    ActivationSnapshot, EffectKind, EffectState, ExecutionEpoch, OperationKind,
};
use record::{Attempt, Binding, Effect, Operation, invalid};

pub(super) const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;
#[derive(Debug, Error)]
pub(crate) enum ActivationError {
    #[error("Os start denied: {0}")]
    StartDenied(&'static str),
    #[error("invalid Os activation: {0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Installation(#[from] InstallationError),
    #[error(transparent)]
    Io(#[from] io::Error),
}
type Result<T> = std::result::Result<T, ActivationError>;
#[derive(Debug)]
pub(crate) struct ActivationJournal {
    storage: Storage,
    installation: String,
}
/// Admission is single-use even when gate delivery fails. Neither cloning a
/// snapshot nor reopening the journal reconstructs this token.
#[derive(Debug)]
pub(crate) struct StartAdmission {
    installation: String,
    attempt: String,
    binding: String,
}
impl StartAdmission {
    #[cfg(test)]
    pub(crate) fn attempt(&self) -> &str {
        &self.attempt
    }
}
impl ActivationJournal {
    pub(crate) fn open_existing(
        path: &Path,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        check(cancellation, deadline)?;
        let storage = Storage::open(path, false)?;
        let authority = storage.lock(cancellation, deadline)?;
        let installation = storage.installation_id(false)?;
        if let Some(bytes) = storage.read_activation()? {
            ActivationSnapshot::parse(&bytes, &installation)?;
        }
        drop(authority);
        Ok(Self {
            storage,
            installation,
        })
    }
    /// Observation only. Reopening or reading never repairs durability or
    /// authorizes effects; every admission/gate republishes and fsyncs state.
    pub(crate) fn snapshot(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<ActivationSnapshot> {
        let _guard = self.storage.lock(cancellation, deadline)?;
        let state = self.load()?;
        check(cancellation, deadline)?;
        Ok(state)
    }
    /// Observation of durable gate consumption, not proof of exec or readiness.
    pub(crate) fn start_gate_used(
        &self,
        resource: &str,
        pin: ContentDigest,
        invocation: &str,
        epoch: &ExecutionEpoch,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<bool> {
        record::check_id(invocation)?;
        let state = self.snapshot(cancellation, deadline)?;
        let Some(binding) = state.bindings.get(resource) else {
            return Ok(false);
        };
        if !binding.authorized || binding.pin != pin.to_string() || binding.epoch != *epoch {
            return Ok(false);
        }
        Ok(state.attempts.values().any(|attempt| {
            attempt.resource == resource
                && attempt.binding == binding.pin
                && attempt.authorization == binding.authorization
                && attempt.invocation == invocation
                && attempt.epoch == *epoch
                && attempt.gate_used
        }))
    }
    #[cfg(test)]
    pub(crate) fn begin_test_pin(
        &self,
        candidate: ContentDigest,
        expected: Option<ContentDigest>,
        epoch: ExecutionEpoch,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<String> {
        self.begin_pin(candidate, expected, epoch, cancellation, deadline)
    }
    /// Recover ownership only from a confirmed Start and this binding's current
    /// authorization. A manager query alone must never supply the invocation.
    pub(crate) fn observed_invocation(
        &self,
        resource: &str,
        pin: ContentDigest,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Option<String>> {
        let state = self.snapshot(cancellation, deadline)?;
        let invocation = recorded_invocation(&state, resource, pin)?;
        check(cancellation, deadline)?;
        Ok(invocation)
    }
    /// Final read of the selected operation and the existing authorization after
    /// live manager observations. It neither renews authority nor claims an
    /// atomic snapshot shared with the manager.
    #[allow(clippy::too_many_arguments)] // Explicit operation, immutable binding, nonce, epoch and invocation authority.
    pub(crate) fn preservation_current(
        &self,
        operation: &str,
        resource: &str,
        pin: ContentDigest,
        authorization: &str,
        epoch: &ExecutionEpoch,
        invocation: &str,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<bool> {
        record::check_id(operation)?;
        record::check_id(authorization)?;
        record::check_id(invocation)?;
        record::text(resource, 272)?;
        epoch.validate()?;
        let _guard = self.storage.lock(cancellation, deadline)?;
        let state = self.load()?;
        check(cancellation, deadline)?;
        let Some(selected) = state.operations.get(operation) else {
            return Ok(false);
        };
        if state.active_operation.as_deref() != Some(operation)
            || state.desired.as_deref() != Some(&selected.candidate)
            || &selected.epoch != epoch
        {
            return Ok(false);
        }
        let Some(binding) = state.bindings.get(resource) else {
            return Ok(false);
        };
        if !binding.authorized
            || binding.pin != pin.to_string()
            || binding.authorization != authorization
            || &binding.epoch != epoch
        {
            return Ok(false);
        }
        let observed = recorded_invocation(&state, resource, pin)?;
        check(cancellation, deadline)?;
        Ok(observed.as_deref() == Some(invocation))
    }

    pub(crate) fn begin(
        &self,
        candidate: &RetainedGeneration,
        expected: Option<ContentDigest>,
        epoch: ExecutionEpoch,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<String> {
        if candidate.installation_id() != self.installation {
            return Err(invalid(
                "candidate belongs to another installation",
            ));
        }
        self.begin_pin(
            candidate.digest(),
            expected,
            epoch,
            cancellation,
            deadline,
        )
    }
    /// Select a retained rollback target. This records intent, not health or
    /// evidence that the target has previously executed.
    pub(crate) fn begin_rollback(
        &self,
        candidate: &RetainedGeneration,
        expected: ContentDigest,
        epoch: ExecutionEpoch,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<String> {
        if candidate.installation_id() != self.installation {
            return Err(invalid(
                "candidate belongs to another installation",
            ));
        }
        self.begin_pin_kind(
            candidate.digest(),
            Some(expected),
            OperationKind::Rollback,
            epoch,
            cancellation,
            deadline,
        )
    }
    fn begin_pin(
        &self,
        candidate: ContentDigest,
        expected: Option<ContentDigest>,
        epoch: ExecutionEpoch,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<String> {
        self.begin_pin_kind(
            candidate,
            expected,
            OperationKind::Apply,
            epoch,
            cancellation,
            deadline,
        )
    }
    #[allow(clippy::too_many_arguments)] // Selection provenance, CAS and bounded journal I/O remain explicit.
    fn begin_pin_kind(
        &self,
        candidate: ContentDigest,
        expected: Option<ContentDigest>,
        kind: OperationKind,
        epoch: ExecutionEpoch,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<String> {
        epoch.validate()?;
        if kind == OperationKind::Rollback && (expected.is_none() || expected == Some(candidate)) {
            return Err(invalid(
                "rollback requires a different prior selection",
            ));
        }
        self.mutate(cancellation, deadline, |state| {
            if state.desired != expected.map(|pin| pin.to_string()) {
                return Err(invalid("desired generation changed"));
            }
            if state
                .boot_fences
                .contains_key(epoch.boot.as_str())
            {
                return Err(invalid("fenced boot cannot select an operation"));
            }
            if state.operations.len() == record::MAX_OPERATIONS {
                return Err(invalid("operation registry exhausted"));
            }
            // An operation whose effects remain uncertain cannot be superseded.
            if state.operations.values().any(|operation| {
                operation.effects.values().any(|effect| {
                    !matches!(
                        effect.state,
                        EffectState::Observed { .. }
                            | EffectState::NotApplied
                            | EffectState::BootFenced { .. }
                            | EffectState::ManagerFenced { .. }
                    )
                })
            }) {
                return Err(invalid("prior effects require reconciliation"));
            }
            let id = fresh(|id| state.operations.contains_key(id))?;
            state.operations.insert(
                id.clone(),
                Operation {
                    kind,
                    previous: state.desired.clone(),
                    candidate: candidate.to_string(),
                    epoch,
                    effects: BTreeMap::new(),
                    abandoned: false,
                },
            );
            state.desired = Some(candidate.to_string());
            state.active_operation = Some(id.clone());
            state.last_abandoned = None;
            Ok(id)
        })
    }
    /// Caller holds execution authority and authenticated the current boot.
    /// This fences remote effects only; it does not prove stop, publication or GC.
    pub(crate) fn fence_previous_boot(
        &self,
        operation: &str,
        current: &ExecutionEpoch,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        current.validate()?;
        self.mutate(cancellation, deadline, |state| {
            let selected = state
                .operations
                .get(operation)
                .ok_or_else(|| invalid("unknown operation"))?;
            let active = state.active_operation.as_deref() == Some(operation)
                && state.desired.as_deref() == Some(selected.candidate.as_str());
            let abandoned = state.active_operation.is_none()
                && state.desired.is_none()
                && state.last_abandoned.as_deref() == Some(operation)
                && selected.abandoned;
            if !(active || abandoned)
                || selected.epoch.boot == current.boot
                || state
                    .boot_fences
                    .contains_key(current.boot.as_str())
                || state
                    .operations
                    .values()
                    .any(|op| op.epoch.scope != current.scope)
                || state
                    .bindings
                    .values()
                    .any(|binding| binding.epoch.scope != current.scope)
            {
                return Err(invalid(
                    "boot fence authority differs from selection",
                ));
            }
            for op in state.operations.values_mut() {
                if op.epoch.boot == current.boot {
                    continue;
                }
                state
                    .boot_fences
                    .insert(op.epoch.boot.as_str().into(), current.clone());
                for effect in op.effects.values_mut() {
                    if effect.kind == EffectKind::Publish {
                        continue;
                    }
                    let job = match &effect.state {
                        EffectState::Intent | EffectState::Unknown => None,
                        EffectState::Accepted {
                            job,
                        } => Some(job.clone()),
                        EffectState::Observed {
                            ..
                        }
                        | EffectState::NotApplied
                        | EffectState::BootFenced {
                            ..
                        }
                        | EffectState::ManagerFenced {
                            ..
                        } => continue,
                    };
                    effect.state = EffectState::BootFenced {
                        epoch: current.clone(),
                        job,
                    };
                }
            }
            for binding in state.bindings.values_mut() {
                if binding.epoch.boot != current.boot {
                    binding.authorized = false;
                }
            }
            Ok(())
        })
    }
    /// Withdraw only the desired selection. The execution guard belongs to the
    /// caller; bindings, start authorizations and retained services remain intact.
    pub(crate) fn abandon(
        &self,
        operation: &str,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<ContentDigest> {
        self.mutate(cancellation, deadline, |state| {
            let selected = state
                .operations
                .get(operation)
                .ok_or_else(|| invalid("unknown operation"))?;
            let candidate = selected
                .candidate
                .parse()
                .map_err(|_| invalid("invalid candidate digest"))?;
            if !state.operations.values().all(Operation::terminal) {
                return Err(invalid("prior effects require reconciliation"));
            }
            if selected.abandoned
                && state.desired.is_none()
                && state.active_operation.is_none()
                && state.last_abandoned.as_deref() == Some(operation)
            {
                return Ok(candidate);
            }
            if selected.abandoned
                || state.active_operation.as_deref() != Some(operation)
                || state.desired.as_deref() != Some(selected.candidate.as_str())
            {
                return Err(invalid(
                    "operation is not the active desired selection",
                ));
            }
            state
                .operations
                .get_mut(operation)
                .expect("validated operation")
                .abandoned = true;
            state.desired = None;
            state.active_operation = None;
            state.last_abandoned = Some(operation.into());
            Ok(candidate)
        })
    }
    #[allow(clippy::too_many_arguments)] // Explicit authority, identity and bounded-I/O context.
    pub(crate) fn plan_effect(
        &self,
        operation: &str,
        resource: &str,
        kind: EffectKind,
        expected: Option<ContentDigest>,
        target: ContentDigest,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<String> {
        record::text(resource, 272)?;
        self.mutate(cancellation, deadline, |state| {
            if matches!(kind, EffectKind::Publish | EffectKind::Stop)
                && state
                    .bindings
                    .get(resource)
                    .is_some_and(|binding| binding.authorized)
            {
                return Err(invalid("revoke existing binding before mutation"));
            }
            if state.active_operation.as_deref() != Some(operation) {
                return Err(invalid("operation was superseded"));
            }
            let desired = state.desired.clone();
            let operation = state
                .operations
                .get_mut(operation)
                .ok_or_else(|| invalid("unknown operation"))?;
            if desired.as_deref() != Some(&operation.candidate) {
                return Err(invalid("operation is no longer selected"));
            }
            if state
                .boot_fences
                .contains_key(operation.epoch.boot.as_str())
            {
                return Err(invalid(
                    "fenced operation cannot plan new effects",
                ));
            }
            if operation.effects.len() >= record::MAX_RESOURCES * 4
                || operation
                    .effects
                    .values()
                    .any(|effect| effect.resource == resource && effect.kind == kind)
            {
                return Err(invalid(
                    "effect already planned or registry exhausted",
                ));
            }
            let id = fresh(|id| operation.effects.contains_key(id))?;
            operation.effects.insert(
                id.clone(),
                Effect {
                    resource: resource.into(),
                    kind,
                    expected: expected.map(|pin| pin.to_string()),
                    target: target.to_string(),
                    state: EffectState::Intent,
                },
            );
            Ok(id)
        })
    }
    pub(crate) fn record_accepted(
        &self,
        operation: &str,
        effect: &str,
        job: &str,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        record::text(job, 4096)?;
        self.update_effect(
            operation,
            effect,
            cancellation,
            deadline,
            |effect| {
                if effect.state != EffectState::Intent {
                    return Err(invalid("effect cannot be submitted again"));
                }
                effect.state = EffectState::Accepted {
                    job: job.into(),
                };
                Ok(())
            },
        )
    }
    pub(crate) fn record_unknown(
        &self,
        operation: &str,
        effect: &str,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        self.update_effect(
            operation,
            effect,
            cancellation,
            deadline,
            |effect| {
                if matches!(
                    effect.state,
                    EffectState::Observed { .. }
                        | EffectState::NotApplied
                        | EffectState::BootFenced { .. }
                        | EffectState::ManagerFenced { .. }
                ) {
                    return Err(invalid("terminal effect cannot become unknown"));
                }
                // Accepted is still unresolved; preserve its durable job identity.
                if matches!(effect.state, EffectState::Intent) {
                    effect.state = EffectState::Unknown;
                }
                Ok(())
            },
        )
    }
    /// Records a local publication target not established under this authority,
    /// not a claim that its bytes never existed. The trusted coordinator must
    /// hold the installation execution guard and verify filesystem evidence.
    /// This terminal state never provides publication or start authorization.
    pub(crate) fn record_not_applied(
        &self,
        operation: &str,
        effect: &str,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        self.mutate(cancellation, deadline, |state| {
            let selected = state
                .operations
                .get(operation)
                .ok_or_else(|| invalid("unknown operation"))?;
            if state.active_operation.as_deref() != Some(operation)
                || state.desired.as_deref() != Some(selected.candidate.as_str())
            {
                return Err(invalid("publication operation was superseded"));
            }
            let publication = selected
                .effects
                .get(effect)
                .ok_or_else(|| invalid("unknown effect"))?;
            if publication.kind != EffectKind::Publish
                || !matches!(
                    publication.state,
                    EffectState::Intent | EffectState::Unknown
                )
                || state
                    .bindings
                    .get(&publication.resource)
                    .is_some_and(|binding| {
                        binding.generation == selected.candidate
                            && binding.publication == publication.target
                    })
            {
                return Err(invalid(
                    "publication cannot be recorded as not applied",
                ));
            }
            state
                .operations
                .get_mut(operation)
                .expect("validated operation")
                .effects
                .get_mut(effect)
                .expect("validated effect")
                .state = EffectState::NotApplied;
            Ok(())
        })
    }
    /// Records an assertion from the trusted internal coordinator. The journal
    /// does not query the manager or turn these fields into proof of execution.
    /// Callers must compare real structured adapter evidence independently.
    /// Started means confirmed exec only; Stopped does not permit root cleanup.
    #[allow(clippy::too_many_arguments)] // Explicit authority, identity and bounded-I/O context.
    pub(crate) fn record_observed(
        &self,
        operation: &str,
        effect: &str,
        fingerprint: ContentDigest,
        invocation: Option<&str>,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        if let Some(invocation) = invocation {
            record::check_id(invocation)?;
        }
        self.update_effect(
            operation,
            effect,
            cancellation,
            deadline,
            |effect| {
                if matches!(
                    effect.state,
                    EffectState::NotApplied
                        | EffectState::BootFenced { .. }
                        | EffectState::ManagerFenced { .. }
                ) {
                    return Err(invalid(
                        "terminal publication cannot become observed",
                    ));
                }
                if effect.target != fingerprint.to_string() {
                    return Err(invalid("observed effect differs from intention"));
                }
                let next = EffectState::Observed {
                    fingerprint: fingerprint.to_string(),
                    invocation: invocation.map(str::to_owned),
                };
                if matches!(effect.state, EffectState::Observed { .. }) && effect.state != next {
                    return Err(invalid(
                        "confirmed effect evidence cannot be replaced",
                    ));
                }
                effect.state = next;
                Ok(())
            },
        )
    }
    /// Joins a published immutable binding to the selected operation. The Publish
    /// target is the hash of the canonical launch file, not a systemd unit hash.
    /// The trusted coordinator must verify publication before recording Observed;
    /// this method validates recorded identities and never fabricates filesystem proof.
    pub(crate) fn authorize_binding(
        &self,
        operation: &str,
        publication: &str,
        binding: &OsLaunchBinding,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        let pin = binding
            .digest()
            .map_err(|_| invalid("invalid immutable launch binding"))?;
        self.mutate(cancellation, deadline, |state| {
            if binding.installation_id() != self.installation {
                return Err(invalid(
                    "launch binding belongs to another installation",
                ));
            }
            if state
                .boot_fences
                .contains_key(binding.epoch().boot.as_str())
            {
                return Err(invalid("fenced boot cannot regain authorization"));
            }
            if state.active_operation.as_deref() != Some(operation) {
                return Err(invalid("operation was superseded"));
            }
            let op = state
                .operations
                .get(operation)
                .ok_or_else(|| invalid("unknown operation"))?;
            if state.desired.as_deref() != Some(&op.candidate) {
                return Err(invalid("generation is no longer desired"));
            }
            if binding.generation().to_string() != op.candidate || binding.epoch() != &op.epoch {
                return Err(invalid(
                    "launch binding generation or epoch differs from operation",
                ));
            }
            let effect = op
                .effects
                .get(publication)
                .ok_or_else(|| invalid("unknown publication"))?;
            if effect.kind != EffectKind::Publish
                || !matches!(effect.state, EffectState::Observed { .. })
            {
                return Err(invalid("publication is not confirmed"));
            }
            if effect.resource != binding.process_key() || effect.target != pin.to_string() {
                return Err(invalid(
                    "publication does not identify this launch binding",
                ));
            }
            if state
                .bindings
                .get(&effect.resource)
                .is_some_and(|old| old.authorized)
            {
                return Err(invalid("binding is already authorized"));
            }
            state.bindings.insert(
                effect.resource.clone(),
                Binding {
                    generation: op.candidate.clone(),
                    pin: pin.to_string(),
                    unit: binding.unit().as_str().into(),
                    publication: effect.target.clone(),
                    authorization: fresh(|id| {
                        state
                            .bindings
                            .values()
                            .any(|binding| binding.authorization == id)
                            || state
                                .attempts
                                .values()
                                .any(|attempt| attempt.authorization == id)
                    })?,
                    epoch: op.epoch.clone(),
                    authorized: true,
                },
            );
            Ok(())
        })
    }
    #[cfg(test)]
    pub(crate) fn revoke_binding(
        &self,
        resource: &str,
        expected: ContentDigest,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        self.mutate(cancellation, deadline, |state| {
            let binding = state
                .bindings
                .get_mut(resource)
                .ok_or_else(|| invalid("unknown binding"))?;
            if binding.pin != expected.to_string() {
                return Err(invalid("binding changed"));
            }
            binding.authorized = false;
            Ok(())
        })
    }
    pub(crate) fn revoke_binding_for_operation(
        &self,
        operation: &str,
        resource: &str,
        expected: ContentDigest,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        self.mutate(cancellation, deadline, |state| {
            let op = state
                .operations
                .get(operation)
                .ok_or_else(|| invalid("unknown operation"))?;
            if state.active_operation.as_deref() != Some(operation)
                || state.desired.as_deref() != Some(&op.candidate)
            {
                return Err(invalid("operation was superseded"));
            }
            let binding = state
                .bindings
                .get_mut(resource)
                .ok_or_else(|| invalid("unknown binding"))?;
            if binding.pin != expected.to_string() || binding.epoch != op.epoch {
                return Err(invalid("binding or epoch changed"));
            }
            binding.authorized = false;
            Ok(())
        })
    }
    /// Caller must authenticate unit/MainPID/InvocationID using the manager.
    /// This journal compares that evidence and consumes it durably, not validates IPC.
    #[allow(clippy::too_many_arguments)] // Explicit authority, identity and bounded-I/O context.
    #[cfg(test)]
    pub(crate) fn admit_start(
        &self,
        resource: &str,
        pin: ContentDigest,
        unit: &SystemdUnitName,
        invocation: &str,
        epoch: &ExecutionEpoch,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<StartAdmission> {
        self.admit_inventory_start(
            resource,
            pin,
            unit,
            invocation,
            epoch,
            None,
            cancellation,
            deadline,
        )
    }
    #[allow(clippy::too_many_arguments)] // Same authenticated admission fields; adds a non-forgeable local process capture.
    pub(crate) fn admit_captured_start(
        &self,
        resource: &str,
        pin: ContentDigest,
        unit: &SystemdUnitName,
        invocation: &str,
        epoch: &ExecutionEpoch,
        launcher: &crate::platform::linux::fd::persisted_namespace::CapturedLauncher,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<StartAdmission> {
        launcher.revalidate(cancellation, deadline)?;
        self.admit_inventory_start(
            resource,
            pin,
            unit,
            invocation,
            epoch,
            Some(launcher.record()),
            cancellation,
            deadline,
        )
    }
    #[allow(clippy::too_many_arguments)] // Admission is one journal transaction over the complete binding and kernel record.
    fn admit_inventory_start(
        &self,
        resource: &str,
        pin: ContentDigest,
        unit: &SystemdUnitName,
        invocation: &str,
        epoch: &ExecutionEpoch,
        launcher: Option<&crate::platform::linux::fd::persisted_namespace::LauncherRecord>,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<StartAdmission> {
        record::check_id(invocation)?;
        self.mutate(cancellation, deadline, |state| {
            let binding = state
                .bindings
                .get(resource)
                .ok_or_else(|| invalid("unknown binding"))?;
            if !binding.authorized
                || binding.pin != pin.to_string()
                || binding.unit != unit.as_str()
                || &binding.epoch != epoch
            {
                return Err(ActivationError::StartDenied(
                    "start binding is revoked or context differs",
                ));
            }
            if state.attempts.len() >= record::MAX_ATTEMPTS
                || state.attempts.values().any(|attempt| {
                    attempt.resource == resource
                        && attempt.invocation == invocation
                        && attempt.epoch == *epoch
                })
            {
                return Err(ActivationError::StartDenied(
                    "invocation already consumed or attempts exhausted",
                ));
            }
            let id = fresh(|id| state.attempts.contains_key(id))?;
            state.attempts.insert(
                id.clone(),
                Attempt {
                    resource: resource.into(),
                    binding: pin.to_string(),
                    authorization: binding.authorization.clone(),
                    invocation: invocation.into(),
                    epoch: epoch.clone(),
                    gate_used: false,
                    namespace: None,
                    launcher: launcher.cloned(),
                },
            );
            Ok(StartAdmission {
                installation: self.installation.clone(),
                attempt: id,
                binding: pin.to_string(),
            })
        })
    }
    /// Holds the same authority lock as revocation. The callback must use this
    /// cancellation/deadline, perform one bounded gate write and never reenter.
    /// Persist gate consumption first; ambiguous I/O is never replayed.
    #[cfg(test)]
    pub(crate) fn with_consumed_start<T>(
        &self,
        admission: StartAdmission,
        cancellation: &Cancellation,
        deadline: Instant,
        action: impl FnOnce() -> io::Result<T>,
    ) -> Result<T> {
        self.consume_start(admission, None, cancellation, deadline, action)
    }
    pub(crate) fn with_namespace_start<T>(
        &self,
        admission: StartAdmission,
        namespace: &crate::platform::linux::fd::persisted_namespace::CapturedNamespace,
        cancellation: &Cancellation,
        deadline: Instant,
        action: impl FnOnce() -> io::Result<T>,
    ) -> Result<T> {
        namespace.revalidate(cancellation, deadline)?;
        self.consume_start(
            admission,
            Some(namespace.record()),
            cancellation,
            deadline,
            action,
        )
    }
    #[allow(clippy::needless_pass_by_value)] // Consume the single-use token even when gate delivery fails.
    fn consume_start<T>(
        &self,
        admission: StartAdmission,
        namespace: Option<&crate::platform::linux::fd::persisted_namespace::NamespaceRecord>,
        cancellation: &Cancellation,
        deadline: Instant,
        action: impl FnOnce() -> io::Result<T>,
    ) -> Result<T> {
        let _guard = self.storage.lock(cancellation, deadline)?;
        let mut state = self.load()?;
        if admission.installation != self.installation {
            return Err(invalid("foreign start admission"));
        }
        let attempt = state
            .attempts
            .get_mut(&admission.attempt)
            .ok_or_else(|| invalid("missing consumed attempt"))?;
        let binding = state
            .bindings
            .get(&attempt.resource)
            .ok_or_else(|| invalid("missing binding"))?;
        if attempt.gate_used
            || attempt.binding != admission.binding
            || !binding.authorized
            || binding.pin != attempt.binding
            || binding.authorization != attempt.authorization
            || binding.epoch != attempt.epoch
        {
            return Err(ActivationError::StartDenied(
                "start authorization no longer valid",
            ));
        }
        if let Some(namespace) = namespace {
            namespace.validate()?;
            if namespace.boot() != &attempt.epoch.boot {
                return Err(invalid("namespace startup boot differs"));
            }
            attempt.namespace = Some(namespace.clone());
        }
        attempt.gate_used = true;
        self.save(&state, cancellation, deadline)?;
        check(cancellation, deadline)?;
        action().map_err(Into::into)
    }
    fn update_effect(
        &self,
        operation: &str,
        effect: &str,
        cancellation: &Cancellation,
        deadline: Instant,
        action: impl FnOnce(&mut Effect) -> Result<()>,
    ) -> Result<()> {
        self.mutate(cancellation, deadline, |state| {
            let operation = state
                .operations
                .get_mut(operation)
                .ok_or_else(|| invalid("unknown operation"))?;
            if operation.abandoned {
                return Err(invalid("abandoned operation is immutable"));
            }
            let effect = operation
                .effects
                .get_mut(effect)
                .ok_or_else(|| invalid("unknown effect"))?;
            action(effect)
        })
    }
    fn load(&self) -> Result<ActivationSnapshot> {
        if self.storage.installation_id(false)? != self.installation {
            return Err(invalid("installation identity changed"));
        }
        self.storage.read_activation()?.map_or_else(
            || {
                Ok(ActivationSnapshot::empty(
                    self.installation.clone(),
                ))
            },
            |bytes| ActivationSnapshot::parse(&bytes, &self.installation),
        )
    }
    fn save(
        &self,
        state: &ActivationSnapshot,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        let bytes = state.bytes()?;
        check(cancellation, deadline)?;
        self.storage.write_activation(&bytes)?;
        Ok(())
    }
    fn mutate<T>(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
        action: impl FnOnce(&mut ActivationSnapshot) -> Result<T>,
    ) -> Result<T> {
        let _guard = self.storage.lock(cancellation, deadline)?;
        let mut state = self.load()?;
        let result = action(&mut state)?;
        self.save(&state, cancellation, deadline)?;
        Ok(result)
    }
}
fn check(cancellation: &Cancellation, deadline: Instant) -> Result<()> {
    cancellation
        .check()
        .map_err(|_| InstallationError::Cancelled)?;
    if Instant::now() >= deadline {
        return Err(InstallationError::Deadline.into());
    }
    Ok(())
}
fn fresh(exists: impl Fn(&str) -> bool) -> Result<String> {
    for _ in 0..64 {
        let random = crate::platform::linux::fd::operation_name()?;
        let id = random
            .strip_prefix("op-")
            .ok_or_else(|| invalid("invalid operation entropy"))?;
        if record::identifier(id) && !exists(id) {
            return Ok(id.into());
        }
    }
    Err(invalid("operation entropy retries exhausted"))
}
fn recorded_invocation(
    state: &ActivationSnapshot,
    resource: &str,
    pin: ContentDigest,
) -> Result<Option<String>> {
    let Some(binding) = state.bindings.get(resource) else {
        return Ok(None);
    };
    if binding.pin != pin.to_string() {
        return Err(invalid("binding changed"));
    }
    // A later admitted attempt without an Observed reply must not disappear
    // when a caller asks for a singleton. This API cannot select among attempts.
    let all: std::collections::BTreeSet<_> = state
        .attempts
        .values()
        .filter(|attempt| {
            attempt.resource == resource
                && attempt.binding == binding.pin
                && attempt.authorization == binding.authorization
                && attempt.epoch == binding.epoch
        })
        .map(|attempt| &attempt.invocation)
        .collect();
    if all.len() > 1 {
        return Err(invalid("ambiguous admitted invocation evidence"));
    }
    let accepted: std::collections::BTreeSet<_> = state
        .operations
        .values()
        .filter(|operation| operation.epoch == binding.epoch)
        .flat_map(|operation| operation.effects.values())
        .filter(|effect| {
            effect.resource == resource
                && effect.kind == EffectKind::Start
                && effect.target == binding.pin
        })
        .filter_map(|effect| match &effect.state {
            EffectState::Observed {
                invocation: Some(value),
                ..
            } => Some(value.as_str()),
            _ => None,
        })
        .collect();
    let mut invocations: std::collections::BTreeSet<_> = state
        .attempts
        .values()
        .filter(|attempt| {
            attempt.resource == resource
                && attempt.binding == binding.pin
                && attempt.authorization == binding.authorization
                && attempt.epoch == binding.epoch
                && attempt.gate_used
                && accepted.contains(attempt.invocation.as_str())
        })
        .map(|attempt| attempt.invocation.clone())
        .collect();
    if invocations.len() > 1 {
        return Err(invalid("ambiguous invocation evidence"));
    }
    Ok(invocations.pop_first())
}

/// Complete authenticated candidate set across historical bindings of one resource.
/// Incomplete attempts remain in the enclosing inventory and cannot be settled.
fn admitted_invocations(
    state: &ActivationSnapshot,
    resource: &str,
    epoch: &ExecutionEpoch,
) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for (id, attempt) in &state.attempts {
        if attempt.resource != resource || attempt.epoch != *epoch {
            continue;
        }
        if !state.operations.values().any(|operation| operation.epoch == *epoch
            && operation.effects.values().any(|effect| effect.resource == resource
                && effect.kind == EffectKind::Publish
                && matches!(&effect.state, EffectState::Observed { fingerprint, .. } if fingerprint == &attempt.binding))) {
            return Err(invalid("historical attempt lacks confirmed publication"));
        }
        if !attempt.gate_used {
            continue;
        }
        let observed = state.operations.values().any(|operation| operation.epoch == *epoch
            && operation.effects.values().any(|effect| effect.resource == resource
                && effect.kind == EffectKind::Start && effect.target == attempt.binding
                && matches!(&effect.state, EffectState::Observed { invocation: Some(found), .. } if found == &attempt.invocation)));
        if (attempt.namespace.is_some() || observed)
            && result
                .insert(attempt.invocation.clone(), id.clone())
                .is_some()
        {
            return Err(invalid("duplicate historical invocation"));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests;

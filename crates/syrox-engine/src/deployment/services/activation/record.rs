use super::{ActivationError, Result};
use crate::platform::linux::boot::BootId;
use crate::{store::ContentDigest, systemd::SystemdUnitName};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const MAX_OPERATIONS: usize = 128;
pub(super) const MAX_RESOURCES: usize = 1024;
pub(super) const MAX_ATTEMPTS: usize = 4096;
const HEADER: &[u8] = b"syrox-os-activation-v1\n";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionEpoch {
    pub boot: BootId,
    /// Structured manager identity supplied by the authenticated adapter, not a PID.
    pub manager: String,
    /// Installation scope (including user identity and explicit manager endpoint).
    pub scope: String,
}
impl ExecutionEpoch {
    pub(crate) fn validate(&self) -> Result<()> {
        text(&self.manager, 256)?;
        text(&self.scope, 4096)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EffectKind {
    Publish,
    Reload,
    Start,
    Stop,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum EffectState {
    Intent,
    Accepted {
        job: String,
    },
    Unknown,
    /// A different authenticated boot fences remote work, not publication or GC.
    BootFenced {
        epoch: ExecutionEpoch,
        job: Option<String>,
    },
    /// Same-boot prior manager work was quiesced; not successful effect completion.
    ManagerFenced {
        epoch: ExecutionEpoch,
        job: Option<String>,
    },
    /// Publication target was not established under the coordinator authority.
    NotApplied,
    /// Data from an explicit reconciliation. This is not namespace quiescence.
    Observed {
        fingerprint: String,
        invocation: Option<String>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Effect {
    pub resource: String,
    pub kind: EffectKind,
    pub expected: Option<String>,
    pub target: String,
    pub state: EffectState,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationKind {
    #[default]
    Apply,
    Rollback,
}
impl OperationKind {
    #[allow(clippy::trivially_copy_pass_by_ref)] // Serde skip predicate requires a reference.
    pub(super) fn is_apply(&self) -> bool {
        *self == Self::Apply
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Operation {
    #[serde(default, skip_serializing_if = "OperationKind::is_apply")]
    pub kind: OperationKind,
    pub previous: Option<String>,
    pub candidate: String,
    pub epoch: ExecutionEpoch,
    pub effects: BTreeMap<String, Effect>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub abandoned: bool,
}
impl Operation {
    pub(crate) fn terminal(&self) -> bool {
        self.effects.values().all(|effect| {
            matches!(
                effect.state,
                EffectState::Observed { .. }
                    | EffectState::NotApplied
                    | EffectState::BootFenced { .. }
                    | EffectState::ManagerFenced { .. }
            )
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub generation: String,
    pub pin: String,
    pub unit: String,
    pub publication: String,
    pub authorization: String,
    pub epoch: ExecutionEpoch,
    pub authorized: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attempt {
    pub resource: String,
    pub binding: String,
    pub authorization: String,
    pub invocation: String,
    pub epoch: ExecutionEpoch,
    pub gate_used: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<crate::platform::linux::fd::persisted_namespace::NamespaceRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher: Option<crate::platform::linux::fd::persisted_namespace::LauncherRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivationSnapshot {
    pub(super) version: u32,
    pub installation: String,
    pub desired: Option<String>,
    pub active_operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_abandoned: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub boot_fences: BTreeMap<String, ExecutionEpoch>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub manager_changes: BTreeMap<String, super::manager_change::ManagerChange>,
    pub operations: BTreeMap<String, Operation>,
    /// Confirmed publication bindings, not a claim of a globally effective generation.
    pub bindings: BTreeMap<String, Binding>,
    pub(super) attempts: BTreeMap<String, Attempt>,
}
impl ActivationSnapshot {
    pub(crate) fn boot_fenced(&self, previous: &ExecutionEpoch, current: &ExecutionEpoch) -> bool {
        previous.boot != current.boot
            && previous.scope == current.scope
            && self
                .boot_fences
                .get(previous.boot.as_str())
                .is_some_and(|fence| fence.boot == current.boot && fence.scope == current.scope)
    }
    pub(super) fn empty(installation: String) -> Self {
        Self {
            version: 1,
            installation,
            desired: None,
            active_operation: None,
            last_abandoned: None,
            boot_fences: BTreeMap::new(),
            manager_changes: BTreeMap::new(),
            operations: BTreeMap::new(),
            bindings: BTreeMap::new(),
            attempts: BTreeMap::new(),
        }
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = HEADER.to_vec();
        serde_json::to_writer(BoundedWriter(&mut bytes), self)
            .map_err(|_| invalid("cannot encode activation state"))?;
        if bytes.len() > super::MAX_STATE_BYTES {
            return Err(invalid("activation state exceeds bound"));
        }
        Ok(bytes)
    }
    pub(super) fn parse(bytes: &[u8], installation: &str) -> Result<Self> {
        if bytes.len() > super::MAX_STATE_BYTES {
            return Err(invalid("activation state exceeds bound"));
        }
        let json = bytes
            .strip_prefix(HEADER)
            .ok_or_else(|| invalid("unsupported activation state"))?;
        let result: Self =
            serde_json::from_slice(json).map_err(|_| invalid("malformed activation state"))?;
        if result.installation != installation || result.bytes()? != bytes {
            return Err(invalid(
                "noncanonical or foreign activation state",
            ));
        }
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        self.validate_registry()?;
        self.validate_selection()?;
        let mut publications = BTreeSet::new();
        let scope = self
            .operations
            .values()
            .next()
            .map(|operation| &operation.epoch.scope);
        self.validate_boot_fences(scope)?;
        for (id, operation) in &self.operations {
            if operation.abandoned && !operation.terminal() {
                return Err(invalid(
                    "abandoned operation has unresolved effects",
                ));
            }
            if Some(&operation.epoch.scope) != scope {
                return Err(invalid("installation manager scope changed"));
            }
            check_id(id)?;
            digest(&operation.candidate)?;
            optional_digest(operation.previous.as_deref())?;
            if operation.kind == OperationKind::Rollback
                && (operation.previous.is_none()
                    || operation.previous.as_ref() == Some(&operation.candidate))
            {
                return Err(invalid(
                    "rollback requires a different prior selection",
                ));
            }
            operation.epoch.validate()?;
            if operation.effects.len() > MAX_RESOURCES * 4 {
                return Err(invalid("effect registry exhausted"));
            }
            let mut unique = BTreeSet::new();
            for (effect_id, effect) in &operation.effects {
                check_id(effect_id)?;
                text(&effect.resource, 272)?;
                optional_digest(effect.expected.as_deref())?;
                digest(&effect.target)?;
                if !unique.insert((effect.resource.as_str(), effect.kind as u8)) {
                    return Err(invalid("duplicate effect intent"));
                }
                validate_effect(effect)?;
                if let EffectState::BootFenced {
                    epoch,
                    ..
                } = &effect.state
                    && (epoch.boot == operation.epoch.boot
                        || epoch.scope != operation.epoch.scope
                        || !self
                            .boot_fences
                            .contains_key(operation.epoch.boot.as_str()))
                {
                    return Err(invalid("invalid fenced effect epoch"));
                }
                if let EffectState::ManagerFenced {
                    epoch,
                    ..
                } = &effect.state
                    && !self.manager_fenced(&operation.epoch, epoch)
                {
                    return Err(invalid("invalid manager fenced effect epoch"));
                }
                if let EffectState::Observed {
                    fingerprint,
                    ..
                } = &effect.state
                    && effect.kind == EffectKind::Publish
                {
                    publications.insert((
                        operation.candidate.as_str(),
                        effect.resource.as_str(),
                        fingerprint.as_str(),
                        operation.epoch.boot.as_str(),
                        operation.epoch.manager.as_str(),
                        operation.epoch.scope.as_str(),
                    ));
                }
            }
        }
        let mut units = BTreeSet::new();
        for (resource, binding) in &self.bindings {
            text(resource, 272)?;
            digest(&binding.generation)?;
            digest(&binding.pin)?;
            digest(&binding.publication)?;
            if binding.pin != binding.publication {
                return Err(invalid(
                    "authorized binding differs from published bytes",
                ));
            }
            check_id(&binding.authorization)?;
            binding.epoch.validate()?;
            if binding.authorized
                && self
                    .boot_fences
                    .contains_key(binding.epoch.boot.as_str())
            {
                return Err(invalid(
                    "fenced boot retains binding authorization",
                ));
            }
            SystemdUnitName::new(&binding.unit).map_err(|_| invalid("invalid binding unit"))?;
            if !units.insert(&binding.unit) {
                return Err(invalid("duplicate binding unit"));
            }
            if !publications.contains(&(
                binding.generation.as_str(),
                resource.as_str(),
                binding.publication.as_str(),
                binding.epoch.boot.as_str(),
                binding.epoch.manager.as_str(),
                binding.epoch.scope.as_str(),
            )) {
                return Err(invalid("binding lacks confirmed publication"));
            }
        }
        self.validate_attempts()?;
        super::manager_change::validate(self)
    }
    fn validate_registry(&self) -> Result<()> {
        if self.version != 1 || !identifier(&self.installation) {
            return Err(invalid("invalid activation identity"));
        }
        if self.operations.len() > MAX_OPERATIONS
            || self.bindings.len() > MAX_RESOURCES
            || self.attempts.len() > MAX_ATTEMPTS
            || self.boot_fences.len() > MAX_OPERATIONS
        {
            return Err(invalid("activation registry exhausted"));
        }
        Ok(())
    }
    fn validate_boot_fences(&self, scope: Option<&String>) -> Result<()> {
        for (previous, current) in &self.boot_fences {
            let previous = BootId::parse(previous).map_err(|_| invalid("invalid fenced boot"))?;
            current.validate()?;
            if previous == current.boot
                || Some(&current.scope) != scope
                || !self
                    .operations
                    .values()
                    .any(|op| op.epoch.boot == previous)
            {
                return Err(invalid("invalid boot fence authority"));
            }
        }
        Ok(())
    }
    fn validate_selection(&self) -> Result<()> {
        optional_digest(self.desired.as_deref())?;
        match &self.active_operation {
            Some(id)
                if self.last_abandoned.is_none()
                    && self.operations.get(id).is_some_and(|op| {
                        !op.abandoned && Some(&op.candidate) == self.desired.as_ref()
                    }) => {}
            None if self.desired.is_none()
                && self.operations.is_empty()
                && self.last_abandoned.is_none() => {}
            None if self.desired.is_none()
                && self.operations.values().all(Operation::terminal)
                && self.last_abandoned.as_ref().is_some_and(|id| {
                    self.operations
                        .get(id)
                        .is_some_and(|op| op.abandoned)
                }) => {}
            _ => {
                return Err(invalid(
                    "active operation differs from desired generation",
                ));
            }
        }
        Ok(())
    }
    fn validate_attempts(&self) -> Result<()> {
        let mut invocations = BTreeSet::new();
        for (id, attempt) in &self.attempts {
            check_id(id)?;
            text(&attempt.resource, 272)?;
            digest(&attempt.binding)?;
            check_id(&attempt.authorization)?;
            check_id(&attempt.invocation)?;
            attempt.epoch.validate()?;
            if let Some(launcher) = &attempt.launcher {
                launcher
                    .validate()
                    .map_err(|_| invalid("invalid launcher inventory evidence"))?;
                if launcher.boot() != &attempt.epoch.boot {
                    return Err(invalid("launcher boot differs from attempt"));
                }
            }
            if let Some(namespace) = &attempt.namespace {
                namespace
                    .validate()
                    .map_err(|_| invalid("invalid namespace startup evidence"))?;
                if !attempt.gate_used || namespace.boot() != &attempt.epoch.boot {
                    return Err(invalid(
                        "namespace evidence differs from consumed gate",
                    ));
                }
            }
            if !invocations.insert((
                &attempt.resource,
                attempt.epoch.boot.as_str(),
                &attempt.epoch.manager,
                &attempt.invocation,
            )) {
                return Err(invalid("replayed invocation"));
            }
        }
        Ok(())
    }
}
fn validate_effect(effect: &Effect) -> Result<()> {
    match &effect.state {
        EffectState::BootFenced {
            epoch,
            job,
        }
        | EffectState::ManagerFenced {
            epoch,
            job,
        } => {
            if effect.kind == EffectKind::Publish {
                return Err(invalid("publication cannot be boot fenced"));
            }
            epoch.validate()?;
            if let Some(job) = job {
                text(job, 4096)?;
            }
        }
        EffectState::Accepted {
            job,
        } => text(job, 4096)?,
        EffectState::Observed {
            fingerprint,
            invocation,
        } => {
            digest(fingerprint)?;
            if fingerprint != &effect.target {
                return Err(invalid("effect observation differs from target"));
            }
            if let Some(invocation) = invocation {
                check_id(invocation)?;
            }
            if effect.kind == EffectKind::Start && invocation.is_none() {
                return Err(invalid("start observation lacks invocation"));
            }
        }
        EffectState::NotApplied if effect.kind != EffectKind::Publish => {
            return Err(invalid("only publication can be not applied"));
        }
        EffectState::Intent | EffectState::Unknown | EffectState::NotApplied => {}
    }
    Ok(())
}
pub(super) fn identifier(text: &str) -> bool {
    text.len() == 32
        && text.bytes().any(|b| b != b'0')
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn check_id(value: &str) -> Result<()> {
    if identifier(value) {
        Ok(())
    } else {
        Err(invalid("invalid attempt/operation identity"))
    }
}
pub(super) fn digest(value: &str) -> Result<()> {
    value
        .parse::<ContentDigest>()
        .map(|_| ())
        .map_err(|_| invalid("invalid content pin"))
}
fn optional_digest(value: Option<&str>) -> Result<()> {
    value.map_or(Ok(()), digest)
}
pub(super) fn text(value: &str, bound: usize) -> Result<()> {
    if value.is_empty() || value.len() > bound || value.bytes().any(|b| b.is_ascii_control()) {
        Err(invalid("invalid activation text"))
    } else {
        Ok(())
    }
}
pub(super) const fn invalid(message: &'static str) -> ActivationError {
    ActivationError::Invalid(message)
}

struct BoundedWriter<'a>(&'a mut Vec<u8>);
impl std::io::Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > super::MAX_STATE_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other(
                "activation encoding exceeds bound",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

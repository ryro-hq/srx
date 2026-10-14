use super::{
    OsRecoveryEffect, OsRecoveryError, OsRecoveryReport, OsRecoveryState, failure, failure_with,
};
use crate::deployment::os::{
    activation::{ActivationSnapshot, EffectKind, EffectState},
    apply::{
        manager::{ApplyManager, EffectOutcome, EffectStatus, Manager},
        preparation::PreparedResource,
    },
    installation::GenerationInstallation,
    paths::OsExecutionPaths,
    unit_files::UnitFiles,
};
use crate::{store::ContentDigest, systemd::SystemdUnitName};
use std::collections::BTreeMap;

type Result<T> = std::result::Result<T, OsRecoveryError>;
/// Caller holds the installation execution guard through the whole observation.
pub(in crate::deployment::os::apply) fn reconcile<M: Manager>(
    driver: ApplyManager<'_, M>,
    installation: &GenerationInstallation,
    paths: &OsExecutionPaths,
    units: &UnitFiles,
    resources: &BTreeMap<String, PreparedResource>,
    snapshot: &ActivationSnapshot,
    candidate: ContentDigest,
) -> OsRecoveryReport {
    let mut report = OsRecoveryReport {
        operation: driver.operation.into(),
        candidate,
        effects: Vec::new(),
        needs_reconciliation: false,
    };
    let Some(operation) = snapshot.operations.get(driver.operation) else {
        report.needs_reconciliation = true;
        return report;
    };
    let mut selected = operation.effects.iter().collect::<Vec<_>>();
    // Complete publication evidence before observing a loaded/start contract.
    // A recovered Stop only records state, so its relative order does not send signals.
    selected.sort_by_key(|(id, effect)| {
        (
            order(
                effect.kind,
                resources.contains_key(&effect.resource),
            ),
            *id,
        )
    });
    let mut coordinator = Coordinator {
        driver,
        installation,
        paths,
        units,
        resources,
    };
    for (id, effect) in selected {
        let result = if matches!(effect.state, EffectState::Observed { .. }) {
            Ok(OsRecoveryState::Observed)
        } else if matches!(effect.state, EffectState::NotApplied) {
            Ok(OsRecoveryState::NotApplied)
        } else if matches!(effect.state, EffectState::BootFenced { .. }) {
            Ok(OsRecoveryState::BootFenced)
        } else if matches!(effect.state, EffectState::ManagerFenced { .. }) {
            Ok(OsRecoveryState::ManagerFenced)
        } else {
            (|| {
                let target = effect
                    .target
                    .parse()
                    .map_err(|source| failure_with("invalid effect target", source))?;
                let previous = effect
                    .expected
                    .as_deref()
                    .map(str::parse)
                    .transpose()
                    .map_err(|source| failure_with("invalid expected publication", source))?;
                coordinator.effect(
                    id,
                    &effect.resource,
                    effect.kind,
                    target,
                    previous,
                )
            })()
        };
        let (status, stage, error) = match result {
            Ok(state) => (state, None, None),
            Err(error) => {
                report.needs_reconciliation = true;
                (
                    OsRecoveryState::Pending,
                    Some(error.stage),
                    error.source.map(|source| source.to_string()),
                )
            }
        };
        report.effects.push(OsRecoveryEffect {
            effect: id.clone(),
            resource: effect.resource.clone(),
            kind: kind_name(effect.kind),
            state: status,
            stage,
            error,
        });
    }
    report
}
struct Coordinator<'a, M: Manager> {
    driver: ApplyManager<'a, M>,
    installation: &'a GenerationInstallation,
    paths: &'a OsExecutionPaths,
    units: &'a UnitFiles,
    resources: &'a BTreeMap<String, PreparedResource>,
}
impl<M: Manager> Coordinator<'_, M> {
    fn effect(
        &mut self,
        id: &str,
        resource: &str,
        kind: EffectKind,
        target: ContentDigest,
        previous: Option<ContentDigest>,
    ) -> Result<OsRecoveryState> {
        self.paths
            .revalidate(self.driver.cancellation, self.driver.deadline)
            .map_err(|source| failure_with("execution paths changed", source))?;
        match kind {
            EffectKind::Publish => self.publication(id, resource, target, previous),
            EffectKind::Stop => self
                .stop(id, resource, target)
                .map(|()| OsRecoveryState::Observed),
            EffectKind::Start => {
                let next = self
                    .resources
                    .get(resource)
                    .ok_or("unknown start resource")?;
                if next.contract.binding() != target {
                    return Err(failure(
                        "start binding differs from requested context",
                    ));
                }
                self.published(next)?;
                observed(
                    &self
                        .driver
                        .reconcile_start(id, resource, &next.binding, &next.contract)
                        .map_err(|source| failure_with("validate start reconciliation", source))?,
                )
                .map(|()| OsRecoveryState::Observed)
            }
            EffectKind::Reload => {
                let key = resource
                    .strip_prefix("unit/")
                    .ok_or("invalid reload resource")?;
                let next = self
                    .resources
                    .get(key)
                    .ok_or("unknown reload resource")?;
                self.published(next)?;
                observed(
                    &self
                        .driver
                        .reconcile_reload(id, resource, target, &[&next.contract])
                        .map_err(|source| failure_with("validate reload reconciliation", source))?,
                )
                .map(|()| OsRecoveryState::Observed)
            }
        }
    }
    fn publication(
        &self,
        id: &str,
        resource: &str,
        target: ContentDigest,
        previous: Option<ContentDigest>,
    ) -> Result<OsRecoveryState> {
        let driver = &self.driver;
        if let Some(key) = resource
            .strip_prefix("unit/")
            .filter(|_| !self.resources.contains_key(resource))
        {
            let next = self
                .resources
                .get(key)
                .ok_or("unknown unit publication")?;
            if next.contract.file_digest() != target {
                return Err(failure(
                    "unit publication differs from requested context",
                ));
            }
            self.units
                .reconcile_expected(
                    next.contract.unit(),
                    previous,
                    target,
                    driver.cancellation,
                    driver.deadline,
                )
                .map_err(|source| failure_with("reconcile exact unit publication", source))?;
            if self
                .units
                .observe(
                    next.contract.unit(),
                    driver.cancellation,
                    driver.deadline,
                )
                .map_err(|source| failure_with("observe owned unit publication", source))?
                != Some(target)
            {
                self.units
                    .confirm_previous(
                        next.contract.unit(),
                        previous,
                        target,
                        driver.cancellation,
                        driver.deadline,
                    )
                    .map_err(|source| failure_with("unit publication remains uncertain", source))?;
                return self.not_applied(id);
            }
        } else {
            let next = self
                .resources
                .get(resource)
                .ok_or("unknown binding publication")?;
            if next.contract.binding() != target {
                return Err(failure(
                    "binding publication differs from requested context",
                ));
            }
            match self
                .installation
                .observe_launch_binding(target, driver.cancellation, driver.deadline)
                .map_err(|source| failure_with("observe durable binding", source))?
            {
                Some(binding) if binding == next.binding => {}
                Some(_) => return Err(failure("binding publication differs")),
                None => return self.not_applied(id),
            }
        }
        driver
            .journal
            .record_observed(
                driver.operation,
                id,
                target,
                None,
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|source| failure_with("record recovered publication", source))
            .map(|()| OsRecoveryState::Observed)
    }
    fn not_applied(&self, id: &str) -> Result<OsRecoveryState> {
        self.driver
            .journal
            .record_not_applied(
                self.driver.operation,
                id,
                self.driver.cancellation,
                self.driver.deadline,
            )
            .map_err(|source| failure_with("record publication not applied", source))?;
        Ok(OsRecoveryState::NotApplied)
    }
    fn published(&self, next: &PreparedResource) -> Result<()> {
        let driver = &self.driver;
        if self
            .installation
            .observe_launch_binding(
                next.contract.binding(),
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|source| failure_with("observe published binding", source))?
            .as_ref()
            != Some(&next.binding)
        {
            return Err(failure("binding publication differs"));
        }
        if self
            .units
            .observe(
                next.contract.unit(),
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|source| failure_with("observe published unit", source))?
            != Some(next.contract.file_digest())
        {
            return Err(failure("unit publication differs"));
        }
        Ok(())
    }
    fn stop(&mut self, id: &str, resource: &str, target: ContentDigest) -> Result<()> {
        let binding = self
            .installation
            .read_launch_binding(
                target,
                self.driver.cancellation,
                self.driver.deadline,
            )
            .map_err(|source| failure_with("read prior stop binding", source))?;
        if binding.process_key() != resource || binding.epoch() != self.driver.epoch {
            return Err(failure("stop binding or epoch differs"));
        }
        let invocation = self
            .driver
            .journal
            .observed_invocation(
                resource,
                target,
                self.driver.cancellation,
                self.driver.deadline,
            )
            .map_err(|source| failure_with("read owned stop invocation", source))?
            .ok_or("stop invocation ownership is not recorded")?;
        let invocation = super::super::coordinator::invocation_bytes(&invocation)?;
        let unit: SystemdUnitName = binding.unit();
        observed(
            &self
                .driver
                .reconcile_stop(id, resource, &unit, &invocation, target)
                .map_err(|source| failure_with("validate stop reconciliation", source))?,
        )
    }
}
fn observed(outcome: &EffectOutcome) -> Result<()> {
    match &outcome.state {
        EffectStatus::Observed {
            ..
        } => Ok(()),
        EffectStatus::Uncertain {
            stage,
            error,
        } => Err(error.as_ref().map_or_else(
            || failure(stage),
            |source| failure_with(stage, source.clone()),
        )),
    }
}
fn order(kind: EffectKind, is_binding: bool) -> u8 {
    match kind {
        EffectKind::Publish if is_binding => 0,
        EffectKind::Publish => 1,
        EffectKind::Stop => 2,
        EffectKind::Reload => 3,
        EffectKind::Start => 4,
    }
}
fn kind_name(kind: EffectKind) -> &'static str {
    match kind {
        EffectKind::Publish => "publish",
        EffectKind::Reload => "reload",
        EffectKind::Start => "start",
        EffectKind::Stop => "stop",
    }
}

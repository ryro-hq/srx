use super::conservation::PreservedResource;
use super::manager::{ApplyManager, EffectOutcome, EffectStatus, Manager, reload_target};
use super::preparation::PreparedResource;
use super::{OsApplyReport, OsApplyResource, OsApplyResourceState};
use crate::deployment::os::{
    activation::{ActivationSnapshot, EffectKind},
    installation::{GenerationInstallation, RetainedGeneration},
    paths::OsExecutionPaths,
    unit_files::UnitFiles,
};
use crate::{store::ContentDigest, systemd::SystemdUnitName};
use std::collections::{BTreeMap, BTreeSet};

type Result<T> = std::result::Result<T, &'static str>;
#[cfg(test)]
#[path = "tests/coordinator/mod.rs"]
mod tests;
pub(super) fn apply<M: Manager>(
    driver: ApplyManager<'_, M>,
    installation: &GenerationInstallation,
    candidate: &RetainedGeneration,
    paths: &OsExecutionPaths,
    units: &UnitFiles,
    resources: &BTreeMap<String, PreparedResource>,
    preserved: &BTreeMap<String, PreservedResource>,
) -> OsApplyReport {
    let mut coordinator = Coordinator {
        driver,
        installation,
        candidate,
        paths,
        units,
        preserved,
    };
    let mut report = OsApplyReport {
        operation: coordinator.driver.operation.into(),
        candidate: candidate.digest(),
        resources: Vec::new(),
        needs_reconciliation: false,
    };
    let Ok(snapshot) = coordinator.driver.journal.snapshot(
        coordinator.driver.cancellation,
        coordinator.driver.deadline,
    ) else {
        report.needs_reconciliation = true;
        return report;
    };
    let keys: BTreeSet<_> = resources
        .keys()
        .chain(snapshot.bindings.keys())
        .cloned()
        .collect();
    for key in keys {
        let next = resources.get(&key);
        let unit = next
            .map(|resource| resource.binding.unit().as_str().to_owned())
            .or_else(|| {
                snapshot
                    .bindings
                    .get(&key)
                    .map(|binding| binding.unit.clone())
            })
            .expect("resource union");
        let result = coordinator.apply_resource(&key, next, &snapshot);
        let (state, error_stage) = match result {
            Ok(state) => (state, None),
            Err(stage) => {
                report.needs_reconciliation = true;
                (OsApplyResourceState::Pending, Some(stage))
            }
        };
        report.resources.push(OsApplyResource {
            resource: key,
            unit,
            state,
            stage: error_stage,
        });
    }
    report
}

struct Coordinator<'a, M: Manager> {
    driver: ApplyManager<'a, M>,
    installation: &'a GenerationInstallation,
    candidate: &'a RetainedGeneration,
    paths: &'a OsExecutionPaths,
    units: &'a UnitFiles,
    preserved: &'a BTreeMap<String, PreservedResource>,
}
impl<M: Manager> Coordinator<'_, M> {
    fn apply_resource(
        &mut self,
        key: &str,
        next: Option<&PreparedResource>,
        snapshot: &ActivationSnapshot,
    ) -> Result<OsApplyResourceState> {
        self.paths
            .revalidate(self.driver.cancellation, self.driver.deadline)
            .map_err(|_| "execution paths changed")?;
        if self.settle_previous(key, next, snapshot)? {
            return Ok(OsApplyResourceState::Unchanged);
        }
        let Some(next) = next else {
            return Ok(OsApplyResourceState::Stopped);
        };
        let publication = self.publish(key, next)?;
        let contracts = [&next.contract];
        observed(
            self.driver
                .reload(
                    &format!("unit/{key}"),
                    reload_target(&contracts),
                    &contracts,
                )
                .map_err(|_| "plan reload")?,
        )?;
        self.driver
            .journal
            .authorize_binding(
                self.driver.operation,
                &publication,
                &next.binding,
                self.driver.cancellation,
                self.driver.deadline,
            )
            .map_err(|_| "authorize binding")?;
        self.paths
            .revalidate(self.driver.cancellation, self.driver.deadline)
            .map_err(|_| "execution paths changed")?;
        observed(
            self.driver
                .start(key, &next.binding, &next.contract)
                .map_err(|_| "plan start")?,
        )?;
        Ok(OsApplyResourceState::Started)
    }
    fn settle_previous(
        &mut self,
        key: &str,
        next: Option<&PreparedResource>,
        snapshot: &ActivationSnapshot,
    ) -> Result<bool> {
        if let Some(previous) = snapshot.bindings.get(key) {
            let pin = previous
                .pin
                .parse::<ContentDigest>()
                .map_err(|_| "invalid prior binding")?;
            let old = self
                .installation
                .read_launch_binding(
                    pin,
                    self.driver.cancellation,
                    self.driver.deadline,
                )
                .map_err(|_| "read prior binding")?;
            if old.epoch() != &previous.epoch
                || old.process_key() != key
                || old.unit().as_str() != previous.unit
            {
                return Err("prior binding differs from journal");
            }
            if previous.epoch != *self.driver.epoch {
                if previous.authorized
                    || (!snapshot.boot_fenced(&previous.epoch, self.driver.epoch)
                        && !snapshot.manager_fenced(&previous.epoch, self.driver.epoch))
                {
                    return Err("prior binding requires epoch reconciliation");
                }
                if !self
                    .driver
                    .verify_boot_idle(&old.unit())
                    .map_err(|_| "observe current boot unit and job")?
                {
                    return Err("current boot unit is not idle or has a job");
                }
                return Ok(false);
            }
            let invocation = self
                .driver
                .journal
                .observed_invocation(
                    key,
                    pin,
                    self.driver.cancellation,
                    self.driver.deadline,
                )
                .map_err(|_| "read owned invocation")?
                .ok_or("prior start requires reconciliation")?;
            let invocation = invocation_bytes(&invocation)?;
            if previous.authorized && next.is_some() {
                let contract = if next.is_some_and(|resource| resource.contract.binding() == pin) {
                    next.map(|resource| &resource.contract)
                } else {
                    self.preserved
                        .get(key)
                        .filter(|resource| resource.binding == old)
                        .map(|resource| &resource.contract)
                };
                if let Some(contract) = contract
                    && self.verify_preserved(
                        key,
                        &old,
                        contract,
                        &previous.authorization,
                        &invocation,
                    )?
                {
                    return Ok(true);
                }
            }
            self.driver
                .journal
                .revoke_binding_for_operation(
                    self.driver.operation,
                    key,
                    pin,
                    self.driver.cancellation,
                    self.driver.deadline,
                )
                .map_err(|_| "revoke prior binding")?;
            let unit = SystemdUnitName::new(&previous.unit).map_err(|_| "invalid prior unit")?;
            observed(
                self.driver
                    .stop(key, &unit, &invocation, pin)
                    .map_err(|_| "plan stop")?,
            )?;
        }
        Ok(false)
    }

    fn verify_preserved(
        &mut self,
        key: &str,
        binding: &crate::deployment::os::launch_binding::OsLaunchBinding,
        contract: &crate::systemd::persistent::OsUnitContract,
        authorization: &str,
        invocation: &[u8; 16],
    ) -> Result<bool> {
        let driver = &mut self.driver;
        if self
            .units
            .observe(
                contract.unit(),
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|_| "observe owned unit")?
            != Some(contract.file_digest())
        {
            return Err("owned unit differs from binding");
        }
        if !driver
            .verify_running(key, binding, contract, invocation)
            .map_err(|_| "verify running invocation")?
        {
            return Ok(false);
        }
        if self
            .units
            .observe(
                contract.unit(),
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|_| "revalidate owned unit")?
            != Some(contract.file_digest())
        {
            return Err("owned unit changed during observation");
        }
        let invocation = invocation
            .iter()
            .fold(String::with_capacity(32), |mut text, byte| {
                use std::fmt::Write as _;
                write!(&mut text, "{byte:02x}").expect("String write");
                text
            });
        if !driver
            .journal
            .preservation_current(
                driver.operation,
                key,
                binding
                    .digest()
                    .map_err(|_| "invalid prior binding")?,
                authorization,
                driver.epoch,
                &invocation,
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|_| "revalidate preservation authority")?
        {
            return Err("preservation authority changed");
        }
        Ok(true)
    }

    fn publish(&self, key: &str, next: &PreparedResource) -> Result<String> {
        let driver = &self.driver;
        let pin = next
            .binding
            .digest()
            .map_err(|_| "invalid binding")?;
        let previous = driver
            .journal
            .snapshot(driver.cancellation, driver.deadline)
            .map_err(|_| "read binding publication")?
            .bindings
            .get(key)
            .map(|binding| binding.pin.parse::<ContentDigest>())
            .transpose()
            .map_err(|_| "invalid prior binding")?;
        let effect = driver
            .journal
            .plan_effect(
                driver.operation,
                key,
                EffectKind::Publish,
                previous,
                pin,
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|_| "plan binding publication")?;
        // Any error after this durable intent leaves unresolved evidence. It must
        // be explicitly reconciled even if the syscall probably did nothing.
        let published = self
            .installation
            .publish_launch_binding(
                self.candidate,
                &next.binding,
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|_| "publish binding")?;
        let read = self
            .installation
            .read_launch_binding(pin, driver.cancellation, driver.deadline)
            .map_err(|_| "read published binding")?;
        if published != pin || read != next.binding {
            return Err("published binding differs");
        }
        driver
            .journal
            .record_observed(
                driver.operation,
                &effect,
                pin,
                None,
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|_| "record binding publication")?;
        self.publish_unit(key, next)?;
        Ok(effect)
    }
    fn publish_unit(&self, key: &str, next: &PreparedResource) -> Result<()> {
        let driver = &self.driver;
        let previous = self
            .units
            .observe(
                next.contract.unit(),
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|_| "observe unit publication")?;
        let pin = next.contract.file_digest();
        let effect = driver
            .journal
            .plan_effect(
                driver.operation,
                &format!("unit/{key}"),
                EffectKind::Publish,
                previous,
                pin,
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|_| "plan unit publication")?;
        let published = self
            .units
            .publish(
                next.contract.unit(),
                &next.contract.render(),
                previous,
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|_| "publish unit")?;
        if published != pin
            || self
                .units
                .observe(
                    next.contract.unit(),
                    driver.cancellation,
                    driver.deadline,
                )
                .map_err(|_| "read published unit")?
                != Some(pin)
        {
            return Err("published unit differs");
        }
        driver
            .journal
            .record_observed(
                driver.operation,
                &effect,
                pin,
                None,
                driver.cancellation,
                driver.deadline,
            )
            .map_err(|_| "record unit publication")
    }
}

fn observed(outcome: EffectOutcome) -> Result<()> {
    // Keep the identities distinct: effect is journal evidence, loaded contains
    // semantic manager fingerprints, neither is a unit-file or binding digest.
    let EffectOutcome {
        effect: _effect,
        state,
        loaded: _loaded,
    } = outcome;
    match state {
        EffectStatus::Observed {
            ..
        } => Ok(()),
        EffectStatus::Uncertain {
            stage,
            ..
        } => Err(stage),
    }
}
pub(super) fn invocation_bytes(text: &str) -> Result<[u8; 16]> {
    let mut bytes = [0; 16];
    if text.len() != 32
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid owned invocation");
    }
    for (index, value) in bytes.iter_mut().enumerate() {
        *value = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid owned invocation")?;
    }
    if bytes == [0; 16] {
        return Err("empty owned invocation");
    }
    Ok(bytes)
}

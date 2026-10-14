use super::*;
use crate::deployment::os::activation::{ActivationSnapshot, EffectState};

impl<M: Manager> ApplyManager<'_, M> {
    fn recovery_effect(
        &mut self,
        effect: &str,
        resource: &str,
        kind: EffectKind,
        target: ContentDigest,
    ) -> Result<ActivationSnapshot> {
        let budget = Budget {
            cancellation: self.cancellation,
            deadline: self.deadline,
        };
        budget.remaining()?;
        let state = self
            .journal
            .snapshot(self.cancellation, self.deadline)
            .map_err(|source| ApplyManagerError::caused_by("read recovery journal", source))?;
        let operation = state
            .operations
            .get(self.operation)
            .ok_or(ApplyManagerError::new(
                "unknown recovery operation",
            ))?;
        let recorded = operation
            .effects
            .get(effect)
            .ok_or(ApplyManagerError::new("unknown recovery effect"))?;
        if &operation.epoch != self.epoch
            || recorded.resource != resource
            || recorded.kind != kind
            || recorded.target != target.to_string()
            || matches!(recorded.state, EffectState::Observed { .. })
        {
            return Err(ApplyManagerError::new(
                "recovery intent differs or is already observed",
            ));
        }
        self.manager.epoch(self.epoch, &budget)?;
        Ok(state)
    }
    /// Present active/notify state and this worker's gate establish exec evidence;
    /// this never invents the completion of a previously lost start job.
    pub(in crate::deployment::os::apply) fn reconcile_start(
        &mut self,
        effect: &str,
        resource: &str,
        binding: &OsLaunchBinding,
        contract: &OsUnitContract,
    ) -> Result<EffectOutcome> {
        let target = binding
            .digest()
            .map_err(|source| ApplyManagerError::caused_by("invalid recovery binding", source))?;
        self.recovery_effect(effect, resource, EffectKind::Start, target)?;
        let result = (|| {
            let budget = Budget {
                cancellation: self.cancellation,
                deadline: self.deadline,
            };
            let status = self
                .manager
                .query(&binding.unit(), &budget)?
                .ok_or(ApplyManagerError::new(
                    "recovery start unit absent",
                ))?;
            let invocation: [u8; 16] =
                status
                    .invocation
                    .as_slice()
                    .try_into()
                    .map_err(|source| {
                        ApplyManagerError::caused_by("invalid recovery invocation", source)
                    })?;
            let loaded = self
                .running_evidence(resource, binding, contract, &invocation)?
                .ok_or(ApplyManagerError::new(
                    "recovery start is not running",
                ))?;
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
                .map_err(|source| {
                    ApplyManagerError::caused_by("revalidate recovery gate", source)
                })?
            {
                return Err(ApplyManagerError::new(
                    "recovery gate authority changed",
                ));
            }
            Ok((Some(text), vec![(binding.unit(), loaded)]))
        })();
        Ok(self.finish(effect.into(), target, result))
    }
    /// The supplied invocation must already belong to this revoked binding in
    /// the journal. Its accepted job must also have left the manager job table.
    /// An absent unit alone cannot exclude a queued stop, nor prove settlement.
    pub(in crate::deployment::os::apply) fn reconcile_stop(
        &mut self,
        effect: &str,
        resource: &str,
        unit: &SystemdUnitName,
        expected_invocation: &[u8; 16],
        target: ContentDigest,
    ) -> Result<EffectOutcome> {
        let state = self.recovery_effect(effect, resource, EffectKind::Stop, target)?;
        let binding = state
            .bindings
            .get(resource)
            .ok_or(ApplyManagerError::new("missing stopped binding"))?;
        if binding.authorized
            || binding.pin != target.to_string()
            || binding.unit != unit.as_str()
            || &binding.epoch != self.epoch
        {
            return Err(ApplyManagerError::new(
                "stop recovery binding is not revoked or differs",
            ));
        }
        let text = invocation_hex(expected_invocation);
        if self
            .journal
            .observed_invocation(resource, target, self.cancellation, self.deadline)
            .map_err(|source| ApplyManagerError::caused_by("read owned stop invocation", source))?
            .as_deref()
            != Some(text.as_str())
        {
            return Err(ApplyManagerError::new(
                "stop recovery invocation is not owned",
            ));
        }
        let result = (|| {
            let budget = Budget {
                cancellation: self.cancellation,
                deadline: self.deadline,
            };
            let EffectState::Accepted {
                job,
            } = &state.operations[self.operation].effects[effect].state
            else {
                return Err(ApplyManagerError::new(
                    "stop acceptance has no recorded job",
                ));
            };
            if !self.manager.recorded_job_absent(job, &budget)? {
                return Err(ApplyManagerError::new(
                    "recorded stop job remains pending",
                ));
            }
            let status = self.manager.query(unit, &budget)?;
            if let Some(status) = &status
                && (&status.unit != unit
                    || status.invocation != expected_invocation
                    || !matches!(
                        status.active_state.as_str(),
                        "inactive" | "failed"
                    ))
            {
                return Err(ApplyManagerError::new(
                    "stop recovery invocation conflicts or remains active",
                ));
            }
            self.manager.epoch(self.epoch, &budget)?;
            Ok((status.map(|_| text), Vec::new()))
        })();
        Ok(self.finish(effect.into(), target, result))
    }
    /// Observe the complete desired batch. This confirms loaded contracts, not a
    /// reply to the earlier Reload method, and does not invoke Reload again.
    pub(in crate::deployment::os::apply) fn reconcile_reload(
        &mut self,
        effect: &str,
        resource: &str,
        target: ContentDigest,
        contracts: &[&OsUnitContract],
    ) -> Result<EffectOutcome> {
        if contracts.is_empty() || contracts.len() > 1024 || reload_target(contracts) != target {
            return Err(ApplyManagerError::new(
                "invalid recovery reload batch",
            ));
        }
        let mut units = std::collections::BTreeSet::new();
        if contracts
            .iter()
            .any(|contract| !units.insert(contract.unit()))
        {
            return Err(ApplyManagerError::new(
                "duplicate recovery reload unit",
            ));
        }
        self.recovery_effect(effect, resource, EffectKind::Reload, target)?;
        let result = (|| {
            let budget = Budget {
                cancellation: self.cancellation,
                deadline: self.deadline,
            };
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
        Ok(self.finish(effect.into(), target, result))
    }
}

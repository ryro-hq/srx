use super::{
    ActivationSnapshot, ManagerChange, ResourceExecution, Result, StopState, epoch_key, invalid,
    validate_epochs,
};
use std::collections::BTreeSet;

pub(in crate::deployment::os::activation) fn validate(state: &ActivationSnapshot) -> Result<()> {
    if state.manager_changes.len() > super::super::record::MAX_OPERATIONS {
        return Err(invalid("manager transition registry exhausted"));
    }
    for (key, change) in &state.manager_changes {
        validate_epochs(&change.previous, &change.current)?;
        if key != &epoch_key(&change.previous)?
            || !state
                .operations
                .get(&change.operation)
                .is_some_and(|op| op.epoch == change.previous)
        {
            return Err(invalid("invalid manager transition identity"));
        }
        let expected: BTreeSet<_> = state
            .attempts
            .iter()
            .filter(|(_, attempt)| attempt.epoch == change.previous)
            .map(|(id, _)| id.clone())
            .collect();
        if change.settled
            && (change.attempts.iter().any(|id| {
                state
                    .attempts
                    .get(id)
                    .is_none_or(|attempt| attempt.namespace.is_none())
            }) || change.resources.keys().any(|name| {
                state
                    .changed_execution(key, name)
                    .is_ok_and(|class| class == ResourceExecution::Incomplete)
            }) || (change.resources.is_empty() && !state.changed_epoch_never_started(key)))
        {
            return Err(invalid(
                "settled manager transition lacks complete execution inventory",
            ));
        }
        if change.attempts != expected
            || change.resources.len() > super::super::record::MAX_RESOURCES
        {
            return Err(invalid("manager transition inventory changed"));
        }
        if state
            .bindings
            .values()
            .any(|binding| binding.epoch == change.previous && binding.authorized)
        {
            return Err(invalid("changed manager retains authorization"));
        }
        if state.bindings.iter().any(|(name, binding)| {
            binding.epoch == change.previous && !change.resources.contains_key(name)
        }) || change.attempts.iter().any(|id| {
            !change
                .resources
                .contains_key(&state.attempts[id].resource)
        }) {
            return Err(invalid("manager transition omits old resource"));
        }
        validate_resources(state, change)?;
    }
    Ok(())
}

fn validate_resources(state: &ActivationSnapshot, change: &ManagerChange) -> Result<()> {
    let mut units = BTreeSet::new();
    for (name, resource) in &change.resources {
        if !units.insert(&resource.binding.unit) {
            return Err(invalid("duplicate historical unit"));
        }
        super::super::record::text(name, 272)?;
        for pin in [
            &resource.binding.generation,
            &resource.binding.pin,
            &resource.binding.publication,
        ] {
            super::super::record::digest(pin)?;
        }
        super::super::record::check_id(&resource.binding.authorization)?;
        crate::systemd::SystemdUnitName::new(&resource.binding.unit)
            .map_err(|_| invalid("invalid historical unit"))?;
        if resource.binding.pin != resource.binding.publication
                || !state.operations.values().any(|op| op.epoch == change.previous
                    && op.candidate == resource.binding.generation
                    && op.effects.values().any(|effect| effect.resource == *name
                        && effect.kind == super::super::EffectKind::Publish
                        && matches!(&effect.state, super::super::EffectState::Observed { fingerprint, .. } if fingerprint == &resource.binding.publication))) {
                return Err(invalid("historical binding lacks confirmed publication"));
            }
        if let Some(current) = state
            .bindings
            .get(name)
            .filter(|binding| binding.epoch == change.previous)
            && (current.pin != resource.binding.pin
                || current.authorization != resource.binding.authorization
                || current.unit != resource.binding.unit
                || current.generation != resource.binding.generation)
        {
            return Err(invalid(
                "historical binding differs from current old-epoch binding",
            ));
        }
        if resource.binding.authorized || resource.binding.epoch != change.previous {
            return Err(invalid("invalid revoked binding"));
        }
        let expected = super::super::admitted_invocations(state, name, &change.previous)?;
        if resource.invocations != expected {
            return Err(invalid("historical invocation inventory differs"));
        }
        if let Some(selected) = resource.stop.invocation()
            && !resource.invocations.contains_key(selected)
        {
            return Err(invalid("stop phase lacks admitted invocation"));
        }
        if let StopState::Accepted {
            job,
            ..
        } = &resource.stop
            && !crate::systemd::valid_job_path(job)
        {
            return Err(invalid("invalid recovery stop job"));
        }
    }
    Ok(())
}

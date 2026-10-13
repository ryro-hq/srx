//! Fechamento dos serviços antes de liberar os outputs retidos.
//!
//! Primeiro encerra a admissão e registra `Closing`. Depois reconecta ao manager
//! e confere o epoch original antes de emitir Stop ou observar settlement.
//! A reconexão não repete mutações; saídas e retenção continuam sendo conferidas
//! independentemente.

use super::{Pump, Role};
use crate::execution::launcher::service_coordinator::{
    ServiceError, remaining, same_invocation, stop_bound,
};
use crate::{cancellation::Cancellation, systemd::SystemdManager};
use std::time::{Duration, Instant};

impl Pump {
    pub(super) fn resume_settlement_manager(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        // Joining admission cancels its in-flight read and may poison the bus.
        // Reconnect explicitly before any new Stop; old jobs/references cannot
        // be adopted. The original epoch and process proofs remain authoritative.
        self.manager
            .reconnect(remaining(deadline)?, cancel)?;
        if self
            .manager
            .observe_identity(remaining(deadline)?, cancel)?
            != self.epoch
        {
            return Err(ServiceError::State(
                "service manager epoch changed during settlement",
            ));
        }
        Ok(())
    }

    pub(super) fn close(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        let mut failure = None;
        for role in &self.roles {
            let result = role
                .observed
                .as_ref()
                .ok_or(ServiceError::State(
                    "service Start binding is uncertain",
                ))
                .and_then(|binding| stop_bound(&mut self.manager, binding, cancel, deadline));
            if let Err(error) = result
                && failure.is_none()
            {
                failure = Some(error);
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        self.settle(cancel, deadline)
    }
    pub(super) fn settle(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        if self
            .manager
            .observe_identity(remaining(deadline)?, cancel)?
            != self.epoch
        {
            return Err(ServiceError::State(
                "service manager epoch changed during settlement",
            ));
        }
        for role in &mut self.roles {
            if role.retirement_uncertain {
                return Err(ServiceError::State(
                    "role retention retirement requires recovery",
                ));
            }
            if role.uncertain {
                return Err(ServiceError::State(
                    "partial service attempt lacks complete settlement evidence",
                ));
            }
            loop {
                let mut exited = true;
                for attempt in &role.history {
                    exited &= super::admission::settled(attempt)?.is_some();
                }
                if exited {
                    break;
                }
                cancel
                    .check()
                    .map_err(|_| ServiceError::State("service group close cancelled"))?;
                std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(10)));
            }
            idle(&mut self.manager, role, cancel, deadline)?;
        }
        if self
            .manager
            .observe_identity(remaining(deadline)?, cancel)?
            != self.epoch
        {
            return Err(ServiceError::State(
                "service manager epoch changed during settlement",
            ));
        }
        // All roles were verified before any interest is retired. Cancellation
        // may leave a subset of already safe holds for later explicit recovery.
        for role in &mut self.roles {
            role.listener.close()?;
            let proofs = role
                .history
                .iter()
                .map(|attempt| {
                    super::admission::settled(attempt)?.ok_or(ServiceError::State(
                        "service settlement evidence unavailable during retirement",
                    ))
                })
                .collect::<Result<Vec<_>, ServiceError>>()?;
            if let Some(hold) = role.hold.take() {
                role.retirement_uncertain = true;
                self.journal.retire_role_retention(
                    &role.binding,
                    &proofs,
                    hold,
                    cancel,
                    deadline,
                )?;
                role.retirement_uncertain = false;
            }
        }
        Ok(())
    }
}
fn idle(
    manager: &mut SystemdManager,
    role: &Role,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<(), ServiceError> {
    let status = manager.query(role.binding.unit(), remaining(deadline)?, cancel)?;
    if let Some(status) = status {
        let binding = role.observed.as_ref().ok_or(ServiceError::State(
            "service has no authenticated invocation",
        ))?;
        same_invocation(&status, binding)?;
        if status.main_pid != 0
            || !matches!(
                status.active_state.as_str(),
                "inactive" | "failed"
            )
        {
            return Err(ServiceError::State("service unit not inactive"));
        }
        let store = manager
            .query_fd_store(role.binding.unit(), remaining(deadline)?, cancel)?
            .ok_or(ServiceError::State(
                "service disappeared during settlement observation",
            ))?;
        if store.invocation != binding.invocation() || store.count != 0 {
            return Err(ServiceError::State("service FD store not empty"));
        }
        if !manager.unit_idle_without_job(role.binding.unit(), remaining(deadline)?, cancel)? {
            return Err(ServiceError::State(
                "service unit has outstanding job",
            ));
        }
    }
    // Absence is only one component: full pinned launcher/init exit evidence was
    // required above, plus durable Closing and an observed Stop/owner Stop.
    Ok(())
}

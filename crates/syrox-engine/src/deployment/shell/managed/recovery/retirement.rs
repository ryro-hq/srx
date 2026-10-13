use super::retention::{RoleRetentionRecovery, RoleRetentionRecoveryOutcome};
use crate::execution::journal::roles::RoleSnapshot;
use crate::execution::journal::roles::retention::RoleRetentionPhase;
use crate::execution::journal::{AttemptPhase, SessionJournal, SessionPhase, SessionSnapshot};
use crate::execution::launcher::service_coordinator::settlement::{
    ObservedServiceAttemptSettlement, observe_recorded_processes,
};
use crate::{
    cancellation::Cancellation, store::ContentDigest, store::Store, systemd::SystemdManager,
    systemd::SystemdScope,
};
use std::path::Path;
use std::time::{Duration, Instant};

pub(super) struct Recovery<'a> {
    pub journal: &'a SessionJournal,
    pub snapshot: &'a SessionSnapshot,
    pub bus: &'a Path,
    pub store: &'a Path,
    pub cancel: &'a Cancellation,
    pub deadline: Instant,
}
impl Recovery<'_> {
    pub(super) fn retire(&self, rows: &mut [RoleRetentionRecovery]) {
        for (role, row) in self.snapshot.roles.iter().zip(rows) {
            if row.outcome != RoleRetentionRecoveryOutcome::Verified {
                continue;
            }
            row.outcome = match self.retire_one(role) {
                Ok(()) => RoleRetentionRecoveryOutcome::Retired,
                Err(message) => RoleRetentionRecoveryOutcome::Pending {
                    message: message
                        .chars()
                        .take(super::MAX_DIAGNOSTIC_CHARACTERS)
                        .collect(),
                },
            };
        }
    }

    fn retire_one(&self, role: &RoleSnapshot) -> Result<(), String> {
        if self.snapshot.phase != SessionPhase::Closing
            || role.authorized
            || role.retention.phase != RoleRetentionPhase::Retained
        {
            return Err("role retention requires further journal reconciliation".into());
        }
        let (proofs, epoch) = self.proofs(role)?;
        self.idle(role, epoch)?;
        self.budget()?;
        let identity = role
            .retention
            .identity
            .as_ref()
            .ok_or("missing retention identity")?;
        let store = Store::open_existing(self.store).map_err(|error| error.to_string())?;
        let hold = store
            .reopen_durable_interest_checked(
                identity.first.as_str(),
                identity.pin,
                identity.store_anchor,
                || {
                    self.budget()
                        .map(|_| ())
                        .map_err(std::io::Error::other)
                },
            )
            .map_err(|error| error.to_string())?;
        // The journal rechecks Closing and the exact full inventory under its
        // authority lock, then records Retiring before consuming this hold.
        self.journal
            .retire_role_retention(
                &role.binding,
                &proofs,
                hold,
                self.cancel,
                self.deadline,
            )
            .map_err(|error| error.to_string())
    }

    fn proofs(
        &self,
        role: &RoleSnapshot,
    ) -> Result<
        (
            Vec<ObservedServiceAttemptSettlement>,
            ContentDigest,
        ),
        String,
    > {
        let mut proofs = Vec::new();
        let mut epoch = None;
        for attempt in self
            .snapshot
            .attempts
            .iter()
            .filter(|attempt| attempt.role == role.binding.name())
        {
            self.budget()?;
            if !matches!(
                attempt.phase,
                AttemptPhase::Consumed | AttemptPhase::Settled
            ) {
                return Err("service attempt has incomplete admission evidence".into());
            }
            let binding = attempt
                .binding
                .as_ref()
                .ok_or("service attempt has no binding")?;
            let records = attempt
                .service_processes
                .as_ref()
                .ok_or("service process inventory missing")?;
            if !records.gate_used || records.namespace.is_none() {
                return Err("service namespace handoff remains incomplete".into());
            }
            if epoch.is_some_and(|value| value != records.manager) {
                return Err("service history spans different manager epochs".into());
            }
            epoch = Some(records.manager);
            let proof = observe_recorded_processes(
                &role.binding,
                &attempt.id,
                binding,
                records,
                self.cancel,
                self.deadline,
            )
            .map_err(|error| error.to_string())?
            .ok_or("service launcher or namespace has not settled")?;
            proofs.push(proof);
        }
        Ok((proofs, epoch.ok_or("service history is empty")?))
    }

    fn idle(&self, role: &RoleSnapshot, epoch: ContentDigest) -> Result<(), String> {
        let head = self
            .snapshot
            .attempts
            .iter()
            .find(|attempt| attempt.id == role.head)
            .and_then(|attempt| attempt.binding.as_ref())
            .ok_or("service head binding missing")?;
        let mut manager = SystemdManager::connect(
            SystemdScope::User {
                bus_socket: self.bus.into(),
            },
            self.budget()?,
            self.cancel,
        )
        .map_err(|error| error.to_string())?;
        if manager
            .observe_identity(self.budget()?, self.cancel)
            .map_err(|error| error.to_string())?
            .fingerprint()
            != epoch
        {
            return Err("service manager epoch changed; retention preserved".into());
        }
        let before = manager
            .query(role.binding.unit(), self.budget()?, self.cancel)
            .map_err(|error| error.to_string())?;
        if let Some(status) = &before {
            if status.unit != *head.unit()
                || status.invocation != head.invocation()
                || status.main_pid != 0
                || !matches!(
                    status.active_state.as_str(),
                    "inactive" | "failed"
                )
            {
                return Err(
                    "service invocation remains active or differs from journal head".into(),
                );
            }
            let retained = manager
                .query_fd_store(role.binding.unit(), self.budget()?, self.cancel)
                .map_err(|error| error.to_string())?
                .ok_or("service disappeared during FD store observation")?;
            if retained.invocation != head.invocation() || retained.count != 0 {
                return Err("service FD store remains retained or differs".into());
            }
            if !manager
                .unit_idle_without_job(role.binding.unit(), self.budget()?, self.cancel)
                .map_err(|error| error.to_string())?
            {
                return Err("service has an outstanding manager job".into());
            }
        }
        let after = manager
            .query(role.binding.unit(), self.budget()?, self.cancel)
            .map_err(|error| error.to_string())?;
        if before != after
            || manager
                .observe_identity(self.budget()?, self.cancel)
                .map_err(|error| error.to_string())?
                .fingerprint()
                != epoch
        {
            return Err("service or manager changed during retirement observation".into());
        }
        // Absence alone never reaches here: complete kernel exit proofs for all
        // historical launchers and namespace inits were required first.
        Ok(())
    }
    fn budget(&self) -> Result<Duration, String> {
        if self.cancel.is_cancelled() {
            return Err("retention recovery cancelled".into());
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .map(|duration| duration.min(super::CALL_BUDGET))
            .ok_or_else(|| "retention recovery deadline expired".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::journal::roles::retention::{
        RoleRetentionIdentity, RoleRetentionSnapshot,
    };
    use crate::execution::journal::{AttemptBinding, AttemptId, AttemptSnapshot, RoleBinding};
    use crate::{execution::restart::ProcessRestart, systemd::SystemdUnitName};

    #[test]
    fn incomplete_history_cannot_reach_manager_or_retire_verified_retention() {
        let (root, journal, session) = super::super::tests::fixture();
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut snapshot = journal
            .begin_closing(&session, "recovery fixture", &cancel, deadline)
            .unwrap();
        let first = AttemptId::parse(&"1".repeat(32)).unwrap();
        let pin = ContentDigest::sha256(b"comparison data, not admission");
        let role = RoleSnapshot {
            binding: RoleBinding::new(
                session,
                "service:probe:main",
                snapshot.pin,
                pin,
                SystemdUnitName::new("syrox-probe.service").unwrap(),
                AttemptBinding::new(
                    SystemdUnitName::new("syrox-owner.service").unwrap(),
                    [2; 16],
                )
                .unwrap(),
                ProcessRestart::Never,
            )
            .unwrap(),
            head: first.clone(),
            authorized: false,
            retention: RoleRetentionSnapshot {
                phase: RoleRetentionPhase::Retained,
                identity: Some(RoleRetentionIdentity::new(
                    first.clone(),
                    pin,
                    pin,
                )),
            },
        };
        // These incomplete comparison snapshots must fail before using either path.
        // No fixture constructs an exit proof or authorizes journal retirement.
        let bus = root.path().join("missing-bus");
        let store = root.path().join("missing-store");
        let verify = |snapshot: &SessionSnapshot, expected: &str| {
            let mut rows = [RoleRetentionRecovery {
                role: role.binding.name().into(),
                first_attempt: Some(first.to_string()),
                phase: "retained",
                outcome: RoleRetentionRecoveryOutcome::Verified,
            }];
            Recovery {
                journal: &journal,
                snapshot,
                bus: &bus,
                store: &store,
                cancel: &cancel,
                deadline,
            }
            .retire(&mut rows);
            assert!(
                matches!(&rows[0].outcome, RoleRetentionRecoveryOutcome::Pending { message } if message.contains(expected))
            );
            assert!(!store.exists());
            assert!(!bus.exists());
        };
        snapshot.roles.push(role.clone());
        verify(&snapshot, "history is empty");
        snapshot.attempts.push(AttemptSnapshot {
            id: first.clone(),
            role: role.binding.name().into(),
            phase: AttemptPhase::Consumed,
            binding: Some(AttemptBinding::new(role.binding.unit().clone(), [3; 16]).unwrap()),
            service_processes: None,
        });
        verify(&snapshot, "process inventory missing");
        snapshot.attempts[0].phase = AttemptPhase::Revoked;
        verify(&snapshot, "incomplete admission");
        for phase in [
            RoleRetentionPhase::Intent,
            RoleRetentionPhase::Retiring,
        ] {
            snapshot.roles[0].retention.phase = phase;
            verify(&snapshot, "further journal reconciliation");
        }
    }
}

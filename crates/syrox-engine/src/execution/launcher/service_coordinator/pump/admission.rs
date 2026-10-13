use super::{Attempt, Pump};
use crate::execution::journal::{AttemptBinding, SessionPhase};
use crate::execution::launcher::service::{DENIED, ServiceLaunchHello};
use crate::execution::launcher::service_coordinator::{
    Admission, ServiceError, admit_attempt, observe_main, remaining, settlement,
};
use crate::execution::transport::PacketChannel;
use crate::{cancellation::Cancellation, execution::restart::ProcessRestart};
use std::os::fd::AsFd as _;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

impl Pump {
    pub(super) fn start_initial(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        for index in 0..self.roles.len() {
            let end = deadline.min(Instant::now() + Duration::from_secs(30));
            // Before Start, an uncertain reply already requires conservative retention.
            self.roles[index].uncertain = true;
            let job = self.manager.start_transient(
                &self.roles[index].service,
                remaining(end)?,
                cancel,
            )?;
            let channel = self.roles[index].listener.accept(end, cancel)?;
            self.accept(index, channel, cancel, end)?;
            super::super::completed(
                &self
                    .manager
                    .wait_job(&job, remaining(end)?, cancel)?,
            )?;
        }
        Ok(())
    }
    pub(super) fn run(&mut self, cancel: &Cancellation) -> Result<(), ServiceError> {
        while !cancel.is_cancelled() {
            let end = Instant::now() + Duration::from_secs(2);
            let snapshot = self
                .journal
                .snapshot(&self.owner.session, cancel, end)?;
            if snapshot.phase == SessionPhase::Closing {
                return Ok(());
            }
            settlement::observe_live_owner(&self.owner, &mut self.manager, cancel, end)?;
            if self
                .manager
                .observe_identity(remaining(end)?, cancel)?
                != self.epoch
            {
                return Err(ServiceError::State(
                    "service manager epoch changed",
                ));
            }
            self.observe_roles(&snapshot, cancel, end)?;
            for index in 0..self.roles.len() {
                if let Some(channel) = self.roles[index].listener.try_accept()? {
                    self.accept(
                        index,
                        channel,
                        cancel,
                        Instant::now() + Duration::from_secs(30),
                    )?;
                }
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Ok(())
    }
    fn observe_roles(
        &mut self,
        snapshot: &crate::execution::journal::SessionSnapshot,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        for role in &mut self.roles {
            let current = snapshot
                .roles
                .iter()
                .find(|entry| entry.binding == role.binding && entry.authorized)
                .ok_or(ServiceError::State(
                    "service role authority differs",
                ))?;
            let head = snapshot
                .attempts
                .iter()
                .find(|attempt| attempt.id == current.head)
                .ok_or(ServiceError::State("service role head missing"))?;
            let status = self
                .manager
                .query(role.binding.unit(), remaining(deadline)?, cancel)?
                .ok_or(ServiceError::State("service role unit vanished"))?;
            role.pending
                .observe(&role.binding, head, &status, Instant::now())?;
        }
        Ok(())
    }
    fn accept(
        &mut self,
        index: usize,
        channel: PacketChannel,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        let peer = channel.peer_credentials()?;
        let launcher = crate::platform::linux::fd::pidfd_open(peer.pid)?;
        settlement::require_live(launcher.as_fd())?;
        let role = &mut self.roles[index];
        let status = observe_main(
            &mut self.manager,
            role.binding.unit(),
            peer,
            None,
            cancel,
            deadline,
        )?;
        let invocation = status
            .invocation
            .try_into()
            .map_err(|_| ServiceError::State("service invocation missing"))?;
        let binding = AttemptBinding::new(role.binding.unit().clone(), invocation)?;
        let hello = ServiceLaunchHello::parse(&channel.receive(peer, 0, deadline, cancel)?.bytes)?;
        let expected = ServiceLaunchHello {
            session: self.owner.session.clone(),
            role: role.binding.digest(),
            generation: role.binding.manifest(),
            command: role.binding.command(),
            binding: binding.clone(),
            owner: self.owner.binding.clone(),
        };
        if hello != expected {
            return Err(ServiceError::State(
                "service hello differs from pinned role",
            ));
        }
        if self
            .manager
            .observe_identity(remaining(deadline)?, cancel)?
            != self.epoch
        {
            return Err(ServiceError::State(
                "service manager epoch changed",
            ));
        }
        let attempt = prepare_attempt(
            &self.journal,
            &self.owner,
            &mut self.manager,
            role,
            &channel,
            cancel,
            deadline,
        )?;
        role.observed = Some(binding.clone());
        role.uncertain = true;
        self.authority
            .state
            .uncertain
            .store(true, Ordering::Release);
        let prepared = role.resources.prepare_attempt(cancel)?;
        let evidence = admit_attempt(
            Admission {
                owner: &self.owner,
                epoch: &self.epoch,
                role: &role.binding,
                service: &role.service,
                prepared: &prepared,
                attempt,
                binding,
                launcher,
                channel,
            },
            &self.journal,
            &mut self.manager,
            cancel,
            deadline,
        )?;
        self.authority
            .state
            .processes
            .lock()
            .map_err(|_| ServiceError::State("service process inventory poisoned"))?
            .push((
                evidence.launcher.try_clone()?,
                evidence.namespace.try_clone()?,
            ));
        role.history.push(Attempt {
            evidence,
            _retention: prepared.retention,
        });
        role.uncertain = false;
        let uncertain = self
            .roles
            .iter()
            .any(|role| role.uncertain || role.history.is_empty());
        self.authority
            .state
            .uncertain
            .store(uncertain, Ordering::Release);
        Ok(())
    }
}
pub(super) fn settled(
    attempt: &Attempt,
) -> Result<Option<settlement::ObservedServiceAttemptSettlement>, ServiceError> {
    Ok(settlement::observe_processes(
        &attempt.evidence.processes,
    )?)
}

fn prepare_attempt(
    journal: &crate::execution::journal::SessionJournal,
    owner: &super::ServiceOwner,
    manager: &mut crate::systemd::SystemdManager,
    role: &super::Role,
    channel: &PacketChannel,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<crate::execution::journal::AttemptId, ServiceError> {
    let Some(previous) = role.history.last() else {
        return Ok(role.first.clone());
    };
    if role.binding.restart() == ProcessRestart::Never {
        journal.with_forbidden_successor(
            &role.binding,
            &previous.evidence.attempt,
            cancel,
            deadline,
            || channel.send(DENIED, &[], deadline, cancel),
        )?;
        return Err(ServiceError::State(
            "service role prohibits a successor",
        ));
    }
    let proof = loop {
        if let Some(proof) = settled(previous)? {
            break proof;
        }
        cancel
            .check()
            .map_err(|_| ServiceError::State("service predecessor wait cancelled"))?;
        std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(10)));
    };
    let owner = settlement::observe_live_owner(owner, manager, cancel, deadline)?;
    Ok(journal.prepare_successor(&role.binding, &proof, &owner, cancel, deadline)?)
}

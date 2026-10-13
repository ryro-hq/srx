//! Admissão dos serviços enquanto o comando foreground está em andamento.
//!
//! Os restarts ficam com o systemd. Se o pump for perdido, o interesse durável
//! na Store permanece, para que a recuperação possa conferir a execução antes
//! de soltar os recursos.

use super::{OwnerHandle, ServiceError, ServiceOwner};
use crate::execution::journal::{
    AttemptBinding, AttemptId, RoleBinding, SessionJournal, SessionPhase,
};
use crate::runtime::launch_preparation::{PreparedRuntimeLaunch, ReusableRuntimeLaunch};
use crate::{
    cancellation::Cancellation, execution::restart::ProcessRestart, systemd::SystemdJobCompletion,
    systemd::SystemdManager, systemd::SystemdService,
};
#[cfg(test)]
use std::os::fd::AsFd as _;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

mod admission;
mod closing;
mod startup;

pub(crate) struct ServiceRoleStart {
    pub role: String,
    pub prepared: PreparedRuntimeLaunch,
    pub restart: ProcessRestart,
}
#[derive(Clone)]
pub(crate) struct ServiceAuthority {
    state: Arc<AuthorityState>,
}
struct AuthorityState {
    healthy: AtomicBool,
    uncertain: AtomicBool,
    processes: Mutex<Vec<(OwnedFd, OwnedFd)>>,
    roles: Vec<RoleBinding>,
}
impl ServiceAuthority {
    pub(crate) fn healthy(&self) -> bool {
        self.state.healthy.load(Ordering::Acquire)
    }
    pub(crate) fn roles(&self) -> &[RoleBinding] {
        &self.state.roles
    }
}
struct Role {
    binding: RoleBinding,
    first: AttemptId,
    listener: crate::execution::launcher::rendezvous::Listener,
    service: SystemdService,
    resources: ReusableRuntimeLaunch,
    hold: Option<crate::store::DurableInterest>,
    retirement_uncertain: bool,
    history: Vec<Attempt>,
    pending: super::ServicePending,
    // An uncertain admission is never omitted from closing by virtue of not
    // having returned a complete namespace handle.
    uncertain: bool,
    observed: Option<AttemptBinding>,
}
struct Attempt {
    evidence: super::ServiceAttempt,
    _retention: std::fs::File,
}
struct Pump {
    owner: Arc<ServiceOwner>,
    journal: Arc<SessionJournal>,
    manager: SystemdManager,
    epoch: crate::systemd::SystemdManagerIdentity,
    roles: Vec<Role>,
    authority: ServiceAuthority,
}
struct Finished {
    pump: Pump,
    error: Option<ServiceError>,
}
pub(crate) struct ServiceGroup {
    owner: Arc<ServiceOwner>,
    journal: Arc<SessionJournal>,
    authority: ServiceAuthority,
    stop: Cancellation,
    thread: Option<JoinHandle<Finished>>,
    finished: Option<Finished>,
}
impl ServiceGroup {
    pub(crate) fn start(
        owner: &OwnerHandle,
        roles: Vec<ServiceRoleStart>,
        private: &Path,
        journal: Arc<SessionJournal>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self, ServiceError> {
        let owner = Arc::new(ServiceOwner::capture(owner)?);
        let pump = startup::prepare(
            Arc::clone(&owner),
            Arc::clone(&journal),
            roles,
            private,
            cancel,
            deadline,
        )?;
        let authority = pump.authority.clone();
        let stop = Cancellation::default();
        let interrupt = stop.clone();
        let startup_cancel = cancel.clone();
        let (ready, waiting) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("syrox-service-admission".into())
            .spawn(move || {
                let _health = Health(pump.authority.clone());
                let mut pump = pump;
                let initial = pump.start_initial(&startup_cancel, deadline);
                let okay = initial.is_ok();
                let _ = ready.send(okay);
                let result = initial.and_then(|()| pump.run(&interrupt));
                if result.is_err() {
                    let cleanup = Cancellation::default();
                    let _ = pump.journal.begin_closing(
                        &pump.owner.session,
                        "service admission lost",
                        &cleanup,
                        Instant::now() + Duration::from_secs(5),
                    );
                }
                Finished {
                    pump,
                    error: result.err(),
                }
            })?;
        let mut group = Self {
            owner,
            journal,
            authority,
            stop,
            thread: Some(thread),
            finished: None,
        };
        loop {
            if cancel.is_cancelled() || Instant::now() >= deadline {
                group.stop.cancel();
                group.join()?;
                return Err(ServiceError::State(
                    "service group startup cancelled or expired",
                ));
            }
            match waiting.recv_timeout(Duration::from_millis(10)) {
                Ok(true) => return Ok(group),
                Ok(false) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    group.join()?;
                    return Err(group
                        .finished
                        .as_mut()
                        .and_then(|done| done.error.take())
                        .unwrap_or(ServiceError::State(
                            "service admission thread stopped",
                        )));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }
    pub(crate) fn authority(&self) -> ServiceAuthority {
        self.authority.clone()
    }
    #[cfg(test)]
    pub(crate) fn role_count(&self) -> usize {
        self.authority.roles().len()
    }
    #[cfg(test)]
    pub(crate) fn namespaces_settled(&self) -> bool {
        if self
            .authority
            .state
            .uncertain
            .load(Ordering::Acquire)
        {
            return false;
        }
        self.authority
            .state
            .processes
            .lock()
            .is_ok_and(|processes| {
                processes.iter().all(|(launcher, namespace)| {
                    crate::platform::linux::fd::pidfd_exited(launcher.as_fd()).unwrap_or(false)
                        && crate::platform::linux::fd::pidfd_exited(namespace.as_fd())
                            .unwrap_or(false)
                })
            })
    }
    fn join(&mut self) -> Result<(), ServiceError> {
        self.stop.cancel();
        if let Some(thread) = self.thread.take() {
            self.finished = Some(thread.join().map_err(|_| {
                ServiceError::State("service pump panicked; durable interests retained")
            })?);
        }
        Ok(())
    }
    fn require_closing(
        &self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        if self
            .journal
            .snapshot(&self.owner.session, cancel, deadline)?
            .phase
            != SessionPhase::Closing
        {
            return Err(ServiceError::State(
                "service group requires durable Closing",
            ));
        }
        Ok(())
    }
    pub(crate) fn close(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        self.require_closing(cancel, deadline)?;
        self.join()?;
        let pump = &mut self
            .finished
            .as_mut()
            .ok_or(ServiceError::State(
                "service evidence unavailable",
            ))?
            .pump;
        pump.resume_settlement_manager(cancel, deadline)?;
        pump.close(cancel, deadline)
    }
    pub(crate) fn settle_after_owner_stop(
        &mut self,
        owner: &OwnerHandle,
        completion: &SystemdJobCompletion,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        if owner.session != self.owner.session || owner.binding != self.owner.binding {
            return Err(ServiceError::State("service group owner differs"));
        }
        super::completed(completion)?;
        self.require_closing(cancel, deadline)?;
        self.join()?;
        let pump = &mut self
            .finished
            .as_mut()
            .ok_or(ServiceError::State(
                "service evidence unavailable",
            ))?
            .pump;
        pump.resume_settlement_manager(cancel, deadline)?;
        pump.settle(cancel, deadline)
    }
}
impl Drop for ServiceGroup {
    fn drop(&mut self) {
        // Never detach an admission thread. Every manager/IPC operation has a
        // cancellation token and deadline. No Drop retires durable interests.
        self.stop.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
struct Health(ServiceAuthority);
impl Drop for Health {
    fn drop(&mut self) {
        self.0
            .state
            .healthy
            .store(false, Ordering::Release);
    }
}

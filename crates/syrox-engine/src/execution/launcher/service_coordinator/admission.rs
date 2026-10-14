use super::settlement::CapturedServiceLauncher;
use super::{
    ServiceAttempt, ServiceError, ServiceOwner, observe_main, observe_owner, remaining, settlement,
};
use crate::execution::journal::{AttemptBinding, AttemptId, RoleBinding, SessionJournal};
use crate::execution::launcher::service::{
    COMMIT, NAMESPACE, PROCESSED, ServiceAttemptChallenge, ServiceLaunchHello, ServiceLaunchRequest,
};
use crate::execution::resources::send_resources;
use crate::execution::transport::PacketChannel;
use crate::runtime::launch_preparation::PreparedRuntimeLaunch;
use crate::{
    cancellation::Cancellation, systemd::SystemdManager, systemd::SystemdManagerIdentity,
    systemd::SystemdService,
};
use std::os::fd::{AsFd, OwnedFd};
use std::time::Instant;

pub(super) struct Admission<'a> {
    pub owner: &'a ServiceOwner,
    pub epoch: &'a SystemdManagerIdentity,
    pub role: &'a RoleBinding,
    pub service: &'a SystemdService,
    pub prepared: &'a PreparedRuntimeLaunch,
    pub attempt: AttemptId,
    pub binding: AttemptBinding,
    pub launcher: OwnedFd,
    pub channel: PacketChannel,
}
pub(super) fn admit_attempt(
    admission: Admission<'_>,
    journal: &SessionJournal,
    manager: &mut SystemdManager,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<ServiceAttempt, ServiceError> {
    let peer = admission.channel.peer_credentials()?;
    let (captured_launcher, contract) = CapturedServiceLauncher::observe(
        &crate::execution::service_evidence::ServiceObservation {
            service: admission.service,
            role: admission.role,
            attempt: &admission.attempt,
            binding: &admission.binding,
            launcher: admission.launcher.as_fd(),
            peer,
            epoch: admission.epoch,
        },
        manager,
        cancel,
        deadline,
    )?;
    let owner = settlement::observe_live_owner(admission.owner, manager, cancel, deadline)?;
    admission.challenge(
        journal,
        &captured_launcher,
        &owner,
        cancel,
        deadline,
    )?;
    let namespace = admission.resources(cancel, deadline)?;
    let captured = captured_launcher
        .capture_namespace(namespace.as_fd(), cancel, deadline)
        .map_err(|source| ServiceError::AdmissionIo {
            stage: "namespace capture before COMMIT",
            source,
        })?;
    admission.observe_retention(manager, cancel, deadline)?;
    observe_owner(
        manager,
        &admission.owner.binding,
        cancel,
        deadline,
    )?;
    observe_main(
        manager,
        admission.role.unit(),
        peer,
        Some(&admission.binding),
        cancel,
        deadline,
    )?;
    settlement::require_live(admission.launcher.as_fd())?;
    captured
        .revalidate(cancel, deadline)
        .map_err(|source| ServiceError::AdmissionIo {
            stage: "process inventory revalidation before COMMIT",
            source,
        })?;
    let final_observation = manager.observe_service_unit(
        admission.service,
        admission.binding.unit(),
        admission.binding.invocation(),
        peer.pid,
        remaining(deadline)?,
        cancel,
    )?;
    if *captured.manager() != final_observation.manager || contract != final_observation.contract {
        return Err(ServiceError::State(
            "service manager or contract changed before gate",
        ));
    }
    journal.with_service_namespace_gate(&captured, &owner, cancel, deadline, || {
        owner
            .revalidate()
            .map_err(std::io::Error::other)?;
        if crate::platform::linux::fd::pidfd_exited(admission.launcher.as_fd())? {
            return Err(std::io::Error::other(
                "pinned service launcher exited",
            ));
        }
        admission
            .channel
            .send(COMMIT, &[], deadline, cancel)
    })?;
    Ok(ServiceAttempt {
        processes: captured,
        attempt: admission.attempt,
        namespace,
        launcher: admission.launcher,
    })
}
impl Admission<'_> {
    fn challenge(
        &self,
        journal: &SessionJournal,
        captured: &CapturedServiceLauncher,
        owner: &settlement::ObservedSessionOwnerAlive,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        journal.authorize_service_attempt(captured, owner, cancel, deadline)?;
        let challenge = ServiceAttemptChallenge {
            role: self.role.digest(),
            attempt: self.attempt.clone(),
            binding: self.binding.clone(),
        };
        self.channel
            .send(&challenge.encode()?, &[], deadline, cancel)?;
        let expected = ServiceLaunchHello {
            session: self.role.session().clone(),
            role: self.role.digest(),
            generation: self.role.manifest(),
            command: self.role.command(),
            binding: self.binding.clone(),
            owner: self.owner.binding.clone(),
        }
        .challenged(&challenge)?;
        let packet = self.channel.receive(
            self.channel.peer_credentials()?,
            0,
            deadline,
            cancel,
        )?;
        if ServiceLaunchRequest::parse(&packet.bytes)? != expected {
            return Err(ServiceError::State(
                "service admission echo differs",
            ));
        }
        owner.revalidate()?;
        settlement::require_live(self.launcher.as_fd())?;
        journal.consume_attempt(
            self.role.session(),
            &self.attempt,
            self.role.manifest(),
            &self.binding,
            cancel,
            deadline,
        )?;
        Ok(())
    }
    fn resources(&self, cancel: &Cancellation, deadline: Instant) -> Result<OwnedFd, ServiceError> {
        let descriptors = self
            .prepared
            .descriptors
            .iter()
            .map(AsFd::as_fd)
            .collect::<Vec<_>>();
        let peer = self.channel.peer_credentials()?;
        send_resources(
            &self.channel,
            &self.prepared.spec,
            &descriptors,
            self.prepared.retention.as_fd(),
            deadline,
            cancel,
        )?;
        if self
            .channel
            .receive(peer, 0, deadline, cancel)?
            .bytes
            != PROCESSED
        {
            return Err(ServiceError::State(
                "expected FD store barrier processing",
            ));
        }
        let packet = self.channel.receive(peer, 1, deadline, cancel)?;
        if packet.bytes != NAMESPACE {
            return Err(ServiceError::State("expected namespace handoff"));
        }
        let namespace = packet
            .descriptors
            .into_iter()
            .next()
            .expect("transport checks descriptor count");
        if crate::platform::linux::fd::pidfd_exited(namespace.as_fd())? {
            return Err(ServiceError::State(
                "namespace exited before commit",
            ));
        }
        Ok(namespace)
    }
    fn observe_retention(
        &self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        let observed = manager
            .query_fd_store(self.role.unit(), remaining(deadline)?, cancel)?
            .ok_or(ServiceError::State(
                "service vanished before FD store observation",
            ))?;
        if observed.invocation != self.binding.invocation()
            || observed.count != 1
            || observed.max != 1
            || observed.notify_access != "main"
        {
            return Err(ServiceError::State(
                "service FD store observation differs",
            ));
        }
        Ok(())
    }
}

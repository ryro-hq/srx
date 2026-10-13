use super::{
    AttemptBinding, AttemptId, EvidenceError as ServiceError, RoleBinding, ServiceObservation,
    remaining,
};
use crate::platform::linux::fd::persisted_namespace::{
    CapturedLauncher, CapturedNamespace, LauncherRecord, NamespaceRecord,
};
use crate::{
    cancellation::Cancellation, store::ContentDigest, systemd::SystemdManager,
    systemd::SystemdManagerIdentity,
};
use std::io;
use std::os::fd::BorrowedFd;
use std::time::Instant;

pub(crate) struct CapturedServiceLauncher {
    role: RoleBinding,
    attempt: AttemptId,
    binding: AttemptBinding,
    launcher: CapturedLauncher,
    manager: SystemdManagerIdentity,
}
pub(crate) struct CapturedServiceProcesses {
    launcher: CapturedServiceLauncher,
    namespace: CapturedNamespace,
}
impl CapturedServiceLauncher {
    #[cfg(test)]
    pub(crate) fn fixture(
        role: &RoleBinding,
        attempt: &AttemptId,
        binding: &AttemptBinding,
        launcher: BorrowedFd<'_>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Self> {
        Ok(Self {
            role: role.clone(),
            attempt: attempt.clone(),
            binding: binding.clone(),
            launcher: CapturedLauncher::capture_peer(launcher, cancel, deadline)?,
            manager: SystemdManagerIdentity::fixture(),
        })
    }

    pub(crate) fn observe(
        admission: &ServiceObservation<'_>,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(Self, ContentDigest), ServiceError> {
        let peer = admission.peer;
        let captured = CapturedLauncher::capture_peer(admission.launcher, cancel, deadline)?;
        let initial = manager.observe_service_unit(
            admission.service,
            admission.binding.unit(),
            admission.binding.invocation(),
            peer.pid,
            remaining(deadline)?,
            cancel,
        )?;
        if initial.manager != *admission.epoch
            || initial.status.main_pid != peer.pid
            || captured.pid() != peer.pid
        {
            return Err(ServiceError::State(
                "service peer or pinned manager epoch differs",
            ));
        }
        captured.revalidate(cancel, deadline)?;
        Ok((
            Self {
                role: admission.role.clone(),
                attempt: admission.attempt.clone(),
                binding: admission.binding.clone(),
                launcher: captured,
                manager: initial.manager,
            },
            initial.contract,
        ))
    }
    pub(crate) fn manager(&self) -> &SystemdManagerIdentity {
        &self.manager
    }
    pub(crate) fn role(&self) -> &RoleBinding {
        &self.role
    }
    pub(crate) fn attempt(&self) -> &AttemptId {
        &self.attempt
    }
    pub(crate) fn binding(&self) -> &AttemptBinding {
        &self.binding
    }
    pub(crate) fn launcher_record(&self) -> &LauncherRecord {
        self.launcher.record()
    }
    pub(crate) fn revalidate(&self, cancel: &Cancellation, deadline: Instant) -> io::Result<()> {
        self.launcher.revalidate(cancel, deadline)
    }
    pub(crate) fn capture_namespace(
        self,
        namespace: BorrowedFd<'_>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<CapturedServiceProcesses> {
        let namespace = self
            .launcher
            .capture_namespace(namespace, cancel, deadline)?;
        Ok(CapturedServiceProcesses {
            launcher: self,
            namespace,
        })
    }
}
impl CapturedServiceProcesses {
    pub(crate) fn exited(&self) -> io::Result<bool> {
        Ok(self.launcher.launcher.exited()? && self.namespace.exited()?)
    }

    pub(crate) fn manager(&self) -> &SystemdManagerIdentity {
        self.launcher.manager()
    }
    pub(crate) fn role(&self) -> &RoleBinding {
        self.launcher.role()
    }
    pub(crate) fn attempt(&self) -> &AttemptId {
        self.launcher.attempt()
    }
    pub(crate) fn binding(&self) -> &AttemptBinding {
        self.launcher.binding()
    }
    pub(crate) fn launcher_record(&self) -> &LauncherRecord {
        self.launcher.launcher_record()
    }
    pub(crate) fn namespace_record(&self) -> &NamespaceRecord {
        self.namespace.record()
    }
    pub(crate) fn revalidate(&self, cancel: &Cancellation, deadline: Instant) -> io::Result<()> {
        self.launcher.revalidate(cancel, deadline)?;
        self.namespace.revalidate(cancel, deadline)?;
        self.launcher.revalidate(cancel, deadline)
    }
}

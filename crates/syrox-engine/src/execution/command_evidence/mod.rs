//! Observação usada para confirmar o fechamento de um comando.
//!
//! EOF e saída do init não bastam para soltar a retenção. O guardian precisa
//! confirmar `ECHILD` no processo que adotou os descendentes, e o coordenador
//! espera a saída desse mesmo guardian antes de concluir o fechamento.

use std::io;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::execution::journal::{ExecutionId, SessionId};
use crate::execution::transport::{PacketChannel, Peer, budget};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardianIdentity {
    pub(crate) pid: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

pub(crate) struct ObservedCommandExecutionSettlement {
    session: SessionId,
    execution: ExecutionId,
    index: ContentDigest,
    retention: ContentDigest,
    guardian: GuardianIdentity,
}
impl ObservedCommandExecutionSettlement {
    pub(crate) fn session(&self) -> &SessionId {
        &self.session
    }
    pub(crate) fn execution(&self) -> &ExecutionId {
        &self.execution
    }
    pub(crate) fn index(&self) -> ContentDigest {
        self.index
    }
    pub(crate) fn retention(&self) -> ContentDigest {
        self.retention
    }
    pub(crate) fn guardian(&self) -> GuardianIdentity {
        self.guardian
    }
}

/// This is wire comparison data, not an observation or cleanup authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SettlementClaim {
    version: u32,
    sequence: u64,
    session: String,
    execution: String,
    index: String,
    retention: String,
    guardian: GuardianIdentity,
    descendants: String,
}
impl SettlementClaim {
    pub(crate) fn new(
        session: &SessionId,
        execution: &ExecutionId,
        index: ContentDigest,
        retention: ContentDigest,
        guardian: GuardianIdentity,
    ) -> io::Result<Self> {
        let claim = Self {
            version: 1,
            sequence: 1,
            session: session.to_string(),
            execution: execution.to_string(),
            index: index.to_string(),
            retention: retention.to_string(),
            guardian,
            descendants: "settled".into(),
        };
        claim.validate()?;
        Ok(claim)
    }
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        bytes.push(b'\n');
        if bytes.len() > 2048 {
            return Err(invalid());
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > 2048 {
            return Err(invalid());
        }
        let claim: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if claim.encode()? != bytes {
            return Err(invalid());
        }
        Ok(claim)
    }
    fn validate(&self) -> io::Result<()> {
        if self.version != 1
            || self.sequence != 1
            || self.descendants != "settled"
            || self.guardian.pid <= 1
            || self.guardian.uid == 0
            || self.guardian.uid == u32::MAX
            || self.guardian.gid == u32::MAX
            || self.guardian.device == 0
            || self.guardian.inode == 0
        {
            return Err(invalid());
        }
        SessionId::parse(&self.session).map_err(|_| invalid())?;
        ExecutionId::parse(&self.execution).map_err(|_| invalid())?;
        for pin in [&self.index, &self.retention] {
            let _: ContentDigest = pin.parse().map_err(|_| invalid())?;
        }
        Ok(())
    }
}

pub(crate) struct SettlementReceiver {
    channel: PacketChannel,
    peer: Peer,
    pidfd: OwnedFd,
    expected: SettlementClaim,
    introduction: Option<(introduction::ObservedCommandMonitor, Vec<u8>)>,
    introduced: bool,
    received: bool,
    finished: bool,
}
impl SettlementReceiver {
    /// `peer` identifies the coordinator's dedicated spawned guardian. Reopen
    /// that still-live PID and compare pidfs identity with the retained pidfd;
    /// a reused numeric PID or an unrelated descriptor cannot establish it.
    pub(crate) fn new(
        channel: PacketChannel,
        peer: Peer,
        pidfd: BorrowedFd<'_>,
        session: &SessionId,
        execution: &ExecutionId,
        index: ContentDigest,
        retention: ContentDigest,
    ) -> io::Result<Self> {
        let pinned = linux_fd::require_unique_pidfd(pidfd)?.identity();
        if peer.pid <= 1 || linux_fd::pidfd_exited(pidfd)? {
            return Err(invalid());
        }
        let fresh = linux_fd::pidfd_open(peer.pid)?;
        if linux_fd::require_unique_pidfd(fresh.as_fd())?.identity() != pinned {
            return Err(invalid());
        }
        let guardian = GuardianIdentity {
            pid: peer.pid,
            uid: peer.uid,
            gid: peer.gid,
            device: pinned.device,
            inode: pinned.inode,
        };
        Ok(Self {
            channel,
            peer,
            pidfd: pidfd.try_clone_to_owned()?,
            expected: SettlementClaim::new(session, execution, index, retention, guardian)?,
            introduction: None,
            introduced: false,
            received: false,
            finished: false,
        })
    }

    /// Establishes the monitor from a packet sent by the pinned guardian, not
    /// from the first packet on the bootstrap connection. ACK releases only the
    /// monitor's bootstrap barrier; it is not an invocation gate permission.
    pub(crate) fn poll_monitor(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Option<introduction::ObservedCommandMonitor>> {
        budget(deadline, cancel)?;
        self.revalidate()?;
        if self.introduced {
            return Err(invalid());
        }
        let result = self.poll_monitor_inner(cancel, deadline);
        if result.is_err() {
            self.finished = true;
        }
        result
    }
    fn poll_monitor_inner(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Option<introduction::ObservedCommandMonitor>> {
        if self.introduction.is_none() {
            let Some(packet) = self.channel.try_receive(self.peer, 1)? else {
                return Ok(None);
            };
            let announcement = introduction::MonitorAnnouncement::decode(&packet.bytes)?;
            let pidfd = packet
                .descriptors
                .into_iter()
                .next()
                .ok_or_else(invalid)?;
            let observed = announcement.verify(
                &self.expected,
                self.pidfd.as_fd(),
                pidfd,
                cancel,
                deadline,
            )?;
            self.introduction = Some((observed, announcement.acknowledgment()?));
        }
        let (observed, acknowledgment) = self.introduction.as_ref().ok_or_else(invalid)?;
        if linux_fd::pidfd_exited(observed.pidfd())? {
            return Err(invalid());
        }
        if !self.channel.try_send(acknowledgment, &[])? {
            return Ok(None);
        }
        self.introduced = true;
        Ok(self
            .introduction
            .take()
            .map(|(observed, _)| observed))
    }

    /// Comparison against the context authenticated at construction. This does
    /// not convert a public `GuardianIdentity` value into an authority.
    pub(crate) fn matches(
        &self,
        session: &SessionId,
        execution: &ExecutionId,
        index: ContentDigest,
        retention: ContentDigest,
    ) -> bool {
        self.expected.session == session.as_str()
            && self.expected.execution == execution.as_str()
            && self.expected.index == index.to_string()
            && self.expected.retention == retention.to_string()
    }
    pub(crate) fn guardian(&self) -> GuardianIdentity {
        self.expected.guardian
    }
    pub(crate) fn revalidate(&self) -> io::Result<()> {
        if self.finished || linux_fd::pidfd_exited(self.pidfd.as_fd())? {
            return Err(invalid());
        }
        let identity = linux_fd::require_unique_pidfd(self.pidfd.as_fd())?.identity();
        if identity.device != self.expected.guardian.device
            || identity.inode != self.expected.guardian.inode
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// No wait or remote effect. Once a valid claim is received, EOF is harmless
    /// but does not replace the independent pidfd exit observation.
    pub(crate) fn poll(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Option<ObservedCommandExecutionSettlement>> {
        budget(deadline, cancel)?;
        if self.finished || !self.introduced {
            return Err(invalid());
        }
        if !self.received {
            self.receive()?;
        }
        let exited = linux_fd::pidfd_exited(self.pidfd.as_fd())?;
        if exited && !self.received {
            // Close the would-block -> guardian-send-and-exit race before
            // diagnosing a missing authenticated claim.
            self.receive()?;
            if !self.received {
                self.finished = true;
                return Err(invalid());
            }
        }
        if !exited || !self.received {
            return Ok(None);
        }
        self.finished = true;
        Ok(Some(ObservedCommandExecutionSettlement {
            session: SessionId::parse(&self.expected.session).map_err(|_| invalid())?,
            execution: ExecutionId::parse(&self.expected.execution).map_err(|_| invalid())?,
            index: self
                .expected
                .index
                .parse()
                .map_err(|_| invalid())?,
            retention: self
                .expected
                .retention
                .parse()
                .map_err(|_| invalid())?,
            guardian: self.expected.guardian,
        }))
    }
    fn receive(&mut self) -> io::Result<()> {
        match self.channel.try_receive(self.peer, 0) {
            Ok(Some(packet)) => {
                let claim = SettlementClaim::decode(&packet.bytes);
                if claim.as_ref().ok() != Some(&self.expected) {
                    self.finished = true;
                    return Err(invalid());
                }
                self.received = true;
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(error) => {
                self.finished = true;
                Err(error)
            }
        }
    }
}

fn invalid() -> io::Error {
    io::Error::other("command execution settlement is unproven")
}
#[cfg(test)]
mod tests;

pub(crate) mod introduction;

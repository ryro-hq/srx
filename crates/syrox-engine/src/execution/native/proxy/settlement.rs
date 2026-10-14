use std::io;
use std::os::fd::AsFd as _;
use std::time::Instant;

use super::custodian::SettledDescendants;
use crate::execution::command_evidence::{GuardianIdentity, SettlementClaim};
use crate::execution::journal::SessionId;
use crate::execution::transport::PacketChannel;
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest};

pub(super) fn send(
    channel: &PacketChannel,
    proof: &SettledDescendants,
    session: &SessionId,
    index: ContentDigest,
    retention: ContentDigest,
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<()> {
    if proof.guardian_pid() != std::process::id() {
        return Err(io::Error::other("foreign guardian settlement"));
    }
    let pidfd = linux_fd::pidfd_open(proof.guardian_pid())?;
    let identity = linux_fd::require_unique_pidfd(pidfd.as_fd())?.identity();
    let guardian = GuardianIdentity {
        pid: proof.guardian_pid(),
        uid: linux_fd::real_uid(),
        gid: linux_fd::real_gid(),
        device: identity.device,
        inode: identity.inode,
    };
    let claim = SettlementClaim::new(
        session,
        proof.execution(),
        index,
        retention,
        guardian,
    )?;
    channel.send(&claim.encode()?, &[], deadline, cancel)
}

/// Announce the custodian's own unreaped monitor on the exclusive guardian
/// channel. The caller keeps the monitor's private start barrier closed until
/// this exact acknowledgment arrives. Errors leave that barrier closed.
pub(super) fn announce_monitor(
    channel: &PacketChannel,
    coordinator: crate::execution::transport::Peer,
    custody: &super::custodian::MonitorCustody,
    context: &SettlementClaim,
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<()> {
    use crate::execution::command_evidence::introduction::MonitorAnnouncement;
    let pidfd = custody.monitor_pidfd()?;
    let announcement = MonitorAnnouncement::new(context, custody.monitor_pid()?, pidfd.as_fd())?;
    channel.send(
        &announcement.encode()?,
        &[pidfd.as_fd()],
        deadline,
        cancel,
    )?;
    let acknowledgment = channel.receive(coordinator, 0, deadline, cancel)?;
    if acknowledgment.bytes != announcement.acknowledgment()?
        || linux_fd::pidfd_exited(pidfd.as_fd())?
    {
        return Err(io::Error::other(
            "command monitor acknowledgment rejected",
        ));
    }
    Ok(())
}

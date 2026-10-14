use std::io::{self, Read as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::{SettlementClaim, invalid};
use crate::execution::transport::{Peer, budget};
use crate::platform::linux::fd::{self as linux_fd, PidfdNamespace};
use crate::{cancellation::Cancellation, store::ContentDigest};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MonitorAnnouncement {
    domain: String,
    version: u32,
    sequence: u64,
    session: String,
    execution: String,
    context: String,
    pid: u32,
    device: u64,
    inode: u64,
}
impl MonitorAnnouncement {
    pub(crate) fn new(
        expected: &SettlementClaim,
        pid: u32,
        pidfd: BorrowedFd<'_>,
    ) -> io::Result<Self> {
        let identity = linux_fd::require_unique_pidfd(pidfd)?.identity();
        if pid <= 1 || pid == expected.guardian.pid || linux_fd::pidfd_exited(pidfd)? {
            return Err(invalid());
        }
        Ok(Self {
            domain: "syrox-command-monitor".into(),
            version: 1,
            sequence: 0,
            session: expected.session.clone(),
            execution: expected.execution.clone(),
            context: ContentDigest::sha256(&expected.encode()?).to_string(),
            pid,
            device: identity.device,
            inode: identity.inode,
        })
    }
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        bytes.push(b'\n');
        if bytes.len() > 2048 {
            return Err(invalid());
        }
        Ok(bytes)
    }
    pub(super) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > 2048 {
            return Err(invalid());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if value.encode()? != bytes {
            return Err(invalid());
        }
        Ok(value)
    }
    pub(crate) fn acknowledgment(&self) -> io::Result<Vec<u8>> {
        Ok(format!(
            "syrox-command-monitor-ack-v1 {}\n",
            ContentDigest::sha256(&self.encode()?)
        )
        .into_bytes())
    }
    pub(super) fn verify(
        &self,
        expected: &SettlementClaim,
        guardian: BorrowedFd<'_>,
        pidfd: OwnedFd,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<ObservedCommandMonitor> {
        let canonical = Self::new(expected, self.pid, pidfd.as_fd())?;
        if self.encode()? != canonical.encode()? {
            return Err(invalid());
        }
        let peer = Peer {
            pid: self.pid,
            uid: expected.guardian.uid,
            gid: expected.guardian.gid,
        };
        verify_process(
            peer,
            expected.guardian.pid,
            guardian,
            pidfd.as_fd(),
            cancel,
            deadline,
        )?;
        Ok(ObservedCommandMonitor {
            peer,
            pidfd,
        })
    }
}

pub(crate) struct ObservedCommandMonitor {
    peer: Peer,
    pidfd: OwnedFd,
}
impl ObservedCommandMonitor {
    pub(crate) fn peer(&self) -> Peer {
        self.peer
    }
    pub(crate) fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }
}

fn verify_process(
    peer: Peer,
    parent: u32,
    guardian: BorrowedFd<'_>,
    pinned: BorrowedFd<'_>,
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<()> {
    budget(deadline, cancel)?;
    let fresh = linux_fd::pidfd_open(peer.pid)?;
    if linux_fd::require_unique_pidfd(fresh.as_fd())?.identity()
        != linux_fd::require_unique_pidfd(pinned)?.identity()
    {
        return Err(invalid());
    }
    let proc = linux_fd::open_top_directory(Path::new("/proc")).map_err(|_| invalid())?;
    if linux_fd::proc_self_pid(proc.fd())? != std::process::id() {
        return Err(invalid());
    }
    let process = linux_fd::open_beneath(proc.fd(), Path::new(&peer.pid.to_string()), true)
        .map_err(|_| invalid())?;
    let status =
        linux_fd::open_beneath(process.fd(), Path::new("status"), false).map_err(|_| invalid())?;
    if linux_fd::filesystem_type(status.fd())? != 0x9fa0 {
        return Err(invalid());
    }
    let mut text = String::new();
    status
        .into_file()
        .take(65537)
        .read_to_string(&mut text)?;
    if text.len() > 65536 {
        return Err(invalid());
    }
    for (key, expected, count) in [
        ("Pid:", peer.pid, 1),
        ("Tgid:", peer.pid, 1),
        ("PPid:", parent, 1),
        ("Uid:", peer.uid, 4),
        ("Gid:", peer.gid, 4),
    ] {
        let mut lines = text
            .lines()
            .filter_map(|line| line.strip_prefix(key));
        let line = lines.next().ok_or_else(invalid)?;
        let mut words = line.split_whitespace();
        if lines.next().is_some() {
            return Err(invalid());
        }
        for _ in 0..count {
            if words
                .next()
                .and_then(|word| word.parse::<u32>().ok())
                != Some(expected)
            {
                return Err(invalid());
            }
        }
        if words.next().is_some() {
            return Err(invalid());
        }
    }
    let monitor_ns = linux_fd::pidfd_namespace(pinned, PidfdNamespace::Pid)?;
    let guardian_ns = linux_fd::pidfd_namespace(guardian, PidfdNamespace::Pid)?;
    if linux_fd::metadata(monitor_ns.as_fd())?.identity()
        != linux_fd::metadata(guardian_ns.as_fd())?.identity()
        || linux_fd::pidfd_exited(pinned)?
        || linux_fd::pidfd_exited(guardian)?
    {
        return Err(invalid());
    }
    budget(deadline, cancel)
}

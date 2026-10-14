use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::admission::{LaunchRequest, admit_request};
use super::rendezvous::Listener;
use super::transport::{PacketChannel, Peer};
use super::{CLOSE, COMMIT, PROCESSED, RETENTION};
#[cfg(test)]
use crate::execution::journal::AttemptId;
use crate::execution::journal::{AttemptBinding, OwnershipError, SessionId, SessionJournal};
use crate::{
    cancellation::Cancellation, store::ContentDigest, store::ObjectLease, systemd::SystemdError,
    systemd::SystemdJobCompletion, systemd::SystemdJobResult, systemd::SystemdManager,
    systemd::SystemdScope, systemd::SystemdService, systemd::SystemdServiceProfile,
    systemd::SystemdUnitName, systemd::SystemdUnitStatus,
};
use thiserror::Error;

#[derive(Clone, Copy)]
pub(crate) struct OwnerStart<'a> {
    pub worker: &'a Path,
    pub worker_digest: ContentDigest,
    pub bus_socket: &'a Path,
    /// Persistent exclusive directory, preserved with the journal until reconciliation.
    pub private_directory: &'a Path,
    pub manifest: &'a [u8],
    pub pin: ContentDigest,
    /// All outputs required by this owner. A separate process-retention OFD
    /// keeps these interests alive independently of the coordinator.
    pub retention: &'a ObjectLease,
}

#[derive(Debug, Error)]
pub(crate) enum OwnerError {
    #[error(transparent)]
    Journal(#[from] OwnershipError),
    #[error(transparent)]
    Manager(#[from] SystemdError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error("session owner state refused: {0}")]
    State(&'static str),
    #[error(
        "owner startup failed for session {session}, unit {unit}: {source}; journal retained for reconciliation"
    )]
    Startup {
        session: SessionId,
        unit: String,
        source: Box<Self>,
    },
}

pub(crate) struct OwnerHandle {
    pub session: SessionId,
    #[cfg(test)]
    pub attempt: AttemptId,
    pub binding: AttemptBinding,
    manager: SystemdManager,
    channel: Option<PacketChannel>,
    // Keeps the process-retention OFD and its Store interests alive until Drop.
    #[allow(dead_code)] // This field owns retention; its Drop releases the OFD.
    retention: Option<File>,
    // Never unlink automatically: a lost Start reply may still lead to Exec.
    worker_snapshot: PathBuf,
    manifest_pin: ContentDigest,
    process: OwnedFd,
    main_pid: u32,
    bus_socket: PathBuf,
}
impl OwnerHandle {
    pub(crate) fn process(&self) -> BorrowedFd<'_> {
        self.process.as_fd()
    }
    pub(crate) const fn main_pid(&self) -> u32 {
        self.main_pid
    }

    pub(crate) fn worker_snapshot(&self) -> &Path {
        &self.worker_snapshot
    }

    pub(crate) const fn manifest_pin(&self) -> ContentDigest {
        self.manifest_pin
    }

    pub(crate) fn bus_socket(&self) -> &Path {
        &self.bus_socket
    }

    /// Persist revocation before closing the lifetime channel or stopping units.
    /// This deliberately does not publish Closed or release durable evidence.
    pub(crate) fn close(
        &mut self,
        journal: &SessionJournal,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<SystemdJobCompletion, OwnerError> {
        journal.begin_closing(
            &self.session,
            "explicit owner close",
            cancellation,
            deadline,
        )?;
        let observed = self.manager.query(
            self.binding.unit(),
            remaining(deadline)?,
            cancellation,
        )?;
        let Some(status) = observed else {
            self.channel.take();
            return Ok(SystemdJobCompletion::Unobserved {
                status: None,
            });
        };
        same_invocation(&status, &self.binding)?;
        let job = self.manager.stop(
            self.binding.unit(),
            remaining(deadline)?,
            cancellation,
        )?;
        if let Some(channel) = self.channel.take() {
            let _ = channel.send(CLOSE, &[], deadline, cancellation);
        }
        Ok(self
            .manager
            .wait_job(&job, remaining(deadline)?, cancellation)?)
    }
}

pub(crate) fn start_owner(
    start: OwnerStart<'_>,
    journal: &SessionJournal,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OwnerHandle, OwnerError> {
    let deadline = deadline.min(Instant::now() + Duration::from_secs(30));
    remaining(deadline)?;
    if !start.worker.is_absolute() {
        return Err(OwnerError::State(
            "worker path must be explicit and absolute",
        ));
    }
    let retention = start.retention.process_retention()?;
    let mut manager = SystemdManager::connect(
        SystemdScope::User {
            bus_socket: start.bus_socket.into(),
        },
        remaining(deadline)?,
        cancellation,
    )?;
    let session = journal.create(start.manifest, start.pin, cancellation, deadline)?;
    let unit = SystemdUnitName::new(format!(
        "syrox-owner-{}.service",
        session.as_str()
    ))?;
    let mut own_binding = None;
    let admitted = start_attempt(
        &start,
        journal,
        &session,
        &unit,
        &mut manager,
        &retention,
        &mut own_binding,
        cancellation,
        deadline,
    );
    match admitted {
        Ok(OwnerAttempt {
            #[cfg(test)]
            attempt,
            binding,
            channel,
            worker_snapshot,
            process,
            main_pid,
        }) => Ok(OwnerHandle {
            session,
            #[cfg(test)]
            attempt,
            binding,
            manager,
            channel: Some(channel),
            retention: Some(retention),
            worker_snapshot,
            manifest_pin: start.pin,
            process,
            main_pid,
            bus_socket: start.bus_socket.to_path_buf(),
        }),
        Err(source) => {
            // A failed/lost mutation is never replayed. Revocation and Stop are
            // independent best efforts; all evidence survives uncertain cleanup.
            let cleanup = Cancellation::default();
            let cleanup_deadline = Instant::now() + Duration::from_secs(5);
            let _ = journal.begin_closing(
                &session,
                "owner startup failed",
                &cleanup,
                cleanup_deadline,
            );
            if let Some(binding) = own_binding {
                let _ = stop_bound(&mut manager, &binding, &cleanup, cleanup_deadline);
            }
            Err(OwnerError::Startup {
                session,
                unit: unit.as_str().into(),
                source: Box::new(source),
            })
        }
    }
}

struct OwnerAttempt {
    #[cfg(test)]
    attempt: AttemptId,
    binding: AttemptBinding,
    channel: PacketChannel,
    worker_snapshot: PathBuf,
    process: OwnedFd,
    main_pid: u32,
}

#[allow(clippy::too_many_arguments)] // Explicit borrowed authorities of one startup transaction.
fn start_attempt(
    start: &OwnerStart<'_>,
    journal: &SessionJournal,
    session: &SessionId,
    unit: &SystemdUnitName,
    manager: &mut SystemdManager,
    retention: &File,
    own_binding: &mut Option<AttemptBinding>,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OwnerAttempt, OwnerError> {
    let attempt = journal.prepare_attempt(session, "owner", cancellation, deadline)?;
    let mut listener = Listener::bind(
        start.private_directory,
        &format!("owner-{}.sock", session.as_str()),
    )?;
    let snapshot = snapshot_worker(
        start.worker,
        start.worker_digest,
        start.private_directory,
        session,
        cancellation,
        deadline,
    )?;
    let mut service = SystemdService::new(unit.clone(), snapshot.clone());
    service.profile = SystemdServiceProfile::Notify {
        fd_store_max: 1,
        start_timeout: remaining(deadline)?,
    };
    service.arguments = vec![
        "__session-owner".into(),
        listener
            .path()
            .to_str()
            .ok_or(OwnerError::State("rendezvous path must be UTF-8"))?
            .into(),
        session.to_string(),
        attempt.to_string(),
        start.pin.to_string(),
        unit.as_str().into(),
    ];
    // Type=notify: acceptance precedes the handshake; waiting for completion
    // here would deadlock against the worker's pending commit.
    let job = manager.start_transient(&service, remaining(deadline)?, cancellation)?;
    let channel = listener.accept(deadline, cancellation)?;
    let peer = channel.peer_credentials()?;
    let process = crate::platform::linux::fd::pidfd_open(peer.pid)?;
    require_live_owner(process.as_fd())?;
    let status = observe_main(manager, unit, peer, None, cancellation, deadline)?;
    let invocation: [u8; 16] = status
        .invocation
        .try_into()
        .map_err(|_| OwnerError::State("owner has no invocation"))?;
    let binding = AttemptBinding::new(unit.clone(), invocation)?;
    *own_binding = Some(binding.clone());
    journal.authorize_attempt(
        session,
        &attempt,
        &binding,
        cancellation,
        deadline,
    )?;
    let expected = LaunchRequest {
        session: session.clone(),
        attempt: attempt.clone(),
        manifest: start.pin,
        binding: binding.clone(),
    };
    admit_request(
        &channel,
        peer,
        &expected,
        journal,
        cancellation,
        deadline,
    )?;
    // The authenticated message proves connect's pathname identity check has
    // completed. Unlinking immediately after accept races that client check.
    listener.close()?;
    observe_main(
        manager,
        unit,
        peer,
        Some(&binding),
        cancellation,
        deadline,
    )?;
    channel.send(
        RETENTION,
        &[retention.as_fd()],
        deadline,
        cancellation,
    )?;
    let packet = channel.receive(peer, 0, deadline, cancellation)?;
    if packet.bytes != PROCESSED {
        return Err(OwnerError::State(
            "expected notifications processed",
        ));
    }
    observe_retention(manager, unit, &binding, cancellation, deadline)?;
    observe_main(
        manager,
        unit,
        peer,
        Some(&binding),
        cancellation,
        deadline,
    )?;
    require_live_owner(process.as_fd())?;
    journal.with_consumed_attempt(
        session,
        &attempt,
        start.pin,
        &binding,
        cancellation,
        deadline,
        || channel.send(COMMIT, &[], deadline, cancellation),
    )?;
    if !matches!(
        manager.wait_job(&job, remaining(deadline)?, cancellation)?,
        SystemdJobCompletion::Observed {
            result: SystemdJobResult::Done
        }
    ) {
        return Err(OwnerError::State(
            "owner start did not complete successfully",
        ));
    }
    let status = observe_main(
        manager,
        unit,
        peer,
        Some(&binding),
        cancellation,
        deadline,
    )?;
    if status.active_state != "active" {
        return Err(OwnerError::State(
            "owner is not active after readiness",
        ));
    }
    require_live_owner(process.as_fd())?;
    Ok(OwnerAttempt {
        #[cfg(test)]
        attempt,
        binding,
        channel,
        worker_snapshot: snapshot,
        process,
        main_pid: peer.pid,
    })
}

fn observe_retention(
    manager: &mut SystemdManager,
    unit: &SystemdUnitName,
    binding: &AttemptBinding,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(), OwnerError> {
    let observed = manager
        .query_fd_store(unit, remaining(deadline)?, cancellation)?
        .ok_or(OwnerError::State(
            "owner vanished before FD store observation",
        ))?;
    if observed.invocation != binding.invocation()
        || observed.count != 1
        || observed.max != 1
        || observed.notify_access != "main"
    {
        return Err(OwnerError::State(
            "owner FD store observation differs",
        ));
    }
    Ok(())
}

fn require_live_owner(process: BorrowedFd<'_>) -> Result<(), OwnerError> {
    if crate::platform::linux::fd::pidfd_exited(process)? {
        return Err(OwnerError::State("pinned owner exited"));
    }
    Ok(())
}

fn observe_main(
    manager: &mut SystemdManager,
    unit: &SystemdUnitName,
    peer: Peer,
    binding: Option<&AttemptBinding>,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<SystemdUnitStatus, OwnerError> {
    let status = loop {
        let status = manager
            .query(unit, remaining(deadline)?, cancellation)?
            .ok_or(OwnerError::State("owner unit vanished"))?;
        if binding.is_none()
            && status.active_state == "activating"
            && (status.main_pid == 0
                || (status.main_pid == peer.pid && status.invocation.is_empty()))
        {
            cancellation
                .check()
                .map_err(|_| OwnerError::State("owner startup cancelled"))?;
            std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(5)));
            continue;
        }
        break status;
    };
    if status.main_pid != peer.pid
        || !matches!(
            status.active_state.as_str(),
            "activating" | "active"
        )
        || binding.is_some_and(|binding| status.invocation != binding.invocation())
    {
        return Err(OwnerError::State(
            "owner main PID, invocation or lifecycle differs",
        ));
    }
    Ok(status)
}
fn same_invocation(status: &SystemdUnitStatus, binding: &AttemptBinding) -> Result<(), OwnerError> {
    if &status.unit == binding.unit() && status.invocation == binding.invocation() {
        Ok(())
    } else {
        Err(OwnerError::State(
            "refusing to stop a replaced owner invocation",
        ))
    }
}
fn stop_bound(
    manager: &mut SystemdManager,
    binding: &AttemptBinding,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(), OwnerError> {
    let Some(status) = manager.query(binding.unit(), remaining(deadline)?, cancellation)? else {
        return Ok(());
    };
    same_invocation(&status, binding)?;
    let job = manager.stop(binding.unit(), remaining(deadline)?, cancellation)?;
    manager.wait_job(&job, remaining(deadline)?, cancellation)?;
    Ok(())
}

fn snapshot_worker(
    worker: &Path,
    worker_digest: ContentDigest,
    private_directory: &Path,
    session: &SessionId,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<PathBuf, OwnerError> {
    const MAX_WORKER_BYTES: usize = 128 * 1024 * 1024;
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(worker)?;
    if !source.metadata()?.is_file() {
        return Err(OwnerError::State("worker must be a regular file"));
    }
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        cancellation
            .check()
            .map_err(|_| OwnerError::State("owner startup cancelled"))?;
        remaining(deadline)?;
        let length = source.read(&mut chunk)?;
        if length == 0 {
            break;
        }
        if bytes.len() + length > MAX_WORKER_BYTES {
            return Err(OwnerError::State("worker snapshot byte limit"));
        }
        bytes.extend_from_slice(&chunk[..length]);
    }
    if ContentDigest::sha256(&bytes) != worker_digest {
        return Err(OwnerError::State(
            "worker candidate digest differs",
        ));
    }
    let path = private_directory.join(format!("worker-{}.bin", session.as_str()));
    let mut snapshot = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    for chunk in bytes.chunks(64 * 1024) {
        cancellation
            .check()
            .map_err(|_| OwnerError::State("owner startup cancelled"))?;
        remaining(deadline)?;
        snapshot.write_all(chunk)?;
    }
    snapshot.set_permissions(std::fs::Permissions::from_mode(0o500))?;
    snapshot.sync_all()?;
    drop(snapshot); // No writable handle may survive Exec (ETXTBSY).
    File::open(private_directory)?.sync_all()?;
    Ok(path)
}

fn remaining(deadline: Instant) -> Result<Duration, OwnerError> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        Err(OwnerError::State(
            "owner operation deadline exceeded",
        ))
    } else {
        Ok(timeout.min(Duration::from_secs(300)))
    }
}

#[cfg(test)]
#[path = "tests/coordinator.rs"]
mod tests;
#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[test]
    fn verified_snapshot_survives_candidate_changes_and_has_no_writable_mode() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = directory.path().join("candidate");
        std::fs::write(&candidate, b"candidate bytes").unwrap();
        let session = SessionId::parse(&"12".repeat(16)).unwrap();
        let pin = ContentDigest::sha256(b"candidate bytes");
        let path = snapshot_worker(
            &candidate,
            pin,
            directory.path(),
            &session,
            &Cancellation::default(),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        std::fs::write(&candidate, b"replacement").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"candidate bytes");
        assert_eq!(
            std::fs::metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o500
        );
        let named = path.clone();
        drop(path);
        assert!(
            named.exists(),
            "snapshot is retained as reconciliation evidence"
        );
    }

    #[test]
    fn wrong_candidate_pin_is_rejected_before_snapshot_publication() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = directory.path().join("candidate");
        std::fs::write(&candidate, b"wrong candidate").unwrap();
        let session = SessionId::parse(&"12".repeat(16)).unwrap();
        assert!(
            snapshot_worker(
                &candidate,
                ContentDigest::sha256(b"expected"),
                directory.path(),
                &session,
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(2)
            )
            .is_err()
        );
        assert!(
            !directory
                .path()
                .join(format!("worker-{session}.bin"))
                .exists()
        );
    }
}

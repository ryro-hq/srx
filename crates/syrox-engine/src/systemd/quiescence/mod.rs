//! Observa o cgroup fixado e os descritores que o manager ainda retém.
//!
//! Cgroup vazio e FD store vazio não provam a saída de um namespace nem o fim de
//! descendentes que escaparam. Uma falha nessas consultas também não deve impedir
//! um Stop que já esteja autorizado por outra prova.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::platform::linux::boot::BootId;
use crate::platform::linux::fd::{self as linux_fd, FileIdentity, OpenedPath};
use crate::{
    cancellation::Cancellation, systemd::SystemdError, systemd::SystemdManager,
    systemd::SystemdUnitStatus,
};
use thiserror::Error;

const CGROUP2_MAGIC: u64 = 0x6367_7270;
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const MAX_EVENTS_BYTES: usize = 4096;

mod events;
use events::{EventsObservation, PinnedEvents};

#[derive(Debug, Error)]
pub(crate) enum QuiescenceError {
    #[error(transparent)]
    Boot(#[from] crate::platform::linux::boot::BootError),
    #[error("cgroup observation is unavailable: {0}")]
    Invalid(&'static str),
    #[error("cgroup observation cancelled")]
    Cancelled,
    #[error("cgroup observation deadline expired")]
    Deadline,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Manager(#[from] SystemdError),
}
type Result<T> = std::result::Result<T, QuiescenceError>;

/// One caller-selected unit invocation. This comparison key does not establish
/// manager ownership, authorize Stop, or prove namespace settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnitInvocation {
    unit: crate::systemd::SystemdUnitName,
    invocation: [u8; 16],
}
impl UnitInvocation {
    pub(crate) fn new(unit: crate::systemd::SystemdUnitName, invocation: [u8; 16]) -> Result<Self> {
        if invocation == [0; 16] {
            return Err(QuiescenceError::Invalid(
                "zero invocation binding",
            ));
        }
        Ok(Self {
            unit,
            invocation,
        })
    }
    pub(crate) const fn unit(&self) -> &crate::systemd::SystemdUnitName {
        &self.unit
    }
    pub(crate) const fn invocation(&self) -> &[u8; 16] {
        &self.invocation
    }
}

/// Persistable comparison data. A marker is not a quiescence or ownership proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CgroupMarker {
    boot: BootId,
    binding: UnitInvocation,
    control_group: String,
    identity: FileIdentity,
}
impl CgroupMarker {
    pub(crate) const fn boot(&self) -> &BootId {
        &self.boot
    }
    pub(crate) const fn binding(&self) -> &UnitInvocation {
        &self.binding
    }
    pub(crate) fn control_group(&self) -> &str {
        &self.control_group
    }
    pub(crate) const fn identity(&self) -> FileIdentity {
        self.identity
    }
}

#[derive(Debug)]
pub(crate) struct PinnedUnitCgroup {
    marker: CgroupMarker,
    root: OpenedPath,
    directory: OpenedPath,
    events: PinnedEvents,
    manager: crate::systemd::SystemdManagerIdentity,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PendingReason {
    UnitAbsent,
    BindingOrPathChanged,
    CgroupUnavailable,
    CgroupReplaced,
    BootChanged,
    ManagerChanged,
    UnitNotIdle,
    ObservationChanged,
    Populated,
    FdStoreUnavailable,
    FdStoreNotEmpty,
}
#[derive(Debug)]
pub(crate) enum CgroupObservation {
    Pending(PendingReason),
    Empty(CgroupEmptyObservation),
    /// The originally pinned core events file was permanently deactivated.
    /// This is not evidence about a replacement cgroup or escaped processes.
    Removed(CgroupEmptyObservation),
}
/// Sequential observations of one pinned cgroup and manager binding. Not Clone,
/// not serializable, and deliberately not named a namespace/settlement proof.
#[derive(Debug)]
pub(crate) struct CgroupEmptyObservation {
    marker: CgroupMarker,
}
impl CgroupEmptyObservation {
    pub(crate) const fn marker(&self) -> &CgroupMarker {
        &self.marker
    }
}

impl PinnedUnitCgroup {
    pub(crate) fn capture(
        manager: &mut SystemdManager,
        binding: &UnitInvocation,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        let boot = BootId::current(cancellation, deadline)?;
        let identity =
            manager.observe_identity(remaining(cancellation, deadline)?, cancellation)?;
        let before = manager
            .query(
                binding.unit(),
                remaining(cancellation, deadline)?,
                cancellation,
            )?
            .ok_or(QuiescenceError::Invalid(
                "unit absent before cgroup pin",
            ))?;
        if before.unit != *binding.unit() || before.invocation != binding.invocation() {
            return Err(QuiescenceError::Invalid(
                "unit binding differs before pin",
            ));
        }
        let relative = relative_group(&before.control_group)?;
        let root = linux_fd::open_top_directory(Path::new(CGROUP_ROOT)).map_err(open_error)?;
        require_filesystem(&root, CGROUP2_MAGIC)?;
        let directory = linux_fd::open_beneath(root.fd(), &relative, true).map_err(open_error)?;
        require_filesystem(&directory, CGROUP2_MAGIC)?;
        let events = PinnedEvents::capture(directory.fd())?;
        let marker = CgroupMarker {
            boot,
            binding: binding.clone(),
            control_group: before.control_group,
            identity: directory.metadata().identity(),
        };
        let pinned = Self {
            marker,
            root,
            directory,
            events,
            manager: identity,
        };
        let after = manager
            .query(
                binding.unit(),
                remaining(cancellation, deadline)?,
                cancellation,
            )?
            .ok_or(QuiescenceError::Invalid(
                "unit absent during cgroup pin",
            ))?;
        if !status_matches(&pinned.marker, &after, EventsObservation::Empty)
            || manager.observe_identity(remaining(cancellation, deadline)?, cancellation)?
                != pinned.manager
            || BootId::current(cancellation, deadline)? != pinned.marker.boot
            || !pinned.same_directory(false)?
        {
            return Err(QuiescenceError::Invalid(
                "unit or cgroup changed while pinning",
            ));
        }
        Ok(pinned)
    }
    pub(crate) fn observe_empty(
        &self,
        manager: &mut SystemdManager,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<CgroupObservation> {
        let pending = CgroupObservation::Pending;
        if BootId::current(cancellation, deadline)? != *self.marker.boot() {
            return Ok(pending(PendingReason::BootChanged));
        }
        if manager.observe_identity(remaining(cancellation, deadline)?, cancellation)?
            != self.manager
        {
            return Ok(pending(PendingReason::ManagerChanged));
        }
        let Some(before) = manager.query(
            self.marker.binding.unit(),
            remaining(cancellation, deadline)?,
            cancellation,
        )?
        else {
            return Ok(pending(PendingReason::UnitAbsent));
        };
        let first = match self.local_observation() {
            Ok(state) => state,
            Err(reason) => return Ok(pending(reason)),
        };
        if !status_matches(&self.marker, &before, first) {
            return Ok(pending(PendingReason::BindingOrPathChanged));
        }
        let Some(store) = manager.query_fd_store(
            self.marker.binding.unit(),
            remaining(cancellation, deadline)?,
            cancellation,
        )?
        else {
            return Ok(pending(PendingReason::FdStoreUnavailable));
        };
        if store.invocation != self.marker.binding.invocation() {
            return Ok(pending(PendingReason::BindingOrPathChanged));
        }
        if store.count != 0 {
            return Ok(pending(PendingReason::FdStoreNotEmpty));
        }
        if first == EventsObservation::Removed
            && !manager.unit_idle_without_job(
                self.marker.binding.unit(),
                remaining(cancellation, deadline)?,
                cancellation,
            )?
        {
            return Ok(pending(PendingReason::UnitNotIdle));
        }
        let Some(after) = manager.query(
            self.marker.binding.unit(),
            remaining(cancellation, deadline)?,
            cancellation,
        )?
        else {
            return Ok(pending(PendingReason::UnitAbsent));
        };
        if !status_matches(&self.marker, &after, first) {
            return Ok(pending(PendingReason::BindingOrPathChanged));
        }
        if BootId::current(cancellation, deadline)? != *self.marker.boot() {
            return Ok(pending(PendingReason::BootChanged));
        }
        if manager.observe_identity(remaining(cancellation, deadline)?, cancellation)?
            != self.manager
        {
            return Ok(pending(PendingReason::ManagerChanged));
        }
        match self.local_observation() {
            Ok(second) if second == first => {}
            Ok(_) => return Ok(pending(PendingReason::ObservationChanged)),
            Err(reason) => return Ok(pending(reason)),
        }
        remaining(cancellation, deadline)?;
        let proof = CgroupEmptyObservation {
            marker: self.marker.clone(),
        };
        Ok(match first {
            EventsObservation::Empty => CgroupObservation::Empty(proof),
            EventsObservation::Removed => CgroupObservation::Removed(proof),
            EventsObservation::Populated => unreachable!("local observation rejects populated"),
        })
    }
    fn local_observation(&self) -> std::result::Result<EventsObservation, PendingReason> {
        let observed = self
            .events
            .observe()
            .map_err(|_| PendingReason::CgroupUnavailable)?;
        if observed == EventsObservation::Populated {
            return Err(PendingReason::Populated);
        }
        match self.same_directory(observed == EventsObservation::Removed) {
            Ok(true) => Ok(observed),
            Ok(false) => Err(PendingReason::CgroupReplaced),
            Err(_) => Err(PendingReason::CgroupUnavailable),
        }
    }
    fn same_directory(&self, removed: bool) -> Result<bool> {
        // ENOENT never proves retirement; it is tolerated only after ENODEV on
        // our pre-pinned core events FD. A replacement at the old name is refused.
        let current_root =
            linux_fd::open_top_directory(Path::new(CGROUP_ROOT)).map_err(open_error)?;
        require_filesystem(&current_root, CGROUP2_MAGIC)?;
        if current_root.metadata().identity() != self.root.metadata().identity()
            || linux_fd::metadata(self.directory.fd())?.identity() != self.marker.identity()
        {
            return Ok(false);
        }
        let current = match linux_fd::open_beneath(
            self.root.fd(),
            &relative_group(self.marker.control_group())?,
            true,
        ) {
            Ok(current) => current,
            Err(linux_fd::OpenError::Other(error))
                if removed && error.raw_os_error() == Some(libc::ENOENT) =>
            {
                return Ok(true);
            }
            Err(error) => return Err(open_error(error)),
        };
        require_filesystem(&current, CGROUP2_MAGIC)?;
        Ok(current.metadata().identity() == self.marker.identity())
    }
}
fn relative_group(text: &str) -> Result<PathBuf> {
    if text.len() > 4096
        || !text.starts_with('/')
        || text.contains('\0')
        || text[1..]
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(QuiescenceError::Invalid(
            "invalid manager cgroup path",
        ));
    }
    Ok(PathBuf::from(&text[1..]))
}
fn require_filesystem(file: &OpenedPath, expected: u64) -> Result<()> {
    if linux_fd::filesystem_type(file.fd())? != expected {
        return Err(QuiescenceError::Invalid(
            "kernel filesystem type differs",
        ));
    }
    Ok(())
}
fn status_matches(
    marker: &CgroupMarker,
    status: &SystemdUnitStatus,
    observed: EventsObservation,
) -> bool {
    status.unit == *marker.binding.unit()
        && status.invocation == marker.binding.invocation()
        && (status.control_group == marker.control_group
            || (observed == EventsObservation::Removed && status.control_group.is_empty()))
        && (observed != EventsObservation::Removed
            || (matches!(
                status.active_state.as_str(),
                "inactive" | "failed"
            ) && status.main_pid == 0))
}
fn populated(bytes: &[u8]) -> Result<bool> {
    if bytes.len() > MAX_EVENTS_BYTES {
        return Err(QuiescenceError::Invalid(
            "cgroup events exceeds bound",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| QuiescenceError::Invalid("invalid cgroup events encoding"))?;
    let mut seen = std::collections::BTreeSet::new();
    let mut populated = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(key), Some(value), None) = (fields.next(), fields.next(), fields.next()) else {
            return Err(QuiescenceError::Invalid("malformed cgroup event"));
        };
        if !seen.insert(key) || value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(QuiescenceError::Invalid(
                "duplicate or invalid cgroup event",
            ));
        }
        if key == "populated" {
            populated = Some(match value {
                "0" => false,
                "1" => true,
                _ => {
                    return Err(QuiescenceError::Invalid(
                        "invalid populated value",
                    ));
                }
            });
        }
    }
    populated.ok_or(QuiescenceError::Invalid(
        "missing populated event",
    ))
}
fn remaining(cancellation: &Cancellation, deadline: Instant) -> Result<Duration> {
    cancellation
        .check()
        .map_err(|_| QuiescenceError::Cancelled)?;
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(QuiescenceError::Deadline)
}
fn open_error(error: linux_fd::OpenError) -> QuiescenceError {
    match error {
        linux_fd::OpenError::Other(error) | linux_fd::OpenError::Unsupported(error) => {
            QuiescenceError::Io(error)
        }
        linux_fd::OpenError::Symlink => {
            QuiescenceError::Invalid("kernel property path traverses a symlink")
        }
    }
}

#[cfg(test)]
mod tests;

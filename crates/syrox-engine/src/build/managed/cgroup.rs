//!
//! Kernel contract reviewed against Linux v6.12:
//! <https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/kernfs/file.c>
//! <https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/cgroup/cgroup.c>
//! `kernfs_seq_start` returns ENODEV after node deactivation. cgroup.events has
//! no custom ENODEV path; cgroup destruction rejects populated/online children.
//! Always seek to zero before reading: `seq_file` may otherwise return cached data.
use super::{
    BuildError, ManagedBuildServiceSpecification, ObservedManagedBuildBinding,
    PreparedManagedBuild, handshake::same_binding, journal::managed::ManagedAttemptContext,
    manager_error, supervision::observe_managed_build_binding,
};
use crate::build::managed::remaining_timeout as remaining;
use crate::platform::linux::boot::BootId;
use crate::{
    cancellation::Cancellation, platform::linux::fd as linux_fd, systemd::SystemdManager,
    systemd::SystemdUnitStatus,
};
use std::{
    fs::File,
    io::{self, Read as _, Seek as _, SeekFrom},
    os::fd::{AsFd as _, OwnedFd},
    path::{Path, PathBuf},
    time::Instant,
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CGROUP2: u64 = 0x6367_7270;
const PROCFS: u64 = 0x9fa0;
const MAX_EVENTS: usize = 4096;
#[derive(Debug)]
struct Binding {
    context: ManagedAttemptContext,
    nonce: String,
    invocation: [u8; 16],
    main_pid: u32,
    contract: crate::store::ContentDigest,
}
impl Binding {
    fn capture(observed: &ObservedManagedBuildBinding) -> Self {
        Self {
            context: observed.context().clone(),
            nonce: observed.nonce().into(),
            invocation: *observed.invocation(),
            main_pid: observed.main_pid(),
            contract: observed.contract(),
        }
    }
    fn matches(&self, other: &ObservedManagedBuildBinding) -> bool {
        self.context == *other.context()
            && self.nonce == other.nonce()
            && self.invocation == *other.invocation()
            && self.main_pid == other.main_pid()
            && self.contract == other.contract()
    }
}
/// The original root/directory/events and live worker identity stay pinned.
/// Neither a path lookup failure nor an inode link count proves removal.
#[derive(Debug)]
pub(in crate::build) struct PinnedManagedBuildCgroup {
    binding: Binding,
    boot: BootId,
    group: String,
    worker: OwnedFd,
    root: linux_fd::OpenedPath,
    directory: linux_fd::OpenedPath,
    events: File,
    events_identity: linux_fd::FileIdentity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::build) enum ManagedCgroupPending {
    ManagerUnavailable,
    EpochChanged,
    UnitUnavailable,
    BindingChanged,
    UnitLive,
    PinsChanged,
    Populated,
    EventsUnavailable,
    Inconsistent,
}
#[derive(Debug)]
pub(in crate::build) enum ManagedCgroupObservation<'a> {
    Pending(ManagedCgroupPending),
    Empty(ManagedCgroupProof<'a>),
    Removed(ManagedCgroupProof<'a>),
}
/// Historical pair of observations, tied to retained kernel objects. Not Clone
/// or serializable; does not assert namespace death or FD-store emptiness.
#[derive(Debug)]
pub(in crate::build) struct ManagedCgroupProof<'a> {
    pinned: &'a PinnedManagedBuildCgroup,
}
impl ManagedCgroupProof<'_> {
    pub(in crate::build) fn matches_binding(&self, binding: &ObservedManagedBuildBinding) -> bool {
        self.pinned.matches_binding(binding)
    }
    pub(in crate::build) fn worker_exited(&self) -> Result<bool, BuildError> {
        self.pinned.worker_exited()
    }
}
impl PinnedManagedBuildCgroup {
    pub(in crate::build) fn capture(
        prepared: &PreparedManagedBuild,
        specification: &ManagedBuildServiceSpecification,
        observed: &ObservedManagedBuildBinding,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self, BuildError> {
        let first =
            observe_managed_build_binding(prepared, specification, manager, cancel, deadline)?;
        if !same_binding(&first, observed) {
            return Err(BuildError::InputChanged);
        }
        let worker = linux_fd::pidfd_open(first.main_pid())?;
        let before = manager
            .query(
                &first.context().unit,
                remaining(cancel, deadline)?,
                cancel,
            )
            .map_err(|error| manager_error(&error))?
            .ok_or(BuildError::InputChanged)?;
        live_status(&before, &first)?;
        let relative = relative_group(&before.control_group)?;
        let process = linux_fd::open_top_directory(&PathBuf::from(format!(
            "/proc/{}",
            first.main_pid()
        )))
        .map_err(open_error)?;
        require_filesystem(process.fd(), PROCFS)?;
        require_membership(&process, &before.control_group, cancel, deadline)?;
        let root = linux_fd::open_top_directory(Path::new(CGROUP_ROOT)).map_err(open_error)?;
        require_filesystem(root.fd(), CGROUP2)?;
        let directory = linux_fd::open_beneath(root.fd(), &relative, true).map_err(open_error)?;
        require_filesystem(directory.fd(), CGROUP2)?;
        let events = linux_fd::open_beneath(directory.fd(), Path::new("cgroup.events"), false)
            .map_err(open_error)?;
        require_events(events.fd())?;
        let events_identity = events.metadata().identity();
        let mut pinned = Self {
            binding: Binding::capture(&first),
            boot: BootId::current(cancel, deadline).map_err(|error| boot_error(&error))?,
            group: before.control_group,
            worker,
            root,
            directory,
            events: events.into_file(),
            events_identity,
        };
        if read_events(&mut pinned.events, cancel, deadline)? != EventState::Populated {
            return Err(BuildError::InputChanged);
        }
        let second =
            observe_managed_build_binding(prepared, specification, manager, cancel, deadline)?;
        let after = manager
            .query(
                &first.context().unit,
                remaining(cancel, deadline)?,
                cancel,
            )
            .map_err(|error| manager_error(&error))?
            .ok_or(BuildError::InputChanged)?;
        live_status(&after, &second)?;
        require_membership(&process, &pinned.group, cancel, deadline)?;
        if !same_binding(&first, &second)
            || after.control_group != pinned.group
            || pinned.boot.as_str() != first.context().boot
            || pinned.worker_exited()?
        {
            return Err(BuildError::InputChanged);
        }
        pinned.validate_pins()?;
        pinned.same_path()?;
        Ok(pinned)
    }
    pub(in crate::build) fn matches_binding(&self, binding: &ObservedManagedBuildBinding) -> bool {
        self.binding.matches(binding)
    }
    pub(in crate::build) fn worker_exited(&self) -> Result<bool, BuildError> {
        Ok(linux_fd::pidfd_exited(self.worker.as_fd())?)
    }
    pub(in crate::build) fn observe<'a>(
        &'a mut self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<ManagedCgroupObservation<'a>, BuildError> {
        use ManagedCgroupObservation::{Empty, Pending, Removed};
        if let Some(reason) = self.frame(manager, cancel, deadline)? {
            return Ok(Pending(reason));
        }
        if self.validate_pins().is_err() {
            return Ok(Pending(ManagedCgroupPending::PinsChanged));
        }
        let Ok(first) = read_events(&mut self.events, cancel, deadline) else {
            remaining(cancel, deadline)?;
            return Ok(Pending(ManagedCgroupPending::EventsUnavailable));
        };
        if first == EventState::Populated {
            return Ok(Pending(ManagedCgroupPending::Populated));
        }
        if first == EventState::Empty && self.same_path().is_err() {
            return Ok(Pending(ManagedCgroupPending::PinsChanged));
        }
        if self.validate_pins().is_err() {
            return Ok(Pending(ManagedCgroupPending::PinsChanged));
        }
        let Ok(second) = read_events(&mut self.events, cancel, deadline) else {
            remaining(cancel, deadline)?;
            return Ok(Pending(ManagedCgroupPending::EventsUnavailable));
        };
        remaining(cancel, deadline)?;
        if let Some(reason) = self.frame(manager, cancel, deadline)? {
            return Ok(Pending(reason));
        }
        if self.validate_pins().is_err() {
            return Ok(Pending(ManagedCgroupPending::PinsChanged));
        }
        if first != second {
            return Ok(Pending(ManagedCgroupPending::Inconsistent));
        }
        if second == EventState::Empty {
            if self.same_path().is_err() {
                return Ok(Pending(ManagedCgroupPending::PinsChanged));
            }
            Ok(Empty(ManagedCgroupProof {
                pinned: self,
            }))
        } else if second == EventState::Removed {
            Ok(Removed(ManagedCgroupProof {
                pinned: self,
            }))
        } else {
            Ok(Pending(ManagedCgroupPending::Populated))
        }
    }
    fn frame(
        &self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Option<ManagedCgroupPending>, BuildError> {
        let Ok(boot) = BootId::current(cancel, deadline) else {
            remaining(cancel, deadline)?;
            return Ok(Some(ManagedCgroupPending::EpochChanged));
        };
        if boot != self.boot {
            return Ok(Some(ManagedCgroupPending::EpochChanged));
        }
        let Ok(identity) = manager.observe_identity(remaining(cancel, deadline)?, cancel) else {
            remaining(cancel, deadline)?;
            return Ok(Some(ManagedCgroupPending::ManagerUnavailable));
        };
        if identity.fingerprint() != self.binding.context.manager {
            return Ok(Some(ManagedCgroupPending::EpochChanged));
        }
        let status = match manager.query(
            &self.binding.context.unit,
            remaining(cancel, deadline)?,
            cancel,
        ) {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(Some(ManagedCgroupPending::UnitUnavailable)),
            Err(_) => {
                remaining(cancel, deadline)?;
                return Ok(Some(ManagedCgroupPending::ManagerUnavailable));
            }
        };
        let Ok(after) = manager.observe_identity(remaining(cancel, deadline)?, cancel) else {
            remaining(cancel, deadline)?;
            return Ok(Some(ManagedCgroupPending::ManagerUnavailable));
        };
        if after != identity {
            return Ok(Some(ManagedCgroupPending::EpochChanged));
        }
        match BootId::current(cancel, deadline) {
            Ok(value) if value == self.boot => {}
            _ => {
                remaining(cancel, deadline)?;
                return Ok(Some(ManagedCgroupPending::EpochChanged));
            }
        }
        Ok(settled_status(
            &status,
            &self.binding,
            &self.group,
        ))
    }
    fn validate_pins(&self) -> Result<(), BuildError> {
        require_filesystem(self.root.fd(), CGROUP2)?;
        require_filesystem(self.directory.fd(), CGROUP2)?;
        require_events(self.events.as_fd())?;
        if linux_fd::metadata(self.directory.fd())?.identity()
            != self.directory.metadata().identity()
            || linux_fd::metadata(self.events.as_fd())?.identity() != self.events_identity
        {
            return Err(BuildError::InputChanged);
        }
        let root = linux_fd::open_top_directory(Path::new(CGROUP_ROOT)).map_err(open_error)?;
        if root.metadata().identity() != self.root.metadata().identity() {
            return Err(BuildError::InputChanged);
        }
        Ok(())
    }
    fn same_path(&self) -> Result<(), BuildError> {
        let directory = linux_fd::open_beneath(
            self.root.fd(),
            &relative_group(&self.group)?,
            true,
        )
        .map_err(open_error)?;
        let events = linux_fd::open_beneath(directory.fd(), Path::new("cgroup.events"), false)
            .map_err(open_error)?;
        if directory.metadata().identity() != self.directory.metadata().identity()
            || events.metadata().identity() != self.events_identity
        {
            return Err(BuildError::InputChanged);
        }
        Ok(())
    }
}
fn live_status(
    status: &SystemdUnitStatus,
    binding: &ObservedManagedBuildBinding,
) -> Result<(), BuildError> {
    if status.unit != binding.context().unit
        || status.invocation != binding.invocation()
        || status.main_pid != binding.main_pid()
        || !matches!(
            status.active_state.as_str(),
            "active" | "activating"
        )
    {
        return Err(BuildError::InputChanged);
    }
    Ok(())
}
fn settled_status(
    status: &SystemdUnitStatus,
    binding: &Binding,
    group: &str,
) -> Option<ManagedCgroupPending> {
    if status.unit != binding.context.unit || status.invocation != binding.invocation {
        return Some(ManagedCgroupPending::BindingChanged);
    }
    if !matches!(
        status.active_state.as_str(),
        "inactive" | "failed"
    ) || status.main_pid != 0
    {
        return Some(ManagedCgroupPending::UnitLive);
    }
    if !status.control_group.is_empty() && status.control_group != group {
        return Some(ManagedCgroupPending::BindingChanged);
    }
    None
}
fn require_membership(
    process: &linux_fd::OpenedPath,
    group: &str,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<(), BuildError> {
    let file =
        linux_fd::open_beneath(process.fd(), Path::new("cgroup"), false).map_err(open_error)?;
    require_filesystem(file.fd(), PROCFS)?;
    let mut bytes = Vec::new();
    file.into_file()
        .take(65537)
        .read_to_end(&mut bytes)?;
    remaining(cancel, deadline)?;
    if bytes.len() > 65536 || unified_group(&bytes)? != group {
        return Err(BuildError::InputChanged);
    }
    Ok(())
}
fn unified_group(bytes: &[u8]) -> Result<&str, BuildError> {
    let text = std::str::from_utf8(bytes).map_err(|_| BuildError::InputChanged)?;
    let mut group = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("0::") {
            if group.replace(value).is_some() {
                return Err(BuildError::InputChanged);
            }
            relative_group(value)?;
        }
    }
    group.ok_or(BuildError::InputChanged)
}
fn relative_group(text: &str) -> Result<PathBuf, BuildError> {
    if text.len() > 4096
        || !text.starts_with('/')
        || text.contains(['\0', '\n', '\r'])
        || text[1..]
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(BuildError::InputChanged);
    }
    Ok(PathBuf::from(&text[1..]))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EventState {
    Populated,
    Empty,
    Removed,
}
fn read_events(
    file: &mut File,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<EventState, BuildError> {
    remaining(cancel, deadline)?;
    require_events(file.as_fd())?;
    let read = (|| -> io::Result<Vec<u8>> {
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.take((MAX_EVENTS + 1) as u64)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    })();
    remaining(cancel, deadline)?;
    match read {
        Err(error) if error.raw_os_error() == Some(libc::ENODEV) => Ok(EventState::Removed),
        Err(error) => Err(error.into()),
        Ok(bytes) => parse_events(&bytes),
    }
}
fn parse_events(bytes: &[u8]) -> Result<EventState, BuildError> {
    if bytes.len() > MAX_EVENTS {
        return Err(BuildError::InputChanged);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| BuildError::InputChanged)?;
    let mut populated = None;
    let mut keys = std::collections::BTreeSet::new();
    for line in text.lines() {
        let mut parts = line.split_ascii_whitespace();
        let (Some(key), Some(value), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(BuildError::InputChanged);
        };
        if !keys.insert(key) || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(BuildError::InputChanged);
        }
        if key == "populated" {
            populated = Some(match value {
                "0" => EventState::Empty,
                "1" => EventState::Populated,
                _ => return Err(BuildError::InputChanged),
            });
        }
    }
    populated.ok_or(BuildError::InputChanged)
}
fn require_events(fd: std::os::fd::BorrowedFd<'_>) -> Result<(), BuildError> {
    require_filesystem(fd, CGROUP2)?;
    if linux_fd::metadata(fd)?.file_type() != linux_fd::FileType::Regular
        || linux_fd::status_flags(fd)? & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(BuildError::InputChanged);
    }
    Ok(())
}
fn require_filesystem(fd: std::os::fd::BorrowedFd<'_>, expected: u64) -> Result<(), BuildError> {
    if linux_fd::filesystem_type(fd)? != expected {
        return Err(BuildError::InputChanged);
    }
    Ok(())
}
fn open_error(error: linux_fd::OpenError) -> BuildError {
    match error {
        linux_fd::OpenError::Other(error) | linux_fd::OpenError::Unsupported(error) => {
            BuildError::Io(error)
        }
        linux_fd::OpenError::Symlink => BuildError::InputChanged,
    }
}

fn boot_error(error: &crate::platform::linux::boot::BootError) -> BuildError {
    match error {
        crate::platform::linux::boot::BootError::Cancelled => BuildError::Cancelled,
        _ => BuildError::Cache(error.to_string()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{store::ContentDigest, systemd::SystemdUnitName};
    use std::time::Duration;
    fn binding() -> Binding {
        Binding {
            context: ManagedAttemptContext {
                action: ContentDigest::sha256(b"action"),
                worker: ContentDigest::sha256(b"worker"),
                boot: "11111111-1111-1111-1111-111111111111".into(),
                manager: ContentDigest::sha256(b"manager"),
                scope: "system".into(),
                unit: SystemdUnitName::new("syrox-cgroup-test.service").unwrap(),
                uid: 1000,
                gid: 1000,
            },
            nonce: "11111111111111111111111111111111".into(),
            invocation: [1; 16],
            main_pid: 42,
            contract: ContentDigest::sha256(b"contract"),
        }
    }
    fn status() -> SystemdUnitStatus {
        SystemdUnitStatus {
            unit: binding().context.unit,
            invocation: vec![1; 16],
            active_state: "inactive".into(),
            sub_state: "dead".into(),
            control_group: "/test/unit".into(),
            result: "success".into(),
            main_pid: 0,
            exec_main_code: 0,
            exec_main_status: 0,
        }
    }
    #[test]
    fn populated_events_are_bounded_unique_and_exact() {
        assert_eq!(
            parse_events(b"populated 0\nfrozen 0\n").unwrap(),
            EventState::Empty
        );
        assert_eq!(
            parse_events(b"populated 1\nfuture_counter 12\n").unwrap(),
            EventState::Populated
        );
        for bytes in [
            b"".as_slice(),
            b"frozen 0\n",
            b"populated 00\n",
            b"populated 2\n",
            b"populated 0\npopulated 1\n",
            b"populated 0 extra\n",
            b"populated 0\nother -1\n",
            b"populated \xff\n",
        ] {
            assert!(parse_events(bytes).is_err());
        }
        assert!(parse_events(&vec![b' '; MAX_EVENTS + 1]).is_err());
    }
    #[test]
    fn membership_and_paths_reject_aliases_prefixes_and_duplicate_unified_entries() {
        assert_eq!(
            unified_group(b"0::/unit/test\n").unwrap(),
            "/unit/test"
        );
        assert_ne!(
            unified_group(b"0::/unit/test-extra\n").unwrap(),
            "/unit/test"
        );
        assert!(unified_group(b"0::/unit/test\n0::/unit/test\n").is_err());
        for path in [
            "",
            "/",
            "relative",
            "//unit",
            "/unit/../other",
            "/unit/./other",
            "/unit/",
            "/unit\nother",
        ] {
            assert!(relative_group(path).is_err());
        }
        assert!(relative_group(&format!("/{}", "x".repeat(4096))).is_err());
    }
    #[test]
    fn only_own_inactive_invocation_can_use_original_pinned_group() {
        let expected = binding();
        let mut value = status();
        assert_eq!(
            settled_status(&value, &expected, "/test/unit"),
            None
        );
        value.control_group.clear();
        assert_eq!(
            settled_status(&value, &expected, "/test/unit"),
            None
        );
        value.active_state = "active".into();
        assert_eq!(
            settled_status(&value, &expected, "/test/unit"),
            Some(ManagedCgroupPending::UnitLive)
        );
        value.active_state = "inactive".into();
        value.main_pid = expected.main_pid;
        assert_eq!(
            settled_status(&value, &expected, "/test/unit"),
            Some(ManagedCgroupPending::UnitLive)
        );
        value.main_pid = 0;
        value.invocation = vec![2; 16];
        assert_eq!(
            settled_status(&value, &expected, "/test/unit"),
            Some(ManagedCgroupPending::BindingChanged)
        );
        value.invocation = vec![1; 16];
        value.control_group = "/test/replaced".into();
        assert_eq!(
            settled_status(&value, &expected, "/test/unit"),
            Some(ManagedCgroupPending::BindingChanged)
        );
    }
    #[test]
    fn regular_file_or_absent_path_never_produces_removed_evidence() {
        let mut file = tempfile::tempfile().unwrap();
        assert!(
            read_events(
                &mut file,
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(2)
            )
            .is_err()
        );
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            read_events(
                &mut file,
                &cancel,
                Instant::now() + Duration::from_secs(2)
            ),
            Err(BuildError::Cancelled)
        ));
    }
    #[test]
    fn full_binding_comparison_includes_image_epoch_nonce_and_contract() {
        let expected = binding();
        let observed = ObservedManagedBuildBinding::for_test(
            expected.context.clone(),
            expected.nonce.clone(),
            expected.invocation,
            expected.main_pid,
            expected.contract,
        );
        assert!(expected.matches(&observed));
        let mut other = binding();
        other.context.manager = ContentDigest::sha256(b"other manager");
        assert!(!other.matches(&observed));
        let mut other = binding();
        other.contract = ContentDigest::sha256(b"other contract");
        assert!(!other.matches(&observed));
        let mut other = binding();
        other.nonce = "22222222222222222222222222222222".into();
        assert!(!other.matches(&observed));
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    #[test]
    #[ignore = "requires explicitly delegated cgroup v2 and host helper; validates Linux v6.12 ENODEV semantics"]
    fn host_pinned_events_observe_alive_empty_and_removed() {
        let parent = PathBuf::from(
            std::env::var_os("SYROX_TEST_CGROUP_DELEGATE")
                .expect("explicit delegated cgroup directory"),
        );
        let helper = PathBuf::from(
            std::env::var_os("SYROX_TEST_CGROUP_SLEEP").expect("explicit sleep helper executable"),
        );
        assert!(parent.is_absolute() && helper.is_absolute());
        let parentfd = linux_fd::open_top_directory(&parent).unwrap();
        require_filesystem(parentfd.fd(), CGROUP2).unwrap();
        let group = parent.join(linux_fd::operation_name().unwrap());
        std::fs::create_dir(&group).unwrap();
        let mut child = Child(
            std::process::Command::new(helper)
                .arg("30")
                .spawn()
                .unwrap(),
        );
        std::fs::write(
            group.join("cgroup.procs"),
            child.0.id().to_string(),
        )
        .unwrap();
        let directory = linux_fd::open_top_directory(&group).unwrap();
        let mut events = linux_fd::open_beneath(directory.fd(), Path::new("cgroup.events"), false)
            .unwrap()
            .into_file();
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(
            read_events(&mut events, &cancel, deadline).unwrap(),
            EventState::Populated
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        loop {
            if read_events(&mut events, &cancel, deadline).unwrap() == EventState::Empty {
                break;
            }
            remaining(&cancel, deadline).unwrap();
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            read_events(&mut events, &cancel, deadline).unwrap(),
            EventState::Empty
        );
        std::fs::remove_dir(&group).unwrap();
        assert_eq!(
            read_events(&mut events, &cancel, deadline).unwrap(),
            EventState::Removed
        );
        assert_eq!(
            read_events(&mut events, &cancel, deadline).unwrap(),
            EventState::Removed
        );
    }
}

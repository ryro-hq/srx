#![allow(unsafe_code)] // uname only: bounded kernel ABI architecture observation.
use super::{BorrowedFd, OpenedPath, OwnedFd};
use super::{
    metadata, open_beneath, open_top_directory, pidfd_exited, pidfd_open, proc_self_pid,
    require_unique_pidfd,
};
use crate::{cancellation::Cancellation, platform::linux::boot::BootId};
use serde::{Deserialize, Serialize};
use std::io::{self, Read as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::Path;
use std::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
}
impl Identity {
    fn read(fd: BorrowedFd<'_>) -> io::Result<Self> {
        let identity = require_unique_pidfd(fd)?.identity();
        Ok(Self {
            device: identity.device,
            inode: identity.inode,
        })
    }
    fn kernel_opened(fd: BorrowedFd<'_>) -> io::Result<Self> {
        let identity = super::pidfs_metadata(fd)?.identity();
        Ok(Self {
            device: identity.device,
            inode: identity.inode,
        })
    }
    fn valid(&self) -> bool {
        self.device != 0 && self.inode != 0
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessRecord {
    boot: BootId,
    observer_init: Identity,
    pid: u32,
    init: Identity,
    start: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NamespaceRole {
    NamespaceInit,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LauncherRole {
    Launcher,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceRecord {
    role: NamespaceRole,
    process: ProcessRecord,
}
pub(crate) struct CapturedNamespace {
    record: NamespaceRecord,
    descriptor: OwnedFd,
    parent: OwnedFd,
}
/// Not serializable or constructible by callers; proof refers to one recorded
/// init, not cgroup emptiness, manager identity, or permission to retire roots.
pub(crate) struct NamespaceExitProof {
    record: NamespaceRecord,
}
impl NamespaceExitProof {
    pub(crate) fn matches(&self, record: &NamespaceRecord) -> bool {
        &self.record == record
    }
}
impl ProcessRecord {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if !self.observer_init.valid() || !self.init.valid() || self.pid <= 1 || self.start == 0 {
            return Err(invalid());
        }
        Ok(())
    }
    fn observe_gone(&self, cancel: &Cancellation, deadline: Instant) -> io::Result<bool> {
        self.validate()?;
        let observer = observer(cancel, deadline)?;
        if observer.0 != self.boot || observer.1 != self.observer_init {
            return Err(invalid());
        }
        let gone = match pidfd_open(self.pid) {
            Ok(fd) => {
                Identity::kernel_opened(fd.as_fd())? != self.init || pidfd_exited(fd.as_fd())?
            }
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => true,
            Err(error) => return Err(error),
        };
        let after = observer_identity(cancel, deadline)?;
        if after != (self.boot.clone(), self.observer_init.clone()) {
            return Err(invalid());
        }
        Ok(gone)
    }
}
impl NamespaceRecord {
    pub(crate) fn validate(&self) -> io::Result<()> {
        self.process.validate()
    }
    pub(crate) fn boot(&self) -> &BootId {
        &self.process.boot
    }
    pub(crate) fn observe_exit(
        &self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Option<NamespaceExitProof>> {
        Ok(self
            .process
            .observe_gone(cancel, deadline)?
            .then(|| NamespaceExitProof {
                record: self.clone(),
            }))
    }
}
impl CapturedNamespace {
    pub(crate) fn capture(
        fd: BorrowedFd<'_>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Self> {
        let parent = pidfd_open(std::process::id())?;
        Self::capture_child(fd, parent.as_fd(), cancel, deadline)
    }
    /// Capture a namespace init owned by a separately pinned launcher in this
    /// observer PID namespace. The parent is retained and must remain alive
    /// through capture/revalidation; its exit is not namespace settlement.
    pub(crate) fn capture_child(
        fd: BorrowedFd<'_>,
        parent: BorrowedFd<'_>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Self> {
        let (boot, observer_init, proc) = observer(cancel, deadline)?;
        let init = Identity::read(fd)?;
        let namespace = super::pidfd_namespace(fd, super::PidfdNamespace::Pid)?;
        let me = pidfd_open(std::process::id())?;
        let own_namespace = super::pidfd_namespace(me.as_fd(), super::PidfdNamespace::Pid)?;
        if metadata(namespace.as_fd())?.identity() == metadata(own_namespace.as_fd())?.identity() {
            return Err(invalid());
        }
        if pidfd_exited(fd)? {
            return Err(invalid());
        }
        let self_proc = open_beneath(
            proc.fd(),
            Path::new(&std::process::id().to_string()),
            true,
        )
        .map_err(open_error)?;
        let (parent_pid, parent_identity) =
            capture_parent(parent, &self_proc, &proc, own_namespace.as_fd())?;
        let info = read(&self_proc, &format!("fdinfo/{}", fd.as_raw_fd()))?;
        let hierarchy = numbers(field(&info, "NSpid:")?)?;
        let pid = numbers(field(&info, "Pid:")?)?;
        if pid.len() != 1
            || pid[0] <= 1
            || hierarchy.len() < 2
            || hierarchy.first() != pid.first()
            || hierarchy.last() != Some(&1)
        {
            return Err(invalid());
        }
        let pid = pid[0];
        let process =
            open_beneath(proc.fd(), Path::new(&pid.to_string()), true).map_err(open_error)?;
        let status = read(&process, "status")?;
        if numbers(field(&status, "PPid:")?)? != [parent_pid]
            || numbers(field(&status, "Tgid:")?)? != [pid]
            || numbers(field(&status, "NSpid:")?)? != hierarchy
        {
            return Err(invalid());
        }
        let start = start_time(&read(&process, "stat")?, pid)?;
        let reopened = pidfd_open(pid)?;
        if Identity::read(reopened.as_fd())? != init
            || pidfd_exited(fd)?
            || Identity::read(parent)? != parent_identity
            || pidfd_exited(parent)?
            || observer_identity(cancel, deadline)? != (boot.clone(), observer_init.clone())
        {
            return Err(invalid());
        }
        let record = NamespaceRecord {
            role: NamespaceRole::NamespaceInit,
            process: ProcessRecord {
                boot,
                observer_init,
                pid,
                init,
                start,
            },
        };
        record.validate()?;
        Ok(Self {
            record,
            descriptor: fd.try_clone_to_owned()?,
            parent: parent.try_clone_to_owned()?,
        })
    }
    pub(crate) fn exited(&self) -> io::Result<bool> {
        pidfd_exited(self.descriptor.as_fd())
    }
    pub(crate) fn record(&self) -> &NamespaceRecord {
        &self.record
    }
    pub(crate) fn revalidate(&self, cancel: &Cancellation, deadline: Instant) -> io::Result<()> {
        let current = Self::capture_child(
            self.descriptor.as_fd(),
            self.parent.as_fd(),
            cancel,
            deadline,
        )?;
        if current.record != self.record {
            return Err(invalid());
        }
        Ok(())
    }
}
fn capture_parent(
    parent: BorrowedFd<'_>,
    self_proc: &OpenedPath,
    proc: &OpenedPath,
    own_namespace: BorrowedFd<'_>,
) -> io::Result<(u32, Identity)> {
    let identity = Identity::read(parent)?;
    if pidfd_exited(parent)? {
        return Err(invalid());
    }
    let namespace = super::pidfd_namespace(parent, super::PidfdNamespace::Pid)?;
    if metadata(namespace.as_fd())?.identity() != metadata(own_namespace)?.identity() {
        return Err(invalid());
    }
    let info = read(
        self_proc,
        &format!("fdinfo/{}", parent.as_raw_fd()),
    )?;
    let pid = numbers(field(&info, "Pid:")?)?;
    if pid.len() != 1 || numbers(field(&info, "NSpid:")?)? != pid {
        return Err(invalid());
    }
    let process =
        open_beneath(proc.fd(), Path::new(&pid[0].to_string()), true).map_err(open_error)?;
    let status = read(&process, "status")?;
    if numbers(field(&status, "Tgid:")?)? != pid || numbers(field(&status, "NSpid:")?)? != pid {
        return Err(invalid());
    }
    let reopened = pidfd_open(pid[0])?;
    if Identity::read(reopened.as_fd())? != identity || pidfd_exited(parent)? {
        return Err(invalid());
    }
    Ok((pid[0], identity))
}
fn observer_identity(cancel: &Cancellation, deadline: Instant) -> io::Result<(BootId, Identity)> {
    let (boot, identity, _) = observer(cancel, deadline)?;
    Ok((boot, identity))
}
fn observer(
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<(BootId, Identity, OpenedPath)> {
    cancel
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())?;
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "namespace evidence deadline",
        ));
    }
    if usize::BITS != 64 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "persistent pidfs identity requires 64-bit kernel",
        ));
    }
    // SAFETY: uname initializes a fixed ABI structure. The supported runtime
    // profile is x86_64; 32-bit pidfs inode allocation can reuse identities.
    let architecture = unsafe {
        let mut name: libc::utsname = std::mem::zeroed();
        if libc::uname(&raw mut name) < 0 {
            return Err(io::Error::last_os_error());
        }
        std::ffi::CStr::from_ptr(name.machine.as_ptr())
            .to_bytes()
            .to_vec()
    };
    if architecture != b"x86_64" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "persistent pidfs identity requires x86_64 kernel",
        ));
    }
    let boot = BootId::current(cancel, deadline).map_err(io::Error::other)?;
    let proc = open_top_directory(Path::new("/proc")).map_err(open_error)?;
    if proc_self_pid(proc.fd())? != std::process::id() {
        return Err(invalid());
    }
    let own = pidfd_open(std::process::id())?;
    let self_proc = open_beneath(
        proc.fd(),
        Path::new(&std::process::id().to_string()),
        true,
    )
    .map_err(open_error)?;
    let info = read(&self_proc, &format!("fdinfo/{}", own.as_raw_fd()))?;
    if numbers(field(&info, "Pid:")?)? != [std::process::id()]
        || numbers(field(&info, "NSpid:")?)? != [std::process::id()]
    {
        return Err(invalid());
    }
    let init = pidfd_open(1)?;
    let identity = Identity::kernel_opened(init.as_fd())?;
    if pidfd_exited(init.as_fd())? {
        return Err(invalid());
    }
    Ok((boot, identity, proc))
}
fn read(proc: &OpenedPath, name: &str) -> io::Result<String> {
    let file = open_beneath(proc.fd(), Path::new(name), false).map_err(open_error)?;
    if super::filesystem_type(file.fd())? != 0x9fa0
        || metadata(file.fd())?.file_type() != super::FileType::Regular
    {
        return Err(invalid());
    }
    let mut text = String::new();
    file.into_file()
        .take(65537)
        .read_to_string(&mut text)?;
    if text.len() > 65536 {
        return Err(invalid());
    }
    Ok(text)
}
fn field<'a>(text: &'a str, name: &str) -> io::Result<&'a str> {
    let mut found = text
        .lines()
        .filter_map(|line| line.strip_prefix(name));
    let value = found.next().ok_or_else(invalid)?;
    if found.next().is_some() {
        return Err(invalid());
    }
    Ok(value.trim())
}
fn numbers(text: &str) -> io::Result<Vec<u32>> {
    let mut out = Vec::new();
    for item in text.split_ascii_whitespace() {
        if out.len() == 32 {
            return Err(invalid());
        }
        let number = item.parse().map_err(|_| invalid())?;
        if number == 0 {
            return Err(invalid());
        }
        out.push(number);
    }
    if out.is_empty() {
        return Err(invalid());
    }
    Ok(out)
}
fn start_time(text: &str, pid: u32) -> io::Result<u64> {
    let prefix = format!("{pid} (");
    if !text.starts_with(&prefix) {
        return Err(invalid());
    }
    text.rsplit_once(") ")
        .and_then(|(_, tail)| tail.split_ascii_whitespace().nth(19))
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())
}
fn open_error(error: super::OpenError) -> io::Error {
    match error {
        super::OpenError::Other(e) | super::OpenError::Unsupported(e) => e,
        super::OpenError::Symlink => invalid(),
    }
}
fn invalid() -> io::Error {
    io::Error::other("namespace startup evidence differs or is unavailable")
}

#[cfg(test)]
#[path = "tests/persisted_namespace/mod.rs"]
pub(crate) mod tests;
/// The authenticated Os launcher before it creates its one namespace child.
/// A launcher record is deliberately not interchangeable with namespace evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LauncherRecord {
    role: LauncherRole,
    inventory_version: u32,
    process: ProcessRecord,
}
pub(crate) struct CapturedLauncher {
    record: LauncherRecord,
    descriptor: OwnedFd,
}
pub(crate) struct LauncherExitProof {
    record: LauncherRecord,
}
impl LauncherRecord {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.inventory_version != 1 {
            return Err(invalid());
        }
        self.process.validate()
    }
    pub(crate) fn boot(&self) -> &BootId {
        &self.process.boot
    }
    pub(crate) fn observe_exit(
        &self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Option<LauncherExitProof>> {
        self.validate()?;
        // Same kernel PID identity predicate; the resulting role remains launcher.
        Ok(self
            .process
            .observe_gone(cancel, deadline)?
            .then(|| LauncherExitProof {
                record: self.clone(),
            }))
    }
}
impl LauncherExitProof {
    pub(crate) fn matches(&self, record: &LauncherRecord) -> bool {
        &self.record == record
    }
}
impl CapturedLauncher {
    /// Called only after the Os entry authenticated itself as manager `MainPID`,
    /// and before `prepare_managed_runtime` creates its sole namespace child.
    pub(crate) fn capture_self(cancel: &Cancellation, deadline: Instant) -> io::Result<Self> {
        let descriptor = pidfd_open(std::process::id())?;
        Self::capture_peer(descriptor.as_fd(), cancel, deadline)
    }
    /// Capture an already pinned, independently authenticated launcher peer.
    /// This verifies process identity in this observer PID namespace; it does
    /// not authenticate its executable, manager binding, or resource authority.
    /// No caller-supplied PID or serialized process record is accepted.
    pub(crate) fn capture_peer(
        descriptor: BorrowedFd<'_>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Self> {
        let (boot, observer_init, proc) = observer(cancel, deadline)?;
        let me = pidfd_open(std::process::id())?;
        let own_namespace = super::pidfd_namespace(me.as_fd(), super::PidfdNamespace::Pid)?;
        let self_proc = open_beneath(
            proc.fd(),
            Path::new(&std::process::id().to_string()),
            true,
        )
        .map_err(open_error)?;
        let (pid, identity) = capture_parent(
            descriptor,
            &self_proc,
            &proc,
            own_namespace.as_fd(),
        )?;
        let process =
            open_beneath(proc.fd(), Path::new(&pid.to_string()), true).map_err(open_error)?;
        let start = start_time(&read(&process, "stat")?, pid)?;
        let reopened = pidfd_open(pid)?;
        if Identity::read(reopened.as_fd())? != identity
            || pidfd_exited(descriptor)?
            || observer_identity(cancel, deadline)? != (boot.clone(), observer_init.clone())
        {
            return Err(invalid());
        }
        let record = LauncherRecord {
            role: LauncherRole::Launcher,
            inventory_version: 1,
            process: ProcessRecord {
                boot,
                observer_init,
                pid,
                init: identity,
                start,
            },
        };
        record.validate()?;
        Ok(Self {
            record,
            descriptor: descriptor.try_clone_to_owned()?,
        })
    }
    /// Bind a namespace capture to this exact retained launcher identity.
    pub(crate) fn capture_namespace(
        &self,
        namespace: BorrowedFd<'_>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<CapturedNamespace> {
        self.revalidate(cancel, deadline)?;
        let captured = CapturedNamespace::capture_child(
            namespace,
            self.descriptor.as_fd(),
            cancel,
            deadline,
        )?;
        self.revalidate(cancel, deadline)?;
        Ok(captured)
    }
    pub(crate) fn exited(&self) -> io::Result<bool> {
        pidfd_exited(self.descriptor.as_fd())
    }
    pub(crate) fn pid(&self) -> u32 {
        self.record.process.pid
    }
    pub(crate) fn record(&self) -> &LauncherRecord {
        &self.record
    }
    pub(crate) fn revalidate(&self, cancel: &Cancellation, deadline: Instant) -> io::Result<()> {
        if Self::capture_peer(self.descriptor.as_fd(), cancel, deadline)?.record != self.record {
            return Err(invalid());
        }
        Ok(())
    }
}

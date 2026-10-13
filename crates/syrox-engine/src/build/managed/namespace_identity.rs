//! Confere o processo e os namespaces mantendo o pidfd aberto.
//!
//! O binding do manager é observado antes e depois da admissão do protocolo.
//! Essa observação não confirma FDSTORE nem libera o payload. São necessários
//! pidfds de pidfs; o antigo tipo anônimo não fornece a identidade usada aqui.

// Kernel contracts: Linux v6.12 fs/pidfs.c and include/uapi/linux/pidfd.h.
use super::{
    BuildError, journal::managed::ManagedAttemptContext, supervision::ObservedManagedBuildBinding,
};
use crate::{
    cancellation::Cancellation, platform::linux::boot::BootId, platform::linux::fd as linux_fd,
};
use sha2::{Digest as _, Sha256};
use std::io::Read as _;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Instant;

/// Keeps the process and namespace objects pinned. Observation is not atomic;
/// every revalidation rejects changed credentials, membership or namespace IDs.
pub struct VerifiedManagedBuildNamespace {
    descriptor: OwnedFd,
    worker: OwnedFd,
    context: ManagedAttemptContext,
    worker_pid: u32,
    pid: u32,
    metadata: linux_fd::Metadata,
    flags: u32,
    proc: linux_fd::OpenedPath,
    self_proc: linux_fd::OpenedPath,
    target_proc: linux_fd::OpenedPath,
    worker_proc: linux_fd::OpenedPath,
    target_namespaces: Namespaces,
    worker_namespaces: Namespaces,
    membership: String,
}
impl std::fmt::Debug for VerifiedManagedBuildNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedManagedBuildNamespace")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}
impl VerifiedManagedBuildNamespace {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
    pub(crate) fn file_identity(&self) -> linux_fd::FileIdentity {
        self.metadata.identity()
    }
    pub(crate) fn mode(&self) -> u32 {
        self.metadata.mode()
    }
    pub(crate) fn flags(&self) -> u32 {
        self.flags
    }
    pub(crate) fn rdev(&self) -> u64 {
        self.metadata.rdev()
    }
    pub(crate) fn pidfd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
    pub fn revalidate(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        super::remaining_request(cancellation, deadline)?;
        if BootId::current(cancellation, deadline)
            .map_err(|error| {
                if matches!(
                    error,
                    crate::platform::linux::boot::BootError::Cancelled
                ) {
                    BuildError::Cancelled
                } else {
                    invalid()
                }
            })?
            .as_str()
            != self.context.boot
        {
            return Err(invalid());
        }
        live(self.descriptor.as_fd())?;
        live(self.worker.as_fd())?;
        if linux_fd::require_unique_pidfd(self.descriptor.as_fd())? != self.metadata
            || linux_fd::descriptor_status_flags(self.descriptor.as_fd())? != self.flags
        {
            return Err(invalid());
        }
        pin_named_process(
            &self.proc,
            self.pid,
            self.descriptor.as_fd(),
            &self.target_proc,
        )?;
        pin_named_process(
            &self.proc,
            self.worker_pid,
            self.worker.as_fd(),
            &self.worker_proc,
        )?;
        self.target_namespaces
            .revalidate(self.descriptor.as_fd())?;
        self.worker_namespaces
            .revalidate(self.worker.as_fd())?;
        let before = self.observe(cancellation, deadline)?;
        image(
            &self.worker_proc,
            self.context.worker,
            cancellation,
            deadline,
        )?;
        if self.observe(cancellation, deadline)? != before {
            return Err(invalid());
        }
        self.target_namespaces
            .revalidate(self.descriptor.as_fd())?;
        self.worker_namespaces
            .revalidate(self.worker.as_fd())?;
        live(self.descriptor.as_fd())?;
        live(self.worker.as_fd())?;
        super::remaining_request(cancellation, deadline).map(|_| ())
    }
    fn observe(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(Status, Status), BuildError> {
        let target = status(&self.target_proc, cancellation, deadline)?;
        let worker = status(&self.worker_proc, cancellation, deadline)?;
        related(
            &target,
            &worker,
            self.pid,
            self.worker_pid,
            self.context.uid,
            self.context.gid,
        )?;
        if fdinfo(
            &self.self_proc,
            self.descriptor.as_fd(),
            cancellation,
            deadline,
        )? != target.nspid
            || cgroup(&self.target_proc, cancellation, deadline)? != self.membership
            || cgroup(&self.worker_proc, cancellation, deadline)? != self.membership
        {
            return Err(invalid());
        }
        Ok((target, worker))
    }
}
/// Validate an owned received pidfd against a separately observed worker binding.
/// Requires pidfs plus `PIDFD_GET_{PID,MNT,USER}_NAMESPACE` capabilities. Caller
/// must reobserve the manager before and after this snapshot prior to admission.
pub fn verify_managed_build_namespace_identity(
    received: OwnedFd,
    binding: &ObservedManagedBuildBinding,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<VerifiedManagedBuildNamespace, BuildError> {
    super::remaining_request(cancellation, deadline)?;
    let metadata = linux_fd::require_unique_pidfd(received.as_fd())?;
    live(received.as_fd())?;
    let flags = linux_fd::descriptor_status_flags(received.as_fd())?;
    let proc = linux_fd::open_top_directory(Path::new("/proc")).map_err(|_| invalid())?;
    if linux_fd::proc_self_pid(proc.fd())? != std::process::id() {
        return Err(invalid());
    }
    let self_proc = proc_directory(&proc, std::process::id())?;
    let hierarchy = fdinfo(
        &self_proc,
        received.as_fd(),
        cancellation,
        deadline,
    )?;
    let pid = hierarchy[0];
    let worker_pid = binding.main_pid();
    if pid <= 1 || worker_pid <= 1 || pid == worker_pid {
        return Err(invalid());
    }
    let target_proc = proc_directory(&proc, pid)?;
    pin_named_process(&proc, pid, received.as_fd(), &target_proc)?;
    let worker = linux_fd::pidfd_open(worker_pid)?;
    linux_fd::require_unique_pidfd(worker.as_fd())?;
    live(worker.as_fd())?;
    let worker_proc = proc_directory(&proc, worker_pid)?;
    pin_named_process(&proc, worker_pid, worker.as_fd(), &worker_proc)?;
    let target_namespaces = Namespaces::open(received.as_fd())?;
    let worker_namespaces = Namespaces::open(worker.as_fd())?;
    namespaces_related(
        &target_namespaces.identities()?,
        &worker_namespaces.identities()?,
    )?;
    if linux_fd::metadata(linux_fd::namespace_parent(target_namespaces.0[0].as_fd())?.as_fd())?
        .identity()
        != worker_namespaces.identities()?[0]
    {
        return Err(invalid());
    }
    let membership = cgroup(&worker_proc, cancellation, deadline)?;
    let result = VerifiedManagedBuildNamespace {
        descriptor: received,
        worker,
        context: binding.context().clone(),
        worker_pid,
        pid,
        metadata,
        flags,
        proc,
        self_proc,
        target_proc,
        worker_proc,
        target_namespaces,
        worker_namespaces,
        membership,
    };
    result.revalidate(cancellation, deadline)?;
    Ok(result)
}
struct Namespaces([OwnedFd; 3]);
impl Namespaces {
    fn open(pidfd: BorrowedFd<'_>) -> Result<Self, BuildError> {
        use linux_fd::PidfdNamespace::{Mount, Pid, User};
        Ok(Self([
            linux_fd::pidfd_namespace(pidfd, Pid)?,
            linux_fd::pidfd_namespace(pidfd, Mount)?,
            linux_fd::pidfd_namespace(pidfd, User)?,
        ]))
    }
    fn identities(&self) -> Result<[linux_fd::FileIdentity; 3], BuildError> {
        Ok([
            linux_fd::metadata(self.0[0].as_fd())?.identity(),
            linux_fd::metadata(self.0[1].as_fd())?.identity(),
            linux_fd::metadata(self.0[2].as_fd())?.identity(),
        ])
    }
    fn revalidate(&self, pidfd: BorrowedFd<'_>) -> Result<(), BuildError> {
        if Self::open(pidfd)?.identities()? != self.identities()? {
            return Err(invalid());
        }
        Ok(())
    }
}
fn namespaces_related(
    child: &[linux_fd::FileIdentity; 3],
    worker: &[linux_fd::FileIdentity; 3],
) -> Result<(), BuildError> {
    if child[0] == worker[0] || child[1] == worker[1] || child[2] != worker[2] {
        return Err(invalid());
    }
    Ok(())
}
fn proc_directory(
    proc: &linux_fd::OpenedPath,
    pid: u32,
) -> Result<linux_fd::OpenedPath, BuildError> {
    let result = linux_fd::open_beneath(proc.fd(), Path::new(&pid.to_string()), true)
        .map_err(|_| invalid())?;
    if linux_fd::filesystem_type(result.fd())? != 0x9fa0 {
        return Err(invalid());
    }
    Ok(result)
}
fn pin_named_process(
    proc: &linux_fd::OpenedPath,
    pid: u32,
    pidfd: BorrowedFd<'_>,
    directory: &linux_fd::OpenedPath,
) -> Result<(), BuildError> {
    let current = linux_fd::pidfd_open(pid)?;
    if linux_fd::require_unique_pidfd(current.as_fd())?.identity()
        != linux_fd::require_unique_pidfd(pidfd)?.identity()
        || proc_directory(proc, pid)?.metadata().identity() != directory.metadata().identity()
    {
        return Err(invalid());
    }
    live(pidfd)
}
fn live(pidfd: BorrowedFd<'_>) -> Result<(), BuildError> {
    if linux_fd::pidfd_exited(pidfd)? {
        return Err(invalid());
    }
    Ok(())
}
fn read(
    proc: &linux_fd::OpenedPath,
    name: &str,
    limit: u64,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<Vec<u8>, BuildError> {
    super::remaining_request(cancellation, deadline)?;
    let file = linux_fd::open_beneath(proc.fd(), Path::new(name), false).map_err(|_| invalid())?;
    if linux_fd::filesystem_type(file.fd())? != 0x9fa0
        || file.metadata().file_type() != linux_fd::FileType::Regular
    {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.into_file()
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    super::remaining_request(cancellation, deadline)?;
    if u64::try_from(bytes.len()).map_err(|_| invalid())? > limit {
        return Err(invalid());
    }
    Ok(bytes)
}
fn unique<'a>(text: &'a str, key: &str) -> Result<&'a str, BuildError> {
    let mut matches = text
        .lines()
        .filter_map(|line| line.strip_prefix(key));
    let value = matches.next().ok_or_else(invalid)?;
    if matches.next().is_some() {
        return Err(invalid());
    }
    Ok(value.trim())
}
fn numbers(text: &str, maximum: usize) -> Result<Vec<u32>, BuildError> {
    let mut output = Vec::new();
    for word in text.split_whitespace() {
        if output.len() == maximum {
            return Err(invalid());
        }
        let value: u32 = word.parse().map_err(|_| invalid())?;
        if word != value.to_string() {
            return Err(invalid());
        }
        output.push(value);
    }
    if output.is_empty() {
        return Err(invalid());
    }
    Ok(output)
}
fn fdinfo(
    proc: &linux_fd::OpenedPath,
    fd: BorrowedFd<'_>,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<Vec<u32>, BuildError> {
    let bytes = read(
        proc,
        &format!("fdinfo/{}", fd.as_raw_fd()),
        4096,
        cancellation,
        deadline,
    )?;
    parse_fdinfo(std::str::from_utf8(&bytes).map_err(|_| invalid())?)
}
fn parse_fdinfo(text: &str) -> Result<Vec<u32>, BuildError> {
    let pid = numbers(unique(text, "Pid:")?, 1)?[0];
    let hierarchy = numbers(unique(text, "NSpid:")?, 32)?;
    if pid <= 1 || hierarchy[0] != pid || hierarchy.contains(&0) {
        return Err(invalid());
    }
    Ok(hierarchy)
}
#[derive(Debug, PartialEq, Eq)]
struct Status {
    pid: u32,
    tgid: u32,
    parent: u32,
    uid: Vec<u32>,
    gid: Vec<u32>,
    nspid: Vec<u32>,
}
fn status(
    proc: &linux_fd::OpenedPath,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<Status, BuildError> {
    let bytes = read(proc, "status", 65_536, cancellation, deadline)?;
    parse_status(std::str::from_utf8(&bytes).map_err(|_| invalid())?)
}
fn parse_status(text: &str) -> Result<Status, BuildError> {
    Ok(Status {
        pid: numbers(unique(text, "Pid:")?, 1)?[0],
        tgid: numbers(unique(text, "Tgid:")?, 1)?[0],
        parent: numbers(unique(text, "PPid:")?, 1)?[0],
        uid: numbers(unique(text, "Uid:")?, 4)?,
        gid: numbers(unique(text, "Gid:")?, 4)?,
        nspid: numbers(unique(text, "NSpid:")?, 32)?,
    })
}
fn related(
    child: &Status,
    worker: &Status,
    pid: u32,
    parent: u32,
    uid: u32,
    gid: u32,
) -> Result<(), BuildError> {
    if child.pid != pid
        || child.tgid != pid
        || child.parent != parent
        || worker.pid != parent
        || worker.tgid != parent
        || child.uid != vec![uid; 4]
        || worker.uid != vec![uid; 4]
        || child.gid != vec![gid; 4]
        || worker.gid != vec![gid; 4]
        || worker.nspid.first() != Some(&parent)
        || child.nspid.first() != Some(&pid)
        || child.nspid.len() != worker.nspid.len() + 1
        || child.nspid.last() != Some(&1)
    {
        return Err(invalid());
    }
    // Numeric PIDs differ at every shared namespace level: only the hierarchy
    // depth and final namespace-init value are comparable, not the PID values.
    if worker.nspid.contains(&0) || child.nspid.contains(&0) {
        return Err(invalid());
    }
    Ok(())
}
fn cgroup(
    proc: &linux_fd::OpenedPath,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<String, BuildError> {
    let bytes = read(proc, "cgroup", 8192, cancellation, deadline)?;
    parse_cgroup(std::str::from_utf8(&bytes).map_err(|_| invalid())?)
}
fn parse_cgroup(text: &str) -> Result<String, BuildError> {
    let path = text
        .strip_prefix("0::")
        .and_then(|s| s.strip_suffix('\n'))
        .ok_or_else(invalid)?;
    if path.len() > 4096
        || !path.starts_with('/')
        || path.len() <= 1
        || path.bytes().any(|b| b.is_ascii_control())
        || path[1..]
            .split('/')
            .any(|p| matches!(p, "" | "." | ".."))
    {
        return Err(invalid());
    }
    Ok(path.into())
}
fn image(
    proc: &linux_fd::OpenedPath,
    expected: crate::store::ContentDigest,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(), BuildError> {
    let mut file = linux_fd::open_proc_executable(proc.fd())?;
    let before = linux_fd::metadata(file.as_fd())?;
    if before.file_type() != linux_fd::FileType::Regular || before.size() > 128 * 1024 * 1024 {
        return Err(invalid());
    }
    let mut reader = (&mut file).take(128 * 1024 * 1024 + 1);
    let mut bytes = [0u8; 16_384];
    let mut total = 0u64;
    let mut hash = Sha256::new();
    loop {
        super::remaining_request(cancellation, deadline)?;
        let count = reader.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        total += u64::try_from(count).map_err(|_| invalid())?;
        if total > 128 * 1024 * 1024 {
            return Err(invalid());
        }
        hash.update(&bytes[..count]);
    }
    if total != before.size()
        || linux_fd::metadata(file.as_fd())? != before
        || linux_fd::metadata(linux_fd::open_proc_executable(proc.fd())?.as_fd())?.identity()
            != before.identity()
        || crate::store::ContentDigest::from_sha256_hash(hash.finalize().into()) != expected
    {
        return Err(invalid());
    }
    super::remaining_request(cancellation, deadline).map(|_| ())
}

fn invalid() -> BuildError {
    BuildError::InvalidRequest
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn status_text(pid: u32, parent: u32, hierarchy: &str) -> String {
        format!(
            "Name:\tworker\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{parent}\nUid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\nNSpid:\t{hierarchy}\n"
        )
    }
    #[test]
    fn pidfd_information_rejects_ambiguous_dead_or_foreign_namespace_targets() {
        assert_eq!(
            parse_fdinfo("pos:\t0\nPid:\t400\nNSpid:\t400\t1\n").unwrap(),
            vec![400, 1]
        );
        for text in [
            "Pid:\t-1\nNSpid:\t-1\n",
            "Pid:\t0\nNSpid:\t0\n",
            "Pid:\t400\nNSpid:\t401\t1\n",
            "Pid:\t400\nPid:\t401\nNSpid:\t400\t1\n",
            "Pid:\t0400\nNSpid:\t400\t1\n",
            "Pid:\t400\n",
        ] {
            assert!(parse_fdinfo(text).is_err(), "{text}");
        }
        let too_deep = format!(
            "Pid:\t400\nNSpid:\t400 {}\n",
            vec!["1"; 32].join(" ")
        );
        assert!(parse_fdinfo(&too_deep).is_err());
    }
    #[test]
    fn namespace_init_requires_exact_parent_credentials_and_hierarchy_depth() {
        let worker = parse_status(&status_text(300, 2, "300\t40")).unwrap();
        let child = parse_status(&status_text(400, 300, "400\t50\t1")).unwrap();
        assert!(related(&child, &worker, 400, 300, 1000, 1001).is_ok());
        for (parent, hierarchy) in [
            (301, "400\t50\t1"),
            (300, "400\t1"),
            (300, "400\t50\t2"),
            (300, "400\t0\t1"),
        ] {
            let changed = parse_status(&status_text(400, parent, hierarchy)).unwrap();
            assert!(related(&changed, &worker, 400, 300, 1000, 1001).is_err());
        }
        let changed =
            parse_status(&status_text(400, 300, "400\t50\t1").replace("Gid:\t1001", "Gid:\t1002"))
                .unwrap();
        assert!(related(&changed, &worker, 400, 300, 1000, 1001).is_err());
        assert!(parse_status(&(status_text(400, 300, "400\t1") + "PPid:\t300\n")).is_err());
    }
    #[test]
    fn namespace_identity_checks_do_not_equate_inode_numbers_on_other_devices() {
        let id = |device, inode| linux_fd::FileIdentity {
            device,
            inode,
        };
        let worker = [id(1, 10), id(1, 11), id(1, 12)];
        let child = [id(1, 20), id(1, 21), id(1, 12)];
        assert!(namespaces_related(&child, &worker).is_ok());
        let mut changed = child;
        changed[0] = worker[0];
        assert!(namespaces_related(&changed, &worker).is_err());
        changed = child;
        changed[1] = worker[1];
        assert!(namespaces_related(&changed, &worker).is_err());
        changed = child;
        changed[2] = id(2, 12);
        assert!(namespaces_related(&changed, &worker).is_err());
    }
    #[test]
    fn cgroup_requires_one_canonical_nonroot_unified_membership() {
        assert_eq!(
            parse_cgroup("0::/user.slice/service.scope\n").unwrap(),
            "/user.slice/service.scope"
        );
        for text in [
            "0::/\n",
            "0::/a/../b\n",
            "0::/a//b\n",
            "0::/a\n0::/a\n",
            "1:cpu:/a\n",
            "0::/a\r\n",
        ] {
            assert!(parse_cgroup(text).is_err());
        }
    }
    #[test]
    fn cancel_and_deadline_fail_before_pid_or_proc_observation() {
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            super::super::remaining_request(&cancel, Instant::now() + Duration::from_secs(1)),
            Err(BuildError::Cancelled)
        ));
        assert!(
            super::super::remaining_request(
                &Cancellation::default(),
                Instant::now()
                    .checked_sub(Duration::from_secs(1))
                    .unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn ordinary_file_cannot_supply_a_unique_pidfs_identity() {
        let file = tempfile::tempfile().unwrap();
        assert_eq!(
            linux_fd::require_unique_pidfd(file.as_fd())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Unsupported
        );
    }
    #[test]
    #[ignore = "requires pidfs and PIDFD_GET namespace ioctls on a real kernel runner"]
    fn kernel_pidfs_identity_is_stable_across_independent_opens() {
        let first = linux_fd::pidfd_open(std::process::id()).unwrap();
        let second = linux_fd::pidfd_open(std::process::id()).unwrap();
        assert_eq!(
            linux_fd::require_unique_pidfd(first.as_fd())
                .unwrap()
                .identity(),
            linux_fd::require_unique_pidfd(second.as_fd())
                .unwrap()
                .identity()
        );
        let namespaces = Namespaces::open(first.as_fd()).unwrap();
        namespaces.revalidate(second.as_fd()).unwrap();
        assert!(!linux_fd::pidfd_exited(first.as_fd()).unwrap());
    }
}

//! Guardian que adota e recolhe os descendentes do monitor.
//!
//! A saída do monitor não prova que os descendentes acabaram. O guardian mantém
//! essa responsabilidade em outro processo. A retenção durável da Store continua
//! com o chamador e só pode acabar depois da confirmação de settlement.

use crate::execution::journal::ExecutionId;
use std::fs::File;
use std::io::{self, Read as _, Seek as _};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

pub(super) enum Spawn {
    Guardian(MonitorCustody),
    Monitor(MonitorUnderCustody),
}

/// Only the actual fork child can exercise this capability, not its init copies.
pub(super) struct MonitorUnderCustody {
    guardian: OwnedFd,
    execution: ExecutionId,
    parent: libc::pid_t,
    process: libc::pid_t,
}
impl MonitorUnderCustody {
    pub(super) fn execution(&self) -> &ExecutionId {
        &self.execution
    }
    pub(super) fn validate(&self) -> io::Result<()> {
        // SAFETY: process identity queries have no pointer arguments.
        if unsafe { libc::getpid() } != self.process
            || unsafe { libc::getppid() } != self.parent
            || crate::platform::linux::fd::pidfd_exited(self.guardian.as_fd())?
        {
            return Err(io::Error::other("monitor guardian identity lost"));
        }
        Ok(())
    }
}

/// Constructed only after the monitor and all adopted children were reaped.
pub(super) struct SettledDescendants {
    execution: ExecutionId,
    guardian_pid: u32,
}
impl SettledDescendants {
    pub(super) fn execution(&self) -> &ExecutionId {
        &self.execution
    }
    pub(super) fn guardian_pid(&self) -> u32 {
        self.guardian_pid
    }
}

pub(super) struct MonitorCustody {
    execution: ExecutionId,
    process: libc::pid_t,
    monitor: libc::pid_t,
    status: Option<ExitStatus>,
    children: File,
    settled: bool,
}

impl MonitorCustody {
    pub(super) fn monitor_pid(&self) -> io::Result<u32> {
        self.validate()?;
        if self.status.is_some() {
            return Err(io::Error::other("monitor already reaped"));
        }
        Ok(self.monitor.cast_unsigned())
    }

    pub(super) fn monitor_pidfd(&self) -> io::Result<OwnedFd> {
        let pid = self.monitor_pid()?;
        // The direct child remains unreaped and this guardian is its sole
        // waiter: its numeric PID cannot be recycled during this open.
        let fd = crate::platform::linux::fd::pidfd_open(pid)?;
        crate::platform::linux::fd::require_unique_pidfd(fd.as_fd())?;
        self.validate()?;
        if crate::platform::linux::fd::pidfd_exited(fd.as_fd())? {
            return Err(io::Error::other("monitor already exited"));
        }
        Ok(fd)
    }

    pub(super) fn monitor_status(&self) -> Option<ExitStatus> {
        self.status
    }

    fn validate(&self) -> io::Result<()> {
        // SAFETY: the fork copies must never operate the parent's child owners.
        if unsafe { libc::getpid() } != self.process {
            return Err(io::Error::other("guardian process changed"));
        }
        Ok(())
    }

    /// Leaves a running monitor alone. Once it exits, terminates adopted children.
    pub(super) fn try_settled(&mut self) -> io::Result<Option<SettledDescendants>> {
        self.validate()?;
        if self.status.is_none() {
            let mut status = 0;
            // SAFETY: this dedicated process is the sole waiter of its monitor.
            let result = unsafe { libc::waitpid(self.monitor, &raw mut status, libc::WNOHANG) };
            if result == 0 {
                return Ok(None);
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                return if error.kind() == io::ErrorKind::Interrupted {
                    Ok(None)
                } else {
                    Err(error)
                };
            }
            self.status = Some(ExitStatus::from_raw(status));
        }
        if !self.settled {
            self.kill_adopted()?;
            loop {
                // SAFETY: no unrelated children exist; this process is the sole waiter.
                let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
                if result == 0 {
                    return Ok(None);
                }
                if result > 0 {
                    continue;
                }
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    self.settled = true;
                    break;
                }
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
        Ok(Some(SettledDescendants {
            execution: self.execution.clone(),
            guardian_pid: self.process.cast_unsigned(),
        }))
    }

    /// Cancellation requests teardown; it never makes a deadline a settlement proof.
    pub(super) fn settle(&mut self) -> io::Result<SettledDescendants> {
        self.validate()?;
        if self.status.is_none() {
            kill_child(self.monitor)?;
        }
        loop {
            if let Some(proof) = self.try_settled()? {
                return Ok(proof);
            }
            // Merely avoids spinning. Success requires a subsequent real ECHILD.
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    fn kill_adopted(&mut self) -> io::Result<()> {
        self.children.rewind()?;
        let mut buffer = [0_u8; 1024];
        let mut pid = 0_i32;
        let mut bytes = 0_usize;
        loop {
            let count = self.children.read(&mut buffer)?;
            bytes = bytes
                .checked_add(count)
                .ok_or_else(invalid_children)?;
            if bytes > 16 * 1024 * 1024 {
                return Err(invalid_children());
            }
            for byte in &buffer[..count] {
                if byte.is_ascii_digit() {
                    pid = pid
                        .checked_mul(10)
                        .and_then(|value| value.checked_add(i32::from(*byte - b'0')))
                        .ok_or_else(invalid_children)?;
                } else if byte.is_ascii_whitespace() {
                    if pid != 0 {
                        kill_child(pid)?;
                        pid = 0;
                    }
                } else {
                    return Err(invalid_children());
                }
            }
            if count == 0 {
                if pid != 0 {
                    kill_child(pid)?;
                }
                return Ok(());
            }
        }
    }
}
impl Drop for MonitorCustody {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self.settle();
        }
    }
}
fn invalid_children() -> io::Error {
    io::Error::other("invalid guardian child inventory")
}

fn kill_child(pid: libc::pid_t) -> io::Result<()> {
    // SAFETY: WNOWAIT pins even exited children. Only the dedicated guardian can
    // reap, so a confirmed direct child's PID cannot be recycled before kill.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        if libc::waitid(
            libc::P_PID,
            pid.cast_unsigned(),
            &raw mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
        if libc::kill(pid, libc::SIGKILL) < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
    }
    Ok(())
}

/// # Safety
/// Only in a dedicated single-threaded worker, before user/PID namespace entry,
/// with no borrowed global locks. No other code may spawn or reap in the guardian.
/// The monitor branch must terminate with `_exit`, never unwind into copied owners.
/// SIGCHLD must have default disposition without NOCLDWAIT; its mask/signalfd are
/// preserved. The caller establishes durable retention BEFORE calling this method.
pub(super) unsafe fn enter(execution: &ExecutionId) -> io::Result<Spawn> {
    // SAFETY: read-only identity and initialized sigaction/fstatfs destinations.
    let process = unsafe { libc::getpid() };
    let thread = unsafe { libc::syscall(libc::SYS_gettid) };
    let mut children = File::open(format!("/proc/self/task/{thread}/children"))?;
    unsafe {
        let mut filesystem: libc::statfs = std::mem::zeroed();
        if libc::fstatfs(children.as_raw_fd(), &raw mut filesystem) < 0 {
            return Err(io::Error::last_os_error());
        }
        if !crate::platform::linux::fd::filesystem_magic_matches(
            filesystem.f_type,
            libc::PROC_SUPER_MAGIC,
        ) {
            return Err(invalid_children());
        }
        let mut action: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut action) < 0 {
            return Err(io::Error::last_os_error());
        }
        if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
            return Err(io::Error::other(
                "guardian requires waitable children",
            ));
        }
    }
    if children.read(&mut [0_u8; 1])? != 0 {
        return Err(io::Error::other("guardian already has children"));
    }
    let parent = crate::platform::linux::fd::pidfd_open(process.cast_unsigned())?;
    // SAFETY: dedicated-worker fork contract stated above. Subreaper is set BEFORE fork.
    unsafe {
        if libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        let monitor = libc::fork();
        if monitor < 0 {
            return Err(io::Error::last_os_error());
        }
        if monitor == 0 {
            drop(children);
            let token = MonitorUnderCustody {
                guardian: parent,
                execution: execution.clone(),
                parent: process,
                process: libc::getpid(),
            };
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0
                || token.validate().is_err()
            {
                libc::_exit(125);
            }
            return Ok(Spawn::Monitor(token));
        }
        drop(parent);
        Ok(Spawn::Guardian(MonitorCustody {
            execution: execution.clone(),
            process,
            monitor,
            status: None,
            children,
            settled: false,
        }))
    }
}

#[cfg(test)]
mod tests {
    //! Isolated process custody proofs; no namespace, manager or tty gate is implied.
    use super::*;
    use std::io::Write as _;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    mod settlement {
        //! Real process + credential-bearing IPC + journal roundtrip. No namespaces or
        //! systemd are launched. The session's initial owner binding is fixture metadata;
        //! the guardian binding and final observation come from the real receiver.
        use super::*;
        use crate::execution::command_evidence::{
            GuardianIdentity, SettlementClaim, SettlementReceiver,
        };
        use crate::execution::journal::{
            AttemptBinding, SessionId, SessionJournal, execution::ExecutionPhase,
        };
        use crate::execution::transport::{PacketChannel, Peer};
        use crate::{
            cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest,
            store::GcRequest, store::ObjectLease, store::Store,
        };
        use std::os::unix::fs::PermissionsExt as _;

        fn deadline() -> Instant {
            Instant::now() + Duration::from_secs(5)
        }

        struct Fixture {
            _root: tempfile::TempDir,
            journal: SessionJournal,
            session: SessionId,
            store: Store,
            lease: ObjectLease,
            digest: ContentDigest,
        }
        fn fixture() -> Fixture {
            let root = tempfile::tempdir().unwrap();
            let registry = root.path().join("sessions");
            std::fs::create_dir(&registry).unwrap();
            std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o700)).unwrap();
            let journal = SessionJournal::open(&registry).unwrap();
            let cancel = Cancellation::default();
            let manifest = b"custodian roundtrip fixture";
            let session = journal
                .create(
                    manifest,
                    ContentDigest::sha256(manifest),
                    &cancel,
                    deadline(),
                )
                .unwrap();
            let attempt = journal
                .prepare_attempt(&session, "owner", &cancel, deadline())
                .unwrap();
            let binding = AttemptBinding::new(
                crate::systemd::SystemdUnitName::new("syrox-fixture-owner.service").unwrap(),
                [1; 16],
            )
            .unwrap();
            journal
                .authorize_attempt(&session, &attempt, &binding, &cancel, deadline())
                .unwrap();
            let path = root.path().join("store");
            std::fs::create_dir(&path).unwrap();
            let store = Store::open(&path).unwrap();
            let operation = store.operation().unwrap();
            let bytes: &[u8] = b"custodian retained artifact";
            let digest = ContentDigest::sha256(bytes);
            operation
                .ingest(bytes, digest, bytes.len() as u64)
                .unwrap();
            let lease = operation
                .retain_objects(&[digest], &[digest])
                .unwrap();
            drop(operation);
            Fixture {
                _root: root,
                journal,
                session,
                store,
                lease,
                digest,
            }
        }

        struct GuardianProcess {
            pid: i32,
            reaped: bool,
        }
        impl GuardianProcess {
            fn reap(&mut self) {
                let mut status = 0;
                assert_eq!(
                    unsafe { libc::waitpid(self.pid, &raw mut status, 0) },
                    self.pid
                );
                self.reaped = true;
                assert_eq!(status, 0, "guardian fixture failed");
            }
        }
        impl Drop for GuardianProcess {
            fn drop(&mut self) {
                if !self.reaped {
                    // SAFETY: exclusive waiter; the child PID has never been reaped.
                    unsafe {
                        libc::kill(self.pid, libc::SIGKILL);
                        while libc::waitpid(self.pid, std::ptr::null_mut(), 0) < 0 {
                            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                                break;
                            }
                        }
                    }
                }
            }
        }

        const TEST_MONITOR_ACK: &[u8] = b"authorize test monitor";

        pub(super) fn roundtrip() {
            let Fixture {
                _root,
                journal,
                session,
                store,
                lease,
                digest,
            } = fixture();
            let cancel = Cancellation::default();
            let index = ContentDigest::sha256(b"fixture command index");
            let mut execution = journal
                .prepare_execution(&session, index, &cancel, deadline())
                .unwrap();
            let hold = lease
                .persist_checked(execution.execution().as_str(), || Ok(()))
                .unwrap();
            execution
                .retain(hold, &cancel, deadline())
                .unwrap();
            execution
                .begin_start(&cancel, deadline())
                .unwrap();
            drop(lease);
            assert!(collect(&store).removed_objects.is_empty());
            let (mut guardian, receiver_channel, mut authorize_write) = launch_guardian(
                &session,
                execution.execution(),
                index,
                execution.retention_digest().unwrap(),
            );
            let pid = guardian.pid;
            let pidfd = linux_fd::pidfd_open(pid.cast_unsigned()).unwrap();
            let mut peer = Peer::current();
            peer.pid = pid.cast_unsigned();
            let mut receiver = SettlementReceiver::new(
                receiver_channel,
                peer,
                pidfd.as_fd(),
                &session,
                execution.execution(),
                index,
                execution.retention_digest().unwrap(),
            )
            .unwrap();
            execution
                .bind_guardian(&receiver, &cancel, deadline())
                .unwrap();
            let introduction_deadline = deadline();
            let monitor = loop {
                if let Some(monitor) = receiver
                    .poll_monitor(&cancel, introduction_deadline)
                    .unwrap()
                {
                    break monitor;
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            assert_ne!(monitor.peer().pid, pid.cast_unsigned());
            assert!(!linux_fd::pidfd_exited(monitor.pidfd()).unwrap());
            execution
                .with_started_execution(0, &cancel, deadline(), || {
                    authorize_write.write_all(TEST_MONITOR_ACK)
                })
                .unwrap();
            drop(authorize_write);
            let limit = deadline();
            let proof = loop {
                if let Some(proof) = receiver.poll(&cancel, limit).unwrap() {
                    break proof;
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            assert!(receiver.poll(&cancel, limit).is_err());
            guardian.reap();
            assert!(collect(&store).removed_objects.is_empty());
            execution
                .finish(proof, &cancel, deadline())
                .unwrap();
            let state = journal
                .snapshot(&session, &cancel, deadline())
                .unwrap();
            assert_eq!(state.executions.len(), 1);
            assert_eq!(state.executions[0].phase, ExecutionPhase::Settled);
            assert_eq!(state.executions[0].next_gate, 1);
            assert_eq!(collect(&store).removed_objects, [digest]);
        }

        fn collect(store: &Store) -> crate::store::GcReport {
            store
                .maintenance()
                .unwrap()
                .garbage_collect(&GcRequest {
                    collect: true,
                    ..GcRequest::default()
                })
                .unwrap()
        }

        fn guardian(
            channel: &PacketChannel,
            coordinator: Peer,
            mut authorize: io::PipeReader,
            session: &SessionId,
            execution: &ExecutionId,
            index: ContentDigest,
            retention: ContentDigest,
        ) {
            let peer = Peer::current();
            let pidfd = linux_fd::pidfd_open(peer.pid).unwrap();
            let identity = linux_fd::require_unique_pidfd(pidfd.as_fd())
                .unwrap()
                .identity();
            let context = SettlementClaim::new(
                session,
                execution,
                index,
                retention,
                GuardianIdentity {
                    pid: peer.pid,
                    uid: peer.uid,
                    gid: peer.gid,
                    device: identity.device,
                    inode: identity.inode,
                },
            )
            .unwrap();
            let (mut barrier_read, mut barrier_write) = io::pipe().unwrap();
            let proof = match unsafe { enter(execution) }.unwrap() {
                Spawn::Monitor(token) => {
                    drop(barrier_write);
                    token.validate().unwrap();
                    let mut barrier = [0];
                    barrier_read.read_exact(&mut barrier).unwrap();
                    assert_eq!(barrier, *b"B");
                    let mut ack = vec![0; TEST_MONITOR_ACK.len()];
                    authorize.read_exact(&mut ack).unwrap();
                    assert_eq!(ack, TEST_MONITOR_ACK);
                    descendants(std::ffi::OsStr::new("crash"), &token);
                    unsafe {
                        libc::_exit(37);
                    }
                }
                Spawn::Guardian(mut custody) => {
                    drop(barrier_read);
                    drop(authorize);
                    crate::execution::native::proxy::settlement::announce_monitor(
                        channel,
                        coordinator,
                        &custody,
                        &context,
                        &Cancellation::default(),
                        deadline(),
                    )
                    .unwrap();
                    barrier_write.write_all(b"B").unwrap();
                    drop(barrier_write);
                    let start = Instant::now();
                    loop {
                        if let Some(proof) = custody.try_settled().unwrap() {
                            break proof;
                        }
                        assert!(start.elapsed() < Duration::from_secs(3));
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            };
            assert_eq!(proof.execution(), execution);
            assert_eq!(proof.guardian_pid(), peer.pid);
            crate::execution::native::proxy::settlement::send(
                channel,
                &proof,
                session,
                index,
                retention,
                &Cancellation::default(),
                deadline(),
            )
            .unwrap();
        }

        fn launch_guardian(
            session: &SessionId,
            execution: &ExecutionId,
            index: ContentDigest,
            retention: ContentDigest,
        ) -> (GuardianProcess, PacketChannel, io::PipeWriter) {
            // This is the actual authenticated transport, never a fabricated Packet or
            // observation. Sandboxes denying it must fail this active test explicitly.
            let (receiver_channel, guardian_channel) = PacketChannel::pair().unwrap();
            let (authorize_read, authorize_write) = io::pipe().unwrap();
            let coordinator = Peer::current();
            let parent = unsafe { libc::getpid() };
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    unsafe {
                        assert_eq!(
                            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0),
                            0
                        );
                        assert_eq!(libc::getppid(), parent);
                    }
                    drop(receiver_channel);
                    drop(authorize_write);
                    guardian(
                        &guardian_channel,
                        coordinator,
                        authorize_read,
                        session,
                        execution,
                        index,
                        retention,
                    );
                }));
                // Never release inherited journal/retention owners through child Drop.
                unsafe {
                    libc::_exit(i32::from(result.is_err()));
                }
            }
            let guardian = GuardianProcess {
                pid,
                reaped: false,
            };
            drop(guardian_channel);
            drop(authorize_read);
            (guardian, receiver_channel, authorize_write)
        }
    }
    const ROLE: &str = "SYROX_CUSTODIAN_FIXTURE";
    const FIXTURE: &str = "execution::native::proxy::custodian::tests::isolated_fixture";

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn isolated(role: &str) {
        let mut child = ChildGuard(
            Command::new(crate::reexec_test_executable(FIXTURE, true))
                .args([
                    "--ignored",
                    "--exact",
                    FIXTURE,
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(ROLE, role)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "isolated custody {role}: {status}"
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "isolated custody timed out"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    #[test]
    fn crash_before_registration_reaps_live_adopted_siblings() {
        isolated("crash");
    }
    #[test]
    fn live_monitor_is_not_settlement_and_explicit_abort_collects_it() {
        isolated("abort");
    }
    #[test]
    fn preexisting_child_is_rejected_without_reaping_or_killing_it() {
        isolated("existing");
    }
    #[test]
    fn monitor_capability_is_invalid_in_forked_init_copy() {
        isolated("copy");
    }
    #[test]
    fn successful_monitor_exit_keeps_its_status_separate_from_settlement() {
        isolated("normal");
    }

    #[test]
    #[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
    fn isolated_fixture() {
        let role = std::env::var_os(ROLE).expect("parent test must supply the fixture environment");
        // Fork once into a genuinely single-threaded fixture process. The libtest
        // waiter never becomes a subreaper and never uses waitpid(-1).
        let parent = unsafe { libc::getpid() };
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child > 0 {
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(child, &raw mut status, 0) },
                child
            );
            assert_eq!(status, 0, "dedicated custody fixture failed");
            return;
        }
        // SAFETY: fixture-only cleanup if its isolated libtest parent is killed.
        unsafe {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0
                || libc::getppid() != parent
            {
                libc::_exit(125);
            }
        }
        let result = std::panic::catch_unwind(|| dedicated_fixture(&role));
        unsafe {
            libc::_exit(i32::from(result.is_err()));
        }
    }

    // Each role exercises one uninterrupted fork/adoption/settlement lifecycle in its
    // isolated subreaper process; splitting phases would obscure descriptor ownership.
    fn dedicated_fixture(role: &std::ffi::OsStr) {
        if role == "settlement" {
            settlement::roundtrip();
            return;
        }
        let execution = ExecutionId::parse("11111111111111111111111111111111").unwrap();
        if role == "sleeper" {
            // stdin EOF also terminates the fixture if its test parent crashes.
            io::copy(&mut io::stdin(), &mut io::sink()).unwrap();
            return;
        }
        if role == "existing" {
            let mut child = ChildGuard(
                Command::new(crate::reexec_test_executable(FIXTURE, true))
                    .args([
                        "--ignored",
                        "--exact",
                        FIXTURE,
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(ROLE, "sleeper")
                    .stdin(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            // SAFETY: failure must precede fork, signaling or child collection.
            assert!(unsafe { enter(&execution) }.is_err());
            assert!(child.0.try_wait().unwrap().is_none());
            child.0.stdin.take();
            assert!(child.0.wait().unwrap().success());
            return;
        }
        let (mut ready_read, mut ready_write) = io::pipe().unwrap();
        let (mut release_read, mut release_write) = io::pipe().unwrap();
        // SAFETY: only this isolated test operates process-global child state.
        // The fork child never returns into libtest; all paths terminate with _exit.
        match unsafe { enter(&execution) }.unwrap() {
            Spawn::Monitor(token) => {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    token.validate().unwrap();
                    drop(ready_read);
                    drop(release_write);
                    descendants(role, &token);
                    ready_write.write_all(b"R").unwrap();
                    let mut byte = [0];
                    release_read.read_exact(&mut byte).unwrap();
                }));
                // SAFETY: never unwind into copied caller resources.
                unsafe {
                    libc::_exit(if outcome.is_ok() {
                        37
                    } else {
                        101
                    });
                }
            }
            Spawn::Guardian(mut custody) => {
                drop(ready_write);
                drop(release_read);
                let mut byte = [0];
                ready_read.read_exact(&mut byte).unwrap();
                assert_eq!(byte, *b"R");
                assert!(custody.try_settled().unwrap().is_none());
                assert!(custody.monitor_status().is_none());
                assert!(custody.monitor_pid().unwrap() > 1);
                let monitor_fd = custody.monitor_pidfd().unwrap();
                assert!(!crate::platform::linux::fd::pidfd_exited(monitor_fd.as_fd()).unwrap());
                let started = Instant::now();
                let proof = if role == "normal" {
                    release_write.write_all(b"X").unwrap();
                    loop {
                        if let Some(proof) = custody.try_settled().unwrap() {
                            break proof;
                        }
                        assert!(started.elapsed() < Duration::from_secs(3));
                        std::thread::sleep(Duration::from_millis(1));
                    }
                } else {
                    custody.settle().unwrap()
                };
                assert_eq!(proof.execution(), &execution);
                assert_eq!(
                    proof.guardian_pid(),
                    unsafe { libc::getpid() }.cast_unsigned()
                );
                assert!(
                    started.elapsed() < Duration::from_secs(3),
                    "settlement must precede orphan fixture alarm watchdog"
                );
                if role == "normal" {
                    assert_eq!(custody.monitor_status().unwrap().code(), Some(37));
                } else {
                    assert_eq!(
                        custody.monitor_status().unwrap().signal(),
                        Some(libc::SIGKILL)
                    );
                }
                assert!(custody.try_settled().unwrap().is_some());
                assert!(custody.monitor_pid().is_err());
                assert!(custody.monitor_pidfd().is_err());
                // SAFETY: this guardian is the only waiter and must have zero children.
                assert_eq!(
                    unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) },
                    -1
                );
                assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::ECHILD)
                );
                drop(release_write);
            }
        }
    }

    fn descendants(role: &std::ffi::OsStr, token: &MonitorUnderCustody) {
        if role == "copy" {
            // SAFETY: isolated fork proof, child uses identity checks and _exit.
            let child = unsafe { libc::fork() };
            assert!(child >= 0);
            if child == 0 {
                let invalid = token.validate().is_err();
                unsafe {
                    libc::_exit(i32::from(!invalid));
                }
            }
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(child, &raw mut status, 0) },
                child
            );
            assert_eq!(status, 0);
        } else if role == "crash" {
            for _ in 0..3 {
                // Each child deliberately survives its original monitor:
                // no PDEATHSIG, registration, pidfd handoff or EOF shortcut.
                let child = unsafe { libc::fork() };
                assert!(child >= 0);
                if child == 0 {
                    unsafe {
                        libc::alarm(5);
                        loop {
                            libc::pause();
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn authenticated_guardian_settlement_finishes_journal_and_releases_gc_hold() {
        isolated("settlement");
    }
}

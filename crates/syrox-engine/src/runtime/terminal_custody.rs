use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::command_proxy::settlement::{
    GuardianIdentity, ObservedCommandExecutionSettlement, SettlementReceiver,
};
use crate::platform::linux::fd::terminal::{
    TerminalAttributes, TerminalGuard, foreground_terminal,
};
use crate::{cancellation::Cancellation, store::ContentDigest};

pub(crate) const TERMINAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const TERMINAL_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Constructible only after the monitor acknowledged the same saved attributes.
#[derive(Debug)]
pub(crate) struct TerminalCustodyConfirmed {
    device: u32,
    original: ContentDigest,
}
impl TerminalCustodyConfirmed {
    pub(crate) fn validate(
        &self,
        host: BorrowedFd<'_>,
        original: &TerminalAttributes,
    ) -> io::Result<()> {
        if foreground_terminal(host)? != self.device
            || original.fingerprint() != self.original
            || !original.matches(&TerminalAttributes::read(host)?)
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootPauseOutcome {
    Resumed,
    Abandoned,
}

pub(crate) enum FrontendPauseOutcome {
    Resumed(TerminalGuard),
    Abandoned(TerminalGuard),
}

pub(crate) trait TerminalFrontend {
    fn ready(&mut self, proof: TerminalCustodyConfirmed) -> io::Result<TerminalGuard>;
    /// The namespace has exited. Drain remaining PTY output with a bounded wait.
    fn namespace_settled(&mut self) -> io::Result<()>;
    /// Guardian has restored the host terminal for a stopped root job. This
    /// transfers the single local guard through a relay-paused stop/resume.
    fn prepare_pause_root(&mut self, cancel: &Cancellation) -> io::Result<()>;
    fn pause_root(
        &mut self,
        guard: TerminalGuard,
        signal: i32,
        root: BorrowedFd<'_>,
        cancel: &Cancellation,
    ) -> io::Result<FrontendPauseOutcome>;
}

#[derive(Debug)]
pub(crate) struct RuntimeTerminalRequest {
    pub(super) slave: Option<OwnedFd>,
    host: OwnedFd,
    channel: Option<UnixStream>,
    remote: Option<UnixStream>,
    identity: [u32; 4],
    original: ContentDigest,
    guard: Option<TerminalGuard>,
    restored: bool,
    active: bool,
    settled: bool,
    monitor: Option<OwnedFd>,
    namespace: Option<OwnedFd>,
    control: Option<UnixStream>,
    execution_guardian: Option<GuardianIdentity>,
}
impl RuntimeTerminalRequest {
    pub(crate) fn new(
        slave: OwnedFd,
        host: BorrowedFd<'_>,
        original: &TerminalAttributes,
    ) -> io::Result<Self> {
        crate::platform::linux::fd::terminal::validate_slave(slave.as_fd())?;
        let device = foreground_terminal(host)?;
        if !original.matches(&TerminalAttributes::read(host)?) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let [pid, session, group] =
            crate::execution::native::terminal_custody::frontend_identity()?;
        let (channel, remote) = UnixStream::pair()?;
        channel.set_nonblocking(true)?;
        Ok(Self {
            slave: Some(slave),
            host: host.try_clone_to_owned()?,
            channel: Some(channel),
            remote: Some(remote),
            identity: [pid, session, group, device],
            original: original.fingerprint(),
            guard: None,
            restored: false,
            active: false,
            settled: false,
            monitor: None,
            namespace: None,
            control: None,
            execution_guardian: None,
        })
    }
    pub(crate) fn slave(&self) -> Option<BorrowedFd<'_>> {
        self.slave.as_ref().map(AsFd::as_fd)
    }

    pub(crate) fn configure<'a>(
        &'a self,
        command: &mut crate::platform::linux::fd::PreparedLaunch<'a>,
    ) -> io::Result<()> {
        let remote = self.remote.as_ref().expect("not spawned");
        for fd in [remote.as_fd(), self.host.as_fd()] {
            command.inherit(fd);
            command.arg(fd.as_raw_fd().to_string())?;
        }
        for value in self.identity {
            command.arg(value.to_string())?;
        }
        Ok(())
    }
    /// Installs the exclusive external guardian before raw activation. Its private
    /// custody channel sends S only after all execution descendants were reaped.
    /// The monitor fork must close/disarm its inherited custody endpoint.
    pub(crate) fn own_guardian(
        &mut self,
        receiver: &SettlementReceiver,
        pidfd: BorrowedFd<'_>,
    ) -> io::Result<()> {
        if self.active || self.monitor.is_some() || self.namespace.is_some() {
            return Err(io::Error::other(
                "terminal custody already assigned",
            ));
        }
        receiver.revalidate()?;
        let guardian = receiver.guardian();
        let identity = crate::platform::linux::fd::require_unique_pidfd(pidfd)?.identity();
        if identity.device != guardian.device
            || identity.inode != guardian.inode
            || crate::platform::linux::fd::pidfd_exited(pidfd)?
        {
            return Err(io::Error::other(
                "terminal guardian identity mismatch",
            ));
        }
        self.monitor = Some(pidfd.try_clone_to_owned()?);
        self.execution_guardian = Some(guardian);
        Ok(())
    }

    /// Final authenticated evidence is a fallback if custody negotiation failed.
    /// Guardian identity is unique to the receiver's pinned execution.
    pub(crate) fn observe_execution_settlement(
        &mut self,
        proof: &ObservedCommandExecutionSettlement,
    ) -> io::Result<()> {
        if self.execution_guardian != Some(proof.guardian()) {
            return Err(io::Error::other(
                "terminal execution settlement mismatch",
            ));
        }
        self.settled = true;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn own_monitor(&mut self, pid: u32, control: &UnixStream) -> io::Result<()> {
        if self.execution_guardian.is_some() {
            return Err(io::Error::other(
                "terminal guardian already assigned",
            ));
        }
        self.monitor = Some(crate::platform::linux::fd::pidfd_open(pid)?);
        self.control = Some(control.try_clone()?);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn own_namespace(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        if self.execution_guardian.is_some() {
            return Err(io::Error::other(
                "root namespace cannot prove execution settlement",
            ));
        }
        self.namespace = Some(fd.try_clone_to_owned()?);
        Ok(())
    }
    pub(crate) fn finish_after_monitor(&mut self) -> io::Result<()> {
        self.restore_local()
    }
    pub(crate) fn spawned(&mut self) {
        self.remote.take();
        self.slave.take();
    }
    pub(crate) fn activate(
        &mut self,
        frontend: &mut dyn TerminalFrontend,
        cancel: &Cancellation,
    ) -> io::Result<()> {
        let mut ready = [0_u8; 33];
        self.read(&mut ready, cancel)?;
        if ready[0] != b'R' || ready[1..] != self.original.as_bytes()[..] {
            return Err(io::Error::other(
                "terminal custody snapshot mismatch",
            ));
        }
        self.guard = Some(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                frontend.ready(TerminalCustodyConfirmed {
                    device: self.identity[3],
                    original: self.original,
                })
            }))
            .map_err(|_| io::Error::other("terminal activation callback panicked"))??,
        );
        self.active = true;
        self.channel
            .as_mut()
            .ok_or_else(|| io::Error::other("terminal custody channel closed"))?
            .write_all(b"A")
    }
    /// Stops relay IO before the coordinator asks the guardian to restore tty.
    pub(crate) fn prepare_pause_root(
        &mut self,
        frontend: &mut dyn TerminalFrontend,
        cancel: &Cancellation,
    ) -> io::Result<()> {
        if self.execution_guardian.is_none()
            || !self.active
            || self.settled
            || self.restored
            || self.guard.is_none()
        {
            return Err(io::Error::other(
                "invalid root terminal preparation",
            ));
        }
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            frontend.prepare_pause_root(cancel)
        }))
        .map_err(|_| io::Error::other("terminal pause preparation panicked"))?
    }

    /// Called only after the guardian acknowledged restoration for `RootEvent`'s
    /// stopped sequence. A pause is not descendant settlement.
    pub(crate) fn pause_root(
        &mut self,
        frontend: &mut dyn TerminalFrontend,
        signal: i32,
        root: BorrowedFd<'_>,
        cancel: &Cancellation,
    ) -> io::Result<RootPauseOutcome> {
        if self.execution_guardian.is_none()
            || !self.active
            || self.settled
            || self.restored
            || !matches!(
                signal,
                libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
            )
        {
            return Err(io::Error::other("invalid root terminal pause"));
        }
        let guard = self
            .guard
            .take()
            .ok_or_else(|| io::Error::other("terminal guard unavailable"))?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            frontend.pause_root(guard, signal, root, cancel)
        }))
        .map_err(|_| io::Error::other("terminal pause callback panicked"))??;
        let (guard, outcome) = match result {
            FrontendPauseOutcome::Resumed(guard) => (guard, RootPauseOutcome::Resumed),
            FrontendPauseOutcome::Abandoned(guard) => (guard, RootPauseOutcome::Abandoned),
        };
        self.guard = Some(guard);
        Ok(outcome)
    }

    pub(crate) fn poll_settled(
        &mut self,
        frontend: &mut dyn TerminalFrontend,
        _cancel: &Cancellation,
    ) -> io::Result<bool> {
        if self.restored {
            return Ok(true);
        }
        let mut byte = [0];
        match self
            .channel
            .as_mut()
            .ok_or_else(|| io::Error::other("terminal custody channel closed"))?
            .read(&mut byte)
        {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Ok(1) if byte[0] == b'S' => {}
            Err(e) => return Err(e),
            _ => {
                return Err(io::Error::other(
                    "terminal custody settlement lost",
                ));
            }
        }
        self.settled = true;
        let drain = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            frontend.namespace_settled()
        }))
        .map_err(|_| io::Error::other("terminal drain callback panicked"))
        .and_then(|value| value);
        let local = self.restore_local();
        let remote = self.request_restoration();
        merge_errors(
            "terminal drain/local restoration",
            merge_errors(
                "terminal drain",
                drain,
                "local restoration",
                local,
            ),
            "monitor restoration",
            remote,
        )?;
        Ok(true)
    }
    fn request_restoration(&mut self) -> io::Result<()> {
        self.channel
            .as_mut()
            .ok_or_else(|| io::Error::other("terminal custody channel closed"))?
            .write_all(b"F")?;
        let mut restored = [0];
        self.read(&mut restored, &Cancellation::default())?;
        if restored != *b"D" {
            return Err(io::Error::other(
                "terminal custody restoration unconfirmed",
            ));
        }
        self.restored = true;
        Ok(())
    }
    fn read(&mut self, bytes: &mut [u8], cancel: &Cancellation) -> io::Result<()> {
        let deadline = Instant::now() + TERMINAL_NEGOTIATION_TIMEOUT;
        let mut offset = 0;
        while offset < bytes.len() {
            if cancel.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "terminal custody cancelled",
                ));
            }
            match self
                .channel
                .as_mut()
                .ok_or_else(|| io::Error::other("terminal custody channel closed"))?
                .read(&mut bytes[offset..])
            {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "terminal custody closed",
                    ));
                }
                Ok(n) => offset += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "terminal custody deadline",
                        ));
                    }
                    crate::execution::native::ready(
                        self.channel
                            .as_ref()
                            .ok_or_else(|| io::Error::other("terminal custody channel closed"))?
                            .as_fd(),
                        25,
                    )?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    fn restore_local(&mut self) -> io::Result<()> {
        if self.execution_guardian.is_some() && !self.settled {
            return Err(io::Error::other(
                "terminal execution settlement is unproven",
            ));
        }
        let result = self
            .guard
            .as_mut()
            .map_or(Ok(()), TerminalGuard::restore);
        self.guard.take();
        result
    }
    pub(crate) fn abort(&mut self) -> io::Result<()> {
        let result = (|| {
            if self.active && !self.restored {
                if !self.settled {
                    self.channel
                        .as_mut()
                        .ok_or_else(|| io::Error::other("terminal custody channel closed"))?
                        .write_all(b"B")?;
                    let mut settled = [0];
                    self.read(&mut settled, &Cancellation::default())?;
                    if settled != *b"S" {
                        return Err(io::Error::other(
                            "terminal abort lacks namespace settlement",
                        ));
                    }
                    self.settled = true;
                }
                let local = self.restore_local();
                let remote = self.request_restoration();
                merge_errors(
                    "local restoration",
                    local,
                    "monitor restoration",
                    remote,
                )?;
            }
            Ok(())
        })();
        // On failed negotiation, keep the raw guard until the caller has
        // waited for monitor/namespace exit, then call finish_local.
        self.channel.take();
        result
    }
}
pub(crate) fn merge_errors(
    first: &str,
    left: io::Result<()>,
    second: &str,
    right: io::Result<()>,
) -> io::Result<()> {
    match (left, right) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(a), Err(b)) => Err(io::Error::other(format!(
            "{first}: {a}; {second}: {b}"
        ))),
    }
}

impl Drop for RuntimeTerminalRequest {
    fn drop(&mut self) {
        // Close custody itself before waiting. shutdown may be denied and is
        // not required for EOF on this uniquely owned endpoint.
        self.channel.take();
        if let Some(control) = self.control.take() {
            let _ = control.shutdown(std::net::Shutdown::Both);
        }
        if let Some(monitor) = &self.monitor {
            let _ = crate::platform::linux::fd::wait_pidfd(monitor.as_fd());
        }
        if let Some(namespace) = &self.namespace {
            let _ = crate::platform::linux::fd::wait_pidfd(namespace.as_fd());
        }
        if self.execution_guardian.is_none()
            && let Some(monitor) = &self.monitor
        {
            let _ = crate::execution::native::terminal_custody::reap_monitor(monitor.as_fd());
        }
        // In full-execution mode launch owns the Child and must collect its
        // exit status itself. Polling its pidfd above does not reap it.
        if self.execution_guardian.is_some() && !self.settled {
            // Guardian death alone is not ECHILD evidence. Do not let the local
            // guard's destructor restore while sibling namespaces may survive.
            if let Some(guard) = self.guard.take() {
                guard.disarm_without_restore();
            }
        } else {
            let _ = self.restore_local();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    #[ignore = "reexec fixture; requires the parent test and isolated fixture environment"]
    fn dropped_request_monitor_fixture() {
        let witness = std::env::var_os("SYROX_CUSTODY_DROP_WITNESS")
            .expect("parent test must supply the fixture environment");
        let mut input = Vec::new();
        io::stdin().read_to_end(&mut input).unwrap();
        assert!(input.is_empty());
        std::fs::write(
            witness,
            b"monitor settled before request drop returned",
        )
        .unwrap();
    }

    #[test]
    fn request_drop_waits_for_monitor_even_during_unwind() {
        if crate::platform::linux::fd::retention_fork_tests::isolate_test(
            "runtime::terminal_custody::tests::request_drop_waits_for_monitor_even_during_unwind",
            "SYROX_CUSTODY_DROP_ISOLATED",
        ) {
            return;
        }
        let temporary = tempfile::tempdir().unwrap();
        let witness = temporary.path().join("settled");
        let (control, remote) = UnixStream::pair().unwrap();
        let remote: OwnedFd = remote.into();
        let mut request = RuntimeTerminalRequest {
            slave: None,
            host: std::fs::File::open("/dev/null").unwrap().into(),
            channel: Some(control.try_clone().unwrap()),
            remote: None,
            identity: [0; 4],
            original: ContentDigest::sha256(b"drop-only fixture without terminal activation"),
            guard: None,
            restored: false,
            active: false,
            settled: false,
            monitor: None,
            namespace: None,
            control: None,
            execution_guardian: None,
        };
        let mut child = Command::new(crate::reexec_test_executable(
            "runtime::terminal_custody::tests::dropped_request_monitor_fixture",
            true,
        ))
        .args([
            "--ignored",
            "--exact",
            "runtime::terminal_custody::tests::dropped_request_monitor_fixture",
            "--nocapture",
        ])
        .env("SYROX_CUSTODY_DROP_WITNESS", &witness)
        .stdin(Stdio::from(remote))
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
        // Synthetic inactive request tests only the Drop barrier, not admission.
        // Install its live child ownership before entering the failing scope.
        if let Err(error) = request.own_monitor(child.id(), &control) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("cannot pin fixture monitor: {error}");
        }
        drop(control);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _owned = request;
            panic!("simulate an unwind outside terminal callbacks");
        }));
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(witness).unwrap(),
            b"monitor settled before request drop returned"
        );
        // Request Drop used waitid(P_PIDFD), so std's subsequent wait sees ECHILD.
        assert_eq!(
            child.wait().unwrap_err().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn reports_both_drain_and_restoration_errors() {
        let error = merge_errors(
            "drain",
            Err(io::Error::other("drain-failure")),
            "restore",
            Err(io::Error::other("restore-failure")),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("drain-failure") && error.contains("restore-failure"));
    }

    #[test]
    fn global_custody_does_not_accept_root_exit_as_settlement() {
        // Structural fixture exercises only the restoration policy, not guardian
        // authentication or real terminal ownership.
        let mut request = RuntimeTerminalRequest {
            slave: None,
            host: std::fs::File::open("/dev/null").unwrap().into(),
            channel: None,
            remote: None,
            identity: [0; 4],
            original: ContentDigest::sha256(b"policy-only"),
            guard: None,
            restored: false,
            active: false,
            settled: false,
            monitor: None,
            namespace: None,
            control: None,
            execution_guardian: Some(GuardianIdentity {
                pid: 42,
                uid: 1000,
                gid: 1000,
                device: 1,
                inode: 2,
            }),
        };
        assert!(request.finish_after_monitor().is_err());
        let root = std::fs::File::open("/dev/null").unwrap();
        assert!(request.own_namespace(root.as_fd()).is_err());
        assert!(request.namespace.is_none());
        assert!(!request.settled);
        // Only the authenticated custody S path or typed final observation sets it.
        request.settled = true;
        request.finish_after_monitor().unwrap();
    }
}

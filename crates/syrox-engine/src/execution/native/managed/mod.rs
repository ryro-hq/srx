use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::process::ExitStatus;
use std::time::Instant;

use super::{WorkerRequest, checked, process, signals::SignalFd};
use crate::cancellation::Cancellation;
mod preparation;

pub(crate) struct ManagedRuntime {
    // Drop settles the namespace before releasing other runtime state.
    child: process::NamespaceChild,
    _root: tempfile::TempDir,
    gate: Option<UnixStream>,
    executed: UnixStream,
    preparation: Option<preparation::Receiver>,
    prepared: bool,
    signals: SignalFd,
}

/// # Safety
/// Dedicated single-threaded worker only; it must exit after this lifecycle.
/// The clone child cannot return or run copied owners' destructors.
pub(crate) unsafe fn prepare_managed_runtime(
    request: &WorkerRequest,
) -> io::Result<ManagedRuntime> {
    if request.terminal.is_some() {
        return Err(io::Error::other(
            "managed services do not own an interactive terminal",
        ));
    }
    let signals = SignalFd::new()?;
    if signals.stop_pending()? {
        return Err(io::Error::other(
            "service stopped before namespace creation",
        ));
    }
    // SAFETY: user-namespace mutation in the dedicated single-threaded worker.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    super::environment::validate_uid(uid)?;
    super::environment::validate_request(request)?;
    let null = super::environment::open_null()?;
    checked(unsafe { libc::unshare(libc::CLONE_NEWUSER) }.into())?;
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1"))?;
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1"))?;
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let parent = crate::platform::linux::fd::pidfd_open(std::process::id())?;
    let (gate, gate_reader) = UnixStream::pair()?;
    let (executed, executed_writer) = UnixStream::pair()?;
    executed.set_nonblocking(true)?;
    let (preparation, preparation_writer) = preparation::pair()?;
    // SAFETY: caller guarantees a single-threaded worker; init always _exit.
    let child = match unsafe { process::spawn()? } {
        process::Spawn::Init => {
            drop(gate);
            drop(executed);
            drop(preparation);
            init_process(
                parent.as_fd(),
                gate_reader,
                (executed_writer, preparation_writer),
                root.path(),
                request,
                signals.original(),
                null,
            );
        }
        process::Spawn::Monitor(child) => child,
    };
    drop((
        gate_reader,
        executed_writer,
        preparation_writer,
        parent,
        null,
    ));
    Ok(ManagedRuntime {
        child,
        _root: root,
        gate: Some(gate),
        executed,
        preparation: Some(preparation),
        prepared: false,
        signals,
    })
}
impl ManagedRuntime {
    pub(crate) fn wait_prepared(
        &mut self,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        let receiver = self.preparation.take().ok_or_else(|| {
            io::Error::other("namespace preparation acknowledgement already consumed")
        })?;
        if let Err(error) = receiver.wait(deadline, cancellation, || {
            if self.signals.stop_pending()? {
                return Err(io::Error::other(
                    "service stopped before namespace preparation",
                ));
            }
            Ok(())
        }) {
            if let Some(status) = self.child.try_wait()? {
                return Err(io::Error::other(format!(
                    "{error}; namespace status: {status}"
                )));
            }
            return Err(error);
        }
        if super::ready(self.child.pidfd(), 0)? {
            return Err(io::Error::other(
                "namespace exited after preparation acknowledgement",
            ));
        }
        self.prepared = true;
        Ok(())
    }
    pub(crate) fn namespace(&self) -> BorrowedFd<'_> {
        self.child.pidfd()
    }
    /// Release only after journal admission, retained namespace pidfd and FD
    /// store observation. Success proves exec, not application-level readiness.
    pub(crate) fn authorize(
        &mut self,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        self.release_gate(deadline, cancellation)?;
        self.await_exec(deadline, cancellation)
    }
    /// One bounded gate write, suitable for a durable authority lock callback.
    pub(crate) fn release_gate(
        &mut self,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        check(deadline, cancellation)?;
        if !self.prepared {
            return Err(io::Error::other(
                "namespace preparation is not acknowledged",
            ));
        }
        if self.signals.stop_pending()? {
            return Err(io::Error::other(
                "service stopped before payload authorization",
            ));
        }
        let mut gate = self
            .gate
            .take()
            .ok_or_else(|| io::Error::other("payload already authorized"))?;
        gate.write_all(b"x")?;
        drop(gate);
        Ok(())
    }
    /// Observe exec acknowledgement outside the journal authority lock.
    pub(crate) fn await_exec(
        &mut self,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        if self.gate.is_some() {
            return Err(io::Error::other("payload gate is still closed"));
        }
        loop {
            check(deadline, cancellation)?;
            if self.signals.stop_pending()? {
                return Err(io::Error::other(
                    "service stopped before readiness",
                ));
            }
            if super::ready(self.child.pidfd(), 0)? {
                return Err(io::Error::other(
                    "namespace exited before readiness",
                ));
            }
            let mut byte = [0_u8; 1];
            match self.executed.read(&mut byte) {
                Ok(1) if byte == *b"e" => return Ok(()),
                Ok(_) => return Err(io::Error::other("payload exec was not confirmed")),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
            poll(
                &[
                    self.executed.as_fd(),
                    self.child.pidfd(),
                    self.signals.descriptor(),
                ],
                20,
            )?;
        }
    }
    pub(crate) fn wait(&mut self, mut stopping: impl FnMut()) -> io::Result<ExitStatus> {
        if self.gate.is_some() {
            return Err(io::Error::other("payload is not authorized"));
        }
        let mut notified = false;
        loop {
            for _ in 0..64 {
                match self.signals.take()? {
                    None => break,
                    Some(libc::SIGCHLD) => {}
                    Some(signal) => {
                        super::signals::forward_pidfd(self.child.pidfd(), signal)?;
                        if !notified {
                            stopping();
                            notified = true;
                        }
                    }
                }
            }
            if super::ready(self.child.pidfd(), 0)? {
                return self.child.wait();
            }
            poll(
                &[
                    self.child.pidfd(),
                    self.signals.descriptor(),
                ],
                -1,
            )?;
        }
    }
}

pub(super) struct ManagedInit {
    pub signals: SignalFd,
    pub executed: UnixStream,
    pub preparation: preparation::Sender,
}
fn init_process(
    parent: BorrowedFd<'_>,
    gate: UnixStream,
    reports: (UnixStream, preparation::Sender),
    root: &std::path::Path,
    request: &WorkerRequest,
    original: libc::sigset_t,
    null: std::fs::File,
) -> ! {
    let (executed, mut preparation) = reports;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: dedicated namespace init; abrupt monitor death must tear it down.
        let setup = (|| {
            checked(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) }.into())?;
            super::require_live_monitor(parent)?;
            SignalFd::for_init(original)
        })();
        let signals = match setup {
            Ok(signals) => signals,
            Err(error) => {
                let _ = preparation.failed(&error);
                return Err(error);
            }
        };
        super::init_request(
            gate,
            root,
            request,
            Some(ManagedInit {
                signals,
                executed,
                preparation,
            }),
            Some(null),
        )
    }));
    let code = match result {
        Ok(Ok(code)) => code,
        Ok(Err(error)) => {
            eprintln!("error: managed namespace init failed: {error}");
            1
        }
        Err(_) => {
            eprintln!("error: managed namespace init panicked before completion");
            1
        }
    };
    // SAFETY: never unwind into copied coordinator owners after clone.
    unsafe { libc::_exit(code) }
}

pub(super) fn wait_authorization(gate: &mut UnixStream, signals: &SignalFd) -> io::Result<()> {
    loop {
        if signals.stop_pending()? {
            return Err(io::Error::other("namespace launch stopped"));
        }
        if super::ready(gate.as_fd(), 0)? {
            let mut byte = [0];
            gate.read_exact(&mut byte)?;
            return if byte == *b"x" {
                Ok(())
            } else {
                Err(io::Error::other("runtime launch refused"))
            };
        }
        poll(&[gate.as_fd(), signals.descriptor()], -1)?;
    }
}
fn check(deadline: Instant, cancellation: &Cancellation) -> io::Result<()> {
    if cancellation.is_cancelled() {
        return Err(crate::cancellation::cancellation_io());
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "managed runtime startup deadline",
        ));
    }
    Ok(())
}
pub(super) fn poll(descriptors: &[BorrowedFd<'_>], timeout: i32) -> io::Result<()> {
    let mut events: Vec<_> = descriptors
        .iter()
        .map(|fd| libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    // SAFETY: initialized poll entries refer to live borrowed descriptors.
    if unsafe {
        libc::poll(
            events.as_mut_ptr(),
            events
                .len()
                .try_into()
                .expect("bounded poll descriptors"),
            timeout,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_budget_rejects_expiry_and_cancellation_before_gate() {
        let cancellation = Cancellation::default();
        assert!(
            check(
                Instant::now()
                    .checked_sub(std::time::Duration::from_secs(1))
                    .unwrap(),
                &cancellation
            )
            .is_err()
        );
        cancellation.cancel();
        let error = check(
            Instant::now() + std::time::Duration::from_secs(1),
            &cancellation,
        )
        .unwrap_err();
        assert!(crate::cancellation::is_cancellation_io(&error));
    }
}

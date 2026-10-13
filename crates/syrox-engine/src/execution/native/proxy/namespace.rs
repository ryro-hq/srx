use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::process::ExitStatus;
use std::time::Instant;

use crate::cancellation::Cancellation;
use crate::execution::configuration::WorkerRequest;

use super::{Event, ProxyInit};
use crate::execution::native::{checked, environment, process, signals::SignalFd};

pub(in crate::execution::native) struct ProxyNamespace {
    child: process::NamespaceChild,
    _root: tempfile::TempDir,
    gate: Option<UnixStream>,
    channel: UnixStream,
    pending: [u8; 5],
    offset: usize,
    executed: bool,
    exited: bool,
}

/// # Safety
/// Dedicated single-threaded monitor, already in its private user namespace;
/// siblings are created from this external monitor, never from a payload PID
/// namespace. No copied owner may unwind in the clone child.
pub(in crate::execution::native) unsafe fn prepare(
    request: &WorkerRequest,
    stdio: [OwnedFd; 3],
    cwd: OwnedFd,
    original: libc::sigset_t,
    commands: &super::mounts::CommandsMount,
) -> io::Result<ProxyNamespace> {
    for descriptor in &stdio {
        // SAFETY: borrowed live descriptor, scalar query without mutation.
        let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if descriptor.as_raw_fd() < 3 || flags & libc::FD_CLOEXEC == 0 {
            return Err(io::Error::other(
                "proxy stdio must be dedicated CLOEXEC descriptors",
            ));
        }
    }
    environment::validate_uid(crate::platform::linux::fd::real_uid())?;
    environment::validate_request(request)?;
    let null = environment::open_null()?;
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let parent = crate::platform::linux::fd::pidfd_open(std::process::id())?;
    let (gate, reader) = UnixStream::pair()?;
    let (channel, child_channel) = UnixStream::pair()?;
    channel.set_nonblocking(true)?;
    // SAFETY: caller supplies the dedicated external monitor contract.
    let child = match unsafe { process::spawn()? } {
        process::Spawn::Init => {
            drop((gate, channel));
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // SAFETY: fresh PID1; parent death must destroy its namespace.
                checked(
                    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) }.into(),
                )?;
                crate::execution::native::require_live_monitor(parent.as_fd())?;
                let signals = SignalFd::for_init(original)?;
                crate::execution::native::init_request_impl(
                    reader,
                    root.path(),
                    request,
                    None,
                    Some(null),
                    Some(ProxyInit {
                        channel: child_channel,
                        signals,
                        stdio,
                        cwd: Some(cwd),
                    }),
                    Some(commands),
                )
            }));
            let code = match outcome {
                Ok(Ok(code)) => code,
                _ => 1,
            };
            // SAFETY: do not run copied external monitor owners' destructors.
            unsafe { libc::_exit(code) }
        }
        process::Spawn::Monitor(child) => child,
    };
    drop((reader, child_channel, stdio, cwd, parent, null));
    Ok(ProxyNamespace {
        child,
        _root: root,
        gate: Some(gate),
        channel,
        pending: [0; 5],
        offset: 0,
        executed: false,
        exited: false,
    })
}

impl ProxyNamespace {
    pub(in crate::execution::native) fn pidfd(&self) -> BorrowedFd<'_> {
        self.child.pidfd()
    }

    /// The caller must have completed session admission and IO readiness. This
    /// single-use local gate itself grants no session authority.
    pub(in crate::execution::native) fn release(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        let mut gate = self
            .gate
            .take()
            .ok_or_else(|| io::Error::other("proxy gate already consumed"))?;
        if cancel.is_cancelled() {
            return Err(crate::cancellation::cancellation_io());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "proxy admission expired",
            ));
        }
        gate.write_all(b"x")
    }

    pub(in crate::execution::native) fn event(&mut self) -> io::Result<Option<Event>> {
        loop {
            match self
                .channel
                .read(&mut self.pending[self.offset..])
            {
                Ok(0) if self.exited && self.offset == 0 => return Ok(None),
                Ok(0) => {
                    return Err(io::Error::other(
                        "proxy init ended without complete status",
                    ));
                }
                Ok(count) => self.offset += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error),
            }
            if self.offset == self.pending.len() {
                let event = Event::decode(self.pending)?;
                self.offset = 0;
                if self.exited
                    || (!self.executed && event != Event::Exec)
                    || (self.executed && event == Event::Exec)
                {
                    return Err(io::Error::other(
                        "proxy init event order violated",
                    ));
                }
                self.executed |= event == Event::Exec;
                self.exited |= matches!(event, Event::Exited(_));
                return Ok(Some(event));
            }
        }
    }

    pub(in crate::execution::native) fn signal(&mut self, signal: i32) -> io::Result<()> {
        if !self.executed || self.exited || !(1..=64).contains(&signal) {
            return Err(io::Error::other("invalid proxy signal phase"));
        }
        self.channel
            .write_all(&[u8::try_from(signal).expect("validated signal")])
    }

    pub(in crate::execution::native) fn try_settled(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
}

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
    status: StatusChannel,
}

struct StatusChannel {
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
                Ok(Err(error)) => {
                    let message = format!("error: command namespace init: {error}\n");
                    let _ = io::stderr().lock().write_all(message.as_bytes());
                    1
                }
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
        status: StatusChannel::new(channel),
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
        self.status.event()
    }

    pub(in crate::execution::native) fn signal(&mut self, signal: i32) -> io::Result<()> {
        if !self.status.executed || self.status.exited || !(1..=64).contains(&signal) {
            return Err(io::Error::other("invalid proxy signal phase"));
        }
        self.status
            .channel
            .write_all(&[u8::try_from(signal).expect("validated signal")])
    }

    pub(in crate::execution::native) fn try_settled(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
}

impl StatusChannel {
    fn new(channel: UnixStream) -> Self {
        Self {
            channel,
            pending: [0; 5],
            offset: 0,
            executed: false,
            exited: false,
        }
    }
    fn event(&mut self) -> io::Result<Option<Event>> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt as _;

    fn channel() -> (StatusChannel, UnixStream) {
        let (reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        (StatusChannel::new(reader), writer)
    }
    #[test]
    fn eof_without_valid_exit_status_is_failure() {
        for prefix in [vec![], Event::Exec.encode().to_vec()] {
            let (mut reader, mut writer) = channel();
            writer.write_all(&prefix).unwrap();
            drop(writer);
            if !prefix.is_empty() {
                assert_eq!(reader.event().unwrap(), Some(Event::Exec));
            }
            assert!(reader.event().is_err());
        }
    }
    #[test]
    fn partial_exit_and_exit_before_exec_are_refused() {
        let (mut reader, mut writer) = channel();
        writer
            .write_all(&Event::Exited(ExitStatus::from_raw(0)).encode())
            .unwrap();
        assert!(reader.event().is_err());
        let (mut reader, mut writer) = channel();
        writer.write_all(&Event::Exec.encode()).unwrap();
        writer
            .write_all(&Event::Exited(ExitStatus::from_raw(0)).encode()[..3])
            .unwrap();
        drop(writer);
        assert_eq!(reader.event().unwrap(), Some(Event::Exec));
        assert!(reader.event().is_err());
    }
    #[test]
    fn authenticated_exit_can_arrive_before_init_closes_channel() {
        let (mut reader, mut writer) = channel();
        let status = ExitStatus::from_raw(7 << 8);
        writer.write_all(&Event::Exec.encode()).unwrap();
        writer
            .write_all(&Event::Exited(status).encode())
            .unwrap();
        assert_eq!(reader.event().unwrap(), Some(Event::Exec));
        assert_eq!(
            reader.event().unwrap(),
            Some(Event::Exited(status))
        );
        assert!(reader.event().unwrap().is_none());
        drop(writer);
        assert!(reader.event().unwrap().is_none());
    }
}

use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

use super::signals::{SignalFd, forward_proxy_group};

pub(super) mod broker;
pub(super) mod custodian;
pub(super) mod entry;
pub(super) mod invocation;
pub(super) mod mounts;
pub(super) mod namespace;
pub(super) mod settlement;
pub(super) mod stdio;

pub(super) struct ProxyInit {
    pub(super) channel: UnixStream,
    pub(super) signals: SignalFd,
    pub(super) stdio: [OwnedFd; 3],
    pub(super) cwd: Option<OwnedFd>,
}
impl ProxyInit {
    pub(super) fn enter_directory(&mut self, path: &std::path::Path) -> io::Result<()> {
        let expected = self
            .cwd
            .take()
            .ok_or_else(|| io::Error::other("proxy cwd already consumed"))?;
        let directory = crate::platform::linux::fd::open_top_directory(path)
            .map_err(|_| io::Error::other("proxy cwd cannot be opened inside namespace"))?;
        if directory.metadata().identity()
            != crate::platform::linux::fd::metadata(expected.as_fd())?.identity()
        {
            return Err(io::Error::other("proxy cwd identity changed"));
        }
        // SAFETY: this descriptor was opened under the new namespace root;
        // never enter the retained host directory descriptor directly.
        super::checked(unsafe { libc::fchdir(directory.fd().as_raw_fd()) }.into())?;
        Ok(())
    }

    pub(super) fn descriptors(&self) -> Vec<i32> {
        let mut descriptors = self.stdio().to_vec();
        descriptors.extend([
            self.channel.as_raw_fd(),
            self.signals.descriptor().as_raw_fd(),
        ]);
        descriptors
    }
    pub(super) fn stdio(&self) -> [i32; 3] {
        self.stdio.each_ref().map(AsRawFd::as_raw_fd)
    }
    pub(super) fn original(&self) -> libc::sigset_t {
        self.signals.original()
    }
    pub(super) fn wait(self, child: Child) -> io::Result<ExitStatus> {
        drop(self.stdio);
        wait_payload(child, self.channel, &self.signals)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Event {
    Exec,
    Stopped(i32),
    Continued,
    Exited(ExitStatus),
}

impl Event {
    fn encode(self) -> [u8; 5] {
        let (tag, value) = match self {
            Self::Exec => (b'e', 0),
            Self::Stopped(signal) => (b's', signal),
            Self::Continued => (b'c', 0),
            Self::Exited(status) => (b'x', status.into_raw()),
        };
        let mut bytes = [0; 5];
        bytes[0] = tag;
        bytes[1..].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    pub(super) fn decode(bytes: [u8; 5]) -> io::Result<Self> {
        let value = i32::from_le_bytes(bytes[1..].try_into().expect("fixed event"));
        match (bytes[0], value) {
            (b'e', 0) => Ok(Self::Exec),
            (b'c', 0) => Ok(Self::Continued),
            (b's', 1..=64) => Ok(Self::Stopped(value)),
            (b'x', _) if libc::WIFEXITED(value) || libc::WIFSIGNALED(value) => {
                Ok(Self::Exited(ExitStatus::from_raw(value)))
            }
            _ => Err(io::Error::other("invalid private proxy event")),
        }
    }
}

/// The sole waiter in namespace PID1. Reporting a principal's exit is separate
/// from the broker's later namespace pidfd/reap settlement proof.
pub(super) fn wait_payload(
    mut child: Child,
    mut channel: UnixStream,
    signals: &SignalFd,
) -> io::Result<ExitStatus> {
    let main = i32::try_from(child.id()).expect("kernel pid_t");
    channel.set_nonblocking(true)?;
    let mut main_reaped = false;
    let result = (|| {
        send(&mut channel, Event::Exec)?;
        loop {
            if let Some(status) = reap(main, &mut channel, &mut main_reaped)? {
                return Ok(status);
            }
            for _ in 0..64 {
                match signals.take()? {
                    None => break,
                    Some(libc::SIGCHLD) => {}
                    Some(signal) => forward_proxy_group(main, signal)?,
                }
            }
            let mut command = [0_u8];
            match channel.read(&mut command) {
                Ok(0) => return Err(io::Error::other("command broker disconnected")),
                Ok(1) if (1..=64).contains(&command[0]) => {
                    forward_proxy_group(main, i32::from(command[0]))?;
                }
                Ok(_) => return Err(io::Error::other("invalid command broker signal")),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
            super::managed::poll(&[channel.as_fd(), signals.descriptor()], 25)?;
        }
    })();
    if result.is_err() && !main_reaped {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

fn reap(
    main: i32,
    channel: &mut UnixStream,
    main_reaped: &mut bool,
) -> io::Result<Option<ExitStatus>> {
    loop {
        let mut status = 0;
        // SAFETY: dedicated namespace init is the sole waiter of its children.
        let pid = unsafe {
            libc::waitpid(
                -1,
                &raw mut status,
                libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED,
            )
        };
        if pid == 0 {
            return Ok(None);
        }
        if pid < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if pid != main {
            continue;
        }
        let event = if libc::WIFSTOPPED(status) {
            Event::Stopped(libc::WSTOPSIG(status))
        } else if libc::WIFCONTINUED(status) {
            Event::Continued
        } else {
            *main_reaped = true;
            Event::Exited(ExitStatus::from_raw(status))
        };
        send(channel, event)?;
        if let Event::Exited(status) = event {
            return Ok(Some(status));
        }
    }
}

fn send(channel: &mut UnixStream, event: Event) -> io::Result<()> {
    let bytes = event.encode();
    let mut offset = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "command broker stopped consuming events",
            ));
        }
        match channel.write(&bytes[offset..]) {
            Ok(0) => return Err(io::Error::other("command broker closed events")),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let mut item = libc::pollfd {
                    fd: channel.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: one live descriptor and initialized poll entry.
                if unsafe { libc::poll(&raw mut item, 1, 25) } < 0
                    && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

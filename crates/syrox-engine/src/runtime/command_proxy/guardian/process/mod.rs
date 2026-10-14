#![allow(unsafe_code)]
use super::{ForegroundRelayIo, child, custody::Custody, local::LocalChannel, wire::Event};
use crate::execution::transport::{PacketChannel, Peer};
use crate::platform::linux::fd::terminal::{
    RelayControl, RelayExit, RelayOptions, relay_controlled,
};
use crate::runtime::command_proxy::{
    frontend::PreparedProxyFrontend, namespace_handoff::NamespaceHandoff, wire::CommandProxyExit,
};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd};
use std::io;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::time::{Duration, Instant};

mod pause;

const HANDSHAKE: Duration = Duration::from_secs(15);

/// # Safety
/// Call only in the dedicated single-threaded worker before creating threads.
/// It changes process signal/job-control state. Every child closes its public
/// channels and waits for namespace exit before attempting restoration.
pub(crate) unsafe fn run(
    prepared: PreparedProxyFrontend,
    cancel: &Cancellation,
) -> io::Result<CommandProxyExit> {
    let (snapshot, relay) = prepared.prepare_guardian_io(cancel)?.into_parts();
    let [pid, session, group] = crate::execution::native::terminal_custody::frontend_identity()?;
    let parent = linux_fd::pidfd_open(pid)?;
    let pinned_group = linux_fd::PinnedProcessGroup::capture(pid)?;
    let (retirement_read, retirement_write) = retirement_pipe()?;
    let (frontend, guardian) = PacketChannel::pair()?;
    // SAFETY: caller guarantees dedicated single-threaded worker; all owned
    // descriptors are split explicitly in the two address spaces below.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if child_pid == 0 {
        drop(frontend);
        drop(retirement_write);
        drop(relay);
        // SAFETY: isolated fork child never returns to the caller or executes
        // payload code. It owns a new background pgrp in the inherited SID.
        let result = unsafe { background() }.and_then(|()| {
            let custody = snapshot
                .map(|snapshot| Custody::new(snapshot, session, group))
                .transpose()?;
            let channel = LocalChannel::new(guardian, peer(pid))?;
            let mut wakeup = child::Wakeup::new(pinned_group, retirement_read, parent);
            child::run(
                &prepared,
                channel,
                &mut wakeup,
                custody.as_ref(),
                pid,
            )
        });
        // SAFETY: lifecycle above already performed explicit namespace/tty
        // cleanup. No inherited Rust destructors may run a second time.
        unsafe {
            libc::_exit(if result.is_ok() {
                0
            } else {
                125
            })
        };
    }
    drop(guardian);
    drop(retirement_read);
    drop(pinned_group);
    drop(parent);
    drop(snapshot);
    drop(prepared);
    // Install ownership before any fallible post-fork observation. The child
    // remains our unreaped direct child even if pidfd_open fails.
    let mut process = GuardianProcess {
        child: child_pid,
        channel: None,
        pidfd: None,
        reaped: false,
        retirement: Some(retirement_write),
    };
    let setup = (|| {
        let child = u32::try_from(child_pid).map_err(io::Error::other)?;
        process.pidfd = Some(linux_fd::pidfd_open(child)?);
        process.channel = Some(LocalChannel::new(frontend, peer(child))?);
        Ok(())
    })();
    let result = setup.and_then(|()| {
        wrapper(
            process.channel.as_mut().expect("local channel"),
            relay,
            cancel,
        )
    });
    process.channel.take();
    let cleanup = process.finish();
    combine(result, cleanup)
}
struct GuardianProcess {
    child: libc::pid_t,
    channel: Option<LocalChannel>,
    pidfd: Option<OwnedFd>,
    reaped: bool,
    retirement: Option<OwnedFd>,
}
impl GuardianProcess {
    fn finish(&mut self) -> io::Result<()> {
        // Irrevocably leave every possible SIGSTOP path before waiting on child.
        self.retirement.take();
        self.channel.take();
        if self.reaped {
            return Ok(());
        }
        // No numeric signal is sent. waitpid refers only to this dedicated
        // process's unreaped direct child, so a reused PID cannot be adopted.
        loop {
            let mut status = 0;
            // SAFETY: status is writable; no other thread/handler owns this
            // direct child's wait status under run's dedicated-worker contract.
            let result = unsafe { libc::waitpid(self.child, &raw mut status, 0) };
            if result == self.child {
                self.reaped = true;
                return validate_guardian_status(status);
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                self.reaped = true;
            }
            return Err(error);
        }
    }
}
impl Drop for GuardianProcess {
    fn drop(&mut self) {
        self.channel.take();
        let _ = self.finish();
    }
}
fn validate_guardian_status(status: i32) -> io::Result<()> {
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        Ok(())
    } else {
        Err(io::Error::other(
            "guardian cleanup did not complete successfully",
        ))
    }
}
fn combine<T>(result: io::Result<T>, cleanup: io::Result<()>) -> io::Result<T> {
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(io::Error::other(format!(
            "wrapper failed: {primary}; guardian cleanup failed: {cleanup}"
        ))),
    }
}

fn peer(pid: u32) -> Peer {
    // SAFETY: read-only credentials of the dedicated process.
    Peer {
        pid,
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    }
}
unsafe fn background() -> io::Result<()> {
    // SAFETY: only the dedicated fork child changes its pgrp and signal mask.
    unsafe {
        if libc::setpgid(0, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        for signal in [
            libc::SIGTTOU,
            libc::SIGTTIN,
            libc::SIGTSTP,
        ] {
            libc::sigaddset(&raw mut set, signal);
        }
        if libc::sigprocmask(
            libc::SIG_BLOCK,
            &raw const set,
            std::ptr::null_mut(),
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
fn wrapper(
    channel: &mut LocalChannel,
    relay: Option<ForegroundRelayIo>,
    cancel: &Cancellation,
) -> io::Result<CommandProxyExit> {
    let deadline = Instant::now() + HANDSHAKE;
    let (event, descriptors) = wait(
        channel,
        1 + usize::from(relay.is_some()),
        cancel,
        Some(deadline),
    )?;
    if event
        != (Event::Prepared {
            terminal: relay.is_some(),
        })
    {
        return Err(invalid());
    }
    let mut namespace = NamespaceHandoff::new(descriptors, relay.is_some())?;
    channel.send(&Event::RelayReady, &[], cancel, deadline)?;
    if wait(channel, 0, cancel, Some(deadline))?.0 != Event::RelayReady {
        return Err(invalid());
    }
    let mut state = WrapperState::default();
    if let Some(relay) = relay {
        let master = namespace.take_master().ok_or_else(invalid)?;
        linux_fd::terminal::validate_master(master.as_fd())?;
        let token = Cancellation::default();
        let result = relay_controlled(
            master.as_fd(),
            relay.input.as_ref().map(AsFd::as_fd),
            relay.output.as_fd(),
            RelayOptions {
                buffer_bytes: 64 * 1024,
                deadline: None,
                forward_resize: true,
            },
            &token,
            || {
                cancel
                    .check()
                    .map_err(|_| crate::cancellation::cancellation_io())?;
                state.tick(
                    channel,
                    &namespace,
                    Some(relay.output.as_fd()),
                    cancel,
                )?;
                if state
                    .drain
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "command terminal drain timed out",
                    ));
                }
                Ok(if state.settled {
                    RelayControl::Drain
                } else {
                    RelayControl::Continue
                })
            },
        )?;
        if result.reason != RelayExit::PtyClosed {
            return Err(invalid());
        }
    }
    while !state.settled {
        let event = wait(channel, 0, cancel, None)?.0;
        state.accept(channel, &event, &namespace, None, cancel)?;
    }
    channel.send(
        &Event::Drained,
        &[],
        cancel,
        Instant::now() + HANDSHAKE,
    )?;
    while state.exit.is_none() {
        let event = wait(
            channel,
            0,
            cancel,
            Some(Instant::now() + HANDSHAKE),
        )?
        .0;
        state.accept(channel, &event, &namespace, None, cancel)?;
    }
    if !state.restored {
        return Err(invalid());
    }
    state.exit.ok_or_else(invalid)
}
#[derive(Default)]
struct WrapperState {
    settled: bool,
    restored: bool,
    drain: Option<Instant>,
    exit: Option<CommandProxyExit>,
    pause: u64,
}
impl WrapperState {
    fn tick(
        &mut self,
        channel: &mut LocalChannel,
        namespace: &NamespaceHandoff,
        terminal: Option<BorrowedFd<'_>>,
        cancel: &Cancellation,
    ) -> io::Result<()> {
        if let Some((event, _)) = channel.poll(0)? {
            self.accept(channel, &event, namespace, terminal, cancel)?;
        }
        Ok(())
    }
    fn accept(
        &mut self,
        channel: &mut LocalChannel,
        event: &Event,
        namespace: &NamespaceHandoff,
        terminal: Option<BorrowedFd<'_>>,
        cancel: &Cancellation,
    ) -> io::Result<()> {
        match event {
            Event::NamespaceSettled if !self.settled && namespace.settled()? => self.settled(),
            Event::Restored if self.settled && !self.restored => self.restored = true,
            Event::Finished(exit) if self.restored && self.exit.is_none() => {
                self.exit = Some(*exit);
            }
            Event::StopPreparing {
                pause,
                signal,
            } if !self.settled && self.pause.checked_add(1) == Some(*pause) => {
                self.pause = *pause;
                if pause::run(
                    channel, namespace, terminal, *pause, *signal, cancel,
                )? {
                    self.settled();
                }
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
    fn settled(&mut self) {
        self.settled = true;
        self.drain = Some(Instant::now() + Duration::from_secs(30));
    }
}
fn retirement_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: two writable slots; success transfers unique CLOEXEC descriptors.
    if unsafe {
        libc::pipe2(
            fds.as_mut_ptr(),
            libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pipe2 returned distinct owned descriptors.
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(fds[0]),
            OwnedFd::from_raw_fd(fds[1]),
        )
    })
}

fn wait(
    channel: &mut LocalChannel,
    fds: usize,
    cancel: &Cancellation,
    deadline: Option<Instant>,
) -> io::Result<(Event, Vec<OwnedFd>)> {
    loop {
        cancel
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local guardian timed out",
            ));
        }
        if let Some(message) = channel.poll(fds)? {
            return Ok(message);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
pub(super) fn readable(fd: BorrowedFd<'_>, millis: i32) -> io::Result<bool> {
    let mut event = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: event is writable and fd remains borrowed during bounded poll.
    let result = unsafe { libc::poll(&raw mut event, 1, millis) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(result > 0)
}
fn invalid() -> io::Error {
    io::Error::other("invalid local wrapper phase")
}

#[cfg(test)]
mod tests {
    use super::{GuardianProcess, combine, validate_guardian_status};
    use std::io;

    #[test]
    fn guardian_failure_is_not_hidden_by_a_successful_remote_exit() {
        assert!(validate_guardian_status(0).is_ok());
        assert!(validate_guardian_status(125 << 8).is_err());
        assert!(validate_guardian_status(libc::SIGKILL).is_err());
        assert!(combine(Ok(37), validate_guardian_status(125 << 8)).is_err());
        let error = combine::<()>(
            Err(io::Error::other("primary")),
            Err(io::Error::other("cleanup")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("primary"));
        assert!(error.to_string().contains("cleanup"));
    }
    #[test]
    fn post_fork_guard_reaps_its_child_even_before_pidfd_acquisition() {
        // SAFETY: the child executes only async-signal-safe _exit, without Rust
        // allocation/destructors; this does not run the production guardian in
        // a multithreaded test process.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // SAFETY: direct fork child terminates immediately, no shared locks.
            unsafe { libc::_exit(0) };
        }
        let mut guard = GuardianProcess {
            child,
            channel: None,
            pidfd: None,
            reaped: false,
            retirement: None,
        };
        guard.finish().unwrap();
        assert!(guard.reaped);
        // SAFETY: only querying our already-reaped child; no numeric signalling.
        assert_eq!(
            unsafe { libc::waitpid(child, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
    #[test]
    fn retirement_writer_is_closed_before_waiting_for_guardian() {
        use std::os::fd::AsRawFd as _;
        let (reader, writer) = super::retirement_pipe().unwrap();
        // SAFETY: child uses only close/poll/read/_exit; no Rust allocation or
        // destructors after fork in this multithreaded test harness.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // SAFETY: fork-private descriptors; bounded poll catches ordering
            // regressions without leaving the test indefinitely blocked.
            unsafe {
                libc::close(writer.as_raw_fd());
                let mut poll = libc::pollfd {
                    fd: reader.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let result = libc::poll(&raw mut poll, 1, 2000);
                let mut byte = 0_u8;
                let eof =
                    result > 0 && libc::read(reader.as_raw_fd(), (&raw mut byte).cast(), 1) == 0;
                libc::_exit(if eof {
                    0
                } else {
                    125
                });
            }
        }
        drop(reader);
        let mut process = GuardianProcess {
            child,
            channel: None,
            pidfd: None,
            reaped: false,
            retirement: Some(writer),
        };
        process.finish().unwrap();
        assert!(process.retirement.is_none());
        assert!(process.reaped);
    }
}

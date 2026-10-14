use super::{Event, HANDSHAKE, LocalChannel, invalid, wait};
use crate::cancellation::Cancellation;
use crate::platform::linux::fd::terminal::{ForegroundPauseOutcome, suspend_foreground_observed};
use crate::runtime::command_proxy::namespace_handoff::NamespaceHandoff;
use std::io;
use std::os::fd::BorrowedFd;
use std::time::Instant;

pub(super) fn run(
    channel: &mut LocalChannel,
    namespace: &NamespaceHandoff,
    terminal: Option<BorrowedFd<'_>>,
    pause: u64,
    signal: i32,
    cancel: &Cancellation,
) -> io::Result<bool> {
    channel.send(
        &Event::RelayPaused {
            pause,
        },
        &[],
        cancel,
        Instant::now() + HANDSHAKE,
    )?;
    let (event, _) = wait(
        channel,
        0,
        cancel,
        Some(Instant::now() + HANDSHAKE),
    )?;
    if event == Event::NamespaceSettled {
        namespace_exited(namespace)?;
        abandon(channel, pause, cancel)?;
        return Ok(true);
    }
    if event
        != (Event::StopReady {
            pause,
            signal,
        })
    {
        return Err(invalid());
    }
    // Drain immediately queued settlement before acting, and use the pidfd to
    // detect exit even before the corresponding broker event is delivered.
    if let Some((event, _)) = channel.poll(0)? {
        if event != Event::NamespaceSettled {
            return Err(invalid());
        }
        namespace_exited(namespace)?;
        abandon(channel, pause, cancel)?;
        return Ok(true);
    }
    let outcome = suspend(namespace, terminal, cancel)?;
    if outcome == ForegroundPauseOutcome::Abandoned {
        abandon(channel, pause, cancel)?;
        return await_settlement(channel, namespace, pause, cancel);
    }
    // Sending Resume irrevocably retires this STOP, even if exit beats its ACK.
    channel.send(
        &Event::Resume {
            pause,
        },
        &[],
        cancel,
        Instant::now() + HANDSHAKE,
    )?;
    match wait(
        channel,
        0,
        cancel,
        Some(Instant::now() + HANDSHAKE),
    )?
    .0
    {
        Event::ResumeReady {
            pause: actual,
        } if actual == pause => {
            if namespace.settled()? {
                await_settlement(channel, namespace, pause, cancel)
            } else {
                Ok(false)
            }
        }
        Event::NamespaceSettled => {
            namespace_exited(namespace)?;
            Ok(true)
        }
        _ => Err(invalid()),
    }
}
fn abandon(channel: &mut LocalChannel, pause: u64, cancel: &Cancellation) -> io::Result<()> {
    channel.send(
        &Event::Abandoned {
            pause,
        },
        &[],
        cancel,
        Instant::now() + HANDSHAKE,
    )
}
fn await_settlement(
    channel: &mut LocalChannel,
    namespace: &NamespaceHandoff,
    pause: u64,
    cancel: &Cancellation,
) -> io::Result<bool> {
    loop {
        match wait(
            channel,
            0,
            cancel,
            Some(Instant::now() + HANDSHAKE),
        )?
        .0
        {
            Event::NamespaceSettled => {
                namespace_exited(namespace)?;
                return Ok(true);
            }
            Event::ResumeReady {
                pause: actual,
            } if actual == pause => {}
            _ => return Err(invalid()),
        }
    }
}
fn namespace_exited(namespace: &NamespaceHandoff) -> io::Result<()> {
    if namespace.settled()? {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn suspend(
    namespace: &NamespaceHandoff,
    terminal: Option<BorrowedFd<'_>>,
    cancel: &Cancellation,
) -> io::Result<ForegroundPauseOutcome> {
    if let Some(terminal) = terminal {
        return suspend_foreground_observed(terminal, namespace.pidfd(), cancel);
    }
    cancel
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())?;
    if namespace.settled()? {
        return Ok(ForegroundPauseOutcome::Abandoned);
    }
    // SAFETY: dedicated wrapper stops only its original process group. The
    // background guardian has armed a pinned group wakeup before StopReady.
    if unsafe { libc::kill(0, libc::SIGSTOP) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if namespace.settled()? {
        Ok(ForegroundPauseOutcome::Abandoned)
    } else {
        Ok(ForegroundPauseOutcome::Resumed)
    }
}

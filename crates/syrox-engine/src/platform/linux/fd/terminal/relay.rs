use super::{TerminalAttributes, WindowSize};
use crate::cancellation::Cancellation;
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::{Duration, Instant};

const MAX_BUFFER: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Clone, Copy, Debug)]
pub(crate) struct RelayOptions {
    /// Per direction: at most 64 KiB. Backpressure stops reads at this bound.
    pub buffer_bytes: usize,
    pub deadline: Option<Instant>,
    /// Sample the outer input terminal's window size at most every 20 ms.
    pub forward_resize: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayExit {
    PtyClosed,
    InputClosed,
    OutputClosed,
    Cancelled,
    Deadline,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelayResult {
    pub reason: RelayExit,
    pub bytes_to_payload: u64,
    pub bytes_to_terminal: u64,
    /// Returning for cancellation/hangup/deadline can leave unsent bytes.
    pub pending_input: usize,
    pub pending_output: usize,
}

/// Relay an actual terminal. Pipes/redirection belong to noninteractive mode.
/// Ctrl-C/Ctrl-Z are ordinary bytes; the slave's line discipline owns signals.
/// Input loss returns immediately so the session owner can revoke/stop. Slave
/// closure drains already received output until completion or the given deadline.
#[cfg(test)]
pub(crate) fn relay(
    master: BorrowedFd<'_>,
    input: BorrowedFd<'_>,
    output: BorrowedFd<'_>,
    options: RelayOptions,
    cancellation: &Cancellation,
) -> io::Result<RelayResult> {
    relay_with_tick(
        master,
        input,
        output,
        options,
        cancellation,
        || Ok(()),
    )
}

/// A bounded poll hook lets the session propagate operational signals and
/// consume custody events without mutating the caller's signal token.
#[cfg(test)]
pub(crate) fn relay_with_tick(
    master: BorrowedFd<'_>,
    input: BorrowedFd<'_>,
    output: BorrowedFd<'_>,
    options: RelayOptions,
    cancellation: &Cancellation,
    tick: impl FnMut() -> io::Result<()>,
) -> io::Result<RelayResult> {
    relay_optional_input_with_tick(
        master,
        Some(input),
        output,
        options,
        cancellation,
        tick,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayControl {
    Continue,
    Drain,
}

/// Redirected stdin is delivered directly to the sibling process. None means
/// this relay never reads it; resize still comes from the output terminal.
#[cfg(test)]
pub(crate) fn relay_optional_input_with_tick(
    master: BorrowedFd<'_>,
    input: Option<BorrowedFd<'_>>,
    output: BorrowedFd<'_>,
    options: RelayOptions,
    cancellation: &Cancellation,
    mut tick: impl FnMut() -> io::Result<()>,
) -> io::Result<RelayResult> {
    relay_controlled(
        master,
        input,
        output,
        options,
        cancellation,
        || {
            tick()?;
            Ok(RelayControl::Continue)
        },
    )
}

/// Drain is irreversible: stop reading host input and discard queued payload
/// input while retaining buffered output. Caller supplies settlement authority.
pub(crate) fn relay_controlled(
    master: BorrowedFd<'_>,
    mut input: Option<BorrowedFd<'_>>,
    output: BorrowedFd<'_>,
    options: RelayOptions,
    cancellation: &Cancellation,
    mut tick: impl FnMut() -> io::Result<RelayControl>,
) -> io::Result<RelayResult> {
    if !(1..=MAX_BUFFER).contains(&options.buffer_bytes)
        || input.is_some_and(|input| master.as_raw_fd() == input.as_raw_fd())
        || master.as_raw_fd() == output.as_raw_fd()
    {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut index: libc::c_uint = 0;
    // SAFETY: master is live and index is writable; only PTY masters support this ioctl.
    if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCGPTN, &raw mut index) } < 0 {
        return Err(io::Error::last_os_error());
    }
    for fd in [Some(master), input, Some(output)]
        .into_iter()
        .flatten()
    {
        // SAFETY: F_GETFL queries flags of the borrowed live descriptor.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_NONBLOCK == 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
    }
    if let Some(input) = input {
        TerminalAttributes::read(input)?;
    }
    TerminalAttributes::read(output)?;
    let mut pending_input = VecDeque::with_capacity(options.buffer_bytes);
    let mut pending_output = VecDeque::with_capacity(options.buffer_bytes);
    let mut bytes_to_payload = 0_u64;
    let mut bytes_to_terminal = 0_u64;
    let mut pty_closed = false;
    let mut pty_input_closed = false;
    let mut size = None;
    let mut next_resize = Instant::now();
    let reason = loop {
        if tick()? == RelayControl::Drain {
            input = None;
            pending_input.clear();
        }
        if cancellation.is_cancelled() {
            break RelayExit::Cancelled;
        }
        let now = Instant::now();
        if options
            .deadline
            .is_some_and(|deadline| now >= deadline)
        {
            break RelayExit::Deadline;
        }
        if pty_closed && pending_output.is_empty() {
            break RelayExit::PtyClosed;
        }
        if options.forward_resize && now >= next_resize {
            next_resize = now + POLL_INTERVAL;
            let current = WindowSize::read(input.unwrap_or(output))?;
            if size != Some(current) {
                current.apply(master)?;
                size = Some(current);
            }
        }
        let read_input = input.is_some()
            && !pty_closed
            && !pty_input_closed
            && pending_input.len() < options.buffer_bytes;
        let read_master = !pty_closed && pending_output.len() < options.buffer_bytes;
        let mut events = [
            event(
                master,
                read_master,
                !pty_closed && !pty_input_closed && !pending_input.is_empty(),
            ),
            event(input.unwrap_or(output), read_input, false),
            event(output, false, !pending_output.is_empty()),
            libc::pollfd {
                fd: cancellation
                    .wake_fd()
                    .map_or(-1, |fd| fd.as_raw_fd()),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout = options
            .deadline
            .map_or(POLL_INTERVAL, |deadline| {
                deadline
                    .saturating_duration_since(now)
                    .min(POLL_INTERVAL)
            });
        let millis = i32::try_from(timeout.as_millis().max(1)).expect("20 ms poll bound");
        // SAFETY: events has four initialized pollfd records and borrowed fds remain live.
        let polled = unsafe {
            libc::poll(
                events.as_mut_ptr(),
                events.len() as libc::nfds_t,
                millis,
            )
        };
        if polled < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if events
            .iter()
            .any(|event| event.revents & libc::POLLNVAL != 0)
        {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        if events[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            break RelayExit::InputClosed;
        }
        if events[2].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            break RelayExit::OutputClosed;
        }
        if cancellation.is_cancelled() {
            break RelayExit::Cancelled;
        }
        if events[2].revents & libc::POLLOUT != 0 {
            match write(output, &mut pending_output)? {
                IoProgress::Closed => break RelayExit::OutputClosed,
                IoProgress::Bytes(count) => {
                    bytes_to_terminal = bytes_to_terminal.saturating_add(count as u64);
                }
                IoProgress::Blocked => {}
            }
        }
        if events[0].revents & libc::POLLOUT != 0 {
            match write(master, &mut pending_input)? {
                IoProgress::Closed => pty_input_closed = true,
                IoProgress::Bytes(count) => {
                    bytes_to_payload = bytes_to_payload.saturating_add(count as u64);
                }
                IoProgress::Blocked => {}
            }
        }
        if read_master
            && events[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
            && matches!(
                read(master, &mut pending_output, options.buffer_bytes)?,
                IoProgress::Closed
            )
        {
            pty_closed = true;
        }
        if read_input
            && events[1].revents & libc::POLLIN != 0
            && matches!(
                read(
                    input.expect("read_input requires input"),
                    &mut pending_input,
                    options.buffer_bytes
                )?,
                IoProgress::Closed
            )
        {
            break RelayExit::InputClosed;
        }
    };
    Ok(RelayResult {
        reason,
        bytes_to_payload,
        bytes_to_terminal,
        pending_input: pending_input.len(),
        pending_output: pending_output.len(),
    })
}

fn event(fd: BorrowedFd<'_>, read: bool, write: bool) -> libc::pollfd {
    libc::pollfd {
        fd: if read || write {
            fd.as_raw_fd()
        } else {
            -1
        },
        events: if read {
            libc::POLLIN
        } else {
            0
        } | if write {
            libc::POLLOUT
        } else {
            0
        },
        revents: 0,
    }
}

enum IoProgress {
    Bytes(usize),
    Blocked,
    Closed,
}
fn outcome(count: isize) -> io::Result<IoProgress> {
    if count > 0 {
        return Ok(IoProgress::Bytes(
            usize::try_from(count).expect("positive count"),
        ));
    }
    if count == 0 {
        return Ok(IoProgress::Closed);
    }
    let error = io::Error::last_os_error();
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) {
        Ok(IoProgress::Blocked)
    } else if error.raw_os_error() == Some(libc::EIO) {
        Ok(IoProgress::Closed)
    } else {
        Err(error)
    }
}
fn read(fd: BorrowedFd<'_>, buffer: &mut VecDeque<u8>, maximum: usize) -> io::Result<IoProgress> {
    let mut bytes = [0_u8; 4096];
    let count = bytes.len().min(maximum - buffer.len());
    // SAFETY: bytes owns count writable bytes, and fd is a validated nonblocking terminal.
    let progress =
        outcome(unsafe { libc::read(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), count) })?;
    if let IoProgress::Bytes(count) = progress {
        buffer.extend(&bytes[..count]);
    }
    Ok(progress)
}
fn write(fd: BorrowedFd<'_>, buffer: &mut VecDeque<u8>) -> io::Result<IoProgress> {
    let (first, second) = buffer.as_slices();
    let bytes = if first.is_empty() {
        second
    } else {
        first
    };
    // SAFETY: bytes holds its readable length; fd is a validated nonblocking terminal.
    let progress =
        outcome(unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) })?;
    if let IoProgress::Bytes(count) = progress {
        buffer.drain(..count);
    }
    Ok(progress)
}

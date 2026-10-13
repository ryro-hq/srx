use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
#[cfg(test)]
use std::time::Instant;

#[cfg(test)]
use crate::cancellation::Cancellation;
use crate::platform::linux::fd::terminal::{
    Pty, TerminalAttributes, WindowSize, foreground_terminal, independent_terminal,
};

#[cfg(test)]
use crate::platform::linux::fd::terminal::{
    RelayExit, RelayOptions, RelayResult, TerminalGuard, relay,
};

#[derive(Debug)]
/// A dedicated PTY and pinned host terminal, prepared without entering raw mode.
/// Consume with [`crate::deployment::shell::ManagedShell::run_prepared_terminal`] after starting
/// the managed session. Preparation alone neither launches nor owns processes.
pub struct PreparedShellTerminal {
    input: OwnedFd,
    output: OwnedFd,
    master: OwnedFd,
    slave: Option<OwnedFd>,
    attributes: TerminalAttributes,
    device: u32,
}

impl PreparedShellTerminal {
    /// Both descriptors must identify the caller's foreground terminal. Kernel
    /// terminal identity accepts /dev/tty aliases without confusing their device
    /// node inode with the underlying PTY. Redirection belongs to noninteractive
    /// mode. No flags or attributes on the supplied descriptors are modified.
    pub fn prepare(input: BorrowedFd<'_>, output: BorrowedFd<'_>) -> io::Result<Self> {
        let device = foreground_terminal(input)?;
        if foreground_terminal(output)? != device {
            return Err(io::Error::from_raw_os_error(libc::ENOTTY));
        }
        let input = independent_terminal(input)?;
        let output = independent_terminal(output)?;
        let attributes = TerminalAttributes::read(input.as_fd())?;
        let size = WindowSize::read(input.as_fd())?;
        let (master, slave) = Pty::open(size, Some(&attributes))?.into_parts();
        if foreground_terminal(input.as_fd())? != device
            || foreground_terminal(output.as_fd())? != device
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        Ok(Self {
            input,
            output,
            master,
            slave: Some(slave),
            attributes,
            device,
        })
    }

    /// Transfer the sole local slave to the execution owner. Keeping another
    /// slave open would prevent master EOF after the payload exits.
    pub(crate) fn take_slave(&mut self) -> io::Result<OwnedFd> {
        self.slave
            .take()
            .ok_or_else(|| io::Error::other("terminal slave already transferred"))
    }

    // This isolated test helper proves ordinary restoration only. Production
    // activation exists exclusively through execution's custody callback.
    #[cfg(test)]
    fn relay_local(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> io::Result<RelayResult> {
        if foreground_terminal(self.input.as_fd())? != self.device
            || foreground_terminal(self.output.as_fd())? != self.device
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        if !self
            .attributes
            .matches(&TerminalAttributes::read(self.input.as_fd())?)
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let early_exit = if cancellation.is_cancelled() {
            Some(RelayExit::Cancelled)
        } else if Instant::now() >= deadline {
            Some(RelayExit::Deadline)
        } else {
            None
        };
        if let Some(reason) = early_exit {
            return Ok(RelayResult {
                reason,
                bytes_to_payload: 0,
                bytes_to_terminal: 0,
                pending_input: 0,
                pending_output: 0,
            });
        }
        let mut guard = TerminalGuard::enter(self.input.as_fd())?;
        let result = relay(
            self.master.as_fd(),
            self.input.as_fd(),
            self.output.as_fd(),
            RelayOptions {
                buffer_bytes: 64 * 1024,
                deadline: Some(deadline),
                forward_resize: true,
            },
            cancellation,
        );
        let restored = guard.restore();
        match (result, restored) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(restore)) => Err(io::Error::other(format!(
                "terminal relay failed: {error}; restoration failed: {restore}"
            ))),
        }
    }
}

mod execution;

#[cfg(test)]
mod tests;

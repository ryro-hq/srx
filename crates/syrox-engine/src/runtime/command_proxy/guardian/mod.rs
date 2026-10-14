use std::io;
use std::os::fd::{AsFd as _, OwnedFd};

use super::request::AdmittedProxyRequest;
use crate::platform::linux::fd::terminal::{
    TerminalAttributes, foreground_terminal, independent_terminal,
};

mod child;
mod custody;
mod local;
pub(crate) mod process;
pub(crate) mod wire;

pub(crate) struct GuardianIo {
    custody: Option<TerminalSnapshot>,
    relay: Option<ForegroundRelayIo>,
}
pub(crate) struct TerminalSnapshot {
    pub(super) terminal: OwnedFd,
    pub(super) original: TerminalAttributes,
    pub(super) device: u32,
}
pub(crate) struct ForegroundRelayIo {
    // None means stdin is redirected: the broker receives it directly and the
    // wrapper must never also consume it in a terminal relay.
    pub(super) input: Option<OwnedFd>,
    pub(super) output: OwnedFd,
}
impl GuardianIo {
    pub(crate) fn prepare(request: &AdmittedProxyRequest) -> io::Result<Self> {
        let mut source = None;
        let mut input = None;
        for (index, fd) in [
            request.stdin(),
            request.stdout(),
            request.stderr(),
        ]
        .into_iter()
        .enumerate()
        {
            match TerminalAttributes::read(fd) {
                Ok(attributes) => {
                    let device = foreground_terminal(fd)?;
                    if let Some((previous, _, _)) = &source {
                        if *previous != device {
                            return Err(invalid());
                        }
                    } else {
                        source = Some((device, attributes, independent_terminal(fd)?));
                    }
                    if index == 0 {
                        input = Some(independent_terminal(fd)?);
                    }
                }
                Err(error) if error.raw_os_error() == Some(libc::ENOTTY) => {}
                Err(error) => return Err(error),
            }
        }
        let Some((device, original, terminal)) = source else {
            return Ok(Self {
                custody: None,
                relay: None,
            });
        };
        let output = independent_terminal(terminal.as_fd())?;
        if !original.matches(&TerminalAttributes::read(terminal.as_fd())?)
            || foreground_terminal(terminal.as_fd())? != device
        {
            return Err(invalid());
        }
        Ok(Self {
            custody: Some(TerminalSnapshot {
                terminal,
                original,
                device,
            }),
            relay: Some(ForegroundRelayIo {
                input,
                output,
            }),
        })
    }
    /// The dedicated worker splits these owners across its local process
    /// boundary. A custody snapshot is not proof that a guardian is alive.
    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<TerminalSnapshot>,
        Option<ForegroundRelayIo>,
    ) {
        (self.custody, self.relay)
    }
}
fn invalid() -> io::Error {
    io::Error::other("incompatible public command terminals")
}

#[cfg(test)]
mod tests;

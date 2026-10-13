#![allow(unsafe_code)]
use super::TerminalSnapshot;
use crate::platform::linux::fd::terminal::TerminalAttributes;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _};

pub(super) struct Custody {
    snapshot: TerminalSnapshot,
    session: u32,
    group: u32,
}
impl Custody {
    pub(super) fn new(snapshot: TerminalSnapshot, session: u32, group: u32) -> io::Result<Self> {
        let custody = Self {
            snapshot,
            session,
            group,
        };
        custody.identity()?;
        if !custody
            .snapshot
            .original
            .matches(&TerminalAttributes::read(
                custody.snapshot.terminal.as_fd(),
            )?)
        {
            return Err(lost());
        }
        Ok(custody)
    }
    pub(super) fn activate(&self) -> io::Result<()> {
        self.identity()?;
        let current = TerminalAttributes::read(self.snapshot.terminal.as_fd())?;
        if !current.matches(&self.snapshot.original) {
            return Err(lost());
        }
        self.snapshot
            .original
            .raw()
            .apply(self.snapshot.terminal.as_fd())
    }
    pub(super) fn restore(&self) -> io::Result<()> {
        self.terminal_identity()?;
        let current = TerminalAttributes::read(self.snapshot.terminal.as_fd())?;
        if current.matches(&self.snapshot.original) {
            return Ok(());
        }
        if !self.is_foreground()? || !current.matches(&self.snapshot.original.raw()) {
            return Err(lost());
        }
        self.snapshot
            .original
            .apply(self.snapshot.terminal.as_fd())
    }
    pub(super) fn is_foreground(&self) -> io::Result<bool> {
        // SAFETY: read-only ioctl against the still-owned controlling terminal.
        let group = unsafe { libc::tcgetpgrp(self.snapshot.terminal.as_raw_fd()) };
        if group < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(group.cast_unsigned() == self.group)
    }
    fn identity(&self) -> io::Result<()> {
        self.terminal_identity()?;
        if !self.is_foreground()? {
            return Err(lost());
        }
        Ok(())
    }
    fn terminal_identity(&self) -> io::Result<()> {
        let fd = self.snapshot.terminal.as_raw_fd();
        let mut device = 0_u32;
        // SAFETY: same-session read-only identity queries; device is writable.
        if unsafe { libc::getsid(0) }.cast_unsigned() != self.session
            || unsafe { libc::tcgetsid(fd) }.cast_unsigned() != self.session
            || unsafe { libc::ioctl(fd, libc::TIOCGDEV, &raw mut device) } < 0
            || device != self.snapshot.device
        {
            return Err(lost());
        }
        Ok(())
    }
}
fn lost() -> io::Error {
    io::Error::other("command terminal ownership changed")
}

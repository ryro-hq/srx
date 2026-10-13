//! Restauração do terminal pelo monitor que guarda sua custody.
//!
//! Conferir o foreground e escrever termios são operações separadas. Outro
//! processo pode tomar o terminal entre elas. A garantia de restauração depende
//! de o monitor continuar vivo e de não haver uma tomada concorrente por terceiros.

use super::*;
use crate::platform::linux::fd::terminal::TerminalAttributes;
use std::io::Write;
use std::os::fd::OwnedFd;

/// Reap only the direct child identified by this pidfd, never a reused numeric PID.
pub(crate) fn reap_monitor(fd: BorrowedFd<'_>) -> io::Result<()> {
    loop {
        // SAFETY: waitid writes siginfo storage and P_PIDFD resolves the pinned
        // process; ECHILD also covers a monitor already reaped by normal wait.
        let result = unsafe {
            let mut status: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PIDFD,
                fd.as_raw_fd().cast_unsigned(),
                &raw mut status,
                libc::WEXITED,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(());
        }
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(crate) fn frontend_identity() -> io::Result<[u32; 3]> {
    // SAFETY: read-only process identity queries.
    let values = unsafe {
        [
            libc::getpid(),
            libc::getsid(0),
            libc::getpgrp(),
        ]
    };
    let mut result = [0; 3];
    for (out, value) in result.iter_mut().zip(values) {
        *out = u32::try_from(value).map_err(io::Error::other)?;
    }
    Ok(result)
}

pub(super) struct Custody {
    tty: OwnedFd,
    parent: OwnedFd,
    channel: UnixStream,
    original: TerminalAttributes,
    session: i32,
    foreground: i32,
    device: u32,
    restored: bool,
    activated: bool,
}
impl Custody {
    /// The worker owns these inherited descriptors; no payload can receive them.
    pub(super) unsafe fn receive(args: &[OsString], forbidden: &[i32]) -> io::Result<Self> {
        if args.len() != 6 {
            return Err(io::Error::other("invalid tty custody header"));
        }
        let channel = fd(&args[0])?;
        let tty = fd(&args[1])?;
        if channel == tty || forbidden.contains(&channel) || forbidden.contains(&tty) {
            return Err(io::Error::other(
                "aliased tty custody descriptors",
            ));
        }
        for value in [channel, tty] {
            checked(unsafe { libc::fcntl(value, libc::F_GETFD) }.into())?;
        }
        let numbers = args[2..]
            .iter()
            .map(|v| {
                v.to_str()
                    .ok_or_else(|| io::Error::other("invalid tty custody identity"))?
                    .parse::<u32>()
                    .map_err(io::Error::other)
            })
            .collect::<io::Result<Vec<_>>>()?;
        let expected_parent = i32::try_from(numbers[0]).map_err(io::Error::other)?;
        // SAFETY: direct parent and session observations do not mutate state.
        if unsafe { libc::getppid() } != expected_parent
            || unsafe { libc::getsid(0) }.cast_unsigned() != numbers[1]
            || unsafe { libc::getpgid(expected_parent) }.cast_unsigned() != numbers[2]
        {
            return Err(io::Error::other(
                "tty custody frontend identity changed",
            ));
        }
        let parent = crate::platform::linux::fd::pidfd_open(numbers[0])?;
        if unsafe { libc::getppid() } != expected_parent
            || crate::platform::linux::fd::pidfd_exited(parent.as_fd())?
        {
            return Err(io::Error::other("tty custody frontend exited"));
        }
        // SAFETY: caller transfers two checked distinct descriptors exclusively.
        let channel = unsafe { UnixStream::from_raw_fd(channel) };
        channel.set_nonblocking(true)?;
        let tty = unsafe { OwnedFd::from_raw_fd(tty) };
        let original = TerminalAttributes::read(tty.as_fd())?;
        let mut custody = Self {
            tty,
            parent,
            channel,
            original,
            session: i32::try_from(numbers[1]).map_err(io::Error::other)?,
            foreground: i32::try_from(numbers[2]).map_err(io::Error::other)?,
            device: numbers[3],
            restored: false,
            activated: false,
        };
        let ready = (|| -> io::Result<()> {
            custody.validate_terminal()?;
            custody.channel.write_all(b"R")?;
            custody
                .channel
                .write_all(custody.original.fingerprint().as_bytes())?;
            // After Ready, only frontend abort/EOF or pinned death terminates
            // the wait. No timeout can race a still-pending raw activation.
            match custody.receive_byte(None)? {
                b'A' => custody.activated = true,
                b'B' => {}
                _ => return Err(io::Error::other("tty custody activation aborted")),
            }
            Ok(())
        })();
        if let Err(error) = ready {
            return match custody.restore() {
                Ok(()) => Err(error),
                Err(restore) => Err(io::Error::other(format!(
                    "terminal custody negotiation failed: {error}; restoration failed: {restore}"
                ))),
            };
        }
        Ok(custody)
    }
    fn receive_byte(&mut self, deadline: Option<std::time::Instant>) -> io::Result<u8> {
        self.receive_byte_with_watch(&mut DrainBudget::new(deadline), &mut || Ok(false))
    }
    fn receive_byte_with_watch(
        &mut self,
        budget: &mut DrainBudget,
        watch: &mut impl FnMut() -> io::Result<bool>,
    ) -> io::Result<u8> {
        loop {
            let armed = watch()?;
            if crate::platform::linux::fd::pidfd_exited(self.parent.as_fd())? {
                return Err(io::Error::other("terminal frontend exited"));
            }
            if budget.expired(std::time::Instant::now(), armed) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "terminal drain deadline",
                ));
            }
            if ready(self.channel.as_fd(), 25)? {
                let mut byte = [0];
                self.channel.read_exact(&mut byte)?;
                return Ok(byte[0]);
            }
        }
    }
    fn validate_terminal(&self) -> io::Result<()> {
        self.validate_terminal_identity()?;
        // SAFETY: read-only foreground query on the pinned terminal.
        if unsafe { libc::tcgetpgrp(self.tty.as_raw_fd()) } != self.foreground {
            return Err(io::Error::other(
                "terminal foreground ownership lost",
            ));
        }
        Ok(())
    }
    fn validate_terminal_identity(&self) -> io::Result<()> {
        let mut device = 0_u32;
        // SAFETY: live tty and writable scalar ioctl destination.
        checked(
            unsafe {
                libc::ioctl(
                    self.tty.as_raw_fd(),
                    libc::TIOCGDEV,
                    &raw mut device,
                )
            }
            .into(),
        )?;
        if device != self.device || unsafe { libc::tcgetsid(self.tty.as_raw_fd()) } != self.session
        {
            return Err(io::Error::other(
                "terminal foreground ownership lost",
            ));
        }
        Ok(())
    }
    pub(super) fn activated(&self) -> bool {
        self.activated
    }
    pub(super) fn descriptors(&self) -> [i32; 2] {
        [
            self.channel.as_raw_fd(),
            self.parent.as_raw_fd(),
        ]
    }
    pub(super) fn accept_abort(&mut self) -> io::Result<()> {
        if self.receive_byte(None)? == b'B' {
            Ok(())
        } else {
            Err(io::Error::other(
                "invalid terminal message while namespace runs",
            ))
        }
    }
    pub(super) fn disarm_child(&mut self) {
        self.restored = true;
    }
    /// Pausing is not settlement. Keep restoration armed even before the
    /// frontend announces resume: it can die between entering raw and sending.
    pub(super) fn pause_for_job(&mut self) -> io::Result<()> {
        self.restore()?;
        self.restored = false;
        Ok(())
    }
    pub(super) fn resume_after_job(&mut self) -> io::Result<()> {
        self.validate_terminal()?;
        if !TerminalAttributes::read(self.tty.as_fd())?.matches(&self.original.raw()) {
            return Err(io::Error::other(
                "terminal not ready for root resume",
            ));
        }
        self.restored = false;
        Ok(())
    }
    pub(super) fn namespace_settled(&mut self) -> io::Result<()> {
        self.namespace_settled_with_watch(|| Ok(false))
    }
    pub(super) fn namespace_settled_with_watch(
        &mut self,
        mut watch: impl FnMut() -> io::Result<bool>,
    ) -> io::Result<()> {
        self.channel.write_all(b"S")?;
        let deadline = std::time::Instant::now()
            + crate::runtime::terminal_custody::TERMINAL_DRAIN_TIMEOUT
            + crate::runtime::terminal_custody::TERMINAL_NEGOTIATION_TIMEOUT;
        let mut budget = DrainBudget::new(Some(deadline));
        loop {
            match self.receive_byte_with_watch(&mut budget, &mut watch)? {
                b'F' => break,
                b'B' => {} // Abort may cross the settlement notification.
                _ => {
                    return Err(io::Error::other(
                        "invalid terminal restore request",
                    ));
                }
            }
        }
        self.restore()?;
        self.channel.write_all(b"D")
    }
    pub(super) fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        self.validate_terminal_identity()?;
        let current = TerminalAttributes::read(self.tty.as_fd())?;
        if !current.matches(&self.original) {
            // An already restored snapshot needs no write and does not claim
            // foreground ownership. Any actual mutation still requires it.
            self.validate_terminal()?;
            if !current.matches(&self.original.raw()) {
                return Err(io::Error::other(
                    "terminal attributes changed outside custody",
                ));
            }
            // SIGTTOU must be blocked for a background process in this session.
            // SAFETY: the dedicated monitor owns its thread's signal mask.
            unsafe {
                let mut mask: libc::sigset_t = std::mem::zeroed();
                let mut previous: libc::sigset_t = std::mem::zeroed();
                checked(libc::sigemptyset(&raw mut mask).into())?;
                checked(libc::sigaddset(&raw mut mask, libc::SIGTTOU).into())?;
                checked(
                    libc::sigprocmask(
                        libc::SIG_BLOCK,
                        &raw const mask,
                        &raw mut previous,
                    )
                    .into(),
                )?;
                let applied = self.original.apply(self.tty.as_fd());
                let restored = checked(
                    libc::sigprocmask(
                        libc::SIG_SETMASK,
                        &raw const previous,
                        std::ptr::null_mut(),
                    )
                    .into(),
                );
                applied.and(restored)?;
            }
        }
        self.restored = true;
        Ok(())
    }
}
impl Drop for Custody {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests;

mod drain_budget;
use drain_budget::DrainBudget;

//! PTYs and terminal attributes accessed through open descriptors.
//!
//! Creating a PTY does not change the caller's terminal. The raw-mode guard restores
//! attributes on return or unwind. After SIGKILL, restoration depends on the
//! monitor that retains custody outside the CLI.

use std::fmt;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

mod relay;
pub(crate) use relay::{RelayControl, RelayExit, RelayOptions, relay_controlled};
#[cfg(test)]
pub(crate) use relay::{RelayResult, relay, relay_optional_input_with_tick, relay_with_tick};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowSize {
    pub rows: u16,
    pub columns: u16,
    pub x_pixels: u16,
    pub y_pixels: u16,
}
impl WindowSize {
    pub(crate) fn read(fd: BorrowedFd<'_>) -> io::Result<Self> {
        let mut size = MaybeUninit::<libc::winsize>::uninit();
        // SAFETY: fd remains live, and size is a writable winsize initialized on success.
        checked(unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                libc::TIOCGWINSZ,
                size.as_mut_ptr(),
            )
        })?;
        // SAFETY: the successful ioctl filled the complete structure.
        let size = unsafe { size.assume_init() };
        Ok(Self {
            rows: size.ws_row,
            columns: size.ws_col,
            x_pixels: size.ws_xpixel,
            y_pixels: size.ws_ypixel,
        })
    }
    pub(crate) fn apply(self, fd: BorrowedFd<'_>) -> io::Result<()> {
        let size = libc::winsize {
            ws_row: self.rows,
            ws_col: self.columns,
            ws_xpixel: self.x_pixels,
            ws_ypixel: self.y_pixels,
        };
        // SAFETY: size and fd remain live throughout the descriptor-only ioctl.
        checked(unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &raw const size) })
    }
}

#[derive(Clone)]
pub(crate) struct TerminalAttributes(libc::termios);
impl fmt::Debug for TerminalAttributes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalAttributes")
            .field("local_flags", &self.0.c_lflag)
            .finish_non_exhaustive()
    }
}
impl TerminalAttributes {
    pub(crate) fn read(fd: BorrowedFd<'_>) -> io::Result<Self> {
        let mut attributes = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: attributes is writable and initialized by successful tcgetattr.
        checked(unsafe { libc::tcgetattr(fd.as_raw_fd(), attributes.as_mut_ptr()) })?;
        // SAFETY: the successful call initialized every field.
        Ok(Self(unsafe { attributes.assume_init() }))
    }
    /// Applies immediately; never waits for terminal output to drain.
    pub(crate) fn apply(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        // SAFETY: the attributes were read from a terminal; fd and pointer stay live.
        checked(unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSANOW, &raw const self.0) })
    }
    /// Versioned digest of meaningful fields only; never hashes ABI padding.
    pub(crate) fn fingerprint(&self) -> crate::store::ContentDigest {
        use sha2::{Digest as _, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"syrox-terminal-attributes-v1\0");
        for field in [
            self.0.c_iflag,
            self.0.c_oflag,
            self.0.c_cflag,
            self.0.c_lflag,
            self.speeds()[0],
            self.speeds()[1],
        ] {
            hash.update(field.to_le_bytes());
        }
        hash.update([self.0.c_line]);
        hash.update(self.0.c_cc);
        crate::store::ContentDigest::from_sha256_hash(hash.finalize().into())
    }
    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.0.c_iflag == other.0.c_iflag
            && self.0.c_oflag == other.0.c_oflag
            && self.0.c_cflag == other.0.c_cflag
            && self.0.c_lflag == other.0.c_lflag
            && self.0.c_line == other.0.c_line
            && self.0.c_cc == other.0.c_cc
            && self.speeds() == other.speeds()
    }
    // These ABI fields have different libc names. Preserve the fingerprint's
    // existing bytes and ordering rather than substituting encoded baud rates.
    fn speeds(&self) -> [libc::speed_t; 2] {
        #[cfg(target_env = "musl")]
        {
            [self.0.__c_ispeed, self.0.__c_ospeed]
        }
        #[cfg(not(target_env = "musl"))]
        {
            [self.0.c_ispeed, self.0.c_ospeed]
        }
    }
    pub(crate) fn raw(&self) -> Self {
        let mut result = self.clone();
        // SAFETY: cfmakeraw only updates this initialized local termios value.
        unsafe { libc::cfmakeraw(&raw mut result.0) };
        result
    }
}

#[derive(Debug)]
pub(crate) struct Pty {
    master: OwnedFd,
    slave: OwnedFd,
}
impl Pty {
    /// Both ends are CLOEXEC from creation. The master is nonblocking; the slave
    /// is blocking for payload stdio. No mutable /dev/pts pathname is followed.
    pub(crate) fn open(
        size: WindowSize,
        attributes: Option<&TerminalAttributes>,
    ) -> io::Result<Self> {
        // SAFETY: posix_openpt takes integer flags and returns a new owned fd.
        let fd = unsafe {
            libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK)
        };
        let master = own(fd)?;
        // SAFETY: master owns a live fresh PTY; these calls only grant/unlock its peer.
        checked(unsafe { libc::grantpt(master.as_raw_fd()) })?;
        checked(unsafe { libc::unlockpt(master.as_raw_fd()) })?;
        // SAFETY: TIOCGPTPEER opens this master's peer atomically with CLOEXEC.
        let peer = unsafe {
            libc::ioctl(
                master.as_raw_fd(),
                libc::TIOCGPTPEER,
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        let slave = own(peer)?;
        validate_slave(slave.as_fd())?;
        if let Some(attributes) = attributes {
            attributes.apply(slave.as_fd())?;
        }
        size.apply(slave.as_fd())?;
        Ok(Self {
            master,
            slave,
        })
    }
    #[cfg(test)]
    pub(crate) fn master(&self) -> BorrowedFd<'_> {
        self.master.as_fd()
    }
    #[cfg(test)]
    pub(crate) fn slave(&self) -> BorrowedFd<'_> {
        self.slave.as_fd()
    }
    pub(crate) fn into_parts(self) -> (OwnedFd, OwnedFd) {
        (self.master, self.slave)
    }
}

/// Accept only a dedicated nonblocking read/write PTY master. This classifies
/// the descriptor; it does not authenticate the sender or namespace ownership.
pub(crate) fn validate_master(fd: BorrowedFd<'_>) -> io::Result<()> {
    let flags = super::status_flags(fd)?;
    let metadata = super::metadata(fd)?;
    if fd.as_raw_fd() < 3
        || flags & libc::O_PATH != 0
        || flags & libc::O_ACCMODE != libc::O_RDWR
        || flags & libc::O_NONBLOCK == 0
        || metadata.mode() & libc::S_IFMT != libc::S_IFCHR
    {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut number: libc::c_uint = 0;
    // SAFETY: the borrowed fd stays live and the ioctl writes one unsigned
    // integer only when it identifies a PTY master.
    checked(unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGPTN, &raw mut number) })?;
    if super::filesystem_type(fd)? != 0x1cd1 {
        // A legacy /dev/ptmx node lives on devtmpfs. Classify its kernel-owned
        // peer by descriptor, without following a mutable /dev/pts pathname.
        // SAFETY: TIOCGPTPEER creates an owned descriptor for this master's
        // peer; NOCTTY prevents assigning a controlling terminal.
        let peer = own(unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                libc::TIOCGPTPEER,
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        })?;
        validate_slave(peer.as_fd())?;
    }
    Ok(())
}

/// Accept only a blocking read/write terminal slave on a devpts filesystem. Ordinary files, device
/// aliases outside devpts, legacy ttys and PTY masters cannot act as the payload PTY.
pub(crate) fn validate_slave(fd: BorrowedFd<'_>) -> io::Result<()> {
    if fd.as_raw_fd() < 3 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: F_GETFL only queries the live slave descriptor.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE != libc::O_RDWR || flags & libc::O_NONBLOCK != 0 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let mut filesystem = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: both pointers have their ABI-sized writable storage and fd is live.
    checked(unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) })?;
    checked(unsafe { libc::fstatfs(fd.as_raw_fd(), filesystem.as_mut_ptr()) })?;
    // SAFETY: successful syscalls initialized the complete structures.
    let stat = unsafe { stat.assume_init() };
    let filesystem = unsafe { filesystem.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFCHR
        || !super::filesystem_magic_matches(filesystem.f_type, libc::DEVPTS_SUPER_MAGIC)
    {
        return Err(io::Error::from_raw_os_error(libc::ENOTTY));
    }
    TerminalAttributes::read(fd)?;
    let mut number: libc::c_uint = 0;
    // SAFETY: TIOCGPTN writes an unsigned integer only for a PTY master.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGPTN, &raw mut number) };
    if result == 0 {
        return Err(io::Error::from_raw_os_error(libc::ENOTTY));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ENOTTY) {
        return Err(error);
    }
    Ok(())
}

/// Establish a new session with the supplied slave as controlling terminal, set
/// its initial foreground group, and install it as stdin/stdout/stderr.
///
/// # Safety
/// Call only in a dedicated single-threaded helper/fork child before payload
/// exec. The caller must not already be a process-group leader. This mutates
/// process session membership and standard descriptors, including on partial failure.
/// It does not run or reap the payload, and makes no assumptions about namespace PID 1.
pub(crate) unsafe fn establish_controlling_terminal(slave: BorrowedFd<'_>) -> io::Result<()> {
    validate_slave(slave)?;
    // SAFETY: caller grants exclusive process-global state, in a fresh helper.
    checked(unsafe { libc::setsid() })?;
    // SAFETY: fd is a validated slave. Zero forbids stealing another session's tty.
    checked(unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY, 0) })?;
    // SAFETY: own process group exists and belongs to the just-created session.
    let group = unsafe { libc::getpgrp() };
    checked(unsafe { libc::tcsetpgrp(slave.as_raw_fd(), group) })?;
    for destination in 0..=2 {
        // SAFETY: validated live slave; the child owns stdio exclusively.
        checked(unsafe { libc::dup2(slave.as_raw_fd(), destination) })?;
        // dup2(oldfd, oldfd) preserves CLOEXEC; clear it on all installed stdio fds.
        // SAFETY: destination is now an owned standard descriptor in the child.
        checked(unsafe { libc::fcntl(destination, libc::F_SETFD, 0) })?;
    }
    Ok(())
}

/// Kernel terminal identity, including aliases such as /dev/tty. Unlike fstat's
/// rdev for that alias, TIOCGDEV identifies the currently attached terminal.
pub(crate) fn foreground_terminal(fd: BorrowedFd<'_>) -> io::Result<u32> {
    TerminalAttributes::read(fd)?;
    let mut device: libc::c_uint = 0;
    // SAFETY: the ioctl writes exactly one unsigned integer into live storage.
    checked(unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGDEV, &raw mut device) })?;
    // SAFETY: both calls only query process/terminal state.
    let foreground = unsafe { libc::tcgetpgrp(fd.as_raw_fd()) };
    if foreground < 0 {
        return Err(io::Error::last_os_error());
    }
    if foreground != unsafe { libc::getpgrp() } {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    Ok(device)
}

/// Reopen the live descriptor, creating a separate OFD without changing flags
/// shared by inherited stdio. Procfs is used only to follow this pinned fd.
pub(crate) fn independent_terminal(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let device = foreground_terminal(fd)?;
    let before = super::metadata(fd)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
    if super::metadata(file.as_fd())?.identity() != before.identity()
        || super::metadata(fd)?.identity() != before.identity()
        || foreground_terminal(file.as_fd())? != device
        || foreground_terminal(fd)? != device
    {
        return Err(io::Error::from_raw_os_error(libc::ESTALE));
    }
    Ok(file.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ForegroundPauseOutcome {
    Resumed,
    Abandoned,
}

/// Root exit cancels only the attempt to suspend. It is not global settlement.
/// An external guardian must be armed to wake the group if exit crosses SIGSTOP.
pub(crate) fn suspend_foreground_observed(
    fd: BorrowedFd<'_>,
    root: BorrowedFd<'_>,
    cancel: &crate::cancellation::Cancellation,
) -> io::Result<ForegroundPauseOutcome> {
    if let Some(outcome) = pause_observation(root, cancel, None)? {
        return Ok(outcome);
    }
    foreground_terminal(fd)?;
    if let Some(outcome) = pause_observation(root, cancel, None)? {
        return Ok(outcome);
    }
    // SAFETY: stop our own foreground process group; never select another PID.
    if unsafe { libc::kill(0, libc::SIGSTOP) } != 0 {
        return Err(io::Error::last_os_error());
    }
    loop {
        // Check root exit before touching the terminal: a dead job need not
        // regain foreground ownership to abandon its suspension.
        if let Some(outcome) = pause_observation(root, cancel, None)? {
            return Ok(outcome);
        }
        // SAFETY: read-only queries of this terminal and our own process group.
        let foreground = unsafe { libc::tcgetpgrp(fd.as_raw_fd()) };
        if foreground < 0 {
            return Err(io::Error::last_os_error());
        }
        if let Some(outcome) = pause_observation(
            root,
            cancel,
            Some(foreground == unsafe { libc::getpgrp() }),
        )? {
            return Ok(outcome);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
fn pause_observation(
    root: BorrowedFd<'_>,
    cancel: &crate::cancellation::Cancellation,
    foreground: Option<bool>,
) -> io::Result<Option<ForegroundPauseOutcome>> {
    cancel
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())?;
    if crate::platform::linux::fd::pidfd_exited(root)? {
        return Ok(Some(ForegroundPauseOutcome::Abandoned));
    }
    Ok(foreground
        .filter(|owned| *owned)
        .map(|_| ForegroundPauseOutcome::Resumed))
}

/// Foreground-only raw-mode guard. Explicit restoration reports errors; Drop is
/// best effort. Session ownership must handle SIGKILL and external terminal loss.
#[derive(Debug)]
pub(crate) struct TerminalGuard {
    fd: OwnedFd,
    saved: TerminalAttributes,
    foreground: libc::pid_t,
    restored: bool,
}
impl TerminalGuard {
    /// Relinquishes local restoration when an independent custodian owns it.
    /// This performs no terminal ioctl and is not evidence of settlement.
    pub(crate) fn disarm_without_restore(mut self) {
        self.restored = true;
    }

    pub(crate) fn enter(fd: BorrowedFd<'_>) -> io::Result<Self> {
        // SAFETY: query descriptor terminal state and the caller's process group.
        let foreground = unsafe { libc::tcgetpgrp(fd.as_raw_fd()) };
        if foreground < 0 {
            return Err(io::Error::last_os_error());
        }
        if foreground != unsafe { libc::getpgrp() } {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        let saved = TerminalAttributes::read(fd)?;
        let fd = fd.try_clone_to_owned()?;
        let guard = Self {
            fd,
            saved,
            foreground,
            restored: false,
        };
        guard.saved.raw().apply(guard.fd.as_fd())?;
        Ok(guard)
    }
    pub(crate) fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        // Do not silently alter a terminal that has already passed to another job.
        // SAFETY: the guard owns the pinned terminal descriptor.
        let foreground = unsafe { libc::tcgetpgrp(self.fd.as_raw_fd()) };
        if foreground < 0 {
            return Err(io::Error::last_os_error());
        }
        if foreground != self.foreground || foreground != unsafe { libc::getpgrp() } {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        let current = TerminalAttributes::read(self.fd.as_fd())?;
        if current.matches(&self.saved) {
            self.restored = true;
            return Ok(());
        }
        if !current.matches(&self.saved.raw()) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        self.saved.apply(self.fd.as_fd())?;
        self.restored = true;
        Ok(())
    }
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn checked(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn own(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful callers transfer a newly created descriptor exactly once.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        if fd < 3 {
            // SAFETY: duplication preserves the open file description and creates a fresh CLOEXEC fd.
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful fcntl returned one newly owned descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
        } else {
            Ok(owned)
        }
    }
}

#[cfg(test)]
mod tests;

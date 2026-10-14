use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

const FORWARDED: [libc::c_int; 4] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
];

pub(super) struct SignalFd {
    descriptor: OwnedFd,
    original: libc::sigset_t,
}
impl SignalFd {
    /// Caller must be the dedicated single-threaded launcher. The process must
    /// exit after this lifecycle; the mask is deliberately not restored on Drop.
    pub(super) fn new() -> io::Result<Self> {
        // SAFETY: initialized signal sets and writable saved-mask storage.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            let mut original = MaybeUninit::<libc::sigset_t>::zeroed();
            super::checked(libc::sigemptyset(&raw mut set).into())?;
            for signal in FORWARDED.into_iter().chain([libc::SIGCHLD]) {
                super::checked(libc::sigaddset(&raw mut set, signal).into())?;
            }
            super::checked(
                libc::sigprocmask(
                    libc::SIG_BLOCK,
                    &raw const set,
                    original.as_mut_ptr(),
                )
                .into(),
            )?;
            let raw = libc::signalfd(
                -1,
                &raw const set,
                libc::SFD_CLOEXEC | libc::SFD_NONBLOCK,
            );
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let descriptor = OwnedFd::from_raw_fd(raw);
            if raw < 3 {
                return Err(io::Error::other(
                    "managed launcher requires open standard descriptors",
                ));
            }
            Ok(Self {
                descriptor,
                original: original.assume_init(),
            })
        }
    }
    pub(super) fn for_init(original: libc::sigset_t) -> io::Result<Self> {
        let mut signals = Self::new()?;
        signals.original = original;
        // SAFETY: namespace PID1 is single-threaded; these blocked signals are
        // consumed by signalfd. Installing handlers permits ancestor delivery.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = permitted as *const () as libc::sighandler_t;
            super::checked(libc::sigemptyset(&raw mut action.sa_mask).into())?;
            for signal in FORWARDED {
                super::checked(
                    libc::sigaction(signal, &raw const action, std::ptr::null_mut()).into(),
                )?;
            }
        }
        Ok(signals)
    }
    pub(super) fn original(&self) -> libc::sigset_t {
        self.original
    }
    pub(super) fn descriptor(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
    pub(super) fn take(&self) -> io::Result<Option<libc::c_int>> {
        let mut info = MaybeUninit::<libc::signalfd_siginfo>::uninit();
        // SAFETY: writable storage exactly one signalfd record, fd live/nonblocking.
        let length = unsafe {
            libc::read(
                self.descriptor.as_raw_fd(),
                info.as_mut_ptr().cast(),
                size_of::<libc::signalfd_siginfo>(),
            )
        };
        if length < 0 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if usize::try_from(length).ok() != Some(size_of::<libc::signalfd_siginfo>()) {
            return Err(io::Error::other("invalid managed signal record"));
        }
        // SAFETY: exact record was initialized by read.
        let signal = i32::try_from(unsafe { info.assume_init() }.ssi_signo)
            .map_err(|_| io::Error::other("invalid managed signal number"))?;
        if signal == libc::SIGCHLD || FORWARDED.contains(&signal) {
            Ok(Some(signal))
        } else {
            Err(io::Error::other("unexpected managed signal"))
        }
    }
    pub(super) fn stop_pending(&self) -> io::Result<bool> {
        for _ in 0..64 {
            match self.take()? {
                Some(libc::SIGCHLD) => {}
                Some(_) => return Ok(true),
                None => return Ok(false),
            }
        }
        Ok(false)
    }
}
extern "C" fn permitted(_: libc::c_int) {}

/// Called only in the forked payload before exec, never in the monitor/init.
pub(super) unsafe fn payload_mask(mut mask: libc::sigset_t) -> io::Result<()> {
    for signal in FORWARDED.into_iter().chain([libc::SIGCHLD]) {
        // SAFETY: initialized signal set and fixed valid signal numbers.
        super::checked(unsafe { libc::sigdelset(&raw mut mask, signal) }.into())?;
    }
    // SAFETY: initialized set; dedicated child owns process-global mask.
    super::checked(
        unsafe {
            libc::sigprocmask(
                libc::SIG_SETMASK,
                &raw const mask,
                std::ptr::null_mut(),
            )
        }
        .into(),
    )
}

pub(super) fn forward_pidfd(target: BorrowedFd<'_>, signal: libc::c_int) -> io::Result<()> {
    if !FORWARDED.contains(&signal) {
        return Err(io::Error::other("invalid forwarded signal"));
    }
    loop {
        // SAFETY: pinned owned child; no numeric host PID is used.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                target.as_raw_fd(),
                signal,
                0,
                0,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => {}
            Some(libc::ESRCH) => return Ok(()),
            _ => return Err(error),
        }
    }
}

pub(super) fn forward_group(main: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    if !FORWARDED.contains(&signal) {
        return Err(io::Error::other("invalid forwarded signal"));
    }
    forward_proxy_group(main, signal)
}

/// The proxy's authenticated control channel additionally carries job-control
/// signals. This must never address a group outside the owned PID namespace.
pub(super) fn forward_proxy_group(main: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: getpid takes no arguments. This check forbids any host-group target.
    if unsafe { libc::getpid() } != 1 || main <= 1 || !(1..=64).contains(&signal) {
        return Err(io::Error::other(
            "signal group is not an owned namespace payload",
        ));
    }
    // The caller still owns the unreaped main child, so its PGID cannot be reused.
    // SAFETY: only the namespace-local payload group is addressed.
    if unsafe { libc::kill(-main, signal) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_owned_namespace_groups_and_graceful_signals_are_forwardable() {
        assert!(forward_group(0, libc::SIGTERM).is_err());
        assert!(forward_group(1, libc::SIGTERM).is_err());
        assert!(forward_group(2, libc::SIGKILL).is_err());
        assert!(forward_pidfd(io::stdin().as_fd(), libc::SIGKILL).is_err());
    }

    #[test]
    fn proxy_job_control_never_targets_the_host_process_group() {
        for signal in [
            libc::SIGSTOP,
            libc::SIGCONT,
            libc::SIGKILL,
            0,
            65,
        ] {
            assert!(forward_proxy_group(std::process::id().cast_signed(), signal).is_err());
        }
        // The original runtime profile still refuses proxy-only controls.
        assert!(forward_group(2, libc::SIGCONT).is_err());
        assert!(forward_group(2, libc::SIGSTOP).is_err());
    }
}

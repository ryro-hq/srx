//! Cancelamento cooperativo das operações da engine.
//!
//! Os leitores conferem cancelamento antes de cada read e devolvem um erro que
//! não pede retry. Um read que já bloqueou precisa do mecanismo de prazo ou
//! interrupção do próprio transporte; o token sozinho não o interrompe.

/// Cancellation observation without producer publication authority.
pub(crate) trait OperationControl: fmt::Debug + Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn check_cancelled(&self) -> Result<(), Cancelled> {
        if self.is_cancelled() {
            Err(Cancelled)
        } else {
            Ok(())
        }
    }
}

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::{fmt, io};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancelled;

impl fmt::Display for Cancelled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("operation cancelled")
    }
}

impl std::error::Error for Cancelled {}

/// Use `Other` because the standard readers retry `Interrupted` unconditionally.
pub(crate) fn cancellation_io() -> io::Error {
    io::Error::other(Cancelled)
}

pub(crate) fn is_cancellation_io(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<Cancelled>)
}

/// Cooperative cancellation, scoped to one caller operation. Library entry
/// points never install process-global signal handlers. Cleanup/settlement must
/// run even after this flag is set.
#[derive(Clone, Debug)]
pub struct Cancellation {
    flag: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    wake: Option<
        Arc<(
            std::os::unix::net::UnixStream,
            std::os::unix::net::UnixStream,
        )>,
    >,
}

impl Default for Cancellation {
    fn default() -> Self {
        Self {
            flag: Arc::default(),
            #[cfg(target_os = "linux")]
            wake: Self::wake_pair().ok().map(Arc::new),
        }
    }
}

impl Cancellation {
    /// Use a caller-owned flag, for example one registered with a signal handler.
    pub fn from_flag(flag: Arc<AtomicBool>) -> Self {
        Self {
            flag,
            #[cfg(target_os = "linux")]
            wake: None,
        }
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
        #[cfg(target_os = "linux")]
        if let Some(wake) = &self.wake {
            use std::io::Write as _;
            let _ = (&wake.1).write(&[1]);
        }
    }

    #[cfg(target_os = "linux")]
    fn wake_pair() -> io::Result<(
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    )> {
        let pair = std::os::unix::net::UnixStream::pair()?;
        pair.0.set_nonblocking(true)?;
        pair.1.set_nonblocking(true)?;
        Ok(pair)
    }

    /// The caller must write to the returned channel whenever it sets the flag.
    /// Suitable for signal-hook's async-signal-safe pipe registration.
    #[cfg(target_os = "linux")]
    pub fn from_flag_with_wakeup(
        flag: Arc<AtomicBool>,
    ) -> io::Result<(Self, std::os::unix::net::UnixStream)> {
        let wake = Self::wake_pair()?;
        let writer = wake.1.try_clone()?;
        Ok((
            Self {
                flag,
                wake: Some(Arc::new(wake)),
            },
            writer,
        ))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn wake_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd as _;
        self.wake.as_ref().map(|wake| wake.0.as_fd())
    }

    pub fn is_cancelled(&self) -> bool {
        self.check().is_err()
    }

    pub fn check(&self) -> Result<(), Cancelled> {
        if self.flag.load(Ordering::Acquire) {
            Err(Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Observe cancellation before each read; this adapter does not interrupt a blocked read.
pub(crate) struct CancellableReader<'a, R> {
    pub(crate) source: R,
    pub(crate) cancellation: &'a Cancellation,
}
impl<R: io::Read> io::Read for CancellableReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.cancellation.is_cancelled() {
            return Err(cancellation_io());
        }
        self.source.read(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn clones_share_cancellation() {
        let token = Cancellation::default();
        let observer = token.clone();
        assert_eq!(observer.check(), Ok(()));
        token.cancel();
        assert_eq!(observer.check(), Err(Cancelled));
    }

    #[test]
    fn caller_owned_flag_does_not_require_a_wakeup_channel() {
        let flag = Arc::new(AtomicBool::new(false));
        let token = Cancellation::from_flag(Arc::clone(&flag));
        assert_eq!(token.check(), Ok(()));
        flag.store(true, Ordering::Release);
        assert_eq!(token.check(), Err(Cancelled));
        assert!(token.wake_fd().is_none());
    }

    #[test]
    fn clones_share_cancellation_and_wake_waiters() {
        let token = Cancellation::default();
        let observer = token.clone();
        assert_eq!(observer.check(), Ok(()));
        token.cancel();
        assert_eq!(observer.check(), Err(Cancelled));
        let mut byte = [0];
        assert_eq!(
            (&observer.wake.as_ref().unwrap().0)
                .read(&mut byte)
                .unwrap(),
            1
        );
    }

    #[test]
    fn caller_owned_signal_flag_and_wakeup_remain_connected() {
        let flag = Arc::new(AtomicBool::new(false));
        let (token, mut writer) = Cancellation::from_flag_with_wakeup(Arc::clone(&flag)).unwrap();
        flag.store(true, Ordering::Release);
        writer.write_all(&[1]).unwrap();
        assert_eq!(token.check(), Err(Cancelled));
        let mut byte = [0];
        assert_eq!(
            (&token.wake.as_ref().unwrap().0)
                .read(&mut byte)
                .unwrap(),
            1
        );
        let without_wakeup = Cancellation::from_flag(flag);
        assert!(without_wakeup.is_cancelled());
        assert!(without_wakeup.wake_fd().is_none());
    }

    #[test]
    fn cancellation_io_is_distinct_from_transport_failure_and_not_retried() {
        let error = cancellation_io();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(is_cancellation_io(&error));
        assert!(!is_cancellation_io(&io::Error::other(
            "operation cancelled"
        )));
    }
}

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use signal_hook::{
    SigId,
    consts::{SIGINT, SIGTERM},
    flag, low_level,
};
use syrox_engine::cancellation::Cancellation;

/// Handlers only set atomics; process control and cleanup stay on the normal
/// operation path. A second signal also requests cancellation, never bypasses cleanup.
pub(super) struct OperationSignals {
    registrations: Vec<SigId>,
    signal: Arc<AtomicUsize>,
    pub(super) cancellation: Cancellation,
}

impl OperationSignals {
    pub(super) fn install() -> std::io::Result<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = Arc::new(AtomicUsize::new(0));
        #[cfg(target_os = "linux")]
        let (cancellation, wake) = Cancellation::from_flag_with_wakeup(cancelled.clone())?;
        let mut guard = Self {
            registrations: Vec::new(),
            signal,
            cancellation,
        };
        for number in [SIGINT, SIGTERM] {
            guard.registrations.push(flag::register_usize(
                number,
                guard.signal.clone(),
                usize::try_from(number).expect("positive signal"),
            )?);
            guard
                .registrations
                .push(flag::register(number, cancelled.clone())?);
            #[cfg(target_os = "linux")]
            guard
                .registrations
                .push(low_level::pipe::register(
                    number,
                    wake.try_clone()?,
                )?);
        }
        Ok(guard)
    }

    pub(super) fn cancelled_exit_code(&self) -> u8 {
        match self.signal.load(Ordering::Acquire) {
            15 => 143,
            _ => 130,
        }
    }
}

impl Drop for OperationSignals {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            low_level::unregister(registration);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_exit_status_distinguishes_interrupt_and_termination() {
        // Avoid delivering a real signal to the parallel test runner.
        let signals = OperationSignals {
            registrations: Vec::new(),
            signal: Arc::default(),
            cancellation: Cancellation::from_flag(Arc::default()),
        };
        signals.cancellation.cancel();
        assert_eq!(signals.cancelled_exit_code(), 130);
        signals.signal.store(15, Ordering::Release);
        assert_eq!(signals.cancelled_exit_code(), 143);
        signals.signal.store(2, Ordering::Release);
        assert_eq!(signals.cancelled_exit_code(), 130);
    }
}

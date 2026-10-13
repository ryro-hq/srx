use super::{BuildControl, BuildError, ProducerControl};
use crate::cancellation::Cancellation;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::ScopedJoinHandle;
use std::time::Duration;

const POLL: Duration = Duration::from_millis(25);

/// Keep the monitor inside the producer's lifetime, including callback unwind.
/// A successful published result is preserved; shared admission separately
/// handles cancellation of the originating consumer after publication.
///
/// The 25 ms interval is not a hard cancellation deadline: an interest check
/// may wait for the existing journal namespace lock for up to five seconds.
/// Publication must call `ProducerControl::check_publication` directly rather
/// than relying on the asynchronously updated local token.
pub(in crate::build) fn with_managed_cancellation<T>(
    control: &ProducerControl,
    run: impl FnOnce(&Cancellation) -> Result<T, BuildError>,
) -> Result<T, BuildError> {
    monitored(control, run)
}

fn monitored<T>(
    control: &dyn BuildControl,
    run: impl FnOnce(&Cancellation) -> Result<T, BuildError>,
) -> Result<T, BuildError> {
    // Reject a known policy failure before creating the monitor or invoking work.
    control.check()?;
    let cancellation = Cancellation::default();
    std::thread::scope(|scope| {
        let (stop, receiver) = mpsc::sync_channel(1);
        let wake = cancellation.clone();
        let thread = std::thread::Builder::new()
            .name("syrox-managed-cancellation".into())
            .spawn_scoped(scope, move || monitor(control, &wake, &receiver))?;
        let monitor = Monitor {
            stop,
            thread: Some(thread),
        };
        let result = run(&cancellation);
        let mut cause = monitor.finish();
        result.map_err(|error| restore_cause(error, &mut cause))
    })
}

fn monitor(
    control: &dyn BuildControl,
    cancellation: &Cancellation,
    stop: &Receiver<()>,
) -> Option<BuildError> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        loop {
            if let Err(error) = control.check() {
                return Some(error);
            }
            match stop.recv_timeout(POLL) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => return None,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }));
    let cause = result.unwrap_or_else(|_| Some(monitor_panicked()));
    if cause.is_some() {
        cancellation.cancel();
    }
    cause
}

struct Monitor<'scope> {
    stop: SyncSender<()>,
    thread: Option<ScopedJoinHandle<'scope, Option<BuildError>>>,
}
impl Monitor<'_> {
    fn finish(mut self) -> Option<BuildError> {
        self.stop_and_join()
    }
    fn stop_and_join(&mut self) -> Option<BuildError> {
        let thread = self.thread.take()?;
        let _ = self.stop.try_send(());
        thread
            .join()
            .unwrap_or_else(|_| Some(monitor_panicked()))
    }
}
impl Drop for Monitor<'_> {
    fn drop(&mut self) {
        // Unwind cannot leave a policy monitor accessing producer state after
        // the producer has released its journal/consumer ownership.
        let _ = self.stop_and_join();
    }
}
fn monitor_panicked() -> BuildError {
    BuildError::Journal("managed cancellation monitor panicked".into())
}

fn restore_cause(error: BuildError, cause: &mut Option<BuildError>) -> BuildError {
    match error {
        BuildError::Cancelled => cause.take().unwrap_or(BuildError::Cancelled),
        BuildError::Settlement {
            stage,
            reason,
            primary,
        } => BuildError::Settlement {
            stage,
            reason,
            primary: primary.map(|error| Box::new(restore_cause(*error, cause))),
        },
        BuildError::FailureAndCleanup {
            primary,
            cleanup,
        } => BuildError::FailureAndCleanup {
            primary: Box::new(restore_cause(*primary, cause)),
            cleanup,
        },
        BuildError::FailureAndJournal {
            primary,
            journal,
        } => BuildError::FailureAndJournal {
            primary: Box::new(restore_cause(*primary, cause)),
            journal,
        },
        BuildError::PublishedAndCache {
            root,
            source,
        } => BuildError::PublishedAndCache {
            root,
            source: Box::new(restore_cause(*source, cause)),
        },
        error => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::time::Instant;

    #[derive(Debug, Default)]
    struct Control {
        failure: AtomicU8,
        checks: AtomicUsize,
    }
    impl BuildControl for Control {
        fn check(&self) -> Result<(), BuildError> {
            self.checks.fetch_add(1, Ordering::SeqCst);
            match self.failure.load(Ordering::SeqCst) {
                0 => Ok(()),
                1 => Err(BuildError::Cancelled),
                2 => Err(BuildError::Journal(
                    "interest identity changed".into(),
                )),
                _ => panic!("controlled monitor panic"),
            }
        }
    }
    fn wait_for(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(
                Instant::now() < deadline,
                "monitor did not make progress"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn fail_and_wait(control: &Control, cancellation: &Cancellation) {
        control.failure.store(2, Ordering::SeqCst);
        wait_for(|| cancellation.is_cancelled());
    }

    #[test]
    fn known_policy_failure_prevents_work() {
        let control = Control::default();
        control.failure.store(2, Ordering::SeqCst);
        let result = monitored::<()>(&control, |_| panic!("work must not start"));
        assert!(
            matches!(result, Err(BuildError::Journal(message)) if message == "interest identity changed")
        );
        assert_eq!(control.checks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn monitor_preserves_original_policy_error_instead_of_local_cancel() {
        let control = Control::default();
        let result = monitored(&control, |cancellation| {
            fail_and_wait(&control, cancellation);
            cancellation.check().map_err(BuildError::from)
        });
        assert!(
            matches!(result, Err(BuildError::Journal(message)) if message == "interest identity changed")
        );
    }

    #[test]
    fn uncertainty_and_cleanup_envelopes_keep_the_original_monitor_cause() {
        let control = Control::default();
        let result = monitored::<()>(&control, |cancellation| {
            fail_and_wait(&control, cancellation);
            Err(BuildError::Settlement {
                stage: "/preserved/stage".into(),
                reason: "unconfirmed namespace",
                primary: Some(Box::new(BuildError::FailureAndCleanup {
                    primary: Box::new(BuildError::Cancelled),
                    cleanup: std::io::Error::other("stop reply lost"),
                })),
            })
        });
        let Err(BuildError::Settlement {
            stage,
            reason,
            primary: Some(primary),
        }) = result
        else {
            panic!("settlement uncertainty must survive");
        };
        assert_eq!(stage, PathBuf::from("/preserved/stage"));
        assert_eq!(reason, "unconfirmed namespace");
        let BuildError::FailureAndCleanup {
            primary,
            cleanup,
        } = *primary
        else {
            panic!("cleanup evidence must survive");
        };
        assert_eq!(cleanup.to_string(), "stop reply lost");
        assert!(
            matches!(*primary, BuildError::Journal(message) if message == "interest identity changed")
        );
    }

    #[test]
    fn independent_execution_failure_and_published_success_are_not_replaced() {
        let control = Control::default();
        let result = monitored::<()>(&control, |cancellation| {
            fail_and_wait(&control, cancellation);
            Err(BuildError::Execution(
                "payload failed independently".into(),
            ))
        });
        assert!(
            matches!(result, Err(BuildError::Execution(message)) if message == "payload failed independently")
        );
        let control = Control::default();
        let result = monitored(&control, |cancellation| {
            // Represents work whose publication already passed the original
            // control boundary. A later policy failure cannot undo that result.
            fail_and_wait(&control, cancellation);
            Ok("already published")
        });
        assert_eq!(result.unwrap(), "already published");
    }

    #[test]
    fn no_policy_failure_preserves_cancellation_from_the_coordinator() {
        let control = Control::default();
        assert!(matches!(
            monitored::<()>(&control, |cancellation| {
                cancellation.cancel();
                Err(BuildError::Cancelled)
            }),
            Err(BuildError::Cancelled)
        ));
    }

    #[test]
    fn monitor_panic_wakes_work_and_is_reported_without_detaching_thread() {
        let control = Control::default();
        let result = monitored::<()>(&control, |cancellation| {
            control.failure.store(3, Ordering::SeqCst);
            wait_for(|| cancellation.is_cancelled());
            Err(BuildError::Cancelled)
        });
        assert!(
            matches!(result, Err(BuildError::Journal(message)) if message == "managed cancellation monitor panicked")
        );
    }

    #[test]
    fn callback_panic_stops_and_joins_the_scoped_monitor() {
        let control = Control::default();
        let panic = std::panic::catch_unwind(|| {
            let _ = monitored::<()>(&control, |_| {
                wait_for(|| control.checks.load(Ordering::SeqCst) >= 2);
                panic!("controlled work panic");
            });
        });
        // Scope cannot unwind back here until its live monitor has exited. Without
        // the stop-on-unwind guard, the monitor would keep polling indefinitely.
        assert!(panic.is_err());
        assert!(control.check().is_ok());
    }

    #[derive(Debug)]
    struct Interests {
        live: AtomicUsize,
        checks: AtomicUsize,
    }
    impl BuildControl for Interests {
        fn check(&self) -> Result<(), BuildError> {
            self.checks.fetch_add(1, Ordering::SeqCst);
            if self.live.load(Ordering::SeqCst) == 0 {
                Err(BuildError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn another_interest_keeps_the_local_token_alive_until_the_last_detaches() {
        let control = Interests {
            live: AtomicUsize::new(2),
            checks: AtomicUsize::new(0),
        };
        let result = monitored::<()>(&control, |cancellation| {
            control.live.fetch_sub(1, Ordering::SeqCst);
            // Test the bridge's policy abstraction, not filesystem lease authority;
            // real consumer admission/detachment is covered in shared tests.
            let checks = control.checks.load(Ordering::SeqCst);
            wait_for(|| control.checks.load(Ordering::SeqCst) > checks + 1);
            assert!(!cancellation.is_cancelled());
            control.live.fetch_sub(1, Ordering::SeqCst);
            wait_for(|| cancellation.is_cancelled());
            Err(BuildError::Cancelled)
        });
        assert!(matches!(result, Err(BuildError::Cancelled)));
    }
}

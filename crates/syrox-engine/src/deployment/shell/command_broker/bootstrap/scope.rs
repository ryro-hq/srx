use std::fmt;
use std::io;
use std::os::fd::AsFd as _;
use std::time::{Duration, Instant};

use crate::cancellation::Cancellation;

use super::{BootstrapServer, PreparedCommandBroker};

#[derive(Debug)]
pub(crate) struct ScopeError<E> {
    pub(crate) foreground: Option<E>,
    pub(crate) server: Option<io::Error>,
}

impl<E: fmt::Display> fmt::Display for ScopeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = &self.foreground {
            write!(f, "command foreground failed: {error}")?;
        }
        if let Some(error) = &self.server {
            if self.foreground.is_some() {
                f.write_str("; ")?;
            }
            write!(f, "command resource service failed: {error}")?;
        }
        Ok(())
    }
}

/// `operation` must be an internal operation token, for example the local token
/// from managed supervision. This function cancels it on return and unwind;
/// passing the user's original cancellation token would cancel unrelated work.
/// The foreground callback must settle its monitor before returning, including
/// when this service cancels the operation. Prepared resources remain borrowed
/// until both foreground and service have stopped.
pub(crate) fn with_server<T, E>(
    mut server: BootstrapServer,
    prepared: &PreparedCommandBroker<'_>,
    execution: &crate::execution::journal::execution::ExecutionGuard<'_>,
    operation: Cancellation,
    foreground: impl FnOnce(&Cancellation) -> Result<T, E>,
) -> Result<T, ScopeError<E>> {
    with_task(
        operation,
        |cancel| loop {
            cancel
                .check()
                .map_err(|_| crate::cancellation::cancellation_io())?;
            // An idle interactive shell has no admission deadline. Once a
            // request arrives, the complete exchange has a bounded lifetime.
            if crate::execution::native::ready(server.as_fd(), 20)?
                && server.serve_one(
                    prepared,
                    execution,
                    cancel,
                    Instant::now() + Duration::from_secs(5),
                )? == super::Served::Closed
            {
                return await_foreground(cancel);
            }
        },
        foreground,
    )
}

/// Admission may end before the guardian has collected all descendants. Keep
/// the scope alive without canceling foreground or treating EOF as settlement.
fn await_foreground(cancel: &Cancellation) -> io::Result<()> {
    while !cancel.is_cancelled() {
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(crate::cancellation::cancellation_io())
}

struct CancelOnDrop<'a>(&'a Cancellation);

impl Drop for CancelOnDrop<'_> {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

// This scope takes responsibility for canceling its private operation on every exit.
#[allow(clippy::needless_pass_by_value)] // This scope takes responsibility for canceling its private operation on every exit.
fn with_task<T, E>(
    operation: Cancellation,
    task: impl FnOnce(&Cancellation) -> io::Result<()> + Send,
    foreground: impl FnOnce(&Cancellation) -> Result<T, E>,
) -> Result<T, ScopeError<E>> {
    std::thread::scope(|scope| {
        // Drop before scope joins, also if the foreground unwinds.
        let stop = CancelOnDrop(&operation);
        let worker = std::thread::Builder::new()
            .name("syrox-command-resources".into())
            .spawn_scoped(scope, || {
                // A server panic must interrupt foreground before join.
                let _stop = CancelOnDrop(&operation);
                match task(&operation) {
                    Err(error)
                        if operation.is_cancelled()
                            && crate::cancellation::is_cancellation_io(&error) =>
                    {
                        Ok(())
                    }
                    Err(error) => Err(error),
                    Ok(()) => Err(io::Error::other(
                        "resource service stopped unexpectedly",
                    )),
                }
            })
            .map_err(|error| ScopeError {
                foreground: None,
                server: Some(error),
            })?;
        let result = foreground(&operation);
        drop(stop);
        let service = worker
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("resource service panicked")));
        match (result, service) {
            (Ok(value), Ok(())) => Ok(value),
            (result, service) => Err(ScopeError {
                foreground: result.err(),
                server: service.err(),
            }),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::with_task;
    use crate::cancellation::Cancellation;
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    fn await_cancel(cancel: &Cancellation) {
        let until = Instant::now() + Duration::from_secs(2);
        while !cancel.is_cancelled() {
            assert!(
                Instant::now() < until,
                "scoped cancellation did not arrive"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn closed_admission_does_not_cancel_foreground_settlement() {
        let admission_closed = AtomicBool::new(false);
        let value = with_task(
            Cancellation::default(),
            |cancel| {
                admission_closed.store(true, Ordering::Release);
                super::await_foreground(cancel)
            },
            |cancel| {
                let until = Instant::now() + Duration::from_secs(2);
                while !admission_closed.load(Ordering::Acquire) {
                    assert!(Instant::now() < until);
                    std::thread::yield_now();
                }
                assert!(!cancel.is_cancelled());
                // The foreground still owns the responsibility to collect proof.
                Ok::<_, io::Error>(42)
            },
        )
        .unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn foreground_return_cancels_and_joins_resource_service() {
        let settled = AtomicBool::new(false);
        let value = with_task(
            Cancellation::default(),
            |cancel| {
                await_cancel(cancel);
                settled.store(true, Ordering::Release);
                Err(crate::cancellation::cancellation_io())
            },
            |_| Ok::<_, io::Error>(42),
        )
        .unwrap();
        assert_eq!(value, 42);
        assert!(settled.load(Ordering::Acquire));
    }

    #[test]
    fn service_failure_cancels_foreground_and_preserves_both_errors() {
        let error = with_task(
            Cancellation::default(),
            |_| Err(io::Error::other("broken handoff")),
            |cancel| {
                await_cancel(cancel);
                Err::<(), _>(io::Error::other("settlement failed"))
            },
        )
        .unwrap_err();
        assert_eq!(
            error.foreground.unwrap().to_string(),
            "settlement failed"
        );
        assert_eq!(
            error.server.unwrap().to_string(),
            "broken handoff"
        );
    }

    #[test]
    fn service_panic_interrupts_foreground_and_is_reported_after_join() {
        let error = with_task(
            Cancellation::default(),
            |_| panic!("resource service fixture"),
            |cancel| {
                await_cancel(cancel);
                Ok::<_, io::Error>(())
            },
        )
        .unwrap_err();
        assert!(error.foreground.is_none());
        assert_eq!(
            error.server.unwrap().to_string(),
            "resource service panicked"
        );
    }

    #[test]
    fn foreground_unwind_cancels_and_joins_before_releasing_borrowed_resources() {
        let settled = AtomicBool::new(false);
        let unwind = std::panic::catch_unwind(|| {
            let _: Result<(), super::ScopeError<io::Error>> = with_task(
                Cancellation::default(),
                |cancel| {
                    await_cancel(cancel);
                    settled.store(true, Ordering::Release);
                    Err(crate::cancellation::cancellation_io())
                },
                |_| panic!("foreground fixture"),
            );
        });
        assert!(unwind.is_err());
        assert!(settled.load(Ordering::Acquire));
    }
}

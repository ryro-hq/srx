use super::PreparedShellTerminal;
use crate::platform::linux::fd::terminal::{
    ForegroundPauseOutcome, RelayControl, RelayExit, RelayOptions, TerminalAttributes,
    TerminalGuard, foreground_terminal, relay_controlled, suspend_foreground_observed,
};
use crate::runtime::terminal_custody::{
    FrontendPauseOutcome, RuntimeTerminalRequest, TERMINAL_DRAIN_TIMEOUT,
    TERMINAL_NEGOTIATION_TIMEOUT, TerminalCustodyConfirmed, TerminalFrontend,
};
use crate::{cancellation::Cancellation, deployment::shell::SessionError};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::process::ExitStatus;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(20);

enum Event {
    Ready,
    Settled,
    Pause(RelayPause),
    Finished(Result<ExitStatus, SessionError>),
}

struct RelayPause {
    acknowledged: Sender<()>,
    resumed: Receiver<RelayControl>,
}
impl RelayPause {
    fn wait(self, signals: &Cancellation, operation: &Cancellation) -> io::Result<RelayControl> {
        self.acknowledged
            .send(())
            .map_err(|_| disconnected())?;
        loop {
            if signals.is_cancelled() {
                operation.cancel();
            }
            match self.resumed.recv_timeout(POLL) {
                Ok(control) => return Ok(control),
                Err(RecvTimeoutError::Disconnected) => return Err(disconnected()),
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

struct FrontendCallbacks {
    host: OwnedFd,
    original: TerminalAttributes,
    device: u32,
    operation: Cancellation,
    events: Sender<Event>,
    drained: Receiver<Result<(), String>>,
    paused: Option<Sender<RelayControl>>,
}
impl TerminalFrontend for FrontendCallbacks {
    fn ready(&mut self, proof: TerminalCustodyConfirmed) -> io::Result<TerminalGuard> {
        proof.validate(self.host.as_fd(), &self.original)?;
        if self.operation.is_cancelled() {
            return Err(crate::cancellation::cancellation_io());
        }
        if foreground_terminal(self.host.as_fd())? != self.device
            || !self
                .original
                .matches(&TerminalAttributes::read(self.host.as_fd())?)
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let guard = TerminalGuard::enter(self.host.as_fd())?;
        self.events
            .send(Event::Ready)
            .map_err(|_| disconnected())?;
        // The guard is transferred, not duplicated. Runtime must restore it
        // before abort/EOF, including failures between Ready and RawActive.
        Ok(guard)
    }

    fn prepare_pause_root(&mut self, cancel: &Cancellation) -> io::Result<()> {
        if self.paused.is_some() {
            return Err(io::Error::other("terminal relay already paused"));
        }
        let (acknowledged, acknowledgment) = mpsc::channel();
        let (resumed, resume) = mpsc::channel();
        self.events
            .send(Event::Pause(RelayPause {
                acknowledged,
                resumed: resume,
            }))
            .map_err(|_| disconnected())?;
        let deadline = Instant::now() + TERMINAL_NEGOTIATION_TIMEOUT;
        loop {
            cancel
                .check()
                .map_err(|_| crate::cancellation::cancellation_io())?;
            match acknowledgment.recv_timeout(POLL) {
                Ok(()) => break,
                Err(RecvTimeoutError::Disconnected) => return Err(disconnected()),
                Err(RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
                Err(RecvTimeoutError::Timeout) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "terminal relay pause timed out",
                    ));
                }
            }
        }
        self.paused = Some(resumed);
        Ok(())
    }

    fn pause_root(
        &mut self,
        mut guard: TerminalGuard,
        _signal: i32,
        root: BorrowedFd<'_>,
        cancel: &Cancellation,
    ) -> io::Result<FrontendPauseOutcome> {
        let resumed = self
            .paused
            .take()
            .ok_or_else(|| io::Error::other("terminal relay pause missing"))?;
        guard.restore()?;
        if suspend_foreground_observed(self.host.as_fd(), root, cancel)?
            == ForegroundPauseOutcome::Abandoned
        {
            self.paused = Some(resumed);
            return Ok(FrontendPauseOutcome::Abandoned(guard));
        }
        drop(guard);
        if foreground_terminal(self.host.as_fd())? != self.device
            || !self
                .original
                .matches(&TerminalAttributes::read(self.host.as_fd())?)
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let guard = TerminalGuard::enter(self.host.as_fd())?;
        resumed
            .send(RelayControl::Continue)
            .map_err(|_| disconnected())?;
        Ok(FrontendPauseOutcome::Resumed(guard))
    }

    fn namespace_settled(&mut self) -> io::Result<()> {
        // Global settlement releases an abandoned or not-yet-executed pause
        // into output-only drain. It never resumes input with original attrs.
        if let Some(paused) = self.paused.take() {
            paused
                .send(RelayControl::Drain)
                .map_err(|_| disconnected())?;
        }
        self.events
            .send(Event::Settled)
            .map_err(|_| disconnected())?;
        let deadline = Instant::now() + TERMINAL_DRAIN_TIMEOUT;
        loop {
            match self.drained.recv_timeout(POLL) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error)) => return Err(io::Error::other(error)),
                Err(RecvTimeoutError::Disconnected) => return Err(disconnected()),
                Err(RecvTimeoutError::Timeout) => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "terminal drain timed out",
                        ));
                    }
                }
            }
        }
    }
}

#[derive(Default)]
struct Observation {
    ready: bool,
    pause: Option<RelayPause>,
    draining: bool,
    drain_deadline: Option<Instant>,
    finished: Option<Result<ExitStatus, SessionError>>,
}
impl Observation {
    fn accept(&mut self, event: Event) {
        match event {
            Event::Ready => self.ready = true,
            Event::Pause(pause) => self.pause = Some(pause),
            Event::Settled => self.drain_deadline = Some(Instant::now() + TERMINAL_DRAIN_TIMEOUT),
            Event::Finished(result) => self.finished = Some(result),
        }
    }
    fn pause_relay(&mut self, signals: &Cancellation, operation: &Cancellation) -> io::Result<()> {
        if let Some(pause) = self.pause.take() {
            self.draining |= pause.wait(signals, operation)? == RelayControl::Drain;
        }
        Ok(())
    }
    fn poll(&mut self, events: &Receiver<Event>) -> io::Result<()> {
        loop {
            match events.try_recv() {
                Ok(event) => self.accept(event),
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) if self.finished.is_some() => return Ok(()),
                Err(TryRecvError::Disconnected) => return Err(disconnected()),
            }
        }
    }
}

impl PreparedShellTerminal {
    /// Internal integration boundary. `run` must implement custody, namespace
    /// settlement, and restoration; it may not return merely after spawning.
    /// Execution has no arbitrary time cap. Negotiation and post-settlement
    /// output draining have separate bounds. Kernel cleanup/join is not claimed
    /// to have a hard wall-clock bound.
    pub(crate) fn run_with(
        mut self,
        signals: &Cancellation,
        run: impl FnOnce(
            RuntimeTerminalRequest,
            &mut dyn TerminalFrontend,
            &Cancellation,
        ) -> Result<ExitStatus, SessionError>
        + Send,
    ) -> Result<ExitStatus, SessionError> {
        if signals.is_cancelled() {
            return Err(SessionError::Cancelled);
        }
        let slave = self.take_slave()?;
        let request = RuntimeTerminalRequest::new(slave, self.input.as_fd(), &self.attributes)?;
        let operation = Cancellation::default();
        let relay_stop = Cancellation::default();
        let (events, receiver) = mpsc::channel();
        let (drained, drain_receiver) = mpsc::channel();
        let mut callbacks = FrontendCallbacks {
            host: self.input.try_clone()?,
            original: self.attributes.clone(),
            device: self.device,
            operation: operation.clone(),
            events: events.clone(),
            drained: drain_receiver,
            paused: None,
        };
        let runtime_operation = operation.clone();
        std::thread::scope(|scope| {
            let runtime = scope.spawn(move || {
                let result = run(request, &mut callbacks, &runtime_operation);
                let _ = events.send(Event::Finished(result));
            });
            let mut observation = Observation::default();
            let frontend = self.run_frontend(
                signals,
                &operation,
                &relay_stop,
                &receiver,
                &mut observation,
            );
            if frontend.is_err() {
                operation.cancel();
            }
            let _ = drained.send(
                frontend
                    .as_ref()
                    .copied()
                    .map_err(ToString::to_string),
            );
            // Continue forwarding actual external cancellation after PTY EOF.
            // A command may close stdio while still running; EOF is not settlement.
            while observation.finished.is_none() {
                if signals.is_cancelled() {
                    operation.cancel();
                }
                match receiver.recv_timeout(POLL) {
                    Ok(event) => {
                        observation.accept(event);
                        if observation
                            .pause_relay(signals, &operation)
                            .is_err()
                        {
                            operation.cancel();
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            let joined = runtime.join();
            if joined.is_err() {
                return Err(SessionError::Supervision(
                    "terminal runtime thread panicked; cleanup requires reconciliation".to_owned(),
                ));
            }
            let result = observation
                .finished
                .unwrap_or_else(|| Err(SessionError::Io(disconnected())));
            combine(frontend, result)
        })
    }

    fn run_frontend(
        &self,
        signals: &Cancellation,
        operation: &Cancellation,
        relay_stop: &Cancellation,
        receiver: &Receiver<Event>,
        observation: &mut Observation,
    ) -> io::Result<()> {
        let deadline = Instant::now() + TERMINAL_NEGOTIATION_TIMEOUT;
        while !observation.ready {
            if signals.is_cancelled() {
                operation.cancel();
                return Err(crate::cancellation::cancellation_io());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "terminal custody negotiation timed out",
                ));
            }
            match receiver.recv_timeout(POLL) {
                Ok(event) => observation.accept(event),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(disconnected()),
            }
            if let Some(result) = &observation.finished {
                return if result.is_ok() {
                    Err(io::Error::other(
                        "terminal runtime completed before custody confirmation",
                    ))
                } else {
                    Ok(())
                };
            }
        }
        let result = relay_controlled(
            self.master.as_fd(),
            Some(self.input.as_fd()),
            self.output.as_fd(),
            RelayOptions {
                buffer_bytes: 64 * 1024,
                deadline: None,
                forward_resize: true,
            },
            relay_stop,
            || {
                observation.poll(receiver)?;
                observation.pause_relay(signals, operation)?;
                if signals.is_cancelled() {
                    operation.cancel();
                    relay_stop.cancel();
                }
                if observation.finished.is_some() {
                    relay_stop.cancel();
                }
                if observation
                    .drain_deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "terminal output drain timed out",
                    ));
                }
                Ok(if observation.draining {
                    RelayControl::Drain
                } else {
                    RelayControl::Continue
                })
            },
        )?;
        match result.reason {
            RelayExit::PtyClosed => Ok(()),
            RelayExit::Cancelled if observation.finished.is_some() => Ok(()),
            RelayExit::Cancelled => Err(crate::cancellation::cancellation_io()),
            RelayExit::InputClosed | RelayExit::OutputClosed => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "host terminal disconnected",
            )),
            RelayExit::Deadline => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "terminal relay timed out",
            )),
        }
    }
}

fn combine(
    frontend: io::Result<()>,
    runtime: Result<ExitStatus, SessionError>,
) -> Result<ExitStatus, SessionError> {
    match (frontend, runtime) {
        (Ok(()), result) => result,
        (Err(error), Ok(_) | Err(SessionError::Cancelled)) => Err(SessionError::Io(error)),
        (Err(frontend), Err(runtime)) => Err(SessionError::Supervision(format!(
            "terminal frontend failed: {frontend}; runtime failed: {runtime}"
        ))),
    }
}
fn disconnected() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "terminal runtime disconnected",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt as _;

    #[test]
    fn frontend_failure_is_not_hidden_by_success_or_cancellation() {
        for runtime in [
            Ok(ExitStatus::from_raw(0)),
            Err(SessionError::Cancelled),
        ] {
            let error = combine(
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "lost terminal",
                )),
                runtime,
            )
            .unwrap_err();
            assert!(error.to_string().contains("lost terminal"));
        }
        let error = combine(
            Err(io::Error::other("restore failed")),
            Err(SessionError::Supervision("owner lost".to_owned())),
        )
        .unwrap_err();
        assert!(error.to_string().contains("restore failed"));
        assert!(error.to_string().contains("owner lost"));
    }

    #[test]
    fn namespace_settlement_waits_for_drain_and_reports_failure() {
        let (events, receiver) = mpsc::channel();
        let (drained, drain_receiver) = mpsc::channel();
        let request = tempfile::tempfile().unwrap();
        // No terminal or fake custody proof is involved: this checks only the
        // post-settlement output acknowledgement callback, never activation.
        let pty = crate::platform::linux::fd::terminal::Pty::open(
            super::super::WindowSize {
                rows: 24,
                columns: 80,
                x_pixels: 0,
                y_pixels: 0,
            },
            None,
        )
        .unwrap();
        let (paused, resume) = mpsc::channel();
        let mut callbacks = FrontendCallbacks {
            host: request.into(),
            original: TerminalAttributes::read(pty.slave()).unwrap(),
            device: 0,
            operation: Cancellation::default(),
            events,
            drained: drain_receiver,
            paused: Some(paused),
        };
        std::thread::scope(|scope| {
            let child = scope.spawn(move || callbacks.namespace_settled());
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap(),
                Event::Settled
            ));
            assert_eq!(
                resume.recv_timeout(Duration::from_secs(1)),
                Ok(RelayControl::Drain)
            );
            assert!(!child.is_finished());
            drained
                .send(Err("output unavailable".to_owned()))
                .unwrap();
            assert!(
                child
                    .join()
                    .unwrap()
                    .unwrap_err()
                    .to_string()
                    .contains("output unavailable")
            );
        });
    }

    #[test]
    fn callback_channel_loss_is_detected_without_waiting_for_negotiation_timeout() {
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        assert_eq!(
            Observation::default()
                .poll(&receiver)
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn paused_relay_waits_for_resume_and_keeps_forwarding_external_cancellation() {
        let (acknowledged, acknowledgment) = mpsc::channel();
        let (resumed, resume) = mpsc::channel();
        let external = Cancellation::default();
        let operation = Cancellation::default();
        std::thread::scope(|scope| {
            let paused = scope.spawn(|| {
                RelayPause {
                    acknowledged,
                    resumed: resume,
                }
                .wait(&external, &operation)
            });
            acknowledgment
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
            assert!(!paused.is_finished());
            external.cancel();
            let deadline = Instant::now() + Duration::from_secs(1);
            while !operation.is_cancelled() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(operation.is_cancelled());
            assert!(!paused.is_finished());
            // Runtime must finish its own abort path before releasing relay ownership.
            drop(resumed);
            assert_eq!(
                paused.join().unwrap().unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        });
    }

    #[test]
    fn paused_relay_resumes_without_cancelling_normal_operation() {
        let (acknowledged, acknowledgment) = mpsc::channel();
        let (resumed, resume) = mpsc::channel();
        let external = Cancellation::default();
        let operation = Cancellation::default();
        std::thread::scope(|scope| {
            let paused = scope.spawn(|| {
                RelayPause {
                    acknowledged,
                    resumed: resume,
                }
                .wait(&external, &operation)
            });
            acknowledgment
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
            assert!(!paused.is_finished());
            resumed.send(RelayControl::Continue).unwrap();
            assert_eq!(
                paused.join().unwrap().unwrap(),
                RelayControl::Continue
            );
        });
        assert!(!external.is_cancelled());
        assert!(!operation.is_cancelled());
    }
}

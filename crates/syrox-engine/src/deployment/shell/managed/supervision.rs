//!
//! The callback runs on its caller and must settle its runtime before returning.
//! Only the read-only monitor may be detached if its bounded queries violate the
//! shutdown deadline; it owns no runtime, configuration or retention descriptors.
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::execution::journal::{
    AttemptBinding, AttemptPhase, OwnershipError, SessionId, SessionJournal, SessionPhase,
};
use crate::{
    cancellation::Cancellation, store::ContentDigest, systemd::SystemdError,
    systemd::SystemdManager, systemd::SystemdScope,
};

const QUERY_BUDGET: Duration = Duration::from_millis(250);
const ROUND_BUDGET: Duration = Duration::from_secs(2);
const INTERVAL: Duration = Duration::from_millis(100);
const JOIN_BUDGET: Duration = Duration::from_secs(2);

pub(super) struct ForegroundAuthority {
    pub journal: Arc<SessionJournal>,
    pub session: SessionId,
    pub pin: ContentDigest,
    pub owner: AttemptBinding,
    pub services: crate::execution::launcher::service_coordinator::ServiceAuthority,
    pub bus_socket: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum MonitorError {
    #[error("foreground caller cancelled")]
    CallerCancelled,
    #[error("foreground authority lost: {0}")]
    Authority(&'static str),
    #[error(transparent)]
    Journal(#[from] OwnershipError),
    #[error(transparent)]
    Manager(#[from] SystemdError),
    #[error("foreground monitor could not start: {0}")]
    Spawn(std::io::Error),
    #[error("foreground monitor panicked")]
    Panicked,
    #[error("foreground monitor did not stop within its bounded query deadline")]
    ShutdownTimeout,
}

#[derive(Debug)]
pub(super) struct SupervisedError<E> {
    pub command: Option<E>,
    pub monitor: Vec<MonitorError>,
}
impl<E: fmt::Display> fmt::Display for SupervisedError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(command) = &self.command {
            write!(formatter, "foreground command failed: {command}")?;
        }
        for (index, error) in self.monitor.iter().enumerate() {
            if self.command.is_some() || index != 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{error}")?;
        }
        Ok(())
    }
}

pub(super) fn supervise<T, E>(
    authority: ForegroundAuthority,
    caller: &Cancellation,
    run: impl FnOnce(&Cancellation) -> Result<T, E>,
) -> Result<T, SupervisedError<E>> {
    let mut manager = None;
    let mut pending = std::collections::BTreeMap::new();
    with_checker(
        caller,
        move |interrupt, deadline| {
            check_authority(
                &authority,
                &mut manager,
                &mut pending,
                interrupt,
                deadline,
            )
        },
        run,
        JOIN_BUDGET,
    )
}

fn check_authority(
    authority: &ForegroundAuthority,
    manager: &mut Option<SystemdManager>,
    pending: &mut std::collections::BTreeMap<
        String,
        crate::execution::launcher::service_coordinator::ServicePending,
    >,
    interrupt: &Cancellation,
    deadline: Instant,
) -> Result<(), MonitorError> {
    // The pump can advance Prepared/Authorized/Consumed while manager queries
    // are in flight. Reconcile a mismatch once against a new complete snapshot;
    // churn never grants an unbounded retry or accepts an active foreign head.
    for _ in 0..2 {
        let snapshot = authority.journal.snapshot(
            &authority.session,
            interrupt,
            deadline.min(Instant::now() + QUERY_BUDGET),
        )?;
        let result = check_snapshot(
            authority, &snapshot, manager, pending, interrupt, deadline,
        );
        if result.is_ok() {
            return result;
        }
        let after = authority.journal.snapshot(
            &authority.session,
            interrupt,
            deadline.min(Instant::now() + QUERY_BUDGET),
        )?;
        if after.revision == snapshot.revision {
            return result;
        }
    }
    Err(MonitorError::Authority(
        "service authority changed during bounded observation",
    ))
}
fn check_snapshot(
    authority: &ForegroundAuthority,
    snapshot: &crate::execution::journal::SessionSnapshot,
    manager: &mut Option<SystemdManager>,
    pending: &mut std::collections::BTreeMap<
        String,
        crate::execution::launcher::service_coordinator::ServicePending,
    >,
    interrupt: &Cancellation,
    deadline: Instant,
) -> Result<(), MonitorError> {
    if snapshot.pin != authority.pin
        || !matches!(
            snapshot.phase,
            SessionPhase::Authorized | SessionPhase::Running
        )
    {
        return Err(MonitorError::Authority(
            "journal pin or lifecycle differs",
        ));
    }
    if !authority.services.healthy() {
        return Err(MonitorError::Authority(
            "service admission monitor stopped",
        ));
    }
    if !snapshot.attempts.iter().any(|attempt| {
        attempt.role == "owner"
            && attempt.phase == AttemptPhase::Consumed
            && attempt.binding.as_ref() == Some(&authority.owner)
    }) {
        return Err(MonitorError::Authority(
            "owner lacks consumed session authorization",
        ));
    }
    if snapshot.roles.len() != authority.services.roles().len() {
        return Err(MonitorError::Authority(
            "service role inventory differs",
        ));
    }
    if manager.is_none() {
        *manager = Some(SystemdManager::connect(
            SystemdScope::User {
                bus_socket: authority.bus_socket.clone(),
            },
            budget(deadline)?,
            interrupt,
        )?);
    }
    let manager = manager
        .as_mut()
        .expect("manager connection initialized");
    let status = manager
        .query(
            authority.owner.unit(),
            budget(deadline)?,
            interrupt,
        )?
        .ok_or(MonitorError::Authority("owner vanished"))?;
    if status.unit != *authority.owner.unit()
        || status.invocation != authority.owner.invocation()
        || status.active_state != "active"
    {
        return Err(MonitorError::Authority(
            "owner invocation or liveness differs",
        ));
    }
    for expected in authority.services.roles() {
        let role = snapshot
            .roles
            .iter()
            .find(|role| role.binding.name() == expected.name())
            .ok_or(MonitorError::Authority("service role missing"))?;
        if !role.authorized || role.binding != *expected {
            return Err(MonitorError::Authority(
                "service role revoked or replaced",
            ));
        }
        let head = snapshot
            .attempts
            .iter()
            .find(|attempt| attempt.id == role.head)
            .ok_or(MonitorError::Authority(
                "service attempt head missing",
            ))?;
        let status = manager
            .query(expected.unit(), budget(deadline)?, interrupt)?
            .ok_or(MonitorError::Authority("service unit vanished"))?;
        pending
            .entry(expected.name().into())
            .or_default()
            .observe(expected, head, &status, Instant::now())
            .map_err(|_| MonitorError::Authority("service role state or restart wait differs"))?;
    }
    Ok(())
}

#[cfg(test)]
fn check_service(
    role: &crate::execution::journal::RoleBinding,
    head: &crate::execution::journal::AttemptSnapshot,
    status: &crate::systemd::SystemdUnitStatus,
) -> Result<(), MonitorError> {
    crate::execution::launcher::service_coordinator::ServicePending::default()
        .observe(role, head, status, Instant::now())
        .map_err(|_| MonitorError::Authority("service role state differs"))
}

fn budget(deadline: Instant) -> Result<Duration, MonitorError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .map(|duration| duration.min(QUERY_BUDGET))
        .ok_or(MonitorError::Authority(
            "liveness query budget expired",
        ))
}

fn with_checker<T, E>(
    caller: &Cancellation,
    mut checker: impl FnMut(&Cancellation, Instant) -> Result<(), MonitorError> + Send + 'static,
    run: impl FnOnce(&Cancellation) -> Result<T, E>,
    join_budget: Duration,
) -> Result<T, SupervisedError<E>> {
    let failure = |error| SupervisedError {
        command: None,
        monitor: vec![error],
    };
    if caller.is_cancelled() {
        return Err(failure(MonitorError::CallerCancelled));
    }
    if let Err(error) = checker(caller, Instant::now() + ROUND_BUDGET) {
        return Err(SupervisedError {
            command: None,
            monitor: if caller.is_cancelled() {
                vec![error, MonitorError::CallerCancelled]
            } else {
                vec![error]
            },
        });
    }
    if caller.is_cancelled() {
        return Err(failure(MonitorError::CallerCancelled));
    }
    let local = Cancellation::default();
    let interrupt = Cancellation::default();
    let (stop, stopped) = mpsc::channel();
    let monitored_caller = caller.clone();
    let monitored_local = local.clone();
    let monitored_interrupt = interrupt.clone();
    let thread = std::thread::Builder::new()
        .name("syrox-foreground-authority".into())
        .spawn(move || {
            let _cancel_on_exit = CancelOnDrop(monitored_local);
            loop {
                if monitored_caller.is_cancelled() {
                    return Err(MonitorError::CallerCancelled);
                }
                match stopped.recv_timeout(INTERVAL) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                if monitored_caller.is_cancelled() {
                    return Err(MonitorError::CallerCancelled);
                }
                match checker(
                    &monitored_interrupt,
                    Instant::now() + ROUND_BUDGET,
                ) {
                    Ok(()) => {}
                    Err(
                        MonitorError::Manager(SystemdError::Cancelled)
                        | MonitorError::Journal(OwnershipError::Cancelled),
                    ) if monitored_interrupt.is_cancelled() => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
        })
        .map_err(|error| failure(MonitorError::Spawn(error)))?;
    let mut monitor = Monitor {
        stop,
        interrupt,
        thread: Some(thread),
        join_budget,
    };
    let result = run(&local);
    let mut errors = Vec::new();
    if let Err(error) = monitor.finish() {
        errors.push(error);
    }
    if caller.is_cancelled()
        && !errors
            .iter()
            .any(|error| matches!(error, MonitorError::CallerCancelled))
    {
        errors.push(MonitorError::CallerCancelled);
    }
    match result {
        Ok(value) if errors.is_empty() => Ok(value),
        Ok(_) => Err(SupervisedError {
            command: None,
            monitor: errors,
        }),
        Err(error) => Err(SupervisedError {
            command: Some(error),
            monitor: errors,
        }),
    }
}

struct CancelOnDrop(Cancellation);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct Monitor {
    stop: mpsc::Sender<()>,
    interrupt: Cancellation,
    thread: Option<JoinHandle<Result<(), MonitorError>>>,
    join_budget: Duration,
}
impl Monitor {
    fn finish(&mut self) -> Result<(), MonitorError> {
        self.interrupt.cancel();
        let _ = self.stop.send(());
        let thread = self.thread.take().expect("monitor joined once");
        let deadline = Instant::now() + self.join_budget;
        while !thread.is_finished() {
            if Instant::now() >= deadline {
                return Err(MonitorError::ShutdownTimeout);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        thread
            .join()
            .map_err(|_| MonitorError::Panicked)?
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.interrupt.cancel();
        let _ = self.stop.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn await_cancel(token: &Cancellation) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !token.is_cancelled() {
            assert!(
                Instant::now() < deadline,
                "monitor failed to cancel foreground"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn revoked_initial_authority_never_executes_callback() {
        let called = AtomicBool::new(false);
        let result = with_checker(
            &Cancellation::default(),
            |_, _| Err(MonitorError::Authority("closed")),
            |_| {
                called.store(true, Ordering::SeqCst);
                Ok::<_, &str>(())
            },
            JOIN_BUDGET,
        );
        assert!(!called.load(Ordering::SeqCst));
        assert!(result.unwrap_err().command.is_none());
    }

    #[test]
    fn liveness_loss_cancels_runtime_and_preserves_both_failures() {
        let checks = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&checks);
        let result = with_checker(
            &Cancellation::default(),
            move |_, _| {
                if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(())
                } else {
                    Err(MonitorError::Authority(
                        "owner invocation replaced",
                    ))
                }
            },
            |local| {
                await_cancel(local);
                Err::<(), _>("runtime settled after cancellation")
            },
            JOIN_BUDGET,
        );
        let error = result.unwrap_err();
        assert_eq!(
            error.command,
            Some("runtime settled after cancellation")
        );
        assert!(matches!(
            error.monitor.as_slice(),
            [MonitorError::Authority(_)]
        ));
        assert!(checks.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn caller_cancellation_has_its_own_cause() {
        let caller = Cancellation::default();
        let result = with_checker(
            &caller,
            |_, _| Ok(()),
            |local| {
                caller.cancel();
                await_cancel(local);
                Ok::<_, &str>(())
            },
            JOIN_BUDGET,
        );
        assert!(matches!(
            result.unwrap_err().monitor.as_slice(),
            [MonitorError::CallerCancelled]
        ));
    }

    #[test]
    fn successful_callback_stops_monitor_without_cancelling_caller() {
        let caller = Cancellation::default();
        assert_eq!(
            with_checker(
                &caller,
                |_, _| Ok(()),
                |_| Ok::<_, &str>(37),
                JOIN_BUDGET
            )
            .unwrap(),
            37
        );
        assert!(!caller.is_cancelled());
    }

    #[test]
    fn checker_panic_cancels_callback_and_is_reported() {
        let mut checks = 0;
        let result = with_checker(
            &Cancellation::default(),
            move |_, _| {
                checks += 1;
                assert_eq!(checks, 1, "injected monitor panic");
                Ok(())
            },
            |local| {
                await_cancel(local);
                Ok::<_, &str>(())
            },
            JOIN_BUDGET,
        );
        assert!(matches!(
            result.unwrap_err().monitor.as_slice(),
            [MonitorError::Panicked]
        ));
    }

    #[test]
    fn shutdown_timeout_is_bounded_and_only_detaches_read_only_checker() {
        let (entered, observed) = mpsc::channel();
        let (release, held) = mpsc::channel();
        let (finished, completion) = mpsc::channel();
        let mut checks = 0;
        let start = Instant::now();
        let result = with_checker(
            &Cancellation::default(),
            move |_, _| {
                checks += 1;
                if checks > 1 {
                    entered.send(()).unwrap();
                    let _ = held.recv_timeout(Duration::from_secs(2));
                    let _ = finished.send(());
                }
                Ok(())
            },
            |_| {
                observed
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap();
                Ok::<_, &str>(())
            },
            Duration::from_millis(20),
        );
        assert!(matches!(
            result.unwrap_err().monitor.as_slice(),
            [MonitorError::ShutdownTimeout]
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
        completion
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
    }

    #[test]
    fn role_supervision_follows_current_consumed_head_and_bounded_manager_restart() {
        use crate::execution::journal::{AttemptId, AttemptSnapshot, RoleBinding};
        use crate::{
            execution::restart::ProcessRestart, execution::restart::RestartLimits,
            systemd::SystemdUnitName, systemd::SystemdUnitStatus,
        };
        let session = SessionId::parse(&"1".repeat(32)).unwrap();
        let owner = AttemptBinding::new(
            SystemdUnitName::new("syrox-owner.service").unwrap(),
            [1; 16],
        )
        .unwrap();
        let unit = SystemdUnitName::new("syrox-service.service").unwrap();
        let pin = ContentDigest::sha256(b"pin");
        let role = RoleBinding::new(
            session.clone(),
            "service:example:main",
            pin,
            pin,
            unit.clone(),
            owner.clone(),
            ProcessRestart::OnFailure(RestartLimits::new(1, 10, 3).unwrap()),
        )
        .unwrap();
        let never = RoleBinding::new(
            session,
            role.name(),
            pin,
            pin,
            unit.clone(),
            owner,
            ProcessRestart::Never,
        )
        .unwrap();
        let mut head = AttemptSnapshot {
            service_processes: None,
            id: AttemptId::parse(&"2".repeat(32)).unwrap(),
            role: role.name().into(),
            phase: AttemptPhase::Consumed,
            binding: Some(AttemptBinding::new(unit.clone(), [2; 16]).unwrap()),
        };
        let mut status = SystemdUnitStatus {
            unit,
            invocation: vec![2; 16],
            active_state: "active".into(),
            sub_state: "running".into(),
            control_group: String::new(),
            result: "success".into(),
            main_pid: 123,
            exec_main_code: 0,
            exec_main_status: 0,
        };
        check_service(&role, &head, &status).unwrap();
        status.invocation = vec![3; 16];
        assert!(
            check_service(&role, &head, &status).is_err(),
            "active unadmitted replacement"
        );
        status.active_state = "activating".into();
        status.sub_state = "auto-restart".into();
        check_service(&role, &head, &status).unwrap();
        assert!(check_service(&never, &head, &status).is_err());
        status.result = "start-limit-hit".into();
        assert!(check_service(&role, &head, &status).is_err());
        status.result = "success".into();
        status.active_state = "active".into();
        head.binding = Some(AttemptBinding::new(status.unit.clone(), [3; 16]).unwrap());
        head.phase = AttemptPhase::Authorized;
        assert!(check_service(&role, &head, &status).is_err());
        head.phase = AttemptPhase::Consumed;
        check_service(&role, &head, &status).unwrap();
        status.active_state = "failed".into();
        assert!(check_service(&role, &head, &status).is_err());
    }
}

use super::{custody::Custody, local::LocalChannel, wire::Event};
use crate::runtime::command_proxy::{
    channel::ControlChannel,
    frontend::PreparedProxyFrontend,
    namespace_handoff::NamespaceHandoff,
    wire::{CommandProxyExit, Message},
};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd};
use std::io;
use std::os::fd::AsFd;
mod budget;
mod wakeup;
use budget::Budget;
use std::time::{Duration, Instant};
pub(super) use wakeup::Wakeup;

const NEGOTIATION: Duration = Duration::from_secs(15);
const DRAIN: Duration = Duration::from_secs(30);

pub(super) fn run(
    prepared: &PreparedProxyFrontend,
    mut local: LocalChannel,
    wakeup: &mut Wakeup,
    custody: Option<&Custody>,
    wrapper_pid: u32,
) -> io::Result<()> {
    let cancel = Cancellation::default();
    let mut namespace = None;
    let proc =
        linux_fd::open_top_directory(std::path::Path::new("/proc")).map_err(|_| invalid())?;
    let wrapper = linux_fd::open_beneath(
        proc.fd(),
        std::path::Path::new(&wrapper_pid.to_string()),
        true,
    )
    .map_err(|_| invalid())?;
    if wakeup.parent_exited()? {
        return Err(invalid());
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute(
            prepared,
            &mut local,
            wakeup,
            custody,
            &mut namespace,
            &cancel,
            &wrapper,
        )
    }))
    .unwrap_or_else(|_| Err(io::Error::other("guardian execution panicked")));
    drop(local);
    // execute's broker channel has now closed. Its monitor must abort on EOF.
    // A pinned sibling pidfd is polled only: signal0 is forbidden across PIDns.
    if let Some(namespace) = namespace
        && let Err(settlement) = linux_fd::wait_pidfd(namespace.pidfd())
    {
        return Err(cleanup_failure(result, settlement));
    }
    // A failed/closed protocol cannot acknowledge retirement. The sole wrapper
    // pipe writer closes before its waitpid, including setup errors and unwind.
    loop {
        match wakeup.tick(true) {
            Ok(false) => break,
            Ok(true) => std::thread::sleep(Duration::from_millis(20)),
            // Do not restore while the wrapper might still enter a protocol
            // STOP/raw transition. Preserve both errors without inventing proof.
            Err(error) => return Err(cleanup_failure(result, error)),
        }
    }
    let restored = custody.map_or(Ok(()), Custody::restore);
    match (result, restored) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(restore)) => Err(restore),
        (Err(primary), Err(restore)) => Err(io::Error::other(format!(
            "guardian failed: {primary}; terminal restoration failed: {restore}"
        ))),
    }
}

fn execute(
    prepared: &PreparedProxyFrontend,
    local: &mut LocalChannel,
    wakeup: &mut Wakeup,
    custody: Option<&Custody>,
    namespace: &mut Option<NamespaceHandoff>,
    cancel: &Cancellation,
    wrapper: &linux_fd::OpenedPath,
) -> io::Result<()> {
    let started = Instant::now();
    let deadline = started + NEGOTIATION;
    prepared.revalidate(cancel)?;
    let mut broker = ControlChannel::connect_ancestor(prepared.context(), cancel, deadline)?;
    let admitted = prepared.request();
    broker.send_request(
        prepared.context(),
        admitted.request(),
        [
            admitted.cwd_descriptor(),
            admitted.stdin(),
            admitted.stdout(),
            admitted.stderr(),
        ],
        cancel,
        deadline,
    )?;
    if !matches!(
        broker.receive(cancel, deadline)?,
        Message::Accepted { .. }
    ) {
        return Err(invalid());
    }
    let Message::NamespacePrepared {
        terminal,
    } = broker.receive(cancel, deadline)?
    else {
        return Err(invalid());
    };
    // Retain the handoff even when terminal expectations differ so failure
    // cleanup still waits for the kernel namespace identity before restoration.
    *namespace = Some(broker.receive_namespace(terminal, cancel, deadline)?);
    let handoff = namespace.as_mut().expect("received namespace");
    if terminal != custody.is_some() {
        return Err(invalid());
    }
    let master = handoff.take_master();
    let mut descriptors = vec![handoff.pidfd()];
    if let Some(master) = &master {
        descriptors.push(master.as_fd());
    }
    local.send(
        &Event::Prepared {
            terminal,
        },
        &descriptors,
        cancel,
        deadline,
    )?;
    drop(master);
    let mut flow = Flow {
        local,
        broker,
        custody,
        handoff,
        cancel,
        wakeup,
        state: State::default(),
        budget: Budget::new(started),
    };
    loop {
        if flow.wakeup.parent_exited()? && !flow.state.aborted {
            flow.broker.send(
                Message::Abort,
                cancel,
                Instant::now() + NEGOTIATION,
            )?;
            flow.state.aborted = true;
        }
        flow.wakeup.tick(flow.handoff.settled()?)?;
        flow.budget
            .check(Instant::now(), flow.wakeup.armed)?;
        flow.observe_wrapper(wrapper)?;
        flow.receive_local()?;
        if flow.receive_remote()? {
            return Ok(());
        }
    }
}
struct Flow<'a> {
    local: &'a mut LocalChannel,
    broker: ControlChannel,
    custody: Option<&'a Custody>,
    handoff: &'a NamespaceHandoff,
    cancel: &'a Cancellation,
    wakeup: &'a mut Wakeup,
    state: State,
    budget: Budget,
}
impl Flow<'_> {
    fn observe_wrapper(&mut self, wrapper: &linux_fd::OpenedPath) -> io::Result<()> {
        if self.state.executed
            && self.state.settlement == Settlement::Active
            && !self.state.aborted
            && matches!(self.state.stop, Stop::Running | Stop::External)
        {
            let stopped = wrapper_stopped(wrapper)?;
            if stopped && self.state.stop != Stop::External {
                self.wakeup.armed = true;
                if let Some(custodian) = self.custody {
                    custodian.restore()?;
                }
                self.broker.send(
                    Message::Signal(libc::SIGSTOP),
                    self.cancel,
                    Instant::now() + NEGOTIATION,
                )?;
                self.state.stop = Stop::External;
            } else if !stopped
                && self.state.stop == Stop::External
                && !self.handoff.settled()?
                && self
                    .custody
                    .map_or(Ok(true), Custody::is_foreground)?
            {
                if let Some(custodian) = self.custody {
                    custodian.activate()?;
                }
                self.broker.send(
                    Message::Signal(libc::SIGCONT),
                    self.cancel,
                    Instant::now() + NEGOTIATION,
                )?;
                self.state.stop = Stop::Running;
                self.wakeup.armed = false;
            }
        }
        Ok(())
    }
    fn receive_local(&mut self) -> io::Result<()> {
        if !self.state.aborted
            && let Some((event, _)) = self.local.poll(0)?
        {
            match event {
                Event::RelayReady if !self.state.committed => {
                    if let Some(custodian) = self.custody {
                        custodian.activate()?;
                    }
                    self.handoff.revalidate()?;
                    self.broker.send(
                        Message::Commit,
                        self.cancel,
                        Instant::now() + NEGOTIATION,
                    )?;
                    self.state.committed = true;
                    self.local.send(
                        &Event::RelayReady,
                        &[],
                        self.cancel,
                        Instant::now() + NEGOTIATION,
                    )?;
                }
                Event::RelayPaused {
                    pause,
                } => {
                    if self.handoff.settled()? {
                        self.state.ack_pause(pause, || Ok(()))?;
                        self.state.stop = Stop::Abandoning(pause);
                        return Ok(());
                    }
                    let signal = self.state.ack_pause(pause, || {
                        self.custody.map_or(Ok(()), Custody::restore)
                    })?;
                    // Before publishing StopReady: a failed send may have delivered it.
                    self.wakeup.armed = true;
                    self.local.send(
                        &Event::StopReady {
                            pause,
                            signal,
                        },
                        &[],
                        self.cancel,
                        Instant::now() + NEGOTIATION,
                    )?;
                }
                Event::Resume {
                    pause,
                } if self.state.stop == Stop::Internal(pause) => {
                    if !self.handoff.settled()? {
                        if let Some(custodian) = self.custody {
                            custodian.activate()?;
                        }
                        self.broker.send(
                            Message::Signal(libc::SIGCONT),
                            self.cancel,
                            Instant::now() + NEGOTIATION,
                        )?;
                    }
                    self.state.stop = Stop::Running;
                    self.wakeup.armed = false; // Sender has already passed its only STOP.
                    if self.state.settlement == Settlement::Active {
                        self.local.send(
                            &Event::ResumeReady {
                                pause,
                            },
                            &[],
                            self.cancel,
                            Instant::now() + NEGOTIATION,
                        )?;
                    }
                }
                Event::Abandoned {
                    pause,
                } if self.state.stop.matches(pause) && self.handoff.settled()? => {
                    self.state.stop = Stop::Running;
                    self.wakeup.armed = false;
                }
                Event::Drained if self.state.settlement == Settlement::Settled => {
                    restore(
                        self.custody,
                        &mut self.broker,
                        self.local,
                        self.cancel,
                    )?;
                    self.state.settlement = Settlement::Restored;
                }
                Event::Abort => {
                    self.broker.send(
                        Message::Abort,
                        self.cancel,
                        Instant::now() + NEGOTIATION,
                    )?;
                    self.state.aborted = true;
                    self.wakeup.armed = false;
                }
                _ => return Err(invalid()),
            }
        }
        Ok(())
    }
    fn receive_remote(&mut self) -> io::Result<bool> {
        if super::process::readable(self.broker.descriptor(), 20)? {
            match self
                .broker
                .receive(self.cancel, Instant::now() + NEGOTIATION)?
            {
                Message::ExecAcknowledged if self.state.committed && !self.state.executed => {
                    self.state.executed = true;
                    self.budget = Budget::Running;
                }
                Message::Stopped(signal)
                    if self.state.executed && self.state.settlement == Settlement::Active =>
                {
                    if !self.handoff.settled()?
                        && let Some(event) = self.state.observe_stop(signal)?
                    {
                        self.local.send(
                            &event,
                            &[],
                            self.cancel,
                            Instant::now() + NEGOTIATION,
                        )?;
                    }
                }
                Message::Continued
                    if self.state.executed && self.state.settlement == Settlement::Active => {}
                Message::Exited(status) if self.state.executed && self.state.exit.is_none() => {
                    self.state.exit = Some(status);
                }
                Message::NamespaceSettled
                    if self.state.settlement == Settlement::Active && self.handoff.settled()? =>
                {
                    self.state.settlement = Settlement::Settled;
                    self.budget = Budget::draining(Instant::now(), self.wakeup.armed);
                    if self.state.aborted {
                        if let Some(custodian) = self.custody {
                            custodian.restore()?;
                        }
                        self.broker.send(
                            Message::RestoreRequested,
                            self.cancel,
                            Instant::now() + NEGOTIATION,
                        )?;
                        self.state.settlement = Settlement::Restored;
                    } else {
                        self.local.send(
                            &Event::NamespaceSettled,
                            &[],
                            self.cancel,
                            Instant::now() + NEGOTIATION,
                        )?;
                    }
                }
                Message::Restored if self.state.settlement == Settlement::Restored => {}
                Message::Finished if self.state.settlement == Settlement::Restored => {
                    if !self.state.aborted {
                        self.local.send(
                            &Event::Finished(self.state.exit.ok_or_else(invalid)?),
                            &[],
                            self.cancel,
                            Instant::now() + NEGOTIATION,
                        )?;
                    }
                    return Ok(true);
                }
                Message::Abort => return Err(io::Error::other("command invocation refused")),
                _ => return Err(invalid()),
            }
        }
        Ok(false)
    }
}
#[derive(Default)]
struct State {
    committed: bool,
    executed: bool,
    stop: Stop,
    settlement: Settlement,
    aborted: bool,
    exit: Option<CommandProxyExit>,
    pause: u64,
}
impl State {
    // Stop notification alone never restores: the relay must acknowledge first.
    fn observe_stop(&mut self, signal: i32) -> io::Result<Option<Event>> {
        if self.aborted || self.stop == Stop::External {
            return Ok(None);
        }
        if self.stop != Stop::Running
            || !matches!(
                signal,
                libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
            )
        {
            return Err(invalid());
        }
        self.pause = self.pause.checked_add(1).ok_or_else(invalid)?;
        self.stop = Stop::Preparing {
            pause: self.pause,
            signal,
        };
        Ok(Some(Event::StopPreparing {
            pause: self.pause,
            signal,
        }))
    }
    fn ack_pause(
        &mut self,
        pause: u64,
        restore: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<i32> {
        if self.aborted {
            return Err(invalid());
        }
        let Stop::Preparing {
            pause: current,
            signal,
        } = self.stop
        else {
            return Err(invalid());
        };
        if current != pause {
            return Err(invalid());
        }
        restore()?;
        self.stop = Stop::Internal(pause);
        Ok(signal)
    }
}
#[derive(Default, PartialEq, Eq, Debug, Clone, Copy)]
enum Stop {
    #[default]
    Running,
    Preparing {
        pause: u64,
        signal: i32,
    },
    Internal(u64),
    Abandoning(u64),
    External,
}
impl Stop {
    fn matches(self, expected: u64) -> bool {
        matches!(self, Self::Preparing { pause, .. } | Self::Internal(pause) | Self::Abandoning(pause) if pause == expected)
    }
}
#[derive(Default, PartialEq, Eq)]
enum Settlement {
    #[default]
    Active,
    Settled,
    Restored,
}
fn restore(
    custody: Option<&Custody>,
    broker: &mut ControlChannel,
    local: &mut LocalChannel,
    cancel: &Cancellation,
) -> io::Result<()> {
    if let Some(custody) = custody {
        custody.restore()?;
    }
    local.send(
        &Event::Restored,
        &[],
        cancel,
        Instant::now() + NEGOTIATION,
    )?;
    broker.send(
        Message::RestoreRequested,
        cancel,
        Instant::now() + NEGOTIATION,
    )
}
fn cleanup_failure(primary: io::Result<()>, cleanup: io::Error) -> io::Error {
    match primary {
        Ok(()) => cleanup,
        Err(primary) => io::Error::other(format!(
            "guardian failed: {primary}; cleanup failed: {cleanup}"
        )),
    }
}
fn invalid() -> io::Error {
    io::Error::other("invalid guardian execution phase")
}

fn wrapper_stopped(wrapper: &linux_fd::OpenedPath) -> io::Result<bool> {
    use std::io::Read as _;
    let status = linux_fd::open_beneath(
        wrapper.fd(),
        std::path::Path::new("status"),
        false,
    )
    .map_err(|_| invalid())?;
    if linux_fd::filesystem_type(status.fd())? != 0x9fa0 {
        return Err(invalid());
    }
    let mut text = String::new();
    status
        .into_file()
        .take(65537)
        .read_to_string(&mut text)?;
    if text.len() > 65536 {
        return Err(invalid());
    }
    let mut fields = text
        .lines()
        .filter_map(|line| line.strip_prefix("State:"));
    let state = fields
        .next()
        .and_then(|value| value.split_whitespace().next())
        .ok_or_else(invalid)?;
    if fields.next().is_some() {
        return Err(invalid());
    }
    Ok(matches!(state, "T" | "t"))
}

#[cfg(test)]
mod tests;

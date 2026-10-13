use std::io::{self, Read as _};
use std::os::fd::{AsFd as _, AsRawFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

use super::{Inputs, NEGOTIATION, PreparedRuntimeLaunch, SignalFd, invalid};
use crate::deployment::shell::command_broker::bootstrap::BootstrapClient;
use crate::execution::launcher::rendezvous::proxy::ProxyListener;
use crate::execution::native::proxy::{
    Event,
    broker::{Broker, BrokerInputs},
    custodian::MonitorUnderCustody,
    invocation::{validate_arguments, verify_working},
    mounts::CommandsMount,
    namespace,
};
use crate::runtime::command_proxy::launch_contract::{RootEvent, RootExit};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd};

/// # Safety
/// Only the dedicated fork branch holding this custody capability calls here.
pub(super) unsafe fn run(
    mut inputs: Inputs,
    root: PreparedRuntimeLaunch,
    token: &MonitorUnderCustody,
    inherited_signals: SignalFd,
    mut barrier: UnixStream,
) -> io::Result<()> {
    let mut byte = [0];
    barrier.read_exact(&mut byte)?;
    if byte != *b"x" {
        return Err(invalid());
    }
    let mut jobs = super::job_control::Channel::new(barrier)?;
    token.validate()?;
    let original = inherited_signals.original();
    drop(inherited_signals);
    let signals = SignalFd::new()?;
    let cancel = Cancellation::default();
    let request = root_request(&root, &mut inputs)?;
    let stdio = root_stdio(inputs.terminal.as_ref())?;
    let node = inputs.node.try_clone()?;
    let commands = CommandsMount::new(inputs.directory, node)?;
    let listener = ProxyListener::from_inherited(
        inputs.listener,
        inputs.node,
        inputs.metadata.context.endpoint_identity(),
    )?;
    let (uid, gid) = (linux_fd::real_uid(), linux_fd::real_gid());
    crate::execution::native::environment::validate_uid(uid)?;
    // SAFETY: dedicated monitor, still outside all payload PID namespaces.
    crate::execution::native::checked(unsafe { libc::unshare(libc::CLONE_NEWUSER) }.into())?;
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1"))?;
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1"))?;
    token.validate()?;
    // SAFETY: dedicated monitor with retained root resources and a private
    // user namespace, creating its first gated child PID namespace.
    let mut root_namespace = unsafe {
        namespace::prepare(
            &request,
            stdio,
            inputs.cwd.try_clone()?,
            original,
            &commands,
        )?
    };
    drop(inputs.terminal.take());
    inputs.root_info.send(
        &inputs.metadata.root_announcement()?,
        &[root_namespace.pidfd()],
        Instant::now() + NEGOTIATION,
        &cancel,
    )?;
    inputs.root_gate.read_exact(&mut byte)?;
    if byte != *b"x" {
        return Err(invalid());
    }
    drop(inputs.root_gate);
    token.validate()?;
    root_namespace.release(&cancel, Instant::now() + NEGOTIATION)?;
    let bootstrap = BootstrapClient::after_root_authorization(inputs.bootstrap, inputs.peer)?;
    // The durable execution's gate zero was consumed for this root; broker
    // admission begins only now and its first private authorization is gate one.
    let root_identity = root_namespace.pidfd().try_clone_to_owned()?;
    let mut broker = Broker::new(BrokerInputs {
        listener,
        bootstrap,
        root: root_identity.as_fd(),
        custody: token,
        execution: &inputs.metadata.execution,
        commands: &commands,
        cwd: inputs.cwd,
        retention: inputs.retention,
        context: inputs.metadata.context.clone(),
        worker: inputs.metadata.worker,
        original,
    })?;
    drop(inputs.control); // Only the guardian consumes coordinator control.
    let exit = EventLoop {
        namespace: &mut root_namespace,
        broker: &mut broker,
        token,
        jobs: &mut jobs,
        info: &inputs.root_info,
        frontend: inputs.frontend.as_fd(),
        signals: &signals,
        cancel: &cancel,
    }
    .run()?;
    drop(broker); // Settle all siblings before publishing the root outcome.
    inputs.root_info.send(
        &exit.encode(),
        &[],
        Instant::now() + NEGOTIATION,
        &cancel,
    )?;
    drop(root);
    Ok(())
}

struct EventLoop<'a, 'b> {
    namespace: &'a mut namespace::ProxyNamespace,
    broker: &'a mut Broker<'b>,
    token: &'a MonitorUnderCustody,
    jobs: &'a mut super::job_control::Channel,
    info: &'a crate::execution::transport::PacketChannel,
    frontend: BorrowedFd<'a>,
    signals: &'a SignalFd,
    cancel: &'a Cancellation,
}
impl EventLoop<'_, '_> {
    fn process_job(&mut self, stopped: &mut Option<(u64, i32, u8)>) -> io::Result<()> {
        match self.jobs.receive()? {
            Some(super::job_control::Event::Prepare(seq)) => {
                let Some((current, signal, 0)) = *stopped else {
                    return Err(invalid());
                };
                if current != seq {
                    return Err(invalid());
                }
                self.info.send(
                    &RootEvent::Stopping {
                        sequence: seq,
                        signal,
                    }
                    .encode()?,
                    &[],
                    Instant::now() + NEGOTIATION,
                    self.cancel,
                )?;
                *stopped = Some((seq, signal, 1));
            }
            Some(super::job_control::Event::Paused(seq)) => {
                let Some((current, signal, 1)) = *stopped else {
                    return Err(invalid());
                };
                if current != seq {
                    return Err(invalid());
                }
                self.info.send(
                    &RootEvent::Stopped {
                        sequence: seq,
                        signal,
                    }
                    .encode()?,
                    &[],
                    Instant::now() + NEGOTIATION,
                    self.cancel,
                )?;
                *stopped = Some((seq, signal, 2));
            }
            Some(super::job_control::Event::Resume(seq)) => {
                if !stopped.is_some_and(|(current, _, notified)| current == seq && notified == 2) {
                    return Err(invalid());
                }
                self.namespace.signal(libc::SIGCONT)?;
                if let Some((_, _, phase)) = stopped {
                    *phase = 3;
                }
            }
            Some(_) => return Err(invalid()),
            None => {}
        }
        Ok(())
    }
    fn run(&mut self) -> io::Result<RootExit> {
        let mut executed = false;
        let mut exit = None;
        let mut sequence = 0_u64;
        let mut stopped = None;
        loop {
            self.token.validate()?;
            self.process_job(&mut stopped)?;
            if linux_fd::pidfd_exited(self.frontend)? {
                return Err(crate::cancellation::cancellation_io());
            }
            while let Some(event) = self.namespace.event()? {
                match event {
                    Event::Exec => executed = true,
                    Event::Exited(status) => exit = Some(RootExit::new(status)?),
                    Event::Stopped(signal) => {
                        if stopped.is_some() {
                            return Err(invalid());
                        }
                        sequence = sequence.checked_add(1).ok_or_else(invalid)?;
                        stopped = Some((sequence, signal, 0));
                        self.jobs
                            .send(super::job_control::Event::Stopped(
                                sequence, signal,
                            ))?;
                    }
                    Event::Continued => {
                        let Some((seq, _, 3)) = stopped.take() else {
                            return Err(invalid());
                        };
                        self.info.send(
                            &RootEvent::Continued {
                                sequence: seq,
                            }
                            .encode()?,
                            &[],
                            Instant::now() + NEGOTIATION,
                            self.cancel,
                        )?;
                    }
                }
            }
            if self.namespace.try_settled()?.is_some() {
                // Drain once after observing exit: a final status packet may have
                // arrived between the first read and the pidfd observation.
                while let Some(event) = self.namespace.event()? {
                    if let Event::Exited(status) = event {
                        exit = Some(RootExit::new(status)?);
                    }
                }
                let exit = exit.ok_or_else(invalid)?;
                return Ok(exit);
            }
            while let Some(signal) = self.signals.take()? {
                if signal != libc::SIGCHLD {
                    if executed {
                        self.namespace.signal(signal)?;
                    } else {
                        return Err(crate::cancellation::cancellation_io());
                    }
                }
            }
            // SAFETY: this is still the dedicated monitor; the custodian capability
            // checked by Broker excludes copied init/payload processes.
            if let Err(error) = unsafe { self.broker.tick(self.cancel) } {
                if linux_fd::pidfd_exited(self.namespace.pidfd())? {
                    continue;
                }
                return Err(error);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

fn root_request(
    root: &PreparedRuntimeLaunch,
    inputs: &mut Inputs,
) -> io::Result<crate::execution::configuration::WorkerRequest> {
    let mut request = root
        .spec
        .worker_request(&root.descriptors)
        .map_err(|_| invalid())?;
    verify_working(
        root,
        inputs.cwd.as_fd(),
        inputs.metadata.context.working_directory(),
    )?;
    if request.cwd != inputs.metadata.context.working_directory() || request.terminal.is_some() {
        return Err(invalid());
    }
    request
        .arguments
        .extend(std::mem::take(&mut inputs.arguments));
    validate_arguments(&request.arguments)?;
    request.terminal = inputs.terminal.as_ref().map(AsRawFd::as_raw_fd);
    Ok(request)
}

fn root_stdio(terminal: Option<&std::os::fd::OwnedFd>) -> io::Result<[std::os::fd::OwnedFd; 3]> {
    if let Some(terminal) = terminal {
        Ok([
            terminal.try_clone()?,
            terminal.try_clone()?,
            terminal.try_clone()?,
        ])
    } else {
        for fd in 0..3 {
            // SAFETY: scalar validity probe before constructing a Rust borrow.
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: standard descriptors belong to this dedicated helper and are
        // only borrowed to produce independently owned CLOEXEC duplicates.
        Ok(unsafe {
            [
                BorrowedFd::borrow_raw(0).try_clone_to_owned()?,
                BorrowedFd::borrow_raw(1).try_clone_to_owned()?,
                BorrowedFd::borrow_raw(2).try_clone_to_owned()?,
            ]
        })
    }
}

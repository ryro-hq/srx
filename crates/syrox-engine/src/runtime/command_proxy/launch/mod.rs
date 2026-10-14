use std::ffi::OsString;
use std::io::{self, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use crate::deployment::shell::command_broker::{
    bootstrap::{BootstrapServer, scope::with_server},
    preparation::PreparedCommandBroker,
};
use crate::execution::journal::{SessionJournal, execution::ExecutionGuard};
use crate::execution::launcher::{
    rendezvous::Listener,
    service_spec::send_resources,
    transport::{PacketChannel, Peer},
};
use crate::platform::linux::fd::{self as linux_fd, PreparedLaunch, Spawned};
use crate::{cancellation::Cancellation, deployment::shell::SessionError};

use super::{
    launch_contract::{self, EntryDescriptors, EntryMetadata, RootControl, RootEvent},
    namespace_handoff::NamespaceHandoff,
    settlement::{ObservedCommandExecutionSettlement, SettlementReceiver},
};

use crate::runtime::terminal_custody::{
    RootPauseOutcome, RuntimeTerminalRequest, TerminalFrontend,
};

pub(crate) enum Attachment<'a> {
    Borrowed(Option<BorrowedFd<'a>>),
    Owned(
        Box<RuntimeTerminalRequest>,
        &'a mut dyn TerminalFrontend,
    ),
}

mod progress;
use progress::{Action, RootProgress};

const NEGOTIATION: Duration = Duration::from_secs(15);

/// The scope guard must close the lifetime endpoint before waiting. Killing the
/// guardian would destroy the process responsible for collecting its children.
struct Process<'a> {
    child: Spawned,
    custody: Option<(
        RuntimeTerminalRequest,
        &'a mut dyn TerminalFrontend,
    )>,
    control: Option<UnixStream>,
    gate: Option<UnixStream>,
}
impl Process<'_> {
    fn abort(&mut self) {
        self.gate.take();
        self.control.take();
    }
}
impl Drop for Process<'_> {
    fn drop(&mut self) {
        self.abort();
        // Custody EOF must reach the guardian before waiting for it, including
        // a failure or unwind during the initial Ready/RawActive handshake.
        self.custody.take();
        let _ = self.child.wait();
    }
}

/// The root selector comes from this broker's prepared consumer, so its closure
/// belongs to the same durable union as every public command. No external
/// `RuntimeClosure` can be substituted here. The managed frontend provides
/// terminal composition for the dedicated worker entry.
// Keep the spawn boundary and every cleanup outcome in one auditable scope.
pub(crate) fn run(
    prepared: &PreparedCommandBroker<'_>,
    journal: &SessionJournal,
    listener: &Listener,
    alias: &str,
    arguments: &[OsString],
    attachment: Attachment<'_>,
    operation: &Cancellation,
) -> Result<ExitStatus, SessionError> {
    let (terminal, custody) = match attachment {
        Attachment::Borrowed(terminal) => (terminal, None),
        Attachment::Owned(request, frontend) => (None, Some((*request, frontend))),
    };
    launch_contract::validate_stdio(
        custody
            .as_ref()
            .and_then(|(request, _)| request.slave())
            .or(terminal),
    )?;
    // Probe pinned process-group signaling before journal or raw-mode effects.
    // The guardian must be able to wake a frontend that stops after root death.
    let frontend_group = custody
        .as_ref()
        .map(|_| linux_fd::PinnedProcessGroup::capture(std::process::id()))
        .transpose()?;
    let root = prepared.prepare_invocation(alias, operation)?;
    launch_contract::validate_root_arguments(&root.spec.arguments, arguments)?;
    let root_spec = root.spec.digest().map_err(supervision)?;
    let mut execution = journal
        .prepare_execution(
            prepared.session(),
            prepared.index().digest(),
            operation,
            deadline(),
        )
        .map_err(supervision)?;
    let metadata = EntryMetadata::new(
        prepared.context().clone(),
        execution.execution().clone(),
        prepared.durable_retention_digest(),
        prepared.worker_digest(),
        root_spec,
        arguments,
    )?;
    if listener.node_identity()? != metadata.context.endpoint_identity() {
        return Err(supervision(
            "command listener does not match prepared context",
        ));
    }
    prepared.directory().revalidate(operation)?;
    let (bootstrap, bootstrap_remote) = PacketChannel::pair()?;
    let (settlement, settlement_remote) = PacketChannel::pair()?;
    let (resources, resources_remote) = PacketChannel::pair()?;
    let (root_info, root_info_remote) = PacketChannel::pair()?;
    let (control, control_remote) = UnixStream::pair()?;
    let (gate, gate_remote) = UnixStream::pair()?;
    let [listener_fd, listener_node] = listener.proxy_descriptors()?;
    let retention = prepared.process_retention()?;
    let frontend = linux_fd::pidfd_open(std::process::id())?;
    let worker = prepared.directory().path().join("worker");
    let mut command = PreparedLaunch::new(worker.as_os_str())?;
    command.arg("__runtime-managed-commands")?;
    launch_contract::configure(
        &mut command,
        &metadata,
        &EntryDescriptors {
            bootstrap: bootstrap_remote.as_fd(),
            settlement: settlement_remote.as_fd(),
            control: control_remote.as_fd(),
            resources: resources_remote.as_fd(),
            root_info: root_info_remote.as_fd(),
            root_gate: gate_remote.as_fd(),
            listener: listener_fd.as_fd(),
            listener_node: listener_node.as_fd(),
            directory: prepared.directory().directory(),
            cwd: prepared.cwd_descriptor(),
            retention: retention.as_fd(),
            frontend_pidfd: frontend.as_fd(),
            frontend_group: frontend_group
                .as_ref()
                .map(linux_fd::PinnedProcessGroup::fd),
        },
        custody
            .as_ref()
            .and_then(|(request, _)| request.slave())
            .or(terminal),
    )?;
    if let Some((request, _)) = &custody {
        request.configure(&mut command)?;
    }
    command.args(arguments)?;
    let hold = prepared.persist_execution(execution.execution(), operation)?;
    execution
        .retain(hold, operation, deadline())
        .map_err(supervision)?;
    execution
        .begin_start(operation, deadline())
        .map_err(supervision)?;
    let child = command.spawn()?;
    let mut process = Process {
        child,
        custody,
        control: Some(control),
        gate: Some(gate),
    };
    if let Some((request, _)) = &mut process.custody {
        request.spawned();
    }
    drop((
        bootstrap_remote,
        settlement_remote,
        resources_remote,
        root_info_remote,
        control_remote,
        gate_remote,
        listener_fd,
        listener_node,
        retention,
        frontend,
        frontend_group,
    ));
    let guardian = linux_fd::pidfd_open(process.child.id())?;
    let peer = Peer {
        pid: process.child.id(),
        uid: linux_fd::effective_uid(),
        gid: linux_fd::effective_gid(),
    };
    let mut receiver = None;
    let mut observed = None;
    let result = (|| -> Result<ExitStatus, SessionError> {
        receiver = Some(SettlementReceiver::new(
            settlement,
            peer,
            guardian.as_fd(),
            prepared.session(),
            execution.execution(),
            prepared.index().digest(),
            prepared.durable_retention_digest(),
        )?);
        let receiver = receiver.as_mut().expect("installed receiver");
        execution
            .bind_guardian(receiver, operation, deadline())
            .map_err(supervision)?;
        if let Some((request, _)) = &mut process.custody {
            request.own_guardian(receiver, guardian.as_fd())?;
        }
        // Guardian receives the private root resources before forking its monitor.
        send_resources(
            &resources,
            &root.spec,
            &root
                .descriptors
                .iter()
                .map(|fd| fd.as_fd())
                .collect::<Vec<_>>(),
            root.retention.as_fd(),
            deadline(),
            operation,
        )
        .map_err(supervision)?;
        if let Some((request, frontend)) = &mut process.custody {
            request.activate(*frontend, operation)?;
        }
        let limit = deadline();
        let monitor = loop {
            if let Some(monitor) = receiver.poll_monitor(operation, limit)? {
                break monitor;
            }
            pause(guardian.as_fd())?;
        };
        let server = BootstrapServer::new(bootstrap, monitor.peer())?;
        with_server(
            server,
            prepared,
            &execution,
            operation.clone(),
            |cancel| {
                foreground(
                    &mut process,
                    &execution,
                    &metadata,
                    &root_info,
                    monitor.peer(),
                    receiver,
                    &mut observed,
                    guardian.as_fd(),
                    cancel,
                )
            },
        )
        .map_err(supervision)
    })();
    drop((resources, root));
    let terminal_abort = if result.is_err() {
        process.abort();
        process
            .custody
            .as_mut()
            .map_or(Ok(()), |(request, _)| request.abort())
    } else {
        Ok(())
    };
    // Keep the proof even if status decoding or the resource-service thread
    // failed: those errors must not discard authentic cleanup authority.
    let cleanup = match observed {
        Some(proof) => Ok(proof),
        None => receiver
            .as_mut()
            .ok_or_else(|| io::Error::other("guardian receiver unavailable"))
            .and_then(|receiver| collect(receiver, guardian.as_fd())),
    };
    let waited = process.child.wait().and_then(|status| {
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "command guardian failed: {status}"
            )))
        }
    });
    let cleanup = cleanup.and_then(|proof| {
        if let Some((request, _)) = &mut process.custody {
            request.observe_execution_settlement(&proof)?;
        }
        execution
            .finish(proof, &Cancellation::default(), deadline())
            .map_err(io::Error::other)
    });
    let terminal_finish = process
        .custody
        .as_mut()
        .map_or(Ok(()), |(request, _)| {
            request.finish_after_monitor()
        });
    match (
        result,
        waited,
        cleanup,
        terminal_abort,
        terminal_finish,
    ) {
        (Ok(status), Ok(()), Ok(()), Ok(()), Ok(())) => Ok(status),
        (result, waited, cleanup, terminal_abort, terminal_finish) => {
            let errors = [
                result.err().map(|e| e.to_string()),
                waited.err().map(|e| e.to_string()),
                cleanup.err().map(|e| e.to_string()),
                terminal_abort.err().map(|e| e.to_string()),
                terminal_finish.err().map(|e| e.to_string()),
            ];
            Err(supervision(
                errors
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join("; "),
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)] // Keep authenticated entry, foreground supervision and independent terminal cleanup in one ownership scope.
fn foreground(
    process: &mut Process<'_>,
    execution: &ExecutionGuard<'_>,
    metadata: &EntryMetadata,
    info: &PacketChannel,
    monitor: Peer,
    receiver: &mut SettlementReceiver,
    observed: &mut Option<ObservedCommandExecutionSettlement>,
    guardian: BorrowedFd<'_>,
    cancel: &Cancellation,
) -> io::Result<ExitStatus> {
    let packet = info.receive(monitor, 1, deadline(), cancel)?;
    if packet.bytes != metadata.root_announcement()? {
        return Err(io::Error::other(
            "root namespace announcement mismatch",
        ));
    }
    let namespace = NamespaceHandoff::new(packet.descriptors, false)?;
    execution
        .with_started_execution(0, cancel, deadline(), || {
            namespace.revalidate()?;
            if namespace.settled()? {
                return Err(io::Error::other(
                    "root namespace exited before gate",
                ));
            }
            process
                .gate
                .as_mut()
                .ok_or_else(|| io::Error::other("root gate closed"))?
                .write_all(b"x")
        })
        .map_err(io::Error::other)?;
    process.gate.take();
    let mut progress = RootProgress::default();
    loop {
        cancel
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        if progress.status().is_none() {
            let action = progress.drain(|| {
                info.try_receive(monitor, 0)?
                    .map(|packet| RootEvent::decode(&packet.bytes))
                    .transpose()
            })?;
            // Root death only suppresses job control. Global cleanup still
            // requires the guardian's authenticated settlement below.
            if namespace.settled()?
                || progress.status().is_some()
                || root_action(process, action, namespace.pidfd(), cancel)?
                    == RootPauseOutcome::Abandoned
            {
                abandon_pause(process, &mut progress)?;
            } else if let Action::Suspend {
                sequence,
                ..
            } = action
            {
                // R is already queued successfully. A subsequent root exit
                // must not send X for the same completed frontend pause.
                progress.resume_sent(sequence)?;
            }
        }
        if let Some((request, frontend)) = &mut process.custody {
            request.poll_settled(*frontend, cancel)?;
        }
        if let Some(proof) = receiver.poll(cancel, deadline())? {
            *observed = Some(proof);
            // The guardian may finish between the first nonblocking read and
            // this proof. Drain queued root events without pausing an already
            // settled job. Bound the drain independently of socket capacity.
            for _ in 0..4096 {
                if progress.status().is_some() {
                    break;
                }
                let Some(packet) = info.try_receive(monitor, 0)? else {
                    break;
                };
                progress.accept(RootEvent::decode(&packet.bytes)?)?;
            }
            return progress
                .status()
                .ok_or_else(|| io::Error::other("root status missing after settlement"));
        }
        pause(guardian)?;
    }
}

fn root_action(
    process: &mut Process<'_>,
    action: Action,
    root: BorrowedFd<'_>,
    cancel: &Cancellation,
) -> io::Result<RootPauseOutcome> {
    let (sequence, resume) = match action {
        Action::None => return Ok(RootPauseOutcome::Resumed),
        Action::PauseRelay(sequence) => (sequence, false),
        Action::Suspend {
            sequence,
            ..
        } => (sequence, true),
    };
    let (request, frontend) = process
        .custody
        .as_mut()
        .ok_or_else(|| io::Error::other("root job control requires an owned terminal frontend"))?;
    if let Action::Suspend {
        signal,
        ..
    } = action
    {
        if request.pause_root(*frontend, signal, root, cancel)? == RootPauseOutcome::Abandoned {
            return Ok(RootPauseOutcome::Abandoned);
        }
    } else {
        request.prepare_pause_root(*frontend, cancel)?;
    }
    cancel
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())?;
    let bytes = if resume {
        RootControl::resume(sequence)?
    } else {
        RootControl::pause(sequence)?
    };
    process
        .control
        .as_mut()
        .ok_or_else(|| io::Error::other("guardian control closed"))?
        .write_all(&bytes)?;
    Ok(RootPauseOutcome::Resumed)
}

fn abandon_pause(process: &mut Process<'_>, progress: &mut RootProgress) -> io::Result<()> {
    if let Some(sequence) = progress.abandon_pause() {
        process
            .control
            .as_mut()
            .ok_or_else(|| io::Error::other("guardian control closed"))?
            .write_all(&RootControl::abandon(sequence)?)?;
    }
    Ok(())
}

fn collect(
    receiver: &mut SettlementReceiver,
    guardian: BorrowedFd<'_>,
) -> io::Result<ObservedCommandExecutionSettlement> {
    let cleanup = Cancellation::default();
    loop {
        if let Some(proof) = receiver.poll(&cleanup, deadline())? {
            return Ok(proof);
        }
        pause(guardian)?;
    }
}
fn pause(fd: BorrowedFd<'_>) -> io::Result<()> {
    crate::execution::native::ready(fd, 20).map(|_| ())
}
fn deadline() -> Instant {
    Instant::now() + NEGOTIATION
}
fn supervision(error: impl std::fmt::Display) -> SessionError {
    SessionError::Supervision(error.to_string())
}

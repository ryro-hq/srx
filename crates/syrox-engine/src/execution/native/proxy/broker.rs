use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;
use std::time::{Duration, Instant};

use super::{
    Event,
    custodian::MonitorUnderCustody,
    invocation::{Invocation, PreparedInvocation},
    mounts::CommandsMount,
};
use crate::deployment::shell::{
    command_broker::bootstrap::{BootstrapClient, BootstrapPoll},
    ownership::{ExecutionId, SessionId},
};
use crate::execution::launcher::{rendezvous::proxy::ProxyListener, transport::PacketChannel};
use crate::runtime::command_proxy::{
    MAX_INVOCATIONS, ProxyContext,
    channel::ControlChannel,
    fragment::RequestReceiver,
    peer::{OwnedProxyNamespaces, ProxyPeer},
    request::AdmittedProxyRequest,
    wire::{CommandProxyExit, Message},
};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest};

const ADMISSION_TIMEOUT: Duration = Duration::from_secs(15);
const RESTORE_TIMEOUT: Duration = Duration::from_secs(40);
const MAX_PENDING_EVENTS: usize = 16;

pub(super) struct Broker<'a> {
    // Entries settle children before the shared resources and listener drop.
    entries: Vec<Entry>,
    listener: ProxyListener,
    bootstrap: BootstrapClient,
    root: OwnedFd,
    custody: &'a MonitorUnderCustody,
    commands: &'a CommandsMount,
    cwd: OwnedFd,
    _retention: std::fs::File,
    context: ProxyContext,
    worker: ContentDigest,
    original: libc::sigset_t,
    bootstrap_entry: Option<SessionId>,
    bootstrap_pending: bool,
}

struct Entry {
    // Closing a wrapper channel can trigger terminal restoration in its
    // guardian: namespace destruction must happen before that EOF is emitted.
    invocation: Option<Invocation>,
    alias: Option<String>,
    spec: Option<ContentDigest>,
    channel: Option<ControlChannel>,
    raw: Option<PacketChannel>,
    peer: ProxyPeer,
    id: SessionId,
    receiver: RequestReceiver,
    admitted: Option<AdmittedProxyRequest>,
    phase: Phase,
    outgoing: VecDeque<Message>,
    master: Option<OwnedFd>,
    handoff_pending: bool,
    deadline: Option<Instant>,
    principal_exited: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Receiving,
    WaitingResources,
    AwaitAuthorization,
    WaitingAuthorization,
    WaitingCommit,
    Running,
    WaitingRestore,
    Finishing,
}

pub(super) struct BrokerInputs<'a> {
    pub listener: ProxyListener,
    pub bootstrap: BootstrapClient,
    pub root: BorrowedFd<'a>,
    pub custody: &'a MonitorUnderCustody,
    pub execution: &'a ExecutionId,
    pub commands: &'a CommandsMount,
    pub cwd: OwnedFd,
    pub retention: std::fs::File,
    pub context: ProxyContext,
    pub worker: ContentDigest,
    pub original: libc::sigset_t,
}
impl<'a> Broker<'a> {
    /// Inputs are inherited through the private runtime bootstrap. Public
    /// wrapper packets can never construct this monitor capability.
    pub(super) fn new(inputs: BrokerInputs<'a>) -> io::Result<Self> {
        inputs.listener.revalidate()?;
        inputs.custody.validate()?;
        if inputs.custody.execution() != inputs.execution || linux_fd::pidfd_exited(inputs.root)? {
            return Err(invalid());
        }
        Ok(Self {
            entries: Vec::new(),
            listener: inputs.listener,
            bootstrap: inputs.bootstrap,
            root: inputs.root.try_clone_to_owned()?,
            custody: inputs.custody,
            commands: inputs.commands,
            cwd: inputs.cwd,
            _retention: inputs.retention,
            context: inputs.context,
            worker: inputs.worker,
            original: inputs.original,
            bootstrap_entry: None,
            bootstrap_pending: false,
        })
    }

    /// # Safety
    /// Runs only in the dedicated, single-threaded runtime monitor after its
    /// private user namespace is established. No payload may call this loop.
    /// One packet per connection/bootstrap per tick; the outer monitor also
    /// drains its existing signals, root status and terminal custody each tick.
    pub(super) unsafe fn tick(&mut self, cancel: &Cancellation) -> io::Result<()> {
        if cancel.is_cancelled() || linux_fd::pidfd_exited(self.root.as_fd())? {
            self.entries.clear();
            return Err(crate::cancellation::cancellation_io());
        }
        self.custody.validate()?;
        let allowed = self.allowed(cancel)?;
        self.accept(&allowed, cancel)?;
        // SAFETY: this method retains tick's dedicated monitor contract.
        unsafe {
            self.poll_bootstrap(&allowed, cancel)?;
        }
        let mut index = 0;
        while index < self.entries.len() {
            let result = self.entries[index].tick(self.cwd.as_fd(), &allowed, cancel);
            match result {
                Ok(true) | Err(_) => {
                    self.entries.remove(index);
                }
                Ok(false) => index += 1,
            }
        }
        if !self.bootstrap_pending
            && let Some(id) = &self.bootstrap_entry
        {
            if let Some(entry) = self
                .entries
                .iter_mut()
                .find(|entry| &entry.id == id)
            {
                if entry.phase == Phase::AwaitAuthorization {
                    entry
                        .peer
                        .revalidate(&allowed, cancel, entry.limit()?)?;
                    self.custody.validate()?;
                    let invocation = entry.invocation.as_ref().ok_or_else(invalid)?;
                    if linux_fd::pidfd_exited(invocation.pidfd())? {
                        return Err(invalid());
                    }
                    let namespace = linux_fd::pidfd_namespace(
                        invocation.pidfd(),
                        linux_fd::PidfdNamespace::Pid,
                    )?;
                    self.bootstrap.begin_authorization(
                        &entry.id,
                        entry.alias.as_deref().ok_or_else(invalid)?,
                        linux_fd::metadata(namespace.as_fd())?.identity(),
                        entry.spec.ok_or_else(invalid)?,
                        cancel,
                        entry.limit()?,
                    )?;
                    entry.phase = Phase::WaitingAuthorization;
                    self.bootstrap_pending = true;
                }
            } else {
                self.bootstrap_entry = None;
            }
        }
        if self.bootstrap_entry.is_none()
            && let Some(index) = self.entries.iter().position(|entry| {
                entry.phase == Phase::WaitingResources && entry.admitted.is_some()
            })
        {
            let entry = &mut self.entries[index];
            if descriptor_budget(cancel)? {
                let alias = entry
                    .admitted
                    .as_ref()
                    .ok_or_else(invalid)?
                    .request()
                    .alias();
                self.bootstrap
                    .begin_request(&entry.id, alias, cancel, entry.limit()?)?;
                self.bootstrap_entry = Some(entry.id.clone());
                self.bootstrap_pending = true;
            } else {
                entry.phase = Phase::Finishing;
                entry.queue(Message::Abort)?;
            }
        }
        Ok(())
    }

    /// Caller must preserve tick's single-threaded monitor contract.
    unsafe fn poll_bootstrap(
        &mut self,
        allowed: &OwnedProxyNamespaces,
        cancel: &Cancellation,
    ) -> io::Result<()> {
        if self.bootstrap_pending {
            let id = self.bootstrap_entry.clone().ok_or_else(invalid)?;
            match self.bootstrap.poll_reply(cancel)? {
                BootstrapPoll::Pending => {}
                BootstrapPoll::Authorized(authorized) => {
                    self.bootstrap_pending = false;
                    self.bootstrap_entry = None;
                    if let Some(entry) = self
                        .entries
                        .iter_mut()
                        .find(|entry| entry.id == id)
                    {
                        if entry.phase != Phase::WaitingAuthorization {
                            return Err(invalid());
                        }
                        if authorized {
                            entry
                                .peer
                                .revalidate(allowed, cancel, entry.limit()?)?;
                            let deadline = entry.limit()?;
                            entry
                                .invocation
                                .as_mut()
                                .ok_or_else(invalid)?
                                .release(self.custody, cancel, deadline)?;
                            entry.phase = Phase::Running;
                            entry.deadline = None;
                        } else {
                            entry.invocation.take();
                            entry.phase = Phase::Finishing;
                            entry.queue(Message::Abort)?;
                        }
                    }
                }
                BootstrapPoll::Ready(resources) => {
                    self.bootstrap_pending = false;
                    if let Some(entry) = self
                        .entries
                        .iter_mut()
                        .find(|entry| entry.id == id)
                    {
                        if entry.phase != Phase::WaitingResources {
                            return Err(invalid());
                        }
                        if let Some(resources) = resources {
                            entry
                                .peer
                                .revalidate(allowed, cancel, entry.limit()?)?;
                            entry.spec = Some(resources.spec.digest().map_err(|_| invalid())?);
                            let admitted = entry.admitted.take().ok_or_else(invalid)?;
                            entry.alias = Some(admitted.request().alias().to_owned());
                            let prepared = PreparedInvocation::new(
                                *resources,
                                admitted,
                                self.cwd.as_fd(),
                                self.context.working_directory(),
                                cancel,
                            )?;
                            // SAFETY: tick is confined to the dedicated monitor;
                            // the unforgeable live-parent capability is checked
                            // again immediately before creating a sibling init.
                            let mut invocation = unsafe {
                                prepared.spawn(self.original, self.commands, self.custody)?
                            };
                            entry.master = invocation.take_master();
                            let terminal = entry.master.is_some();
                            entry.invocation = Some(invocation);
                            entry.handoff_pending = true;
                            entry.phase = Phase::WaitingCommit;
                            entry.queue(Message::NamespacePrepared {
                                terminal,
                            })?;
                        } else {
                            self.bootstrap_entry = None;
                            entry.phase = Phase::Finishing;
                            entry.queue(Message::Abort)?;
                        }
                    } else {
                        self.bootstrap_entry = None;
                    }
                }
            }
        }
        Ok(())
    }

    fn allowed(&self, cancel: &Cancellation) -> io::Result<OwnedProxyNamespaces> {
        let mut descriptors = vec![self.root.as_fd()];
        for entry in &self.entries {
            if let Some(invocation) = &entry.invocation
                && !linux_fd::pidfd_exited(invocation.pidfd())?
            {
                descriptors.push(invocation.pidfd());
            }
        }
        OwnedProxyNamespaces::from_owned_inits(
            &descriptors,
            cancel,
            Instant::now() + ADMISSION_TIMEOUT,
        )
    }
    fn accept(&mut self, allowed: &OwnedProxyNamespaces, cancel: &Cancellation) -> io::Result<()> {
        if self.entries.len() == MAX_INVOCATIONS {
            return Ok(());
        }
        let Some(channel) = self.listener.try_accept()? else {
            return Ok(());
        };
        let deadline = Instant::now() + ADMISSION_TIMEOUT;
        let Ok(peer) = ProxyPeer::authenticate(
            channel.peer_credentials()?,
            self.worker,
            allowed,
            cancel,
            deadline,
        ) else {
            return Ok(());
        };
        let name = linux_fd::operation_name()?;
        let id = SessionId::parse(name.strip_prefix("op-").ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        self.entries.push(Entry {
            invocation: None,
            alias: None,
            spec: None,
            channel: None,
            raw: Some(channel),
            peer,
            id,
            receiver: RequestReceiver::new(self.context.clone()),
            admitted: None,
            phase: Phase::Receiving,
            outgoing: VecDeque::new(),
            master: None,
            handoff_pending: false,
            deadline: Some(deadline),
            principal_exited: false,
        });
        Ok(())
    }
}
impl Entry {
    fn limit(&self) -> io::Result<Instant> {
        self.deadline.ok_or_else(invalid)
    }
    fn queue(&mut self, message: Message) -> io::Result<()> {
        if self.outgoing.len() == MAX_PENDING_EVENTS {
            return Err(invalid());
        }
        self.outgoing.push_back(message);
        Ok(())
    }
    fn tick(
        &mut self,
        cwd: BorrowedFd<'_>,
        allowed: &OwnedProxyNamespaces,
        cancel: &Cancellation,
    ) -> io::Result<bool> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
            || linux_fd::pidfd_exited(self.peer.pidfd())?
        {
            return Err(invalid());
        }
        if self.phase == Phase::Receiving {
            let channel = self.raw.as_ref().ok_or_else(invalid)?;
            if let Some((request, descriptors)) =
                self.receiver
                    .poll(channel, self.peer.peer(), cancel, self.limit()?)?
            {
                self.admitted = Some(AdmittedProxyRequest::validate(
                    request,
                    descriptors,
                    cwd,
                    cancel,
                )?);
                self.channel = Some(ControlChannel::new(
                    self.raw.take().ok_or_else(invalid)?,
                    self.peer.peer(),
                )?);
                self.phase = Phase::WaitingResources;
                self.queue(Message::Accepted {
                    invocation: self.id.to_string(),
                })?;
            }
            return Ok(false);
        }
        let channel = self.channel.as_mut().ok_or_else(invalid)?;
        if let Some(message) = self.outgoing.front() {
            if channel.try_send(message.clone())? {
                self.outgoing.pop_front();
            }
            return Ok(false);
        }
        if self.handoff_pending {
            if channel.try_send_namespace(
                self.invocation
                    .as_ref()
                    .ok_or_else(invalid)?
                    .pidfd(),
                self.master.as_ref().map(|fd| fd.as_fd()),
            )? {
                self.master.take();
                self.handoff_pending = false;
            }
            return Ok(false);
        }
        if self.phase == Phase::Finishing {
            return Ok(true);
        }
        if let Some(message) = channel.try_receive()? {
            match (self.phase, message) {
                (Phase::WaitingCommit, Message::Commit) => {
                    self.peer
                        .revalidate(allowed, cancel, self.limit()?)?;
                    // Public IO readiness is not journal authorization.
                    self.phase = Phase::AwaitAuthorization;
                }
                (Phase::Running, Message::Signal(signal)) => self
                    .invocation
                    .as_mut()
                    .ok_or_else(invalid)?
                    .signal(signal)?,
                (Phase::WaitingRestore, Message::RestoreRequested) => {
                    self.queue(Message::Restored)?;
                    self.queue(Message::Finished)?;
                    self.phase = Phase::Finishing;
                }
                _ => return Err(invalid()),
            }
        }
        if self.phase == Phase::Running {
            self.poll_invocation()?;
        }
        Ok(false)
    }
    fn poll_invocation(&mut self) -> io::Result<()> {
        let invocation = self.invocation.as_mut().ok_or_else(invalid)?;
        if let Some(event) = invocation.event()? {
            let message = match event {
                Event::Exec => Message::ExecAcknowledged,
                Event::Stopped(signal) => Message::Stopped(signal),
                Event::Continued => Message::Continued,
                Event::Exited(status) => {
                    self.principal_exited = true;
                    let status = if let Some(code) = status.code() {
                        CommandProxyExit::Exited(u8::try_from(code).map_err(|_| invalid())?)
                    } else {
                        CommandProxyExit::Signaled(status.signal().ok_or_else(invalid)?)
                    };
                    Message::Exited(status)
                }
            };
            self.queue(message)?;
        }
        if self.principal_exited
            && self
                .invocation
                .as_mut()
                .ok_or_else(invalid)?
                .settled()?
        {
            self.queue(Message::NamespaceSettled)?;
            self.phase = Phase::WaitingRestore;
            self.deadline = Some(Instant::now() + RESTORE_TIMEOUT);
        }
        Ok(())
    }
}
fn invalid() -> io::Error {
    io::Error::other("command broker admission or protocol refused")
}

// The monitor is single-threaded and admits only one resource transfer at a
// time. Count all currently open descriptors, then reserve the full service
// envelope plus setup/stdio/PTY/control overhead before requesting any SCM FDs.
fn descriptor_budget(cancel: &Cancellation) -> io::Result<bool> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: writable rlimit storage, read-only query.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful getrlimit initialized the structure.
    let limit = unsafe { limit.assume_init() }.rlim_cur;
    let proc =
        linux_fd::open_top_directory(std::path::Path::new("/proc")).map_err(|_| invalid())?;
    let pid = linux_fd::proc_self_pid(proc.fd())?;
    if pid != std::process::id() {
        return Err(invalid());
    }
    let mut count = 0_u64;
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        if cancel.is_cancelled() {
            return Err(crate::cancellation::cancellation_io());
        }
        entry?;
        count = count.checked_add(1).ok_or_else(invalid)?;
        if count >= limit {
            return Ok(false);
        }
    }
    let required = u64::try_from(crate::execution::resources::MAX_SERVICE_FDS + 32)
        .expect("bounded service descriptor envelope");
    Ok(count
        .checked_add(required)
        .is_some_and(|total| total <= limit))
}

use std::io;
use std::os::fd::{AsFd as _, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Instant;

use crate::cancellation::Cancellation;
use crate::execution::configuration::WorkerRequest;
use crate::execution::resources::ServiceMountKind;
use crate::platform::linux::fd::{
    self as linux_fd,
    terminal::{Pty, TerminalAttributes, WindowSize},
};
use crate::runtime::command_proxy::request::{
    AdmittedProxyRequest, MAX_ARGUMENT_BYTES, MAX_ARGUMENT_TOTAL_BYTES, MAX_ARGUMENTS,
};
use crate::runtime::launch_preparation::PreparedRuntimeLaunch;

use super::{
    Event,
    mounts::CommandsMount,
    namespace::{self, ProxyNamespace},
};

pub(super) struct PreparedInvocation {
    launch: PreparedRuntimeLaunch,
    request: WorkerRequest,
    stdio: [OwnedFd; 3],
    cwd: OwnedFd,
    terminal: Option<OwnedFd>,
    master: Option<OwnedFd>,
}

pub(super) struct Invocation {
    // Drop kills/reaps the namespace before releasing any private resources.
    namespace: ProxyNamespace,
    _launch: PreparedRuntimeLaunch,
    master: Option<OwnedFd>,
}

impl PreparedInvocation {
    pub(super) fn new(
        launch: PreparedRuntimeLaunch,
        admitted: AdmittedProxyRequest,
        authorized_cwd: BorrowedFd<'_>,
        expected_cwd: &Path,
        cancel: &Cancellation,
    ) -> io::Result<Self> {
        admitted.revalidate(authorized_cwd, cancel)?;
        let mut request = launch
            .spec
            .worker_request(&launch.descriptors)
            .map_err(|_| invalid())?;
        verify_working(&launch, authorized_cwd, expected_cwd)?;
        if request.cwd != expected_cwd || request.terminal.is_some() {
            return Err(invalid());
        }
        request
            .arguments
            .extend_from_slice(admitted.request().arguments());
        validate_arguments(&request.arguments)?;
        if admitted.request().cwd() != Path::new(".") {
            request.cwd = expected_cwd.join(admitted.request().cwd());
        }
        // Keep the received cwd FD only for admission. It is never installed as
        // an arbitrary mount or trusted as an independently supplied host path.
        let (_, cwd, stdio) = admitted.into_parts();
        let (stdio, terminal, master) = private_terminal(stdio)?;
        request.terminal = terminal.as_ref().map(AsRawFd::as_raw_fd);
        if cancel.is_cancelled() {
            return Err(crate::cancellation::cancellation_io());
        }
        Ok(Self {
            launch,
            request,
            stdio,
            cwd,
            terminal,
            master,
        })
    }

    /// # Safety
    /// Same dedicated external-monitor contract as `namespace::prepare`. The
    /// caller must revalidate peer and cwd admission immediately before this
    /// handoff; a prepared value by itself is not permission to release a gate.
    pub(super) unsafe fn spawn(
        self,
        original: libc::sigset_t,
        commands: &CommandsMount,
        custody: &super::custodian::MonitorUnderCustody,
    ) -> io::Result<Invocation> {
        custody.validate()?;
        let Self {
            launch,
            request,
            stdio,
            cwd,
            terminal,
            master,
        } = self;
        // SAFETY: forwarded from the dedicated monitor caller.
        let namespace = unsafe { namespace::prepare(&request, stdio, cwd, original, commands)? };
        // No slave writer may remain in the monitor and keep relay EOF alive.
        drop(terminal);
        Ok(Invocation {
            namespace,
            _launch: launch,
            master,
        })
    }
}

impl Invocation {
    pub(super) fn pidfd(&self) -> BorrowedFd<'_> {
        self.namespace.pidfd()
    }
    /// Transfers only the freshly allocated private master to the authenticated
    /// wrapper/guardian. No source terminal or private service FD is exported.
    pub(super) fn take_master(&mut self) -> Option<OwnedFd> {
        self.master.take()
    }
    pub(super) fn release(
        &mut self,
        custody: &super::custodian::MonitorUnderCustody,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        custody.validate()?;
        if self.master.is_some() {
            return Err(invalid());
        }
        self.namespace.release(cancel, deadline)
    }
    pub(super) fn event(&mut self) -> io::Result<Option<Event>> {
        self.namespace.event()
    }
    pub(super) fn signal(&mut self, signal: i32) -> io::Result<()> {
        self.namespace.signal(signal)
    }
    pub(super) fn settled(&mut self) -> io::Result<bool> {
        self.namespace
            .try_settled()
            .map(|status| status.is_some())
    }
}

pub(super) fn verify_working(
    launch: &PreparedRuntimeLaunch,
    cwd: BorrowedFd<'_>,
    target: &Path,
) -> io::Result<()> {
    let mut working = launch
        .spec
        .mounts
        .iter()
        .filter(|mount| mount.kind == ServiceMountKind::Working);
    let mount = working.next().ok_or_else(invalid)?;
    if working.next().is_some() || Path::new(&mount.target) != target {
        return Err(invalid());
    }
    let descriptor = launch
        .descriptors
        .get(usize::from(mount.slot))
        .ok_or_else(invalid)?;
    if linux_fd::metadata(descriptor.as_fd())?.identity() != linux_fd::metadata(cwd)?.identity() {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn validate_arguments(arguments: &[std::ffi::OsString]) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut total = 0_usize;
    if arguments.len() > MAX_ARGUMENTS {
        return Err(invalid());
    }
    for argument in arguments {
        let bytes = argument.as_bytes();
        total = total
            .checked_add(bytes.len())
            .ok_or_else(invalid)?;
        if bytes.len() > MAX_ARGUMENT_BYTES
            || bytes.contains(&0)
            || total > MAX_ARGUMENT_TOTAL_BYTES
        {
            return Err(invalid());
        }
    }
    Ok(())
}

type PrivateIo = ([OwnedFd; 3], Option<OwnedFd>, Option<OwnedFd>);
fn private_terminal(mut stdio: [OwnedFd; 3]) -> io::Result<PrivateIo> {
    let mut tty = [false; 3];
    let mut source = None;
    for (index, descriptor) in stdio.iter().enumerate() {
        if descriptor.as_raw_fd() < 3 {
            return Err(invalid());
        }
        match TerminalAttributes::read(descriptor.as_fd()) {
            Ok(attributes) => {
                let identity = linux_fd::metadata(descriptor.as_fd())?.identity();
                if let Some((previous, _, _)) = &source {
                    if *previous != identity {
                        return Err(invalid());
                    }
                } else {
                    source = Some((
                        identity,
                        attributes,
                        WindowSize::read(descriptor.as_fd())?,
                    ));
                }
                tty[index] = true;
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOTTY) => {}
            Err(error) => return Err(error),
        }
    }
    let Some((_, attributes, size)) = source else {
        return Ok((stdio, None, None));
    };
    let (master, slave) = Pty::open(size, Some(&attributes))?.into_parts();
    for (index, descriptor) in stdio.iter_mut().enumerate() {
        if tty[index] {
            *descriptor = slave.try_clone()?;
        }
    }
    Ok((stdio, Some(slave), Some(master)))
}

fn invalid() -> io::Error {
    io::Error::other("invalid prepared command invocation")
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::fd::AsFd as _;

    use super::{
        Pty, TerminalAttributes, WindowSize, linux_fd, private_terminal, validate_arguments,
    };

    #[test]
    fn effective_arguments_include_base_and_literal_extra_bytes() {
        let mut combined = vec![OsString::from("base"); 256];
        assert!(validate_arguments(&combined).is_ok());
        combined.push("extra".into());
        assert!(validate_arguments(&combined).is_err());
        let mut combined = vec![OsString::from("x".repeat(4096)); 16];
        assert!(validate_arguments(&combined).is_ok());
        combined.push("x".into());
        assert!(validate_arguments(&combined).is_err());
    }

    #[test]
    fn terminal_replacement_never_forwards_original_slave() {
        let original = Pty::open(
            WindowSize {
                rows: 24,
                columns: 80,
                x_pixels: 0,
                y_pixels: 0,
            },
            None,
        )
        .unwrap();
        let attributes = TerminalAttributes::read(original.slave()).unwrap();
        let source = linux_fd::metadata(original.slave())
            .unwrap()
            .identity();
        let input = std::array::from_fn(|_| original.slave().try_clone_to_owned().unwrap());
        let (stdio, terminal, master) = private_terminal(input).unwrap();
        let terminal = terminal.unwrap();
        let target = linux_fd::metadata(terminal.as_fd())
            .unwrap()
            .identity();
        assert_ne!(source, target);
        for descriptor in &stdio {
            assert_eq!(
                linux_fd::metadata(descriptor.as_fd())
                    .unwrap()
                    .identity(),
                target
            );
        }
        assert!(attributes.matches(&TerminalAttributes::read(terminal.as_fd()).unwrap()));
        assert!(master.is_some());
        assert!(attributes.matches(&TerminalAttributes::read(original.slave()).unwrap()));
    }
}

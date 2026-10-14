use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::{AsFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::{custodian, settlement};
use crate::execution::native::{signals::SignalFd, terminal_custody::Custody};
use crate::execution::transport::{PacketChannel, Peer};
use crate::runtime::command_proxy::launch_contract::{DESCRIPTOR_COUNT, EntryMetadata};
use crate::runtime::launch_preparation::PreparedRuntimeLaunch;
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd};

mod guardian;
mod job_control;
mod monitor;
const NEGOTIATION: Duration = Duration::from_secs(15);

struct Inputs {
    metadata: EntryMetadata,
    arguments: Vec<OsString>,
    bootstrap: PacketChannel,
    settlement: Option<PacketChannel>,
    control: UnixStream,
    resources: Option<PacketChannel>,
    root_info: PacketChannel,
    root_gate: UnixStream,
    listener: OwnedFd,
    node: OwnedFd,
    directory: OwnedFd,
    cwd: OwnedFd,
    retention: File,
    frontend: OwnedFd,
    frontend_group: Option<linux_fd::PinnedProcessGroup>,
    terminal: Option<OwnedFd>,
    peer: Peer,
}

/// # Safety
/// Dedicated single-threaded worker; descriptor arguments transfer ownership.
/// No caller code may run after this helper returns.
pub(in crate::execution::native) unsafe fn run(args: &[OsString]) -> io::Result<i32> {
    let (mut inputs, custody_args, forbidden) = unsafe { receive_header(args)? };
    crate::runtime::command_proxy::launch_contract::validate_stdio(
        inputs.terminal.as_ref().map(|fd| fd.as_fd()),
    )?;
    let cancel = Cancellation::default();
    let resources = crate::execution::resources::receive_resources(
        inputs.resources.as_ref().ok_or_else(invalid)?,
        inputs.peer,
        inputs.metadata.root_spec,
        Instant::now() + NEGOTIATION,
        &cancel,
    )
    .map_err(|_| invalid())?;
    let root = PreparedRuntimeLaunch {
        spec: resources.spec,
        descriptors: resources.descriptors,
        retention: File::from(resources.retention),
        origin_interest: None,
    };
    let mut custody = if custody_args.is_empty() {
        None
    } else {
        // SAFETY: all argument descriptors have been checked for aliases; this
        // dedicated process owns the transferred terminal-control pair.
        Some(unsafe { Custody::receive(custody_args, &forbidden)? })
    };
    if custody
        .as_ref()
        .is_some_and(|custody| !custody.activated())
    {
        return Err(invalid());
    }
    let signals = SignalFd::new()?;
    let (reader, mut writer) = UnixStream::pair()?;
    // SAFETY: entry contract requires the dedicated single-threaded process.
    match unsafe { custodian::enter(&inputs.metadata.execution)? } {
        custodian::Spawn::Monitor(token) => {
            drop(writer);
            if let Some(mut copy) = custody.take() {
                copy.disarm_child();
                drop(copy);
            }
            // These endpoints must not survive in the monitor or any init.
            drop(inputs.settlement.take());
            drop(inputs.resources.take());
            drop(inputs.frontend_group.take());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // SAFETY: this is the unique child issued the custody token.
                unsafe { monitor::run(inputs, root, &token, signals, reader) }
            }));
            if let Ok(Err(error)) = &result {
                let message = format!("error: command monitor: {error}\n");
                let _ = io::stderr().lock().write_all(message.as_bytes());
            }
            // SAFETY: copied guardian owners must never unwind to caller code.
            unsafe {
                libc::_exit(if matches!(result, Ok(Ok(()))) {
                    0
                } else {
                    125
                })
            }
        }
        custodian::Spawn::Guardian(children) => {
            drop(reader);
            drop(root);
            let Inputs {
                metadata,
                settlement: channel,
                control,
                frontend,
                frontend_group,
                retention,
                peer,
                bootstrap,
                resources,
                root_info,
                root_gate,
                listener,
                node,
                directory,
                cwd,
                terminal,
                arguments: _,
            } = inputs;
            drop((
                bootstrap, resources, root_info, root_gate, listener, node, directory, cwd,
                terminal,
            ));
            let mut guardian = guardian::Guardian::new(
                children,
                custody,
                control,
                frontend,
                frontend_group,
                retention,
            );
            let channel = channel.ok_or_else(invalid)?;
            let outcome = (|| {
                let claim = guardian::Guardian::claim(&metadata)?;
                settlement::announce_monitor(
                    &channel,
                    peer,
                    guardian.children(),
                    &claim,
                    &cancel,
                    Instant::now() + NEGOTIATION,
                )?;
                writer.write_all(b"x")?;
                guardian.wait(&signals, writer)
            })();
            guardian.finish(outcome, &channel, &metadata)
        }
    }
}

unsafe fn receive_header(args: &[OsString]) -> io::Result<(Inputs, &[OsString], Vec<i32>)> {
    let metadata = EntryMetadata::decode(
        args.first()
            .and_then(|arg| arg.to_str())
            .ok_or_else(invalid)?,
    )?;
    let tail = args
        .len()
        .checked_sub(metadata.root_arguments_count())
        .ok_or_else(invalid)?;
    if !matches!(tail, 15 | 21) {
        return Err(invalid());
    }
    metadata.validate_root_arguments(&args[tail..])?;
    let (numbers, group, terminal) = header_descriptors(args, tail)?;
    for fd in &numbers {
        // SAFETY: each inherited descriptor was probed and is uniquely owned.
        crate::execution::native::checked(
            unsafe { libc::fcntl(*fd, libc::F_SETFD, libc::FD_CLOEXEC) }.into(),
        )?;
    }
    let mut owned = numbers[..DESCRIPTOR_COUNT].iter().map(|fd| {
        // SAFETY: distinct, live inherited descriptors transferred by caller.
        unsafe { OwnedFd::from_raw_fd(*fd) }
    });
    let bootstrap = PacketChannel::from_owned(owned.next().ok_or_else(invalid)?)?;
    let settlement = PacketChannel::from_owned(owned.next().ok_or_else(invalid)?)?;
    let control = UnixStream::from(owned.next().ok_or_else(invalid)?);
    control.set_nonblocking(true)?;
    let resources = PacketChannel::from_owned(owned.next().ok_or_else(invalid)?)?;
    let root_info = PacketChannel::from_owned(owned.next().ok_or_else(invalid)?)?;
    let root_gate = UnixStream::from(owned.next().ok_or_else(invalid)?);
    let listener = owned.next().ok_or_else(invalid)?;
    let node = owned.next().ok_or_else(invalid)?;
    let directory = owned.next().ok_or_else(invalid)?;
    let cwd = owned.next().ok_or_else(invalid)?;
    let retention = File::from(owned.next().ok_or_else(invalid)?);
    let frontend = owned.next().ok_or_else(invalid)?;
    let peer = resources.peer_credentials()?;
    // SAFETY: scalar process query in dedicated helper.
    let parent = unsafe { libc::getppid() }.cast_unsigned();
    let fresh = linux_fd::pidfd_open(parent)?;
    if peer.pid != parent
        || peer.uid != linux_fd::real_uid()
        || peer.gid != linux_fd::real_gid()
        || linux_fd::require_unique_pidfd(frontend.as_fd())?.identity()
            != linux_fd::require_unique_pidfd(fresh.as_fd())?.identity()
        || linux_fd::pidfd_exited(frontend.as_fd())?
    {
        return Err(invalid());
    }
    let frontend_group = if let Some(group) = group {
        let parse = |position: usize| {
            args[position]
                .to_str()
                .ok_or_else(invalid)?
                .parse::<u32>()
                .map_err(|_| invalid())
        };
        // SAFETY: optional group descriptor is distinct and owned by this entry.
        let group = unsafe { OwnedFd::from_raw_fd(group) };
        Some(linux_fd::PinnedProcessGroup::from_received(
            group,
            frontend.as_fd(),
            peer.pid,
            parse(18)?,
            parse(19)?,
        )?)
    } else {
        None
    };
    let terminal = terminal.map(|fd| {
        // SAFETY: optional terminal was checked distinct from all channels.
        unsafe { OwnedFd::from_raw_fd(fd) }
    });
    if let Some(terminal) = &terminal {
        linux_fd::terminal::validate_slave(terminal.as_fd())?;
    }
    Ok((
        Inputs {
            metadata,
            arguments: args[tail..].to_vec(),
            bootstrap,
            settlement: Some(settlement),
            control,
            resources: Some(resources),
            root_info,
            root_gate,
            listener,
            node,
            directory,
            cwd,
            retention,
            frontend,
            frontend_group,
            terminal,
            peer,
        },
        &args[15..tail],
        numbers,
    ))
}
fn invalid() -> io::Error {
    io::Error::other("invalid private command runtime entry")
}

fn header_descriptors(
    args: &[OsString],
    tail: usize,
) -> io::Result<(Vec<i32>, Option<i32>, Option<i32>)> {
    let mut numbers = Vec::with_capacity(DESCRIPTOR_COUNT + 2);
    for value in &args[1..=DESCRIPTOR_COUNT] {
        let fd = crate::execution::native::fd(value)?;
        if numbers.contains(&fd) {
            return Err(invalid());
        }
        numbers.push(fd);
    }
    let mut optional_fd = |value: &OsString| -> io::Result<Option<i32>> {
        if value == "none" {
            return Ok(None);
        }
        let descriptor = crate::execution::native::fd(value)?;
        if numbers.contains(&descriptor) {
            return Err(invalid());
        }
        numbers.push(descriptor);
        Ok(Some(descriptor))
    };
    let group = optional_fd(&args[13])?;
    let terminal = optional_fd(&args[14])?;
    if (tail == 21) != group.is_some() || (tail == 21 && terminal.is_none()) {
        return Err(invalid());
    }
    Ok((numbers, group, terminal))
}

//! A Linux helper that prepares the namespace and supervises the payload.
//!
//! It runs in a dedicated process with one thread. The monitor retains namespace
//! PID 1 until its wait completes. Losing the coordinator closes the control
//! channel and drives execution toward settlement.
//!
//! [`proxy::custodian`] adopts and reaps descendants independently of the monitor.
//! [`terminal_custody`] owns terminal restoration and its concurrency limits.

use std::ffi::{CString, OsString};
use std::io::{self, Read as _};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::Path;
use std::process::Command;

use crate::execution::configuration::{MountKind, WorkerRequest};
mod secrets;

pub(crate) mod build;
pub(crate) mod build_policy;
mod command_exit;
pub use command_exit::reraise_shell_command_signal;
mod environment;
#[cfg(test)]
mod helper_tests;
mod managed;
mod process;
mod proxy;
mod signals;
pub(crate) mod terminal_custody;
pub(crate) use managed::prepare_managed_runtime;

fn checked(result: libc::c_long) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn text(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)
}

fn mount(
    source: Option<&Path>,
    target: &Path,
    kind: Option<&std::ffi::CStr>,
    flags: libc::c_ulong,
) -> io::Result<()> {
    let source = source.map(text).transpose()?;
    let target = text(target)?;
    // SAFETY: all optional strings remain live through this synchronous syscall.
    checked(
        unsafe {
            libc::mount(
                source
                    .as_ref()
                    .map_or(std::ptr::null(), |s| s.as_ptr()),
                target.as_ptr(),
                kind.map_or(std::ptr::null(), std::ffi::CStr::as_ptr),
                flags,
                std::ptr::null(),
            )
        }
        .into(),
    )
    .map_err(|error| io::Error::other(format!("mount {source:?} on {target:?}: {error}")))
}

/// Event wait shared with the coordinator. A timeout is used only by callers
/// whose cancellation source is an externally owned atomic flag.
pub(crate) fn ready(fd: BorrowedFd<'_>, timeout: i32) -> io::Result<bool> {
    let mut item = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: item is initialized and writable for the duration of poll.
    let result = unsafe { libc::poll(&raw mut item, 1, timeout) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(result > 0)
}

pub(crate) fn wait_event(
    fd: BorrowedFd<'_>,
    cancellation: &crate::cancellation::Cancellation,
) -> io::Result<()> {
    wait_event_timeout(fd, cancellation, -1)
}

pub(crate) fn wait_event_timeout(
    fd: BorrowedFd<'_>,
    cancellation: &crate::cancellation::Cancellation,
    timeout: i32,
) -> io::Result<()> {
    let Some(wake) = cancellation.wake_fd() else {
        return ready(
            fd,
            if timeout < 0 {
                25
            } else {
                timeout.min(25)
            },
        )
        .map(|_| ());
    };
    let mut events = [
        libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: both poll entries refer to live descriptors retained by the caller.
    let result = unsafe { libc::poll(events.as_mut_ptr(), 2, timeout) };
    if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn fd(value: &OsString) -> io::Result<i32> {
    let descriptor = value
        .to_str()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 2)
        .ok_or_else(|| io::Error::other("invalid runtime descriptor"))?;
    // SAFETY: F_GETFD accepts an integer and fails for a descriptor not inherited.
    checked(unsafe { libc::fcntl(descriptor, libc::F_GETFD) }.into())?;
    Ok(descriptor)
}

fn status_code(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(9))
}

/// Internal worker entry point, before starting threads.
///
/// # Safety
/// Call only in a dedicated single-threaded process with no active borrowed
/// process-global locks. Descriptor arguments must transfer ownership of live,
/// distinct channels to this function. The init clone allocates after clone3
/// and terminates with _exit; it never returns to the caller.
pub unsafe fn runtime_helper(args: &[OsString]) -> io::Result<i32> {
    // SAFETY: forwarded dedicated-worker contract and transferred channels.
    unsafe { runtime_helper_profile(args, false) }
}

/// Managed foreground entry with preserved caller UID and private runtime filesystems.
///
/// # Safety
/// The dedicated single-threaded worker and transferred-channel requirements of
/// `runtime_helper` apply; the worker must exit after returning.
pub unsafe fn managed_runtime_helper(args: &[OsString]) -> io::Result<i32> {
    // SAFETY: forwarded dedicated-worker contract and transferred channels.
    unsafe { runtime_helper_profile(args, true) }
}

unsafe fn runtime_helper_profile(args: &[OsString], managed_environment: bool) -> io::Result<i32> {
    let mut custody = None;
    let mut normalized = Vec::new();
    let args = if args
        .first()
        .is_some_and(|a| a == "monitor-terminal")
    {
        if !managed_environment || args.len() < 11 {
            return Err(io::Error::other(
                "invalid managed custody request",
            ));
        }
        normalized.push(OsString::from("monitor"));
        normalized.extend_from_slice(&args[1..4]);
        normalized.extend_from_slice(&args[10..]);
        let mut reserved = vec![
            fd(&args[1])?,
            fd(&args[2])?,
            fd(&args[3])?,
        ];
        if let Some(tty) = crate::execution::configuration::terminal_descriptor(&normalized[4..])
            .map_err(io::Error::other)?
        {
            reserved.push(tty);
        }
        // SAFETY: dedicated monitor owns the inherited descriptors, checked for aliases.
        custody = Some(unsafe { terminal_custody::Custody::receive(&args[4..10], &reserved) }?);
        &normalized[..]
    } else {
        args
    };
    // SAFETY: same dedicated monitor and transferred descriptor contract.
    let result = if custody
        .as_ref()
        .is_some_and(|guard| !guard.activated())
    {
        Err(io::Error::other(
            "terminal frontend aborted before namespace preparation",
        ))
    } else {
        unsafe { runtime_helper_run(args, managed_environment, &mut custody) }
    };
    let settlement = custody.as_mut().map_or(
        Ok(()),
        terminal_custody::Custody::namespace_settled,
    );
    let result = match (result, settlement) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(settlement)) => Err(io::Error::other(format!(
            "runtime failed: {error}; terminal settlement failed: {settlement}"
        ))),
    };
    let restoration = custody
        .as_mut()
        .map_or(Ok(()), terminal_custody::Custody::restore);
    match (result, restoration) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(restore)) => Err(io::Error::other(format!(
            "runtime failed: {error}; terminal restoration failed: {restore}"
        ))),
    }
}

unsafe fn runtime_helper_run(
    args: &[OsString],
    managed_environment: bool,
    custody: &mut Option<terminal_custody::Custody>,
) -> io::Result<i32> {
    if args.len() < 5
        || args.len() > 4096
        || args.iter().map(|s| s.len()).sum::<usize>() > 1024 * 1024
    {
        return Err(io::Error::other("invalid runtime request"));
    }
    if args[0] != "monitor" {
        return Err(io::Error::other("invalid runtime mode"));
    }
    let control_fd = fd(&args[1])?;
    let info_fd = fd(&args[2])?;
    let gate_fd = fd(&args[3])?;
    if control_fd == info_fd || control_fd == gate_fd || info_fd == gate_fd {
        return Err(io::Error::other("aliased runtime channels"));
    }
    let terminal = crate::execution::configuration::terminal_descriptor(&args[4..])
        .map_err(io::Error::other)?;
    if let Some(terminal) = terminal {
        if [control_fd, info_fd, gate_fd].contains(&terminal) {
            return Err(io::Error::other(
                "terminal aliases runtime control channel",
            ));
        }
        // The helper is single-threaded, so this successful probe establishes a
        // live descriptor before constructing the Rust borrow below.
        checked(unsafe { libc::fcntl(terminal, libc::F_GETFD) }.into())?;
        // SAFETY: the inherited descriptor was checked and stays open through this call.
        crate::platform::linux::fd::terminal::validate_slave(unsafe {
            BorrowedFd::borrow_raw(terminal)
        })?;
    }
    // SAFETY: these distinct inherited descriptors are transferred by the caller.
    let control = unsafe { UnixStream::from_raw_fd(control_fd) };
    // SAFETY: info_fd is a distinct inherited channel, now owned here.
    let info = unsafe { std::os::fd::OwnedFd::from_raw_fd(info_fd) };
    // SAFETY: gate_fd is the third distinct channel transferred by the caller.
    let gate = unsafe { UnixStream::from_raw_fd(gate_fd) };
    // SAFETY: querying the process credentials has no memory arguments.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let null = if managed_environment {
        environment::validate_uid(uid)?;
        let request = WorkerRequest::parse(&args[4..]).map_err(io::Error::other)?;
        environment::validate_request(&request)?;
        Some(environment::open_null()?)
    } else {
        None
    };
    let (namespace_user, namespace_group) = if managed_environment {
        (uid, gid)
    } else {
        (0, 0)
    };
    // SAFETY: namespace flags are fixed; the helper is single-threaded.
    checked(unsafe { libc::unshare(libc::CLONE_NEWUSER) }.into())?;
    std::fs::write(
        "/proc/self/uid_map",
        format!("{namespace_user} {uid} 1"),
    )?;
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write(
        "/proc/self/gid_map",
        format!("{namespace_group} {gid} 1"),
    )?;
    let root = if managed_environment {
        tempfile::Builder::new()
            .permissions(std::os::unix::fs::PermissionsExt::from_mode(
                0o700,
            ))
            .tempdir()?
    } else {
        tempfile::tempdir()?
    };
    let parent = crate::platform::linux::fd::pidfd_open(std::process::id())?;
    // SAFETY: the helper's caller guarantees a fresh single-threaded process.
    // The init branch closes the monitor channels and cannot return or unwind.
    let mut child = match unsafe { process::spawn()? } {
        process::Spawn::Init => {
            if let Some(mut inherited) = custody.take() {
                inherited.disarm_child();
                drop(inherited);
            }
            drop(control);
            drop(info);
            init_process(
                parent.as_fd(),
                gate,
                root.path(),
                &args[4..],
                null,
            );
        }
        process::Spawn::Monitor(child) => child,
    };
    drop(gate);
    drop(parent);
    drop(null);
    if let Some(terminal) = terminal {
        // SAFETY: the monitor no longer uses its inherited copy; init has its own table.
        checked(unsafe { libc::close(terminal) }.into())?;
    }
    let outcome = (|| {
        crate::platform::linux::fd::send_fd(info.as_fd(), child.pidfd())?;
        drop(info);
        // SCM_RIGHTS pins the same process object even if init exits before the
        // coordinator receives it. No numeric-PID pin acknowledgement is needed.
        let custody_fds = custody
            .as_ref()
            .map_or([-1, -1], terminal_custody::Custody::descriptors);
        let mut events = [
            libc::pollfd {
                fd: control_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: child.pidfd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: custody_fds[0],
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: custody_fds[1],
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        loop {
            // SAFETY: events contains two initialized entries, both fds live.
            let result = unsafe { libc::poll(events.as_mut_ptr(), 4, -1) };
            if result < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(io::Error::last_os_error());
            }
            if events[2].revents != 0 || events[3].revents != 0 {
                child.kill()?;
                if let Some(custody) = custody {
                    custody.accept_abort()?;
                }
                break;
            }
            if events[0].revents != 0 {
                child.kill()?;
            }
            if events[0].revents != 0 || events[1].revents != 0 {
                break;
            }
        }
        Ok(())
    })();
    if outcome.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    outcome?;
    Ok(status_code(status))
}

/// Only the clone child enters this function. Catching unwinds prevents the
/// monitor's copied `TempDir` and process-retention owners from being dropped.
fn init_process(
    parent: BorrowedFd<'_>,
    gate: UnixStream,
    root: &Path,
    args: &[OsString],
    null: Option<std::fs::File>,
) -> ! {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: integer-only prctl in the fresh namespace init.
        checked(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) }.into())?;
        // getppid can be zero across PID namespaces. The inherited pidfd also
        // detects monitor death before installing the parent-death signal.
        require_live_monitor(parent)?;
        init(gate, root, args, null)
    }));
    let code = match result {
        Ok(Ok(code)) => code,
        Ok(Err(error)) => {
            eprintln!("error: {error}");
            1
        }
        Err(_) => 1,
    };
    // SAFETY: terminate the clone without running copied monitor destructors or
    // atexit handlers. PID 1 exit tears down all remaining namespace descendants.
    unsafe { libc::_exit(code) }
}

fn require_live_monitor(parent: BorrowedFd<'_>) -> io::Result<()> {
    let mut event = libc::pollfd {
        fd: parent.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: parent is a retained pidfd and event is initialized. Unlike
        // the coordinator's event loop, an interrupted probe cannot mean alive:
        // monitor death may have preceded PR_SET_PDEATHSIG in this child.
        let result = unsafe { libc::poll(&raw mut event, 1, 0) };
        if result == 0 {
            return Ok(());
        }
        if result > 0 {
            return Err(io::Error::other("runtime monitor exited"));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn init(
    gate: UnixStream,
    root: &Path,
    args: &[OsString],
    null: Option<std::fs::File>,
) -> io::Result<i32> {
    let request = WorkerRequest::parse(args).map_err(io::Error::other)?;
    init_request(gate, root, &request, None, null)
}

fn init_request(
    gate: UnixStream,
    root: &Path,
    request: &WorkerRequest,
    managed: Option<managed::ManagedInit>,
    null: Option<std::fs::File>,
) -> io::Result<i32> {
    init_request_impl(gate, root, request, managed, null, None, None)
}

fn init_request_impl(
    mut gate: UnixStream,
    root: &Path,
    request: &WorkerRequest,
    mut managed: Option<managed::ManagedInit>,
    null: Option<std::fs::File>,
    mut proxy: Option<proxy::ProxyInit>,
    commands: Option<&proxy::mounts::CommandsMount>,
) -> io::Result<i32> {
    let preparation = (|| {
        prepare_request_filesystem(root, request, null, commands)?;
        drop_privileges()
            .map_err(|error| io::Error::other(format!("runtime privilege reduction: {error}")))?;
        if let Some(proxy) = &mut proxy {
            proxy.enter_directory(&request.cwd)?;
            proxy::stdio::scrub_init_stdio()?;
        } else {
            std::env::set_current_dir(&request.cwd).map_err(|error| {
                io::Error::other(format!(
                    "runtime working directory entry: {error}"
                ))
            })?;
        }
        Ok::<_, io::Error>(())
    })();
    if let Err(error) = preparation {
        if let Some(managed) = &mut managed {
            let _ = managed.preparation.failed(&error);
        }
        return Err(error);
    }
    if let Some(managed) = &mut managed {
        managed.preparation.ready()?;
    }
    if let Some(managed) = &managed {
        managed::wait_authorization(&mut gate, &managed.signals)?;
    } else {
        let mut authorization = [0];
        gate.read_exact(&mut authorization)?;
        if authorization != *b"x" {
            return Err(io::Error::other("runtime launch refused"));
        }
    }
    drop(gate);
    let mut kept = Vec::new();
    if let Some(terminal) = request.terminal {
        kept.push(terminal);
    }
    if let Some(managed) = &managed {
        kept.push(managed.signals.descriptor().as_raw_fd());
        kept.push(managed.executed.as_raw_fd());
    }
    if let Some(proxy) = &proxy {
        kept.extend(proxy.descriptors());
    }
    close_inherited_descriptors(&kept)?;
    let mut payload = Command::new(&request.program);
    payload
        .args(&request.arguments)
        .env_clear()
        .envs(&request.environment);
    if commands.is_some() {
        payload.env("PATH", "/syrox/commands/bin");
    }
    if let Some(locale) = &request.locale {
        payload
            .env("LC_ALL", "C.utf8")
            .env("LOCPATH", locale);
    }
    // PID 1 also adopts orphaned descendants. Reap them while the principal is
    // alive, but only its status determines this invocation's result. Exiting
    // PID 1 after that result still terminates remaining descendants; the outer
    // monitor retains the existing namespace-settlement barrier.
    let terminal = request.terminal;
    let original = managed
        .as_ref()
        .map(|managed| managed.signals.original())
        .or_else(|| proxy.as_ref().map(proxy::ProxyInit::original));
    let proxy_stdio = proxy.as_ref().map(proxy::ProxyInit::stdio);
    if terminal.is_some() || original.is_some() {
        // SAFETY: only the dedicated payload child changes session/group/mask;
        // the pinned terminal stays open until this callback finishes.
        unsafe {
            payload.pre_exec(move || {
                configure_payload_child(terminal, original)?;
                if let Some(stdio) = proxy_stdio {
                    for (target, source) in [0, 1, 2].into_iter().zip(stdio) {
                        checked(libc::dup2(source, target).into())?;
                    }
                }
                Ok(())
            });
        }
    }
    let child = payload.spawn()?;
    if let Some(terminal) = request.terminal {
        // SAFETY: the payload now owns stdio duplicates; init needs no PTY slave.
        checked(unsafe { libc::close(terminal) }.into())?;
    }
    if let Some(proxy) = proxy {
        return proxy.wait(child).map(status_code);
    }
    if let Some(mut managed) = managed {
        use std::io::Write as _;
        // Command::spawn only succeeds after its exec-error pipe closes.
        managed.executed.write_all(b"e")?;
        drop(managed.executed);
        Ok(status_code(process::wait_payload_managed(
            child,
            &managed.signals,
        )?))
    } else {
        Ok(status_code(process::wait_payload(child)?))
    }
}

fn prepare_request_filesystem(
    root: &Path,
    request: &WorkerRequest,
    null: Option<std::fs::File>,
    commands: Option<&proxy::mounts::CommandsMount>,
) -> io::Result<()> {
    let managed_environment = null.is_some();
    if !managed_environment
        && request
            .mounts
            .iter()
            .any(|m| matches!(m.kind, MountKind::State | MountKind::Secret))
    {
        return Err(io::Error::other(
            "session state requires the managed runtime",
        ));
    }
    // Pin before filesystem changes. Only an explicitly supplied, validated PTY
    // permits the kernel controlling-terminal device into this private /dev.
    let tty = (managed_environment && request.terminal.is_some())
        .then(environment::open_controlling_tty)
        .transpose()?;
    // clone3 created a private mount namespace, separate from the monitor.
    mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
    )?;
    mount(
        Some(Path::new("tmpfs")),
        root,
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
    )?;
    if let Some(null) = null {
        environment::validate_cwd(&request.cwd)?;
        environment::mount(root, null.as_fd(), tty.as_ref())?;
    }
    drop(tty);
    mount_request_bindings(root, request, managed_environment)?;
    if let Some(commands) = commands {
        commands.attach(root)?;
    }
    std::fs::create_dir(root.join("oldroot"))?;
    let old = text(&root.join("oldroot"))?;
    let root = text(root)?;
    // SAFETY: both directories exist in the private mount namespace.
    checked(unsafe { libc::syscall(libc::SYS_pivot_root, root.as_ptr(), old.as_ptr()) })?;
    std::env::set_current_dir("/")?;
    // SAFETY: oldroot is the detached host mount; this affects only our namespace.
    checked(unsafe { libc::umount2(c"/oldroot".as_ptr(), libc::MNT_DETACH) }.into())?;
    std::fs::remove_dir("/oldroot")?;
    Ok(())
}

fn mount_request_bindings(
    root: &Path,
    request: &WorkerRequest,
    managed_environment: bool,
) -> io::Result<()> {
    for binding in &request.mounts {
        if binding.kind == MountKind::State {
            let file = std::fs::File::open(&binding.source)?;
            let pinned = crate::execution::configuration::validate_state_directory(file.as_fd())
                .map_err(io::Error::other)?;
            let source = crate::platform::linux::fd::directory_path(&pinned)?;
            if crate::execution::configuration::paths_overlap(&source, &request.cwd) {
                return Err(io::Error::other(
                    "working directory overlaps session state",
                ));
            }
        }
        if binding.kind == MountKind::Configuration {
            let file = std::fs::File::open(&binding.source)?;
            let pinned =
                crate::execution::configuration::validate_configuration_directory(file.as_fd())
                    .map_err(io::Error::other)?;
            let source = crate::platform::linux::fd::directory_path(&pinned)?;
            if crate::execution::configuration::paths_overlap(&source, &request.cwd) {
                return Err(io::Error::other(
                    "working directory would expose configuration",
                ));
            }
        }
        let destination = root.join(
            binding
                .target
                .strip_prefix("/")
                .map_err(io::Error::other)?,
        );
        if binding.kind == MountKind::Secret {
            secrets::mount_secret(&binding.source, &destination)?;
            continue;
        }
        std::fs::create_dir_all(&destination)?;
        if binding.kind == MountKind::Mask {
            mount(
                Some(Path::new("tmpfs")),
                &destination,
                Some(c"tmpfs"),
                libc::MS_NOSUID | libc::MS_NODEV,
            )?;
        } else {
            bind_tree(
                &binding.source,
                &destination,
                binding.kind,
                managed_environment,
            )?;
            if !matches!(
                binding.kind,
                MountKind::Working | MountKind::State
            ) {
                let target = text(&destination)?;
                let attrs = libc::mount_attr {
                    attr_set: libc::MOUNT_ATTR_RDONLY,
                    attr_clr: 0,
                    propagation: 0,
                    userns_fd: 0,
                };
                // SAFETY: target and mount_attr are live; only our namespace changes.
                checked(unsafe {
                    libc::syscall(
                        libc::SYS_mount_setattr,
                        libc::AT_FDCWD,
                        target.as_ptr(),
                        libc::AT_RECURSIVE,
                        &raw const attrs,
                        size_of_val(&attrs),
                    )
                })?;
            }
            if binding.kind == MountKind::State {
                mount(
                    None,
                    &destination,
                    None,
                    libc::MS_BIND
                        | libc::MS_REMOUNT
                        | libc::MS_NOSUID
                        | libc::MS_NODEV
                        | libc::MS_NOEXEC,
                )?;
            }
        }
    }
    Ok(())
}

fn close_inherited_descriptors(kept: &[i32]) -> io::Result<()> {
    let mut kept: Vec<_> = kept
        .iter()
        .copied()
        .map(|fd| {
            u32::try_from(fd)
                .ok()
                .filter(|fd| *fd >= 3)
                .ok_or_else(|| io::Error::other("invalid preserved descriptor"))
        })
        .collect::<io::Result<_>>()?;
    kept.sort_unstable();
    kept.dedup();
    let mut first = 3_u32;
    for fd in kept {
        if first < fd {
            // SAFETY: only explicitly retained descriptors survive into init wait.
            checked(unsafe { libc::syscall(libc::SYS_close_range, first, fd - 1, 0_u32) })?;
        }
        first = fd + 1;
    }
    // SAFETY: all remaining inherited host/channel descriptors are unnecessary.
    checked(unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0_u32) })
}

fn runtime_tree_flags(kind: MountKind, managed_environment: bool) -> i32 {
    let recursion = if managed_environment && matches!(kind, MountKind::Working | MountKind::State)
    {
        0
    } else {
        libc::AT_RECURSIVE
    };
    1 | libc::O_CLOEXEC | libc::AT_EMPTY_PATH | recursion
}

/// Reopen in the current mount namespace before mounting an inherited `f_path`.
/// The path is only a lookup hint; the pinned device/inode remain authoritative.
fn local_mount_source(
    source: &Path,
    directory: bool,
) -> io::Result<crate::platform::linux::fd::OpenedPath> {
    use std::os::unix::fs::MetadataExt as _;
    let original = std::fs::metadata(source)?;
    let local_path = if source.starts_with("/proc/self/fd") {
        std::fs::read_link(source)?
    } else {
        source.to_path_buf()
    };
    let local = if directory {
        crate::platform::linux::fd::open_top_directory(&local_path)
    } else {
        crate::platform::linux::fd::open_top(&local_path)
    }
    .map_err(|error| io::Error::other(format!("mount source reopen: {error:?}")))?;
    let actual = local.metadata().identity();
    if (original.dev(), original.ino()) != (actual.device, actual.inode) {
        return Err(io::Error::other("mount source identity changed"));
    }
    Ok(local)
}

fn bind_tree(
    source: &Path,
    destination: &Path,
    kind: MountKind,
    managed_environment: bool,
) -> io::Result<()> {
    let local = local_mount_source(source, true)?;
    if managed_environment && matches!(kind, MountKind::Working | MountKind::State) {
        crate::execution::resources::validate_managed_working_descriptor(local.fd())?;
    }
    let destination = text(destination)?;
    // SAFETY: AT_EMPTY_PATH clones the live, reopened directory directly. Its
    // existing metadata already established identity; no /proc path or new stat
    // is needed. The descriptor belongs to this mount namespace.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            local.fd().as_raw_fd(),
            c"".as_ptr(),
            runtime_tree_flags(kind, managed_environment),
        )
    };
    if raw < 0 {
        return Err(io::Error::other(format!(
            "open_tree: {}",
            io::Error::last_os_error()
        )));
    }
    let raw = i32::try_from(raw).map_err(io::Error::other)?;
    // SAFETY: successful open_tree transfers a fresh descriptor.
    let tree = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    // SAFETY: MOVE_MOUNT_F_EMPTY_PATH attaches the live detached mount at target.
    checked(unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            tree.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            4_u32,
        )
    })
}

fn drop_privileges() -> io::Result<()> {
    // SAFETY: integer-only prctl operations on this single-threaded init.
    checked(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }.into())?;
    // SECBIT_NOROOT | SECBIT_NOROOT_LOCKED prevents uid 0 regaining caps on exec.
    checked(unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 3, 0, 0, 0) }.into())?;
    for cap in 0..1024 {
        // SAFETY: dropping a numeric bounding capability has no pointers.
        // DROP succeeds even if the bit is already clear; EINVAL marks the end
        // of the kernel's capability range, so a separate READ is redundant.
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if result < 0 {
            if cap > 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                return clear_capabilities();
            }
            return Err(io::Error::last_os_error());
        }
    }
    Err(io::Error::other(
        "kernel capability range exceeds runtime support",
    ))
}

fn clear_capabilities() -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Caps {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let caps = [Caps {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset v3 expects one header and two initialized capability words.
    checked(unsafe { libc::syscall(libc::SYS_capset, &raw const header, caps.as_ptr()) })
}

/// Configure only the dedicated fork child; session/stdio/signal state is global.
unsafe fn configure_payload_child(
    terminal: Option<libc::c_int>,
    original: Option<libc::sigset_t>,
) -> io::Result<()> {
    if let Some(terminal) = terminal {
        // SAFETY: caller retains the validated terminal for this pre-exec child.
        unsafe {
            crate::platform::linux::fd::terminal::establish_controlling_terminal(
                BorrowedFd::borrow_raw(terminal),
            )?;
            checked(libc::close(terminal).into())?;
        }
    } else if original.is_some() {
        // A PTY payload is already a session/group leader after setsid, so
        // setpgid would fail EPERM. Nonterminal Managed payloads still need it.
        checked(unsafe { libc::setpgid(0, 0) }.into())?;
    }
    if let Some(original) = original {
        unsafe { signals::payload_mask(original) }?;
    }
    Ok(())
}

#[cfg(test)]
mod terminal_tests;

/// Dedicated managed command guardian entry, with journal admission supplied
/// through its private coordinator channels. No host execution fallback exists.
///
/// # Safety
/// Call only in a dedicated single-threaded worker. Descriptor arguments
/// transfer ownership, and the worker must exit after this function returns.
pub unsafe fn managed_command_runtime_helper(args: &[OsString]) -> io::Result<i32> {
    // SAFETY: forwarded dedicated-process and descriptor ownership contract.
    unsafe { proxy::entry::run(args) }
}

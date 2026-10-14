use std::fs::{File, Permissions};
use std::io::{self, Read, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::ExitStatus;
use std::time::Instant;

use super::{checked, process, signals::SignalFd};

mod diagnostics;
mod execution;
use crate::build::managed::namespace::NamespaceLayout;
use crate::cancellation::Cancellation;

#[derive(Debug)]
pub(crate) struct BuildCapture {
    pub artifacts: File,
    pub logs: File,
    identities: [crate::platform::linux::fd::FileIdentity; 2],
}
impl BuildCapture {
    pub(crate) fn from_received(artifacts: OwnedFd, logs: OwnedFd) -> io::Result<Self> {
        let identities = execution::validate_capture(artifacts.as_fd(), logs.as_fd())?;
        Ok(Self {
            artifacts: artifacts.into(),
            logs: logs.into(),
            identities,
        })
    }
    pub(crate) fn revalidate(&self) -> io::Result<()> {
        if execution::validate_capture(self.artifacts.as_fd(), self.logs.as_fd())?
            != self.identities
        {
            return Err(io::Error::other(
                "build capture descriptors changed",
            ));
        }
        Ok(())
    }
}

pub(crate) struct PreparedNamespace {
    // Settle init before root cleanup or descriptor ownership can disappear.
    child: process::NamespaceChild,
    _root: tempfile::TempDir,
    gate: Option<UnixStream>,
    executed: UnixStream,
    capture: Option<BuildCapture>,
    signals: SignalFd,
    released: bool,
    exec_confirmed: bool,
}
impl PreparedNamespace {
    pub(crate) fn pidfd(&self) -> BorrowedFd<'_> {
        self.child.pidfd()
    }
    /// Poll stop signals while the monitor is parked in an external protocol.
    /// SIGCHLD notifications may be drained: the pidfd retains exit readiness.
    pub(crate) fn check_stop(&self) -> io::Result<bool> {
        self.signals.stop_pending()
    }
    pub(crate) fn take_capture(&mut self) -> io::Result<BuildCapture> {
        self.capture
            .take()
            .ok_or_else(|| io::Error::other("build capture already transferred"))
    }
    /// Local gate only. The caller must independently hold journal admission.
    /// A failed attempt consumes the gate as well: it must never be replayed.
    pub(crate) fn release_gate(
        &mut self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        let mut gate = self
            .gate
            .take()
            .ok_or_else(|| io::Error::other("build gate already consumed"))?;
        check(cancellation, deadline)?;
        if self.capture.is_some() {
            return Err(io::Error::other(
                "build capture was not transferred before gate release",
            ));
        }
        if self.signals.stop_pending()? {
            return Err(io::Error::other(
                "build stopped before authorization",
            ));
        }
        gate.write_all(b"x")?;
        self.released = true;
        Ok(())
    }
    pub(crate) fn await_exec(
        &mut self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        if !self.released {
            return Err(io::Error::other("build gate was not released"));
        }
        if self.exec_confirmed {
            return Ok(());
        }
        loop {
            check(cancellation, deadline)?;
            // A short successful worker can already be dead. Consume its exec
            // acknowledgement before inspecting namespace exit readiness.
            if execution_ack(&mut self.executed, || {
                super::ready(self.child.pidfd(), 0)
            })? {
                self.exec_confirmed = true;
                return Ok(());
            }
            if self.signals.stop_pending()? {
                return Err(io::Error::other(
                    "build stopped before exec acknowledgement",
                ));
            }
            super::managed::poll(
                &[
                    self.executed.as_fd(),
                    self.child.pidfd(),
                    self.signals.descriptor(),
                ],
                20,
            )?;
        }
    }
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        for _ in 0..64 {
            match self.signals.take()? {
                None => break,
                Some(libc::SIGCHLD) => {}
                Some(signal) => super::signals::forward_pidfd(self.child.pidfd(), signal)?,
            }
        }
        self.child.try_wait()
    }
}
fn execution_ack(
    executed: &mut impl Read,
    exited: impl FnOnce() -> io::Result<bool>,
) -> io::Result<bool> {
    if read_exec_marker(executed)? {
        return Ok(true);
    }
    if !exited()? {
        return Ok(false);
    }
    // Exit may become ready between the first nonblocking read and poll.
    // Re-read after that observation: the child writes its ACK before exiting.
    if read_exec_marker(executed)? {
        return Ok(true);
    }
    Err(io::Error::other(
        "build exited without exec acknowledgement",
    ))
}
fn read_exec_marker(executed: &mut impl Read) -> io::Result<bool> {
    let mut byte = [0];
    loop {
        match executed.read(&mut byte) {
            Ok(1) if byte == *b"e" => return Ok(true),
            Ok(_) => return Err(io::Error::other("build exec was not confirmed")),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

/// # Safety
/// Dedicated single-threaded worker only; init always terminates via `_exit`.
pub(crate) unsafe fn prepare(
    layout: &NamespaceLayout,
    resources: &crate::build::managed::ManagedBuildResources,
    cancellation: &Cancellation,
    deadline: Instant,
) -> io::Result<PreparedNamespace> {
    check(cancellation, deadline)?;
    let uid = crate::platform::linux::fd::real_uid();
    let gid = crate::platform::linux::fd::real_gid();
    super::environment::validate_uid(uid)?;
    if uid != crate::platform::linux::fd::effective_uid()
        || gid != crate::platform::linux::fd::effective_gid()
    {
        return Err(io::Error::other(
            "build namespace requires matching caller credentials",
        ));
    }
    let (capture, writers) = execution::pipes()?;
    let signals = SignalFd::new()?;
    if signals.stop_pending()? {
        return Err(io::Error::other(
            "build stopped before namespace preparation",
        ));
    }
    let null = super::environment::open_null()?;
    let root = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()?;
    let parent = crate::platform::linux::fd::pidfd_open(std::process::id())?;
    let (mut life, child_life) = UnixStream::pair()?;
    life.set_nonblocking(true)?;
    let (mut diagnostic, diagnostic_writer) = UnixStream::pair()?;
    diagnostic.set_nonblocking(true)?;
    let (executed, executed_writer) = UnixStream::pair()?;
    executed.set_nonblocking(true)?;
    // SAFETY: the caller supplies the single-threaded dedicated-worker contract.
    checked(unsafe { libc::unshare(libc::CLONE_NEWUSER) }.into())?;
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1"))?;
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1"))?;
    // SAFETY: no shared VM/file table; the init branch never returns to owners.
    let child = match unsafe { process::spawn_build()? } {
        process::Spawn::Init => {
            drop((life, executed, capture, diagnostic));
            child_entry(
                parent.as_fd(),
                InitChannels {
                    life: child_life,
                    diagnostic: diagnostic_writer,
                    executed: executed_writer,
                    writers,
                    original: signals.original(),
                },
                root.path(),
                layout,
                resources,
                null.as_fd(),
                (cancellation, deadline),
            );
        }
        process::Spawn::Monitor(child) => child,
    };
    // Only the monitor restores its incoming mask. The cloned init keeps
    // blocked signals/signalfd; the monitor's installed cancellation handlers
    // must remain live even during bounded protocol and notification waits.
    let original_mask = signals.original();
    // SAFETY: dedicated monitor owns this thread's mask; initialized saved set.
    checked(
        unsafe {
            libc::sigprocmask(
                libc::SIG_SETMASK,
                &raw const original_mask,
                std::ptr::null_mut(),
            )
        }
        .into(),
    )?;
    drop((
        child_life,
        executed_writer,
        diagnostic_writer,
        writers,
        parent,
        null,
    ));
    wait_layout(
        &mut life,
        &mut diagnostic,
        &child,
        &signals,
        cancellation,
        deadline,
    )?;
    Ok(PreparedNamespace {
        child,
        _root: root,
        gate: Some(life),
        executed,
        capture: Some(capture),
        signals,
        released: false,
        exec_confirmed: false,
    })
}
fn wait_layout(
    life: &mut UnixStream,
    diagnostic: &mut UnixStream,
    child: &process::NamespaceChild,
    signals: &SignalFd,
    cancellation: &Cancellation,
    deadline: Instant,
) -> io::Result<()> {
    loop {
        check(cancellation, deadline)?;
        if signals.stop_pending()? {
            return Err(io::Error::other(
                "build stopped before layout readiness",
            ));
        }
        let mut byte = [0];
        match life.read(&mut byte) {
            Ok(1) if byte == *b"m" => return Ok(()),
            Ok(_) => {
                return Err(diagnostics::receive(
                    diagnostic,
                    cancellation,
                    deadline,
                ));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
        if super::ready(child.pidfd(), 0)? {
            return Err(diagnostics::receive(
                diagnostic,
                cancellation,
                deadline,
            ));
        }
        super::managed::poll(&[life.as_fd(), child.pidfd()], 20)?;
    }
}

struct InitChannels {
    life: UnixStream,
    diagnostic: UnixStream,
    executed: UnixStream,
    writers: execution::Writers,
    original: libc::sigset_t,
}
fn child_entry(
    parent: BorrowedFd<'_>,
    channels: InitChannels,
    root: &Path,
    layout: &NamespaceLayout,
    resources: &crate::build::managed::ManagedBuildResources,
    null: BorrowedFd<'_>,
    budget: (&Cancellation, Instant),
) -> ! {
    let (cancellation, deadline) = budget;
    let InitChannels {
        mut life,
        mut diagnostic,
        executed,
        writers,
        original,
    } = channels;
    let mut stage = diagnostics::Stage::Monitor;
    let prepared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> io::Result<SignalFd> {
            // SAFETY: integer-only process controls in the new namespace init.
            checked(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) }.into())?;
            super::require_live_monitor(parent)?;
            if std::process::id() != 1 {
                return Err(io::Error::other(
                    "build init is not namespace PID 1",
                ));
            }
            stage = diagnostics::Stage::Signals;
            execution::null_stdio(null)?;
            let signals = SignalFd::for_init(original)?;
            stage = diagnostics::Stage::Mounts;
            install(root, layout, resources.descriptors(), null)?;
            stage = diagnostics::Stage::Inputs;
            resources
                .verify_namespace_inputs(cancellation, deadline)
                .map_err(io::Error::other)?;
            stage = diagnostics::Stage::Verification;
            verify_mounts(layout)?;
            stage = diagnostics::Stage::Privileges;
            super::drop_privileges()?;
            stage = diagnostics::Stage::Descriptors;
            super::close_inherited_descriptors(&[
                life.as_raw_fd(),
                diagnostic.as_raw_fd(),
                executed.as_raw_fd(),
                writers.artifacts.as_raw_fd(),
                writers.logs.as_raw_fd(),
                signals.descriptor().as_raw_fd(),
            ])?;
            Ok(signals)
        },
    ));
    let code = match prepared {
        Ok(Ok(signals)) => {
            drop(diagnostic);
            let result = (|| -> io::Result<i32> {
                life.write_all(b"m")?;
                super::managed::wait_authorization(&mut life, &signals)?;
                drop(life);
                execution::execute(layout, &signals, executed, writers)
            })();
            result.unwrap_or(1)
        }
        Ok(Err(error)) => {
            diagnostics::send(&mut diagnostic, stage, &error);
            1
        }
        Err(_) => {
            diagnostics::send(
                &mut diagnostic,
                stage,
                &io::Error::other("namespace initialization panicked"),
            );
            1
        }
    };
    // SAFETY: never run copied monitor owners' destructors in the clone child.
    unsafe { libc::_exit(code) }
}
fn install(
    root: &Path,
    layout: &NamespaceLayout,
    descriptors: &[OwnedFd],
    null: BorrowedFd<'_>,
) -> io::Result<()> {
    super::mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
    )?;
    tmpfs(root, 16 * 1024 * 1024, 8192, true)?;
    for (name, bytes) in [
        ("work", layout.work_bytes),
        ("out", layout.output_bytes),
        ("tmp", 64 * 1024 * 1024),
    ] {
        let path = root.join(name);
        std::fs::create_dir(&path)?;
        tmpfs(&path, bytes, 65_536, false)?;
    }
    for entry in &layout.mounts {
        let target = root.join(
            entry
                .target
                .strip_prefix('/')
                .ok_or_else(|| io::Error::other("invalid mount target"))?,
        );
        std::fs::create_dir_all(target.parent().expect("absolute target parent"))?;
        if entry.directory {
            std::fs::create_dir(&target)?;
        } else {
            File::create(&target)?;
        }
        let source = format!(
            "/proc/self/fd/{}",
            descriptors[entry.slot].as_raw_fd()
        );
        // Inherited f_paths belong to the old mount namespace. Reopen and pin
        // the same inode locally; bind by that fd, never by a mutable pathname.
        let local = super::local_mount_source(Path::new(&source), entry.directory)?;
        let source = format!("/proc/self/fd/{}", local.fd().as_raw_fd());
        // Nonrecursive bind: undeclared submounts are never inherited.
        super::mount(
            Some(Path::new(&source)),
            &target,
            None,
            libc::MS_BIND,
        )?;
        super::mount(
            None,
            &target,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        )?;
    }
    let output = root.join(layout.output_parent.trim_start_matches('/'));
    std::fs::create_dir_all(&output)?;
    for name in &layout.outputs {
        std::fs::create_dir(output.join(name))?;
    }
    minimal_devices(root, null)?;
    pivot(root)?;
    // Only the root mount is readonly; explicit /work,/out,/tmp remain writable.
    super::mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
    )?;
    std::env::set_current_dir("/work")
}
fn minimal_devices(root: &Path, null: BorrowedFd<'_>) -> io::Result<()> {
    let proc = root.join("proc");
    std::fs::create_dir(&proc)?;
    super::mount(
        Some(Path::new("proc")),
        &proc,
        Some(c"proc"),
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
    )?;
    let dev = root.join("dev");
    std::fs::create_dir(&dev)?;
    let target = dev.join("null");
    super::environment::bind_device(&target, Path::new("/dev/null"), null)?;
    for (name, number) in [
        ("stdin", 0),
        ("stdout", 1),
        ("stderr", 2),
    ] {
        std::os::unix::fs::symlink(format!("/proc/self/fd/{number}"), dev.join(name))?;
    }
    Ok(())
}
fn pivot(root: &Path) -> io::Result<()> {
    std::fs::create_dir(root.join("oldroot"))?;
    let old = super::text(&root.join("oldroot"))?;
    let root = super::text(root)?;
    // SAFETY: both directories exist on our private namespace root mount.
    checked(unsafe { libc::syscall(libc::SYS_pivot_root, root.as_ptr(), old.as_ptr()) })?;
    std::env::set_current_dir("/")?;
    // SAFETY: detach the inherited host root only in this new mount namespace.
    checked(unsafe { libc::umount2(c"/oldroot".as_ptr(), libc::MNT_DETACH) }.into())?;
    std::fs::remove_dir("/oldroot")
}
fn tmpfs(target: &Path, bytes: u64, inodes: u64, noexec: bool) -> io::Result<()> {
    let data = std::ffi::CString::new(format!(
        "size={bytes},nr_inodes={inodes},mode=0700"
    ))
    .expect("numeric options");
    let target = super::text(target)?;
    let flags = libc::MS_NOSUID
        | libc::MS_NODEV
        | if noexec {
            libc::MS_NOEXEC
        } else {
            0
        };
    // SAFETY: all strings are live; called only in the freshly cloned namespace.
    checked(
        unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                target.as_ptr(),
                c"tmpfs".as_ptr(),
                flags,
                data.as_ptr().cast(),
            )
        }
        .into(),
    )
}
fn check(cancellation: &Cancellation, deadline: Instant) -> io::Result<()> {
    if cancellation.is_cancelled() {
        return Err(crate::cancellation::cancellation_io());
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "build namespace preparation deadline",
        ));
    }
    Ok(())
}

fn verify_mounts(layout: &NamespaceLayout) -> io::Result<()> {
    for path in ["/", "/proc"].into_iter().chain(
        layout
            .mounts
            .iter()
            .map(|entry| entry.target.as_str()),
    ) {
        if filesystem_flags(Path::new(path))? & libc::ST_RDONLY == 0 {
            return Err(io::Error::other(
                "build readonly mount was not established",
            ));
        }
    }
    for path in ["/work", "/out", "/tmp"] {
        if filesystem_flags(Path::new(path))? & libc::ST_RDONLY != 0 {
            return Err(io::Error::other(
                "build writable mount was not established",
            ));
        }
    }
    if std::fs::symlink_metadata("/usr").is_ok() {
        return Err(io::Error::other(
            "ambient host tools exposed to build",
        ));
    }
    Ok(())
}
fn filesystem_flags(path: &Path) -> io::Result<libc::c_ulong> {
    let path = super::text(path)?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: stat points to writable output, path is NUL terminated.
    checked(unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) }.into())?;
    // SAFETY: statvfs succeeded and initialized its output.
    Ok(unsafe { stat.assume_init() }.f_flag)
}

#[cfg(test)]
mod tests;

use std::io;
use std::os::fd::{AsFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

pub(super) enum Spawn {
    Init,
    Monitor(NamespaceChild),
}

/// The pidfd and the right to reap this direct child have the same owner.
/// Early returns stop and settle the namespace before releasing its resources.
pub(super) struct NamespaceChild {
    pid: libc::pid_t,
    pinned: OwnedFd,
    status: Option<ExitStatus>,
}

impl NamespaceChild {
    pub(super) fn pidfd(&self) -> BorrowedFd<'_> {
        self.pinned.as_fd()
    }

    pub(super) fn kill(&self) -> io::Result<()> {
        crate::platform::linux::fd::kill_pidfd(self.pidfd())
    }

    pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        if !crate::platform::linux::fd::pidfd_exited(self.pidfd())? {
            return Ok(None);
        }
        self.wait().map(Some)
    }

    pub(super) fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        loop {
            let mut status = 0;
            // SAFETY: pid is our unreaped direct child; status is a writable int.
            let result = unsafe { libc::waitpid(self.pid, &raw mut status, 0) };
            if result == self.pid {
                let status = ExitStatus::from_raw(status);
                self.status = Some(status);
                return Ok(status);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

impl Drop for NamespaceChild {
    fn drop(&mut self) {
        if self.status.is_none() {
            let _ = self.kill();
            let _ = self.wait();
        }
    }
}

/// Reap all children adopted by namespace PID 1 while the main payload lives.
/// Owning the `Child` prevents a second waiter in this launcher; adopted child
/// statuses cannot replace the main result. The caller exits the namespace init
/// immediately after this returns, preserving its existing lifetime contract.
pub(super) fn wait_payload(payload: std::process::Child) -> io::Result<ExitStatus> {
    let main = libc::pid_t::try_from(payload.id()).expect("spawn returns a kernel pid_t");
    let outcome = loop {
        let mut raw_status = 0;
        // SAFETY: -1 selects this process's children; raw_status is writable.
        // This function is the sole waiter in the single-threaded namespace init.
        let reaped = unsafe { libc::waitpid(-1, &raw mut raw_status, 0) };
        if reaped == main {
            break Ok(ExitStatus::from_raw(raw_status));
        }
        if reaped > 0 {
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            break Err(error);
        }
    };
    drop(payload);
    outcome
}

/// # Safety
/// The process must be single-threaded, with no active borrowed process-global
/// locks. The init branch must terminate with _exit rather than return/unwind
/// into the monitor's owners. No VM, stack or file-descriptor table is shared.
pub(super) unsafe fn spawn() -> io::Result<Spawn> {
    // SAFETY: propagated single-threaded clone contract.
    unsafe { spawn_flags(0) }
}

/// Build init additionally receives isolated network, IPC and UTS namespaces.
/// # Safety
/// The same dedicated-process requirements as `spawn` apply.
pub(super) unsafe fn spawn_build() -> io::Result<Spawn> {
    // SAFETY: propagated single-threaded clone contract.
    unsafe { spawn_flags(libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS) }
}
unsafe fn spawn_flags(extra: libc::c_int) -> io::Result<Spawn> {
    const CLONE_PIDFD: u64 = 0x1000;
    let mut pidfd: libc::c_int = -1;
    let args = CloneArgs {
        flags: CLONE_PIDFD
            | u64::from((libc::CLONE_NEWNS | libc::CLONE_NEWPID | extra).cast_unsigned()),
        pidfd: (&raw mut pidfd).addr() as u64,
        exit_signal: u64::from(libc::SIGCHLD.cast_unsigned()),
        ..CloneArgs::default()
    };
    // SAFETY: the caller establishes fork safety. With CLONE_VM unset, a null
    // stack requests a copy of the caller's stack; all ABI fields are initialized.
    // The kernel writes the newly owned pidfd into the parent's live int.
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &raw const args,
            size_of::<CloneArgs>(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result == 0 {
        return Ok(Spawn::Init);
    }
    let pid = libc::pid_t::try_from(result).expect("clone3 returns a kernel pid_t");
    // SAFETY: successful CLONE_PIDFD transfers one fresh descriptor to the parent.
    let pinned = unsafe { OwnedFd::from_raw_fd(pidfd) };
    Ok(Spawn::Monitor(NamespaceChild {
        pid,
        pinned,
        status: None,
    }))
}

/// Namespace PID1 owns the unreaped principal while forwarding to its group.
/// All adopted descendants are drained on every SIGCHLD wakeup.
pub(super) fn wait_payload_managed(
    payload: std::process::Child,
    signals: &super::signals::SignalFd,
) -> io::Result<ExitStatus> {
    let main = libc::pid_t::try_from(payload.id()).expect("kernel pid_t");
    loop {
        loop {
            let mut status = 0;
            // SAFETY: this init is the sole waiter for its own children.
            let child = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
            if child == main {
                drop(payload);
                return Ok(ExitStatus::from_raw(status));
            }
            if child > 0 {
                continue;
            }
            if child == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        let mut received = false;
        for _ in 0..64 {
            match signals.take()? {
                None => break,
                Some(libc::SIGCHLD) => received = true,
                Some(signal) => {
                    received = true;
                    super::signals::forward_group(main, signal)?;
                }
            }
        }
        if !received {
            super::managed::poll(&[signals.descriptor()], -1)?;
        }
    }
}

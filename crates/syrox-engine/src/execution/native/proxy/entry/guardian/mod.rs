use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

use super::{Custody, EntryMetadata, NEGOTIATION, PacketChannel, SignalFd, settlement};
use crate::execution::command_evidence::{GuardianIdentity, SettlementClaim};
use crate::execution::native::proxy::custodian::{MonitorCustody, SettledDescendants};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd};

pub(super) struct Guardian {
    children: MonitorCustody,
    custody: Option<Custody>,
    control: UnixStream,
    frontend: OwnedFd,
    _retention: File,
    proof: Option<SettledDescendants>,
    group: Option<linux_fd::PinnedProcessGroup>,
    pause: pause::PauseState,
    reader: control::Reader,
}
impl Guardian {
    pub(super) fn new(
        children: MonitorCustody,
        custody: Option<Custody>,
        control: UnixStream,
        frontend: OwnedFd,
        group: Option<linux_fd::PinnedProcessGroup>,
        retention: File,
    ) -> Self {
        Self {
            children,
            custody,
            control,
            frontend,
            _retention: retention,
            proof: None,
            group,
            pause: pause::PauseState::default(),
            reader: control::Reader::default(),
        }
    }
    pub(super) fn children(&self) -> &MonitorCustody {
        &self.children
    }
    pub(super) fn claim(metadata: &EntryMetadata) -> io::Result<SettlementClaim> {
        let pid = std::process::id();
        let pidfd = linux_fd::pidfd_open(pid)?;
        let identity = linux_fd::require_unique_pidfd(pidfd.as_fd())?.identity();
        SettlementClaim::new(
            &metadata.context.session()?,
            &metadata.execution,
            metadata.context.index()?,
            metadata.retention,
            GuardianIdentity {
                pid,
                uid: linux_fd::real_uid(),
                gid: linux_fd::real_gid(),
                device: identity.device,
                inode: identity.inode,
            },
        )
    }
    pub(super) fn wait(&mut self, signals: &SignalFd, jobs: UnixStream) -> io::Result<()> {
        let mut jobs = super::job_control::Channel::new(jobs)?;
        self.control.set_nonblocking(true)?;
        loop {
            if let Some(proof) = self.children.try_settled()? {
                self.proof = Some(proof);
                return if self
                    .children
                    .monitor_status()
                    .is_some_and(|status| status.success())
                {
                    Ok(())
                } else {
                    Err(io::Error::other("command monitor failed"))
                };
            }
            match jobs.receive() {
                Ok(Some(super::job_control::Event::Stopped(next, _))) => {
                    self.pause.register(next)?;
                    jobs.send(super::job_control::Event::Prepare(next))?;
                }
                Ok(Some(_)) => {
                    return Err(io::Error::other(
                        "unexpected root job-control event",
                    ));
                }
                Ok(None) => {}
                // Only wait/reaping above may establish settlement, not EOF.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
                Err(e) => return Err(e),
            }
            let abort = if let Some((tag, value)) = self.control_event()? {
                let (next, effect) = self.pause.transition(tag, value)?;
                match effect {
                    pause::Effect::Pause => {
                        if let Some(custody) = &mut self.custody {
                            custody.pause_for_job()?;
                        }
                        // Arm before the ACK can escape: a failed send must keep
                        // the wakeup obligation for the cleanup path.
                        self.pause = next;
                        jobs.send(super::job_control::Event::Paused(value))?;
                    }
                    pause::Effect::Resume => {
                        if let Some(custody) = &mut self.custody {
                            custody.resume_after_job()?;
                        }
                        jobs.send(super::job_control::Event::Resume(value))?;
                        self.pause = next;
                    }
                    pause::Effect::Abort | pause::Effect::Abandon => self.pause = next,
                }
                effect == pause::Effect::Abort
            } else {
                false
            };
            if abort || signals.stop_pending()? || linux_fd::pidfd_exited(self.frontend.as_fd())? {
                self.proof = Some(self.children.settle()?);
                return Err(crate::cancellation::cancellation_io());
            }
            if let Some(custody) = &mut self.custody {
                let descriptors = custody.descriptors();
                // SAFETY: custody retains both descriptors throughout this poll.
                if crate::execution::native::ready(
                    unsafe { std::os::fd::BorrowedFd::borrow_raw(descriptors[0]) },
                    0,
                )? {
                    custody.accept_abort()?;
                    self.proof = Some(self.children.settle()?);
                    return Err(crate::cancellation::cancellation_io());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    fn control_event(&mut self) -> io::Result<Option<(u8, u64)>> {
        self.reader.read(&mut self.control)
    }
    /// Called only after ECHILD. Wakeup remains armed until the frontend says
    /// no future protocol stop is possible, including during the S/F/D wait.
    fn wakeup_tick(&mut self) -> io::Result<bool> {
        if self.proof.is_none() {
            return Err(io::Error::other(
                "wakeup before descendant settlement",
            ));
        }
        if linux_fd::pidfd_exited(self.frontend.as_fd())? {
            self.pause.abort();
            return Ok(false);
        }
        if let Some((tag, sequence)) = self.control_event()? {
            let (next, _) = self.pause.transition(tag, sequence)?;
            // ECHILD has already been proved. Resume clears the protocol arm,
            // but must never signal a payload from this path.
            self.pause = next;
        }
        if self.pause.armed() {
            self.group
                .as_ref()
                .ok_or_else(|| io::Error::other("root pause has no pinned process group"))?
                .continue_if_stopped()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn finish_wakeup(&mut self) -> io::Result<()> {
        while self.wakeup_tick()? {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Ok(())
    }
    pub(super) fn finish(
        &mut self,
        outcome: io::Result<()>,
        channel: &PacketChannel,
        metadata: &EntryMetadata,
    ) -> io::Result<i32> {
        if self.proof.is_none() {
            match self.children.settle() {
                Ok(proof) => self.proof = Some(proof),
                Err(error) => {
                    if let Some(custody) = &mut self.custody {
                        custody.disarm_child();
                    }
                    return merge(outcome, Err(error)).map(|()| 0);
                }
            }
        }
        // Move terminal custody out while the callback watches the same
        // guardian's protocol arm. Neither a CONT nor tty restoration is proof.
        let mut custody = self.custody.take();
        let handshake = custody.as_mut().map_or(Ok(()), |custody| {
            custody.namespace_settled_with_watch(|| self.wakeup_tick())
        });
        let wakeup = self.finish_wakeup();
        let restore = custody.as_mut().map_or(Ok(()), Custody::restore);
        self.custody = custody;
        let claim = settlement::send(
            channel,
            self.proof.as_ref().expect("settled"),
            &metadata.context.session()?,
            metadata.context.index()?,
            metadata.retention,
            &Cancellation::default(),
            Instant::now() + NEGOTIATION,
        );
        merge(
            merge(outcome, handshake),
            merge(wakeup, merge(restore, claim)),
        )
        .map(|()| 0)
    }
}
impl Drop for Guardian {
    fn drop(&mut self) {
        if self.proof.is_none() {
            self.proof = self.children.settle().ok();
        }
        if self.proof.is_some() {
            let _ = self.finish_wakeup();
        }
        if let Some(custody) = &mut self.custody {
            if self.proof.is_some() {
                let _ = custody.restore();
            } else {
                custody.disarm_child();
            }
        }
    }
}
fn merge(primary: io::Result<()>, cleanup: io::Result<()>) -> io::Result<()> {
    match (primary, cleanup) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(primary), Err(cleanup)) => Err(io::Error::other(format!(
            "{primary}; cleanup failed: {cleanup}"
        ))),
    }
}

mod control;
mod pause;

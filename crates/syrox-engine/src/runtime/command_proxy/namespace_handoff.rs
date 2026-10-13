use std::io;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use crate::platform::linux::fd::{self as linux_fd, FileIdentity};

pub(crate) struct NamespaceHandoff {
    pidfd: OwnedFd,
    identity: FileIdentity,
    master: Option<OwnedFd>,
}
impl NamespaceHandoff {
    pub(super) fn new(mut descriptors: Vec<OwnedFd>, terminal: bool) -> io::Result<Self> {
        if descriptors.len() != 1 + usize::from(terminal) {
            return Err(invalid());
        }
        let master = if terminal {
            descriptors.pop()
        } else {
            None
        };
        let pidfd = descriptors.pop().ok_or_else(invalid)?;
        let identity = identity(pidfd.as_fd())?;
        if linux_fd::pidfd_exited(pidfd.as_fd())? {
            return Err(invalid());
        }
        if let Some(master) = &master {
            linux_fd::terminal::validate_master(master.as_fd())?;
        }
        Ok(Self {
            pidfd,
            identity,
            master,
        })
    }
    pub(crate) fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }
    pub(crate) fn take_master(&mut self) -> Option<OwnedFd> {
        self.master.take()
    }
    pub(crate) fn revalidate(&self) -> io::Result<()> {
        if identity(self.pidfd.as_fd())? != self.identity {
            return Err(invalid());
        }
        if let Some(master) = &self.master {
            linux_fd::terminal::validate_master(master.as_fd())?;
        }
        Ok(())
    }
    pub(crate) fn settled(&self) -> io::Result<bool> {
        self.revalidate()?;
        linux_fd::pidfd_exited(self.pidfd.as_fd())
    }
}

fn identity(fd: BorrowedFd<'_>) -> io::Result<FileIdentity> {
    // Do not use require_unique_pidfd here: its signal-zero probe requires the
    // same PID namespace or an ancestor (kernel/signal.c access_pidfd_pidns).
    if linux_fd::filesystem_type(fd)? != 0x5049_4446 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unique pidfs identities required",
        ));
    }
    let metadata = linux_fd::metadata(fd)?;
    let identity = metadata.identity();
    let flags = linux_fd::descriptor_status_flags(fd)?;
    if identity.device == 0
        || identity.inode == 0
        || metadata.mode() & libc::S_IFMT != 0
        || metadata.rdev() != 0
        || flags & (libc::O_PATH | libc::O_EXCL).cast_unsigned() != 0
    {
        return Err(invalid());
    }
    Ok(identity)
}
fn invalid() -> io::Error {
    io::Error::other("invalid command namespace descriptors")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::fd::terminal::{Pty, WindowSize};

    #[test]
    fn handoff_pins_live_pidfd_and_private_master_without_signaling_target() {
        let pidfd = linux_fd::pidfd_open(std::process::id()).unwrap();
        let pty = Pty::open(
            WindowSize {
                rows: 24,
                columns: 80,
                x_pixels: 0,
                y_pixels: 0,
            },
            None,
        )
        .unwrap();
        let master = pty.master().try_clone_to_owned().unwrap();
        let mut handoff = NamespaceHandoff::new(vec![pidfd, master], true).unwrap();
        assert!(!handoff.settled().unwrap());
        assert!(handoff.take_master().is_some());
        assert!(handoff.take_master().is_none());
        handoff.revalidate().unwrap();
    }

    #[test]
    fn handoff_rejects_role_count_regular_file_and_slave_as_master() {
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(NamespaceHandoff::new(vec![file.into()], false).is_err());
        assert!(NamespaceHandoff::new(Vec::new(), false).is_err());
        let pty = Pty::open(
            WindowSize {
                rows: 24,
                columns: 80,
                x_pixels: 0,
                y_pixels: 0,
            },
            None,
        )
        .unwrap();
        let pidfd = linux_fd::pidfd_open(std::process::id()).unwrap();
        assert!(
            NamespaceHandoff::new(
                vec![
                    pidfd,
                    pty.slave().try_clone_to_owned().unwrap()
                ],
                true
            )
            .is_err()
        );
    }
}

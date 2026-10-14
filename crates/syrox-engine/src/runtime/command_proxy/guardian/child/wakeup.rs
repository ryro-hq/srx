use crate::platform::linux::fd::{self as linux_fd, PinnedProcessGroup};
use std::io::{self, Read as _};
use std::os::fd::{AsFd as _, OwnedFd};

pub(in crate::runtime::command_proxy::guardian) struct Wakeup {
    group: PinnedProcessGroup,
    retirement: std::fs::File,
    parent: OwnedFd,
    pub(super) armed: bool,
}
impl Wakeup {
    pub(crate) fn new(group: PinnedProcessGroup, retirement: OwnedFd, parent: OwnedFd) -> Self {
        Self {
            group,
            retirement: retirement.into(),
            parent,
            armed: false,
        }
    }
    pub(super) fn parent_exited(&self) -> io::Result<bool> {
        linux_fd::pidfd_exited(self.parent.as_fd())
    }
    pub(super) fn tick(&mut self, namespace_exited: bool) -> io::Result<bool> {
        if !self.armed {
            return Ok(false);
        }
        if self.parent_exited()? || self.retired()? {
            self.armed = false;
            return Ok(false);
        }
        if namespace_exited {
            self.group.continue_if_stopped()?;
        }
        Ok(true)
    }
    fn retired(&mut self) -> io::Result<bool> {
        let mut byte = [0];
        match self.retirement.read(&mut byte) {
            Ok(0) => Ok(true),
            Ok(_) => Err(io::Error::other(
                "invalid wrapper retirement record",
            )),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
}

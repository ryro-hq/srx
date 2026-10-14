use super::{Listener, PacketChannel, invalid, socket_integer};
use crate::platform::linux::fd::{self as linux_fd, FileIdentity};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd};

impl Listener {
    pub(crate) fn proxy_descriptors(&self) -> io::Result<[OwnedFd; 2]> {
        self.check_node(true)?;
        Ok([
            self.socket.try_clone()?,
            self.node.try_clone()?,
        ])
    }
    pub(crate) fn node_identity(&self) -> io::Result<FileIdentity> {
        self.check_node(true)?;
        Ok(linux_fd::metadata(self.node.as_fd())?.identity())
    }
}

pub(crate) struct ProxyListener {
    socket: OwnedFd,
    node: OwnedFd,
    identity: FileIdentity,
}
impl ProxyListener {
    /// Descriptors originate only in the private coordinator bootstrap. A public
    /// wrapper never supplies a listener or a socket mount node.
    pub(crate) fn from_inherited(
        socket: OwnedFd,
        node: OwnedFd,
        expected: FileIdentity,
    ) -> io::Result<Self> {
        if socket_integer(socket.as_fd(), libc::SO_TYPE)? != libc::SOCK_SEQPACKET
            || socket_integer(socket.as_fd(), libc::SO_DOMAIN)? != libc::AF_UNIX
            || socket_integer(socket.as_fd(), libc::SO_ACCEPTCONN)? != 1
        {
            return Err(invalid("invalid inherited command listener"));
        }
        let listener = Self {
            socket,
            node,
            identity: expected,
        };
        listener.revalidate()?;
        Ok(listener)
    }
    pub(crate) fn revalidate(&self) -> io::Result<()> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: live descriptor and writable exact ABI structure.
        if unsafe { libc::fstat(self.node.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstat initialized stat.
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_uid != linux_fd::effective_uid()
            || stat.st_nlink != 1
            || linux_fd::status_flags(self.node.as_fd())? & libc::O_PATH == 0
            || linux_fd::metadata(self.node.as_fd())?.identity() != self.identity
        {
            return Err(invalid("inherited command socket node changed"));
        }
        Ok(())
    }
    pub(crate) fn try_accept(&self) -> io::Result<Option<PacketChannel>> {
        self.revalidate()?;
        // SAFETY: owned listening Unix socket, no peer sockaddr requested.
        let raw = unsafe {
            libc::accept4(
                self.socket.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            )
        };
        if raw < 0 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        // SAFETY: successful accept4 transfers one fresh descriptor.
        let channel = PacketChannel::from_owned(unsafe { OwnedFd::from_raw_fd(raw) })?;
        channel.peer_credentials()?;
        Ok(Some(channel))
    }
}

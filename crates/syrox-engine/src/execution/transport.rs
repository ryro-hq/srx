use std::io;
use std::mem::{MaybeUninit, size_of, size_of_val};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use crate::cancellation::Cancellation;

pub(crate) const MAX_BYTES: usize = 4096;
pub(crate) const MAX_FDS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Peer {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}
impl Peer {
    #[cfg(test)]
    pub(crate) fn current() -> Self {
        // SAFETY: these credential queries take no memory arguments.
        unsafe {
            Self {
                pid: libc::getpid().cast_unsigned(),
                uid: libc::getuid(),
                gid: libc::getgid(),
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct Packet {
    pub bytes: Vec<u8>,
    pub descriptors: Vec<OwnedFd>,
}
#[derive(Debug)]
pub(crate) struct PacketChannel(OwnedFd);
impl AsFd for PacketChannel {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl PacketChannel {
    pub(crate) fn pair() -> io::Result<(Self, Self)> {
        let mut descriptors = [-1; 2];
        // SAFETY: two writable ints receive distinct fresh descriptors.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                descriptors.as_mut_ptr(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful socketpair transfers ownership of both fds.
        let (left, right) = unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        };
        Ok((Self::from_owned(left)?, Self::from_owned(right)?))
    }

    /// Require a connected/local Unix sequenced-packet socket and enable kernel
    /// credentials before any sender is authorized. Does not infer a peer identity.
    pub(crate) fn from_owned(fd: OwnedFd) -> io::Result<Self> {
        if socket_integer(fd.as_fd(), libc::SO_TYPE)? != libc::SOCK_SEQPACKET
            || socket_integer(fd.as_fd(), libc::SO_DOMAIN)? != libc::AF_UNIX
        {
            return Err(invalid(
                "launcher requires Unix sequenced-packet socket",
            ));
        }
        let mut address = MaybeUninit::<libc::sockaddr_un>::uninit();
        let mut address_size =
            libc::socklen_t::try_from(size_of::<libc::sockaddr_un>()).expect("sockaddr_un size");
        // SAFETY: sockaddr_un is sufficiently large for an AF_UNIX peer address.
        if unsafe {
            libc::getpeername(
                fd.as_raw_fd(),
                address.as_mut_ptr().cast(),
                &raw mut address_size,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // Ownership conversion normalizes descriptor flags; per-call DONTWAIT
        // avoids mutating the shared open-file-description's blocking mode.
        // SAFETY: fd is owned and both operations use fixed fcntl arguments.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        if flags < 0
            || unsafe {
                libc::fcntl(
                    fd.as_raw_fd(),
                    libc::F_SETFD,
                    flags | libc::FD_CLOEXEC,
                )
            } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let enabled: libc::c_int = 1;
        // SAFETY: enabled has the expected ABI size and fd is owned/live.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&raw const enabled).cast(),
                libc::socklen_t::try_from(size_of_val(&enabled)).expect("integer option size"),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(fd))
    }

    pub(crate) fn send(
        &self,
        bytes: &[u8],
        fds: &[BorrowedFd<'_>],
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES || fds.len() > MAX_FDS {
            return Err(invalid("launcher packet limit"));
        }
        loop {
            budget(deadline, cancellation)?;
            if self.try_send(bytes, fds)? {
                return Ok(());
            }
            wait(
                self.as_fd(),
                libc::POLLOUT,
                deadline,
                cancellation,
            )?;
        }
    }

    /// Attempt one atomic packet without waiting. False means no packet was
    /// transferred (`WouldBlock` or `EINTR`); the caller retains its queued data and
    /// descriptor ownership and must enforce its deadline across retries.
    pub(crate) fn try_send(&self, bytes: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<bool> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES || fds.len() > MAX_FDS {
            return Err(invalid("launcher packet limit"));
        }
        // usize alignment is sufficient for cmsghdr on supported Linux ABIs.
        let mut control = [0_usize; 1024 / size_of::<usize>()];
        let mut iov = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: zero msghdr is valid; all pointers below remain live through send.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        if !fds.is_empty() {
            let length =
                u32::try_from(fds.len() * size_of::<libc::c_int>()).expect("bounded fd count");
            message.msg_control = control.as_mut_ptr().cast();
            // SAFETY: aligned storage holds a cmsghdr and at most128 int handles.
            unsafe {
                message.msg_controllen = libc::CMSG_SPACE(length) as _;
                let header = libc::CMSG_FIRSTHDR(&raw const message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(length) as _;
                for (index, fd) in fds.iter().enumerate() {
                    libc::CMSG_DATA(header)
                        .add(index * size_of::<libc::c_int>())
                        .cast::<libc::c_int>()
                        .write_unaligned(fd.as_raw_fd());
                }
            }
        }
        // SAFETY: the message contains borrowed, initialized storage.
        let sent = unsafe {
            libc::sendmsg(
                self.0.as_raw_fd(),
                &raw const message,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if sent >= 0 {
            return if usize::try_from(sent).ok() == Some(bytes.len()) {
                Ok(true)
            } else {
                Err(invalid("partial launcher packet"))
            };
        }
        let error = io::Error::last_os_error();
        if matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) {
            Ok(false)
        } else {
            Err(error)
        }
    }

    pub(crate) fn receive(
        &self,
        peer: Peer,
        expected_fds: usize,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> io::Result<Packet> {
        if peer.pid == 0 || expected_fds > MAX_FDS {
            return Err(invalid(
                "invalid expected launcher peer or fd count",
            ));
        }
        self.receive_checked(peer, expected_fds, deadline, cancellation)
    }

    /// Used only by a proxy connected through its authenticated, read-only
    /// namespace socket mount. An ancestor has no PID in the receiving namespace.
    /// This does not weaken the positive-PID admission used by all launchers.
    pub(crate) fn receive_namespace_ancestor(
        &self,
        peer: Peer,
        expected_fds: usize,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> io::Result<Packet> {
        if peer.pid != 0
            || peer.uid != crate::platform::linux::fd::real_uid()
            || peer.gid != crate::platform::linux::fd::real_gid()
            || expected_fds > MAX_FDS
        {
            return Err(invalid("invalid namespace ancestor credentials"));
        }
        self.receive_checked(peer, expected_fds, deadline, cancellation)
    }

    /// One nonblocking receive for a cooperative single-threaded monitor.
    /// The caller owns its deadline/cancellation checks across polling turns.
    pub(crate) fn try_receive(
        &self,
        peer: Peer,
        expected_fds: usize,
    ) -> io::Result<Option<Packet>> {
        if peer.pid == 0 || expected_fds > MAX_FDS {
            return Err(invalid(
                "invalid expected launcher peer or fd count",
            ));
        }
        match self.receive_now(peer, expected_fds) {
            Ok(packet) => Ok(Some(packet)),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn receive_checked(
        &self,
        peer: Peer,
        expected_fds: usize,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> io::Result<Packet> {
        loop {
            budget(deadline, cancellation)?;
            match self.receive_now(peer, expected_fds) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait(self.as_fd(), libc::POLLIN, deadline, cancellation)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }

    fn receive_now(&self, peer: Peer, expected_fds: usize) -> io::Result<Packet> {
        let mut bytes = [0_u8; MAX_BYTES];
        let mut control = [0_usize; 1024 / size_of::<usize>()];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: zero msghdr is valid; initialized buffers stay live throughout.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen =
            u32::try_from(size_of_val(&control)).expect("bounded ancillary storage") as _;
        // SAFETY: message describes bounded writable storage. Received FDs get CLOEXEC atomically.
        let count = unsafe {
            libc::recvmsg(
                self.0.as_raw_fd(),
                &raw mut message,
                libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut descriptors = Vec::new();
        let mut credential = None;
        let mut malformed = false;
        // SAFETY: kernel controls the cmsg layout within aligned storage. Collect
        // every installed FD even after an invalid control or truncated message.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&raw const message);
            while !header.is_null() {
                let length =
                    ((*header).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                match ((*header).cmsg_level, (*header).cmsg_type) {
                    (libc::SOL_SOCKET, libc::SCM_RIGHTS) => {
                        malformed |= !length.is_multiple_of(size_of::<libc::c_int>());
                        for at in 0..length / size_of::<libc::c_int>() {
                            let fd = libc::CMSG_DATA(header)
                                .add(at * size_of::<libc::c_int>())
                                .cast::<libc::c_int>()
                                .read_unaligned();
                            descriptors.push(OwnedFd::from_raw_fd(fd));
                        }
                    }
                    (libc::SOL_SOCKET, libc::SCM_CREDENTIALS) => {
                        if length == size_of::<libc::ucred>() && credential.is_none() {
                            let raw = libc::CMSG_DATA(header)
                                .cast::<libc::ucred>()
                                .read_unaligned();
                            credential = Some(Peer {
                                pid: raw.pid.cast_unsigned(),
                                uid: raw.uid,
                                gid: raw.gid,
                            });
                        } else {
                            malformed = true;
                        }
                    }
                    _ => malformed = true,
                }
                header = libc::CMSG_NXTHDR(&raw const message, header);
            }
        }
        if count == 0
            && !malformed
            && credential.is_none()
            && descriptors.is_empty()
            && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "launcher peer closed the channel",
            ));
        }
        if count == 0
            || malformed
            || credential != Some(peer)
            || descriptors.len() != expected_fds
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        {
            return Err(invalid(
                "invalid launcher packet, credentials or descriptors",
            ));
        }
        let count = usize::try_from(count).map_err(|_| invalid("invalid packet size"))?;
        Ok(Packet {
            bytes: bytes[..count].to_vec(),
            descriptors,
        })
    }
}

pub(crate) fn socket_integer(fd: BorrowedFd<'_>, option: libc::c_int) -> io::Result<libc::c_int> {
    let mut value = MaybeUninit::<libc::c_int>::uninit();
    let mut size =
        libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("integer option size");
    // SAFETY: value has writable storage of the requested socket option size.
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            value.as_mut_ptr().cast(),
            &raw mut size,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != size_of::<libc::c_int>() {
        return Err(invalid("invalid socket option size"));
    }
    // SAFETY: successful getsockopt returned the full integer.
    Ok(unsafe { value.assume_init() })
}
pub(crate) fn budget(deadline: Instant, cancellation: &Cancellation) -> io::Result<()> {
    cancellation
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())?;
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "launcher IPC deadline",
        ));
    }
    Ok(())
}
pub(crate) fn wait(
    fd: BorrowedFd<'_>,
    event: libc::c_short,
    deadline: Instant,
    cancellation: &Cancellation,
) -> io::Result<()> {
    loop {
        budget(deadline, cancellation)?;
        let mut descriptors = [
            libc::pollfd {
                fd: fd.as_raw_fd(),
                events: event,
                revents: 0,
            },
            libc::pollfd {
                fd: cancellation
                    .wake_fd()
                    .map_or(-1, |fd| fd.as_raw_fd()),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(20));
        let millis = i32::try_from(timeout.as_millis().max(1)).expect("20ms bound");
        // SAFETY: both pollfd records are initialized; borrowed fds stay live.
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, millis) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        budget(deadline, cancellation)?;
        if result > 0 && descriptors[0].revents != 0 {
            return Ok(());
        }
    }
}
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
#[path = "tests/transport.rs"]
mod tests;

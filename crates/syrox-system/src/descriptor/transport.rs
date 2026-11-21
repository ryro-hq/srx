//! Descriptor transfer with fixed framing, bounded ancillary storage and
//! deterministic ownership on malformed/truncated messages. These operations
//! authenticate neither a peer nor the resource transferred by that peer.

use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

/// Credentials observed by the kernel at connection/socket-pair creation.
/// A zero PID can identify a peer outside the observer's PID namespace. These
/// values require an independent authorization policy; possession is not approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// Read kernel peer credentials without applying a caller-specific UID policy.
pub fn peer_credentials(socket: BorrowedFd<'_>) -> io::Result<PeerCredentials> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = libc::socklen_t::try_from(size_of::<libc::ucred>()).expect("ucred size");
    // SAFETY: writable ucred storage and its exact size are supplied. The live
    // borrowed descriptor selects the socket; no caller credentials are accepted.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &raw mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid peer credentials size",
        ));
    }
    // SAFETY: getsockopt initialized the exact ucred layout, checked above.
    let credentials = unsafe { credentials.assume_init() };
    Ok(PeerCredentials {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

/// Create a private close-on-exec Unix sequence-packet pair.
pub fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: fds is writable and socketpair initializes both slots on success.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socketpair returns two distinct newly owned FDs.
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(fds[0]),
            OwnedFd::from_raw_fd(fds[1]),
        )
    })
}

/// Transfer a reference while the caller retains ownership of its descriptor.
pub fn send_fd(socket: BorrowedFd<'_>, descriptor: BorrowedFd<'_>) -> io::Result<()> {
    let mut byte = b'n';
    let mut iov = libc::iovec {
        iov_base: (&raw mut byte).cast(),
        iov_len: 1,
    };
    // usize supplies cmsghdr alignment, including the padding after its payload.
    let mut control = [0_usize; 8];
    // SAFETY: zero is a valid empty msghdr; all buffers are live through sendmsg.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    // SAFETY: control has more than enough space for one cmsghdr and one int.
    unsafe {
        let fd_bytes = u32::try_from(size_of::<i32>()).expect("an fd fits u32 bytes");
        message.msg_controllen = libc::CMSG_SPACE(fd_bytes) as _;
        let header = libc::CMSG_FIRSTHDR(&raw const message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(fd_bytes) as _;
        libc::CMSG_DATA(header)
            .cast::<i32>()
            .write_unaligned(descriptor.as_raw_fd());
    }
    loop {
        // SAFETY: the initialized header references the live buffers above.
        let sent = unsafe {
            libc::sendmsg(
                socket.as_raw_fd(),
                &raw const message,
                libc::MSG_NOSIGNAL,
            )
        };
        if sent == 1 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if sent >= 0 {
            return Err(io::Error::other("incomplete descriptor message"));
        }
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Receive exactly one close-on-exec descriptor without blocking. Every
/// installed descriptor is closed if the message is malformed or truncated.
pub fn receive_fd(socket: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    let mut byte = 0_u8;
    let mut iov = libc::iovec {
        iov_base: (&raw mut byte).cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 8];
    // SAFETY: zero is a valid empty msghdr; pointers below reference live storage.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen =
        u32::try_from(size_of_val(&control)).expect("control buffer fits u32 bytes") as _;
    // SAFETY: recvmsg writes only inside the initialized buffers described above.
    let received = unsafe {
        libc::recvmsg(
            socket.as_raw_fd(),
            &raw mut message,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
        )
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut descriptors = Vec::new();
    // SAFETY: the kernel produced the cmsg layout within our aligned buffer.
    // Take ownership of ALL installed descriptors before rejecting any message;
    // MSG_CTRUNC can still deliver a subset which must be closed by us.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&raw const message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let length =
                    ((*header).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                for index in 0..length / size_of::<i32>() {
                    let raw = libc::CMSG_DATA(header)
                        .add(index * size_of::<i32>())
                        .cast::<i32>()
                        .read_unaligned();
                    descriptors.push(OwnedFd::from_raw_fd(raw));
                }
            }
            header = libc::CMSG_NXTHDR(&raw const message, header);
        }
    }
    if received != 1
        || byte != b'n'
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || descriptors.len() != 1
    {
        return Err(io::Error::other("invalid descriptor message"));
    }
    Ok(descriptors
        .pop()
        .expect("one received descriptor"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    #[test]
    fn descriptor_survives_sender_close_and_is_cloexec() {
        let (receiver, sender) = seqpacket_pair().unwrap();
        let file = tempfile::tempfile().unwrap();
        send_fd(sender.as_fd(), file.as_fd()).unwrap();
        drop((file, sender));
        let descriptor = std::fs::File::from(receive_fd(receiver.as_fd()).unwrap());
        assert_eq!(descriptor.metadata().unwrap().len(), 0);
        assert_ne!(
            // SAFETY: query the live descriptor returned by recvmsg.
            unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert!(receive_fd(receiver.as_fd()).is_err());
    }

    #[test]
    fn malformed_and_truncated_messages_close_every_installed_descriptor() {
        for (count, marker) in [(1_u32, b'!'), (2, b'n'), (32, b'n')] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("lock");
            std::fs::write(&path, b"").unwrap();
            let owner = std::fs::File::open(&path).unwrap();
            assert!(
                super::super::flock(
                    owner.as_fd(),
                    super::super::FlockMode::ExclusiveNonblocking
                )
                .unwrap()
            );
            let (receiver, sender) = seqpacket_pair().unwrap();
            let mut byte = marker;
            let mut iov = libc::iovec {
                iov_base: (&raw mut byte).cast(),
                iov_len: 1,
            };
            let mut storage = [0_usize; 32];
            // SAFETY: aligned storage fits 32 fd integers and its header. Send
            // duplicate references to one flock description to detect any leak.
            unsafe {
                let mut message: libc::msghdr = std::mem::zeroed();
                message.msg_iov = &raw mut iov;
                message.msg_iovlen = 1;
                message.msg_control = storage.as_mut_ptr().cast();
                message.msg_controllen = libc::CMSG_SPACE(count * 4) as _;
                let header = libc::CMSG_FIRSTHDR(&raw const message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(count * 4) as _;
                for at in 0..count as usize {
                    libc::CMSG_DATA(header)
                        .add(at * 4)
                        .cast::<i32>()
                        .write_unaligned(owner.as_raw_fd());
                }
                assert_eq!(
                    libc::sendmsg(
                        sender.as_raw_fd(),
                        &raw const message,
                        libc::MSG_NOSIGNAL
                    ),
                    1
                );
            }
            drop((owner, sender));
            assert!(receive_fd(receiver.as_fd()).is_err());
            let probe = std::fs::File::open(path).unwrap();
            assert!(
                super::super::flock(
                    probe.as_fd(),
                    super::super::FlockMode::ExclusiveNonblocking
                )
                .unwrap(),
                "received descriptor leaked for {count} rights"
            );
        }
    }

    #[test]
    fn kernel_peer_credentials_are_observed_and_regular_files_are_refused() {
        use std::os::fd::AsFd as _;
        let (first, second) = seqpacket_pair().unwrap();
        for socket in [&first, &second] {
            let peer = peer_credentials(socket.as_fd()).unwrap();
            assert_eq!(
                u32::try_from(peer.pid).unwrap(),
                std::process::id()
            );
            // SAFETY: these queries have no arguments or side effects.
            assert_eq!((peer.uid, peer.gid), unsafe {
                (libc::geteuid(), libc::getegid())
            });
        }
        assert!(peer_credentials(tempfile::tempfile().unwrap().as_fd()).is_err());
    }
}

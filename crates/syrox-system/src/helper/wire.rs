use super::policy::{Policy, refused};
use serde::Serialize;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::fs::FileExt as _;
use std::time::Instant;
use syrox_system::descriptor::{self, PeerCredentials, sealed};
pub(super) use syrox_system::helper_protocol::Request;

pub(super) fn authenticate(socket: &File, policy: &Policy) -> io::Result<PeerCredentials> {
    for (option, expected) in [
        (libc::SO_DOMAIN, libc::AF_UNIX),
        (libc::SO_TYPE, libc::SOCK_SEQPACKET),
        (libc::SO_ACCEPTCONN, 0),
    ] {
        let mut value = 0_i32;
        let mut bytes = u32::try_from(size_of::<i32>()).unwrap();
        // SAFETY: exact writable integer option output on the owned socket.
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw mut value).cast(),
                &raw mut bytes,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if bytes as usize != size_of::<i32>() || value != expected {
            return Err(refused(
                "helper requires a connected Unix seqpacket description",
            ));
        }
    }
    let peer = descriptor::peer_credentials(socket.as_fd())?;
    if peer.pid <= 0 || peer.uid != policy.client_uid || peer.gid != policy.client_gid {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let flags = descriptor::status_flags(socket.as_fd())?;
    // SAFETY: own the accepted connection; mode changes affect no other session.
    if unsafe {
        libc::fcntl(
            socket.as_raw_fd(),
            libc::F_SETFL,
            flags | libc::O_NONBLOCK,
        )
    } < 0
        || unsafe {
            libc::fcntl(
                socket.as_raw_fd(),
                libc::F_SETFD,
                libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(peer)
}

pub(super) fn receive(
    socket: &File,
    peer: PeerCredentials,
    deadline: Instant,
) -> io::Result<Request> {
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match descriptor::receive_fd(socket.as_fd()) {
            Ok(fd) => {
                let file = File::from(fd);
                sealed::validate_secret_owned(file.as_fd(), peer.uid)?;
                let mut bytes = vec![
                    0;
                    usize::try_from(file.metadata()?.len())
                        .map_err(|_| refused("request length overflow"))?
                ];
                file.read_exact_at(&mut bytes, 0)?;
                return serde_json::from_slice(&bytes).map_err(io::Error::from);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let mut poll = libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one live pollfd with a bounded 20 ms wait.
                if unsafe { libc::poll(&raw mut poll, 1, 20) } < 0
                    && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn reply(socket: &File, journal_record: File) -> io::Result<()> {
    let response = sealed::snapshot_secret(journal_record, 65_536, || Ok(()))?;
    descriptor::send_fd(socket.as_fd(), response.as_fd())
}

pub(super) fn reply_value(socket: &File, value: &impl Serialize) -> io::Result<()> {
    use std::io::{Seek as _, Write as _};
    use std::os::fd::FromRawFd as _;
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 65_536 {
        return Err(refused("helper response exceeds 64 KiB"));
    }
    // SAFETY: fixed anonymous staging file, never a client-selected path.
    let raw = unsafe {
        libc::memfd_create(
            c"syrox-helper-response".as_ptr(),
            libc::MFD_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut source = unsafe { File::from_raw_fd(raw) };
    source.write_all(&bytes)?;
    source.rewind()?;
    reply(socket, source)
}

use super::{invalid, refused};
use crate::{
    descriptor::{self, sealed},
    helper_protocol::Request,
};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Component, Path};
use std::time::Instant;

#[derive(Debug)]
pub(super) struct Connection {
    socket: File,
    user_namespace: File,
}

impl Connection {
    pub fn connect(
        path: &Path,
        check: &mut impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<Self> {
        check_deadline(check, deadline)?;
        require_identity_namespace()?;
        let user_namespace = File::open("/proc/self/ns/user")?;
        let before = endpoint(path)?;
        let bytes = path.as_os_str().as_encoded_bytes();
        // SAFETY: fixed local socket with nonblocking/CLOEXEC semantics.
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = unsafe { File::from_raw_fd(raw) };
        // SAFETY: initialized sockaddr_un with a bounded terminated pathname.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = u16::try_from(libc::AF_UNIX).unwrap();
        for (out, byte) in address.sun_path.iter_mut().zip(bytes) {
            *out = libc::c_char::try_from(*byte).unwrap();
        }
        let length =
            u32::try_from(std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1)
                .unwrap();
        if unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&raw const address).cast(),
                length,
            )
        } < 0
        {
            // Backlog/capacity failures are returned before sending a request;
            // there is no implicit reconnect or operation retry.
            return Err(io::Error::last_os_error());
        }
        let after = endpoint(path)?;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(refused(
                "helper endpoint changed while connecting",
            ));
        }
        authenticate(&socket)?;
        check_deadline(check, deadline)?;
        Ok(Self {
            socket,
            user_namespace,
        })
    }

    fn check(
        &self,
        check: &mut impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<()> {
        check_deadline(check, deadline)?;
        let pinned = self.user_namespace.metadata()?;
        let current = std::fs::metadata("/proc/self/ns/user")?;
        if (pinned.dev(), pinned.ino()) != (current.dev(), current.ino()) {
            return Err(refused(
                "helper control must remain outside the worker user namespace",
            ));
        }
        authenticate(&self.socket)
    }

    pub fn send(
        &self,
        request: &Request,
        check: &mut impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<()> {
        self.check(check, deadline)?;
        let bytes = serde_json::to_vec(request)?;
        let message = sealed::snapshot_bytes(&bytes, &mut *check)?;
        loop {
            self.check(check, deadline)?;
            match descriptor::send_fd(self.socket.as_fd(), message.as_fd()) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLOUT, check, deadline)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                other => return other,
            }
        }
    }

    pub fn receive(
        &self,
        check: &mut impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<OwnedFd> {
        loop {
            self.check(check, deadline)?;
            match descriptor::receive_fd(self.socket.as_fd()) {
                Ok(fd) => return Ok(fd),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLIN, check, deadline)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }

    pub fn response(
        &self,
        check: &mut impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<serde_json::Value> {
        let file = File::from(self.receive(check, deadline)?);
        sealed::validate_secret_owned(file.as_fd(), 0)?;
        let mut bytes = vec![
            0;
            usize::try_from(file.metadata()?.len())
                .map_err(|_| invalid("helper response size overflow"))?
        ];
        file.read_exact_at(&mut bytes, 0)?;
        self.check(check, deadline)?;
        serde_json::from_slice(&bytes).map_err(io::Error::from)
    }

    fn wait(
        &self,
        events: i16,
        check: &mut impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<()> {
        self.check(check, deadline)?;
        let mut poll = libc::pollfd {
            fd: self.socket.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: one initialized live pollfd; cancellation is checked per wait.
        if unsafe { libc::poll(&raw mut poll, 1, 20) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn check_deadline(check: &mut impl FnMut() -> io::Result<()>, deadline: Instant) -> io::Result<()> {
    check()?;
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(())
}

fn require_identity_namespace() -> io::Result<()> {
    // Root-owned peer/message identities must be observed in the coordinator's
    // full identity mapping, never interpreted through a worker's uid mapping.
    for path in [
        "/proc/self/uid_map",
        "/proc/self/gid_map",
    ] {
        use std::io::Read as _;
        let mut value = String::new();
        File::open(path)?
            .take(4097)
            .read_to_string(&mut value)?;
        if value.len() > 4096
            || value.split_whitespace().collect::<Vec<_>>() != ["0", "0", "4294967295"]
        {
            return Err(refused(
                "helper client requires the coordinator's full identity namespace",
            ));
        }
    }
    // SAFETY: credential observations only; the client never elevates itself.
    let credentials = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    if credentials.0 == 0 || credentials.0 != credentials.1 || credentials.2 != credentials.3 {
        return Err(refused(
            "helper client requires matching non-root coordinator credentials",
        ));
    }
    Ok(())
}

fn endpoint(path: &Path) -> io::Result<std::fs::Metadata> {
    let text = path
        .to_str()
        .ok_or_else(|| refused("helper socket requires a literal pathname"))?;
    if !path.is_absolute()
        || text.len() > 107
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        || text[1..]
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(refused(
            "helper socket requires a bounded canonical Unix pathname",
        ));
    }
    let mut parent = descriptor::open_resolved(
        None,
        Path::new("/"),
        true,
        libc::RESOLVE_NO_SYMLINKS,
    )?;
    let components = path.components().collect::<Vec<_>>();
    for component in &components[1..components.len() - 1] {
        let Component::Normal(name) = component else {
            return Err(refused("invalid helper endpoint ancestor"));
        };
        parent = descriptor::open_resolved(
            Some(parent.as_fd()),
            Path::new(name),
            true,
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
        )?;
        let m = parent.metadata()?;
        if m.uid() != 0 || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0) {
            return Err(refused(
                "helper endpoint ancestors are not protected by root ownership",
            ));
        }
    }
    let file = descriptor::open_path(path)?;
    let m = file.metadata()?;
    if !m.file_type().is_socket() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o7777 != 0o660 {
        return Err(refused(
            "helper endpoint requires a protected root-owned mode-0660 socket",
        ));
    }
    Ok(m)
}

pub(super) fn authenticate(socket: &File) -> io::Result<()> {
    let mut kind = 0_i32;
    let mut bytes = u32::try_from(size_of::<i32>()).unwrap();
    // SAFETY: fixed integer output query on an owned connection.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut kind).cast(),
            &raw mut bytes,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let peer = descriptor::peer_credentials(socket.as_fd())?;
    if kind != libc::SOCK_SEQPACKET
        || bytes as usize != size_of::<i32>()
        || peer.pid <= 0
        || peer.uid != 0
        || peer.gid != 0
    {
        return Err(refused(
            "helper connection does not authenticate a root seqpacket peer",
        ));
    }
    Ok(())
}

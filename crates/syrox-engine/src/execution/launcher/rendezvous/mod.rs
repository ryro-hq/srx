pub(crate) mod proxy;
use super::transport::{PacketChannel, Peer, budget, socket_integer, wait};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd};
use std::ffi::CString;
use std::io;
use std::mem::{MaybeUninit, size_of, size_of_val};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug)]
pub(crate) struct Listener {
    socket: OwnedFd,
    directory: linux_fd::OpenedPath,
    node: OwnedFd,
    name: CString,
    path: PathBuf,
    removed: bool,
    preserve_node_on_drop: bool,
}
impl Listener {
    pub(crate) fn bind(private_directory: &Path, basename: &str) -> io::Result<Self> {
        valid_name(basename)?;
        let path = std::path::absolute(private_directory)?.join(basename);
        address(&path)?; // The advertised path must also fit sockaddr_un.
        let directory = private_parent(path.parent().expect("joined basename"))?;
        let name = CString::new(basename).map_err(io::Error::other)?;
        let socket = new_socket()?;
        let (address, length) = address(&anchored(directory.fd(), basename))?;
        // SAFETY: initialized address has exactly the length supplied to bind.
        if unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&raw const address).cast(),
                length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // If opening the new node fails, leave the unknown entry for conservative
        // recovery instead of unlinking a name whose ownership is unproven.
        let node = socket_node(directory.fd(), &name, false).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "bound rendezvous {} requires inspection; node ownership unavailable: {error}",
                    path.display()
                ),
            )
        })?;
        let mut listener = Self {
            socket,
            directory,
            node,
            name,
            path,
            removed: false,
            preserve_node_on_drop: false,
        };
        if let Err(error) = listener.start_listening() {
            return match listener.close() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(io::Error::new(
                    error.kind(),
                    format!(
                        "rendezvous setup failed: {error}; cleanup pending at {}: {cleanup}",
                        listener.path.display()
                    ),
                )),
            };
        }
        Ok(listener)
    }
    fn start_listening(&self) -> io::Result<()> {
        let descriptor_path = CString::new(format!("/proc/self/fd/{}", self.node.as_raw_fd()))
            .expect("numeric descriptor path");
        // SAFETY: procfs follows our retained O_PATH handle to this socket inode;
        // no mutable pathname component is traversed after its acquisition.
        if unsafe { libc::chmod(descriptor_path.as_ptr(), 0o600) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.check_node(true)?;
        // SO_PASSCRED was enabled before bind/listen so early queued messages
        // carry credentials even when the sender runs before accept.
        // SAFETY: socket is a live bound Unix socket; backlog is bounded.
        if unsafe { libc::listen(self.socket.as_raw_fd(), 16) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn try_accept(&self) -> io::Result<Option<PacketChannel>> {
        self.check_node(true)?;
        // SAFETY: no address requested; accept4 returns a fresh owned descriptor.
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
            return match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(None),
                _ => Err(error),
            };
        }
        // SAFETY: accept4 returned a fresh descriptor owned by this function.
        let channel = PacketChannel::from_owned(unsafe { OwnedFd::from_raw_fd(raw) })?;
        channel.peer_credentials()?;
        Ok(Some(channel))
    }
    pub(crate) fn accept(
        &self,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> io::Result<PacketChannel> {
        loop {
            budget(deadline, cancellation)?;
            if let Some(channel) = self.try_accept()? {
                budget(deadline, cancellation)?;
                return Ok(channel);
            }
            wait(
                self.socket.as_fd(),
                libc::POLLIN,
                deadline,
                cancellation,
            )?;
        }
    }
    /// Once a runtime may own this node, automatic unlink is no longer valid.
    /// Descriptors still close normally; explicit close requires caller proof.
    pub(crate) fn preserve_on_drop(&mut self) {
        self.preserve_node_on_drop = true;
    }

    /// Cleanup failure leaves the entry for inspection, never deletes a replacement.
    pub(crate) fn close(&mut self) -> io::Result<()> {
        if self.removed {
            return linux_fd::sync_directory(self.directory.fd());
        }
        self.check_node(false)?;
        // SAFETY: single-component name was checked against the retained inode.
        // The private parent must not be concurrently mutated by its owner.
        if unsafe {
            libc::unlinkat(
                self.directory.fd().as_raw_fd(),
                self.name.as_ptr(),
                0,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        self.removed = true;
        linux_fd::sync_directory(self.directory.fd())
    }
    fn check_node(&self, require_mode: bool) -> io::Result<()> {
        let current = socket_node(self.directory.fd(), &self.name, require_mode)?;
        if linux_fd::metadata(current.as_fd())?.identity()
            != linux_fd::metadata(self.node.as_fd())?.identity()
        {
            return Err(invalid("rendezvous socket inode replaced"));
        }
        let directory = private_parent(self.path.parent().expect("absolute socket path"))?;
        if directory.metadata().identity() != self.directory.metadata().identity() {
            return Err(invalid("rendezvous parent replaced"));
        }
        Ok(())
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        if !self.preserve_node_on_drop {
            let _ = self.close();
        }
    }
}

impl PacketChannel {
    pub(crate) fn connect(
        path: &Path,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> io::Result<Self> {
        Self::connect_profile(path, None, deadline, cancellation)
    }
    pub(crate) fn connect_command_proxy(
        expected_socket: linux_fd::FileIdentity,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> io::Result<Self> {
        Self::connect_profile(
            Path::new("/syrox/commands/broker.sock"),
            Some(expected_socket),
            deadline,
            cancellation,
        )
    }
    fn connect_profile(
        path: &Path,
        expected_socket: Option<linux_fd::FileIdentity>,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> io::Result<Self> {
        let namespace_ancestor = expected_socket.is_some();
        budget(deadline, cancellation)?;
        let path = std::path::absolute(path)?;
        address(&path)?;
        let basename = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("invalid rendezvous name"))?;
        valid_name(basename)?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("missing rendezvous parent"))?;
        let directory = if namespace_ancestor {
            let directory = linux_fd::open_top_directory(parent)
                .map_err(|_| invalid("invalid command endpoint parent"))?;
            if !directory.metadata().is_trusted_directory()
                || directory.metadata().mode() & 0o7777 != 0o500
            {
                return Err(invalid(
                    "command endpoint parent must be owned and mode0500",
                ));
            }
            require_readonly_mount(directory.fd())?;
            directory
        } else {
            private_parent(parent)?
        };
        let name = CString::new(basename).map_err(io::Error::other)?;
        let node = socket_node(directory.fd(), &name, true)?;
        if expected_socket.is_some_and(|identity| {
            linux_fd::metadata(node.as_fd())
                .map_or(true, |metadata| metadata.identity() != identity)
        }) {
            return Err(invalid(
                "command endpoint differs from admitted context",
            ));
        }
        let socket = new_socket()?;
        let (address, length) = address(&anchored(directory.fd(), basename))?;
        loop {
            budget(deadline, cancellation)?;
            // SAFETY: sockaddr is initialized and socket is live, nonblocking.
            if unsafe {
                libc::connect(
                    socket.as_raw_fd(),
                    (&raw const address).cast(),
                    length,
                )
            } == 0
            {
                break;
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::EAGAIN) => {
                    // AF_UNIX backlog saturation does not initiate a connection.
                    // Poll may report immediately; bounded pause avoids spinning.
                    std::thread::sleep(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(std::time::Duration::from_millis(5)),
                    );
                }
                Some(libc::EINPROGRESS | libc::EALREADY) => {
                    wait(
                        socket.as_fd(),
                        libc::POLLOUT,
                        deadline,
                        cancellation,
                    )?;
                    let error = socket_integer(socket.as_fd(), libc::SO_ERROR)?;
                    if error != 0 {
                        return Err(io::Error::from_raw_os_error(error));
                    }
                    break;
                }
                Some(libc::EISCONN) => break,
                _ => return Err(error),
            }
        }
        let current = socket_node(directory.fd(), &name, true)?;
        if linux_fd::metadata(current.as_fd())?.identity()
            != linux_fd::metadata(node.as_fd())?.identity()
        {
            return Err(invalid("rendezvous changed while connecting"));
        }
        let channel = Self::from_owned(socket)?;
        channel.peer_credentials_profile(namespace_ancestor)?;
        budget(deadline, cancellation)?;
        Ok(channel)
    }
    /// Connection identity is checked again per message by `PacketChannel::receive`.
    pub(crate) fn peer_credentials(&self) -> io::Result<Peer> {
        self.peer_credentials_profile(false)
    }
    pub(crate) fn namespace_ancestor_credentials(&self) -> io::Result<Peer> {
        self.peer_credentials_profile(true)
    }
    fn peer_credentials_profile(&self, namespace_ancestor: bool) -> io::Result<Peer> {
        let mut credentials = MaybeUninit::<libc::ucred>::uninit();
        let mut length = libc::socklen_t::try_from(size_of::<libc::ucred>()).expect("ucred size");
        // SAFETY: writable ucred storage and its exact size are supplied.
        if unsafe {
            libc::getsockopt(
                self.as_fd().as_raw_fd(),
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
            return Err(invalid("invalid peer credentials size"));
        }
        // SAFETY: getsockopt initialized all fields after exact length check.
        let credentials = unsafe { credentials.assume_init() };
        // SAFETY: geteuid takes no arguments.
        let valid_pid = if namespace_ancestor {
            credentials.pid == 0
        } else {
            credentials.pid > 0
        };
        if !valid_pid
            || credentials.uid != unsafe { libc::geteuid() }
            || (namespace_ancestor && credentials.gid != linux_fd::real_gid())
        {
            return Err(invalid(
                "launcher peer must have a positive PID and the same effective user",
            ));
        }
        Ok(Peer {
            pid: credentials.pid.cast_unsigned(),
            uid: credentials.uid,
            gid: credentials.gid,
        })
    }
}
fn new_socket() -> io::Result<OwnedFd> {
    // SAFETY: fixed valid socket domain/type; success gives fresh ownership.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a fresh owned fd.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let enabled: libc::c_int = 1;
    // SAFETY: integer option points to initialized storage.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&raw const enabled).cast(),
            libc::socklen_t::try_from(size_of_val(&enabled)).expect("integer size"),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}
fn private_parent(path: &Path) -> io::Result<linux_fd::OpenedPath> {
    let directory = linux_fd::open_top_directory(path).map_err(|error| match error {
        linux_fd::OpenError::Other(error) | linux_fd::OpenError::Unsupported(error) => error,
        linux_fd::OpenError::Symlink => invalid("rendezvous parent traverses symlink"),
    })?;
    if !directory.metadata().is_trusted_directory() || directory.metadata().mode() & 0o7777 != 0o700
    {
        return Err(invalid(
            "rendezvous parent must be owned and mode0700",
        ));
    }
    Ok(directory)
}
fn socket_node(parent: BorrowedFd<'_>, name: &CString, require_mode: bool) -> io::Result<OwnedFd> {
    // SAFETY: parent is live and name is a validated single component.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat yields fresh ownership.
    let node = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat writable and fd live.
    if unsafe { libc::fstat(node.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat initialized structure.
    let stat = unsafe { stat.assume_init() };
    // SAFETY: geteuid takes no arguments.
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_nlink != 1
        || (require_mode && stat.st_mode & 0o7777 != 0o600)
    {
        return Err(invalid("untrusted rendezvous socket node"));
    }
    Ok(node)
}
fn valid_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        || matches!(name, "." | "..")
    {
        Err(invalid("invalid rendezvous basename"))
    } else {
        Ok(())
    }
}
fn anchored(directory: BorrowedFd<'_>, name: &str) -> PathBuf {
    PathBuf::from(format!(
        "/proc/self/fd/{}/{name}",
        directory.as_raw_fd()
    ))
}
fn address(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: zeroed sockaddr_un valid and AF_UNIX below initializes family.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
        return Err(invalid(
            "rendezvous path exceeds Unix socket limit",
        ));
    }
    address.sun_family = libc::AF_UNIX
        .try_into()
        .expect("AF_UNIX fits family");
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = (*byte).cast_signed();
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    Ok((
        address,
        libc::socklen_t::try_from(length).expect("sockaddr size"),
    ))
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests;

fn require_readonly_mount(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut stat = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: live descriptor and writable exact ABI storage.
    if unsafe { libc::fstatvfs(fd.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatvfs initialized the structure on success.
    let stat = unsafe { stat.assume_init() };
    if stat.f_flag & libc::ST_RDONLY == 0 {
        return Err(invalid(
            "command endpoint mount must be read-only",
        ));
    }
    Ok(())
}

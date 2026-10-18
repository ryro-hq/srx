use super::contract;
use super::properties::Property;
use super::wire::{self, Frame, Writer};
use super::{Budget, MANAGER_INTERFACE, MANAGER_PATH, MAX_JOBS, SystemdError, job_id};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[derive(Debug)]
pub(super) struct Message {
    destination: String,
    path: String,
    interface: String,
    member: String,
    signature: String,
    body: Writer,
}
impl Message {
    pub fn string(&mut self, v: &str) -> Result<(), SystemdError> {
        self.signature.push('s');
        self.body.string(v)
    }
    pub fn u32(&mut self, v: u32) {
        self.signature.push('u');
        self.body.u32(v);
    }
    pub fn properties(&mut self, p: &[Property]) -> Result<(), SystemdError> {
        self.signature.push_str("a(sv)");
        self.body.properties(p)
    }
    pub fn empty_array(&mut self, s: &str) -> Result<(), SystemdError> {
        self.signature.push('a');
        self.signature.push_str(s);
        self.body.empty_array(s)
    }
}
#[derive(Debug)]
pub(super) struct Reply(pub(super) Frame);
impl Reply {
    pub fn expect_empty(&self) -> Result<(), SystemdError> {
        if self.0.signature.is_empty() && self.0.body.is_empty() {
            Ok(())
        } else {
            Err(SystemdError::Protocol("expected empty reply"))
        }
    }
    fn text(&self, sig: &str) -> Result<String, SystemdError> {
        self.signature(sig)?;
        let mut r = self.0.reader();
        let s = r.string()?.to_owned();
        r.end()?;
        Ok(s)
    }
    pub fn single_object(&mut self) -> Result<String, SystemdError> {
        self.text("o")
    }
    pub fn single_string(&self) -> Result<String, SystemdError> {
        self.text("s")
    }
    fn signature(&self, sig: &str) -> Result<(), SystemdError> {
        if self.0.signature == sig {
            Ok(())
        } else {
            Err(SystemdError::Protocol(
                "unexpected reply signature",
            ))
        }
    }
}
#[derive(Debug)]
pub(super) struct JobEvent {
    pub unit: String,
    pub result: String,
}
#[derive(Debug)]
pub(super) struct Bus {
    socket: OwnedFd,
    guid: String,
    owner: Option<String>,
    serial: u32,
    healthy: bool,
    configuration_revision: u64,
    configuration_path: Option<String>,
    configuration_subscribed: bool,
    watched: BTreeMap<String, usize>,
    pending: BTreeMap<String, String>,
    jobs: BTreeMap<String, JobEvent>,
    received: Vec<u8>,
}
fn io_status(value: libc::c_int) -> Result<libc::c_int, SystemdError> {
    if value < 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(value)
    }
}
fn disconnected() -> SystemdError {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        "D-Bus connection needs reconnect",
    )
    .into()
}
fn would_wait(error: &SystemdError) -> bool {
    matches!(error,SystemdError::Io(e) if matches!(e.kind(),std::io::ErrorKind::WouldBlock|std::io::ErrorKind::Interrupted))
}
fn socket_path(address: &str) -> Result<Vec<u8>, SystemdError> {
    let value = address
        .strip_prefix("unix:path=")
        .ok_or(SystemdError::Invalid("local socket required"))?;
    let mut path = Vec::new();
    let mut bytes = value.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let a = bytes
                .next()
                .and_then(|b| char::from(b).to_digit(16))
                .ok_or(SystemdError::Invalid("invalid bus address"))?;
            let b = bytes
                .next()
                .and_then(|b| char::from(b).to_digit(16))
                .ok_or(SystemdError::Invalid("invalid bus address"))?;
            path.push(u8::try_from(a * 16 + b).expect("hex byte"));
        } else {
            path.push(byte);
        }
    }
    if path.first() != Some(&b'/') || path.contains(&0) || path.len() >= 108 {
        return Err(SystemdError::Invalid("invalid Unix socket path"));
    }
    Ok(path)
}
fn wait(socket: &OwnedFd, events: libc::c_short, budget: &Budget<'_>) -> Result<(), SystemdError> {
    budget.check()?;
    let ms =
        i32::try_from(budget.remaining_us()?.div_ceil(1000).min(20)).expect("bounded milliseconds");
    let mut poll = libc::pollfd {
        fd: socket.as_raw_fd(),
        events,
        revents: 0,
    };
    let result = unsafe { libc::poll(&raw mut poll, 1, ms) };
    if result < 0 {
        let error = SystemdError::Io(std::io::Error::last_os_error());
        if !would_wait(&error) {
            return Err(error);
        }
    }
    budget.check()
}
fn connect_socket(path: &[u8], budget: &Budget<'_>) -> Result<OwnedFd, SystemdError> {
    budget.check()?;
    let raw = io_status(unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    })?;
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::sa_family_t::try_from(libc::AF_UNIX).expect("AF_UNIX fits");
    for (out, byte) in address.sun_path.iter_mut().zip(path) {
        *out = libc::c_char::from_ne_bytes([*byte]);
    }
    let result = unsafe {
        libc::connect(
            raw,
            (&raw const address).cast(),
            libc::socklen_t::try_from(size_of::<libc::sa_family_t>() + path.len() + 1)
                .expect("sockaddr size"),
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        // EAGAIN on Unix sockets is a refused/full listen queue, not an in-progress connect.
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error.into());
        }
        wait(&socket, libc::POLLOUT, budget)?;
        let mut code: libc::c_int = 0;
        let mut length = libc::socklen_t::try_from(size_of_val(&code)).expect("int size");
        io_status(unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut code).cast(),
                &raw mut length,
            )
        })?;
        if code != 0 {
            return Err(std::io::Error::from_raw_os_error(code).into());
        }
    }
    Ok(socket)
}
fn send(socket: &OwnedFd, bytes: &[u8], budget: &Budget<'_>) -> Result<(), SystemdError> {
    let mut offset = 0;
    while offset < bytes.len() {
        budget.check()?;
        let n = unsafe {
            libc::send(
                socket.as_raw_fd(),
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
                libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            let e = SystemdError::Io(std::io::Error::last_os_error());
            if would_wait(&e) {
                wait(socket, libc::POLLOUT, budget)?;
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(disconnected());
        }
        offset += usize::try_from(n).expect("nonnegative write");
    }
    Ok(())
}
fn recv(socket: &OwnedFd, bytes: &mut [u8]) -> Result<usize, SystemdError> {
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    // Zero control capacity: Linux closes discarded SCM_RIGHTS descriptors; CTRUNC
    // reports forbidden ancillary data. No descriptors can enter our ownership.
    let n = unsafe {
        libc::recvmsg(
            socket.as_raw_fd(),
            &raw mut message,
            libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        return Err(SystemdError::Protocol(
            "unexpected ancillary data",
        ));
    }
    if n == 0 {
        return Err(disconnected());
    }
    Ok(usize::try_from(n).expect("nonnegative read"))
}
impl Bus {
    pub fn connect(address: &str, budget: &Budget<'_>) -> Result<Self, SystemdError> {
        let socket = connect_socket(&socket_path(address)?, budget)?;
        let uid = unsafe { libc::geteuid() }.to_string();
        let mut auth = String::from("\0AUTH EXTERNAL ");
        for byte in uid.bytes() {
            write!(auth, "{byte:02x}").expect("String write");
        }
        auth.push_str("\r\n");
        send(&socket, auth.as_bytes(), budget)?;
        let mut line = Vec::new();
        loop {
            budget.check()?;
            let mut byte = [0];
            match recv(&socket, &mut byte) {
                Ok(_) => line.push(byte[0]),
                Err(e) if would_wait(&e) => {
                    wait(&socket, libc::POLLIN, budget)?;
                    continue;
                }
                Err(e) => return Err(e),
            }
            if line.len() > 128 {
                return Err(SystemdError::Protocol(
                    "authentication response too large",
                ));
            }
            if line.ends_with(b"\r\n") {
                break;
            }
        }
        let guid = line
            .strip_prefix(b"OK ")
            .and_then(|l| l.strip_suffix(b"\r\n"))
            .ok_or(SystemdError::Protocol(
                "EXTERNAL authentication refused",
            ))?;
        if guid.len() != 32 || !guid.iter().all(u8::is_ascii_hexdigit) {
            return Err(SystemdError::Protocol("invalid bus GUID"));
        }
        // Deliberately omit NEGOTIATE_UNIX_FD.
        send(&socket, b"BEGIN\r\n", budget)?;
        let mut bus = Self {
            socket,
            guid: guid
                .iter()
                .map(|byte| char::from(byte.to_ascii_lowercase()))
                .collect(),
            owner: None,
            serial: 0,
            healthy: true,
            configuration_revision: 0,
            configuration_path: None,
            configuration_subscribed: false,
            watched: BTreeMap::new(),
            pending: BTreeMap::new(),
            jobs: BTreeMap::new(),
            received: Vec::new(),
        };
        let hello = bus.method(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "Hello",
        )?;
        let name = bus.call(hello, budget)?.single_string()?;
        if !unique_name(&name) {
            return Err(SystemdError::Protocol("invalid unique bus name"));
        }
        Ok(bus)
    }
    pub fn set_owner(&mut self, owner: String) -> Result<(), SystemdError> {
        if !unique_name(&owner) {
            return Err(SystemdError::Protocol("invalid manager owner"));
        }
        self.owner = Some(owner);
        Ok(())
    }
    pub fn guid(&self) -> &str {
        &self.guid
    }
    pub fn invalidate(&mut self) {
        self.healthy = false;
    }
    pub fn verify_manager_owner(&mut self, owner: &str) -> Result<(), SystemdError> {
        if !self.healthy {
            return Err(disconnected());
        }
        if self.owner.as_deref() != Some(owner) || !unique_name(owner) {
            self.healthy = false;
            return Err(SystemdError::Protocol(
                "manager ownership changed; reconnect required",
            ));
        }
        Ok(())
    }
    pub fn method(
        &self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
    ) -> Result<Message, SystemdError> {
        if !self.healthy {
            return Err(disconnected());
        }
        for value in [destination, path, interface, member] {
            super::text(value)?;
        }
        contract::method(interface, member)?;
        Ok(Message {
            destination: destination.into(),
            path: path.into(),
            interface: interface.into(),
            member: member.into(),
            signature: String::new(),
            body: Writer::default(),
        })
    }
    pub fn manager_method(&self, member: &str) -> Result<Message, SystemdError> {
        self.method(
            self.owner
                .as_deref()
                .ok_or(SystemdError::Protocol("manager owner missing"))?,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            member,
        )
    }
    pub fn manager_unit_job(
        &self,
        member: &str,
        unit: &str,
        mode: &str,
    ) -> Result<Message, SystemdError> {
        let mut message = self.manager_method(member)?;
        message.string(unit)?;
        message.string(mode)?;
        Ok(message)
    }
    // Consuming requests prevents accidental mutation replay by the caller.
    #[allow(clippy::needless_pass_by_value)] // Consuming requests prevents accidental mutation replay by the caller.
    pub fn call(&mut self, message: Message, budget: &Budget<'_>) -> Result<Reply, SystemdError> {
        if !self.healthy {
            return Err(disconnected());
        }
        budget.check()?;
        let specification = contract::method(&message.interface, &message.member)?;
        if specification.is_some_and(|specification| specification.input != message.signature) {
            return Err(SystemdError::Protocol(
                "request differs from host interface signature",
            ));
        }
        let result = self
            .call_inner(&message, budget)
            .and_then(|reply| {
                if let Some(specification) = specification {
                    reply.signature(specification.output)?;
                }
                Ok(reply)
            });
        if matches!(&result,Err(e)if !matches!(e,SystemdError::Remote{..})) {
            self.healthy = false;
        }
        result
    }
    fn call_inner(
        &mut self,
        message: &Message,
        budget: &Budget<'_>,
    ) -> Result<Reply, SystemdError> {
        self.serial = self
            .serial
            .checked_add(1)
            .ok_or(SystemdError::Protocol(
                "serial exhausted; reconnect required",
            ))?;
        let serial = self.serial;
        let bytes = wire::encode(
            serial,
            &message.destination,
            &message.path,
            &message.interface,
            &message.member,
            &message.signature,
            &message.body.0,
        )?;
        send(&self.socket, &bytes, budget)?;
        loop {
            budget.check()?;
            let frame = self.receive(budget)?;
            if frame.kind == 4 {
                self.signal(&frame)?;
                continue;
            }
            if !matches!(frame.kind, 2 | 3) {
                return Err(SystemdError::Protocol(
                    "unexpected incoming method call",
                ));
            }
            if frame.reply != serial {
                continue;
            }
            if frame.sender != message.destination
                && !(frame.kind == 3 && frame.sender == "org.freedesktop.DBus")
            {
                return Err(SystemdError::Protocol(
                    "reply sender is not pinned owner",
                ));
            }
            if frame.kind == 3 {
                let mut r = frame.reader();
                let text = if frame.signature.is_empty() {
                    String::new()
                } else if frame.signature == "s" {
                    r.string()?.to_owned()
                } else {
                    return Err(SystemdError::Protocol(
                        "invalid remote error body",
                    ));
                };
                r.end()?;
                return Err(match frame.error.as_str() {
                    "org.freedesktop.DBus.Error.NoReply"
                    | "org.freedesktop.DBus.Error.Timeout"
                    | "org.freedesktop.DBus.Error.TimedOut" => SystemdError::Deadline,
                    "org.freedesktop.DBus.Error.Disconnected" => disconnected(),
                    _ => SystemdError::Remote {
                        name: frame.error,
                        message: text,
                    },
                });
            }
            return Ok(Reply(frame));
        }
    }
    fn receive(&mut self, budget: &Budget<'_>) -> Result<Frame, SystemdError> {
        loop {
            budget.check()?;
            let needed = if self.received.len() >= 16 {
                wire::frame_size(&self.received)?
            } else {
                16
            };
            if self.received.len() == needed && needed >= 16 {
                return wire::decode(&std::mem::take(&mut self.received));
            }
            let mut bytes = [0; 8192];
            let size = (needed - self.received.len()).min(bytes.len());
            match recv(&self.socket, &mut bytes[..size]) {
                Ok(n) => self.received.extend_from_slice(&bytes[..n]),
                Err(e) if would_wait(&e) => wait(&self.socket, libc::POLLIN, budget)?,
                Err(e) => return Err(e),
            }
        }
    }
    pub fn pump(&mut self, budget: &Budget<'_>) -> Result<(), SystemdError> {
        // Calls also drain signals. A short bounded pause avoids busy GetJob polling.
        wait(&self.socket, libc::POLLIN, budget)
    }
    pub fn watch(&mut self, unit: &str) -> Result<(), SystemdError> {
        if self.watched.values().sum::<usize>() >= MAX_JOBS {
            return Err(SystemdError::Invalid("too many outstanding jobs"));
        }
        *self.watched.entry(unit.into()).or_default() += 1;
        Ok(())
    }
    pub fn release(&mut self, unit: &str) {
        if let Some(count) = self.watched.get_mut(unit) {
            *count -= 1;
            if *count == 0 {
                self.watched.remove(unit);
                self.jobs.retain(|_, event| event.unit != unit);
            }
        }
    }
    pub fn register_job(&mut self, path: &str, unit: &str) {
        if self
            .pending
            .insert(path.into(), unit.into())
            .is_some()
        {
            self.release(unit);
        }
    }
    pub fn release_job(&mut self, path: &str) {
        if let Some(unit) = self.pending.remove(path) {
            self.release(&unit);
        }
    }
    pub fn take_job(&mut self, path: &str) -> Option<JobEvent> {
        self.jobs.remove(path)
    }
    pub fn has_job(&self, path: &str) -> bool {
        self.jobs.contains_key(path)
    }
    pub fn configuration_revision(&self) -> u64 {
        self.configuration_revision
    }
    pub fn watch_loaded(&mut self, path: &str, budget: &Budget<'_>) -> Result<(), SystemdError> {
        if !self.configuration_subscribed {
            for rule in [
                contract::RELOADING.rule(None),
                contract::UNIT_REMOVED.rule(None),
                contract::PROPERTIES_CHANGED.rule(None),
            ] {
                let mut call = self.method(
                    "org.freedesktop.DBus",
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus",
                    "AddMatch",
                )?;
                call.string(&rule)?;
                self.call(call, budget)?.expect_empty()?;
            }
            self.configuration_subscribed = true;
        }
        self.configuration_path = Some(path.into());
        Ok(())
    }
    fn signal(&mut self, frame: &Frame) -> Result<(), SystemdError> {
        let watched = self.configuration_path.as_deref();
        let removed_watched = if self.owner.as_deref() == Some(&frame.sender)
            && watched.is_some()
            && frame.path == MANAGER_PATH
            && frame.interface == MANAGER_INTERFACE
            && frame.member == contract::UNIT_REMOVED.name
        {
            if frame.signature != contract::UNIT_REMOVED.signature {
                return Err(SystemdError::Protocol(
                    "invalid UnitRemoved signature",
                ));
            }
            let mut reader = frame.reader();
            let _unit = reader.string()?;
            let path = reader.string()?;
            let removed = Some(path) == watched;
            reader.end()?;
            removed
        } else {
            false
        };
        if self.owner.as_deref() == Some(&frame.sender)
            && watched.is_some()
            && ((frame.path == MANAGER_PATH
                && frame.interface == MANAGER_INTERFACE
                && frame.member == contract::RELOADING.name)
                || removed_watched
                || (Some(frame.path.as_str()) == watched
                    && frame.interface == contract::PROPERTIES_CHANGED.interface
                    && frame.member == contract::PROPERTIES_CHANGED.name))
        {
            self.configuration_revision =
                self.configuration_revision
                    .checked_add(1)
                    .ok_or(SystemdError::Protocol(
                        "configuration observation counter exhausted",
                    ))?;
        }
        if self.owner.as_deref() != Some(&frame.sender)
            || frame.path != MANAGER_PATH
            || frame.interface != MANAGER_INTERFACE
            || frame.member != contract::JOB_REMOVED.name
        {
            return Ok(());
        }
        if frame.signature != contract::JOB_REMOVED.signature {
            return Err(SystemdError::Protocol(
                "invalid JobRemoved signature",
            ));
        }
        let mut r = frame.reader();
        let id = r.u32()?;
        let path = r.string()?.to_owned();
        let unit = r.string()?.to_owned();
        let result = r.string()?.to_owned();
        r.end()?;
        if job_id(&path) != Some(id) {
            return Err(SystemdError::Protocol(
                "invalid JobRemoved identity",
            ));
        }
        if !self.watched.contains_key(&unit) {
            return Ok(());
        }
        if self.jobs.len() >= MAX_JOBS && !self.jobs.contains_key(&path) {
            return Err(SystemdError::Protocol("job event queue exceeded"));
        }
        self.jobs.insert(
            path,
            JobEvent {
                unit,
                result,
            },
        );
        Ok(())
    }
    pub(super) fn get(
        &mut self,
        path: &str,
        interface: &str,
        name: &str,
        budget: &Budget<'_>,
    ) -> Result<Reply, SystemdError> {
        let expected = contract::property_signature(interface, name)?;
        let mut m = self.method(
            self.owner
                .as_deref()
                .ok_or(SystemdError::Protocol("manager owner missing"))?,
            path,
            "org.freedesktop.DBus.Properties",
            "Get",
        )?;
        m.string(interface)?;
        m.string(name)?;
        let reply = self.call(m, budget)?;
        reply.signature("v")?;
        expect_variant(reply.0.reader().sig()?, expected)?;
        Ok(reply)
    }
    pub fn get_unit_job(
        &mut self,
        path: &str,
        budget: &Budget<'_>,
    ) -> Result<(u32, String), SystemdError> {
        let reply = self.get(path, super::UNIT_INTERFACE, "Job", budget)?;
        decode_unit_job(&reply)
    }
    pub fn get_string(
        &mut self,
        path: &str,
        interface: &str,
        name: &str,
        budget: &Budget<'_>,
    ) -> Result<String, SystemdError> {
        let reply = self.get(path, interface, name, budget)?;
        let mut r = reply.0.reader();
        expect_variant(r.sig()?, "s")?;
        let v = r.string()?.to_owned();
        r.end()?;
        Ok(v)
    }
    pub fn get_u32(
        &mut self,
        path: &str,
        interface: &str,
        name: &str,
        budget: &Budget<'_>,
    ) -> Result<u32, SystemdError> {
        let reply = self.get(path, interface, name, budget)?;
        let mut r = reply.0.reader();
        expect_variant(r.sig()?, "u")?;
        let v = r.u32()?;
        r.end()?;
        Ok(v)
    }
    pub fn get_i32(
        &mut self,
        path: &str,
        interface: &str,
        name: &str,
        budget: &Budget<'_>,
    ) -> Result<i32, SystemdError> {
        let reply = self.get(path, interface, name, budget)?;
        let mut r = reply.0.reader();
        expect_variant(r.sig()?, "i")?;
        let v = i32::from_ne_bytes(r.u32()?.to_ne_bytes());
        r.end()?;
        Ok(v)
    }
    pub fn get_bytes(
        &mut self,
        path: &str,
        interface: &str,
        name: &str,
        budget: &Budget<'_>,
    ) -> Result<Vec<u8>, SystemdError> {
        let reply = self.get(path, interface, name, budget)?;
        let mut r = reply.0.reader();
        expect_variant(r.sig()?, "ay")?;
        let v = r.bytes()?;
        r.end()?;
        Ok(v)
    }
}
fn decode_unit_job(reply: &Reply) -> Result<(u32, String), SystemdError> {
    reply.signature("v")?;
    let mut reader = reply.0.reader();
    expect_variant(reader.sig()?, "(uo)")?;
    reader.align(8)?;
    let id = reader.u32()?;
    let path = reader.string()?.to_owned();
    reader.end()?;
    if (id == 0 && path != "/") || (id != 0 && job_id(&path) != Some(id)) {
        return Err(SystemdError::Protocol("noncanonical unit job"));
    }
    Ok((id, path))
}
fn expect_variant(actual: &str, expected: &str) -> Result<(), SystemdError> {
    if actual == expected {
        Ok(())
    } else {
        Err(SystemdError::Protocol(
            "unexpected property variant",
        ))
    }
}
fn unique_name(name: &str) -> bool {
    name.len() <= 255
        && name.starts_with(':')
        && name[1..].contains('.')
        && name[1..].split('.').all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })
}

/// Operational credentials used only to constrain user-manager contracts.
pub(super) fn caller_ids() -> (u32, u32, u32, u32) {
    unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd::wire::Reader;
    fn bus() -> Bus {
        Bus {
            socket: std::fs::File::open("/dev/null").unwrap().into(),
            guid: "0123456789abcdef0123456789abcdef".into(),
            owner: Some(":1.2".into()),
            serial: 0,
            healthy: true,
            configuration_revision: 0,
            configuration_path: None,
            configuration_subscribed: false,
            watched: BTreeMap::new(),
            pending: BTreeMap::new(),
            jobs: BTreeMap::new(),
            received: Vec::new(),
        }
    }
    fn event(sender: &str) -> Frame {
        let mut body = Writer::default();
        body.u32(7);
        body.string("/org/freedesktop/systemd1/job/7")
            .unwrap();
        body.string("syrox-test.service").unwrap();
        body.string("done").unwrap();
        Frame {
            kind: 4,
            reply: 0,
            sender: sender.into(),
            path: MANAGER_PATH.into(),
            interface: MANAGER_INTERFACE.into(),
            member: "JobRemoved".into(),
            error: String::new(),
            signature: "uoss".into(),
            body: body.0,
            little: true,
        }
    }
    #[test]
    fn unit_job_tuple_requires_exact_signature_and_canonical_pair() {
        for (id, path, valid) in [
            (0, "/", true),
            (7, "/org/freedesktop/systemd1/job/7", true),
            (0, "/org/freedesktop/systemd1/job/7", false),
            (7, "/", false),
            (7, "/org/freedesktop/systemd1/job/07", false),
        ] {
            let mut body = Writer::default();
            body.sig("(uo)").unwrap();
            body.align(8);
            body.u32(id);
            body.string(path).unwrap();
            let mut frame = event(":1.2");
            frame.signature = "v".into();
            frame.body = body.0;
            let mut reply = Reply(frame);
            assert_eq!(decode_unit_job(&reply).is_ok(), valid);
            reply.0.signature = "(uo)".into();
            assert!(decode_unit_job(&reply).is_err());
            reply.0.signature = "v".into();
            reply.0.body.push(0);
            assert!(decode_unit_job(&reply).is_err());
        }
    }
    #[test]
    fn spoofed_job_completion_is_not_observed_and_repeated_release_is_safe() {
        let mut bus = bus();
        bus.watch("syrox-test.service").unwrap();
        bus.signal(&event(":9.9")).unwrap();
        assert!(!bus.has_job("/org/freedesktop/systemd1/job/7"));
        bus.signal(&event(":1.2")).unwrap();
        assert!(bus.has_job("/org/freedesktop/systemd1/job/7"));
        bus.register_job(
            "/org/freedesktop/systemd1/job/7",
            "syrox-test.service",
        );
        bus.watch("syrox-test.service").unwrap();
        bus.register_job(
            "/org/freedesktop/systemd1/job/8",
            "syrox-test.service",
        );
        bus.release_job("/org/freedesktop/systemd1/job/7");
        bus.release_job("/org/freedesktop/systemd1/job/7");
        assert_eq!(bus.watched["syrox-test.service"], 1);
        bus.release_job("/org/freedesktop/systemd1/job/8");
        assert!(bus.watched.is_empty());
    }
    #[test]
    fn changed_manager_owner_invalidates_connection_before_further_requests() {
        let mut bus = bus();
        let message = bus.manager_method("StopUnit").unwrap();
        assert!(bus.verify_manager_owner(":1.2").is_ok());
        assert!(bus.verify_manager_owner(":1.3").is_err());
        assert!(bus.verify_manager_owner(":1.2").is_err());
        assert!(bus.manager_method("StopUnit").is_err());
        let cancellation = crate::cancellation::Cancellation::default();
        let budget = Budget::new(std::time::Duration::from_secs(1), &cancellation).unwrap();
        assert!(
            matches!(bus.call(message, &budget), Err(SystemdError::Io(error))
            if error.kind() == std::io::ErrorKind::ConnectionAborted)
        );
    }
    fn manager() -> super::super::SystemdManager {
        super::super::SystemdManager {
            scope: super::super::SystemdScope::System,
            bus: bus(),
            connection: 1,
        }
    }
    #[test]
    fn persistent_start_and_reload_have_distinct_wire_contracts() {
        let bus = bus();
        let message = bus
            .manager_unit_job("StartUnit", "syrox-test.service", "fail")
            .unwrap();
        assert_eq!(message.member, "StartUnit");
        assert_eq!(message.destination, ":1.2");
        assert_eq!(message.signature, "ss");
        let mut reader = Reader::new(&message.body.0, true);
        assert_eq!(reader.string().unwrap(), "syrox-test.service");
        assert_eq!(reader.string().unwrap(), "fail");
        reader.end().unwrap();
        let reload = bus.manager_method("Reload").unwrap();
        assert!(reload.signature.is_empty());
        assert!(reload.body.0.is_empty());
    }
    #[test]
    fn persistent_mutations_preserve_uncertainty_without_replay() {
        let cancellation = crate::cancellation::Cancellation::default();
        let timeout = std::time::Duration::from_secs(1);
        let unit = super::super::SystemdUnitName::new("syrox-test.service").unwrap();
        let mut manager = manager();
        assert!(matches!(
            manager.start_unit(&unit, timeout, &cancellation),
            Err(SystemdError::MutationUncertain { .. })
        ));
        assert_eq!(manager.bus.serial, 1);
        assert!(manager.bus.watched.is_empty());
        assert!(
            manager
                .start_unit(&unit, timeout, &cancellation)
                .is_err()
        );
        assert_eq!(manager.bus.serial, 1);
        let mut reload_manager = self::manager();
        assert!(matches!(
            reload_manager.reload(timeout, &cancellation),
            Err(SystemdError::ManagerMutationUncertain {
                operation: "Reload",
                ..
            })
        ));
        assert_eq!(reload_manager.bus.serial, 1);
        assert!(
            reload_manager
                .reload(timeout, &cancellation)
                .is_err()
        );
        assert_eq!(reload_manager.bus.serial, 1);
    }
    #[test]
    fn persistent_mutations_reject_cancelled_or_invalid_budget_before_send() {
        let cancellation = crate::cancellation::Cancellation::default();
        cancellation.cancel();
        let mut manager = manager();
        let unit = super::super::SystemdUnitName::new("syrox-test.service").unwrap();
        assert!(matches!(
            manager.start_unit(
                &unit,
                std::time::Duration::from_secs(1),
                &cancellation
            ),
            Err(SystemdError::Cancelled)
        ));
        assert!(matches!(
            manager.reload(std::time::Duration::from_secs(1), &cancellation),
            Err(SystemdError::Cancelled)
        ));
        assert_eq!(manager.bus.serial, 0);
        assert!(
            manager
                .reload(
                    std::time::Duration::ZERO,
                    &crate::cancellation::Cancellation::default()
                )
                .is_err()
        );
        assert_eq!(manager.bus.serial, 0);
    }
    #[test]
    fn loaded_configuration_revision_ignores_spoofed_and_unrelated_property_signals() {
        let mut bus = bus();
        let path = "/org/freedesktop/systemd1/unit/syrox_test";
        bus.configuration_path = Some(path.into());
        let mut signal = event(":9.9");
        signal.member = "Reloading".into();
        signal.signature = "b".into();
        signal.body = 1_u32.to_le_bytes().to_vec();
        bus.signal(&signal).unwrap();
        assert_eq!(bus.configuration_revision(), 0);
        signal.sender = ":1.2".into();
        bus.signal(&signal).unwrap();
        assert_eq!(bus.configuration_revision(), 1);
        signal.interface = "org.freedesktop.DBus.Properties".into();
        signal.member = "PropertiesChanged".into();
        signal.path = "/org/freedesktop/systemd1/unit/unrelated".into();
        bus.signal(&signal).unwrap();
        assert_eq!(bus.configuration_revision(), 1);
        signal.path = path.into();
        bus.signal(&signal).unwrap();
        assert_eq!(bus.configuration_revision(), 2);
    }
    #[test]
    fn unit_removal_invalidates_only_the_observed_unit() {
        let mut bus = bus();
        let path = "/org/freedesktop/systemd1/unit/syrox_test";
        bus.configuration_path = Some(path.into());
        let mut signal = event(":1.2");
        signal.member = "UnitRemoved".into();
        signal.signature = "so".into();
        for (sender, removed, revision) in [
            (
                ":1.2",
                "/org/freedesktop/systemd1/unit/foreign",
                0,
            ),
            (":9.9", path, 0),
            (":1.2", path, 1),
        ] {
            let mut body = Writer::default();
            body.string("syrox-test.service").unwrap();
            body.string(removed).unwrap();
            signal.sender = sender.into();
            signal.body = body.0;
            bus.signal(&signal).unwrap();
            assert_eq!(bus.configuration_revision(), revision);
        }
        signal.signature = "s".into();
        assert!(bus.signal(&signal).is_err());
        assert_eq!(bus.configuration_revision(), 1);
    }
    #[test]
    fn job_queue_and_local_authority_have_explicit_limits() {
        let mut bus = bus();
        for _ in 0..MAX_JOBS {
            bus.watch("syrox-test.service").unwrap();
        }
        assert!(bus.watch("syrox-test.service").is_err());
        assert_eq!(
            socket_path("unix:path=/tmp/a%2cb").unwrap(),
            b"/tmp/a,b"
        );
        for address in [
            "tcp:host=localhost",
            "unix:path=relative",
            "unix:path=/tmp/%00",
            "unix:path=/tmp/%zz",
        ] {
            assert!(socket_path(address).is_err());
        }
        assert!(socket_path(&format!("unix:path=/{}", "a".repeat(108))).is_err());
        assert!(!unique_name(":1"));
        assert!(!unique_name(":1..2"));
        assert!(unique_name(":1.42"));
    }
}

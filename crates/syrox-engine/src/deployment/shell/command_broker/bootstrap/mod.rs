use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::execution::journal::SessionId;
use crate::execution::journal::execution::ExecutionGuard;
use crate::execution::resources::{ResourceReceiver, send_resources};
use crate::execution::transport::{PacketChannel, Peer};
use crate::runtime::launch_preparation::PreparedRuntimeLaunch;
use crate::{cancellation::Cancellation, store::ContentDigest};

use super::preparation::PreparedCommandBroker;

const MAX_ENVELOPE: usize = 4096;

pub(crate) mod scope;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    sequence: u64,
    invocation: String,
    alias: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization: Option<Authorization>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    gate_sequence: u64,
    namespace_device: u64,
    namespace_inode: u64,
    spec: String,
}

struct Grant {
    invocation: String,
    alias: String,
    spec: ContentDigest,
}

impl Grant {
    fn matches(&self, request: &Request) -> bool {
        self.invocation == request.invocation
            && self.alias == request.alias
            && request
                .authorization
                .as_ref()
                .is_some_and(|auth| auth.spec == self.spec.to_string())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u32,
    sequence: u64,
    invocation: String,
    /// None is a generic refusal. Internal errors never cross this envelope.
    pin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorized: Option<bool>,
}

struct Connection {
    channel: PacketChannel,
    peer: Peer,
    sequence: u64,
    failed: bool,
}

impl Connection {
    fn new(channel: PacketChannel, peer: Peer) -> io::Result<Self> {
        if peer.pid == 0 {
            return Err(invalid());
        }
        Ok(Self {
            channel,
            peer,
            sequence: 0,
            failed: false,
        })
    }

    fn begin(&mut self) -> io::Result<u64> {
        if self.failed || self.sequence == u64::MAX {
            return Err(invalid());
        }
        // Failure at any later point leaves the connection permanently poisoned.
        self.failed = true;
        Ok(self.sequence)
    }

    fn finish(&mut self) {
        self.sequence += 1; // begin rejects the terminal value.
        self.failed = false;
    }
}

pub(crate) struct BootstrapServer(Connection, Option<Grant>);
pub(crate) struct BootstrapClient(Connection, Option<Pending>, u64);

struct Pending {
    request: Request,
    deadline: Instant,
    receiver: Option<ResourceReceiver>,
    outgoing: Option<Vec<u8>>,
}

pub(crate) enum BootstrapPoll {
    Pending,
    Ready(Option<Box<PreparedRuntimeLaunch>>),
    Authorized(bool),
}

impl AsFd for BootstrapServer {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.channel.as_fd()
    }
}

impl AsFd for BootstrapClient {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.channel.as_fd()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Served {
    Granted,
    Denied,
    Authorized,
    /// Peer closed while the server was awaiting a new request. This closes
    /// admission only; it provides no evidence about running descendants.
    Closed,
}

impl BootstrapServer {
    /// Caller pins the monitor's process identity before constructing this
    /// connection. SCM credentials authenticate every subsequent packet.
    pub(crate) fn new(channel: PacketChannel, peer: Peer) -> io::Result<Self> {
        Connection::new(channel, peer).map(|connection| Self(connection, None))
    }

    pub(crate) fn serve_one(
        &mut self,
        prepared: &PreparedCommandBroker<'_>,
        execution: &ExecutionGuard<'_>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Served> {
        if !prepared.matches_execution(execution) {
            self.0.failed = true;
            return Err(invalid());
        }
        self.serve_with(
            prepared,
            cancel,
            deadline,
            |sequence, channel, bytes| {
                execution
                    .with_started_execution(sequence, cancel, deadline, || {
                        channel.send(bytes, &[], deadline, cancel)
                    })
                    .map_err(|_| handoff_error(cancel))
            },
        )
    }

    fn serve_with(
        &mut self,
        prepared: &PreparedCommandBroker<'_>,
        cancel: &Cancellation,
        deadline: Instant,
        authorize: impl FnOnce(u64, &PacketChannel, &[u8]) -> io::Result<()>,
    ) -> io::Result<Served> {
        let sequence = self.0.begin()?;
        let packet = match self
            .0
            .channel
            .receive(self.0.peer, 0, deadline, cancel)
        {
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(Served::Closed);
            }
            result => result?,
        };
        let request = Request::decode(&packet.bytes, sequence)?;
        // One lane spans resources, IO readiness and authorization. A new
        // resource request replaces an abandoned grant. Existing running jobs
        // remain independent; no unbounded stale-grant inventory is retained.
        let previous = self.1.take();
        if let Some(authorization) = &request.authorization {
            let grant = previous.ok_or_else(invalid)?;
            if !grant.matches(&request) {
                return Err(invalid());
            }
            let response = Response {
                version: 1,
                sequence,
                invocation: request.invocation.clone(),
                pin: None,
                authorized: Some(true),
            };
            authorize(
                authorization.gate_sequence,
                &self.0.channel,
                &encode(&response)?,
            )?;
            self.0.finish();
            return Ok(Served::Authorized);
        }
        let launch = match prepared.prepare_invocation(&request.alias, cancel) {
            Ok(launch) => Some(launch),
            Err(_) if cancel.is_cancelled() => return Err(crate::cancellation::cancellation_io()),
            Err(_) => None,
        };
        let pin = launch
            .as_ref()
            .map(|launch| launch.spec.digest())
            .transpose()
            .map_err(|_| invalid())?;
        let response = Response {
            version: 1,
            sequence,
            invocation: request.invocation.clone(),
            pin: pin.map(|pin| pin.to_string()),
            authorized: None,
        };
        self.0
            .channel
            .send(&encode(&response)?, &[], deadline, cancel)?;
        let served = if let Some(launch) = launch {
            send_resources(
                &self.0.channel,
                &launch.spec,
                &launch
                    .descriptors
                    .iter()
                    .map(|fd| fd.as_fd())
                    .collect::<Vec<_>>(),
                launch.retention.as_fd(),
                deadline,
                cancel,
            )
            .map_err(|_| handoff_error(cancel))?;
            self.1 = Some(Grant {
                invocation: request.invocation,
                alias: request.alias,
                spec: pin.ok_or_else(invalid)?,
            });
            Served::Granted
        } else {
            Served::Denied
        };
        self.0.finish();
        Ok(served)
    }
}

impl BootstrapClient {
    /// The root Shell gate consumes journal sequence zero before the public
    /// command lane can run. Packet sequences still start at zero independently.
    pub(crate) fn after_root_authorization(channel: PacketChannel, peer: Peer) -> io::Result<Self> {
        Connection::new(channel, peer).map(|connection| Self(connection, None, 1))
    }

    /// The monitor must independently authenticate and pin the CLI process.
    #[cfg(test)]
    fn new(channel: PacketChannel, peer: Peer) -> io::Result<Self> {
        Connection::new(channel, peer).map(|connection| Self(connection, None, 0))
    }

    /// Queue one small request on an idle channel. Only one resource exchange is
    /// outstanding per connection; live invocations remain independently owned.
    pub(crate) fn begin_request(
        &mut self,
        invocation: &SessionId,
        alias: &str,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        self.begin(invocation, alias, None, cancel, deadline)
    }

    /// Only the monitor's admitted namespace identity may be supplied here.
    /// The public wrapper's Commit confirms IO readiness, never this authority.
    pub(crate) fn begin_authorization(
        &mut self,
        invocation: &SessionId,
        alias: &str,
        namespace: crate::platform::linux::fd::FileIdentity,
        spec: ContentDigest,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        self.begin(
            invocation,
            alias,
            Some(Authorization {
                gate_sequence: self.2,
                namespace_device: namespace.device,
                namespace_inode: namespace.inode,
                spec: spec.to_string(),
            }),
            cancel,
            deadline,
        )
    }

    fn begin(
        &mut self,
        invocation: &SessionId,
        alias: &str,
        authorization: Option<Authorization>,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        if self.1.take().is_some() {
            self.0.failed = true;
            return Err(invalid());
        }
        let sequence = self.0.begin()?;
        let request = Request {
            version: 1,
            sequence,
            invocation: invocation.to_string(),
            alias: alias.into(),
            authorization,
        };
        request.validate(sequence)?;
        crate::execution::transport::budget(deadline, cancel)?;
        let outgoing = Some(encode(&request)?);
        self.1 = Some(Pending {
            request,
            deadline,
            receiver: None,
            outgoing,
        });
        Ok(())
    }

    /// Send or consume at most one packet without waiting. The admission deadline was
    /// fixed by `begin_request` and cannot be extended by polling. Between calls,
    /// the monitor must service signals, exits and other live invocations.
    /// Any error permanently poisons the channel and drops partial resources.
    pub(crate) fn poll_reply(&mut self, cancel: &Cancellation) -> io::Result<BootstrapPoll> {
        self.0.failed = true;
        let mut pending = self.1.take().ok_or_else(invalid)?;
        crate::execution::transport::budget(pending.deadline, cancel)?;
        if let Some(bytes) = &pending.outgoing {
            if self.0.channel.try_send(bytes, &[])? {
                pending.outgoing = None;
            }
            crate::execution::transport::budget(pending.deadline, cancel)?;
            self.1 = Some(pending);
            return Ok(BootstrapPoll::Pending);
        }
        let count = pending
            .receiver
            .as_ref()
            .map(ResourceReceiver::expected_fds)
            .transpose()
            .map_err(|_| invalid())?
            .unwrap_or(0);
        let Some(packet) = self.0.channel.try_receive(self.0.peer, count)? else {
            self.1 = Some(pending);
            return Ok(BootstrapPoll::Pending);
        };
        let resources = if let Some(receiver) = &mut pending.receiver {
            receiver
                .push(packet)
                .map_err(|_| handoff_error(cancel))?
        } else {
            let response = Response::decode(&packet.bytes, &pending.request)?;
            if let Some(authorized) = response.authorized {
                crate::execution::transport::budget(pending.deadline, cancel)?;
                self.2 = self.2.checked_add(1).ok_or_else(invalid)?;
                self.0.finish();
                return Ok(BootstrapPoll::Authorized(authorized));
            }
            let Some(pin) = response.pin else {
                crate::execution::transport::budget(pending.deadline, cancel)?;
                self.0.finish();
                return Ok(BootstrapPoll::Ready(None));
            };
            pending.receiver = Some(ResourceReceiver::new(
                pin.parse().map_err(|_| invalid())?,
            ));
            None
        };
        crate::execution::transport::budget(pending.deadline, cancel)?;
        if let Some(resources) = resources {
            self.0.finish();
            return Ok(BootstrapPoll::Ready(Some(Box::new(
                PreparedRuntimeLaunch {
                    spec: resources.spec,
                    descriptors: resources.descriptors,
                    retention: resources.retention.into(),
                    origin_interest: None,
                },
            ))));
        }
        self.1 = Some(pending);
        Ok(BootstrapPoll::Pending)
    }
}

impl Request {
    fn validate(&self, sequence: u64) -> io::Result<()> {
        if self.version != 1
            || self.sequence != sequence
            || SessionId::parse(&self.invocation)
                .map_err(|_| invalid())?
                .to_string()
                != self.invocation
            || self.alias.is_empty()
            || self.alias.len() > 128
            || matches!(self.alias.as_str(), "." | "..")
            || !self
                .alias
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(invalid());
        }
        if let Some(authorization) = &self.authorization {
            let _: ContentDigest = authorization
                .spec
                .parse()
                .map_err(|_| invalid())?;
            if authorization.namespace_device == 0
                || authorization.namespace_inode == 0
                || authorization.gate_sequence == u64::MAX
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn decode(bytes: &[u8], sequence: u64) -> io::Result<Self> {
        let value: Self = decode(bytes)?;
        value.validate(sequence)?;
        Ok(value)
    }
}

impl Response {
    fn decode(bytes: &[u8], request: &Request) -> io::Result<Self> {
        let value: Self = decode(bytes)?;
        if value.version != 1
            || value.sequence != request.sequence
            || value.invocation != request.invocation
            || value.authorized.is_some() != request.authorization.is_some()
            || (value.authorized.is_some() && value.pin.is_some())
        {
            return Err(invalid());
        }
        if let Some(pin) = &value.pin {
            let _: ContentDigest = pin.parse().map_err(|_| invalid())?;
        }
        Ok(value)
    }
}

fn encode(value: &impl Serialize) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    bytes.push(b'\n');
    if bytes.len() > MAX_ENVELOPE {
        return Err(invalid());
    }
    Ok(bytes)
}

fn decode<T: for<'de> Deserialize<'de> + Serialize>(bytes: &[u8]) -> io::Result<T> {
    if bytes.len() > MAX_ENVELOPE {
        return Err(invalid());
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if encode(&value)? != bytes {
        return Err(invalid());
    }
    Ok(value)
}

fn invalid() -> io::Error {
    io::Error::other("invalid private command handoff")
}

fn handoff_error(cancel: &Cancellation) -> io::Error {
    if cancel.is_cancelled() {
        crate::cancellation::cancellation_io()
    } else {
        invalid()
    }
}

#[cfg(test)]
mod tests;

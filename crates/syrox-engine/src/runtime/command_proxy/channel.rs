use std::io;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::time::Instant;

use crate::cancellation::Cancellation;
use crate::execution::transport::{PacketChannel, Peer};

use super::wire::{Frame, Message};

pub(crate) struct ControlChannel {
    channel: PacketChannel,
    peer: Peer,
    sent: u64,
    received: u64,
    failed: bool,
    view: PeerView,
    requested: bool,
    handed_off: bool,
}

enum PeerView {
    Local,
    Ancestor,
}

impl ControlChannel {
    /// The caller must independently pin and authenticate this peer before
    /// construction. Per-packet kernel credentials prevent endpoint delegation
    /// from silently changing the sender.
    pub(crate) fn new(channel: PacketChannel, peer: Peer) -> io::Result<Self> {
        if peer.pid == 0 {
            return Err(io::Error::other("invalid command proxy peer"));
        }
        Ok(Self {
            channel,
            peer,
            sent: 0,
            received: 0,
            failed: false,
            view: PeerView::Local,
            requested: false,
            handed_off: false,
        })
    }

    pub(crate) fn connect_ancestor(
        context: &super::ProxyContext,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Self> {
        let channel =
            PacketChannel::connect_command_proxy(context.endpoint_identity(), deadline, cancel)?;
        let peer = channel.namespace_ancestor_credentials()?;
        Ok(Self {
            channel,
            peer,
            sent: 0,
            received: 0,
            failed: false,
            view: PeerView::Ancestor,
            requested: false,
            handed_off: false,
        })
    }

    pub(crate) fn send(
        &mut self,
        message: Message,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        self.check()?;
        self.failed = true;
        let bytes = Frame::new(self.sent, message)?.encode()?;
        self.channel.send(&bytes, &[], deadline, cancel)?;
        self.sent = self.sent.checked_add(1).ok_or_else(exhausted)?;
        self.failed = false;
        Ok(())
    }

    /// A nonblocking monitor send. The event-loop owner retains the same
    /// pending message until this returns true; no packet is replayed afterward.
    pub(crate) fn try_send(&mut self, message: Message) -> io::Result<bool> {
        self.check()?;
        self.failed = true;
        let bytes = Frame::new(self.sent, message)?.encode()?;
        if !self.channel.try_send(&bytes, &[])? {
            self.failed = false;
            return Ok(false);
        }
        self.sent = self.sent.checked_add(1).ok_or_else(exhausted)?;
        self.failed = false;
        Ok(true)
    }

    pub(crate) fn receive(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Message> {
        self.check()?;
        self.failed = true;
        let packet = if matches!(self.view, PeerView::Ancestor) {
            self.channel
                .receive_namespace_ancestor(self.peer, 0, deadline, cancel)?
        } else {
            self.channel
                .receive(self.peer, 0, deadline, cancel)?
        };
        let frame = Frame::decode(&packet.bytes, self.received)?;
        self.received = self
            .received
            .checked_add(1)
            .ok_or_else(exhausted)?;
        self.failed = false;
        Ok(frame.message().clone())
    }

    /// One monitor-side packet per tick. A would-block result preserves the
    /// sequence and does not poison the channel; malformed input does.
    pub(crate) fn try_receive(&mut self) -> io::Result<Option<Message>> {
        self.check()?;
        if matches!(self.view, PeerView::Ancestor) {
            return Err(io::Error::other(
                "ancestor control requires frontend receive",
            ));
        }
        self.failed = true;
        let Some(packet) = self.channel.try_receive(self.peer, 0)? else {
            self.failed = false;
            return Ok(None);
        };
        let frame = Frame::decode(&packet.bytes, self.received)?;
        self.received = self
            .received
            .checked_add(1)
            .ok_or_else(exhausted)?;
        self.failed = false;
        Ok(Some(frame.message().clone()))
    }

    pub(crate) fn send_request(
        &mut self,
        context: &super::ProxyContext,
        request: &super::request::ProxyRequest,
        descriptors: [BorrowedFd<'_>; 4],
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        self.check()?;
        if !matches!(self.view, PeerView::Ancestor)
            || self.requested
            || self.sent != 0
            || self.received != 0
        {
            return Err(io::Error::other("invalid command request phase"));
        }
        self.failed = true;
        self.requested = true;
        super::fragment::send_request(
            &self.channel,
            context,
            request,
            descriptors,
            cancel,
            deadline,
        )?;
        self.failed = false;
        Ok(())
    }

    /// The broker hands off the owned init pidfd, plus a private PTY master only
    /// when the namespace preparation declared terminal IO.
    pub(crate) fn try_send_namespace(
        &mut self,
        pidfd: BorrowedFd<'_>,
        master: Option<BorrowedFd<'_>>,
    ) -> io::Result<bool> {
        self.check()?;
        if matches!(self.view, PeerView::Ancestor) || self.handed_off {
            return Err(io::Error::other(
                "invalid namespace handoff phase",
            ));
        }
        self.failed = true;
        let sent = if let Some(master) = master {
            self.channel
                .try_send(b"SCPI1", &[pidfd, master])?
        } else {
            self.channel.try_send(b"SCPI1", &[pidfd])?
        };
        self.handed_off = sent;
        self.failed = false;
        Ok(sent)
    }

    pub(crate) fn receive_namespace(
        &mut self,
        terminal: bool,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<super::namespace_handoff::NamespaceHandoff> {
        self.check()?;
        if !matches!(self.view, PeerView::Ancestor) || self.handed_off {
            return Err(io::Error::other(
                "invalid namespace handoff phase",
            ));
        }
        self.failed = true;
        let packet = self.channel.receive_namespace_ancestor(
            self.peer,
            1 + usize::from(terminal),
            deadline,
            cancel,
        )?;
        if packet.bytes != b"SCPI1" {
            return Err(io::Error::other(
                "invalid command namespace handoff",
            ));
        }
        let handoff =
            super::namespace_handoff::NamespaceHandoff::new(packet.descriptors, terminal)?;
        self.handed_off = true;
        self.failed = false;
        Ok(handoff)
    }

    pub(crate) fn descriptor(&self) -> BorrowedFd<'_> {
        self.channel.as_fd()
    }

    fn check(&self) -> io::Result<()> {
        if self.failed {
            Err(io::Error::other(
                "command proxy channel requires settlement after uncertainty",
            ))
        } else {
            Ok(())
        }
    }
}

fn exhausted() -> io::Error {
    io::Error::other("command proxy sequence exhausted")
}

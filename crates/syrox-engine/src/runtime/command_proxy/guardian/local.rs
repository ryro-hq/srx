use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::time::Instant;

use super::wire::{self, Event};
use crate::cancellation::Cancellation;
use crate::execution::transport::{PacketChannel, Peer};

pub(super) struct LocalChannel {
    channel: PacketChannel,
    peer: Peer,
    sent: u64,
    received: u64,
    failed: bool,
}
impl LocalChannel {
    pub(super) fn new(channel: PacketChannel, peer: Peer) -> io::Result<Self> {
        if peer.pid == 0 {
            return Err(invalid());
        }
        Ok(Self {
            channel,
            peer,
            sent: 0,
            received: 0,
            failed: false,
        })
    }
    pub(super) fn send(
        &mut self,
        event: &Event,
        descriptors: &[BorrowedFd<'_>],
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<()> {
        self.check()?;
        self.failed = true;
        if descriptors.len() != wire::descriptor_count(event) {
            return Err(invalid());
        }
        let bytes = wire::encode(self.sent, event)?;
        self.channel
            .send(&bytes, descriptors, deadline, cancel)?;
        self.sent = self.sent.checked_add(1).ok_or_else(invalid)?;
        self.failed = false;
        Ok(())
    }
    pub(super) fn poll(
        &mut self,
        expected_fds: usize,
    ) -> io::Result<Option<(Event, Vec<OwnedFd>)>> {
        self.check()?;
        if expected_fds > 2 {
            return Err(invalid());
        }
        self.failed = true;
        let Some(packet) = self
            .channel
            .try_receive(self.peer, expected_fds)?
        else {
            self.failed = false;
            return Ok(None);
        };
        let event = wire::decode(&packet.bytes, self.received)?;
        if expected_fds != wire::descriptor_count(&event) {
            return Err(invalid());
        }
        self.received = self.received.checked_add(1).ok_or_else(invalid)?;
        self.failed = false;
        Ok(Some((event, packet.descriptors)))
    }
    fn check(&self) -> io::Result<()> {
        if self.failed {
            Err(invalid())
        } else {
            Ok(())
        }
    }
}
fn invalid() -> io::Error {
    io::Error::other("local guardian channel requires cleanup")
}

#[cfg(test)]
mod tests {
    use super::{Event, LocalChannel, PacketChannel};
    use crate::cancellation::Cancellation;
    use std::os::fd::AsFd as _;
    use std::time::{Duration, Instant};

    #[test]
    fn local_peer_sequence_and_descriptor_mismatch_poison_the_exchange() {
        let (left, right) = PacketChannel::pair().unwrap();
        let peer = right.peer_credentials().unwrap();
        let mut sender = LocalChannel::new(left, peer).unwrap();
        let mut receiver = LocalChannel::new(right, peer).unwrap();
        sender
            .send(
                &Event::RelayReady,
                &[],
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert!(matches!(
            receiver.poll(0).unwrap(),
            Some((Event::RelayReady, _))
        ));
        let foreign = tempfile::tempfile().unwrap();
        let bytes = super::wire::encode(1, &Event::RelayReady).unwrap();
        sender
            .channel
            .send(
                &bytes,
                &[foreign.as_fd()],
                Instant::now() + Duration::from_secs(2),
                &Cancellation::default(),
            )
            .unwrap();
        assert!(receiver.poll(0).is_err());
        assert!(receiver.failed);
        assert!(receiver.poll(0).is_err());
    }
}

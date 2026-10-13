use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::time::Instant;

use sha2::{Digest as _, Sha256};

use crate::cancellation::Cancellation;
use crate::execution::transport::{PacketChannel, Peer};

use super::ProxyContext;
use super::request::{MAX_REQUEST_BYTES, ProxyRequest};

const HEADER_SIZE: usize = 40;
const PART_BYTES: usize = 4088;

pub(crate) fn send_request(
    channel: &PacketChannel,
    context: &ProxyContext,
    request: &ProxyRequest,
    descriptors: [BorrowedFd<'_>; 4],
    cancel: &Cancellation,
    deadline: Instant,
) -> io::Result<()> {
    let bytes = request.canonical_bytes()?;
    channel.send(&context_hello(context)?, &[], deadline, cancel)?;
    let header = header(&bytes)?;
    channel.send(&header, &descriptors, deadline, cancel)?;
    for (index, chunk) in bytes.chunks(PART_BYTES).enumerate() {
        let offset = index * PART_BYTES;
        let mut part = Vec::with_capacity(8 + chunk.len());
        part.extend_from_slice(b"SRP1");
        part.extend_from_slice(
            &u32::try_from(offset)
                .expect("bounded request")
                .to_le_bytes(),
        );
        part.extend_from_slice(chunk);
        channel.send(&part, &[], deadline, cancel)?;
    }
    Ok(())
}

/// One packet per poll, retaining only bounded bytes and four IO handles. This
/// lets existing invocations progress while a new wrapper is still sending.
pub(crate) struct RequestReceiver {
    expected: ProxyContext,
    phase: ReceivePhase,
}
enum ReceivePhase {
    Hello,
    Header,
    Body {
        size: usize,
        digest: [u8; 32],
        bytes: Vec<u8>,
        descriptors: Vec<OwnedFd>,
    },
    Finished,
}
impl RequestReceiver {
    pub(crate) fn new(expected: ProxyContext) -> Self {
        Self {
            expected,
            phase: ReceivePhase::Hello,
        }
    }
    pub(crate) fn poll(
        &mut self,
        channel: &PacketChannel,
        peer: Peer,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> io::Result<Option<(ProxyRequest, Vec<OwnedFd>)>> {
        if cancel.is_cancelled() {
            self.phase = ReceivePhase::Finished;
            return Err(crate::cancellation::cancellation_io());
        }
        if Instant::now() >= deadline {
            self.phase = ReceivePhase::Finished;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "command request deadline",
            ));
        }
        let expected_fds = if matches!(self.phase, ReceivePhase::Header) {
            4
        } else {
            0
        };
        if matches!(self.phase, ReceivePhase::Finished) {
            return Err(invalid());
        }
        let packet = match channel.try_receive(peer, expected_fds) {
            Ok(None) => return Ok(None),
            Ok(Some(packet)) => packet,
            Err(error) => {
                self.phase = ReceivePhase::Finished;
                return Err(error);
            }
        };
        match std::mem::replace(&mut self.phase, ReceivePhase::Finished) {
            ReceivePhase::Hello => {
                if packet.bytes != context_hello(&self.expected)? {
                    return Err(invalid());
                }
                self.phase = ReceivePhase::Header;
            }
            ReceivePhase::Header => {
                let (size, digest) = decode_header(&packet.bytes)?;
                self.phase = ReceivePhase::Body {
                    size,
                    digest,
                    bytes: Vec::with_capacity(size),
                    descriptors: packet.descriptors,
                };
            }
            ReceivePhase::Body {
                size,
                digest,
                mut bytes,
                descriptors,
            } => {
                append_part(&mut bytes, size, &packet.bytes)?;
                if bytes.len() == size {
                    let observed: [u8; 32] = Sha256::digest(&bytes).into();
                    if observed != digest {
                        return Err(invalid());
                    }
                    return Ok(Some((ProxyRequest::decode(&bytes)?, descriptors)));
                }
                self.phase = ReceivePhase::Body {
                    size,
                    digest,
                    bytes,
                    descriptors,
                };
            }
            ReceivePhase::Finished => return Err(invalid()),
        }
        Ok(None)
    }
}

fn context_hello(context: &ProxyContext) -> io::Result<Vec<u8>> {
    let mut hello = b"SCH2".to_vec();
    hello.extend_from_slice(&Sha256::digest(context.canonical_bytes()?));
    Ok(hello)
}

fn header(bytes: &[u8]) -> io::Result<[u8; HEADER_SIZE]> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err(invalid());
    }
    let mut header = [0; HEADER_SIZE];
    header[..4].copy_from_slice(b"SRH1");
    header[4..8].copy_from_slice(
        &u32::try_from(bytes.len())
            .expect("bounded request")
            .to_le_bytes(),
    );
    header[8..].copy_from_slice(&Sha256::digest(bytes));
    Ok(header)
}

fn decode_header(header: &[u8]) -> io::Result<(usize, [u8; 32])> {
    if header.len() != HEADER_SIZE || &header[..4] != b"SRH1" {
        return Err(invalid());
    }
    let size = u32::from_le_bytes(header[4..8].try_into().expect("header bound")) as usize;
    if size == 0 || size > MAX_REQUEST_BYTES {
        return Err(invalid());
    }
    Ok((
        size,
        header[8..].try_into().expect("header bound"),
    ))
}

fn append_part(bytes: &mut Vec<u8>, size: usize, part: &[u8]) -> io::Result<()> {
    if part.len() <= 8 || part.len() > PART_BYTES + 8 || &part[..4] != b"SRP1" {
        return Err(invalid());
    }
    let offset = u32::from_le_bytes(part[4..8].try_into().expect("part bound")) as usize;
    let expected = PART_BYTES.min(
        size.checked_sub(bytes.len())
            .ok_or_else(invalid)?,
    );
    if offset != bytes.len() || part.len() - 8 != expected {
        return Err(invalid());
    }
    bytes.extend_from_slice(&part[8..]);
    Ok(())
}

fn invalid() -> io::Error {
    io::Error::other("invalid fragmented command request")
}

#[cfg(test)]
mod tests {
    use super::{MAX_REQUEST_BYTES, PART_BYTES, append_part, decode_header, header};

    #[test]
    fn bounds_are_admitted_before_allocation_and_parts_cannot_overlap() {
        assert!(header(&vec![0; MAX_REQUEST_BYTES + 1]).is_err());
        let mut admitted = header(&[1]).unwrap();
        admitted[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_header(&admitted).is_err());
        let mut bytes = Vec::new();
        let mut part = b"SRP1".to_vec();
        part.extend_from_slice(&0_u32.to_le_bytes());
        part.extend_from_slice(&vec![7; PART_BYTES]);
        append_part(&mut bytes, PART_BYTES + 1, &part).unwrap();
        assert!(append_part(&mut bytes, PART_BYTES + 1, &part).is_err());
        part.truncate(8);
        part[4..8].copy_from_slice(&u32::try_from(PART_BYTES).unwrap().to_le_bytes());
        part.push(8);
        append_part(&mut bytes, PART_BYTES + 1, &part).unwrap();
        assert_eq!(bytes.len(), PART_BYTES + 1);
        assert!(append_part(&mut bytes, PART_BYTES + 1, &part).is_err());
    }
}

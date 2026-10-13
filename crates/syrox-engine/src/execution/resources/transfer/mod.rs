use super::{
    MAX_SERVICE_FDS, MAX_SPEC_BYTES, Result, ServiceSpec, ServiceSpecError, require,
    validate_retention,
};
use crate::execution::transport::{PacketChannel, Peer, budget};
use crate::{cancellation::Cancellation, store::ContentDigest};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::os::fd::AsFd as _;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::time::Instant;

mod receiver;
pub(crate) use receiver::ResourceReceiver;

const OFFER: &[u8] = b"syrox-service-offer-v1\n";
const CHUNK: &[u8] = b"syrox-service-chunk-v1\n";
const RESOURCES: &[u8] = b"syrox-service-resources-v1";
const CHUNK_BYTES: usize = crate::execution::transport::MAX_BYTES - CHUNK.len() - 4;

#[derive(Debug)]
pub(crate) struct ReceivedResources {
    pub spec: ServiceSpec,
    pub descriptors: Vec<OwnedFd>,
    pub retention: OwnedFd,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    pin: String,
    bytes: usize,
    chunks: usize,
    slots: usize,
}
impl Header {
    fn parse(packet: &[u8], expected: ContentDigest) -> Result<Self> {
        let bytes = packet
            .strip_prefix(OFFER)
            .ok_or(ServiceSpecError::Invalid(
                "invalid service offer version",
            ))?;
        let header: Self = serde_json::from_slice(bytes)?;
        require(
            header.bytes > 0
                && header.bytes <= MAX_SPEC_BYTES
                && header.slots > 0
                && header.slots <= MAX_SERVICE_FDS,
            "invalid service offer size or descriptors",
        )?;
        require(
            header.chunks == header.bytes.div_ceil(CHUNK_BYTES),
            "invalid service chunk count",
        )?;
        require(
            header.pin == expected.to_string(),
            "service offer differs from independently expected pin",
        )?;
        require(
            serde_json::to_vec(&header)? == bytes,
            "noncanonical service offer",
        )?;
        Ok(header)
    }
    fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = OFFER.to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        Ok(bytes)
    }
}

pub(crate) fn send_resources(
    channel: &PacketChannel,
    spec: &ServiceSpec,
    descriptors: &[BorrowedFd<'_>],
    retention: BorrowedFd<'_>,
    deadline: Instant,
    cancellation: &Cancellation,
) -> Result<()> {
    budget(deadline, cancellation)?;
    let bytes = spec.canonical_bytes()?;
    spec.validate_descriptors(descriptors)?;
    validate_retention(retention)?;
    budget(deadline, cancellation)?;
    let header = Header {
        pin: ContentDigest::sha256(&bytes).to_string(),
        bytes: bytes.len(),
        chunks: bytes.len().div_ceil(CHUNK_BYTES),
        slots: descriptors.len(),
    };
    channel.send(&header.encode()?, &[], deadline, cancellation)?;
    for (index, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
        channel.send(
            &encode_chunk(index, chunk),
            &[],
            deadline,
            cancellation,
        )?;
    }
    let mut resources = descriptors.to_vec();
    resources.push(retention);
    channel.send(RESOURCES, &resources, deadline, cancellation)?;
    Ok(())
}
pub(crate) fn receive_resources(
    channel: &PacketChannel,
    peer: Peer,
    expected_command: ContentDigest,
    deadline: Instant,
    cancellation: &Cancellation,
) -> Result<ReceivedResources> {
    let mut receiver = ResourceReceiver::new(expected_command);
    loop {
        budget(deadline, cancellation)?;
        let packet = channel.receive(
            peer,
            receiver.expected_fds()?,
            deadline,
            cancellation,
        )?;
        if let Some(resources) = receiver.push(packet)? {
            budget(deadline, cancellation)?;
            return Ok(resources);
        }
    }
}

fn encode_chunk(index: usize, bytes: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(CHUNK.len() + 4 + bytes.len());
    packet.extend(CHUNK);
    packet.extend(
        u32::try_from(index)
            .expect("8MiB body chunk index bound")
            .to_le_bytes(),
    );
    packet.extend(bytes);
    packet
}
fn decode_chunk(packet: &[u8], index: usize, length: usize) -> Result<&[u8]> {
    let frame = packet
        .strip_prefix(CHUNK)
        .ok_or(ServiceSpecError::Invalid(
            "invalid service chunk version",
        ))?;
    require(
        frame.len() == 4 + length,
        "invalid service chunk size",
    )?;
    let observed = u32::from_le_bytes(
        frame[..4]
            .try_into()
            .expect("checked prefix length"),
    );
    require(
        usize::try_from(observed).ok() == Some(index),
        "service chunks out of order or duplicated",
    )?;
    Ok(&frame[4..])
}

#[cfg(test)]
mod tests;

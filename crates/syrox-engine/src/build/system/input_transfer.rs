//! One-shot, credential-checked input transfer before worker namespace entry.
//!
//! Acknowledgement covers input validation/retention only, not FDSTORE, a build
//! journal transition, an execution gate, namespace health or process settlement.

use super::{BuildError, SystemBuildAction, SystemBuildInputResources};
use crate::{
    cancellation::Cancellation,
    execution::transport::{PacketChannel, Peer},
    platform::linux::fd,
    store::ContentDigest,
};
use std::{os::fd::OwnedFd, time::Instant};

const READY: &[u8] = b"syrox-system-input-ready-v1\n";
const MANIFEST: &[u8] = b"syrox-system-input-manifest-v1\n";
const BATCH: &[u8] = b"syrox-system-input-batch-v1\n";
const ACCEPTED: &[u8] = b"syrox-system-input-accepted-v1\n";
const FRAGMENT_BYTES: usize = 1024;
const BATCH_FDS: usize = 64;

/// Expected kernel message credentials, selected independently from a received
/// packet. The caller must bind PID/image/manager identity to its own session.
#[derive(Clone, Copy, Debug)]
pub struct SystemBuildInputPeer {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// A connected local seqpacket and one fresh nonzero session nonce, consumed after a
/// single transfer. Neither socket ownership nor the nonce authenticates a PID's
/// executable, manager invocation or authority to execute the selected action.
#[derive(Debug)]
pub struct SystemBuildInputTransfer {
    channel: PacketChannel,
    peer: Peer,
    nonce: [u8; 32],
}

impl SystemBuildInputTransfer {
    pub fn new(
        socket: OwnedFd,
        expected_peer: SystemBuildInputPeer,
        nonce: [u8; 32],
    ) -> Result<Self, BuildError> {
        if expected_peer.pid <= 1
            || expected_peer.uid == 0
            || nonce == [0; 32]
            || fd::real_uid() != fd::effective_uid()
            || fd::real_gid() != fd::effective_gid()
            || expected_peer.uid != fd::effective_uid()
            || expected_peer.gid != fd::effective_gid()
        {
            return Err(BuildError::InvalidRequest);
        }
        Ok(Self {
            channel: PacketChannel::from_owned(socket)?,
            peer: Peer {
                pid: expected_peer.pid,
                uid: expected_peer.uid,
                gid: expected_peer.gid,
            },
            nonce,
        })
    }

    /// Retain the sender until the authenticated recipient acknowledges complete
    /// input validation and acquisition of the independent retention description.
    /// Failure never authorizes execution or automatic replay on this channel.
    pub fn send(
        self,
        resources: &SystemBuildInputResources,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        check(cancellation, deadline)?;
        let ready = ready(
            self.nonce,
            resources.action_digest(),
            resources.manifest_digest(),
            resources.reserved_descriptors(),
        );
        let packet = self
            .channel
            .receive(self.peer, 0, deadline, cancellation)
            .map_err(|e| io_error(e, cancellation, deadline))?;
        if packet.bytes != ready {
            return Err(BuildError::InputChanged);
        }
        resources.revalidate(cancellation)?;
        check(cancellation, deadline)?;
        let binding = ContentDigest::sha256(&ready);
        let total =
            u32::try_from(resources.manifest().len()).map_err(|_| BuildError::InvalidRequest)?;
        for (index, bytes) in resources
            .manifest()
            .chunks(FRAGMENT_BYTES)
            .enumerate()
        {
            let offset =
                u32::try_from(index * FRAGMENT_BYTES).map_err(|_| BuildError::InvalidRequest)?;
            let mut packet = header(MANIFEST, binding, total, offset);
            packet.extend_from_slice(bytes);
            self.channel
                .send(&packet, &[], deadline, cancellation)
                .map_err(|e| io_error(e, cancellation, deadline))?;
        }
        let total =
            u32::try_from(resources.descriptors().len()).map_err(|_| BuildError::InvalidRequest)?;
        for (index, descriptors) in resources
            .descriptors()
            .chunks(BATCH_FDS)
            .enumerate()
        {
            let offset =
                u32::try_from(index * BATCH_FDS).map_err(|_| BuildError::InvalidRequest)?;
            let mut packet = header(BATCH, binding, total, offset);
            packet.extend_from_slice(
                &u32::try_from(descriptors.len())
                    .map_err(|_| BuildError::InvalidRequest)?
                    .to_le_bytes(),
            );
            let fds = descriptors
                .iter()
                .map(std::os::fd::AsFd::as_fd)
                .collect::<Vec<_>>();
            self.channel
                .send(&packet, &fds, deadline, cancellation)
                .map_err(|e| io_error(e, cancellation, deadline))?;
        }
        let packet = self
            .channel
            .receive(self.peer, 0, deadline, cancellation)
            .map_err(|e| io_error(e, cancellation, deadline))?;
        if packet.bytes != header(ACCEPTED, binding, total, 0) {
            return Err(BuildError::InputChanged);
        }
        check(cancellation, deadline)
    }

    /// The expected action/digest/reserve are independent coordinator evidence,
    /// never values copied from the incoming offer. No descriptors are received
    /// before the complete manifest passes that binding and aggregate FD budget.
    pub fn receive(
        self,
        action: &SystemBuildAction,
        expected_manifest: ContentDigest,
        reserved: u32,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<SystemBuildInputResources, BuildError> {
        check(cancellation, deadline)?;
        let ready = ready(
            self.nonce,
            action.digest(),
            expected_manifest,
            reserved,
        );
        let binding = ContentDigest::sha256(&ready);
        self.channel
            .send(&ready, &[], deadline, cancellation)
            .map_err(|e| io_error(e, cancellation, deadline))?;
        let mut bytes = Vec::new();
        let mut total = None;
        loop {
            let packet = self
                .channel
                .receive(self.peer, 0, deadline, cancellation)
                .map_err(|e| io_error(e, cancellation, deadline))?;
            let fixed = MANIFEST.len() + 32 + 8;
            if packet.bytes.len() < fixed {
                return Err(BuildError::InvalidRequest);
            }
            let length = u32::from_le_bytes(
                packet.bytes[fixed - 8..fixed - 4]
                    .try_into()
                    .expect("checked header"),
            );
            let offset = u32::try_from(bytes.len()).map_err(|_| BuildError::InvalidRequest)?;
            if length == 0
                || usize::try_from(length).map_err(|_| BuildError::InvalidRequest)?
                    > SystemBuildInputResources::MAX_MANIFEST_BYTES
                || total.is_some_and(|before| before != length)
                || offset >= length
                || packet.bytes[..fixed] != header(MANIFEST, binding, length, offset)
            {
                return Err(BuildError::InputChanged);
            }
            let count = usize::try_from(length - offset)
                .map_err(|_| BuildError::InvalidRequest)?
                .min(FRAGMENT_BYTES);
            if packet.bytes.len() != fixed + count {
                return Err(BuildError::InvalidRequest);
            }
            total = Some(length);
            bytes.extend_from_slice(&packet.bytes[fixed..]);
            if bytes.len() == usize::try_from(length).map_err(|_| BuildError::InvalidRequest)? {
                break;
            }
        }
        let slots = SystemBuildInputResources::expected_descriptor_count(
            action,
            expected_manifest,
            &bytes,
            reserved,
        )?;
        let mut descriptors = Vec::new();
        while descriptors.len() < usize::try_from(slots).map_err(|_| BuildError::InvalidRequest)? {
            let offset =
                u32::try_from(descriptors.len()).map_err(|_| BuildError::InvalidRequest)?;
            let count = usize::try_from(slots - offset)
                .map_err(|_| BuildError::InvalidRequest)?
                .min(BATCH_FDS);
            let mut expected = header(BATCH, binding, slots, offset);
            expected.extend_from_slice(
                &u32::try_from(count)
                    .map_err(|_| BuildError::InvalidRequest)?
                    .to_le_bytes(),
            );
            let packet = self
                .channel
                .receive(self.peer, count, deadline, cancellation)
                .map_err(|e| io_error(e, cancellation, deadline))?;
            if packet.bytes != expected {
                return Err(BuildError::InputChanged);
            }
            descriptors.extend(packet.descriptors);
        }
        let resources = SystemBuildInputResources::from_received(
            action,
            expected_manifest,
            &bytes,
            reserved,
            descriptors,
            cancellation,
        )?;
        check(cancellation, deadline)?;
        self.channel
            .send(
                &header(ACCEPTED, binding, slots, 0),
                &[],
                deadline,
                cancellation,
            )
            .map_err(|e| io_error(e, cancellation, deadline))?;
        Ok(resources)
    }
}

fn ready(
    nonce: [u8; 32],
    action: ContentDigest,
    manifest: ContentDigest,
    reserved: u32,
) -> Vec<u8> {
    let mut bytes = READY.to_vec();
    bytes.extend(nonce);
    bytes.extend(action.as_bytes());
    bytes.extend(manifest.as_bytes());
    bytes.extend(reserved.to_le_bytes());
    bytes
}

fn header(domain: &[u8], binding: ContentDigest, total: u32, offset: u32) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    bytes.extend(binding.as_bytes());
    bytes.extend(total.to_le_bytes());
    bytes.extend(offset.to_le_bytes());
    bytes
}

fn check(cancellation: &Cancellation, deadline: Instant) -> Result<(), BuildError> {
    cancellation.check()?;
    if Instant::now() >= deadline {
        return Err(BuildError::Timeout);
    }
    Ok(())
}

fn io_error(error: std::io::Error, cancellation: &Cancellation, deadline: Instant) -> BuildError {
    if cancellation.is_cancelled() {
        BuildError::Cancelled
    } else if Instant::now() >= deadline {
        BuildError::Timeout
    } else {
        BuildError::Io(error)
    }
}

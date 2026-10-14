use super::{CHUNK_BYTES, Header, RESOURCES, ReceivedResources, decode_chunk};
use crate::execution::resources::{
    Result, ServiceSpec, ServiceSpecError, require, validate_retention,
};
use crate::execution::transport::{MAX_BYTES, Packet};
use crate::store::ContentDigest;
use std::os::fd::AsFd as _;

enum Stage {
    Offer,
    Body {
        header: Header,
        bytes: Vec<u8>,
        index: usize,
    },
    Resources {
        spec: ServiceSpec,
        slots: usize,
    },
}

pub(crate) struct ResourceReceiver {
    expected: ContentDigest,
    stage: Option<Stage>,
}

impl ResourceReceiver {
    pub(crate) fn new(expected: ContentDigest) -> Self {
        Self {
            expected,
            stage: Some(Stage::Offer),
        }
    }

    /// Pass this exact count to the credential-checking `PacketChannel` receive.
    /// A terminal or failed collector cannot accept another packet.
    pub(crate) fn expected_fds(&self) -> Result<usize> {
        match &self.stage {
            Some(
                Stage::Offer
                | Stage::Body {
                    ..
                },
            ) => Ok(0),
            Some(Stage::Resources {
                slots,
                ..
            }) => Ok(slots + 1),
            None => Err(ServiceSpecError::Invalid(
                "resource receiver is terminal",
            )),
        }
    }

    /// The caller authenticates packet credentials and checks cancellation and
    /// deadlines before every step. Any error permanently consumes this state;
    /// callers must abandon the connection rather than retry a partial handoff.
    pub(crate) fn push(&mut self, mut packet: Packet) -> Result<Option<ReceivedResources>> {
        let expected_fds = self.expected_fds()?;
        let stage = self.stage.take().expect("validated active stage");
        require(
            packet.bytes.len() <= MAX_BYTES,
            "oversized resource packet",
        )?;
        require(
            packet.descriptors.len() == expected_fds,
            "resource descriptor count mismatch",
        )?;
        let next = match stage {
            Stage::Offer => {
                let header = Header::parse(&packet.bytes, self.expected)?;
                let bytes = Vec::with_capacity(header.bytes);
                Stage::Body {
                    header,
                    bytes,
                    index: 0,
                }
            }
            Stage::Body {
                header,
                mut bytes,
                index,
            } => {
                let length = (header.bytes - bytes.len()).min(CHUNK_BYTES);
                bytes.extend(decode_chunk(&packet.bytes, index, length)?);
                if index + 1 == header.chunks {
                    let spec = ServiceSpec::decode(&bytes, self.expected)?;
                    require(
                        spec.mounts.len() == header.slots,
                        "service body descriptor count differs from offer",
                    )?;
                    Stage::Resources {
                        spec,
                        slots: header.slots,
                    }
                } else {
                    Stage::Body {
                        header,
                        bytes,
                        index: index + 1,
                    }
                }
            }
            Stage::Resources {
                spec,
                ..
            } => {
                require(
                    packet.bytes == RESOURCES,
                    "invalid service resource handoff",
                )?;
                let retention = packet
                    .descriptors
                    .pop()
                    .ok_or(ServiceSpecError::Invalid(
                        "missing retention descriptor",
                    ))?;
                spec.validate_descriptors(
                    &packet
                        .descriptors
                        .iter()
                        .map(|fd| fd.as_fd())
                        .collect::<Vec<_>>(),
                )?;
                validate_retention(retention.as_fd())?;
                return Ok(Some(ReceivedResources {
                    spec,
                    descriptors: packet.descriptors,
                    retention,
                }));
            }
        };
        self.stage = Some(next);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    //! Direct Packet assembly tests. These deliberately do not claim `SCM_RIGHTS` or
    //! peer-credential authentication: the production caller supplies that boundary.
    use super::super::{CHUNK_BYTES, Header, RESOURCES, encode_chunk};
    use super::ResourceReceiver;
    use crate::execution::resources::{
        ServiceSpec,
        tests::{fixture, resources},
    };
    use crate::execution::transport::{MAX_BYTES, Packet};
    use crate::store::ContentDigest;
    use std::os::fd::{AsFd as _, OwnedFd};

    fn packet(bytes: Vec<u8>) -> Packet {
        Packet {
            bytes,
            descriptors: Vec::new(),
        }
    }
    fn header(spec: &ServiceSpec) -> Header {
        let length = spec.canonical_bytes().unwrap().len();
        Header {
            pin: spec.digest().unwrap().to_string(),
            bytes: length,
            chunks: length.div_ceil(CHUNK_BYTES),
            slots: spec.mounts.len(),
        }
    }
    fn chunks(spec: &ServiceSpec) -> Vec<Vec<u8>> {
        spec.canonical_bytes()
            .unwrap()
            .chunks(CHUNK_BYTES)
            .enumerate()
            .map(|(index, bytes)| encode_chunk(index, bytes))
            .collect()
    }
    fn offered(spec: &ServiceSpec) -> ResourceReceiver {
        let mut receiver = ResourceReceiver::new(spec.digest().unwrap());
        assert_eq!(receiver.expected_fds().unwrap(), 0);
        assert!(
            receiver
                .push(packet(header(spec).encode().unwrap()))
                .unwrap()
                .is_none()
        );
        receiver
    }
    fn resources_stage(spec: &ServiceSpec) -> ResourceReceiver {
        let mut receiver = offered(spec);
        for bytes in chunks(spec) {
            assert_eq!(receiver.expected_fds().unwrap(), 0);
            assert!(receiver.push(packet(bytes)).unwrap().is_none());
        }
        assert_eq!(
            receiver.expected_fds().unwrap(),
            spec.mounts.len() + 1
        );
        receiver
    }
    fn terminal(receiver: &mut ResourceReceiver) {
        assert!(receiver.expected_fds().is_err());
        assert!(receiver.push(packet(Vec::new())).is_err());
        assert!(receiver.expected_fds().is_err());
    }

    #[test]
    fn complete_multichunk_body_preserves_descriptor_identity_and_becomes_terminal() {
        let mut spec = fixture();
        spec.arguments = vec!["public literal".repeat(200); 4];
        assert!(chunks(&spec).len() > 2);
        let mut receiver = resources_stage(&spec);
        let (_directory, mut descriptors, retention) = resources();
        let identities = descriptors
            .iter()
            .map(|fd| {
                crate::platform::linux::fd::metadata(fd.as_fd())
                    .unwrap()
                    .identity()
            })
            .collect::<Vec<_>>();
        let retention_identity = crate::platform::linux::fd::metadata(retention.as_fd())
            .unwrap()
            .identity();
        descriptors.push(retention.into());
        let assembled = receiver
            .push(Packet {
                bytes: RESOURCES.to_vec(),
                descriptors,
            })
            .unwrap()
            .unwrap();
        assert_eq!(assembled.spec, spec);
        assert_eq!(
            assembled
                .descriptors
                .iter()
                .map(
                    |fd| crate::platform::linux::fd::metadata(fd.as_fd())
                        .unwrap()
                        .identity()
                )
                .collect::<Vec<_>>(),
            identities
        );
        assert_eq!(
            crate::platform::linux::fd::metadata(assembled.retention.as_fd())
                .unwrap()
                .identity(),
            retention_identity
        );
        assembled
            .spec
            .worker_request(&assembled.descriptors)
            .unwrap();
        terminal(&mut receiver);
    }

    #[test]
    fn invalid_offer_pin_size_slots_and_packet_bound_are_terminal() {
        let spec = fixture();
        let pin = spec.digest().unwrap();
        let mut wrong_pin = header(&spec);
        wrong_pin.pin = ContentDigest::sha256(b"different").to_string();
        let mut empty = header(&spec);
        empty.bytes = 0;
        let mut slots = header(&spec);
        slots.slots = 0;
        let mut oversized = header(&spec);
        oversized.bytes = crate::execution::resources::MAX_SPEC_BYTES + 1;
        oversized.chunks = oversized.bytes.div_ceil(CHUNK_BYTES);
        let mut count = header(&spec);
        count.chunks += 1;
        for bytes in [
            wrong_pin.encode().unwrap(),
            oversized.encode().unwrap(),
            empty.encode().unwrap(),
            slots.encode().unwrap(),
            count.encode().unwrap(),
            vec![0; MAX_BYTES + 1],
        ] {
            let mut receiver = ResourceReceiver::new(pin);
            assert!(receiver.push(packet(bytes)).is_err());
            terminal(&mut receiver);
        }
    }

    #[test]
    fn body_order_duplicate_truncation_and_pin_mismatch_are_terminal() {
        let mut spec = fixture();
        spec.arguments = vec!["x".repeat(4096); 3];
        let body = chunks(&spec);
        let mut receiver = offered(&spec);
        assert!(receiver.push(packet(body[1].clone())).is_err());
        terminal(&mut receiver);
        let mut receiver = offered(&spec);
        receiver.push(packet(body[0].clone())).unwrap();
        assert!(receiver.push(packet(body[0].clone())).is_err());
        terminal(&mut receiver);
        let mut receiver = offered(&spec);
        let mut short = body[0].clone();
        short.pop();
        assert!(receiver.push(packet(short)).is_err());
        terminal(&mut receiver);
        let mut receiver = offered(&spec);
        let mut changed = body.clone();
        *changed.last_mut().unwrap().last_mut().unwrap() ^= 1;
        for bytes in &changed[..changed.len() - 1] {
            receiver.push(packet(bytes.clone())).unwrap();
        }
        assert!(
            receiver
                .push(packet(changed.last().unwrap().clone()))
                .is_err()
        );
        terminal(&mut receiver);
    }

    #[test]
    fn offer_slot_mismatch_and_early_descriptors_cannot_advance() {
        let spec = fixture();
        let mut receiver = ResourceReceiver::new(spec.digest().unwrap());
        let mut offer = header(&spec);
        offer.slots += 1;
        receiver
            .push(packet(offer.encode().unwrap()))
            .unwrap();
        let body = chunks(&spec);
        for bytes in &body[..body.len() - 1] {
            assert!(
                receiver
                    .push(packet(bytes.clone()))
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            receiver
                .push(packet(body.last().unwrap().clone()))
                .is_err()
        );
        terminal(&mut receiver);
        let (_directory, mut descriptors, _retention) = resources();
        for body_stage in [false, true] {
            let mut receiver = if body_stage {
                offered(&spec)
            } else {
                ResourceReceiver::new(spec.digest().unwrap())
            };
            let bytes = if body_stage {
                chunks(&spec).remove(0)
            } else {
                header(&spec).encode().unwrap()
            };
            assert!(
                receiver
                    .push(Packet {
                        bytes,
                        descriptors: vec![descriptors.pop().unwrap()]
                    })
                    .is_err()
            );
            terminal(&mut receiver);
        }
    }

    #[test]
    fn resources_require_exact_tag_count_directory_roles_and_retention() {
        let spec = fixture();
        for case in 0..4 {
            let (_directory, mut descriptors, retention) = resources();
            let mut receiver = resources_stage(&spec);
            let bytes = if case == 0 {
                b"wrong resource frame".to_vec()
            } else {
                RESOURCES.to_vec()
            };
            match case {
                1 => {
                    descriptors.pop();
                }
                2 => descriptors[1] = descriptors[0].try_clone().unwrap(),
                3 => descriptors[0] = retention.as_fd().try_clone_to_owned().unwrap(),
                _ => {}
            }
            descriptors.push(OwnedFd::from(retention));
            assert!(
                receiver
                    .push(Packet {
                        bytes,
                        descriptors
                    })
                    .is_err()
            );
            terminal(&mut receiver);
        }
        let (_directory, mut descriptors, _retention) = resources();
        let mut receiver = resources_stage(&spec);
        descriptors.push(descriptors[0].try_clone().unwrap());
        assert!(
            receiver
                .push(Packet {
                    bytes: RESOURCES.to_vec(),
                    descriptors
                })
                .is_err()
        );
        terminal(&mut receiver);
    }
}

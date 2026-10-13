use super::BuildError;
use super::resources::{
    MAX_MANAGED_RESOURCE_SLOTS, ManagedBuildResources, validate_managed_build_resources,
    validate_managed_resource_budget,
};
use super::worker::{ManagedBuildWorkerInspection, inspect_managed_build_worker};
use crate::execution::transport::{PacketChannel, Peer};
use crate::{cancellation::Cancellation, store::ContentDigest};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::os::fd::AsFd as _;
use std::time::Instant;

const OFFER_DOMAIN: &[u8] = b"syrox-managed-build-resources-v1\n";
const BATCH_DOMAIN: &[u8] = b"syrox-managed-build-resource-batch-v1\n";
const MAX_PACKET: usize = 4096;
const MAX_MANIFEST: usize = 1024;
const BATCH_FDS: usize = 64;
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    hello: String,
    manifest: String,
    total: usize,
}
impl Offer {
    fn validate(&self, expected_hello: &[u8]) -> Result<(), BuildError> {
        if self.hello.as_bytes() != expected_hello
            || self.manifest.is_empty()
            || self.manifest.len() > MAX_MANIFEST
            || !(5..=MAX_MANAGED_RESOURCE_SLOTS).contains(&self.total)
            || self.total % 2 != 1
        {
            return Err(BuildError::InvalidRequest);
        }
        Ok(())
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    offer: String,
    total: usize,
    offset: usize,
    count: usize,
}
impl Batch {
    fn expected(offer: ContentDigest, total: usize, offset: usize) -> Result<Self, BuildError> {
        if offset >= total || total > MAX_MANAGED_RESOURCE_SLOTS {
            return Err(BuildError::InvalidRequest);
        }
        Ok(Self {
            offer: offer.to_string(),
            total,
            offset,
            count: (total - offset).min(BATCH_FDS),
        })
    }
    fn validate(&self, expected: &Self) -> Result<(), BuildError> {
        if self.offer != expected.offer
            || self.total != expected.total
            || self.offset != expected.offset
            || self.count != expected.count
        {
            return Err(BuildError::InvalidRequest);
        }
        Ok(())
    }
}
fn encode<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, BuildError> {
    super::encode_json(domain, value, MAX_PACKET)
}
fn decode<T: DeserializeOwned + Serialize>(domain: &[u8], bytes: &[u8]) -> Result<T, BuildError> {
    let value = super::decode_json(domain, bytes, MAX_PACKET)?;
    if encode(domain, &value)? != bytes {
        return Err(BuildError::InvalidRequest);
    }
    Ok(value)
}
pub(in crate::build) fn send(
    channel: &PacketChannel,
    hello: &[u8],
    resources: &ManagedBuildResources,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(), BuildError> {
    let offer = Offer {
        hello: std::str::from_utf8(hello)
            .map_err(|_| BuildError::InvalidRequest)?
            .into(),
        manifest: std::str::from_utf8(resources.manifest())
            .map_err(|_| BuildError::InvalidRequest)?
            .into(),
        total: resources.descriptors().len(),
    };
    offer.validate(hello)?;
    let bytes = encode(OFFER_DOMAIN, &offer)?;
    let pin = ContentDigest::sha256(&bytes);
    channel.send(&bytes, &[], deadline, cancellation)?;
    for (index, descriptors) in resources
        .descriptors()
        .chunks(BATCH_FDS)
        .enumerate()
    {
        let batch = Batch::expected(pin, offer.total, index * BATCH_FDS)?;
        let borrowed: Vec<_> = descriptors
            .iter()
            .map(std::os::fd::AsFd::as_fd)
            .collect();
        channel.send(
            &encode(BATCH_DOMAIN, &batch)?,
            &borrowed,
            deadline,
            cancellation,
        )?;
    }
    Ok(())
}
pub(in crate::build) fn receive(
    channel: &PacketChannel,
    peer: Peer,
    hello: &[u8],
    inspection: &ManagedBuildWorkerInspection,
    invocation: [u8; 16],
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<
    (
        ManagedBuildWorkerInspection,
        ManagedBuildResources,
    ),
    BuildError,
> {
    let packet = channel.receive(peer, 0, deadline, cancellation)?;
    // The coordinator persists Bound before Offer. Inspect after receiving it,
    // rather than racing its legitimate Awaiting -> Bound transition after Hello.
    let inspection = inspect_managed_build_worker(
        inspection.operation_path(),
        inspection.action_digest(),
        inspection.nonce(),
        cancellation,
        deadline,
    )?;
    if inspection.bound_process() != Some((invocation, std::process::id())) {
        return Err(BuildError::InvalidRequest);
    }
    let offer: Offer = decode(OFFER_DOMAIN, &packet.bytes)?;
    offer.validate(hello)?;
    let pin = ContentDigest::sha256(&packet.bytes);
    // Do not reserve the untrusted total: batch zero authenticates the Action's
    // actual profile budget before any further descriptors may accumulate.
    let mut descriptors = Vec::new();
    while descriptors.len() < offer.total {
        let expected = Batch::expected(pin, offer.total, descriptors.len())?;
        let packet = channel.receive(peer, expected.count, deadline, cancellation)?;
        decode::<Batch>(BATCH_DOMAIN, &packet.bytes)?.validate(&expected)?;
        if descriptors.is_empty()
            && validate_managed_resource_budget(
                &inspection,
                offer.manifest.as_bytes(),
                packet.descriptors[0].as_fd(),
                cancellation,
                deadline,
            )? != offer.total
        {
            return Err(BuildError::InvalidRequest);
        }
        descriptors.extend(packet.descriptors);
    }
    let resources = validate_managed_build_resources(
        &inspection,
        offer.manifest.as_bytes(),
        descriptors,
        cancellation,
        deadline,
    )?;
    Ok((inspection, resources))
}
#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> Offer {
        Offer {
            hello: "bound-hello".into(),
            manifest: "{}".into(),
            total: 5,
        }
    }
    #[test]
    fn offer_is_canonical_bounded_and_domain_separated() {
        let offer = offer();
        let encoded = encode(OFFER_DOMAIN, &offer).unwrap();
        decode::<Offer>(OFFER_DOMAIN, &encoded)
            .unwrap()
            .validate(b"bound-hello")
            .unwrap();
        assert!(decode::<Offer>(BATCH_DOMAIN, &encoded).is_err());
        let mut spaced = encoded.clone();
        spaced.push(b' ');
        assert!(decode::<Offer>(OFFER_DOMAIN, &spaced).is_err());
        assert!(decode::<Offer>(OFFER_DOMAIN, &encoded[..encoded.len() - 1]).is_err());
        let mut unknown = encoded[..encoded.len() - 1].to_vec();
        unknown.extend_from_slice(b",\"extra\":true}");
        assert!(decode::<Offer>(OFFER_DOMAIN, &unknown).is_err());
        assert!(decode::<Offer>(OFFER_DOMAIN, &vec![b'x'; MAX_PACKET + 1]).is_err());
    }
    #[test]
    fn untrusted_offer_cannot_expand_identity_manifest_or_descriptor_budget() {
        let mut value = offer();
        assert!(
            value
                .validate(b"other-operation-action-nonce-invocation")
                .is_err()
        );
        for total in [
            0,
            4,
            6,
            MAX_MANAGED_RESOURCE_SLOTS,
            MAX_MANAGED_RESOURCE_SLOTS + 1,
            usize::MAX,
        ] {
            value.total = total;
            assert!(value.validate(b"bound-hello").is_err());
        }
        value.total = MAX_MANAGED_RESOURCE_SLOTS - 1;
        value.validate(b"bound-hello").unwrap();
        value.manifest = "x".repeat(MAX_MANIFEST + 1);
        assert!(value.validate(b"bound-hello").is_err());
        value.manifest.clear();
        assert!(value.validate(b"bound-hello").is_err());
    }
    #[test]
    fn batches_reject_cross_offer_replay_skips_and_wrong_counts() {
        let pin = ContentDigest::sha256(b"first offer");
        let expected = Batch::expected(pin, 133, 64).unwrap();
        for change in 0..4 {
            let mut actual = Batch::expected(pin, 133, 64).unwrap();
            match change {
                0 => actual.offer = ContentDigest::sha256(b"other offer").to_string(),
                1 => actual.total += 2,
                2 => actual.offset = 0,
                _ => actual.count -= 1,
            }
            assert!(actual.validate(&expected).is_err());
        }
        expected.validate(&expected).unwrap();
        let last = Batch::expected(pin, 133, 128).unwrap();
        assert_eq!(last.count, 5);
        assert!(Batch::expected(pin, 133, 133).is_err());
        assert!(Batch::expected(pin, usize::MAX, 0).is_err());
    }
    #[test]
    fn batching_preserves_large_profile_capacity_without_packet_sized_input_cap() {
        let pin = ContentDigest::sha256(b"offer");
        for total in [5, 65, 133, 223, 4063] {
            let mut offset = 0;
            while offset < total {
                let batch = Batch::expected(pin, total, offset).unwrap();
                assert!((1..=64).contains(&batch.count));
                decode::<Batch>(
                    BATCH_DOMAIN,
                    &encode(BATCH_DOMAIN, &batch).unwrap(),
                )
                .unwrap()
                .validate(&batch)
                .unwrap();
                offset += batch.count;
            }
            assert_eq!(offset, total);
        }
    }
    #[test]
    fn offer_pin_covers_identity_and_resource_metadata() {
        let original = encode(OFFER_DOMAIN, &offer()).unwrap();
        let mut identity = offer();
        identity.hello.push('x');
        let mut metadata = offer();
        metadata.manifest.push(' ');
        let mut count = offer();
        count.total = 7;
        for changed in [identity, metadata, count] {
            assert_ne!(
                ContentDigest::sha256(&original),
                ContentDigest::sha256(&encode(OFFER_DOMAIN, &changed).unwrap())
            );
        }
    }
    #[test]
    fn credential_checked_transport_accepts_full_batch_and_rejects_wrong_fd_count() {
        use std::fs::File;
        use std::time::Duration;
        let (sender, receiver) = PacketChannel::pair().unwrap();
        let cancellation = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        let file = File::open("/dev/null").unwrap();
        let borrowed = vec![file.as_fd(); BATCH_FDS];
        let expected = Batch::expected(ContentDigest::sha256(b"offer"), 65, 0).unwrap();
        sender
            .send(
                &encode(BATCH_DOMAIN, &expected).unwrap(),
                &borrowed,
                deadline,
                &cancellation,
            )
            .unwrap();
        let packet = receiver
            .receive(Peer::current(), 64, deadline, &cancellation)
            .unwrap();
        assert_eq!(packet.descriptors.len(), 64);
        decode::<Batch>(BATCH_DOMAIN, &packet.bytes)
            .unwrap()
            .validate(&expected)
            .unwrap();
        sender
            .send(
                &encode(BATCH_DOMAIN, &expected).unwrap(),
                &[],
                deadline,
                &cancellation,
            )
            .unwrap();
        assert!(
            receiver
                .receive(Peer::current(), 64, deadline, &cancellation)
                .is_err()
        );
    }
}

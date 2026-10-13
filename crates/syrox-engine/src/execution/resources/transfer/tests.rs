use super::*;
use crate::execution::resources::tests::{fixture, resources};
use std::time::Duration;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
#[test]
fn offer_declares_pin_size_slots_and_exact_chunk_count() {
    let spec = fixture();
    let bytes = spec.canonical_bytes().unwrap();
    let pin = spec.digest().unwrap();
    let header = Header {
        pin: pin.to_string(),
        bytes: bytes.len(),
        slots: spec.mounts.len(),
        chunks: bytes.len().div_ceil(CHUNK_BYTES),
    };
    assert!(Header::parse(&header.encode().unwrap(), pin).is_ok());
    assert!(
        Header::parse(
            &header.encode().unwrap(),
            ContentDigest::sha256(b"wrong")
        )
        .is_err()
    );
    for invalid in [
        Header {
            bytes: MAX_SPEC_BYTES + 1,
            ..header
        },
        Header {
            slots: MAX_SERVICE_FDS + 1,
            ..Header {
                pin: pin.to_string(),
                bytes: 1,
                chunks: 1,
                slots: 1,
            }
        },
        Header {
            pin: pin.to_string(),
            bytes: CHUNK_BYTES + 1,
            chunks: 1,
            slots: 1,
        },
    ] {
        assert!(Header::parse(&invalid.encode().unwrap(), pin).is_err());
    }
}
#[test]
fn chunk_framing_rejects_reordering_duplicates_truncation_and_extra_bytes() {
    let bytes = vec![7; CHUNK_BYTES];
    let packet = encode_chunk(3, &bytes);
    assert_eq!(
        packet.len(),
        crate::execution::transport::MAX_BYTES
    );
    assert_eq!(
        decode_chunk(&packet, 3, CHUNK_BYTES).unwrap(),
        bytes
    );
    for index in [0, 2, 4] {
        assert!(decode_chunk(&packet, index, CHUNK_BYTES).is_err());
    }
    assert!(decode_chunk(&packet[..packet.len() - 1], 3, CHUNK_BYTES).is_err());
    let mut extra = packet;
    extra.push(0);
    assert!(decode_chunk(&extra, 3, CHUNK_BYTES).is_err());
}
#[test]
fn transfer_larger_than_one_packet_preserves_pin_and_descriptor_roles() {
    let (_temp, descriptors, retention) = resources();
    let mut spec = fixture();
    spec.arguments = vec!["x".repeat(4096); 8];
    let pin = spec.digest().unwrap();
    let (sender, receiver) = PacketChannel::pair().unwrap();
    let cancellation = Cancellation::default();
    let bundle = std::thread::scope(|scope| {
        let sending = scope.spawn(|| {
            send_resources(
                &sender,
                &spec,
                &descriptors
                    .iter()
                    .map(std::os::fd::AsFd::as_fd)
                    .collect::<Vec<_>>(),
                retention.as_fd(),
                deadline(),
                &cancellation,
            )
        });
        let bundle = receive_resources(
            &receiver,
            Peer::current(),
            pin,
            deadline(),
            &cancellation,
        )
        .unwrap();
        sending.join().unwrap().unwrap();
        bundle
    });
    assert_eq!(bundle.spec, spec);
    assert_eq!(bundle.descriptors.len(), 2);
    bundle
        .spec
        .worker_request(&bundle.descriptors)
        .unwrap();
    assert!(
        crate::platform::linux::fd::metadata(bundle.retention.as_fd())
            .unwrap()
            .is_trusted_regular()
    );
}
#[test]
fn expired_or_cancelled_transfer_never_publishes_partial_resources() {
    let (_temp, descriptors, retention) = resources();
    let spec = fixture();
    let (sender, receiver) = PacketChannel::pair().unwrap();
    let cancellation = Cancellation::default();
    cancellation.cancel();
    assert!(
        send_resources(
            &sender,
            &spec,
            &descriptors
                .iter()
                .map(std::os::fd::AsFd::as_fd)
                .collect::<Vec<_>>(),
            retention.as_fd(),
            deadline(),
            &cancellation
        )
        .is_err()
    );
    let idle = Cancellation::default();
    assert!(
        matches!(receive_resources(&receiver,Peer::current(),spec.digest().unwrap(),Instant::now(),&idle),Err(ServiceSpecError::Io(error)) if error.kind()==std::io::ErrorKind::TimedOut)
    );
}

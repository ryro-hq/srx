use super::*;
use std::time::Duration;
fn message() -> NamespaceProcessed {
    NamespaceProcessed::expected(b"authenticated hello", b"resource manifest").unwrap()
}
#[test]
fn namespace_claim_binds_context_and_rejects_other_protocol_phases() {
    let expected = message();
    let bytes = expected.encode().unwrap();
    NamespaceProcessed::verify(&bytes, &expected).unwrap();
    for changed in [
        NamespaceProcessed::expected(b"other hello", b"resource manifest").unwrap(),
        NamespaceProcessed::expected(b"authenticated hello", b"other manifest").unwrap(),
        NamespaceProcessed {
            name: RETENTION_NAME.into(),
            ..message()
        },
    ] {
        assert!(NamespaceProcessed::verify(&changed.encode().unwrap(), &expected).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(b' ');
    assert!(NamespaceProcessed::verify(&extra, &expected).is_err());
    assert!(NamespaceProcessed::verify(&bytes[1..], &expected).is_err());
    assert!(NamespaceProcessed::verify(&vec![0; 2049], &expected).is_err());
}
fn entry(name: &str, inode: u64) -> FdStoreEntry {
    FdStoreEntry {
        name: name.into(),
        mode: 0o100_400,
        device_major: 0,
        device_minor: 3,
        inode,
        special_major: 0,
        special_minor: 0,
        flags: 0,
    }
}
#[test]
fn both_manager_entries_are_required_and_order_is_irrelevant() {
    let lease = entry(RETENTION_NAME, 10);
    let namespace = entry(NAME, 20);
    verify_pair(
        &[
            entry(NAME, 20),
            entry(RETENTION_NAME, 10),
        ],
        &lease,
        &namespace,
    )
    .unwrap();
    for entries in [
        vec![entry(RETENTION_NAME, 10)],
        vec![
            entry(RETENTION_NAME, 10),
            entry(RETENTION_NAME, 10),
        ],
        vec![
            entry(RETENTION_NAME, 10),
            entry(NAME, 21),
        ],
        vec![
            entry(RETENTION_NAME, 10),
            entry(NAME, 20),
            entry("extra", 30),
        ],
    ] {
        assert!(verify_pair(&entries, &lease, &namespace).is_err());
    }
    let mut altered = entry(NAME, 20);
    altered.flags = 1;
    assert!(
        verify_pair(
            &[entry(RETENTION_NAME, 10), altered],
            &lease,
            &namespace
        )
        .is_err()
    );
}
#[test]
fn namespace_phase_requires_three_ordered_descriptors() {
    use crate::execution::transport::{PacketChannel, Peer};
    use std::os::fd::AsFd as _;
    let (sender, receiver) = PacketChannel::pair().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let cancel = Cancellation::default();
    let bytes = message().encode().unwrap();
    sender
        .send(&bytes, &[], deadline, &cancel)
        .unwrap();
    assert!(
        receiver
            .receive(Peer::current(), 3, deadline, &cancel)
            .is_err()
    );
    let (sender, receiver) = PacketChannel::pair().unwrap();
    let file = std::fs::File::open("/dev/null").unwrap();
    sender
        .send(
            &bytes,
            &[file.as_fd(), file.as_fd(), file.as_fd()],
            deadline,
            &cancel,
        )
        .unwrap();
    let packet = receiver
        .receive(Peer::current(), 3, deadline, &cancel)
        .unwrap();
    NamespaceProcessed::verify(&packet.bytes, &message()).unwrap();
    assert_eq!(packet.descriptors.len(), 3);
    // Transport count is not admission: pidfd and pipe verifiers reject these FDs.
}

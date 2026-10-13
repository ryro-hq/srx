use super::{ContentDigest, ExecutionId, GuardianIdentity, SessionId, SettlementClaim};

fn claim() -> SettlementClaim {
    SettlementClaim::new(
        &SessionId::parse(&"1".repeat(32)).unwrap(),
        &ExecutionId::parse(&"2".repeat(32)).unwrap(),
        ContentDigest::sha256(b"index"),
        ContentDigest::sha256(b"hold"),
        GuardianIdentity {
            pid: 42,
            uid: 1000,
            gid: 1000,
            device: 1,
            inode: 7,
        },
    )
    .unwrap()
}
#[test]
fn comparison_record_is_canonical_bounded_and_rejects_incomplete_settlement() {
    let expected = claim();
    let bytes = expected.encode().unwrap();
    assert!(SettlementClaim::decode(&bytes).unwrap() == expected);
    assert!(SettlementClaim::decode(&bytes[..bytes.len() - 1]).is_err());
    assert!(SettlementClaim::decode(&vec![b' '; 2049]).is_err());
    for mutation in ["pending", "eof", "root-exited"] {
        let mut forged = claim();
        forged.descendants = mutation.into();
        assert!(forged.encode().is_err());
    }
}
#[test]
fn execution_index_retention_and_guardian_are_all_part_of_comparison() {
    let expected = claim();
    let mut changes = Vec::new();
    let mut other = claim();
    other.execution = "3".repeat(32);
    changes.push(other);
    let mut other = claim();
    other.session = "3".repeat(32);
    changes.push(other);
    let mut other = claim();
    other.index = ContentDigest::sha256(b"other").to_string();
    changes.push(other);
    let mut other = claim();
    other.retention = ContentDigest::sha256(b"other").to_string();
    changes.push(other);
    let mut other = claim();
    other.guardian.inode += 1;
    changes.push(other);
    for other in changes {
        assert!(SettlementClaim::decode(&other.encode().unwrap()).unwrap() != expected);
    }
    let mut replay = claim();
    replay.sequence = 0;
    assert!(replay.encode().is_err());
}

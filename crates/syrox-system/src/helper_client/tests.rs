use super::*;
use crate::{
    descriptor::{self, sealed},
    helper_protocol::Request,
};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::time::Duration;

#[test]
fn root_authentication_uses_actual_kernel_peer_and_transport() {
    let (server, _peer) = descriptor::seqpacket_pair().unwrap();
    // SAFETY: credential observations only; the ordinary test runner has no root authority.
    let expected = unsafe { libc::geteuid() == 0 && libc::getegid() == 0 };
    assert_eq!(
        connection::authenticate(&File::from(server)).is_ok(),
        expected
    );
    let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let descriptor: OwnedFd = stream.into();
    assert!(connection::authenticate(&File::from(descriptor)).is_err());
}

#[test]
fn cancellation_and_unprotected_endpoints_precede_connection_effects() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("socket");
    std::fs::write(&path, b"preserved").unwrap();
    let before = std::fs::metadata(&path).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    let error = HelperClient::connect(
        &path,
        || Err(io::ErrorKind::Interrupted.into()),
        deadline,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(HelperClient::connect(&path, || Ok(()), deadline).is_err());
    assert!(HelperClient::connect(Path::new("relative"), || Ok(()), deadline).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"preserved");
    assert_eq!(
        std::fs::metadata(&path).unwrap().ino(),
        before.ino()
    );
    assert_eq!(
        std::fs::read_dir(temporary.path())
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn canonical_requests_and_receipts_reject_foreign_or_unsupported_operations() {
    let id = "ab".repeat(16);
    let request = Request::Inspect {
        version: 1,
        id: id.clone(),
    };
    let mut value = serde_json::to_value(request).unwrap();
    assert_eq!(value["operation"], "inspect_scratch");
    value["shell"] = serde_json::Value::from("unaccepted");
    assert!(serde_json::from_value::<Request>(value).is_err());
    for bad in [
        "",
        "00",
        &"A".repeat(32),
        &"g".repeat(32),
        "../../selected",
    ] {
        assert!(validate_id(bad).is_err());
    }
    assert!(validate_id(&id).is_ok());
    assert!(validate_hash(&"01".repeat(32)).is_ok());
    assert!(validate_hash(&"F".repeat(64)).is_err());
    let receipt = serde_json::json!({ "version": 1, "state": "released", "details": { "id": id } });
    assert!(record(&receipt, "released", &id).is_ok());
    assert!(record(&receipt, "reconciled", &id).is_err());
    assert!(record(&receipt, "released", &"cd".repeat(16)).is_err());
    let mut future = receipt;
    future["version"] = serde_json::Value::from(2);
    assert!(record(&future, "released", &id).is_err());
}

#[test]
fn byte_snapshots_preserve_the_existing_sealed_file_contract_and_bound() {
    use std::io::Read as _;
    use std::os::fd::AsFd as _;
    let bytes = vec![0xa5; 65_536];
    let mut file = sealed::snapshot_bytes(&bytes, || Ok(())).unwrap();
    sealed::validate_secret(file.as_fd()).unwrap();
    let mut read = Vec::new();
    file.read_to_end(&mut read).unwrap();
    assert_eq!(read, bytes);
    assert!(sealed::snapshot_bytes(&vec![0; 65_537], || Ok(())).is_err());
    assert_eq!(
        sealed::snapshot_bytes(b"", || Err(io::ErrorKind::Interrupted.into()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
}

use super::*;
use std::{
    io::{Read as _, Write as _},
    os::unix::fs::MetadataExt as _,
};

#[test]
fn private_snapshots_are_readonly_exclusive_and_reject_changes_under_the_selected_pin() {
    let cancellation = Cancellation::default();
    for mode in [0o400, 0o500] {
        let directory = tempfile::tempdir().unwrap();
        let mut file = snapshot::bytes(
            directory.path(),
            "worker",
            b"pinned build bytes",
            mode,
            &cancellation,
        )
        .unwrap();
        assert_eq!(file.metadata().unwrap().mode() & 0o7777, mode);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"pinned build bytes");
        assert!(file.write_all(b"change").is_err());
        assert!(file.set_len(0).is_err());
        assert!(
            snapshot::bytes(
                directory.path(),
                "worker",
                b"replacement",
                mode,
                &cancellation
            )
            .is_err()
        );
        let fd = file.into();
        snapshot::verify(
            &fd,
            ContentDigest::sha256(b"pinned build bytes"),
            1024,
            &cancellation,
        )
        .unwrap();
        assert!(matches!(
            snapshot::verify(
                &fd,
                ContentDigest::sha256(b"different"),
                1024,
                &cancellation
            ),
            Err(BuildError::InputChanged)
        ));
    }
    let cancelled = Cancellation::default();
    cancelled.cancel();
    let directory = tempfile::tempdir().unwrap();
    assert!(matches!(
        snapshot::bytes(
            directory.path(),
            "action",
            b"none",
            0o400,
            &cancelled
        ),
        Err(BuildError::Cancelled)
    ));
    assert!(matches!(
        snapshot::bytes(
            directory.path(),
            "action",
            b"none",
            0o600,
            &cancellation
        ),
        Err(BuildError::InvalidRequest)
    ));
    assert!(!directory.path().join("action").exists());
}

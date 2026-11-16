use super::*;
use std::io::{Seek as _, Write as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::time::{Duration, Instant};
use syrox_system::descriptor::{self, sealed};

fn policy() -> policy::Policy {
    // SAFETY: current credentials are observed only; no root authority is used.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    serde_json::from_value(serde_json::json!({
        "version": 1, "client_uid": uid, "client_gid": gid, "maximum_operations": 2,
        "maximum": { "memory_bytes": 134_217_728, "cpu_percent": 100, "processes": 16,
            "descriptors": 128, "scratch_bytes": 67_108_864, "files": 512, "output_bytes": 1_048_576, "duration_seconds": 120 },
        "state_directory": "/unused",
        "formatter": { "path": "/unused", "sha256": "00".repeat(32), "size_bytes": 64 },
        "checker": { "path": "/unused", "sha256": "00".repeat(32), "size_bytes": 64 }
    })).unwrap()
}

#[test]
fn workspace_root_preflight_rejects_budget_geometry_version_and_root_peer_before_state_io() {
    let mut policy = policy();
    let temporary = tempfile::tempdir().unwrap();
    // This unprivileged directory must never reach the root trust/open path.
    policy.state_directory = temporary.path().join("not-created");
    let socket = tempfile::tempfile().unwrap();
    let peer = descriptor::PeerCredentials {
        pid: 42,
        uid: 1000,
        gid: 1000,
    };
    let request = |version, budget| wire::Request::PrepareWorkspace {
        version,
        id: "ab".repeat(16),
        budget,
        layout_sha256: "cd".repeat(32),
    };
    let mut excessive = policy.maximum;
    excessive.scratch_bytes += 4096;
    let error = workspace::serve(
        &socket,
        peer,
        &request(1, excessive),
        &policy,
        [0; 32],
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("above administrator limit")
    );
    let error = workspace::serve(
        &socket,
        peer,
        &request(1, policy.maximum),
        &policy,
        [0; 32],
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("workspace output geometry")
    );
    let error = workspace::serve(
        &socket,
        peer,
        &request(2, policy.maximum),
        &policy,
        [0; 32],
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unsupported workspace request version")
    );
    let root = descriptor::PeerCredentials {
        uid: 0,
        ..peer
    };
    assert_eq!(
        workspace::serve(
            &socket,
            root,
            &request(1, policy.maximum),
            &policy,
            [0; 32]
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        std::fs::read_dir(temporary.path())
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn activation_authentication_rejects_wrong_identity_and_socket_type() {
    let (server, _client) = descriptor::seqpacket_pair().unwrap();
    let server = File::from(server);
    let mut policy = policy();
    let peer = wire::authenticate(&server, &policy).unwrap();
    assert_eq!(
        (peer.uid, peer.gid),
        (policy.client_uid, policy.client_gid)
    );
    policy.client_uid = policy.client_uid.wrapping_add(1);
    assert_eq!(
        wire::authenticate(&server, &policy)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    let (stream, _other) = std::os::unix::net::UnixStream::pair().unwrap();
    let stream: OwnedFd = stream.into();
    assert!(wire::authenticate(&File::from(stream), &policy).is_err());
}

#[test]
fn sealed_request_ignores_shared_seek_and_rejects_unknown_fields() {
    let (server, client) = descriptor::seqpacket_pair().unwrap();
    let server = File::from(server);
    let peer = wire::authenticate(&server, &policy()).unwrap();
    for (body, accepted) in [
        (
            serde_json::json!({ "operation": "release_scratch", "version": 1, "id": "ab".repeat(16), "authorization": "cd".repeat(32) }),
            true,
        ),
        (
            serde_json::json!({ "operation": "release_scratch", "version": 1, "id": "ab".repeat(16), "authorization": "cd".repeat(32), "shell": "unaccepted" }),
            false,
        ),
    ] {
        let mut source = tempfile::tempfile().unwrap();
        source
            .write_all(&serde_json::to_vec(&body).unwrap())
            .unwrap();
        source.rewind().unwrap();
        let mut message = sealed::snapshot_secret(source, 65_536, || Ok(())).unwrap();
        message.seek(io::SeekFrom::End(0)).unwrap();
        descriptor::send_fd(client.as_fd(), message.as_fd()).unwrap();
        assert_eq!(
            wire::receive(
                &server,
                peer,
                Instant::now() + Duration::from_secs(1)
            )
            .is_ok(),
            accepted
        );
    }
    let unsealed = tempfile::tempfile().unwrap();
    descriptor::send_fd(client.as_fd(), unsealed.as_fd()).unwrap();
    assert!(
        wire::receive(
            &server,
            peer,
            Instant::now() + Duration::from_secs(1)
        )
        .is_err()
    );
}

#[test]
fn journal_refuses_replay_and_partial_terminal_records() {
    let temporary = tempfile::tempdir().unwrap();
    let state = File::open(temporary.path()).unwrap();
    let mut journal = journal::Journal::create(&state, "op-test").unwrap();
    journal
        .record("authorized", serde_json::json!({}))
        .unwrap();
    assert!(session::check_state(&state, 2).is_err());
    assert!(journal::Journal::create(&state, "op-test").is_err());
    let mut partial = journal::new_file(&journal.directory, "9999-released.json").unwrap();
    partial.write_all(b"{\"version\":1").unwrap();
    partial.sync_all().unwrap();
    drop(journal);
    assert!(session::check_state(&state, 2).is_err());
    let clean = tempfile::tempdir().unwrap();
    let state = File::open(clean.path()).unwrap();
    let mut journal = journal::Journal::create(&state, "op-completed").unwrap();
    journal
        .record("authorized", serde_json::json!({}))
        .unwrap();
    journal
        .record("released", serde_json::json!({}))
        .unwrap();
    assert!(journal.released);
    session::check_state(&state, 2).unwrap();
    assert!(session::check_state(&state, 1).is_err());
}

#[test]
fn helper_policy_refuses_unprotected_paths_and_noncanonical_pins() {
    assert!(policy::trusted(Path::new("relative"), false).is_err());
    assert!(policy::trusted(Path::new("/dev/null"), false).is_err());
    assert!(policy::trusted(Path::new("/tmp/../etc"), true).is_err());
    for pin in [
        "",
        "00",
        &"a".repeat(63),
        &"A".repeat(64),
        &"z".repeat(64),
    ] {
        assert!(policy::digest(pin).is_err());
    }
    assert_eq!(
        policy::digest(&"a0".repeat(32)).unwrap(),
        [0xa0; 32]
    );
}

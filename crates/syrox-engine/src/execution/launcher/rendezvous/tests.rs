use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::time::Duration;

fn directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(
        directory.path(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    directory
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn retained_runtime_listener_preserves_node_until_explicit_cleanup() {
    let directory = directory();
    let mut retained = Listener::bind(directory.path(), "retained.sock").unwrap();
    let path = retained.path().to_owned();
    let identity = retained.node_identity().unwrap();
    retained.preserve_on_drop();
    drop(retained);
    let parent = linux_fd::open_top_directory(directory.path()).unwrap();
    let node = socket_node(
        parent.fd(),
        &CString::new("retained.sock").unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(
        linux_fd::metadata(node.as_fd())
            .unwrap()
            .identity(),
        identity
    );
    assert!(Listener::bind(directory.path(), "retained.sock").is_err());

    let mut settled = Listener::bind(directory.path(), "settled.sock").unwrap();
    let cleaned = settled.path().to_owned();
    settled.preserve_on_drop();
    settled.close().unwrap();
    drop(settled);
    assert!(!cleaned.exists());
    assert!(path.exists());
}

#[test]
fn packets_sent_before_accept_keep_credentials_and_descriptors_are_cloexec() {
    let directory = directory();
    let mut listener = Listener::bind(directory.path(), "launcher.sock").unwrap();
    let cancellation = Cancellation::default();
    let sender = PacketChannel::connect(listener.path(), deadline(), &cancellation).unwrap();
    sender
        .send(b"early request", &[], deadline(), &cancellation)
        .unwrap();
    let receiver = listener
        .accept(deadline(), &cancellation)
        .unwrap();
    assert_eq!(
        receiver.peer_credentials().unwrap(),
        Peer::current()
    );
    let packet = receiver
        .receive(Peer::current(), 0, deadline(), &cancellation)
        .unwrap();
    assert_eq!(packet.bytes, b"early request");
    assert!(packet.descriptors.is_empty());
    for fd in [
        listener.socket.as_fd(),
        sender.as_fd(),
        receiver.as_fd(),
    ] {
        // SAFETY: fcntl reads flags from borrowed live fd.
        assert_ne!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
    assert_eq!(
        fs::symlink_metadata(listener.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    listener.close().unwrap();
    assert!(!listener.path().exists());
    listener.close().unwrap();
}

#[test]
fn invalid_parents_and_names_are_rejected_before_socket_creation() {
    let directory = directory();
    for name in [
        "",
        ".",
        "..",
        "../socket",
        "a/b",
        "a\0b",
    ] {
        assert!(Listener::bind(directory.path(), name).is_err());
    }
    let alias = directory.path().join("alias");
    symlink(directory.path(), &alias).unwrap();
    assert!(Listener::bind(&alias, "socket").is_err());
    fs::set_permissions(
        directory.path(),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(Listener::bind(directory.path(), "socket").is_err());
}

#[test]
fn cleanup_refuses_replacement_inode_and_connect_refuses_symlinks_and_wrong_mode() {
    let directory = directory();
    let mut listener = Listener::bind(directory.path(), "socket").unwrap();
    let path = listener.path().to_owned();
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"replacement").unwrap();
    assert!(listener.close().is_err());
    drop(listener);
    assert_eq!(fs::read(&path).unwrap(), b"replacement");
    let listener = Listener::bind(directory.path(), "real").unwrap();
    let alias = directory.path().join("alias");
    symlink(listener.path(), &alias).unwrap();
    let cancellation = Cancellation::default();
    assert!(PacketChannel::connect(&alias, deadline(), &cancellation).is_err());
    fs::set_permissions(listener.path(), fs::Permissions::from_mode(0o666)).unwrap();
    assert!(PacketChannel::connect(listener.path(), deadline(), &cancellation).is_err());
    fs::set_permissions(listener.path(), fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn idle_accept_has_deadline_and_cancellation_and_connect_checks_budget_first() {
    let directory = directory();
    let listener = Listener::bind(directory.path(), "socket").unwrap();
    let cancellation = Cancellation::default();
    assert_eq!(
        listener
            .accept(
                Instant::now() + Duration::from_millis(10),
                &cancellation
            )
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    cancellation.cancel();
    assert!(
        listener
            .accept(deadline(), &cancellation)
            .is_err()
    );
    assert!(PacketChannel::connect(listener.path(), deadline(), &cancellation).is_err());
}

#[test]
fn saturated_accept_queue_cannot_make_connect_wait_past_deadline() {
    let directory = directory();
    let listener = Listener::bind(directory.path(), "socket").unwrap();
    let cancellation = Cancellation::default();
    let mut clients = Vec::new();
    let mut saturated = false;
    for _ in 0..32 {
        match PacketChannel::connect(
            listener.path(),
            Instant::now() + Duration::from_millis(20),
            &cancellation,
        ) {
            Ok(client) => clients.push(client),
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                saturated = true;
                break;
            }
        }
    }
    assert!(
        saturated,
        "bounded listen backlog should become full"
    );
    assert!(!clients.is_empty());
}

#[test]
fn cancellation_wakes_an_accept_already_waiting() {
    let directory = directory();
    let listener = Listener::bind(directory.path(), "socket").unwrap();
    let cancellation = Cancellation::default();
    std::thread::scope(|scope| {
        let waiting = scope.spawn(|| listener.accept(deadline(), &cancellation));
        cancellation.cancel();
        let error = waiting.join().unwrap().unwrap_err();
        assert!(crate::cancellation::is_cancellation_io(&error));
    });
}

#[test]
fn name_collision_never_clobbers_existing_entries() {
    let directory = directory();
    let path = directory.path().join("occupied");
    fs::write(&path, b"keep this file").unwrap();
    assert_eq!(
        Listener::bind(directory.path(), "occupied")
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrInUse
    );
    assert_eq!(fs::read(&path).unwrap(), b"keep this file");
}

#[test]
fn unix_address_bounds_and_nul_are_rejected_without_truncation() {
    assert!(address(Path::new(&format!("/{}", "a".repeat(106)))).is_ok());
    assert!(address(Path::new(&format!("/{}", "a".repeat(107)))).is_err());
    assert!(address(Path::new("/tmp/a\0b")).is_err());
    assert!(valid_name(&"a".repeat(65)).is_err());
}

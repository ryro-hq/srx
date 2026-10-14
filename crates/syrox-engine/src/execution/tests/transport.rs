use super::*;
use std::fs::File;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn peer_close_is_eof_but_empty_authenticated_packet_is_invalid() {
    let (sender, receiver) = PacketChannel::pair().unwrap();
    raw_packet(&sender, b"", sender.as_fd(), 0);
    let cancellation = Cancellation::default();
    assert_eq!(
        receiver
            .receive(Peer::current(), 0, deadline(), &cancellation)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    drop(sender);
    assert_eq!(
        receiver
            .receive(Peer::current(), 0, deadline(), &cancellation)
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
}

fn locked_file() -> (tempfile::TempDir, File) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("witness");
    std::fs::write(&path, b"lease witness").unwrap();
    let file = File::open(path).unwrap();
    assert!(
        crate::platform::linux::fd::flock(
            file.as_fd(),
            crate::platform::linux::fd::FlockMode::ExclusiveNonblocking
        )
        .unwrap()
    );
    (directory, file)
}

fn witness_free(directory: &tempfile::TempDir) -> bool {
    let probe = File::open(directory.path().join("witness")).unwrap();
    crate::platform::linux::fd::flock(
        probe.as_fd(),
        crate::platform::linux::fd::FlockMode::ExclusiveNonblocking,
    )
    .unwrap()
}

fn raw_packet(channel: &PacketChannel, bytes: &[u8], descriptor: BorrowedFd<'_>, count: usize) {
    assert!(count <= 253);
    let mut storage = [0_usize; 320];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: aligned buffers below hold at most Linux's 253 descriptors. The
    // kernel duplicates borrowed descriptors; original ownership is unchanged.
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        if count != 0 {
            let length = u32::try_from(count * size_of::<libc::c_int>()).unwrap();
            message.msg_control = storage.as_mut_ptr().cast();
            message.msg_controllen = libc::CMSG_SPACE(length) as _;
            let header = libc::CMSG_FIRSTHDR(&raw const message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(length) as _;
            for index in 0..count {
                libc::CMSG_DATA(header)
                    .add(index * size_of::<libc::c_int>())
                    .cast::<libc::c_int>()
                    .write_unaligned(descriptor.as_raw_fd());
            }
        }
        assert_eq!(
            libc::sendmsg(
                channel.as_fd().as_raw_fd(),
                &raw const message,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT
            ),
            isize::try_from(bytes.len()).unwrap()
        );
    }
}

#[test]
fn maximum_packet_and_descriptors_survive_sender_close_with_cloexec() {
    let (sender, receiver) = PacketChannel::pair().unwrap();
    let (directory, file) = locked_file();
    let payload = vec![b'x'; MAX_BYTES];
    sender
        .send(
            &payload,
            &vec![file.as_fd(); MAX_FDS],
            deadline(),
            &Cancellation::default(),
        )
        .unwrap();
    drop((sender, file));
    assert!(!witness_free(&directory));
    let packet = receiver
        .receive(
            Peer::current(),
            MAX_FDS,
            deadline(),
            &Cancellation::default(),
        )
        .unwrap();
    assert_eq!(packet.bytes, payload);
    assert_eq!(packet.descriptors.len(), MAX_FDS);
    for descriptor in &packet.descriptors {
        // SAFETY: queries flags of a descriptor kept alive by the packet.
        assert_ne!(
            unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
    assert!(!witness_free(&directory));
    drop(packet);
    assert!(witness_free(&directory));
}

#[test]
fn wrong_pid_uid_or_gid_rejects_and_closes_all_received_descriptors() {
    let peer = Peer::current();
    for wrong in [
        Peer {
            pid: peer.pid + 1,
            ..peer
        },
        Peer {
            uid: peer.uid.wrapping_add(1),
            ..peer
        },
        Peer {
            gid: peer.gid.wrapping_add(1),
            ..peer
        },
    ] {
        let (sender, receiver) = PacketChannel::pair().unwrap();
        let (directory, file) = locked_file();
        sender
            .send(
                b"credentials",
                &[file.as_fd()],
                deadline(),
                &Cancellation::default(),
            )
            .unwrap();
        drop((sender, file));
        assert_eq!(
            receiver
                .receive(wrong, 1, deadline(), &Cancellation::default())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(
            witness_free(&directory),
            "rejected credentials leaked rights"
        );
    }
}

#[test]
fn packet_credentials_identify_forked_sender_not_socketpair_creator() {
    let (sender, receiver) = PacketChannel::pair().unwrap();
    let bytes = b"child";
    let sender_fd = sender.as_fd().as_raw_fd();
    // SAFETY: child performs only async-signal-safe send/_exit and never runs
    // Rust allocation, assertions or destructors after fork in the test harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            let count = libc::send(
                sender_fd,
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            );
            libc::_exit(i32::from(count != 5));
        }
    }
    let mut status = 0;
    // SAFETY: pid is our unreaped child and status is writable. Keep it unreaped
    // while validating credentials; its numeric identity cannot be reused.
    let expected = Peer {
        pid: pid.cast_unsigned(),
        ..Peer::current()
    };
    let packet = receiver.receive(expected, 0, deadline(), &Cancellation::default());
    loop {
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if waited == pid {
            break;
        }
        assert_eq!(
            io::Error::last_os_error().kind(),
            io::ErrorKind::Interrupted
        );
    }
    assert_eq!(status, 0);
    assert_eq!(packet.unwrap().bytes, bytes);
    sender
        .send(
            b"parent",
            &[],
            deadline(),
            &Cancellation::default(),
        )
        .unwrap();
    assert!(
        receiver
            .receive(expected, 0, deadline(), &Cancellation::default())
            .is_err()
    );
}

#[test]
fn malformed_counts_and_truncation_release_all_installed_rights() {
    // Descriptor counts are process-wide; unrelated parallel tests must not
    // open or close descriptors between this regression's two observations.
    if crate::platform::linux::fd::retention_fork_tests::isolate_test(
        "execution::transport::tests::malformed_counts_and_truncation_release_all_installed_rights",
        "SYROX_TRANSPORT_FD_COUNT_ISOLATED",
    ) {
        return;
    }

    for (count, length, expected) in [
        (0, 1, 1),
        (1, 1, 0),
        (2, 1, 1),
        (MAX_FDS + 1, 1, MAX_FDS),
        (253, 1, MAX_FDS),
        (1, MAX_BYTES + 1, 1),
        (1, 0, 1),
    ] {
        let (sender, receiver) = PacketChannel::pair().unwrap();
        let (directory, file) = locked_file();
        raw_packet(&sender, &vec![b'x'; length], file.as_fd(), count);
        drop((sender, file));
        assert_eq!(
            receiver
                .receive(
                    Peer::current(),
                    expected,
                    deadline(),
                    &Cancellation::default()
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(
            witness_free(&directory),
            "rights leaked count={count} bytes={length}"
        );
    }
}

#[test]
fn queued_rights_close_with_unread_channel_and_invalid_receive_is_pure() {
    let (sender, receiver) = PacketChannel::pair().unwrap();
    let (directory, file) = locked_file();
    sender
        .send(
            b"queued",
            &[file.as_fd()],
            deadline(),
            &Cancellation::default(),
        )
        .unwrap();
    drop((sender, file));
    assert!(
        receiver
            .receive(
                Peer {
                    pid: 0,
                    ..Peer::current()
                },
                1,
                deadline(),
                &Cancellation::default()
            )
            .is_err()
    );
    assert!(
        receiver
            .receive(
                Peer::current(),
                MAX_FDS + 1,
                deadline(),
                &Cancellation::default()
            )
            .is_err()
    );
    assert!(!witness_free(&directory));
    drop(receiver);
    assert!(witness_free(&directory));
}

#[test]
fn cancellation_preserves_unsent_and_unreceived_packets() {
    let (sender, receiver) = PacketChannel::pair().unwrap();
    let cancelled = Cancellation::default();
    cancelled.cancel();
    let error = sender
        .send(b"not-sent", &[], deadline(), &cancelled)
        .unwrap_err();
    assert!(crate::cancellation::is_cancellation_io(&error));
    sender
        .send(
            b"retained",
            &[],
            deadline(),
            &Cancellation::default(),
        )
        .unwrap();
    let error = receiver
        .receive(Peer::current(), 0, deadline(), &cancelled)
        .unwrap_err();
    assert!(crate::cancellation::is_cancellation_io(&error));
    assert_eq!(
        receiver
            .receive(
                Peer::current(),
                0,
                deadline(),
                &Cancellation::default()
            )
            .unwrap()
            .bytes,
        b"retained"
    );
    assert_eq!(
        receiver
            .receive(
                Peer::current(),
                0,
                Instant::now(),
                &Cancellation::default()
            )
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn pending_receive_cancellation_and_peer_close_are_bounded() {
    let (sender, receiver) = PacketChannel::pair().unwrap();
    let cancellation = Cancellation::default();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(20));
            cancellation.cancel();
        });
        let error = receiver
            .receive(Peer::current(), 0, deadline(), &cancellation)
            .unwrap_err();
        assert!(crate::cancellation::is_cancellation_io(&error));
    });
    drop(sender);
    let started = Instant::now();
    assert!(
        receiver
            .receive(
                Peer::current(),
                0,
                deadline(),
                &Cancellation::default()
            )
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn outgoing_limits_do_not_enqueue_partial_packets() {
    let (sender, receiver) = PacketChannel::pair().unwrap();
    let file = tempfile::tempfile().unwrap();
    for (bytes, count) in [
        (vec![], 0),
        (vec![0; MAX_BYTES + 1], 0),
        (vec![0], MAX_FDS + 1),
    ] {
        assert!(
            sender
                .send(
                    &bytes,
                    &vec![file.as_fd(); count],
                    deadline(),
                    &Cancellation::default()
                )
                .is_err()
        );
    }
    sender
        .send(b"only", &[], deadline(), &Cancellation::default())
        .unwrap();
    assert_eq!(
        receiver
            .receive(
                Peer::current(),
                0,
                deadline(),
                &Cancellation::default()
            )
            .unwrap()
            .bytes,
        b"only"
    );
}

fn fill_send_queue(sender: &PacketChannel, bytes: &[u8]) -> usize {
    for sent in 0..4096 {
        // SAFETY: buffer is live; nonblocking send only fills our private socket.
        let count = unsafe {
            libc::send(
                sender.as_fd().as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if count < 0 {
            assert_eq!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::WouldBlock
            );
            assert!(sent > 0);
            return sent;
        }
        assert_eq!(usize::try_from(count).unwrap(), bytes.len());
    }
    panic!("could not saturate bounded private socket queue");
}

#[test]
fn full_send_queue_obeys_deadline_and_cancellation() {
    let (sender, _receiver) = PacketChannel::pair().unwrap();
    let bytes = [b'x'; MAX_BYTES];
    fill_send_queue(&sender, &bytes);
    assert_eq!(
        sender
            .send(
                &bytes,
                &[],
                Instant::now() + Duration::from_millis(20),
                &Cancellation::default()
            )
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    let cancellation = Cancellation::default();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(20));
            cancellation.cancel();
        });
        assert!(crate::cancellation::is_cancellation_io(
            &sender
                .send(&bytes, &[], deadline(), &cancellation)
                .unwrap_err()
        ));
    });
}

#[test]
fn imported_descriptors_reject_non_socket_and_stream_transport() {
    assert!(PacketChannel::from_owned(tempfile::tempfile().unwrap().into()).is_err());
    let (stream, _other) = UnixStream::pair().unwrap();
    assert!(PacketChannel::from_owned(stream.into()).is_err());
    // SAFETY: successful socket returns a new descriptor taken exactly once.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
        )
    };
    assert!(raw >= 0);
    let unconnected = unsafe { OwnedFd::from_raw_fd(raw) };
    assert!(PacketChannel::from_owned(unconnected).is_err());

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("listener");
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: bounded local pathname is copied into zeroed sockaddr_un storage;
    // this is a private listening socket, never an ambient service endpoint.
    unsafe {
        let raw = libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
        );
        assert!(raw >= 0);
        let listener = OwnedFd::from_raw_fd(raw);
        let mut address: libc::sockaddr_un = std::mem::zeroed();
        address.sun_family = libc::sa_family_t::try_from(libc::AF_UNIX).unwrap();
        assert!(bytes.len() < address.sun_path.len());
        for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
            *target = libc::c_char::from_ne_bytes([*byte]);
        }
        let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
        assert_eq!(
            libc::bind(
                raw,
                (&raw const address).cast(),
                libc::socklen_t::try_from(length).unwrap()
            ),
            0
        );
        assert_eq!(libc::listen(raw, 1), 0);
        assert!(PacketChannel::from_owned(listener).is_err());
    }
}

#[test]
fn imported_connected_channel_installs_cloexec_without_changing_shared_status_flags() {
    let (channel, _other) = PacketChannel::pair().unwrap();
    let PacketChannel(fd) = channel;
    // SAFETY: fd stays owned and open while its descriptor flags are changed.
    let flags = unsafe {
        assert_eq!(libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0), 0);
        libc::fcntl(fd.as_raw_fd(), libc::F_GETFL)
    };
    let channel = PacketChannel::from_owned(fd).unwrap();
    unsafe {
        assert_ne!(
            libc::fcntl(channel.as_fd().as_raw_fd(), libc::F_GETFD) & libc::FD_CLOEXEC,
            0
        );
        assert_eq!(
            libc::fcntl(channel.as_fd().as_raw_fd(), libc::F_GETFL),
            flags
        );
    }
}

#[test]
fn queued_and_received_process_lease_survives_coordinator_drop() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::store::Store::initialize(directory.path()).unwrap();
    let coordinator = store.operation().unwrap();
    let interest = coordinator.retain_objects(&[], &[]).unwrap();
    let process = interest.process_retention().unwrap();
    let (sender, receiver) = PacketChannel::pair().unwrap();
    sender
        .send(
            b"lease",
            &[process.as_fd()],
            deadline(),
            &Cancellation::default(),
        )
        .unwrap();
    drop((sender, process, coordinator, interest));
    assert_eq!(
        store
            .maintenance()
            .unwrap()
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                ..crate::store::GcRequest::default()
            })
            .unwrap()
            .removed_interests,
        0
    );
    let packet = receiver
        .receive(
            Peer::current(),
            1,
            deadline(),
            &Cancellation::default(),
        )
        .unwrap();
    assert_eq!(
        store
            .maintenance()
            .unwrap()
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                ..crate::store::GcRequest::default()
            })
            .unwrap()
            .removed_interests,
        0
    );
    drop(packet);
    assert_eq!(
        store
            .maintenance()
            .unwrap()
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                ..crate::store::GcRequest::default()
            })
            .unwrap()
            .removed_interests,
        1
    );
}

#[test]
fn nonblocking_receive_is_empty_and_authenticates_each_exact_credential() {
    let (sender, receiver) = PacketChannel::pair().unwrap();
    let peer = Peer::current();
    assert!(receiver.try_receive(peer, 0).unwrap().is_none());
    for wrong in [
        Peer {
            pid: peer.pid + 1,
            ..peer
        },
        Peer {
            uid: peer.uid.wrapping_add(1),
            ..peer
        },
        Peer {
            gid: peer.gid.wrapping_add(1),
            ..peer
        },
    ] {
        assert!(sender.try_send(b"credential", &[]).unwrap());
        assert!(receiver.try_receive(wrong, 0).is_err());
        assert!(receiver.try_receive(peer, 0).unwrap().is_none());
    }
    assert!(sender.try_send(b"correct", &[]).unwrap());
    assert_eq!(
        receiver
            .try_receive(peer, 0)
            .unwrap()
            .unwrap()
            .bytes,
        b"correct"
    );
    assert!(receiver.try_receive(peer, 0).unwrap().is_none());
}

#[test]
fn nonblocking_full_queue_returns_false_and_retry_has_no_partial_or_duplicate_packet() {
    use std::sync::{Arc, Condvar, Mutex};
    let (sender, receiver) = PacketChannel::pair().unwrap();
    let fill = [b'x'; MAX_BYTES];
    let count = fill_send_queue(&sender, &fill);
    let pending = [b'y'; MAX_BYTES];
    let finished = Arc::new((Mutex::new(false), Condvar::new()));
    let watchdog_finished = Arc::clone(&finished);
    let watchdog = std::thread::spawn(move || {
        let (lock, wake) = &*watchdog_finished;
        let (done, timeout) = wake
            .wait_timeout_while(
                lock.lock().unwrap(),
                Duration::from_secs(2),
                |done| !*done,
            )
            .unwrap();
        let expired = timeout.timed_out() && !*done;
        if expired {
            // Release a wrongly blocking sender before reporting failure. This
            // deadline is a watchdog, never evidence of successful delivery.
            while receiver
                .try_receive(Peer::current(), 0)
                .unwrap()
                .is_some()
            {}
        }
        (receiver, expired)
    });
    let result = sender.try_send(&pending, &[]);
    let (lock, wake) = &*finished;
    *lock.lock().unwrap() = true;
    wake.notify_one();
    let (receiver, expired) = watchdog.join().unwrap();
    assert!(
        !expired,
        "try_send waited for a receiver to drain backpressure"
    );
    assert!(!result.unwrap());
    for _ in 0..count {
        assert_eq!(
            receiver
                .try_receive(Peer::current(), 0)
                .unwrap()
                .unwrap()
                .bytes,
            fill
        );
    }
    assert!(
        receiver
            .try_receive(Peer::current(), 0)
            .unwrap()
            .is_none()
    );
    assert!(sender.try_send(&pending, &[]).unwrap());
    assert!(sender.try_send(b"after-retry", &[]).unwrap());
    assert_eq!(
        receiver
            .try_receive(Peer::current(), 0)
            .unwrap()
            .unwrap()
            .bytes,
        pending
    );
    assert_eq!(
        receiver
            .try_receive(Peer::current(), 0)
            .unwrap()
            .unwrap()
            .bytes,
        b"after-retry"
    );
    assert!(
        receiver
            .try_receive(Peer::current(), 0)
            .unwrap()
            .is_none()
    );
}

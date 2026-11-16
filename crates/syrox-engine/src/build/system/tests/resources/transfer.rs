use super::*;
use crate::execution::transport::{PacketChannel, Peer};
use crate::platform::linux::fd;
use std::{
    os::{fd::FromRawFd as _, unix::process::CommandExt as _},
    process::{Child, Command},
    time::{Duration, Instant},
};

const CHILD_CONTEXT: &str = "SRX_SYSTEM_INPUT_TRANSFER_TEST_CONTEXT";
const CHILD_FD: i32 = 198;
const NONCE: [u8; 32] = [0x6d; 32];

fn peer() -> SystemBuildInputPeer {
    SystemBuildInputPeer {
        pid: std::process::id(),
        uid: fd::real_uid(),
        gid: fd::real_gid(),
    }
}
fn packet_peer() -> Peer {
    Peer {
        pid: std::process::id(),
        uid: fd::real_uid(),
        gid: fd::real_gid(),
    }
}
fn pair() -> (OwnedFd, OwnedFd) {
    let (left, right) = PacketChannel::pair().unwrap();
    (
        left.as_fd().try_clone_to_owned().unwrap(),
        right.as_fd().try_clone_to_owned().unwrap(),
    )
}

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn batched_transfer_to_a_distinct_process_retains_inputs_through_parent_gc() {
    let kinds = (0..33).map(|i| i % 2 == 0).collect::<Vec<_>>();
    let fixture = imported(&kinds, 1);
    let cancel = Cancellation::default();
    let inputs = fixture.prepare().unwrap();
    let resources = inputs
        .prepare_input_resources(40, &cancel)
        .unwrap();
    assert_eq!(resources.descriptors().len(), 84);
    assert!(resources.manifest().len() > 1024);
    let action = inputs.action().clone();
    let context = fixture.directory.path().join("child-context");
    fs::create_dir(&context).unwrap();
    fs::set_permissions(&context, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(context.join("action"), action.encode()).unwrap();
    fs::write(context.join("spec.json"), serde_json::to_vec(&serde_json::json!({ "parent_pid": std::process::id(), "manifest": resources.manifest_digest().to_string(), "budget": action.budget().request() })).unwrap()).unwrap();
    let (left, right) = pair();
    let raw = right.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "build::system::tests::resources::transfer::transport_child",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    command.env(CHILD_CONTEXT, &context);
    // SAFETY: after fork, only fixed descriptor syscalls run before exec. All
    // unrelated parent handles are CLOEXEC, so they cannot fake child retention.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) < 0
                || (raw != CHILD_FD && libc::dup2(raw, CHILD_FD) < 0)
                || libc::fcntl(CHILD_FD, libc::F_SETFD, 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = Reap(command.spawn().unwrap());
    drop(right);
    let child_peer = SystemBuildInputPeer {
        pid: child.0.id(),
        ..peer()
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    SystemBuildInputTransfer::new(left, child_peer, NONCE)
        .unwrap()
        .send(&resources, &cancel, deadline)
        .unwrap();
    drop(resources);
    drop(inputs);
    let report = fixture
        .store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: (0..33)
                .map(|i| RootName::new(format!("input_{i}")).unwrap())
                .collect(),
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    fs::write(context.join("release"), b"parent GC complete").unwrap();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "input transfer child deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let report = fixture
        .store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain && report.failures.is_empty());
    assert!(
        fixture
            .store
            .operation()
            .unwrap()
            .open_verified(action.source_digest(), 1024)
            .unwrap()
            .is_none()
    );
}

#[test]
#[ignore = "private child entry; requires the parent-created context and one explicit inherited seqpacket"]
fn transport_child() {
    let context =
        std::path::PathBuf::from(std::env::var_os(CHILD_CONTEXT).expect("private parent context"));
    let metadata = fs::symlink_metadata(&context).unwrap();
    assert!(
        metadata.is_dir()
            && metadata.uid() == fd::effective_uid()
            && metadata.mode() & 0o7777 == 0o700
    );
    let spec: serde_json::Value =
        serde_json::from_slice(&fs::read(context.join("spec.json")).unwrap()).unwrap();
    let request: crate::system::budget::BuildBudget =
        serde_json::from_value(spec["budget"].clone()).unwrap();
    let configuration = configuration(ContentDigest::sha256(&worker()));
    let budget = configuration.admit(request).unwrap();
    let action = SystemBuildAction::parse(
        &fs::read(context.join("action")).unwrap(),
        &budget,
    )
    .unwrap();
    let selected: ContentDigest = spec["manifest"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let expected = SystemBuildInputPeer {
        pid: u32::try_from(spec["parent_pid"].as_u64().unwrap()).unwrap(),
        ..peer()
    };
    // SAFETY: the parent exec contract gives this entry exclusive ownership of
    // exactly one inherited fd at CHILD_FD. No other child test owns this role.
    #[allow(unsafe_code)]
    let socket = unsafe { OwnedFd::from_raw_fd(CHILD_FD) };
    let cancel = Cancellation::default();
    let deadline = Instant::now() + Duration::from_secs(30);
    let resources = SystemBuildInputTransfer::new(socket, expected, NONCE)
        .unwrap()
        .receive(&action, selected, 40, &cancel, deadline)
        .unwrap();
    assert_eq!(resources.descriptors().len(), 84);
    while !context.join("release").try_exists().unwrap() {
        assert!(
            Instant::now() < deadline,
            "parent release deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    resources.revalidate(&cancel).unwrap();
    let root = resources.view_descriptor(32, &cancel).unwrap();
    assert_eq!(
        fs::read(format!(
            "/proc/self/fd/{}/data_000000",
            root.as_raw_fd()
        ))
        .unwrap(),
        b"input-32-0"
    );
    println!(
        "SRX_SYSTEM_INPUT_TRANSFER_CHILD_OK {}",
        action.digest()
    );
}

#[test]
fn nonce_and_kernel_pid_mismatch_fail_without_accepting_resources() {
    let fixture = imported(&[true], 1);
    let inputs = fixture.prepare().unwrap();
    let resources = inputs
        .prepare_input_resources(40, &Cancellation::default())
        .unwrap();
    for mismatch in 0..2 {
        let (left, right) = pair();
        let sender_peer = if mismatch == 1 {
            SystemBuildInputPeer {
                pid: peer().pid + 1,
                ..peer()
            }
        } else {
            peer()
        };
        let sender = SystemBuildInputTransfer::new(left, sender_peer, NONCE).unwrap();
        let receiver = SystemBuildInputTransfer::new(
            right,
            peer(),
            if mismatch == 0 {
                [1; 32]
            } else {
                NONCE
            },
        )
        .unwrap();
        std::thread::scope(|scope| {
            let expected = resources.manifest_digest();
            let action = inputs.action();
            let child = scope.spawn(move || {
                receiver.receive(
                    action,
                    expected,
                    40,
                    &Cancellation::default(),
                    Instant::now() + Duration::from_secs(2),
                )
            });
            assert!(
                sender
                    .send(
                        &resources,
                        &Cancellation::default(),
                        Instant::now() + Duration::from_secs(2)
                    )
                    .is_err()
            );
            assert!(child.join().unwrap().is_err());
        });
    }
}

#[test]
fn malformed_fragment_or_batch_cannot_reach_an_acceptance() {
    let fixture = imported(&[true], 1);
    let inputs = fixture.prepare().unwrap();
    let resources = inputs
        .prepare_input_resources(40, &Cancellation::default())
        .unwrap();
    for invalid in 0..2 {
        let (left, right) = pair();
        let sender = PacketChannel::from_owned(left).unwrap();
        let receiver = SystemBuildInputTransfer::new(right, peer(), NONCE).unwrap();
        std::thread::scope(|scope| {
            let task = scope.spawn(|| {
                receiver.receive(
                    inputs.action(),
                    resources.manifest_digest(),
                    40,
                    &Cancellation::default(),
                    Instant::now() + Duration::from_secs(2),
                )
            });
            let cancel = Cancellation::default();
            let deadline = Instant::now() + Duration::from_secs(2);
            let ready = sender
                .receive(packet_peer(), 0, deadline, &cancel)
                .unwrap();
            let binding = ContentDigest::sha256(&ready.bytes);
            let mut header = b"syrox-system-input-manifest-v1\n".to_vec();
            header.extend(binding.as_bytes());
            if invalid == 0 {
                header.extend(
                    (u32::try_from(SystemBuildInputResources::MAX_MANIFEST_BYTES).unwrap() + 1)
                        .to_le_bytes(),
                );
                header.extend(0_u32.to_le_bytes());
                sender
                    .send(&header, &[], deadline, &cancel)
                    .unwrap();
            } else {
                header.extend(
                    u32::try_from(resources.manifest().len())
                        .unwrap()
                        .to_le_bytes(),
                );
                header.extend(0_u32.to_le_bytes());
                header.extend(resources.manifest());
                sender
                    .send(&header, &[], deadline, &cancel)
                    .unwrap();
                let mut batch = b"syrox-system-input-batch-v1\n".to_vec();
                batch.extend(binding.as_bytes());
                batch.extend(4_u32.to_le_bytes());
                batch.extend(1_u32.to_le_bytes());
                batch.extend(4_u32.to_le_bytes());
                let fds = resources
                    .descriptors()
                    .iter()
                    .map(std::os::fd::AsFd::as_fd)
                    .collect::<Vec<_>>();
                sender
                    .send(&batch, &fds, deadline, &cancel)
                    .unwrap();
            }
            assert!(task.join().unwrap().is_err());
        });
    }
}

#[test]
fn cancelled_expired_and_idle_channels_keep_execution_closed() {
    let fixture = fixture(12);
    let inputs = fixture.prepare().unwrap();
    let resources = inputs
        .prepare_input_resources(40, &Cancellation::default())
        .unwrap();
    let (left, right) = pair();
    let canceled = Cancellation::default();
    canceled.cancel();
    assert!(matches!(
        SystemBuildInputTransfer::new(left, peer(), NONCE)
            .unwrap()
            .send(
                &resources,
                &canceled,
                Instant::now() + Duration::from_secs(1)
            ),
        Err(BuildError::Cancelled)
    ));
    assert!(matches!(
        SystemBuildInputTransfer::new(right, peer(), NONCE)
            .unwrap()
            .receive(
                inputs.action(),
                resources.manifest_digest(),
                40,
                &Cancellation::default(),
                Instant::now()
            ),
        Err(BuildError::Timeout)
    ));
    let (left, _right) = pair();
    assert!(matches!(
        SystemBuildInputTransfer::new(left, peer(), NONCE)
            .unwrap()
            .receive(
                inputs.action(),
                resources.manifest_digest(),
                40,
                &Cancellation::default(),
                Instant::now() + Duration::from_millis(20)
            ),
        Err(BuildError::Timeout)
    ));
}

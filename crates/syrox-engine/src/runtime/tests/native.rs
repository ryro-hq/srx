use super::*;

fn collected_process_interests(store: &Store) -> usize {
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            ..crate::store::GcRequest::default()
        })
        .unwrap()
        .removed_interests
}

fn empty_process_interest(store: &Store) -> fs::File {
    store
        .operation()
        .unwrap()
        .retain_objects(&[], &[])
        .unwrap()
        .process_retention()
        .unwrap()
}

/// Keep test subprocesses bounded even when an assertion or IPC operation fails.
struct ReapedTestChild(Child);

impl Drop for ReapedTestChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[allow(unsafe_code)] // Keep native gate case assertions and their retained fixtures in one cleanup scope.
fn native_gate_case(case: u8) {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::initialize(&temporary.path().join("retention-store")).unwrap();
    let output_directory = temporary.path().join("payload");
    fs::create_dir(&output_directory).unwrap();
    let binary = output_directory.join("gated-native");
    let output_prefix = format!("/syrox/store/{}/out", "a".repeat(64));
    compile(
        r#"#include <fcntl.h>
        #include <unistd.h>
        int main(void) {
            int fd = open("ran", O_WRONLY | O_CREAT, 0600);
            if (fd >= 0) close(fd);
            return 0;
        }"#,
        &binary,
        &["-static"],
    );
    let helper = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("syrox-worker");
    {
        let (control, monitor_control) = UnixStream::pair().unwrap();
        let (info, info_writer) = crate::platform::linux::fd::seqpacket_pair().unwrap();
        let (mut gate, gate_reader) = UnixStream::pair().unwrap();
        let mut command = Command::new(&helper);
        let retention = empty_process_interest(&store);
        crate::platform::linux::fd::pass_fd_to_child(&mut command, retention.as_raw_fd());
        command.args(["__runtime", "monitor"]);
        for fd in [
            monitor_control.as_raw_fd(),
            info_writer.as_raw_fd(),
            gate_reader.as_raw_fd(),
        ] {
            command.arg(fd.to_string());
            crate::platform::linux::fd::pass_fd_to_child(&mut command, fd);
        }
        let working_fd = fs::File::open(temporary.path()).unwrap();
        let output_fd = fs::File::open(&output_directory).unwrap();
        for file in [&working_fd, &output_fd] {
            crate::platform::linux::fd::pass_fd_to_child(&mut command, file.as_raw_fd());
        }
        command
            .arg("--ro")
            .arg(format!("/proc/self/fd/{}", output_fd.as_raw_fd()))
            .arg(&output_prefix);
        command
            .arg("--rw")
            .arg(format!(
                "/proc/self/fd/{}",
                working_fd.as_raw_fd()
            ))
            .arg(temporary.path());
        if case == 5 {
            command.args(["--mask", "relative-invalid-target"]);
        }
        command
            .arg("--cwd")
            .arg(temporary.path())
            .arg("--")
            .arg(format!("{output_prefix}/gated-native"));
        let mut monitor = ReapedTestChild(command.spawn().unwrap());
        drop(retention);
        drop((monitor_control, info_writer, gate_reader));
        if case == 4 {
            // Lose the coordinator before consuming the kernel-pinned message.
            control
                .shutdown(std::net::Shutdown::Both)
                .unwrap();
        }
        if case >= 6 {
            let cancellation = crate::cancellation::Cancellation::default();
            if case == 6 {
                // A message is waiting, but the coordinator has not received it.
                let mut event = libc::pollfd {
                    fd: info.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one initialized poll entry borrows the live info socket.
                assert_eq!(
                    unsafe { libc::poll(&raw mut event, 1, 10_000) },
                    1
                );
                assert_ne!(event.revents & libc::POLLIN, 0);
                cancellation.cancel();
            }
            let mut namespace = None;
            let error = prepare_namespace(
                info.as_fd(),
                &mut gate,
                &cancellation,
                &mut namespace,
                || {
                    if case == 7 {
                        cancellation.cancel();
                    }
                },
            )
            .unwrap_err();
            assert_eq!(namespace.is_some(), case == 7);
            assert!(matches!(
                abort_launch(
                    || monitor.0.wait(),
                    namespace.as_ref(),
                    control,
                    gate,
                    error
                ),
                RuntimeError::Cancelled
            ));
            assert!(monitor.0.try_wait().unwrap().is_some());
            assert_eq!(collected_process_interests(&store), 1);
            assert!(!temporary.path().join("ran").exists());
            return;
        }
        let pinned = receive_namespace(
            info.as_fd(),
            &crate::cancellation::Cancellation::default(),
        )
        .unwrap();
        if case < 4 {
            assert_eq!(collected_process_interests(&store), 0);
        }
        match case {
            0 => drop(gate), // EOF must never authorize a payload.
            1 => {
                gate.write_all(b"!").unwrap();
                drop(gate);
            }
            2 | 4 => {
                control
                    .shutdown(std::net::Shutdown::Both)
                    .unwrap();
                drop(gate);
            }
            3 => {
                monitor.0.kill().unwrap();
                drop(gate);
            }
            5 => {
                drop(gate);
            }
            _ => unreachable!(),
        }
        assert!(!monitor.0.wait().unwrap().success());
        crate::platform::linux::fd::wait_pidfd(pinned.as_fd()).unwrap();
        assert_eq!(collected_process_interests(&store), 1);
        assert!(
            !temporary.path().join("ran").exists(),
            "unauthorized payload in case {case}"
        );
    }
}

#[test]
fn namespace_info_wait_observes_cancellation_without_message() {
    let (info, _writer) = crate::platform::linux::fd::seqpacket_pair().unwrap();
    let cancellation = crate::cancellation::Cancellation::default();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(60));
            cancellation.cancel();
        });
        assert!(matches!(
            receive_namespace(info.as_fd(), &cancellation),
            Err(RuntimeError::Cancelled)
        ));
    });
}

#[test]
fn native_namespace_rejects_regular_file_descriptor() {
    let (info, writer) = crate::platform::linux::fd::seqpacket_pair().unwrap();
    let file = tempfile::tempfile().unwrap();
    crate::platform::linux::fd::send_fd(writer.as_fd(), file.as_fd()).unwrap();
    assert!(matches!(
        receive_namespace(
            info.as_fd(),
            &crate::cancellation::Cancellation::default()
        ),
        Err(RuntimeError::Io(_))
    ));
}

#[test]
fn failed_gate_release_leaves_pinned_process_available_for_settlement() {
    let (info, writer) = crate::platform::linux::fd::seqpacket_pair().unwrap();
    let (mut gate, reader) = UnixStream::pair().unwrap();
    drop(reader);
    let child = ReapedTestChild(
        Command::new("/usr/bin/sleep")
            .arg("10")
            .spawn()
            .unwrap(),
    );
    let pinned = crate::platform::linux::fd::pidfd_open(child.0.id()).unwrap();
    crate::platform::linux::fd::send_fd(writer.as_fd(), pinned.as_fd()).unwrap();
    let mut namespace = None;
    let error = prepare_namespace(
        info.as_fd(),
        &mut gate,
        &crate::cancellation::Cancellation::default(),
        &mut namespace,
        || {},
    )
    .unwrap_err();
    assert!(matches!(error, RuntimeError::Io(_)));
    let pinned = namespace.unwrap();
    crate::platform::linux::fd::kill_pidfd(pinned.as_fd()).unwrap();
    crate::platform::linux::fd::wait_pidfd(pinned.as_fd()).unwrap();
}

#[test]
#[ignore = "requires the release syrox-worker binary, Linux user namespaces and static GCC"]
fn native_runtime_refuses_eof_invalid_authorization_and_coordinator_loss() {
    for case in 0..6 {
        native_gate_case(case);
    }
}

#[test]
#[ignore = "requires syrox-worker, Linux user namespaces and static GCC"]
fn native_cancellation_before_pin_prevents_payload() {
    native_gate_case(6);
}

#[test]
#[ignore = "requires syrox-worker, Linux user namespaces and static GCC"]
fn native_cancellation_after_pin_prevents_payload_and_settles() {
    native_gate_case(7);
}

use super::*;

#[test]
fn managed_foreground_uses_explicit_snapshot_and_distinct_worker_entry() {
    let snapshot = std::path::Path::new("/controlled/release/worker-snapshot");
    assert_eq!(
        runtime_worker(RuntimeProfile {
            worker: Some(snapshot)
        })
        .unwrap(),
        snapshot
    );
    assert!(
        runtime_worker(RuntimeProfile {
            worker: Some(std::path::Path::new("relative-worker"))
        })
        .is_err()
    );
    assert_eq!(
        RuntimeProfile {
            worker: Some(snapshot)
        }
        .worker_mode(),
        "__runtime-managed"
    );
    assert_eq!(
        RuntimeProfile {
            worker: None
        }
        .worker_mode(),
        "__runtime"
    );
}

#[test]
#[ignore = "requires explicit SYROX_OWNER_WORKER and SYROX_SESSION_PAYLOAD candidates, nonroot UID and Linux user/PID/mount namespaces"]
fn host_managed_foreground_preserves_identity_minimal_environment_and_exit_status() {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let worker = PathBuf::from(
        std::env::var_os("SYROX_OWNER_WORKER").expect("explicit worker candidate required"),
    );
    let payload = PathBuf::from(
        std::env::var_os("SYROX_SESSION_PAYLOAD")
            .expect("explicit static session payload required"),
    );
    assert!(worker.is_absolute() && payload.is_absolute());
    let mut candidates = Vec::new();
    for path in [&worker, &payload] {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .unwrap();
        assert!(file.metadata().unwrap().is_file());
        let mut bytes = Vec::new();
        file.take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() <= 128 * 1024 * 1024);
        eprintln!(
            "candidate {} sha256 {}",
            path.display(),
            ContentDigest::sha256(&bytes)
        );
        candidates.push(bytes);
    }
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::initialize(&temporary.path().join("store")).unwrap();
    let app = retained(
        &store,
        "managed-foreground-host",
        &candidates[1],
        None,
    );
    let closure = verify_runtime(
        &store,
        &RuntimeRequest {
            application: runtime_file(&app),
            loader: None,
            libraries: vec![],
        },
    )
    .unwrap();
    let cwd = temporary.path().join("work");
    fs::create_dir(&cwd).unwrap();
    let peer = crate::execution::transport::Peer::current();
    assert_ne!(peer.uid, 0);
    let cancellation = crate::cancellation::Cancellation::default();
    let watch_token = cancellation.clone();
    let (done, completion) = std::sync::mpsc::channel();
    let watchdog = std::thread::spawn(move || {
        if completion
            .recv_timeout(Duration::from_secs(30))
            .is_err()
        {
            watch_token.cancel();
            true
        } else {
            false
        }
    });
    let result = run_runtime_managed_with_cancellation(
        &worker,
        &closure,
        &[
            "managed".into(),
            peer.uid.to_string().into(),
            peer.gid.to_string().into(),
        ],
        &cwd,
        &RuntimeConfiguration::default(),
        None,
        &cancellation,
    );
    let _ = done.send(());
    assert!(
        !watchdog.join().unwrap(),
        "managed foreground exceeded deadline"
    );
    assert_eq!(result.unwrap().code(), Some(37));
}

#[test]
fn managed_terminal_refuses_non_tty_before_worker_or_cwd_access() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let app = retained(
        &store,
        "terminal-preflight",
        &elf(2, None, &[], None, None),
        None,
    );
    let closure = verify_runtime(
        &store,
        &RuntimeRequest {
            application: runtime_file(&app),
            loader: None,
            libraries: vec![],
        },
    )
    .unwrap();
    let invalid = tempfile::tempfile().unwrap();
    let worker = temporary.path().join("absent-worker");
    let cwd = temporary.path().join("absent-cwd");
    let cancelled = crate::cancellation::Cancellation::default();
    cancelled.cancel();
    assert!(matches!(
        run_runtime_managed_with_cancellation(
            &worker,
            &closure,
            &[],
            &cwd,
            &RuntimeConfiguration::default(),
            Some(invalid.as_fd()),
            &cancelled,
        ),
        Err(RuntimeError::Cancelled)
    ));
    assert!(matches!(
        run_runtime_managed_with_cancellation(
            &worker,
            &closure,
            &[],
            &cwd,
            &RuntimeConfiguration::default(),
            Some(invalid.as_fd()),
            &crate::cancellation::Cancellation::default(),
        ),
        Err(RuntimeError::Io(_))
    ));
    assert!(!worker.exists());
    assert!(!cwd.exists());
}

use super::*;
use crate::platform::linux::fd::terminal::{Pty, WindowSize};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

fn pinned_candidate(path_variable: &str, pin_variable: &str) -> Vec<u8> {
    let path = PathBuf::from(std::env::var_os(path_variable).expect("explicit candidate required"));
    assert!(path.is_absolute());
    let pin: ContentDigest = std::env::var(pin_variable)
        .expect("explicit SHA256 required")
        .parse()
        .unwrap();
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
    assert_eq!(ContentDigest::sha256(&bytes), pin);
    validate_static_worker_image(&bytes).unwrap();
    bytes
}

#[test]
#[ignore = "requires explicit SYROX_OWNER_WORKER/SYROX_SESSION_PAYLOAD and corresponding _SHA256 pins, nonroot UID and Linux user/PID/mount namespaces"]
fn managed_terminal_devtty_survives_stdin_redirection() {
    let worker_bytes = pinned_candidate("SYROX_OWNER_WORKER", "SYROX_OWNER_WORKER_SHA256");
    let payload = pinned_candidate(
        "SYROX_SESSION_PAYLOAD",
        "SYROX_SESSION_PAYLOAD_SHA256",
    );
    let temporary = tempfile::tempdir().unwrap();
    let worker = temporary.path().join("worker");
    fs::write(&worker, worker_bytes).unwrap();
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o500)).unwrap();
    let store = Store::initialize(&temporary.path().join("store")).unwrap();
    let app = retained(&store, "managed-terminal-host", &payload, None);
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
    let (master, slave) = Pty::open(
        WindowSize {
            rows: 24,
            columns: 80,
            x_pixels: 0,
            y_pixels: 0,
        },
        None,
    )
    .unwrap()
    .into_parts();
    let mut master = fs::File::from(master);
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
            "terminal-devtty".into(),
            peer.uid.to_string().into(),
            peer.gid.to_string().into(),
        ],
        &cwd,
        &RuntimeConfiguration::default(),
        Some(slave.as_fd()),
        &cancellation,
    );
    let _ = done.send(());
    assert!(
        !watchdog.join().unwrap(),
        "managed terminal settlement exceeded deadline"
    );
    assert_eq!(result.unwrap().code(), Some(37));
    read_terminal_marker(
        &mut master,
        b"SYROX_SESSION_V1 DEVTTY OK stdin-pipe foreground-session",
        Duration::from_secs(5),
    )
    .unwrap();
}

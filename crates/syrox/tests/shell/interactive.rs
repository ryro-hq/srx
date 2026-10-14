//! Opt-in real CLI gates. Compile a RELEASE/static srx and syrox-worker, and an
//! explicit static build of tests/fixtures/session-payload.c. Supply absolute
//! `SYROX_INTERACTIVE_{CLI,WORKER,PAYLOAD}` and matching `*_SHA256`; also supply
//! `SYROX_INTERACTIVE_BUS` (authorized user-manager socket) and
//! `SYROX_INTERACTIVE_PARENT` (existing owned mode0700, short absolute directory).
//! Run a single ignored test by exact name on a Linux namespace-capable runner.
//! Every gate preserves its private evidence directory. No source candidate is
//! changed; no host shell/compiler/PATH lookup is used. Packet/namespace/manager
//! denial is failure/PENDING, never a skipped pass. These cover owner+foreground
//! only, not configured services, job control, pipelines, logout or full Shell.
#![allow(unsafe_code)] // Isolated test PTYs, process descriptors, and pre-exec setup.

use std::fs::{self, File};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

#[allow(dead_code)] // Shared fixture encoder; its ELF fixture generator is unused here.
#[path = "../bundle/fixtures.rs"]
mod bundle_fixture;
#[path = "interactive/driver.rs"]
mod driver;
#[path = "interactive/fixture.rs"]
mod fixture;
#[path = "interactive/observation.rs"]
mod observation;

#[test]
#[ignore = "real opt-in pinned CLI/worker/payload, user systemd, namespaces and PTY custody required"]
fn interactive_literal_resize_exit_and_restore() {
    gate("resize");
}
#[test]
#[ignore = "real opt-in pinned CLI/worker/payload, user systemd, namespaces and PTY custody required"]
fn interactive_ctrl_c_status_and_restore() {
    gate("interrupt");
}
#[test]
#[ignore = "real opt-in pinned CLI/worker/payload, user systemd, namespaces, pidfds and post-SIGKILL custody required"]
fn interactive_cli_sigkill_restores_and_settles_pinned_processes() {
    gate("kill");
}

fn gate(mode: &str) {
    let bus = fixture::absolute("SYROX_INTERACTIVE_BUS");
    let root = fixture::create();
    let result = std::panic::catch_unwind(|| driver::anchor(&root, mode, &bus));
    if result.is_err() {
        // Only the new private journal can authorize these recovery requests;
        // never stop enumerated or name-matching foreign manager units.
        let cancel = syrox_engine::cancellation::Cancellation::default();
        if let Ok(entries) = syrox_engine::deployment::shell::list_managed_shell_sessions(
            &root.join("state"),
            &cancel,
        ) {
            for entry in entries {
                let recovered = syrox_engine::deployment::shell::recover_managed_shell_session(
                    &root.join("state"),
                    &entry.session,
                    &bus,
                    &root.join("store"),
                    &cancel,
                );
                eprintln!(
                    "gate cleanup for {}: {recovered:?}",
                    entry.session
                );
            }
        }
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[ignore = "reexecuted PTY fixture; exercised by interactive lifecycle gates"]
fn anchor_process() {
    let root = std::env::var_os("SYROX_INTERACTIVE_ANCHOR")
        .expect("anchor fixture requires its owning gate");
    let root = std::path::PathBuf::from(root);
    let mode = std::env::var("SYROX_INTERACTIVE_MODE").unwrap();
    assert!(matches!(
        mode.as_str(),
        "resize" | "interrupt" | "kill"
    ));
    let master: i32 = std::env::var("SYROX_INTERACTIVE_MASTER")
        .unwrap()
        .parse()
        .unwrap();
    assert!(master >= 3);
    // SAFETY: dedicated anchor receives exactly this owned master descriptor
    // across exec. Mark CLOEXEC before spawning the candidate CLI.
    assert_eq!(
        unsafe { libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: dup atomically creates a CLOEXEC reference to the anchor's stdio.
    let slave = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
    assert!(slave >= 3);
    let slave = unsafe { std::os::fd::OwnedFd::from_raw_fd(slave) };
    let mut terminal = driver::Terminal {
        master,
        slave,
    };
    let original = driver::attributes(0);
    // SAFETY: these are read-only process/session queries in the isolated anchor.
    assert_eq!(unsafe { libc::tcgetpgrp(0) }, unsafe {
        libc::getpgrp()
    });
    let bus = fixture::absolute("SYROX_INTERACTIVE_BUS");
    let witness = root.join("work/witness");
    fs::write(&witness, b"").unwrap();
    let arguments = if mode == "kill" {
        vec![
            "orphan".to_owned(),
            witness.to_str().unwrap().to_owned(),
        ]
    } else {
        vec![
            "terminal".to_owned(),
            "literal ; $HOME *".to_owned(),
            "41".to_owned(),
            "113".to_owned(),
        ]
    };
    let mut cli = driver::cli(&root, &bus, &arguments);
    let deadline = Instant::now() + driver::TIMEOUT;
    let mut captured = Vec::new();
    let ready = if mode == "kill" {
        b"SYROX_SESSION_V1 READY witness-held".as_slice()
    } else {
        b"SYROX_SESSION_V1 READY terminal 24 80".as_slice()
    };
    terminal.until(ready, &mut cli, &mut captured, deadline);
    assert!(
        !driver::same_attributes(&original, &driver::attributes(0)),
        "CLI never activated raw mode"
    );
    let mut observed = observation::Observation::capture(&root, &bus, cli.id());
    match mode.as_str() {
        "resize" => {
            terminal.resize(41, 113);
            // Resize propagation is polled at most every20ms, but readiness here
            // is checked by the payload after its input line, not by this delay.
            std::thread::sleep(Duration::from_millis(60));
            terminal.send(b"literal ; $HOME *\n", deadline);
            terminal.until(
                b"SYROX_SESSION_V1 TERMINAL OK",
                &mut cli,
                &mut captured,
                deadline,
            );
        }
        "interrupt" => terminal.send(&[3], deadline),
        "kill" => {
            assert!(!witness_free(&witness));
            cli.kill();
        }
        _ => unreachable!(),
    }
    let status = loop {
        terminal.drain(&mut captured);
        if let Some(status) = cli.poll() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "CLI exit deadline: {}",
            String::from_utf8_lossy(&captured)
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    fs::write(root.join("terminal-output.log"), &captured).unwrap();
    match mode.as_str() {
        "resize" => assert_eq!(status.code(), Some(0)),
        "interrupt" => assert_eq!(
            status.code(),
            Some(130),
            "{}",
            String::from_utf8_lossy(&captured)
        ),
        "kill" => assert_eq!(status.signal(), Some(libc::SIGKILL)),
        _ => unreachable!(),
    }
    while !driver::same_attributes(&original, &driver::attributes(0)) {
        assert!(
            Instant::now() < deadline,
            "host terminal was not restored after {mode}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    observed.settled(&root, deadline, mode == "kill");
    if mode == "kill" {
        assert!(
            witness_free(&witness),
            "namespace descendant still holds witness"
        );
    }
    fs::write(
        root.join("interactive-anchor-success"),
        b"payload status, terminal restoration and settlement assertions completed\n",
    )
    .unwrap();
}
fn witness_free(path: &Path) -> bool {
    let file = File::open(path).unwrap();
    // SAFETY: flock operates on our existing regular witness only.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return true;
    }
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EWOULDBLOCK)
    );
    false
}

#[path = "interactive/stop_exit.rs"]
mod stop_exit;

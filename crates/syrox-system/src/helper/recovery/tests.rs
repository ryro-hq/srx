use super::*;
use crate::{journal, session};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use syrox_system::descriptor;

const ID: &str = "0123456789abcdef0123456789abcdef";

fn fixture(live: bool) -> (tempfile::TempDir, File, Journal) {
    let temporary = tempfile::tempdir().unwrap();
    let state = File::open(temporary.path()).unwrap();
    state
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .unwrap();
    let mut journal = Journal::create(&state, &format!("op-{ID}")).unwrap();
    let mut runtime = runtime::Runtime::observe().unwrap();
    if !live {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .unwrap();
        runtime.helper_pid = child.id();
        child.wait().unwrap();
    }
    journal
        .record(
            "authorized",
            serde_json::json!({ "runtime": runtime }),
        )
        .unwrap();
    journal
        .record("allocate-intent", serde_json::json!({}))
        .unwrap();
    let mut image = journal::new_file(&journal.directory, "scratch.img").unwrap();
    image
        .write_all(b"retained filesystem contents")
        .unwrap();
    image.sync_all().unwrap();
    let m = image.metadata().unwrap();
    journal
        .record(
            "image-allocated",
            serde_json::json!({ "device": m.dev(), "inode": m.ino(), "bytes": m.len() }),
        )
        .unwrap();
    (temporary, state, journal)
}

#[test]
fn recovery_requires_ended_session_and_observed_tool_exit() {
    let (_temporary, state, _journal) = fixture(true);
    let (plan, _, _) = inspect(&state, ID, [0; 32]).unwrap();
    assert_eq!(plan.action, "blocked");
    assert!(
        plan.reasons
            .contains(&"original helper session is still alive")
    );

    let (_temporary, state, mut journal) = fixture(false);
    journal
        .record(
            "tool-intent",
            serde_json::json!({ "stage": "format" }),
        )
        .unwrap();
    let (plan, _, _) = inspect(&state, ID, [0; 32]).unwrap();
    assert_eq!(plan.action, "blocked");
    journal
        .record(
            "tool-result",
            serde_json::json!({ "stage": "format" }),
        )
        .unwrap();
    assert_eq!(
        inspect(&state, ID, [0; 32]).unwrap().0.action,
        "reconcile-retained-image"
    );
}

#[test]
fn reconciliation_revalidates_hash_and_preserves_image_without_claiming_health() {
    let (temporary, state, mut journal) = fixture(false);
    let path = temporary
        .path()
        .join(format!("op-{ID}/scratch.img"));
    let before = std::fs::read(&path).unwrap();
    let (server, client) = descriptor::seqpacket_pair().unwrap();
    let server = File::from(server);
    let hash = inspect(&state, ID, [0; 32])
        .unwrap()
        .0
        .sha256()
        .unwrap();
    let count = std::fs::read_dir(temporary.path().join(format!("op-{ID}")))
        .unwrap()
        .count();
    assert!(serve(&server, &state, [1; 32], ID, Some(&hash)).is_err());
    assert_eq!(
        std::fs::read_dir(temporary.path().join(format!("op-{ID}")))
            .unwrap()
            .count(),
        count
    );
    journal
        .record(
            "uncertain",
            serde_json::json!({ "error": "interrupted" }),
        )
        .unwrap();
    assert!(serve(&server, &state, [0; 32], ID, Some(&hash)).is_err());
    let hash = inspect(&state, ID, [0; 32])
        .unwrap()
        .0
        .sha256()
        .unwrap();
    assert!(session::check_state(&state, 2).is_err());
    serve(&server, &state, [0; 32], ID, Some(&hash)).unwrap();
    let response = File::from(descriptor::receive_fd(std::os::fd::AsFd::as_fd(&client)).unwrap());
    let mut bytes = Vec::new();
    response
        .take(65_537)
        .read_to_end(&mut bytes)
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["state"], "reconciled");
    assert_eq!(
        value["details"]["filesystem_health_verified"],
        false
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    session::check_state(&state, 2).unwrap();
    assert!(Journal::create(&state, &format!("op-{ID}")).is_err());
    assert!(serve(&server, &state, [0; 32], ID, Some(&hash)).is_err());
}

#[test]
fn changed_image_partial_record_and_missing_runtime_fail_closed() {
    let (temporary, state, _journal) = fixture(false);
    let path = temporary
        .path()
        .join(format!("op-{ID}/scratch.img"));
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(99)
        .unwrap();
    assert!(inspect(&state, ID, [0; 32]).is_err());

    let (_temporary, state, journal) = fixture(false);
    journal::new_file(&journal.directory, "0003-uncertain.json")
        .unwrap()
        .write_all(b"{")
        .unwrap();
    assert!(inspect(&state, ID, [0; 32]).is_err());
    assert!(session::check_state(&state, 2).is_err());

    // An old journal with no runtime evidence remains visible but cannot be
    // automatically reconciled under this same-boot contract.
    let mut journal = Journal::create(&File::open(temporary.path()).unwrap(), "op-other").unwrap();
    journal
        .record("authorized", serde_json::json!({}))
        .unwrap();
    assert!(
        inspect(
            &File::open(temporary.path()).unwrap(),
            "other",
            [0; 32]
        )
        .is_err()
    );
}

#[test]
fn kernel_runtime_changes_do_not_establish_session_death() {
    let now = runtime::Runtime::observe().unwrap();
    let mut origin = runtime::Runtime::observe().unwrap();
    assert!(!origin.previous_session_ended(&now).unwrap());
    origin.boot_id = "0".repeat(36);
    assert!(origin.previous_session_ended(&now).is_err());
    origin.boot_id.clone_from(&now.boot_id);
    origin.pid_namespace = now.pid_namespace.wrapping_add(1);
    assert!(origin.previous_session_ended(&now).is_err());
}

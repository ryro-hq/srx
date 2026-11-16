use super::*;
use crate::{journal, recovery, session};
use std::{io::Write as _, os::unix::fs::PermissionsExt as _};
use syrox_system::budget::BuildBudget;

const ID: &str = "abcdef0123456789abcdef0123456789";
fn fixture(live: bool, output: bool) -> (tempfile::TempDir, File, Journal) {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        temporary.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let state = File::open(temporary.path()).unwrap();
    let mut journal = Journal::create(&state, &format!("op-{ID}")).unwrap();
    let mut origin = runtime::Runtime::observe().unwrap();
    if !live {
        origin.helper_pid = i32::MAX as u32;
        origin.helper_start_ticks = 0;
    }
    let budget = BuildBudget {
        memory_bytes: 134_217_728,
        cpu_percent: 100,
        processes: 16,
        descriptors: 128,
        scratch_bytes: 67_108_864,
        files: 1024,
        output_bytes: 134_217_728,
        duration_seconds: 180,
    };
    journal.record("authorized",serde_json::json!({"request":Request::PrepareWorkspace {version:1,id:ID.into(),budget,layout_sha256:"ab".repeat(32)},"authorization":"cd".repeat(32),"policy_sha256":([0_u8;32]),"runtime":origin})).unwrap();
    for (role, size) in [
        ("scratch", budget.scratch_bytes),
        ("output", budget.output_bytes),
    ] {
        if role == "output" && !output {
            continue;
        }
        let image = journal::new_file(&journal.directory, &format!("{role}.img")).unwrap();
        image.set_len(size).unwrap();
        image.sync_all().unwrap();
        let metadata = image.metadata().unwrap();
        journal.record("image-allocated",serde_json::json!({"role":role,"device":metadata.dev(),"inode":metadata.ino(),"bytes":metadata.len()})).unwrap();
    }
    (temporary, state, journal)
}

#[test]
fn both_retained_images_and_ended_session_are_required_without_formatting() {
    let (temporary, state, _) = fixture(false, true);
    let before_scratch = std::fs::metadata(
        temporary
            .path()
            .join(format!("op-{ID}/scratch.img")),
    )
    .unwrap();
    let (plan, _, _) = inspect(&state, ID, [0; 32]).unwrap();
    assert_eq!(plan["action"], "reconcile-retained-workspace");
    assert_eq!(plan["images"].as_object().unwrap().len(), 2);
    assert_eq!(plan["filesystem_health_verified"], false);
    assert!(recovery::inspect(&state, ID, [0; 32]).is_err());
    assert!(session::check_state(&state, 4).is_err());
    let after = std::fs::metadata(
        temporary
            .path()
            .join(format!("op-{ID}/scratch.img")),
    )
    .unwrap();
    assert_eq!(
        (
            before_scratch.dev(),
            before_scratch.ino(),
            before_scratch.len()
        ),
        (after.dev(), after.ino(), after.len())
    );
    let (_temporary, state, _) = fixture(true, true);
    assert_eq!(
        inspect(&state, ID, [0; 32]).unwrap().0["action"],
        "blocked"
    );
    let (_temporary, state, _) = fixture(false, false);
    assert_eq!(
        inspect(&state, ID, [0; 32]).unwrap().0["action"],
        "blocked"
    );
}

#[test]
fn changed_policy_images_tool_intents_and_journal_affect_recovery() {
    let (temporary, state, mut journal) = fixture(false, true);
    let first = inspect(&state, ID, [0; 32]).unwrap().0;
    assert_eq!(
        inspect(&state, ID, [1; 32]).unwrap().0["action"],
        "blocked"
    );
    journal
        .record(
            "tool-intent",
            serde_json::json!({"stage":"output-check-before"}),
        )
        .unwrap();
    let pending = inspect(&state, ID, [0; 32]).unwrap().0;
    assert_eq!(pending["action"], "blocked");
    assert_ne!(hash(&first).unwrap(), hash(&pending).unwrap());
    journal
        .record(
            "tool-result",
            serde_json::json!({"stage":"output-check-before"}),
        )
        .unwrap();
    assert_eq!(
        inspect(&state, ID, [0; 32]).unwrap().0["action"],
        "reconcile-retained-workspace"
    );
    File::options()
        .write(true)
        .open(
            temporary
                .path()
                .join(format!("op-{ID}/output.img")),
        )
        .unwrap()
        .set_len(32)
        .unwrap();
    assert!(inspect(&state, ID, [0; 32]).is_err());
    let (_temporary, state, mut journal) = fixture(false, true);
    journal
        .record(
            "tool-result",
            serde_json::json!({"stage":"scratch-format"}),
        )
        .unwrap();
    assert!(inspect(&state, ID, [0; 32]).is_err());
}

#[test]
fn matching_two_image_terminal_receipts_are_required_to_reuse_state() {
    let (_temporary, state, mut journal) = fixture(false, true);
    journal.record("released",serde_json::json!({"id":ID,"authorization":"cd".repeat(32),"layout_sha256":"ab".repeat(32),"image_retained":true,"images":1})).unwrap();
    assert!(!recovery::settled(&state, &format!("op-{ID}")).unwrap());
    journal.record("released",serde_json::json!({"id":ID,"authorization":"cd".repeat(32),"layout_sha256":"ab".repeat(32),"image_retained":true,"images":2})).unwrap();
    assert!(recovery::settled(&state, &format!("op-{ID}")).unwrap());
    journal
        .record("response-undelivered", serde_json::json!({}))
        .unwrap();
    assert!(recovery::settled(&state, &format!("op-{ID}")).unwrap());
    assert!(session::check_state(&state, 4).is_ok());
}

#[test]
fn workspace_resources_do_not_expand_legacy_journal_acceptance() {
    let temporary = tempfile::tempdir().unwrap();
    let state = File::open(temporary.path()).unwrap();
    let mut journal = Journal::create(&state, "op-legacy").unwrap();
    journal
        .record("authorized", serde_json::json!({}))
        .unwrap();
    journal::new_file(&journal.directory, "output.img")
        .unwrap()
        .write_all(b"untouched")
        .unwrap();
    assert!(evidence::load(&state, "op-legacy").is_err());
    let (_temporary, state, journal) = fixture(false, true);
    journal::new_file(&journal.directory, "unknown").unwrap();
    assert!(inspect(&state, ID, [0; 32]).is_err());
}

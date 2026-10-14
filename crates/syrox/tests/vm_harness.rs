pub mod vm_support;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::time::Duration;
use vm_support::{artifacts, common};

#[test]
fn gate_summary_rejects_zero_ignored_failed_and_duplicate_results() {
    common::require_one_passed("test result: ok. 1 passed; 0 failed; 0 ignored; 4 filtered out;\n")
        .unwrap();
    for text in [
        "test result: ok. 0 passed; 0 failed; 0 ignored;",
        "test result: ok. 1 passed; 0 failed; 1 ignored;",
        "test result: FAILED. 0 passed; 1 failed; 0 ignored;",
        "test result: ok. 1 passed; 0 failed; 0 ignored;\ntest result: ok. 1 passed; 0 failed; 0 ignored;",
    ] {
        assert!(
            common::require_one_passed(text).is_err(),
            "{text}"
        );
    }
}

#[test]
fn inventory_summary_requires_the_exact_target_counts_and_unfiltered_run() {
    let log = "     Running unittests src/lib.rs (target/debug/deps/engine-identified)\n\nrunning 1 test\ntest fixture ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 10 filtered out;\ntest result: ok. 7 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out;\n     Running next.rs (target/debug/deps/next)\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 filtered out;\n";
    let binary = Path::new("/identified/engine-identified");
    assert!(vm_support::inventory::complete_target_passed(
        log, binary, 10, 3
    ));
    assert!(!vm_support::inventory::complete_target_passed(
        log,
        Path::new("wrong"),
        10,
        3
    ));
    assert!(!vm_support::inventory::complete_target_passed(
        log, binary, 9, 3
    ));
    assert!(!vm_support::inventory::complete_target_passed(
        &log.replace("7 passed", "6 passed"),
        binary,
        10,
        3
    ));
    assert!(!vm_support::inventory::complete_target_passed(
        &log.replace(
            "0 measured; 0 filtered out",
            "0 measured; 1 filtered out"
        ),
        binary,
        10,
        3
    ));
}

#[test]
fn gate_selection_requires_complete_identity_and_no_duplicates() {
    let selected = common::Selection::default().selected();
    common::validate_selection(&selected, false).unwrap();
    for field in [
        "package", "target", "category", "group", "reason",
    ] {
        let mut altered = selected[0].clone();
        match field {
            "package" => altered.package.push_str("-foreign"),
            "target" => altered.target.push_str("-foreign"),
            "category" => altered.category = common::Category::Fixture,
            "group" => altered.group.push_str("-foreign"),
            _ => altered.reason.push_str("-foreign"),
        }
        assert!(common::validate_selection(&[altered], false).is_err());
    }
    assert!(
        common::validate_selection(&[selected[0].clone(), selected[0].clone()], false).is_err()
    );
}

#[test]
fn compilation_cache_reuses_environment_and_evicts_only_inactive_entries() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("cache");
    let control = vm_support::process::Control::uncancelled();
    let old_key = "a".repeat(64);
    let new_key = "b".repeat(64);
    let old = vm_support::cache::acquire(&root, &old_key, &control).unwrap();
    fs::write(old.directory.join("compiled"), vec![1; 8192]).unwrap();
    let old_path = old.directory.clone();
    drop(old);
    let current = vm_support::cache::acquire(&root, &new_key, &control).unwrap();
    fs::write(current.directory.join("compiled"), vec![2; 8192]).unwrap();
    let limit = vm_support::cache::bytes(&current.directory, &control).unwrap();
    let report = vm_support::cache::prune(&root, limit, &control).unwrap();
    assert_eq!(report["removed"], serde_json::json!([old_key]));
    assert!(!old_path.exists());
    assert_eq!(
        fs::read(current.directory.join("compiled")).unwrap(),
        vec![2; 8192]
    );
    assert!(vm_support::cache::prune(&root, limit - 1, &control).is_err());
    let current_path = current.directory.clone();
    drop(current);
    let reused = vm_support::cache::acquire(&root, &new_key, &control).unwrap();
    assert_eq!(reused.directory, current_path);
    assert!(reused.directory.join("compiled").is_file());
    drop(reused);
    vm_support::cache::prune(&root, 0, &control).unwrap();
    assert!(!current_path.exists());
}

#[test]
fn compilation_cache_refuses_links_and_cancelled_preparation() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("cache");
    fs::create_dir(&root).unwrap();
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("preserved"), b"evidence").unwrap();
    let key = "c".repeat(64);
    std::os::unix::fs::symlink(&outside, root.join(&key)).unwrap();
    let control = vm_support::process::Control::uncancelled();
    assert!(vm_support::cache::acquire(&root, &key, &control).is_err());
    assert!(vm_support::cache::prune(&root, 0, &control).is_err());
    assert!(outside.join("preserved").is_file());
    control.cancelled.store(true, Ordering::Relaxed);
    assert!(vm_support::cache::acquire(&root, &"d".repeat(64), &control).is_err());
    assert!(!root.join("d".repeat(64)).exists());
}

#[test]
fn unconfirmed_vm_cleanup_keeps_cache_protected_after_host_lease_drop() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("cache");
    let control = vm_support::process::Control::uncancelled();
    let key = "e".repeat(64);
    let entry = vm_support::cache::acquire(&root, &key, &control).unwrap();
    fs::write(entry.directory.join("compiled"), b"retained").unwrap();
    entry.mark_active().unwrap();
    drop(entry);
    assert!(vm_support::cache::prune(&root, 0, &control).is_err());
    assert_eq!(
        fs::read(root.join(&key).join("compiled")).unwrap(),
        b"retained"
    );
    assert!(vm_support::cache::acquire(&root, &key, &control).is_err());
}

#[test]
fn frozen_gate_evidence_survives_replacement_of_shared_compilation_outputs() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("shared");
    fs::write(&source, b"first capture").unwrap();
    let required = [
        "syrox-engine/lib",
        "syrox/build",
        "syrox/shell",
        "syrox/usability",
        "srx",
        "syrox-worker",
    ];
    let artifacts = required
        .into_iter()
        .map(|key| (key.to_owned(), source.clone()))
        .collect();
    let control = vm_support::process::Control::uncancelled();
    let first = artifacts::freeze(
        &artifacts,
        &temporary.path().join("first"),
        &control,
    )
    .unwrap();
    fs::write(&source, b"second capture").unwrap();
    let second = artifacts::freeze(
        &artifacts,
        &temporary.path().join("second"),
        &control,
    )
    .unwrap();
    let worker = first["syrox-engine/lib"]
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("syrox-worker");
    assert_eq!(worker, first["syrox-worker"]);
    assert_eq!(fs::read(worker).unwrap(), b"first capture");
    for key in required {
        assert_eq!(fs::read(&first[key]).unwrap(), b"first capture");
        assert_eq!(fs::read(&second[key]).unwrap(), b"second capture");
    }
}

#[cfg(feature = "vm-tests")]
#[test]
fn sdk_preparation_and_startup_are_bounded_and_cancelled() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        for stage in ["image preparation", "VM startup"] {
            let control = vm_support::process::Control::uncancelled();
            let flag = std::sync::Arc::clone(&control.cancelled);
            let cancel = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(60)).await;
                flag.store(true, Ordering::Relaxed);
            });
            let pending = std::future::pending::<Result<(), String>>();
            let error = control
                .bounded(stage, Duration::from_secs(5), pending)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("cancelled"));
            cancel.await.unwrap();
        }
        let control = vm_support::process::Control::uncancelled();
        let error = control
            .bounded(
                "image preparation",
                Duration::from_millis(60),
                std::future::pending::<Result<(), String>>(),
            )
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("image preparation timed out")
        );
    });
}

#[test]
fn candidate_copy_refuses_links_limits_and_reused_evidence() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("candidate");
    let copied = temporary.path().join("copy");
    fs::write(&source, b"identified candidate").unwrap();
    assert!(vm_support::snapshot::copy_candidate(&source, &copied, 4).is_err());
    assert!(!copied.exists());
    let pin = vm_support::snapshot::copy_candidate(&source, &copied, 128).unwrap();
    assert_eq!(
        pin,
        vm_support::snapshot::digest(&copied).unwrap()
    );
    fs::write(&source, b"replacement").unwrap();
    assert!(vm_support::snapshot::copy_candidate(&source, &copied, 128).is_err());
    assert_eq!(
        fs::read(&copied).unwrap(),
        b"identified candidate"
    );
    let link = temporary.path().join("link");
    std::os::unix::fs::symlink(&source, &link).unwrap();
    assert!(
        vm_support::snapshot::copy_candidate(&link, &temporary.path().join("new"), 128).is_err()
    );
}

#[test]
fn concurrent_build_replacement_cannot_publish_partial_candidate_evidence() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("candidate");
    fs::write(&source, vec![1_u8; 8 * 1024 * 1024]).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_stop = std::sync::Arc::clone(&stop);
    let writer_source = source.clone();
    let (ready, started) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let replacement = writer_source.with_extension("build");
        let bytes = vec![2_u8; 8 * 1024 * 1024];
        ready.send(()).unwrap();
        while !writer_stop.load(Ordering::Relaxed) {
            fs::write(&replacement, &bytes).unwrap();
            fs::rename(&replacement, &writer_source).unwrap();
        }
    });
    started.recv().unwrap();
    let mut failures = 0;
    for index in 0..4 {
        let destination = temporary.path().join(format!("copy-{index}"));
        if let Ok(pin) =
            vm_support::snapshot::copy_candidate(&source, &destination, 16 * 1024 * 1024)
        {
            assert_eq!(
                pin,
                vm_support::snapshot::digest(&destination).unwrap()
            );
            let bytes = fs::read(&destination).unwrap();
            assert_eq!(bytes.len(), 8 * 1024 * 1024);
            assert!(bytes.iter().all(|byte| *byte == bytes[0]));
        } else {
            failures += 1;
            assert!(!destination.exists());
        }
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    assert!(
        failures > 0,
        "replacement must be observed during the bounded copies"
    );
    assert!(
        fs::read_dir(temporary.path())
            .unwrap()
            .all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".candidate-")
            })
    );
}

fn editor_fixture() -> (
    tempfile::TempDir,
    vm_support::editors::Inputs,
    vm_support::editors::Tools,
) {
    use vm_support::editors::{Inputs, Tools};
    let root = tempfile::tempdir().unwrap();
    let core = root.path().join("core");
    let vscode = root.path().join("vscode");
    let neovim = root.path().join("neovim");
    let opencode = root.path().join("opencode");
    for checkout in [&core, &vscode, &neovim, &opencode] {
        fs::create_dir_all(checkout.join("tests/fixtures")).unwrap();
        fs::write(
            checkout.join("tests/fixtures/lsp-contract.json"),
            b"contract",
        )
        .unwrap();
    }
    fs::create_dir(core.join("std")).unwrap();
    let binary = root.path().join("srx");
    fs::write(&binary, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o500)).unwrap();
    let tool = root.path().join("editor-tool");
    fs::write(
        &tool,
        b"#!/bin/sh\nprintf '%s\\n' \"$SRX_BIN\" \"$SRX_STD_DIR\" \"$XDG_STATE_HOME\" \"$*\"\n",
    )
    .unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
    (
        root,
        Inputs {
            core,
            binary,
            vscode,
            neovim,
            opencode,
            hosts: false,
        },
        Tools {
            npm: tool.clone(),
            neovim: tool,
        },
    )
}

#[test]
fn editor_checks_pin_candidate_and_run_optional_host_commands() {
    let (root, mut input, tools) = editor_fixture();
    for hosts in [false, true] {
        input.hosts = hosts;
        let evidence = root.path().join(if hosts {
            "hosts"
        } else {
            "local"
        });
        vm_support::editors::run(&input, &tools, &evidence).unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(evidence.join("report.json")).unwrap()).unwrap();
        assert_eq!(report["status"], "passed");
        assert_eq!(
            report["pending"].as_array().unwrap().len(),
            if hosts {
                0
            } else {
                2
            }
        );
        let logs: Vec<_> = fs::read_dir(&evidence)
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "log")
            })
            .collect();
        assert_eq!(
            logs.len(),
            if hosts {
                8
            } else {
                5
            }
        );
        for log in logs {
            let output = fs::read_to_string(log.path()).unwrap();
            assert!(output.contains(evidence.join("candidates/srx").to_str().unwrap()));
            assert!(output.contains(input.core.join("std").to_str().unwrap()));
        }
        assert!(vm_support::editors::run(&input, &tools, &evidence).is_err());
    }
}

#[test]
fn editor_contract_mismatch_and_command_failure_preserve_failed_report() {
    let (root, input, tools) = editor_fixture();
    fs::write(
        input
            .vscode
            .join("tests/fixtures/lsp-contract.json"),
        b"different",
    )
    .unwrap();
    let mismatch = root.path().join("mismatch");
    assert!(vm_support::editors::run(&input, &tools, &mismatch).is_err());
    assert!(!mismatch.join("vscode-check.log").exists());
    fs::write(
        input
            .vscode
            .join("tests/fixtures/lsp-contract.json"),
        b"contract",
    )
    .unwrap();
    fs::write(
        &tools.npm,
        b"#!/bin/sh\necho 'editor fixture failure'\nexit 13\n",
    )
    .unwrap();
    let failure = root.path().join("failure");
    assert!(vm_support::editors::run(&input, &tools, &failure).is_err());
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(failure.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["status"], "failed");
    assert!(
        fs::read_to_string(failure.join("vscode-check.log"))
            .unwrap()
            .contains("editor fixture failure")
    );
}

#[test]
fn registry_classifies_every_ignored_test_and_filters_restart_exactly() {
    let entries = common::gates();
    assert_eq!(entries.len(), 76);
    let counts: Vec<_> = [
        "gate",
        "qualification",
        "fixture",
        "benchmark",
        "network",
        "external",
    ]
    .into_iter()
    .map(|kind| {
        entries
            .iter()
            .filter(|gate| serde_json::to_value(gate.category).unwrap() == kind)
            .count()
    })
    .collect();
    assert_eq!(counts, [45, 1, 22, 4, 1, 3]);
    let selection = common::Selection::parse(&[
        "shell_restart".into(),
        "--nocapture".into(),
    ])
    .unwrap();
    let selected = selection.selected();
    assert_eq!(selected.len(), 2);
    let exact = common::Selection::parse(&[
        selected[0].name.clone(),
        "--exact".into(),
    ])
    .unwrap();
    assert_eq!(exact.selected().len(), 1);
    assert!(
        common::Selection::parse(&["missing-fixture".into()])
            .unwrap()
            .selected()
            .is_empty()
    );
    assert!(common::Selection::parse(&["--unknown".into()]).is_err());
}

#[test]
fn candidate_mutation_and_missing_fixture_are_failures() {
    let temporary = tempfile::tempdir().unwrap();
    let binary = temporary.path().join("candidate");
    fs::write(&binary, b"original").unwrap();
    let pins = BTreeMap::from([(
        "candidate".to_owned(),
        vm_support::snapshot::digest(&binary).unwrap(),
    )]);
    vm_support::snapshot::verify_files(temporary.path(), &pins).unwrap();
    fs::write(&binary, b"modified").unwrap();
    assert!(
        vm_support::snapshot::verify_files(temporary.path(), &pins)
            .unwrap_err()
            .to_string()
            .contains("pinned input changed")
    );
    fs::remove_file(binary).unwrap();
    assert!(vm_support::snapshot::verify_files(temporary.path(), &pins).is_err());
}

#[test]
fn cargo_artifact_discovery_accepts_selected_targets_and_refuses_ambiguity() {
    assert!(artifacts::artifacts("{\"reason\":\"build-finished\",\"success\":true}").is_err());
    let mut messages = Vec::new();
    for (name, kind, test) in [
        ("syrox_engine", "lib", true),
        ("srx", "bin", false),
        ("syrox-worker", "bin", false),
        ("build", "test", true),
        ("shell", "test", true),
        ("usability", "test", true),
    ] {
        messages.push(
            serde_json::json!({"reason":"compiler-artifact","executable":format!("/guest/{name}"),
            "target":{"name":name,"kind":[kind]},"profile":{"test":test}})
            .to_string(),
        );
    }
    let output = messages.join("\n");
    assert_eq!(artifacts::artifacts(&output).unwrap().len(), 6);
    messages.push(
        serde_json::json!({"reason":"compiler-artifact","executable":"/foreign/engine",
        "target":{"name":"syrox_engine","kind":["lib"]},"profile":{"test":true}})
        .to_string(),
    );
    assert!(artifacts::artifacts(&messages.join("\n")).is_err());
}

#[test]
fn failing_child_keeps_output_and_nonzero_status() {
    let temporary = tempfile::tempdir().unwrap();
    let control = vm_support::process::Control::new(None).unwrap();
    let log = temporary.path().join("failure.log");
    let error = vm_support::process::command(
        Command::new("sh").args([
            "-c",
            "printf 'fixture failure\n'; exit 7",
        ]),
        &log,
        Duration::from_secs(2),
        &control,
    )
    .unwrap_err();
    assert!(error.to_string().contains("command failed"));
    assert!(
        vm_support::process::read_log(&log)
            .unwrap()
            .contains("fixture failure")
    );
}

#[test]
fn timeout_terminates_the_process_group_and_preserves_partial_output() {
    let temporary = tempfile::tempdir().unwrap();
    let control = vm_support::process::Control::new(None).unwrap();
    let log = temporary.path().join("timeout.log");
    let error = vm_support::process::command(
        Command::new("sh")
            .args([
                "-c",
                "printf 'started\n'; sleep 30 & echo $! > child.pid; wait",
            ])
            .current_dir(temporary.path()),
        &log,
        Duration::from_millis(120),
        &control,
    )
    .unwrap_err();
    assert!(error.to_string().contains("timeout"));
    assert!(
        vm_support::process::read_log(&log)
            .unwrap()
            .contains("started")
    );
    let pid = fs::read_to_string(temporary.path().join("child.pid")).unwrap();
    // SIGKILL delivery to group members is asynchronous. Reaping the leader
    // does not mean its child has already reached the terminal kernel state.
    // procfs can return ESRCH if the child disappears during the status read.
    let until = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let status = fs::read_to_string(format!("/proc/{}/status", pid.trim()));
        match status {
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) =>
            {
                break;
            }
            Err(error) => panic!("cannot observe timed-out child: {error}"),
            Ok(status) => {
                if status.lines().any(|line| {
                    line.starts_with("State:")
                        && (line.contains("Z (zombie)") || line.contains("X (dead)"))
                }) {
                    break;
                }
                assert!(
                    std::time::Instant::now() < until,
                    "timed-out process group child remains live: {status}"
                );
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn cancellation_prevents_start_and_settles_running_child() {
    let temporary = tempfile::tempdir().unwrap();
    let control = vm_support::process::Control::new(None).unwrap();
    control.cancelled.store(true, Ordering::Relaxed);
    let log = temporary.path().join("not-started.log");
    assert!(
        vm_support::process::command(
            Command::new("sh").args(["-c", "exit 0"]),
            &log,
            Duration::from_secs(2),
            &control
        )
        .is_err()
    );
    assert!(!log.exists());
    control.cancelled.store(false, Ordering::Relaxed);
    let flag = std::sync::Arc::clone(&control.cancelled);
    let cancel = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        flag.store(true, Ordering::Relaxed);
    });
    let error = vm_support::process::command(
        Command::new("sh").args(["-c", "printf 'started\n'; sleep 30"]),
        &temporary.path().join("cancelled.log"),
        Duration::from_secs(2),
        &control,
    )
    .unwrap_err();
    cancel.join().unwrap();
    assert!(error.to_string().contains("cancelled"));
}

#[test]
fn source_capture_includes_dirty_and_new_bytes_and_omits_build_state() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("repo");
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "--quiet"]);
    fs::write(root.join("tracked.rs"), "committed").unwrap();
    fs::write(root.join(".gitignore"), "target/\n*.md\n").unwrap();
    git(&root, &["add", "."]);
    git(
        &root,
        &[
            "-c",
            "user.name=VM Regression",
            "-c",
            "user.email=vm@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "initial",
        ],
    );
    fs::write(root.join("tracked.rs"), "dirty").unwrap();
    fs::write(root.join("new.rs"), "new").unwrap();
    fs::create_dir(root.join("target")).unwrap();
    fs::write(root.join("target/should-not-copy"), "build").unwrap();
    fs::write(root.join("local-notes.md"), "ignored notes").unwrap();
    let destination = temporary.path().join("snapshot");
    let manifest = vm_support::snapshot::snapshot(&root, &destination).unwrap();
    assert_eq!(
        fs::read_to_string(destination.join("tracked.rs")).unwrap(),
        "dirty"
    );
    assert_eq!(
        fs::read_to_string(destination.join("new.rs")).unwrap(),
        "new"
    );
    assert!(!destination.join("target").exists());
    assert!(!destination.join("local-notes.md").exists());
    assert_eq!(
        fs::metadata(destination.join("new.rs"))
            .unwrap()
            .permissions()
            .mode()
            & 0o222,
        0
    );
    let pins = serde_json::from_value(manifest["files"].clone()).unwrap();
    fs::write(root.join("new.rs"), "later edit").unwrap();
    vm_support::snapshot::verify_files(&destination, &pins).unwrap();
    assert!(vm_support::snapshot::verify_files(&root, &pins).is_err());
    thaw(&destination);
}

fn git(root: &Path, arguments: &[&str]) {
    assert!(
        Command::new("git")
            .args(arguments)
            .current_dir(root)
            .output()
            .unwrap()
            .status
            .success()
    );
}

fn thaw(root: &Path) {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            thaw(&entry.path());
        }
    }
}

#[test]
fn normally_exited_leader_is_retained_until_descendants_are_stopped() {
    let temporary = tempfile::tempdir().unwrap();
    let control = vm_support::process::Control::new(None).unwrap();
    vm_support::process::command(
        Command::new("sh")
            .args(["-c", "(sleep 1; touch late) & exit 0"])
            .current_dir(temporary.path()),
        &temporary.path().join("exit.log"),
        Duration::from_secs(2),
        &control,
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    assert!(!temporary.path().join("late").exists());
}

#[test]
fn reports_reject_unknown_status_and_missing_required_gate_fields() {
    use vm_support::evidence::Report;
    for document in [
        serde_json::json!({"status":"success","selected":[]}),
        serde_json::json!({"status":"passed","selected":[],"gates":[{"name":"gate","status":"passed"}]}),
    ] {
        assert!(serde_json::from_value::<Report>(document).is_err());
    }
}

#[test]
#[allow(unsafe_code)]
fn ignored_sigchld_is_refused_before_spawn() {
    if std::env::var_os("SYROX_TEST_IGNORED_SIGCHLD").is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ignored_sigchld_is_refused_before_spawn",
            ])
            .env("SYROX_TEST_IGNORED_SIGCHLD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        common::require_one_passed(&String::from_utf8_lossy(&output.stdout)).unwrap();
        return;
    }
    // SAFETY: only this isolated regression process changes its disposition.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
    }
    let temporary = tempfile::tempdir().unwrap();
    let control = vm_support::process::Control::new(None).unwrap();
    let log = temporary.path().join("refused.log");
    let error = vm_support::process::command(
        Command::new("sh").args(["-c", "touch ran"]),
        &log,
        Duration::from_secs(2),
        &control,
    )
    .unwrap_err();
    assert!(error.to_string().contains("waitable children"));
    assert!(!log.exists());
}

#[test]
fn essential_suite_selects_eight_journeys_and_full_keeps_distinct_gates() {
    let selection = common::Selection::default().selected();
    assert_eq!(
        selection
            .iter()
            .map(|gate| gate.name.as_str())
            .collect::<Vec<_>>(),
        common::ESSENTIAL_GATES
    );
    assert!(
        selection
            .iter()
            .all(|gate| gate.category == common::Category::Gate)
    );
    let full = common::Selection::parse(&["--suite".into(), "full".into()])
        .unwrap()
        .selected();
    assert_eq!(
        full.len(),
        common::gates()
            .iter()
            .filter(|gate| gate.category == common::Category::Gate)
            .count()
    );
    assert!(full.len() > 8);
    for gate in full {
        let exact = common::Selection::parse(&[gate.name.clone(), "--exact".into()])
            .unwrap()
            .selected();
        assert_eq!(exact, vec![gate]);
    }
    assert!(common::Selection::parse(&["--suite".into(), "unknown".into()]).is_err());
    assert_eq!(
        common::gates()
            .iter()
            .filter(|gate| gate.category == common::Category::Qualification)
            .count(),
        1
    );
}

#[test]
fn resource_admission_uses_host_and_every_ancestor_without_overflow() {
    use vm_support::resources::VM_HOST_MARGIN;

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let child = root.join("child");
    fs::create_dir(&child).unwrap();
    fs::write(
        root.join("memory.max"),
        (6_u64 * 1024 * 1024 * 1024).to_string(),
    )
    .unwrap();
    fs::write(
        root.join("memory.current"),
        (4_u64 * 1024 * 1024 * 1024).to_string(),
    )
    .unwrap();
    fs::write(child.join("memory.max"), "max").unwrap();
    fs::write(child.join("memory.current"), "1000").unwrap();
    let result = vm_support::resources::available(
        "MemAvailable: 8388608 kB\n",
        root,
        &child,
        VM_HOST_MARGIN,
    )
    .unwrap();
    assert_eq!(
        result["available_bytes"],
        2_u64 * 1024 * 1024 * 1024
    );
    assert_eq!(result["ready"], true);
    fs::write(root.join("memory.current"), "0").unwrap();
    assert_eq!(
        vm_support::resources::available(
            "MemAvailable: 4194304 kB\n",
            root,
            &child,
            VM_HOST_MARGIN
        )
        .unwrap()["ready"],
        true
    );
    fs::write(root.join("memory.current"), u64::MAX.to_string()).unwrap();
    assert_eq!(
        vm_support::resources::available(
            "MemAvailable: 8388608 kB\n",
            root,
            &child,
            VM_HOST_MARGIN
        )
        .unwrap()["available_bytes"],
        0
    );
    assert!(vm_support::resources::available("missing", root, &child, VM_HOST_MARGIN).is_err());
    assert!(
        vm_support::resources::available(
            "MemAvailable: 8388608 kB",
            &child,
            root,
            VM_HOST_MARGIN
        )
        .is_err()
    );
}

#[test]
fn preparation_observes_low_memory_while_vm_admission_enforces_boot_reserve() {
    use vm_support::resources::{VM_HOST_MARGIN, available};

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let child = root.join("child");
    fs::create_dir(&child).unwrap();
    fs::write(
        root.join("memory.max"),
        VM_HOST_MARGIN.to_string(),
    )
    .unwrap();
    fs::write(root.join("memory.current"), "0").unwrap();
    fs::write(child.join("memory.max"), "max").unwrap();
    fs::write(child.join("memory.current"), "0").unwrap();

    let low_memory = "MemAvailable: 131072 kB\n";
    let preparation = available(low_memory, root, &child, 0).unwrap();
    assert_eq!(preparation["required_bytes"], 0);
    assert_eq!(
        preparation["available_bytes"],
        128_u64 * 1024 * 1024
    );
    assert_eq!(preparation["ready"], true);
    assert_eq!(
        available(low_memory, root, &child, VM_HOST_MARGIN).unwrap()["ready"],
        false
    );

    // The ancestor supplies exactly the VM plus 1 GiB of host reserve.
    let ample_host = "MemAvailable: 8388608 kB\n";
    let boundary = available(ample_host, root, &child, VM_HOST_MARGIN).unwrap();
    assert_eq!(boundary["required_bytes"], 1536_u64 * 1024 * 1024);
    assert_eq!(boundary["available_bytes"], VM_HOST_MARGIN);
    assert_eq!(boundary["ready"], true);
    fs::write(root.join("memory.current"), "1").unwrap();
    assert_eq!(
        available(ample_host, root, &child, VM_HOST_MARGIN).unwrap()["ready"],
        false
    );
    assert_eq!(
        available(ample_host, root, &child, 0).unwrap()["ready"],
        true
    );

    // A smaller descendant limit takes precedence over a roomy ancestor/host.
    fs::write(root.join("memory.current"), "0").unwrap();
    fs::write(child.join("memory.max"), "536870912").unwrap();
    let constrained = available(ample_host, root, &child, VM_HOST_MARGIN).unwrap();
    assert_eq!(
        constrained["available_bytes"],
        512_u64 * 1024 * 1024
    );
    assert_eq!(constrained["ready"], false);
}

#[test]
fn sdk_resources_refuse_hotplug_and_memory_growth() {
    let config = serde_json::json!({"resources":{"cpus":1,"max_cpus":1,"memory_mib":512,"max_memory_mib":512}});
    vm_support::resources::verify_vm(&config).unwrap();
    for field in [
        "cpus",
        "max_cpus",
        "memory_mib",
        "max_memory_mib",
    ] {
        let mut altered = config.clone();
        altered["resources"][field] = serde_json::json!(4096);
        assert!(vm_support::resources::verify_vm(&altered).is_err());
    }
}

#[cfg(feature = "vm-tests")]
#[test]
fn preparation_contains_only_selected_targets_and_one_pidfs_qualifier() {
    let gate = common::Selection::parse(&[
        common::ESSENTIAL_GATES[0].into(),
        "--exact".into(),
    ])
    .unwrap()
    .selected();
    assert_eq!(
        vm_support::candidates::targets(&gate),
        std::collections::BTreeSet::from([
            ("syrox-engine".into(), "lib".into()),
            ("syrox".into(), "vm_guest".into())
        ])
    );
    assert!(
        !vm_support::candidates::targets(&common::Selection::default().selected())
            .contains(&("syrox".into(), "usability".into()))
    );
}

#[test]
fn byte_identical_captures_reuse_times_and_failed_attempt_reversions_stay_fresh() {
    use std::fs::{File, FileTimes};
    use std::time::{Duration, UNIX_EPOCH};
    let root = tempfile::tempdir().unwrap();
    let compilation = root.path().join("target");
    let sources = root.path().join("sources");
    fs::create_dir(&compilation).unwrap();
    fs::create_dir(&sources).unwrap();
    let path = sources.join("input");
    let prepare = |bytes: &[u8], seconds: u64| {
        fs::write(&path, bytes).unwrap();
        File::open(&path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(seconds)))
            .unwrap();
        let pins = BTreeMap::from([(
            "input".into(),
            vm_support::snapshot::digest(&path).unwrap(),
        )]);
        vm_support::source_times::reuse(&compilation, &sources, &pins).unwrap();
        fs::metadata(&path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    assert_eq!(prepare(b"first", 100), 100);
    assert_eq!(
        prepare(b"first", 200),
        100,
        "identical bytes preserve freshness"
    );
    assert_eq!(prepare(b"changed; failed preparation", 300), 300);
    assert_eq!(
        prepare(b"first", 400),
        400,
        "reversion must invalidate outputs from the failed attempt"
    );
    assert_eq!(prepare(b"first", 500), 400);
}

#[test]
fn native_suite_requires_complete_counts_and_cannot_accept_gate_filters() {
    use vm_support::{common::Suite, native::require_complete};
    let args = ["--suite", "native"].map(str::to_owned);
    assert_eq!(
        common::Selection::parse(&args).unwrap().suite,
        Suite::Native
    );
    assert!(
        common::Selection::parse(&args)
            .unwrap()
            .selected()
            .is_empty()
    );
    for extra in ["fixture", "--exact", "--skip"] {
        let mut args = args.to_vec();
        args.extend([extra.to_owned(), "fixture".to_owned()]);
        assert!(common::Selection::parse(&args).is_err());
    }
    let valid = "test result: ok. 7 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out;";
    require_complete(valid, 10, 3).unwrap();
    for invalid in [
        valid.replace("7 passed", "6 passed"),
        valid.replace("3 ignored", "2 ignored"),
        valid.replace("0 filtered", "1 filtered"),
        valid.replace("ok.", "FAILED."),
    ] {
        assert!(require_complete(&invalid, 10, 3).is_err());
    }
    assert!(require_complete(valid, 0, 0).is_err());
    require_complete(
        "test result: ok. 0 passed; 0 failed; 3 ignored; 0 filtered out;",
        3,
        3,
    )
    .unwrap();
}

#[test]
fn native_evidence_rejects_omitted_duplicate_and_incomplete_targets() {
    use serde_json::json;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("report.json");
    let rows = vm_support::native::REQUIRED_TARGETS
        .map(|target| json!({"target":target,"status":"passed","total":10,"passed":7,"ignored":3}));
    let report =
        json!({"status":"passed","profile":"native","selected":[],"gates":[],"native":rows});
    vm_support::evidence::save(&path, &report).unwrap();
    let mut omitted = report.clone();
    omitted["native"].as_array_mut().unwrap().pop();
    assert!(vm_support::evidence::save(&path, &omitted).is_err());
    let mut duplicate = report.clone();
    duplicate["native"]
        .as_array_mut()
        .unwrap()
        .push(rows[0].clone());
    assert!(vm_support::evidence::save(&path, &duplicate).is_err());
    let mut incomplete = report;
    incomplete["native"][0]["passed"] = json!(6);
    assert!(vm_support::evidence::save(&path, &incomplete).is_err());
}

#[test]
fn release_bundle_rejects_different_sources_targets_and_executable_bytes() {
    use serde_json::json;
    let directory = tempfile::tempdir().unwrap();
    let mut elf = vec![0; 128];
    elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
    elf[16] = 3;
    elf[18] = 62;
    elf[32] = 64;
    elf[52] = 64;
    elf[54] = 56;
    elf[56] = 1;
    elf[64] = 1;
    for name in ["srx", "syrox-worker"] {
        fs::write(directory.path().join(name), &elf).unwrap();
    }
    let pin = vm_support::snapshot::digest(&directory.path().join("srx")).unwrap();
    let sources = BTreeMap::from([("Cargo.lock".to_owned(), "1".repeat(64))]);
    let manifest = json!({"schema":1,"target":"x86_64-unknown-linux-musl","rust":"1.98.1","sources":sources,"binaries":{"srx":pin,"syrox-worker":pin}});
    let path = directory.path().join("manifest.json");
    common::save(&path, &manifest).unwrap();
    vm_support::candidate_bundle::load(directory.path(), &sources, "1.98.1").unwrap();
    assert!(
        vm_support::candidate_bundle::load(directory.path(), &BTreeMap::new(), "1.98.1").is_err()
    );
    assert!(vm_support::candidate_bundle::load(directory.path(), &sources, "1.99.0").is_err());
    let mut invalid = manifest.clone();
    invalid["target"] = json!("aarch64-unknown-linux-musl");
    common::save(&path, &invalid).unwrap();
    assert!(vm_support::candidate_bundle::load(directory.path(), &sources, "1.98.1").is_err());
    common::save(&path, &manifest).unwrap();
    elf[127] = 1;
    fs::write(directory.path().join("syrox-worker"), elf).unwrap();
    assert!(vm_support::candidate_bundle::load(directory.path(), &sources, "1.98.1").is_err());
}

#[test]
fn preparation_parallelism_requires_a_positive_count_and_keeps_local_default() {
    let jobs = vm_support::resources::preparation_jobs;
    assert_eq!(jobs(None).unwrap(), 1);
    assert_eq!(jobs(Some("4")).unwrap(), 4);
    for invalid in [
        "0",
        "-1",
        "all",
        "4; exit",
        "99999999999999999999999999",
    ] {
        assert!(jobs(Some(invalid)).is_err());
    }
}

#[test]
fn embedded_worker_build_accepts_static_gnu_and_musl_and_refuses_dynamic_cli() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = tempfile::tempdir().unwrap();
    let script = directory.path().join("build-script");
    assert!(
        Command::new("rustc")
            .arg("--edition=2024")
            .arg(workspace.join("crates/syrox/build.rs"))
            .arg("-o")
            .arg(&script)
            .status()
            .unwrap()
            .success()
    );
    let mut elf = vec![0; 128];
    elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
    elf[16] = 3;
    elf[18] = 62;
    elf[32] = 64;
    elf[52] = 64;
    elf[54] = 56;
    elf[56] = 1;
    elf[64] = 1;
    let worker = directory.path().join("worker");
    fs::write(&worker, &elf).unwrap();
    for (target, features, accepted) in [
        (
            "x86_64-unknown-linux-gnu",
            "sse2,crt-static",
            true,
        ),
        (
            "x86_64-unknown-linux-musl",
            "crt-static,sse2",
            true,
        ),
        ("x86_64-unknown-linux-gnu", "sse2", false),
        ("x86_64-unknown-linux-musl", "sse2", false),
        ("aarch64-unknown-linux-musl", "crt-static", false),
    ] {
        let output = Command::new(&script)
            .env("TARGET", target)
            .env("CARGO_CFG_TARGET_FEATURE", features)
            .env("OUT_DIR", directory.path())
            .env("SYROX_EMBED_WORKER", &worker)
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            accepted,
            "{target}/{features}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if accepted {
            assert_eq!(
                fs::read(directory.path().join("syrox-worker.bin")).unwrap(),
                elf
            );
        }
    }
}

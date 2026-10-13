//! Exercise refusal, cancellation and cache reuse with fresh, real VM evidence.
#[path = "../tests/vm_support/mod.rs"]
pub mod vm_support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use vm_support::{
    Result, common,
    process::{self, Control},
    snapshot,
};

const GATE: &str = "systemd::tests::real_user_manager_start_query_reconnect_and_stop_gate";

fn report(path: &Path) -> Result<serde_json::Value> {
    let bytes = fs::read(path.join("report.json"))?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("VM report limit".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn completed_cleanup(document: &serde_json::Value) -> bool {
    document["vm_cleanup"]
        .as_str()
        .is_some_and(|value| value == "confirmed absent" || value.starts_with("destroyed;"))
}

fn startup_cancellation(case: PathBuf, marker: PathBuf) -> std::thread::JoinHandle<Result<()>> {
    std::thread::spawn(move || -> Result<()> {
        let deadline = Instant::now() + Duration::from_mins(10);
        loop {
            if let Ok(document) = report(&case) {
                if document["vm_cleanup"] == "pending" {
                    fs::write(&marker, b"cancel during VM startup")?;
                    return Ok(());
                }
                if document["status"] != "preparing" {
                    return Err("startup ended before cancellation boundary".into());
                }
            }
            if Instant::now() >= deadline {
                return Err("startup cancellation observation timed out".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })
}

fn invoke(
    root: &Path,
    evidence: &Path,
    mode: &str,
    control: &Control,
) -> Result<serde_json::Value> {
    let case = evidence.join(mode);
    let marker = evidence.join(format!("{mode}.cancel"));
    let mut command = Command::new(env!("CARGO"));
    command
        .args([
            "test",
            "--locked",
            "--features",
            "vm-tests",
            "-p",
            "syrox",
            "--test",
            "vm",
            "--",
            GATE,
            "--exact",
            "--nocapture",
        ])
        .current_dir(root)
        .env("SYROX_VM_EVIDENCE", &case)
        .env_remove("SYROX_VM_FAULT")
        .env_remove("SYROX_VM_CANCEL_FILE");
    let fault = [
        "test_failure",
        "timeout",
        "missing_fixture",
        "candidate_mutation",
    ]
    .contains(&mode);
    if fault {
        command.env("SYROX_VM_FAULT", mode);
    }
    if mode.starts_with("cancel_") {
        command.env("SYROX_VM_CANCEL_FILE", &marker);
    }
    if mode == "cancel_preparation" {
        fs::write(&marker, b"cancel before preparation")?;
    }
    let cancel_thread =
        (mode == "cancel_startup").then(|| startup_cancellation(case.clone(), marker.clone()));
    let result = process::command(
        &mut command,
        &evidence.join(format!("{mode}.log")),
        Duration::from_mins(30),
        control,
    );
    if let Some(thread) = cancel_thread {
        thread
            .join()
            .map_err(|_| "cancellation observer panicked")??;
    }
    let document = report(&case)?;
    let expected = if mode.starts_with("cancel_") {
        "cancelled"
    } else if fault {
        "failed"
    } else {
        "passed"
    };
    if document["status"] != expected || result.is_ok() != (expected == "passed") {
        return Err(format!("{mode}: unexpected VM result/status").into());
    }
    if mode == "cancel_preparation" {
        if document["vm_cleanup"] != "not-started" {
            return Err("preparation cancellation started a VM".into());
        }
    } else if !completed_cleanup(&document) {
        return Err(format!("{mode}: VM cleanup unconfirmed").into());
    }
    let guest = &document["guest"];
    let detail = guest["error"].as_str().unwrap_or("");
    let correct_refusal = match mode {
        "missing_fixture" => detail.contains("required fixture missing"),
        "candidate_mutation" => detail.contains("pinned input changed"),
        "timeout" => guest["gates"][0]["error"]
            .as_str()
            .is_some_and(|text| text.contains("timeout")),
        "test_failure" => guest["gates"][0]["status"] == "failed",
        _ => true,
    };
    if !correct_refusal {
        return Err(format!("{mode}: failure did not prove the injected refusal").into());
    }
    Ok(document)
}

fn verify_evidence(case: &Path, document: &serde_json::Value) -> Result<()> {
    let candidates = serde_json::from_value(document["guest"]["binaries"].clone())?;
    snapshot::verify_files(&case.join("candidates"), &candidates)?;
    let binaries: BTreeMap<String, String> =
        serde_json::from_value(document["guest"]["artifact_pins"].clone())?;
    for (path, pin) in binaries {
        let relative = path
            .strip_prefix("/evidence/")
            .ok_or("unbound artifact evidence path")?;
        if snapshot::digest(&case.join(relative))? != pin {
            return Err("earlier run evidence changed after cache reuse".into());
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let evidence = PathBuf::from(
        args.next()
            .ok_or("usage: verify_vm_harness FRESH_EVIDENCE")?,
    );
    if args.next().is_some() || evidence.exists() {
        return Err("fresh acceptance evidence required".into());
    }
    common::private(&evidence)?;
    let evidence = evidence.canonicalize()?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let control = Control::new(None)?;
    let mut summary = serde_json::json!({"status":"preparing","cases":[],"one_vm_per_run":true});
    let result = (|| {
        let first = invoke(&root, &evidence, "baseline", &control)?;
        for mode in [
            "test_failure",
            "timeout",
            "missing_fixture",
            "candidate_mutation",
            "cancel_preparation",
            "cancel_startup",
        ] {
            let document = invoke(&root, &evidence, mode, &control)?;
            summary["cases"].as_array_mut().ok_or("case array")?.push(serde_json::json!({"case":mode,"status":"proved","run_status":document["status"],"vm_cleanup":document["vm_cleanup"]}));
            common::save(&evidence.join("report.json"), &summary)?;
        }
        let second = invoke(&root, &evidence, "reuse", &control)?;
        if first["compilation_key"] != second["compilation_key"]
            || first["guest"]["binaries"] != second["guest"]["binaries"]
        {
            return Err(
                "cache reuse changed pinned candidates for identical sources/environment".into(),
            );
        }
        verify_evidence(&evidence.join("baseline"), &first)?;
        verify_evidence(&evidence.join("reuse"), &second)?;
        summary["cache_reuse"] = serde_json::json!({"status":"proved","compilation_key":first["compilation_key"],"candidate_pins":first["guest"]["binaries"],"earlier_evidence":"preserved"});
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })();
    summary["status"] = serde_json::json!(if result.is_ok() {
        "passed"
    } else {
        "failed"
    });
    if let Err(error) = &result {
        summary["error"] = serde_json::json!(error.to_string());
    }
    common::save(&evidence.join("report.json"), &summary)?;
    result
}

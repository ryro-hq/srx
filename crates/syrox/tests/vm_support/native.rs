//! Execute prepared libtests in the qualified kernel, without compiling in the guest.
use super::{
    Result, common,
    process::{self, Control},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub const REQUIRED_TARGETS: [&str; 3] = [
    "syrox-engine/lib",
    "syrox-lang/lib",
    "syrox/cli",
];

pub fn require_complete(output: &str, total: usize, ignored: usize) -> Result<()> {
    if total == 0 || ignored > total {
        return Err("native target requires a nonempty valid inventory".into());
    }
    let summary = output
        .lines()
        .rev()
        .find(|line| line.starts_with("test result:"))
        .ok_or("native target did not report a libtest summary")?;
    let expected = format!(
        "test result: ok. {} passed; 0 failed; {ignored} ignored;",
        total - ignored
    );
    if !summary.starts_with(&expected) || !summary.contains("0 filtered out;") {
        return Err("native target results differ from its complete inventory".into());
    }
    Ok(())
}

pub fn run(
    artifacts: &BTreeMap<String, PathBuf>,
    evidence: &Path,
    control: &Control,
) -> Result<Vec<Value>> {
    let mut results = Vec::new();
    for (name, binary) in artifacts
        .iter()
        .filter(|(name, _)| name.contains('/') && !name.ends_with("/vm_guest"))
    {
        let label = name.replace('/', "--");
        let list = process::command(
            Command::new(binary).arg("--list"),
            &evidence.join(format!("native-{label}-list.log")),
            Duration::from_secs(30),
            control,
        )?;
        let total = list
            .lines()
            .filter(|line| line.ends_with(": test"))
            .count();
        let ignored = process::command(
            Command::new(binary).args(["--list", "--ignored"]),
            &evidence.join(format!("native-{label}-ignored.log")),
            Duration::from_secs(30),
            control,
        )?
        .lines()
        .filter(|line| line.ends_with(": test"))
        .count();
        if total == 0 {
            results.push(json!({"target":name,"status":"empty","total":0,"ignored":0}));
            continue;
        }
        let output = process::command(
            Command::new(binary)
                .arg("--test-threads=1")
                .env("TMPDIR", "/work/native-tmp")
                .current_dir("/work/src"),
            &evidence.join(format!("native-{label}.log")),
            Duration::from_mins(15),
            control,
        )?;
        require_complete(&output, total, ignored)?;
        results.push(json!({"target":name,"status":if total == ignored {"ignored"} else {"passed"},"total":total,"passed":total-ignored,"ignored":ignored}));
        common::save(
            &evidence.join("native-targets.json"),
            &json!(results),
        )?;
    }
    if !REQUIRED_TARGETS.iter().all(|required| {
        results
            .iter()
            .any(|row| row["target"] == *required && row["status"] == "passed")
    }) {
        return Err("native suite omitted a required nonempty target".into());
    }
    Ok(results)
}

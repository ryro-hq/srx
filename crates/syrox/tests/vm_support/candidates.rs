//! Prepare release candidates before VM startup in a pinned container using host resources.
use super::{
    Result, artifacts, common,
    config::Config,
    process::{self, Control},
    snapshot,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub fn targets(selected: &[common::Gate]) -> BTreeSet<(String, String)> {
    selected
        .iter()
        .map(|gate| (gate.package.clone(), gate.target.clone()))
        .chain([
            ("syrox-engine".into(), "lib".into()),
            ("syrox".into(), "vm_guest".into()),
        ])
        .collect()
}

pub fn prepare(
    config: &Config,
    evidence: &Path,
    vendor: &Path,
    compilation: &Path,
    control: &Control,
) -> Result<Value> {
    let selected: Vec<common::Gate> =
        serde_json::from_slice(&fs::read(evidence.join("selected.json"))?)?;
    let targets = targets(&selected);
    let source_manifest: Value =
        serde_json::from_slice(&fs::read(evidence.join("source-manifest.json"))?)?;
    let source_pins = serde_json::from_value(source_manifest["files"].clone())?;
    super::source_times::reuse(
        compilation,
        &evidence.join("sources"),
        &source_pins,
    )?;
    let image = config
        .preparation_image
        .as_deref()
        .unwrap_or(&config.image);
    let inspection = process::command(
        Command::new("docker").args(["image", "inspect", image]),
        &evidence.join("preparation-image.json"),
        Duration::from_secs(30),
        control,
    )?;
    let inspection: Value = serde_json::from_str(&inspection)?;
    let image_id = inspection[0]["Id"]
        .as_str()
        .ok_or("preparation image ID unavailable")?;
    let mut script = String::from(
        r#"set -euxo pipefail
trap 'cat /sys/fs/cgroup/cpu.stat > /evidence/preparation-cpu-final.txt; cat /sys/fs/cgroup/memory.peak > /evidence/preparation-memory-peak.txt' EXIT
cat /sys/fs/cgroup/cpu.stat > /evidence/preparation-cpu-initial.txt
cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.swap.max > /evidence/preparation-effective-limits.txt
export PATH=/opt/rust/bin:/usr/local/cargo/bin:/usr/bin:/bin
export CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export RUST_TEST_THREADS=1 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export RUSTFLAGS='-C target-feature=+crt-static' LZMA_API_STATIC=1
mkdir -p "$CARGO_HOME"
cat > "$CARGO_HOME/config.toml" <<'CONFIG'
[source.crates-io]
replace-with = "vendored"
[source.vendored]
directory = "/vendor"
CONFIG
cd /work/src
rustc --version --verbose > /evidence/preparation-toolchain.log
test "$(rustc --version | cut -d' ' -f2)" = "$(sed -n 's/channel = "\(.*\)"/\1/p' rust-toolchain.toml)"
sha256sum "$(command -v rustc)" "$(command -v gcc)" >> /evidence/preparation-toolchain.log
cargo build --release --locked --offline -p syrox --bins --target x86_64-unknown-linux-gnu --message-format=json > /evidence/release-build.jsonl
"#,
    );
    let mut build = String::from(
        "cargo test --locked --offline --no-default-features --no-run --target x86_64-unknown-linux-gnu --features vm-guest -p syrox -p syrox-engine --lib",
    );
    for (package, target) in &targets {
        if !["syrox", "syrox-engine"].contains(&package.as_str())
            || ![
                "lib",
                "vm_guest",
                "build",
                "shell",
                "usability",
            ]
            .contains(&target.as_str())
        {
            return Err("unregistered preparation target".into());
        }
        if target != "lib" {
            write!(build, " --test {target}")?;
        }
    }
    writeln!(
        script,
        "{build} --message-format=json > /evidence/candidate-build.jsonl"
    )?;
    script.push_str(r#"mkdir -p /evidence/prepared-payloads
for name in session-payload path-payload; do
    gcc -std=c11 -static -no-pie -O2 -Wall -Wextra -Werror "tests/fixtures/$name.c" -o "/evidence/prepared-payloads/$name"
done
gcc -std=c11 -O2 -Wall -Wextra -Werror crates/syrox/tests/vm_support/capabilities.c -o /evidence/prepared-payloads/capabilities
"#);
    fs::write(evidence.join("prepare-candidates.sh"), script)?;
    let name = format!("syrox-prep-{}", super::host::run_id()?);
    let mut command = Command::new("docker");
    command.args([
        "create",
        "--name",
        &name,
        "--network=none",
        "--pids-limit=256",
        "--user=1000:1000",
        "--entrypoint=/bin/bash",
        "--tmpfs=/tmp:rw,nosuid,nodev,size=512m",
    ]);
    for (source, destination, readonly) in [
        (evidence.join("sources"), "/work/src", true),
        (evidence.to_path_buf(), "/evidence", false),
        (vendor.to_path_buf(), "/vendor", true),
        (compilation.to_path_buf(), "/target", false),
    ] {
        command.arg("--mount").arg(format!(
            "type=bind,src={},dst={destination}{}",
            source.display(),
            if readonly {
                ",readonly"
            } else {
                ""
            }
        ));
    }
    command
        .arg(image_id)
        .arg("/evidence/prepare-candidates.sh");
    let outcome: Result<Value> = (|| {
        process::command(
            &mut command,
            &evidence.join("preparation-create.log"),
            Duration::from_secs(30),
            control,
        )?;
        let info = process::command(
            Command::new("docker").args(["inspect", &name]),
            &evidence.join("preparation-config.json"),
            Duration::from_secs(30),
            control,
        )?;
        let info: Value = serde_json::from_str(&info)?;
        let host = &info[0]["HostConfig"];
        process::command(
            Command::new("docker").args(["start", "--attach", &name]),
            &evidence.join("preparation.log"),
            Duration::from_hours(2),
            control,
        )?;
        let state = process::command(
            Command::new("docker").args(["inspect", &name]),
            &evidence.join("preparation-final.json"),
            Duration::from_secs(30),
            control,
        )?;
        let state: Value = serde_json::from_str(&state)?;
        if state[0]["State"]["ExitCode"] != 0 || state[0]["State"]["OOMKilled"] != false {
            return Err("preparation failed or was OOM-killed; inspect preparation.log".into());
        }
        let mut compiled = artifacts::artifacts(&process::read_log(
            &evidence.join("candidate-build.jsonl"),
        )?)?;
        let release = artifacts::artifacts(&process::read_log(
            &evidence.join("release-build.jsonl"),
        )?)?;
        for name in ["srx", "syrox-worker"] {
            compiled.insert(
                name.to_owned(),
                release
                    .get(name)
                    .ok_or("release candidate missing")?
                    .clone(),
            );
        }
        for path in compiled.values_mut() {
            *path = compilation.join(path.strip_prefix("/target")?);
        }
        for key in targets
            .iter()
            .map(|(package, target)| format!("{package}/{target}"))
            .chain(["srx".into(), "syrox-worker".into()])
        {
            if !compiled.contains_key(&key) {
                return Err(format!("selected artifact missing: {key}").into());
            }
        }
        let frozen = artifacts::freeze(&compiled, evidence, control)?;
        let manifest: BTreeMap<_, _> = frozen
            .iter()
            .map(|(key, path)| {
                Ok((
                    key.clone(),
                    format!(
                        "/evidence/{}",
                        path.strip_prefix(evidence)?.display()
                    ),
                ))
            })
            .collect::<Result<_>>()?;
        common::save(
            &evidence.join("prepared-artifacts.json"),
            &manifest,
        )?;
        let pins: BTreeMap<_, _> = frozen
            .iter()
            .map(|(key, path)| Ok((manifest[key].clone(), snapshot::digest(path)?)))
            .chain(
                [
                    "session-payload",
                    "path-payload",
                    "capabilities",
                ]
                .into_iter()
                .map(|name| {
                    Ok((
                        format!("/evidence/prepared-payloads/{name}"),
                        snapshot::digest(&evidence.join("prepared-payloads").join(name))?,
                    ))
                }),
            )
            .collect::<Result<_>>()?;
        common::save(&evidence.join("prepared-pins.json"), &pins)?;
        Ok(
            json!({"image_id":image_id,"targets":targets,"candidate_profile":"release","fixture_profile":"test","features":["vm-guest"],"default_features":false,"resource_policy":"host-inherited","configuration":host,"state":state[0]["State"],"artifacts":manifest,"pins":pins, "resource_measurement":{"memory_peak_bytes":fs::read_to_string(evidence.join("preparation-memory-peak.txt"))?.trim().parse::<u64>()?,"cpu_initial":fs::read_to_string(evidence.join("preparation-cpu-initial.txt"))?,"cpu_final":fs::read_to_string(evidence.join("preparation-cpu-final.txt"))?,"effective_limits":fs::read_to_string(evidence.join("preparation-effective-limits.txt"))?}}),
        )
    })();
    if !evidence.join("preparation-final.json").exists() {
        let _ = process::command(
            Command::new("docker").args(["inspect", &name]),
            &evidence.join("preparation-final.json"),
            Duration::from_secs(30),
            &Control::uncancelled(),
        );
    }
    let cleanup = process::command(
        Command::new("docker").args(["rm", "--force", &name]),
        &evidence.join("preparation-cleanup.log"),
        Duration::from_secs(30),
        &Control::uncancelled(),
    );
    common::save(
        &evidence.join("preparation-report.json"),
        &json!({
            "status":if outcome.is_ok() {"passed"} else if control.check().is_err() {"cancelled"} else {"failed"},
            "error":outcome.as_ref().err().map(ToString::to_string),
            "cleanup":if cleanup.is_ok() {"container removed"} else {"unconfirmed"},
            "cleanup_error":cleanup.as_ref().err().map(ToString::to_string)
        }),
    )?;
    cleanup?;
    outcome
}

//! Exact Cargo package/target/libtest inventory. Listing is never passing evidence.
use super::{
    Result, common,
    process::{self, Control},
    snapshot,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn names(output: &str) -> BTreeSet<String> {
    output
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .map(str::to_owned)
        .collect()
}

/// Subprocess fixture output may interleave individual libtest lines. A full
/// target summary proves all selected names only with matching identity/counts.
pub fn complete_target_passed(log: &str, executable: &Path, total: usize, ignored: usize) -> bool {
    let Some(filename) = executable
        .file_name()
        .and_then(|name| name.to_str())
    else {
        return false;
    };
    let suffix = format!("/{filename})");
    let mut section = false;
    let mut last_summary = None;
    for line in log.lines() {
        if line.trim_start().starts_with("Running ") {
            if section {
                break;
            }
            section = line.ends_with(&suffix);
        } else if section && line.trim_start().starts_with("Doc-tests ") {
            break;
        } else if section && line.starts_with("test result:") {
            last_summary = Some(line);
        }
    }
    let expected = format!(
        "test result: ok. {} passed; 0 failed; {ignored} ignored;",
        total.saturating_sub(ignored)
    );
    last_summary.is_some_and(|line| line.starts_with(&expected) && line.contains("0 filtered out;"))
}

fn requirements(package: &str, target: &str, name: &str) -> &'static str {
    if package == "syrox-lang" {
        "Rust 1.98.1; bounded source text in memory; cancellation tokens"
    } else if package == "syrox" && target != "lib" {
        "Linux; compiled CLI/worker; bundled std; private temporary filesystem; subprocesses; target fixtures"
    } else if name.contains("terminal") {
        "Linux; private PTY/devpts; foreground/session operations; process/descriptor observation"
    } else if name.contains("systemd") || name.contains("transport") || name.contains("launcher") {
        "Linux; private local Unix IPC and descriptor passing; filesystem locks; subprocesses as required"
    } else if name.contains("https") || name.contains("github") {
        "Linux; private local sockets/TLS fixtures; bounded filesystem; cancellation; live network only when explicit"
    } else {
        "Linux; private filesystem; trusted descriptors and locks; process/IPC primitives as required by the exact case"
    }
}

pub fn run(root: &Path, evidence: &Path, results_log: &Path) -> Result<()> {
    if evidence.exists() {
        return Err("inventory evidence already exists".into());
    }
    common::private(evidence)?;
    let control = Control::new(None)?;
    let sources = snapshot::snapshot(root, &evidence.join("sources"))?;
    common::save(&evidence.join("source-manifest.json"), &sources)?;
    let metadata = process::command(
        Command::new(env!("CARGO"))
            .args([
                "metadata",
                "--locked",
                "--offline",
                "--no-deps",
                "--format-version=1",
            ])
            .current_dir(root),
        &evidence.join("metadata.json"),
        Duration::from_mins(2),
        &control,
    )?;
    let metadata: Value = serde_json::from_str(&metadata)?;
    let packages: BTreeMap<_, _> = metadata["packages"]
        .as_array()
        .ok_or("Cargo packages")?
        .iter()
        .map(|package| {
            Ok((
                package["id"]
                    .as_str()
                    .ok_or("package ID")?
                    .to_owned(),
                package["name"]
                    .as_str()
                    .ok_or("package name")?
                    .to_owned(),
            ))
        })
        .collect::<Result<_>>()?;
    let output = process::command(
        Command::new(env!("CARGO"))
            .args([
                "test",
                "--workspace",
                "--locked",
                "--offline",
                "--no-default-features",
                "--no-run",
                "--message-format=json",
            ])
            .current_dir(root),
        &evidence.join("cargo-artifacts.jsonl"),
        Duration::from_mins(30),
        &control,
    )?;
    let mut targets = BTreeMap::new();
    for line in output.lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" || message["profile"]["test"] != true {
            continue;
        }
        let Some(package) = message["package_id"]
            .as_str()
            .and_then(|id| packages.get(id))
        else {
            continue;
        };
        let Some(executable) = message["executable"].as_str() else {
            continue;
        };
        let kind = message["target"]["kind"][0]
            .as_str()
            .ok_or("target kind")?;
        let target = if kind == "lib" {
            "lib"
        } else {
            message["target"]["name"]
                .as_str()
                .ok_or("target name")?
        };
        if let Some(previous) = targets.insert(
            (package.clone(), target.to_owned()),
            PathBuf::from(executable),
        ) && previous != Path::new(executable)
        {
            return Err("ambiguous inventory target".into());
        }
    }
    let observed = fs::read_to_string(results_log)?;
    fs::copy(results_log, evidence.join("results.log"))?;
    let fixtures: BTreeMap<String, Vec<String>> =
        serde_json::from_str(include_str!("fixtures.json"))?;
    let gates = common::gates();
    let mut rows = Vec::new();
    let mut actual_ignored = BTreeSet::new();
    let mut binary_pins = BTreeMap::new();
    for (index, ((package, target), executable)) in targets.iter().enumerate() {
        let binary_pin = snapshot::digest(executable)?;
        binary_pins.insert(format!("{package}/{target}"), binary_pin.clone());
        let listed = process::command(
            Command::new(executable).args(["--list", "--format=terse"]),
            &evidence.join(format!("list-{index}.log")),
            Duration::from_secs(30),
            &control,
        )?;
        let ignored = names(&process::command(
            Command::new(executable).args(["--list", "--ignored", "--format=terse"]),
            &evidence.join(format!("ignored-{index}.log")),
            Duration::from_secs(30),
            &control,
        )?);
        let listed_names = names(&listed);
        let target_passed = complete_target_passed(
            &observed,
            executable,
            listed_names.len(),
            ignored.len(),
        );
        for name in listed_names {
            let gate = gates.iter().find(|gate| {
                &gate.package == package && &gate.target == target && gate.name == name
            });
            if ignored.contains(&name) {
                actual_ignored.insert((package.clone(), target.clone(), name.clone()));
            }
            let parents = fixtures.get(&name).cloned().unwrap_or_default();
            let individual = observed
                .lines()
                .filter_map(|line| line.strip_prefix("test "))
                .filter_map(|line| line.split_once(" ... "))
                .filter(|(test, _)| *test == name)
                .map(|(_, status)| status)
                .next_back()
                .unwrap_or("not_observed");
            let status = if !parents.is_empty()
                || gate.is_some_and(|gate| gate.category == common::Category::Fixture)
            {
                "auxiliary_only"
            } else if ignored.contains(&name) {
                "ignored"
            } else if target_passed {
                "passed"
            } else {
                "not_proven"
            };
            let category = gate.map_or_else(
                || {
                    if parents.is_empty() {
                        "regression"
                    } else {
                        "subprocess_fixture"
                    }
                    .to_owned()
                },
                |gate| {
                    serde_json::to_value(gate.category)
                        .expect("category")
                        .as_str()
                        .expect("category text")
                        .to_owned()
                },
            );
            rows.push(json!({"package":package,"target":target,"name":name,
                "purpose":name.rsplit("::").next().unwrap_or(&name).replace('_'," "),
                "requirements":gate.map_or(requirements(package,target,&name),|gate|gate.reason.as_str()),
                "preparation":if parents.is_empty() { "Cargo builds the target; the exact test creates its private fixtures. VM gates use qualified guest preparation." } else { "Invoke only through the listed parent tests with their environment/descriptor contract." },
                "fixture_parents":parents,"category":category,"ignored":ignored.contains(&name),
                "evidence":{"binary_sha256":binary_pin,"listing":format!("list-{index}.log"),"result":status,"individual_output":individual,"complete_target_passed":target_passed,"results_log":"results.log"},
                "pending":if ignored.contains(&name) { "Requires separate gate/external evidence for these sources; listing does not approve it." } else if category == "subprocess_fixture" { "An ordinary no-op fixture pass is not a standalone behavioral assertion; use parent evidence." } else { "" }
            }));
        }
        if snapshot::digest(executable)? != binary_pin {
            return Err("inventory binary changed".into());
        }
    }
    let registered: BTreeSet<_> = gates
        .iter()
        .map(|gate| {
            (
                gate.package.clone(),
                gate.target.clone(),
                gate.name.clone(),
            )
        })
        .collect();
    if actual_ignored != registered {
        return Err(format!(
            "unclassified/missing ignored tests: {:?} / {:?}",
            actual_ignored.difference(&registered),
            registered.difference(&actual_ignored)
        )
        .into());
    }
    for (fixture, parents) in &fixtures {
        for name in std::iter::once(fixture).chain(parents) {
            if !rows.iter().any(|row| row["name"] == *name) {
                return Err(
                    format!("fixture or parent missing from exact inventory: {name}").into(),
                );
            }
        }
    }
    let mut table = String::from(
        "# Exact test matrix\n\nPackage, target and libtest name are the identity. A listed or no-op fixture test does not establish behavioral coverage.\n\n| Package | Target | Exact name | Category | Requirements | Preparation | Fixture parents | Evidence/result | Pending |\n|---|---|---|---|---|---|---|---|---|\n",
    );
    for row in &rows {
        let clean = |value: &Value| {
            value
                .as_str()
                .unwrap_or("")
                .replace('|', "\\|")
                .replace('\n', " ")
        };
        writeln!(
            table,
            "| {} | {} | `{}` | {} | {} | {} | {} | {} | {} |",
            clean(&row["package"]),
            clean(&row["target"]),
            clean(&row["name"]),
            clean(&row["category"]),
            clean(&row["requirements"]),
            clean(&row["preparation"]),
            row["fixture_parents"],
            clean(&row["evidence"]["result"]),
            clean(&row["pending"])
        )?;
    }
    fs::write(evidence.join("matrix.md"), table)?;
    common::save(
        &evidence.join("matrix.json"),
        &json!({"schema":1,"source_sha256":sources["sha256"],"features":"--no-default-features","binary_pins":binary_pins,"tests":rows}),
    )?;
    snapshot::verify_files(
        root,
        &serde_json::from_value(sources["files"].clone())?,
    )?;
    println!(
        "Exact test matrix: {}",
        evidence.join("matrix.json").display()
    );
    Ok(())
}

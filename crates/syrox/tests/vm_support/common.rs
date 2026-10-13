use super::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

pub const SDK_VERSION: &str = "0.7.3";
pub const GUEST_CANDIDATES: &str = "/work/candidates";
pub const MAX_LOG: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    TestFailure,
    Timeout,
    MissingFixture,
    CandidateMutation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Gate,
    Qualification,
    Fixture,
    Benchmark,
    Network,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub package: String,
    pub target: String,
    pub name: String,
    pub category: Category,
    pub group: String,
    pub reason: String,
}

impl Gate {
    pub fn label(&self) -> String {
        format!("{}::{}", self.group, self.name)
    }
}

pub fn gates() -> Vec<Gate> {
    serde_json::from_str(include_str!("gates.json")).expect("checked-in gate registry")
}

#[derive(Debug, Default)]
pub struct Selection {
    pub filters: Vec<String>,
    pub skips: Vec<String>,
    pub exact: bool,
    pub list: bool,
    pub full: bool,
}

impl Selection {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut selection = Self::default();
        let mut arguments = args.iter();
        while let Some(arg) = arguments.next() {
            match arg.as_str() {
                "--list" => selection.list = true,
                "--suite" => match arguments.next().map(String::as_str) {
                    Some("full") => selection.full = true,
                    Some("essential") => selection.full = false,
                    _ => return Err("--suite requires essential or full".into()),
                },
                "--exact" => selection.exact = true,
                "--skip" => selection.skips.push(
                    arguments
                        .next()
                        .ok_or("missing --skip value")?
                        .clone(),
                ),
                "--test-threads" | "--format" | "--color" => {
                    arguments
                        .next()
                        .ok_or("missing test option value")?;
                }
                "--nocapture" | "--show-output" | "--ignored" | "--include-ignored" | "--quiet"
                | "-q" | "--" => {}
                value
                    if value.starts_with("--test-threads=")
                        || value.starts_with("--format=")
                        || value.starts_with("--color=") => {}
                value if value.starts_with('-') => {
                    return Err(format!("unsupported libtest option: {value}").into());
                }
                value => selection.filters.push(value.to_owned()),
            }
        }
        Ok(selection)
    }

    pub fn selected(&self) -> Vec<Gate> {
        let mut selected: Vec<_> = gates()
            .into_iter()
            .filter(|gate| gate.category == Category::Gate)
            .filter(|gate| {
                (self.filters.is_empty()
                    && (self.full || ESSENTIAL_GATES.contains(&gate.name.as_str())))
                    || self.filters.iter().any(|filter| {
                        if self.exact {
                            gate.label() == *filter || gate.name == *filter
                        } else {
                            gate.label().contains(filter)
                        }
                    })
            })
            .filter(|gate| {
                !self
                    .skips
                    .iter()
                    .any(|skip| gate.label().contains(skip))
            })
            .collect();
        selected.sort_by_key(|gate| {
            ESSENTIAL_GATES
                .iter()
                .position(|name| *name == gate.name)
                .unwrap_or(usize::MAX)
        });
        selected
    }
}

pub fn validate_selection(selected: &[Gate], ecosystem: bool) -> Result<()> {
    let registered = gates();
    let mut identities = std::collections::BTreeSet::new();
    if selected.is_empty() && !ecosystem {
        return Err("unregistered or empty gate selection".into());
    }
    for gate in selected {
        if gate.category != Category::Gate
            || !registered.contains(gate)
            || !identities.insert((&gate.package, &gate.target, &gate.name))
        {
            return Err("unregistered, altered or duplicate gate identity".into());
        }
    }
    Ok(())
}

pub fn require_one_passed(output: &str) -> Result<()> {
    let summaries: Vec<_> = output
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect();
    if summaries.len() != 1
        || !summaries[0].starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;")
    {
        return Err("gate must execute exactly one passing test, with no ignored tests".into());
    }
    Ok(())
}

pub fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    let stage = path.with_extension("json.stage");
    fs::write(&stage, serde_json::to_vec_pretty(value)?)?;
    fs::rename(stage, path)?;
    Ok(())
}

pub fn private(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Ordered default product journeys; pidfs qualification runs separately once.
pub const ESSENTIAL_GATES: [&str; 8] = [
    "build::managed::execution::tests::host_managed_directory_build_publishes_verified_artifact_without_toolchain",
    "host_build_prefix_materializes_and_runs_at_its_action_path",
    "runtime::tests::host_dynamic_runtime_uses_only_declared_loader_and_library",
    "runtime::tests::host_runtime_cancellation_settles_before_releasing_retention",
    "deployment::shell::managed::tests::state::session_state_persists_between_commands_isolates_sessions_and_closes_after_settlement",
    "execution::launcher::os::tests::restart::automatic_restart_reopens_pins_limits_attempts_and_refuses_revoked_payload",
    "interactive::interactive_literal_resize_exit_and_restore",
    "interactive::interactive_ctrl_c_status_and_restore",
];

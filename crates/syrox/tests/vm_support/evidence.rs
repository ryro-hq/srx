//! Stable typed report boundaries. SDK-specific observations remain extensible.
use super::{Result, common::Gate};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Preparing,
    Passed,
    Failed,
    Cancelled,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    NotRun,
    Running,
    Passed,
    Failed,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    pub name: String,
    pub package: String,
    pub target: String,
    pub status: GateStatus,
    pub log: PathBuf,
    pub workspace: PathBuf,
    #[serde(flatten)]
    pub diagnostics: BTreeMap<String, Value>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub status: RunStatus,
    pub selected: Vec<Gate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gates: Option<Vec<GateReport>>,
    #[serde(flatten)]
    pub observations: BTreeMap<String, Value>,
}

pub fn save(path: &Path, document: &Value) -> Result<()> {
    let report: Report = serde_json::from_value(document.clone())?;
    if let Some(gates) = &report.gates {
        let mut seen = std::collections::BTreeSet::new();
        for gate in gates {
            let identity = (&gate.package, &gate.target, &gate.name);
            if !seen.insert(identity)
                || !report.selected.iter().any(|selected| {
                    selected.package == gate.package
                        && selected.target == gate.target
                        && selected.name == gate.name
                })
            {
                return Err("unknown or duplicate gate report identity".into());
            }
        }
        if report.status == RunStatus::Passed
            && (gates.len() != report.selected.len()
                || gates
                    .iter()
                    .any(|gate| gate.status != GateStatus::Passed))
        {
            return Err("passed report did not execute every selected gate".into());
        }
    }
    if report.status == RunStatus::Passed && document["profile"] == "native" {
        let targets = document["native"]
            .as_array()
            .ok_or("native report omitted target evidence")?;
        let mut identities = std::collections::BTreeSet::new();
        if targets.is_empty()
            || targets.iter().any(|target| {
                let Some(name) = target["target"].as_str() else {
                    return true;
                };
                if !identities.insert(name) {
                    return true;
                }
                !(target["status"] == "passed"
                    && target["total"].as_u64().is_some_and(|total| {
                        let passed = target["passed"].as_u64();
                        let ignored = target["ignored"].as_u64();
                        total > 0
                            && passed.is_some_and(|passed| passed > 0)
                            && passed
                                .zip(ignored)
                                .is_some_and(|(passed, ignored)| {
                                    passed.checked_add(ignored) == Some(total)
                                })
                    })
                    || target["status"] == "ignored"
                        && target["total"]
                            .as_u64()
                            .is_some_and(|total| total > 0)
                        && target["ignored"] == target["total"]
                        && target["passed"] == 0
                    || target["status"] == "empty"
                        && target["total"] == 0
                        && target["ignored"] == 0)
            })
            || super::native::REQUIRED_TARGETS
                .iter()
                .any(|required| {
                    !targets
                        .iter()
                        .any(|row| row["target"] == *required && row["status"] == "passed")
                })
        {
            return Err("native report has incomplete target results".into());
        }
    }
    super::common::save(path, &report)
}

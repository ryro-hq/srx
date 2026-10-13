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
    super::common::save(path, &report)
}

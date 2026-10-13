//! Plano e fontes guardados pela mesma preparação do projeto.
//!
//! As origens dos inputs ficam com o plano. A realização usa essas origens para
//! adquirir uma fonte local sem reabrir ou reavaliar outro texto do projeto.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use syrox_lang::source::SourceDomainId;

use crate::plan::Plan;

/// A Plan bound to the source resources from the very same locked evaluation.
/// Clones share both descriptions and snapshots. Dropping a plain `Plan` never
/// controls resource lifetime; realization must keep this preparation alive.
#[derive(Clone, Debug)]
pub struct PreparedPlan {
    plan: Arc<Plan>,
    resources: Arc<ProjectResources>,
}

#[derive(Debug)]
struct ProjectResources {
    project: PathBuf,
    roots: BTreeMap<SourceDomainId, PathBuf>,
    #[cfg(target_os = "linux")]
    _snapshots: Vec<Arc<crate::acquire::github::Snapshot>>,
}

impl PreparedPlan {
    #[cfg(target_os = "linux")]
    pub(super) fn new(
        plan: Plan,
        project: &Path,
        roots: &BTreeMap<SourceDomainId, &super::LoadedProject>,
    ) -> Self {
        Self {
            plan: Arc::new(plan),
            resources: Arc::new(ProjectResources {
                project: project.to_path_buf(),
                roots: roots
                    .iter()
                    .map(|(domain, project)| (*domain, project.path().to_path_buf()))
                    .collect(),
                _snapshots: roots
                    .values()
                    .filter_map(|project| project.snapshot.clone())
                    .collect(),
            }),
        }
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Discard live source ownership and return only the pure description.
    pub fn into_plan(self) -> Plan {
        Arc::unwrap_or_clone(self.plan)
    }

    pub fn project(&self) -> &Path {
        &self.resources.project
    }

    pub(crate) fn project_root(&self, owner: SourceDomainId) -> Option<&Path> {
        self.resources
            .roots
            .get(&owner)
            .map(PathBuf::as_path)
    }
}

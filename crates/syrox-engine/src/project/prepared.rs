//! A plan and source origins retained from the same project preparation.
//!
//! Input origins stay with the plan. Realization uses them to acquire a local
//! source without reopening or reevaluating different project text.

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
    source_pins: BTreeMap<SourceDomainId, crate::store::ContentDigest>,
    #[cfg(target_os = "linux")]
    _snapshots: Vec<Arc<crate::acquire::github::Snapshot>>,
}

impl PreparedPlan {
    #[cfg(target_os = "linux")]
    pub(super) fn new(
        plan: Plan,
        project: &Path,
        roots: &BTreeMap<SourceDomainId, &super::LoadedProject>,
        standard: Option<&super::AuthenticatedStandardLibrary>,
    ) -> Result<Self, super::ProjectOperationError> {
        let source_pins = roots
            .iter()
            .map(|(domain, project)| {
                let lock = super::lock::LockManifest::generate(project, standard)
                    .map_err(super::map_generated_lock_error)?;
                Ok((
                    *domain,
                    crate::store::ContentDigest::from_sha256_hash(*lock.digest()),
                ))
            })
            .collect::<Result<_, super::ProjectOperationError>>()?;
        Ok(Self {
            plan: Arc::new(plan),
            resources: Arc::new(ProjectResources {
                project: project.to_path_buf(),
                source_pins,
                roots: roots
                    .iter()
                    .map(|(domain, project)| (*domain, project.path().to_path_buf()))
                    .collect(),
                _snapshots: roots
                    .values()
                    .filter_map(|project| project.snapshot.clone())
                    .collect(),
            }),
        })
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

    /// Complete source and std snapshot of the authenticated recipe owner.
    pub fn recipe_source_pin(
        &self,
        package: &crate::plan::PlanPackage,
    ) -> Option<crate::store::ContentDigest> {
        self.resources
            .source_pins
            .get(&package.recipe_owner()?)
            .copied()
    }

    pub(crate) fn project_root(&self, owner: SourceDomainId) -> Option<&Path> {
        self.resources
            .roots
            .get(&owner)
            .map(PathBuf::as_path)
    }
}

use super::{
    RuntimeClosure, RuntimeError, RuntimeFile, invalid, materialization_error,
    verify_materialized_runtime,
};
use crate::{
    cancellation::Cancellation, result::MaterializedArtifact, result::OutputOrigin,
    result::RetainedOutput, store::Store,
};
use std::collections::BTreeMap;

/// Persistible runtime roles for a generation/service. Each role must have been
/// retained by its owner before the generation is selected. Roots may be shared
/// when loader and libraries use the same output. Retirement belongs to the
/// generation journal, not to the lifetime of this plain descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedRuntime {
    pub application: RuntimeFile<RetainedOutput>,
    pub loader: Option<RuntimeFile<RetainedOutput>>,
    pub libraries: Vec<RetainedOutput>,
}

impl RetainedRuntime {
    /// Open after preparation/process exit, without a project, toolchain, worker
    /// build or network. Every role and the ELF closure are verified again.
    pub fn open(
        &self,
        store: &Store,
        cancellation: &Cancellation,
    ) -> Result<RuntimeClosure, RuntimeError> {
        super::check_runtime(cancellation)?;
        if self.libraries.len() > super::MAX_RUNTIME_LIBRARIES {
            return Err(invalid("too many retained runtime libraries"));
        }
        // One pinned manifest can supply many roles; authenticate its complete
        // closure once per root/manifest pair, then materialize selected views
        // through that live admission instead of recursively reopening it.
        let mut admissions = BTreeMap::new();
        let mut views: BTreeMap<_, MaterializedArtifact> = BTreeMap::new();
        let result_error = |error: crate::result::ResultError| {
            if cancellation.is_cancelled() {
                RuntimeError::Cancelled
            } else {
                invalid(&error.to_string())
            }
        };
        let mut open = |output: &RetainedOutput| -> Result<MaterializedArtifact, RuntimeError> {
            let view_key = (output.root.clone(), output.identity.clone());
            if let Some(view) = views.get(&view_key) {
                return Ok(view.share());
            }
            let view = match output.identity.origin {
                OutputOrigin::Built {
                    ..
                } => output
                    .open(store, cancellation)
                    .map_err(materialization_error)?,
                OutputOrigin::Imported {
                    manifest,
                } => {
                    let key = (output.root.clone(), manifest);
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        admissions.entry(key.clone())
                    {
                        entry.insert(
                            crate::result::AdmittedResult::open(
                                store,
                                &output.root,
                                manifest,
                                cancellation,
                            )
                            .map_err(result_error)?,
                        );
                    }
                    admissions[&key]
                        .materialize_output(&output.identity, cancellation)
                        .map_err(result_error)?
                }
            };
            views.insert(view_key, view.share());
            Ok(view)
        };
        let application = RuntimeFile {
            output: open(&self.application.output)?,
            path: self.application.path.clone(),
        };
        let loader = self
            .loader
            .as_ref()
            .map(|file| {
                Ok::<_, RuntimeError>(RuntimeFile {
                    output: open(&file.output)?,
                    path: file.path.clone(),
                })
            })
            .transpose()?;
        let libraries = self
            .libraries
            .iter()
            .map(open)
            .collect::<Result<Vec<_>, _>>()?;
        verify_materialized_runtime(application, loader, libraries, cancellation)
    }
}

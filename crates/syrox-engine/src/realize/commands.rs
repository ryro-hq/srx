use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use thiserror::Error;

use super::{
    BuildProgress, RealizeContext, RealizeError, RealizeOptions, plan_for_export, reference_parts,
};
use crate::{
    cancellation::Cancellation, config::UserConfiguration, plan::PlanCommand, plan::PlanCommandRef,
    plan::PlanOutputRef, plan::PlanPackageId, project::CheckConfiguration, project::PreparedPlan,
    runtime::RuntimeClosure, runtime::RuntimeError, runtime::RuntimeFile,
    runtime::verify_materialized_runtime, store::StoreError,
};

#[derive(Debug)]
pub struct ResolvedCommand {
    project: PathBuf,
    export: String,
    prepared: PreparedPlan,
    command: PlanCommand,
}

impl ResolvedCommand {
    pub fn project(&self) -> &Path {
        &self.project
    }
    pub fn export(&self) -> &str {
        &self.export
    }
    pub const fn description(&self) -> &PlanCommand {
        &self.command
    }
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("select a declared command for export `{0}` with --command")]
    MissingSelection(String),
    #[error("no declared command `{0}` in the selected recipe")]
    MissingCommand(String),
    #[error(transparent)]
    Resolve(#[from] RealizeError),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Project(#[from] crate::project::ProjectOperationError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Pure selection of one named command from a single locked evaluation.
pub fn resolve_command(
    reference: &str,
    command: Option<&str>,
    user: &UserConfiguration,
    checks: &CheckConfiguration,
) -> Result<ResolvedCommand, CommandError> {
    let (project, export, pin) = reference_parts(reference, user)?;
    let export = export.ok_or(RealizeError::MissingSelection)?;
    let command = command.ok_or_else(|| CommandError::MissingSelection(export.to_owned()))?;
    let project = std::path::absolute(project)?;
    let prepared = plan_for_export(&project, export, pin, checks)?;
    let plan = prepared.plan();
    let package = plan
        .packages()
        .find(|package| package.has_export(export))
        .ok_or_else(|| RealizeError::MissingExport(export.to_owned()))?;
    let selected = PlanCommandRef {
        package: package.id().clone(),
        name: command.to_owned(),
    };
    let mut resolved = resolve_plan_command(&prepared, &selected)?;
    resolved.project = project;
    export.clone_into(&mut resolved.export);
    Ok(resolved)
}

/// Reuses the prepared graph and validates selection before Store/build effects.
pub fn resolve_plan_command(
    prepared: &PreparedPlan,
    selected: &PlanCommandRef,
) -> Result<ResolvedCommand, CommandError> {
    let command = prepared
        .plan()
        .commands()
        .find(|command| command.package() == &selected.package && command.name() == selected.name)
        .ok_or_else(|| CommandError::MissingCommand(selected.name.clone()))?
        .clone();
    let package = prepared
        .plan()
        .packages()
        .find(|node| node.id() == &selected.package)
        .expect("validated command package");
    Ok(ResolvedCommand {
        project: prepared.project().to_path_buf(),
        export: package
            .export()
            .unwrap_or(package.id().as_str())
            .to_owned(),
        prepared: prepared.clone(),
        command,
    })
}

/// Realize only the selected command's outputs and verify its private closure.
pub fn realize_command(
    resolved: &ResolvedCommand,
    user: &UserConfiguration,
    worker: &Path,
    offline: bool,
    cancellation: &Cancellation,
    mut progress: impl FnMut(&PlanPackageId, BuildProgress),
) -> Result<RuntimeClosure, CommandError> {
    cancellation.check().map_err(RealizeError::from)?;
    let context = RealizeContext::new(RealizeOptions {
        configuration: user,
        worker,
        offline,
    });
    let store = context.store()?;
    let command = &resolved.command;
    let mut results = BTreeMap::new();
    let application = PlanOutputRef {
        package: command.package().clone(),
        output: command.output().to_owned(),
    };
    let mut views = BTreeMap::new();
    for selected in std::iter::once(&application)
        .chain(command.loader().map(|file| &file.output))
        .chain(command.libraries())
    {
        if views.contains_key(selected) {
            continue;
        }
        if let std::collections::btree_map::Entry::Vacant(entry) =
            results.entry(selected.package.clone())
        {
            let output = super::resolve_plan_output(&resolved.prepared, selected)?;
            entry.insert(super::outputs::realize_package(
                &output,
                &context,
                cancellation,
                |stage| progress(&selected.package, stage),
            )?);
        }
        let (view, _) =
            results[&selected.package].materialize(store, &selected.output, cancellation)?;
        views.insert(selected.clone(), view);
    }
    Ok(verify_materialized_runtime(
        RuntimeFile {
            output: views[&application].share(),
            path: command.path().to_owned(),
        },
        command.loader().map(|file| RuntimeFile {
            output: views[&file.output].share(),
            path: file.path.clone(),
        }),
        command
            .libraries()
            .map(|output| views[output].share())
            .collect(),
        cancellation,
    )?)
}

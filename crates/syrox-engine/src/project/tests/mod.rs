use sha2::Digest as _;

use std::collections::HashMap;

use std::fmt::Write as _;

use std::fs;

use std::io::{self, Cursor};

use std::os::unix::fs::symlink;

use std::path::{Path, PathBuf};

use std::process::Command;

use std::sync::atomic::{AtomicU64, Ordering};

use syrox_lang::{
    MAX_SOURCE_BYTES, MAX_SOURCES, checker::CanonicalItemIdentity, checker::CheckPolicy,
    evaluator::EvaluationEnvironment, evaluator::EvaluationSetupError, source::SourceDomainId,
};

use super::loader::{
    InputRoot, LoadBudget, identity, open_beneath, open_error, open_top, read_source,
    reopen_directory, walk_input,
};

use super::*;

use crate::platform::linux::fd::OpenError;

mod configuration;

mod consumers;

mod editor;

mod evaluation;

mod generic_build;

mod imported;

mod package_set;

mod recipe_ref;

mod reference_graph;

mod refresh;

mod systems;

mod versioned;

mod assets;

mod catalog;

mod children;

mod diagnostics;

mod inputs;

mod limits;

mod locking;

mod module_exports;

mod ordered_maps;

mod planning;

mod standard_library;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempProject(PathBuf);

impl TempProject {
    fn new() -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "syrox-project-test-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, text).unwrap();
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn package_configuration() -> CheckConfiguration {
    CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    }
}

fn package_plan(source: &str) -> Result<crate::plan::Plan, ProjectOperationError> {
    let project = TempProject::new();
    project.write("main.srx", source);
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration)?;
    plan_project_with(&project.0, &configuration)
}

// Low-level value serialization tests deliberately bypass destination selection.
// The public project planner rejects these values as Services/Shell destinations.
fn value_projection_plan(
    path: &Path,
    config: &CheckConfiguration,
) -> Result<crate::plan::Plan, ProjectOperationError> {
    let locked = open_locked_project_with(path, config)?;
    let checked = analyze::check_loaded(locked.loaded(), config)?;
    let realized = syrox_lang::evaluator::evaluate_with_limits(
        &checked,
        &config.policy,
        &config.environment,
        config.evaluation_limits,
    )
    .map_err(|source| CheckFailure::EvaluationSetup {
        source,
    })?;
    analyze::require_success(locked.loaded(), &realized)?;
    crate::plan::Plan::from_realized(
        &realized,
        *locked.lock_digest(),
        config.policy.identity(),
        config.standard_library.as_ref(),
    )
    .map_err(ProjectOperationError::from)
}

fn recipe_graph_source(nodes: &[(&str, &str, &[&str])]) -> String {
    let mut source = String::from("mod catalog {\n");
    for (name, id, dependencies) in nodes {
        let edges = dependencies
            .iter()
            .map(|name| format!("std::Dependency {{ recipe = project::{name}; }}"))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(source, "mod {name} {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = \"{id}\"; dependencies = [{edges}]; }}; acquisition = None; build = None; build_inputs = None; commands = []; }} }} }}").unwrap();
    }
    source.push_str("} pub publish(catalog, recipe): std::Recipe;");
    source
}

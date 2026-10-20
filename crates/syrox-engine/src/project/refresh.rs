//! Restricted configuration updates. Dependencies remain at their locked pins.

use std::path::Path;

use super::{
    CheckConfiguration, LockedProject, PreparedPlan, ProjectOperationError, analyze, compare_lock,
    expected_lock, loader, lock, map_lock_publication, read_graph_lock, read_lock,
    validate_lock_policy, validate_project_limits,
};
use crate::platform::linux::fd::{self, FlockMode, OpenedPath};

// The directory lock also covers explicit project-lock updates. It introduces
// no extra files and is released when its descriptor closes, including errors.
pub(super) fn lock_root(path: &Path) -> Result<OpenedPath, ProjectOperationError> {
    let root = fd::open_top_directory(path).map_err(|error| loader::open_error(path, error))?;
    if !fd::flock(root.fd(), FlockMode::ExclusiveNonblocking).map_err(|source| {
        ProjectOperationError::LockIo {
            source,
        }
    })? {
        return Err(ProjectOperationError::LockBusy);
    }
    Ok(root)
}

/// Prepare an edited configuration while retaining every existing dependency,
/// source asset and standard-library pin. Only `main.srx` may change. An existing
/// lock is required; updating dependencies still requires an explicit lock
/// operation. The returned plan comes from the snapshot checked here.
pub fn prepare_project_consumer_refresh_root_with(
    path: &Path,
    configuration: &CheckConfiguration,
    name: &str,
) -> Result<PreparedPlan, ProjectOperationError> {
    validate_project_limits(configuration.project_limits)?;
    validate_lock_policy(configuration)?;
    let mutation = lock_root(path)?;
    // Offline loading uses the already locked GitHub commits, never mutable refs.
    let loaded = loader::load_project_linux(path, configuration)?;
    if mutation.metadata().identity() != loaded.root.metadata().identity() {
        return Err(ProjectOperationError::ConcurrentEdit);
    }
    let actual = read_lock(&loaded)?.ok_or(ProjectOperationError::MissingLock {
        name: lock::LOCK_FILE_NAME,
    })?;
    let expected = expected_lock(&loaded, configuration)?;
    match actual.drift_except_main(&expected) {
        Some(lock::LockDrift::StandardLibrary) => {
            return Err(ProjectOperationError::StandardLibraryDrift);
        }
        Some(lock::LockDrift::Graph) => return Err(ProjectOperationError::GraphDrift),
        Some(lock::LockDrift::Project) => return Err(ProjectOperationError::ProjectDrift),
        None => {}
    }
    if read_graph_lock(&loaded)?.is_some() {
        return Err(ProjectOperationError::GraphDrift);
    }
    let checked = analyze::check_loaded(&loaded, configuration)?;
    let project = LockedProject {
        loaded,
        checked,
        configuration: configuration.clone(),
        digest: *expected.digest(),
    };
    let mut evaluation = project.evaluation()?;
    evaluation.select_consumer(name)?;
    let prepared = evaluation.into_selected_prepared_plan()?;

    // Do not publish a lock from a snapshot superseded during checking. Keeping
    // the plan above also prevents a later editor write from changing this run.
    let current = loader::load_project_linux(path, configuration)?;
    if current.root.metadata().identity() != mutation.metadata().identity()
        || expected_lock(&current, configuration)?.data() != expected.data()
        || read_lock(&current)?.as_ref() != Some(&actual)
        || read_graph_lock(&current)?.is_some()
    {
        return Err(ProjectOperationError::ConcurrentEdit);
    }
    if configuration.github.cancellation.is_cancelled() {
        return Err(
            super::CheckFailure::Github(crate::acquire::github::GithubError::Cancelled).into(),
        );
    }
    if actual.data() == expected.data() {
        compare_lock(&actual, &expected)?;
    } else {
        fd::write_atomic_beneath(
            project.loaded.root.fd(),
            Path::new(lock::LOCK_FILE_NAME),
            expected.data(),
        )
        .map_err(map_lock_publication)?;
    }
    Ok(prepared)
}

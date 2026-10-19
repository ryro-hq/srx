//! Loading a project, verifying its sources and preparing evaluation.
//!
//! # One preparation for planning and realization
//!
//! The lock and standard library are checked before the plan is prepared.
//! [`PreparedPlan`] keeps the result and input origins so [`crate::realize`] does
//! not read a different project revision. See [`lock`] for pinned identities and
//! [`prepared`](../../src/syrox_engine/project/prepared.rs.html) for the data retained with the plan.
//!
//! # Editing a project
//!
//! [`ProjectAnalysis`] accepts overlays and keeps the snapshots used by each query.
//! This path can report partial editor facts; execution uses the checked evaluation
//! path. [`editor`](../../src/syrox_engine/project/editor.rs.html) owns project snapshots and [`evaluation`](../../src/syrox_engine/project/evaluation.rs.html) owns locked evaluation.

#[cfg(target_os = "linux")]
mod analyze;
#[cfg(target_os = "linux")]
mod evaluation;
#[cfg(target_os = "linux")]
pub use evaluation::{LockedProject, ProjectEvaluation, open_locked_project_with};
mod editor;
#[cfg(target_os = "linux")]
mod loader;
#[cfg(target_os = "linux")]
mod locator;
mod prepared;
mod standard_library;
pub use editor::{
    ProjectAnalysis, ProjectAnalysisError, ProjectAnalysisLockStatus, ProjectAnalysisSnapshot,
};
#[cfg(target_os = "linux")]
pub use editor::{open_project_analysis_with, open_standard_library_analysis_with};
pub use prepared::PreparedPlan;
pub use standard_library::{
    AuthenticatedStandardLibrary, AuthenticatedStandardSource, StandardLibraryError,
};

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::string::FromUtf8Error;

use syrox_lang::{
    MAX_SOURCE_BYTES, MAX_SOURCES, checker::CheckPolicy, diagnostic::Diagnostic,
    evaluator::EvaluationEnvironment, evaluator::EvaluationLimits, evaluator::EvaluationSetupError,
    evaluator::RealizedProgram, source::Source, source::SourceDomainId, source::SourceError,
    source::SourceId, source::SourceSet,
};
use thiserror::Error;

use crate::project::lock::MAX_LOCK_BYTES;

/// Maximum bytes accepted across `main.srx`, inputs, and supplied standard-library sources.
pub const MAX_PROJECT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum directory entries visited while loading a project.
pub const MAX_DIRECTORY_ENTRIES: usize = 65_536;
/// Maximum filesystem operations charged by the project loader.
pub const MAX_PROJECT_WORK: usize = 262_144;
/// Maximum depth below one input directory.
pub const MAX_DIRECTORY_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectLimits {
    pub max_total_bytes: usize,
    pub max_sources: usize,
    pub max_directory_entries: usize,
    pub max_work: usize,
    pub max_directory_depth: usize,
}

impl Default for ProjectLimits {
    fn default() -> Self {
        Self {
            max_total_bytes: MAX_PROJECT_BYTES,
            max_sources: MAX_SOURCES,
            max_directory_entries: MAX_DIRECTORY_ENTRIES,
            max_work: MAX_PROJECT_WORK,
            max_directory_depth: MAX_DIRECTORY_DEPTH,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CheckConfiguration {
    pub standard_library: Option<AuthenticatedStandardLibrary>,
    pub policy: CheckPolicy,
    pub environment: EvaluationEnvironment,
    pub evaluation_limits: EvaluationLimits,
    pub project_limits: ProjectLimits,
    pub github: crate::acquire::github::GithubConfiguration,
}

impl Default for CheckConfiguration {
    fn default() -> Self {
        let policy = CheckPolicy::default();
        let environment = EvaluationEnvironment::new(&policy);
        Self {
            standard_library: None,
            policy,
            environment,
            evaluation_limits: EvaluationLimits::default(),
            project_limits: ProjectLimits::default(),
            github: crate::acquire::github::GithubConfiguration::default(),
        }
    }
}

#[derive(Debug)]
pub struct LoadedProjectSource {
    relative_path: PathBuf,
    source_id: SourceId,
}

#[derive(Debug)]
pub struct LoadedProjectAsset {
    content: std::sync::Arc<[u8]>,
    relative_path: PathBuf,
    size: u64,
    digest: [u8; 32],
}

impl LoadedProjectAsset {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }
    pub const fn size(&self) -> u64 {
        self.size
    }
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl LoadedProjectSource {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn source_id(&self) -> SourceId {
        self.source_id
    }
}

#[derive(Debug)]
pub struct LoadedProjectInput {
    name: String,
    locator: String,
    domain: SourceDomainId,
    files: Vec<LoadedProjectSource>,
}

impl LoadedProjectInput {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn locator(&self) -> &str {
        &self.locator
    }

    pub const fn domain(&self) -> SourceDomainId {
        self.domain
    }

    pub fn files(&self) -> impl ExactSizeIterator<Item = &LoadedProjectSource> {
        self.files.iter()
    }
}

#[derive(Debug)]
pub struct LoadedProject {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    root: crate::platform::linux::fd::OpenedPath,
    sources: SourceSet,
    main_source: SourceId,
    inputs: Vec<LoadedProjectInput>,
    assets: Vec<LoadedProjectAsset>,
    #[cfg(target_os = "linux")]
    child_edges: Vec<lock::graph::ProjectEdge>,
    #[cfg(target_os = "linux")]
    children: Vec<(String, std::sync::Arc<LoadedProject>)>,
    #[cfg(target_os = "linux")]
    snapshot: Option<std::sync::Arc<crate::acquire::github::Snapshot>>,
}

impl LoadedProject {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn sources(&self) -> &SourceSet {
        &self.sources
    }

    pub fn main_source(&self) -> &Source {
        self.sources
            .get(self.main_source)
            .expect("loaded project retains its main source")
    }

    pub fn inputs(&self) -> impl ExactSizeIterator<Item = &LoadedProjectInput> {
        self.inputs.iter()
    }

    pub fn assets(&self) -> impl ExactSizeIterator<Item = &LoadedProjectAsset> {
        self.assets.iter()
    }

    pub(crate) fn child_edges(&self) -> &[lock::graph::ProjectEdge] {
        #[cfg(target_os = "linux")]
        {
            &self.child_edges
        }
    }
}

#[derive(Debug)]
pub struct ValidatedProject {
    loaded: LoadedProject,
    declarations: usize,
    realized: RealizedProgram,
}

impl ValidatedProject {
    pub const fn loaded(&self) -> &LoadedProject {
        &self.loaded
    }

    pub const fn declarations(&self) -> usize {
        self.declarations
    }

    pub const fn realized(&self) -> &RealizedProgram {
        &self.realized
    }

    pub fn report(&self) -> CheckReport {
        CheckReport {
            path: self.loaded.path.clone(),
            declarations: self.declarations,
            realized_roots: self.realized.roots().len(),
        }
    }
}

#[derive(Debug)]
pub struct CheckReport {
    pub path: PathBuf,
    pub declarations: usize,
    pub realized_roots: usize,
}

#[derive(Debug)]
pub struct LockReport {
    status: lock::LockStatus,
    check: CheckReport,
    digest: [u8; 32],
}

impl LockReport {
    pub const fn status(&self) -> lock::LockStatus {
        self.status
    }

    pub const fn check(&self) -> &CheckReport {
        &self.check
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Debug, Error)]
pub enum LockPublicationError {
    #[error("lock publication failed before replacement: {source}")]
    BeforeRename {
        #[source]
        source: io::Error,
    },
    #[error("lock publication failed before replacement ({source}) and cleanup failed: {cleanup}")]
    CleanupFailed {
        source: io::Error,
        cleanup: LockCleanupError,
    },
}

#[derive(Debug, Error)]
pub enum LockCleanupError {
    #[error("temporary removal failed: {source}")]
    Removal {
        #[source]
        source: io::Error,
    },
    #[error("cleanup directory synchronization failed: {source}")]
    Synchronization {
        #[source]
        source: io::Error,
    },
    #[error(
        "temporary removal failed ({removal}) and cleanup directory synchronization failed ({synchronization})"
    )]
    RemovalAndSynchronization {
        removal: io::Error,
        synchronization: io::Error,
    },
}

#[derive(Debug, Error)]
pub enum ProjectOperationError {
    #[error(transparent)]
    Editor(#[from] ProjectAnalysisError),
    #[error("project has no value output `{name}`")]
    MissingOutput {
        name: String,
    },
    #[error("project output `{name}` must have authenticated std::Os or std::Shell type")]
    InvalidConsumerOutput {
        name: String,
    },
    #[error("library catalog is invalid: {reason}")]
    InvalidCatalog {
        reason: &'static str,
    },
    #[error("library catalog has no entry `{key}`")]
    MissingPackageReference {
        key: String,
    },
    #[error(transparent)]
    Check(#[from] CheckFailure),
    #[error("project has no {name}")]
    MissingLock {
        name: &'static str,
    },
    #[error("project lock is malformed or noncanonical: {source}")]
    MalformedLock {
        #[source]
        source: lock::LockFormatError,
    },
    #[error("project sources have drifted from the lock")]
    ProjectDrift,
    #[error("project graph lock has drifted from its authenticated child snapshots")]
    GraphDrift,
    #[error(
        "project asset `{path}` is not authenticated in the consuming project with the requested digest"
    )]
    UnpinnedProjectAsset {
        path: String,
    },
    #[error("project source `{path}` has no authenticated project origin")]
    UnknownProjectSourceOrigin {
        path: String,
    },
    #[error("project graph lock is malformed or noncanonical: {source}")]
    MalformedGraphLock {
        source: lock::LockFormatError,
    },
    #[error("authenticated standard library has drifted from the lock")]
    StandardLibraryDrift,
    #[error("project lock is a symbolic link")]
    LockSymlink,
    #[error("project lock is not a regular file")]
    LockNonRegular,
    #[error("project lock has multiple hard links")]
    LockHardLinked,
    #[error("cannot access project lock: {source}")]
    LockIo {
        #[source]
        source: io::Error,
    },
    #[error("cannot remove obsolete graph lock: {source}")]
    GraphRemoval {
        source: io::Error,
    },
    #[error(transparent)]
    LockPublication(#[from] LockPublicationError),
    #[error(
        "project lock was replaced but its identity or publication durability could not be confirmed: {source}"
    )]
    LockPublicationUncertain {
        #[source]
        source: io::Error,
    },
    #[error("the current lock requires the default `syrox.empty` policy and matching environment")]
    PolicyProvenanceRequired,
    #[error("generated canonical lock exceeds the {MAX_LOCK_BYTES}-byte limit")]
    GeneratedLockTooLarge,
    #[error(transparent)]
    Plan(#[from] crate::plan::PlanError),
}

#[derive(Debug, Error)]
pub enum CheckFailure {
    #[error(transparent)]
    Github(#[from] crate::acquire::github::GithubError),
    #[error("the Linux kernel does not provide the required openat2 secure traversal: {source}")]
    UnsupportedKernel {
        #[source]
        source: io::Error,
    },
    #[error("configured project limit `{field}` is {configured}, above the hard maximum {maximum}")]
    InvalidProjectLimit {
        field: &'static str,
        configured: usize,
        maximum: usize,
    },
    #[error("cannot inspect {path}: {source}")]
    Inspect {
        path: PathBuf,
        source: io::Error,
    },
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: io::Error,
    },
    #[error("{path} exceeds the {MAX_SOURCE_BYTES}-byte source limit")]
    TooLarge {
        path: PathBuf,
    },
    #[error("project sources exceed the configured {limit}-byte total limit")]
    ProjectTooLarge {
        limit: usize,
    },
    #[error("project source count exceeds the configured {limit}-source limit")]
    TooManySources {
        limit: usize,
    },
    #[error("project directory entries exceed the configured {limit}-entry limit")]
    TooManyDirectoryEntries {
        limit: usize,
    },
    #[error("project loading exceeds the configured {limit}-work-unit limit")]
    WorkLimit {
        limit: usize,
    },
    #[error("{path} exceeds the configured input directory depth of {limit}")]
    DirectoryDepth {
        path: PathBuf,
        limit: usize,
    },
    #[error("{path} is not valid UTF-8: {source}")]
    InvalidUtf8 {
        path: PathBuf,
        source: FromUtf8Error,
    },
    #[error("path contains a non-UTF-8 component: {path:?}")]
    InvalidPathEncoding {
        path: PathBuf,
    },
    #[error("project directory is missing main.srx: {path}")]
    MissingMain {
        path: PathBuf,
    },
    #[error("expected a regular .srx source file: {path}")]
    InvalidSourceFile {
        path: PathBuf,
    },
    #[error("expected a regular asset file: {path}")]
    InvalidAssetFile {
        path: PathBuf,
    },
    #[error("expected an input directory: {path}")]
    InputNotDirectory {
        path: PathBuf,
    },
    #[error("symbolic links are not allowed in project sources: {path}")]
    SymbolicLink {
        path: PathBuf,
    },
    #[error(
        "input `{name}` has unsupported locator `{locator}`; expected path:, modules: or github:"
    )]
    UnsupportedLocator {
        name: String,
        locator: String,
    },
    #[error("input `{name}` path must be relative and contain no `..`: {path}")]
    UnsafeInputPath {
        name: String,
        path: PathBuf,
    },
    #[error("duplicate project input name `{name}`")]
    DuplicateInputName {
        name: String,
    },
    #[error("invalid modules input: {reason}")]
    InvalidModuleInput {
        reason: String,
    },
    #[error("child project {path} has no {name}")]
    MissingChildLock {
        path: PathBuf,
        name: &'static str,
    },
    #[error("child project {path} lock could not be verified: {reason}")]
    InvalidChildLock {
        path: PathBuf,
        reason: String,
    },
    #[error("project {path} input pins could not be read: {reason}")]
    InvalidInputLock {
        path: PathBuf,
        reason: String,
    },
    #[error("project snapshot contains a cycle or repeated directory: {path}")]
    ChildProjectCycle {
        path: PathBuf,
    },
    #[error("project graph exceeds the configured input directory depth of {limit}")]
    ProjectGraphDepth {
        limit: usize,
    },
    #[error("project has more than {limit} imported project edges")]
    TooManyProjectEdges {
        limit: usize,
    },
    #[error("input paths overlap and would alias source authority: {first} and {second}")]
    AliasedInputPaths {
        first: PathBuf,
        second: PathBuf,
    },
    #[error("source files are aliases of the same filesystem object: {first} and {second}")]
    AliasedSourceFiles {
        first: PathBuf,
        second: PathBuf,
    },
    #[error(transparent)]
    InvalidSource(#[from] SourceError),
    #[error("source contains {} error(s)", .errors.len())]
    Diagnostics {
        input: SourceSet,
        errors: Vec<Diagnostic>,
    },
    #[error("evaluation setup failed: {source}")]
    EvaluationSetup {
        #[source]
        source: EvaluationSetupError,
    },
    #[error("evaluation failed for {} root(s)", .failed_roots.len())]
    Evaluation {
        input: SourceSet,
        errors: Vec<Diagnostic>,
        failed_roots: Vec<String>,
    },
}

pub fn check_path_with(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<CheckReport, CheckFailure> {
    validate_project_limits(configuration.project_limits)?;
    check_path_platform(path, configuration)
}

pub fn check_project(path: &Path) -> Result<CheckReport, CheckFailure> {
    check_project_with(path, &CheckConfiguration::default())
}

pub fn check_project_with(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<CheckReport, CheckFailure> {
    validate_project_limits(configuration.project_limits)?;
    check_project_platform(path, configuration)
}

pub fn validate_project_with(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<ValidatedProject, CheckFailure> {
    validate_project_limits(configuration.project_limits)?;
    validate_project_platform(path, configuration)
}

pub fn lock_project(path: &Path) -> Result<LockReport, ProjectOperationError> {
    lock_project_with(path, &CheckConfiguration::default())
}

pub fn lock_project_with(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<LockReport, ProjectOperationError> {
    validate_project_limits(configuration.project_limits)?;
    validate_lock_policy(configuration)?;
    lock_project_platform(path, configuration)
}

pub fn check_project_lock(path: &Path) -> Result<LockReport, ProjectOperationError> {
    check_project_lock_with(path, &CheckConfiguration::default())
}

pub fn check_project_lock_with(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<LockReport, ProjectOperationError> {
    validate_project_limits(configuration.project_limits)?;
    validate_lock_policy(configuration)?;
    check_project_lock_platform(path, configuration)
}

/// Acquire missing project snapshots at their locked commits and content hashes.
/// This operation never resolves mutable refs or rewrites a Lock.
pub fn fetch_project_inputs_with(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<LockReport, ProjectOperationError> {
    validate_project_limits(configuration.project_limits)?;
    validate_lock_policy(configuration)?;
    #[cfg(target_os = "linux")]
    {
        let loaded = loader::load_project_mode(
            path,
            configuration,
            crate::acquire::github::InputMode::Fetch,
        )?;
        let actual = read_lock(&loaded)?.ok_or(ProjectOperationError::MissingLock {
            name: lock::LOCK_FILE_NAME,
        })?;
        compare_lock(&actual, &expected_lock(&loaded, configuration)?)?;
        if read_graph_lock(&loaded)?.is_some() {
            return Err(ProjectOperationError::GraphDrift);
        }
        let checked = analyze::check_loaded(&loaded, configuration)?;
        Ok(LockReport {
            status: lock::LockStatus::Unchanged,
            check: CheckReport {
                path: loaded.path.clone(),
                declarations: checked.resolved().parsed().declaration_count(),
                realized_roots: 0,
            },
            digest: *actual.digest(),
        })
    }
}

pub fn plan_project_with(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<crate::plan::Plan, ProjectOperationError> {
    prepare_project_with(path, configuration).map(PreparedPlan::into_plan)
}

/// Prepare one locked graph, retaining the source snapshots for later realization.
pub fn prepare_project_with(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<PreparedPlan, ProjectOperationError> {
    validate_project_limits(configuration.project_limits)?;
    validate_lock_policy(configuration)?;
    prepare_project_platform(path, configuration)
}

/// Project only the requested Os/Shell destinations from one verified snapshot.
/// Repeated names select the same root; referenced recipes remain lazy.
pub fn plan_project_outputs_with(
    path: &Path,
    configuration: &CheckConfiguration,
    outputs: &[&str],
) -> Result<crate::plan::Plan, ProjectOperationError> {
    #[cfg(target_os = "linux")]
    {
        let project = open_locked_project_with(path, configuration)?;
        let mut evaluation = project.evaluation()?;
        for output in outputs {
            evaluation.select_consumer(output)?;
        }
        evaluation.into_selected_plan()
    }
}

/// Plan one authenticated Os/Shell output and its referenced recipes. Other
/// outputs remain unevaluated, and no packages or configuration are realized.
pub fn plan_project_consumer_with(
    path: &Path,
    configuration: &CheckConfiguration,
    name: &str,
) -> Result<crate::plan::Plan, ProjectOperationError> {
    prepare_project_consumer_with(path, configuration, name).map(PreparedPlan::into_plan)
}

/// Select one authenticated Os/Shell output from one locked evaluation and
/// retain its source snapshots for realization. Unselected factories stay lazy.
pub fn prepare_project_consumer_with(
    path: &Path,
    configuration: &CheckConfiguration,
    name: &str,
) -> Result<PreparedPlan, ProjectOperationError> {
    let project = open_locked_project_with(path, configuration)?;
    let mut evaluation = project.evaluation()?;
    evaluation.select_consumer(name)?;
    evaluation.into_selected_prepared_plan()
}

/// Plan one published recipe and its providers from a verified snapshot.
pub fn plan_project_package_with(
    path: &Path,
    configuration: &CheckConfiguration,
    key: &str,
) -> Result<crate::plan::Plan, ProjectOperationError> {
    #[cfg(target_os = "linux")]
    {
        let locked = open_locked_project_with(path, configuration)?;
        let mut evaluation = locked.evaluation()?;
        if evaluation.select_package(key)? {
            evaluation.into_selected_plan()
        } else {
            Err(ProjectOperationError::MissingPackageReference {
                key: key.to_owned(),
            })
        }
    }
}

fn validate_project_limits(limits: ProjectLimits) -> Result<(), CheckFailure> {
    for (field, configured, maximum) in [
        (
            "max_total_bytes",
            limits.max_total_bytes,
            MAX_PROJECT_BYTES,
        ),
        ("max_sources", limits.max_sources, MAX_SOURCES),
        (
            "max_directory_entries",
            limits.max_directory_entries,
            MAX_DIRECTORY_ENTRIES,
        ),
        ("max_work", limits.max_work, MAX_PROJECT_WORK),
        (
            "max_directory_depth",
            limits.max_directory_depth,
            MAX_DIRECTORY_DEPTH,
        ),
    ] {
        if configured > maximum {
            return Err(CheckFailure::InvalidProjectLimit {
                field,
                configured,
                maximum,
            });
        }
    }
    Ok(())
}

fn validate_lock_policy(configuration: &CheckConfiguration) -> Result<(), ProjectOperationError> {
    let default = CheckPolicy::default();
    if configuration.policy != default || configuration.environment.policy() != &default {
        return Err(ProjectOperationError::PolicyProvenanceRequired);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_path_platform(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<CheckReport, CheckFailure> {
    loader::check_path_linux(path, configuration)
}

#[cfg(target_os = "linux")]
fn check_project_platform(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<CheckReport, CheckFailure> {
    loader::check_project_linux(path, configuration)
}

#[cfg(target_os = "linux")]
fn validate_project_platform(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<ValidatedProject, CheckFailure> {
    loader::validate_project_linux(path, configuration)
}

#[cfg(target_os = "linux")]
fn expected_lock(
    loaded: &LoadedProject,
    configuration: &CheckConfiguration,
) -> Result<lock::LockManifest, ProjectOperationError> {
    lock::LockManifest::generate(loaded, configuration.standard_library.as_ref())
        .map_err(map_generated_lock_error)
}

#[cfg(target_os = "linux")]
fn map_generated_lock_error(source: lock::LockFormatError) -> ProjectOperationError {
    match source {
        lock::LockFormatError::TooLarge => ProjectOperationError::GeneratedLockTooLarge,
        source => ProjectOperationError::MalformedLock {
            source,
        },
    }
}

#[cfg(target_os = "linux")]
fn read_lock(project: &LoadedProject) -> Result<Option<lock::LockManifest>, ProjectOperationError> {
    read_lock_handle(&project.root)
}

#[cfg(target_os = "linux")]
fn read_lock_handle(
    project: &crate::platform::linux::fd::OpenedPath,
) -> Result<Option<lock::LockManifest>, ProjectOperationError> {
    let bytes = crate::platform::linux::fd::read_bounded_beneath(
        project.fd(),
        Path::new(lock::LOCK_FILE_NAME),
        MAX_LOCK_BYTES,
    )
    .map_err(map_lock_io)?;
    bytes
        .map(|bytes| {
            lock::LockManifest::parse(&bytes).map_err(|source| {
                ProjectOperationError::MalformedLock {
                    source,
                }
            })
        })
        .transpose()
}

#[cfg(target_os = "linux")]
fn map_lock_io(source: crate::platform::linux::fd::LockIoError) -> ProjectOperationError {
    match source {
        crate::platform::linux::fd::LockIoError::Symlink => ProjectOperationError::LockSymlink,
        crate::platform::linux::fd::LockIoError::NonRegular => {
            ProjectOperationError::LockNonRegular
        }
        crate::platform::linux::fd::LockIoError::HardLinked => {
            ProjectOperationError::LockHardLinked
        }
        crate::platform::linux::fd::LockIoError::TooLarge => ProjectOperationError::MalformedLock {
            source: lock::LockFormatError::TooLarge,
        },
        crate::platform::linux::fd::LockIoError::Io(source) => ProjectOperationError::LockIo {
            source,
        },
    }
}

#[cfg(target_os = "linux")]
fn map_lock_publication(
    error: crate::platform::linux::fd::WriteAtomicError,
) -> ProjectOperationError {
    match error {
        crate::platform::linux::fd::WriteAtomicError::BeforeRename {
            source,
            cleanup: None,
        } => LockPublicationError::BeforeRename {
            source,
        }
        .into(),
        crate::platform::linux::fd::WriteAtomicError::BeforeRename {
            source,
            cleanup: Some(cleanup),
        } => LockPublicationError::CleanupFailed {
            source,
            cleanup: map_lock_cleanup(cleanup),
        }
        .into(),
        crate::platform::linux::fd::WriteAtomicError::AfterRename {
            source,
        } => ProjectOperationError::LockPublicationUncertain {
            source,
        },
    }
}

#[cfg(target_os = "linux")]
fn map_lock_cleanup(source: crate::platform::linux::fd::CleanupError) -> LockCleanupError {
    match source {
        crate::platform::linux::fd::CleanupError::Removal(source) => LockCleanupError::Removal {
            source,
        },
        crate::platform::linux::fd::CleanupError::Synchronization(source) => {
            LockCleanupError::Synchronization {
                source,
            }
        }
        crate::platform::linux::fd::CleanupError::RemovalAndSynchronization {
            removal,
            synchronization,
        } => LockCleanupError::RemovalAndSynchronization {
            removal,
            synchronization,
        },
    }
}

#[cfg(target_os = "linux")]
fn compare_lock(
    actual: &lock::LockManifest,
    expected: &lock::LockManifest,
) -> Result<(), ProjectOperationError> {
    match actual.drift(expected) {
        None => Ok(()),
        Some(lock::LockDrift::Project) => Err(ProjectOperationError::ProjectDrift),
        Some(lock::LockDrift::StandardLibrary) => Err(ProjectOperationError::StandardLibraryDrift),
        Some(lock::LockDrift::Graph) => Err(ProjectOperationError::GraphDrift),
    }
}

#[cfg(target_os = "linux")]
const GRAPH_LOCK_FILE: &str = "Syrox.graph.lock";

#[cfg(target_os = "linux")]
fn read_graph_lock(
    project: &LoadedProject,
) -> Result<Option<lock::graph::GraphLock>, ProjectOperationError> {
    let bytes = crate::platform::linux::fd::read_bounded_beneath(
        project.root.fd(),
        Path::new(GRAPH_LOCK_FILE),
        MAX_LOCK_BYTES,
    )
    .map_err(map_lock_io)?;
    bytes
        .map(|bytes| {
            lock::graph::GraphLock::parse(&bytes).map_err(|source| {
                ProjectOperationError::MalformedGraphLock {
                    source,
                }
            })
        })
        .transpose()
}

#[cfg(target_os = "linux")]
fn lock_project_platform(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<LockReport, ProjectOperationError> {
    let loaded = loader::load_project_mode(
        path,
        configuration,
        crate::acquire::github::InputMode::Refresh,
    )?;
    let checked = analyze::check_loaded(&loaded, configuration)?;
    let expected = expected_lock(&loaded, configuration)?;
    let existing = read_lock(&loaded)?;
    let old_graph = read_graph_lock(&loaded)?;
    let status = match (&existing, &old_graph) {
        (None, _) => lock::LockStatus::Created,
        (Some(existing), None) if existing.data() == expected.data() => lock::LockStatus::Unchanged,
        _ => lock::LockStatus::Updated,
    };
    if configuration.github.cancellation.is_cancelled() {
        return Err(CheckFailure::Github(crate::acquire::github::GithubError::Cancelled).into());
    }
    if status != lock::LockStatus::Unchanged {
        crate::platform::linux::fd::write_atomic_beneath(
            loaded.root.fd(),
            Path::new(lock::LOCK_FILE_NAME),
            expected.data(),
        )
        .map_err(map_lock_publication)?;
    }
    if old_graph.is_some() {
        let opened = crate::platform::linux::fd::open_existing_regular(
            loaded.root.fd(),
            Path::new(GRAPH_LOCK_FILE),
        )
        .map_err(|source| ProjectOperationError::GraphRemoval {
            source,
        })?;
        crate::platform::linux::fd::unlink_opened(
            loaded.root.fd(),
            Path::new(GRAPH_LOCK_FILE),
            opened.metadata().identity(),
        )
        .map_err(|source| ProjectOperationError::GraphRemoval {
            source,
        })?;
        crate::platform::linux::fd::sync_directory(loaded.root.fd()).map_err(|source| {
            ProjectOperationError::GraphRemoval {
                source,
            }
        })?;
    }
    Ok(LockReport {
        status,
        check: CheckReport {
            path: loaded.path.clone(),
            declarations: checked.resolved().parsed().declaration_count(),
            realized_roots: 0,
        },
        digest: *expected.digest(),
    })
}

#[cfg(target_os = "linux")]
fn check_project_lock_platform(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<LockReport, ProjectOperationError> {
    let project = open_locked_project_with(path, configuration)?;
    Ok(LockReport {
        status: lock::LockStatus::Unchanged,
        check: project.check_report(),
        digest: *project.lock_digest(),
    })
}

#[cfg(target_os = "linux")]
fn prepare_project_platform(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<PreparedPlan, ProjectOperationError> {
    let project = open_locked_project_with(path, configuration)?;
    let mut evaluation = project.evaluation()?;
    evaluation.include_project_outputs()?;
    evaluation.select_all_packages()?;
    evaluation.into_selected_prepared_plan()
}

#[cfg(target_os = "linux")]
fn project_plan(
    loaded: &LoadedProject,
    realized: &RealizedProgram,
    digest: [u8; 32],
    configuration: &CheckConfiguration,
) -> Result<PreparedPlan, ProjectOperationError> {
    analyze::require_success(loaded, realized)?;
    let plan = crate::plan::Plan::from_realized(
        realized,
        digest,
        configuration.policy.identity(),
        configuration.standard_library.as_ref(),
    )
    .map_err(ProjectOperationError::from)?;
    let mut roots = BTreeMap::new();
    collect_project_roots(
        loaded,
        loaded,
        SourceDomainId::project(),
        &mut roots,
    );
    for source in plan
        .acquisitions()
        .flat_map(crate::plan::PlanAcquisition::sources)
    {
        if let Some(path) = source.url().strip_prefix("project:") {
            let Some(owner) = source
                .owner()
                .and_then(|domain| roots.get(&domain))
            else {
                return Err(
                    ProjectOperationError::UnknownProjectSourceOrigin {
                        path: path.to_owned(),
                    },
                );
            };
            let Some(asset_path) = path.strip_prefix("assets/") else {
                continue;
            };
            let relative = Path::new("assets").join(asset_path);
            if !owner.assets().any(|asset| {
                asset.relative_path() == relative
                    && asset.digest() == source.digest().as_bytes()
                    && asset.size() <= source.maximum_bytes()
            }) {
                return Err(ProjectOperationError::UnpinnedProjectAsset {
                    path: relative.display().to_string(),
                });
            }
        }
    }
    Ok(PreparedPlan::new(plan, loaded.path(), &roots))
}

#[cfg(target_os = "linux")]
fn collect_project_roots<'a>(
    root: &LoadedProject,
    project: &'a LoadedProject,
    domain: SourceDomainId,
    roots: &mut BTreeMap<SourceDomainId, &'a LoadedProject>,
) {
    if roots.insert(domain, project).is_some() {
        return;
    }
    for (alias, child) in &project.children {
        let child_domain = root
            .sources()
            .child_project_domain(domain, alias)
            .expect("validated child has a source domain");
        collect_project_roots(root, child, child_domain, roots);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;

pub mod lock;
pub mod reference;

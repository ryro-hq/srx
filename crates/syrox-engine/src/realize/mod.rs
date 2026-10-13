//! Realiza os outputs de um plano já preparado.
//!
//! Resolver a referência escolhe a receita sem abrir a Store ou adquirir fontes.
//! Na realização, [`RealizeOptions`] traz configuração, worker e modo offline;
//! cancelamento e progresso pertencem ao pedido em andamento.
//!
//! A operação abre sua Store depois do preflight do backend e a compartilha com
//! as dependências. Leases globais terminam antes de executar outra dependência;
//! os interesses nos objetos e views continuam vivos durante o build.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use thiserror::Error;

use crate::{
    acquire::https::HttpsError, acquire::https::HttpsSourceRequest,
    acquire::https::HttpsTransportPolicy, acquire::https::acquire_https_with_cancellation,
    build::BuildError, build::BuildResult, cancellation::Cancellation, config::UserConfiguration,
    plan::PlanBuild, project::CheckConfiguration, project::PreparedPlan,
    project::ProjectOperationError, project::prepare_project_with, store::ContentDigest,
    store::RootName, store::Store, store::StoreError,
};

#[cfg(target_os = "linux")]
mod commands;
mod managed;
#[cfg(target_os = "linux")]
pub(crate) mod outputs;
#[cfg(target_os = "linux")]
pub use commands::{
    CommandError, ResolvedCommand, realize_command, resolve_command, resolve_plan_command,
};
#[cfg(target_os = "linux")]
pub use outputs::{ResolvedOutput, realize_output, resolve_plan_output};

/// Invocation policy shared by build and output realization. Cancellation and
/// progress belong to each request, rather than to this configuration.
#[derive(Clone, Copy, Debug)]
pub struct RealizeOptions<'a> {
    pub configuration: &'a UserConfiguration,
    pub worker: &'a Path,
    pub offline: bool,
}

/// The operation opens its Store after backend preflight. Dependencies borrow
/// this same Store; operation leases never cross dependency execution.
pub(crate) struct RealizeContext<'a> {
    options: RealizeOptions<'a>,
    store: OnceLock<Store>,
}

impl<'a> RealizeContext<'a> {
    pub(crate) fn new(options: RealizeOptions<'a>) -> Self {
        Self {
            options,
            store: OnceLock::new(),
        }
    }

    pub(crate) fn store(&self) -> Result<&Store, RealizeError> {
        if self.store.get().is_none() {
            let store = Store::initialize(self.options.configuration.store())?;
            let _ = self.store.set(store);
        }
        Ok(self
            .store
            .get()
            .expect("operation opened its Store"))
    }
}

#[derive(Debug)]
pub struct ResolvedBuild {
    project: PathBuf,
    export: String,
    lock_digest: String,
    prepared: PreparedPlan,
    build: PlanBuild,
}

impl ResolvedBuild {
    pub fn project(&self) -> &Path {
        &self.project
    }
    pub fn export(&self) -> &str {
        &self.export
    }
    pub fn lock_digest(&self) -> &str {
        &self.lock_digest
    }
    pub const fn description(&self) -> &PlanBuild {
        &self.build
    }
    pub fn backend(&self) -> &'static str {
        crate::build::PROFILE
    }
}

#[derive(Clone, Copy, Debug)]
pub enum BuildProgress {
    PreparingStore,
    CheckingBackend,
    SourceCacheHit,
    AcquiringSource,
    Building,
}

#[derive(Debug, Error)]
pub enum RealizeError {
    #[error("realization cancelled")]
    Cancelled,
    #[error(
        "invalid build reference; use a catalog export, .#export, ./path#export or a project path"
    )]
    InvalidReference,
    #[error(
        "no default catalog configured; set [catalog] path and lock-sha256 in the user configuration, or use .#export"
    )]
    MissingCatalog,
    #[error(
        "configured catalog lock has changed; inspect the checkout and explicitly update catalog.lock-sha256"
    )]
    CatalogDrift,
    #[error("select a public member explicitly with .#member or ./project#member")]
    MissingSelection,
    #[error("no public buildable package export `{0}` in this project")]
    MissingExport(String),
    #[error("the Plan has no build output `{}` for package `{}`", .0.output, .0.package)]
    MissingOutput(crate::plan::PlanOutputRef),
    #[error(
        "host bootstrap is not configured; set [build] host-toolchain = \"/usr\" in the user configuration"
    )]
    MissingToolchain,
    #[error(
        "managed build is not configured; set all fields in [build.managed] including the pinned worker and explicit manager scope"
    )]
    MissingManagedConfiguration,
    #[error("managed worker refused: {0}")]
    ManagedWorker(&'static str),
    #[error("source {0} is absent in offline mode")]
    OfflineMissing(ContentDigest),
    #[error("source URL has no exact grant in network.allow-https: {0}")]
    SourceDenied(String),
    #[error("automatic acquisition supports HTTPS and pinned project-local sources only")]
    UnsupportedSource,
    #[error(transparent)]
    Project(#[from] ProjectOperationError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Https(#[from] HttpsError),
    #[error(transparent)]
    Local(#[from] crate::acquire::local::LocalSourceError),
    #[error(transparent)]
    Build(#[from] BuildError),
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Materialization(#[from] crate::result::MaterializationError),
    #[error(transparent)]
    Result(crate::result::ResultError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<crate::result::ResultError> for RealizeError {
    fn from(error: crate::result::ResultError) -> Self {
        match error {
            crate::result::ResultError::Cancelled => Self::Cancelled,
            error => Self::Result(error),
        }
    }
}

impl From<crate::cancellation::Cancelled> for RealizeError {
    fn from(_: crate::cancellation::Cancelled) -> Self {
        Self::Cancelled
    }
}

/// Resolve a public export against verified recipe bytes without touching the
/// Store, network or build host. A simple name always uses the pinned catalog.
pub fn resolve_build(
    reference: &str,
    user: &UserConfiguration,
    checks: &CheckConfiguration,
) -> Result<ResolvedBuild, RealizeError> {
    let (project, export, pin) = reference_parts(reference, user)?;
    let key = export.ok_or(RealizeError::MissingSelection)?;
    let project = std::path::absolute(project)?;
    let plan = plan_for_export(&project, key, pin, checks)?;
    resolved_export(project, key, plan)
}

#[cfg(target_os = "linux")]
fn plan_for_export(
    project: &Path,
    key: &str,
    pin: Option<ContentDigest>,
    checks: &CheckConfiguration,
) -> Result<PreparedPlan, RealizeError> {
    let locked = crate::project::open_locked_project_with(project, checks)?;
    if pin.is_some_and(|pin| pin.as_bytes() != locked.lock_digest()) {
        return Err(RealizeError::CatalogDrift);
    }
    let mut evaluation = locked.evaluation()?;
    match evaluation.select_package(key) {
        Ok(true) => Ok(evaluation.into_selected_prepared_plan()?),
        Err(ProjectOperationError::MissingPackageReference {
            ..
        }) => Err(RealizeError::MissingExport(key.to_owned())),
        Err(error) => Err(error.into()),
        Ok(false) => {
            evaluation.evaluate_all()?;
            Ok(evaluation.into_prepared_plan()?)
        }
    }
}

fn resolved_export(
    project: PathBuf,
    export: &str,
    prepared: PreparedPlan,
) -> Result<ResolvedBuild, RealizeError> {
    let plan = prepared.plan();
    let export = export.to_owned();
    let package = plan
        .packages()
        .find(|package| package.has_export(&export))
        .ok_or_else(|| RealizeError::MissingExport(export.clone()))?;
    let build = plan
        .builds()
        .find(|build| build.package() == package.id())
        .ok_or_else(|| RealizeError::MissingExport(export.clone()))?
        .clone();
    Ok(resolved_node(project, export, prepared, build))
}

fn resolved_node(
    project: PathBuf,
    export: String,
    prepared: PreparedPlan,
    build: PlanBuild,
) -> ResolvedBuild {
    let lock_digest = prepared
        .plan()
        .lock_digest()
        .iter()
        .fold(String::new(), |mut text, byte| {
            write!(&mut text, "{byte:02x}").expect("String write is infallible");
            text
        });
    ResolvedBuild {
        project,
        export,
        lock_digest,
        prepared,
        build,
    }
}

/// Resolve all public builds from one verified project snapshot. In particular,
/// `build -A` must not reload and reevaluate the project for every export.
pub fn resolve_builds(
    reference: &str,
    user: &UserConfiguration,
    checks: &CheckConfiguration,
) -> Result<Vec<ResolvedBuild>, RealizeError> {
    let (project, export, pin) = reference_parts(reference, user)?;
    if export.is_some() {
        return Err(RealizeError::InvalidReference);
    }
    let project = std::path::absolute(project)?;
    let prepared = prepare_project_with(&project, checks)?;
    let plan = prepared.plan();
    if pin.is_some_and(|pin| pin.as_bytes() != plan.lock_digest()) {
        return Err(RealizeError::CatalogDrift);
    }
    let lock_digest = plan
        .lock_digest()
        .iter()
        .fold(String::new(), |mut text, byte| {
            write!(&mut text, "{byte:02x}").expect("String write is infallible");
            text
        });
    let mut builds = plan
        .packages()
        .filter_map(|package| {
            let export = package.export()?;
            let build = plan
                .builds()
                .find(|build| build.package() == package.id())?;
            Some(ResolvedBuild {
                project: project.clone(),
                export: export.to_owned(),
                lock_digest: lock_digest.clone(),
                prepared: prepared.clone(),
                build: build.clone(),
            })
        })
        .collect::<Vec<_>>();
    builds.sort_by(|left, right| left.export.cmp(&right.export));
    Ok(builds)
}

/// Search only the configured, pinned local catalog. No registry or network lookup.
pub fn search_build_exports(
    query: &str,
    user: &UserConfiguration,
    checks: &CheckConfiguration,
) -> Result<Vec<String>, RealizeError> {
    validate_search_query(query)?;
    let catalog = user
        .catalog()
        .ok_or(RealizeError::MissingCatalog)?;
    search_project_exports(
        query,
        catalog.path(),
        Some(catalog.lock_digest().as_bytes()),
        checks,
    )
}

/// Search a local project verified against its Lock, without a configured catalog.
pub fn search_project_build_exports(
    query: &str,
    path: &Path,
    checks: &CheckConfiguration,
) -> Result<Vec<String>, RealizeError> {
    search_project_exports(query, path, None, checks)
}

fn search_project_exports(
    query: &str,
    path: &Path,
    expected_lock: Option<&[u8; 32]>,
    checks: &CheckConfiguration,
) -> Result<Vec<String>, RealizeError> {
    validate_search_query(query)?;
    #[cfg(target_os = "linux")]
    let plan = {
        let locked = crate::project::open_locked_project_with(path, checks)?;
        if expected_lock.is_some_and(|expected| expected != locked.lock_digest()) {
            return Err(RealizeError::CatalogDrift);
        }
        let mut evaluation = locked.evaluation()?;
        if let Some(names) = evaluation.catalog_names()? {
            let query = query.to_ascii_lowercase();
            return Ok(names
                .into_iter()
                .filter(|name| name.to_ascii_lowercase().contains(&query))
                .collect());
        }
        evaluation.evaluate_all()?;
        evaluation.into_plan()?
    };
    let query = query.to_ascii_lowercase();
    let mut names = plan
        .packages()
        .filter(|package| {
            plan.builds()
                .any(|build| build.package() == package.id())
        })
        .filter_map(|package| {
            package
                .export()
                .filter(|export| export.to_ascii_lowercase().contains(&query))
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

fn validate_search_query(query: &str) -> Result<(), RealizeError> {
    if query.len() > 255 || !query.is_ascii() {
        return Err(RealizeError::InvalidReference);
    }
    Ok(())
}

type ReferenceParts<'a> = (&'a Path, Option<&'a str>, Option<ContentDigest>);

fn reference_parts<'a>(
    reference: &'a str,
    user: &'a UserConfiguration,
) -> Result<ReferenceParts<'a>, RealizeError> {
    match crate::project::reference::parse_project_reference(reference)
        .map_err(|_| RealizeError::InvalidReference)?
    {
        crate::project::reference::ProjectReference::Project {
            path,
            export,
        } => Ok((path, export, None)),
        crate::project::reference::ProjectReference::Catalog {
            export,
        } => {
            let catalog = user
                .catalog()
                .ok_or(RealizeError::MissingCatalog)?;
            Ok((
                catalog.path(),
                Some(export),
                Some(catalog.lock_digest()),
            ))
        }
    }
}

/// Cancellable realization. Source transport observes cancellation during its
/// bounded deadline. After admission, requests have
/// independent interests in a shared producer. The last cancellation stops its
/// payload through the service manager before cleanup or releasing retention.
pub fn realize_build(
    resolved: &ResolvedBuild,
    options: RealizeOptions<'_>,
    cancellation: &Cancellation,
    progress: impl FnMut(BuildProgress),
) -> Result<BuildResult, RealizeError> {
    RealizeContext::new(options).realize_build(resolved, cancellation, progress)
}

/// Realize several exports with bounded invocation-wide admission. A completed
/// task immediately releases capacity to the next export; results and failures
/// are selected in the original export order after every admitted task settles.
pub fn realize_builds(
    builds: &[ResolvedBuild],
    options: RealizeOptions<'_>,
    jobs: usize,
    cancellation: &Cancellation,
) -> Result<Vec<BuildResult>, RealizeError> {
    run_bounded(builds.len(), jobs.min(8), |index| {
        realize_build(&builds[index], options, cancellation, |_| {})
    })
}

fn run_bounded<T: Send, E: Send + From<std::io::Error>>(
    count: usize,
    jobs: usize,
    work: impl Fn(usize) -> Result<T, E> + Sync,
) -> Result<Vec<T>, E> {
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let completed = Mutex::new(Vec::with_capacity(count));
    std::thread::scope(|scope| -> Result<(), E> {
        let mut handles = Vec::new();
        for _ in 0..count.min(jobs.max(1)) {
            let handle = std::thread::Builder::new().spawn_scoped(scope, || {
                while !failed.load(Ordering::Acquire) {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= count {
                        break;
                    }
                    let result = work(index);
                    if result.is_err() {
                        failed.store(true, Ordering::Release);
                    }
                    completed
                        .lock()
                        .expect("build result queue poisoned")
                        .push((index, result));
                }
            });
            match handle {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    failed.store(true, Ordering::Release);
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err(E::from(error));
                }
            }
        }
        let mut panicked = false;
        for handle in handles {
            panicked |= handle.join().is_err();
        }
        if panicked {
            return Err(E::from(std::io::Error::other(
                "build worker panicked",
            )));
        }
        Ok(())
    })?;
    let mut results = completed
        .into_inner()
        .expect("build result queue poisoned");
    results.sort_by_key(|(index, _)| *index);
    results
        .into_iter()
        .map(|(_, result)| result)
        .collect()
}

impl RealizeContext<'_> {
    fn realize_build(
        &self,
        resolved: &ResolvedBuild,
        cancellation: &Cancellation,
        progress: impl FnMut(BuildProgress),
    ) -> Result<BuildResult, RealizeError> {
        cancellation.check()?;
        match resolved.build.program().profile {
            crate::build::BuildProfile::Managed => {
                managed::realize(resolved, self, cancellation, progress)
            }
            crate::build::BuildProfile::HostBootstrap => {
                self.realize_bootstrap(resolved, cancellation, progress)
            }
        }
    }

    fn realize_bootstrap(
        &self,
        resolved: &ResolvedBuild,
        cancellation: &Cancellation,
        mut progress: impl FnMut(BuildProgress),
    ) -> Result<BuildResult, RealizeError> {
        let RealizeOptions {
            configuration: user,
            worker,
            offline,
        } = self.options;
        #[cfg(target_os = "linux")]
        let mut phases = crate::build::profile::PhaseProfiler::new();
        cancellation.check()?;
        let toolchain = user
            .host_toolchain()
            .ok_or(RealizeError::MissingToolchain)?;
        progress(BuildProgress::PreparingStore);
        cancellation.check()?;
        let store = self.store()?;
        let lease = store.operation()?;
        if let Some(input) = resolved.build.inputs().first()
            && !resolved
                .prepared
                .plan()
                .imports()
                .any(|item| item.package() == &input.package)
            && let Some((result, _)) = crate::build::retained_build_with_inputs(
                resolved.prepared.plan(),
                &resolved.build,
                &input.package,
                store,
                toolchain,
                worker,
                cancellation,
            )?
        {
            progress(BuildProgress::SourceCacheHit);
            return Ok(result);
        }
        #[cfg(target_os = "linux")]
        phases.mark("store-open");
        drop(lease); // Dependency execution must not inherit the global Store barrier.
        let mut inputs = Vec::new();
        let mut input_views = Vec::new();
        #[cfg(target_os = "linux")]
        for selected in resolved.build.inputs() {
            cancellation.check()?;
            let selected_output = resolve_plan_output(&resolved.prepared, selected)?;
            let package = outputs::realize_package(
                &selected_output,
                self,
                cancellation,
                &mut progress as &mut dyn FnMut(BuildProgress),
            )?;
            let (view, output) = package.materialize(store, &selected.output, cancellation)?;
            input_views.push(view);
            inputs.push(crate::build::BuildInput {
                output,
            });
        }
        let specification = crate::build::BuildSpecification {
            inputs,
            ..resolved.build.request()
        };
        let lease = store.operation()?;
        // An admitted result already retains and verifies the locked source. On a
        // miss, keep the prepared Action (including worker and inventory bytes)
        // across acquisition so the backend never reinvents a different identity.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let prepared = if lease.managed_build_roots()?.is_empty() {
            // A new Store cannot contain an admitted build result. Keep the cold
            // acquisition's previous early offline/permission checks and inventory
            // the toolchain only once, after the source has arrived.
            phases.mark("pre-source-empty-store");
            None
        } else {
            match crate::build::prepare_managed(
                resolved.prepared.plan(),
                &specification,
                store,
                toolchain,
                worker,
                cancellation,
            )? {
                crate::build::PreparedLookup::Hit(result) => {
                    phases.mark("pre-source-action-hit");
                    progress(BuildProgress::Building);
                    return Ok(*result);
                }
                crate::build::PreparedLookup::Miss(prepared) => {
                    phases.mark("pre-source-action-miss");
                    Some(prepared)
                }
            }
        };
        let source = resolved
            .prepared
            .plan()
            .acquisitions()
            .find(|acquisition| acquisition.package() == resolved.build.package())
            .and_then(|acquisition| acquisition.sources().next())
            .expect("validated build source");
        let maximum_source =
            if resolved.build.program().resources == crate::build::BuildResources::Large {
                crate::build::MAX_LARGE_SOURCE_BYTES
            } else {
                crate::build::MAX_SOURCE_BYTES
            };
        // Integrity failures are errors, never a trigger for silent replacement.
        #[cfg(target_os = "linux")]
        let cached = source_cached(
            &lease,
            source.digest(),
            source.maximum_bytes().min(maximum_source),
            cancellation,
        )?;
        #[cfg(target_os = "linux")]
        phases.mark("source-lookup");
        if !cached {
            // Offline forbids transport, not reading a digest-pinned file beneath
            // this project's explicitly authorized directory.
            if offline && source.url().starts_with("https://") {
                return Err(RealizeError::OfflineMissing(source.digest()));
            }
            if !source.url().starts_with("https://") && !source.url().starts_with("project:") {
                return Err(RealizeError::UnsupportedSource);
            }
            if source.url().starts_with("https://") && !user.permits_https(source.url()) {
                return Err(RealizeError::SourceDenied(
                    source.url().to_owned(),
                ));
            }
        }
        if cached {
            progress(BuildProgress::SourceCacheHit);
        } else {
            // Keep the pre-download capability check. A fully local result may be
            // reused without a live service manager; misses check again before launch.
            progress(BuildProgress::CheckingBackend);
            cancellation.check()?;
            if source.url().starts_with("https://") {
                crate::build::check_build_host(toolchain)?;
            }
            cancellation.check()?;
            progress(BuildProgress::AcquiringSource);
            cancellation.check()?;
            let root = RootName::new(format!("source_{}", source.digest()))
                .expect("digest makes a bounded root");
            if let Some(relative) = source.url().strip_prefix("project:") {
                let origin = source
                    .owner()
                    .and_then(|owner| resolved.prepared.project_root(owner))
                    .ok_or(RealizeError::UnsupportedSource)?;
                acquire_build_local(
                    store,
                    origin,
                    relative,
                    source.digest(),
                    source.maximum_bytes().min(maximum_source),
                    &root,
                    cancellation,
                )?;
            } else {
                acquire_build_https(
                    store,
                    source.url(),
                    source.digest(),
                    source.maximum_bytes().min(maximum_source),
                    &root,
                    cancellation,
                )?;
            }
        }
        #[cfg(target_os = "linux")]
        phases.mark("source-acquisition");
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        if !cached && let Some(ref prepared) = prepared {
            prepared.revalidate_after_acquisition(toolchain, cancellation)?;
            phases.mark("post-acquisition-inventory-check");
        }
        progress(BuildProgress::Building);
        cancellation.check()?;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let result = if let Some(prepared) = prepared {
            crate::build::build_prepared(*prepared, store, toolchain, cancellation)?
        } else {
            crate::build::build_managed(
                resolved.prepared.plan(),
                &specification,
                store,
                toolchain,
                worker,
                cancellation,
            )?
        };
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        let result = crate::build::build_managed(
            resolved.prepared.plan(),
            &specification,
            store,
            toolchain,
            worker,
            cancellation,
        )?;
        #[cfg(target_os = "linux")]
        phases.mark("build-realization");
        drop(lease);
        Ok(result)
    }
}

pub(crate) fn acquire_build_local(
    store: &Store,
    project_path: &Path,
    relative: &str,
    digest: ContentDigest,
    maximum_bytes: u64,
    root: &RootName,
    cancellation: &Cancellation,
) -> Result<(), RealizeError> {
    let absolute = std::path::absolute(project_path)?;
    // The loader already admitted every component without following symlinks.
    // Remove lexical `..` left by a sibling locator before constructing the
    // absolute file URL; canonicalize() here would follow a newly added symlink.
    let mut project_path = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::ParentDir => {
                project_path.pop();
            }
            std::path::Component::CurDir => {}
            other => project_path.push(other.as_os_str()),
        }
    }
    let project = crate::acquire::local::AuthorizedLocalDirectory::open(&project_path)?;
    let path = project_path.join(relative);
    let url = url::Url::from_file_path(&path)
        .map_err(|()| RealizeError::UnsupportedSource)?
        .to_string();
    let request = crate::acquire::local::LocalSourceRequest::new(&url, digest, maximum_bytes)?;
    crate::acquire::local::acquire_local_with_cancellation(
        store,
        &project,
        &request,
        root,
        cancellation,
    )
    .map_err(|error| match error {
        crate::acquire::local::LocalSourceError::Cancelled => RealizeError::Cancelled,
        error => RealizeError::Local(error),
    })?;
    Ok(())
}

fn acquire_build_https(
    store: &Store,
    url: &str,
    digest: ContentDigest,
    maximum_bytes: u64,
    root: &RootName,
    cancellation: &Cancellation,
) -> Result<(), RealizeError> {
    let request = HttpsSourceRequest::new(url, digest, maximum_bytes)?;
    acquire_https_with_cancellation(
        store,
        &request,
        root,
        HttpsTransportPolicy {
            maximum_redirects: 0,
            ..HttpsTransportPolicy::default()
        },
        cancellation,
    )
    .map_err(|error| match error {
        HttpsError::Cancelled => RealizeError::Cancelled,
        error => RealizeError::Https(error),
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn source_cached(
    lease: &crate::store::OperationLease,
    digest: ContentDigest,
    maximum_bytes: u64,
    cancellation: &Cancellation,
) -> Result<bool, RealizeError> {
    lease
        .open_verified_checked(digest, maximum_bytes, || {
            if cancellation.is_cancelled() {
                Err(crate::cancellation::cancellation_io())
            } else {
                Ok(())
            }
        })
        .map(|source| source.is_some())
        .map_err(|error| {
            if cancellation.is_cancelled()
                && matches!(error, StoreError::Io(ref source) if crate::cancellation::is_cancellation_io(source))
            {
                RealizeError::Cancelled
            } else {
                RealizeError::Store(error)
            }
        })
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use std::sync::{atomic::AtomicUsize, mpsc};
    use std::time::Duration;

    #[test]
    fn capacity_is_replenished_without_a_batch_barrier() {
        let (release, waiting) = mpsc::channel();
        let waiting = Mutex::new(waiting);
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let result = run_bounded::<usize, std::io::Error>(3, 2, |index| {
            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(current, Ordering::SeqCst);
            if index == 0 {
                waiting
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(std::io::Error::other)?;
            } else if index == 2 {
                release.send(()).unwrap();
            }
            active.fetch_sub(1, Ordering::SeqCst);
            Ok(index)
        })
        .unwrap();
        assert_eq!(result, [0, 1, 2]);
        assert!(peak.load(Ordering::SeqCst) <= 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn failures_select_the_earliest_export_after_admitted_work_settles() {
        let gate = std::sync::Barrier::new(2);
        let next_started = AtomicBool::new(false);
        let result = run_bounded::<(), std::io::Error>(3, 2, |index| {
            if index == 2 {
                next_started.store(true, Ordering::SeqCst);
            }
            gate.wait();
            if index == 0 {
                std::thread::sleep(Duration::from_millis(30));
            }
            Err(std::io::Error::other(format!("failure {index}")))
        });
        assert_eq!(result.unwrap_err().to_string(), "failure 0");
        assert!(!next_started.load(Ordering::SeqCst));
    }
}

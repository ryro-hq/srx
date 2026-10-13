use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use syrox_lang::{
    analysis::AnalysisCancellation, analysis::AnalysisCancelled, analysis::AnalysisHost,
    analysis::AnalysisLimits, analysis::AnalysisRevision, analysis::AnalysisSnapshot,
    analysis::AnalysisUpdateError, analysis::DocumentSnapshot, analysis::SemanticAnalysis,
    analysis::SemanticAnalysisError, checker::CheckPolicy, source::SourceId, source::SourceSet,
    syntax::ItemKind, syntax::SyntaxKeyword, syntax::SyntaxTokenKind,
};
use thiserror::Error;

use super::{CheckConfiguration, LoadedProject};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectAnalysisLockStatus {
    Unchecked,
    Missing,
    Current,
    Drift,
}

#[derive(Debug, Error)]
pub enum ProjectAnalysisError {
    #[error(transparent)]
    Update(#[from] AnalysisUpdateError),
    #[error(transparent)]
    Cancelled(#[from] AnalysisCancelled),
    #[error(transparent)]
    Semantic(#[from] SemanticAnalysisError),
    #[error("editor source is not part of the loaded project graph")]
    UnknownSource,
    #[error("authenticated virtual sources are read-only")]
    ReadOnlySource,
    #[error("input declarations changed or are incomplete; reload the project graph")]
    TopologyChanged,
}

/// Editor inputs over a loaded graph. Domain/module/standard-library identity
/// comes from the loader; editing text cannot change these bindings in place.
#[derive(Debug)]
pub struct ProjectAnalysis {
    paths: Arc<BTreeMap<SourceId, std::path::PathBuf>>,
    host: AnalysisHost,
    topology: Arc<SourceSet>,
    bindings: Arc<BTreeMap<SourceId, String>>,
    inputs: Arc<BTreeMap<SourceId, Vec<(String, String)>>>,
    policy: Arc<CheckPolicy>,
    cache: Arc<OnceLock<Arc<SemanticAnalysis>>>,
    reusable: Option<Arc<OnceLock<Arc<SemanticAnalysis>>>>,
    lock_status: ProjectAnalysisLockStatus,
}

impl ProjectAnalysis {
    pub fn from_loaded(
        loaded: &LoadedProject,
        configuration: &CheckConfiguration,
    ) -> Result<Self, ProjectAnalysisError> {
        Self::from_editor_sources(
            loaded.sources().clone(),
            source_paths(loaded),
            configuration,
        )
    }

    fn from_editor_sources(
        sources: SourceSet,
        paths: BTreeMap<SourceId, std::path::PathBuf>,
        configuration: &CheckConfiguration,
    ) -> Result<Self, ProjectAnalysisError> {
        let mut host = AnalysisHost::new(AnalysisLimits {
            max_documents: configuration.project_limits.max_sources,
            max_source_bytes: configuration
                .project_limits
                .max_total_bytes
                .saturating_mul(2),
        });
        let mut bindings = BTreeMap::new();
        let mut inputs = BTreeMap::new();
        for (id, source) in sources.iter() {
            // Source names may repeat across imported domains. Keys are local
            // to this topology and cannot alias another project's source.
            let key = format!("source:{}", id.index());
            host.set_disk(&key, source.text())?;
            inputs.insert(
                id,
                input_contract(&syrox_lang::syntax::parse_file(source))?,
            );
            bindings.insert(id, key);
        }
        Ok(Self {
            paths: Arc::new(paths),
            host,
            topology: Arc::new(sources),
            bindings: Arc::new(bindings),
            inputs: Arc::new(inputs),
            policy: Arc::new(configuration.policy.clone()),
            cache: Arc::new(OnceLock::new()),
            reusable: None,
            lock_status: ProjectAnalysisLockStatus::Unchecked,
        })
    }

    pub fn set_overlay(
        &mut self,
        id: SourceId,
        version: i32,
        text: &str,
    ) -> Result<AnalysisRevision, ProjectAnalysisError> {
        if !self.paths.contains_key(&id) && self.bindings.contains_key(&id) {
            return Err(ProjectAnalysisError::ReadOnlySource);
        }
        let key = self
            .bindings
            .get(&id)
            .ok_or(ProjectAnalysisError::UnknownSource)?;
        let same = self
            .host
            .snapshot()
            .document(key)
            .is_some_and(|document| document.source().text() == text);
        let revision = self.host.set_overlay(key, version, text)?;
        self.invalidate(same);
        Ok(revision)
    }

    pub fn close_overlay(
        &mut self,
        id: SourceId,
    ) -> Result<AnalysisRevision, ProjectAnalysisError> {
        let key = self
            .bindings
            .get(&id)
            .ok_or(ProjectAnalysisError::UnknownSource)?;
        let previous = self.host.snapshot().revision();
        let before = self.host.snapshot().document(key);
        let revision = self.host.close_overlay(key)?;
        let same = before
            .zip(self.host.snapshot().document(key))
            .is_some_and(|(before, after)| before.source().text() == after.source().text());
        if revision != previous {
            self.invalidate(same);
        }
        Ok(revision)
    }

    pub fn is_current(&self, revision: &AnalysisRevision) -> bool {
        self.host.is_current(revision)
    }

    fn invalidate(&mut self, same_content: bool) {
        self.reusable = if same_content {
            if self.cache.get().is_some() || self.reusable.is_none() {
                Some(self.cache.clone())
            } else {
                self.reusable.clone()
            }
        } else {
            None
        };
        self.cache = Arc::new(OnceLock::new());
    }

    pub fn snapshot(&self) -> ProjectAnalysisSnapshot {
        ProjectAnalysisSnapshot {
            paths: self.paths.clone(),
            snapshot: self.host.snapshot(),
            topology: self.topology.clone(),
            bindings: self.bindings.clone(),
            inputs: self.inputs.clone(),
            policy: self.policy.clone(),
            cache: self.cache.clone(),
            reusable: self.reusable.clone(),
            lock_status: self.lock_status,
        }
    }
}

/// Inspection-only authoring workspace for a standard-library source tree.
/// Reads all .srx siblings recursively into one std domain, without loading the
/// bundled std a second time or constructing an authenticated execution project.
#[cfg(target_os = "linux")]
pub fn open_standard_library_analysis_with(
    path: &std::path::Path,
    configuration: &CheckConfiguration,
) -> Result<ProjectAnalysis, super::ProjectOperationError> {
    use super::loader::{InputRoot, LoadBudget, open_top, walk_input};
    super::validate_project_limits(configuration.project_limits)?;
    let mut budget = LoadBudget::new(configuration.project_limits);
    let opened = open_top(path, &mut budget)?;
    let files = walk_input(
        path,
        InputRoot {
            name: "std".into(),
            relative: std::path::PathBuf::new(),
            opened,
        },
        &mut std::collections::HashMap::new(),
        &mut std::collections::HashMap::new(),
        &mut budget,
    )?;
    let mut sources = SourceSet::new();
    let mut paths = BTreeMap::new();
    for (relative, text) in files {
        let physical = path.join(relative);
        let id = sources
            .add_standard_library(physical.display().to_string(), text)
            .map_err(super::CheckFailure::from)?;
        paths.insert(id, physical);
    }
    ProjectAnalysis::from_editor_sources(sources, paths, configuration)
        .map_err(super::ProjectOperationError::Editor)
}

#[derive(Clone, Debug)]
pub struct ProjectAnalysisSnapshot {
    paths: Arc<BTreeMap<SourceId, std::path::PathBuf>>,
    snapshot: AnalysisSnapshot,
    topology: Arc<SourceSet>,
    bindings: Arc<BTreeMap<SourceId, String>>,
    inputs: Arc<BTreeMap<SourceId, Vec<(String, String)>>>,
    policy: Arc<CheckPolicy>,
    cache: Arc<OnceLock<Arc<SemanticAnalysis>>>,
    reusable: Option<Arc<OnceLock<Arc<SemanticAnalysis>>>>,
    lock_status: ProjectAnalysisLockStatus,
}

impl ProjectAnalysisSnapshot {
    /// Physical files from the loaded graph. Std and generated sources have no
    /// filesystem URI. Multiple domains may refer to the same physical file.
    pub fn source_paths(&self) -> &BTreeMap<SourceId, std::path::PathBuf> {
        &self.paths
    }
    pub fn revision(&self) -> AnalysisRevision {
        self.snapshot.revision()
    }
    /// Status of the disk graph when opened, not an authentication of overlays.
    pub const fn lock_status(&self) -> ProjectAnalysisLockStatus {
        self.lock_status
    }
    pub fn sources(&self) -> &SourceSet {
        &self.topology
    }
    pub fn document(&self, id: SourceId) -> Option<DocumentSnapshot> {
        self.snapshot.document(self.bindings.get(&id)?)
    }

    pub fn analyze(
        &self,
        cancellation: &AnalysisCancellation,
    ) -> Result<Arc<SemanticAnalysis>, ProjectAnalysisError> {
        cancellation.check()?;
        if let Some(cached) = self.cache.get() {
            return Ok(cached.clone());
        }
        if let Some(previous) = self
            .reusable
            .as_ref()
            .and_then(|cache| cache.get())
            && let Some(reused) = self
                .snapshot
                .revalidate_project_analysis(previous, cancellation)?
        {
            let reused = Arc::new(reused);
            let _ = self.cache.set(reused.clone());
            return Ok(self.cache.get().cloned().unwrap_or(reused));
        }
        for (id, expected) in self.inputs.iter() {
            let document = self
                .document(*id)
                .ok_or(ProjectAnalysisError::UnknownSource)?;
            if input_contract(document.parsed(cancellation)?)? != *expected {
                return Err(ProjectAnalysisError::TopologyChanged);
            }
        }
        let analysis = Arc::new(self.snapshot.analyze_project(
            &self.topology,
            &self.bindings,
            &self.policy,
            cancellation,
        )?);
        cancellation.check()?;
        let _ = self.cache.set(analysis.clone());
        Ok(self.cache.get().cloned().unwrap_or(analysis))
    }
}

fn source_paths(loaded: &LoadedProject) -> BTreeMap<SourceId, std::path::PathBuf> {
    fn collect(
        project: &LoadedProject,
        topology: &SourceSet,
        index: &BTreeMap<(syrox_lang::source::SourceDomainId, &str), SourceId>,
        owner: syrox_lang::source::SourceDomainId,
        paths: &mut BTreeMap<SourceId, std::path::PathBuf>,
        visited: &mut std::collections::BTreeSet<syrox_lang::source::SourceDomainId>,
    ) {
        if !visited.insert(owner) {
            return;
        }
        #[cfg(target_os = "linux")]
        if project.snapshot.is_some() {
            // The LSP serves these sources through its read-only virtual scheme.
            return;
        }
        if let Some(&id) = index.get(&(owner, project.main_source().name())) {
            paths.insert(id, project.path().join("main.srx"));
        }
        for input in project.inputs() {
            let Some(domain) = topology.input_domain(owner, input.name()) else {
                continue;
            };
            let Some((_, relative)) = input.locator().split_once(':') else {
                continue;
            };
            for file in input.files() {
                let original = project
                    .sources()
                    .get(file.source_id())
                    .expect("loaded input source");
                if let Some(&id) = index.get(&(domain, original.name())) {
                    paths.insert(
                        id,
                        project
                            .path()
                            .join(relative)
                            .join(file.relative_path()),
                    );
                }
            }
        }
        #[cfg(target_os = "linux")]
        for (alias, child) in &project.children {
            if let Some(domain) = topology.child_project_domain(owner, alias) {
                collect(child, topology, index, domain, paths, visited);
            }
        }
    }
    let mut paths = BTreeMap::new();
    let index = loaded
        .sources()
        .iter()
        .map(|(id, source)| {
            (
                (
                    loaded
                        .sources()
                        .domain(id)
                        .expect("registered source domain"),
                    source.name(),
                ),
                id,
            )
        })
        .collect();
    collect(
        loaded,
        loaded.sources(),
        &index,
        syrox_lang::source::SourceDomainId::project(),
        &mut paths,
        &mut std::collections::BTreeSet::new(),
    );
    paths
}

fn input_contract(
    parsed: &syrox_lang::syntax::ParsedFile,
) -> Result<Vec<(String, String)>, ProjectAnalysisError> {
    let mut blocks = 0;
    let mut inputs = Vec::new();
    for item in parsed.recovered_items() {
        if let ItemKind::Inputs(declaration) = &item.kind {
            blocks += 1;
            inputs.extend(declaration.entries.iter().map(|input| {
                (
                    input.name.text.clone(),
                    input.value.source.clone(),
                )
            }));
        }
    }
    // Missing/nested input blocks cannot silently inherit the old graph.
    if blocks
        != parsed
            .tokens()
            .filter(|token| token.kind == SyntaxTokenKind::Keyword(SyntaxKeyword::Inputs))
            .count()
    {
        return Err(ProjectAnalysisError::TopologyChanged);
    }
    inputs.sort();
    Ok(inputs)
}

#[cfg(target_os = "linux")]
pub fn open_project_analysis_with(
    path: &std::path::Path,
    configuration: &CheckConfiguration,
) -> Result<ProjectAnalysis, super::ProjectOperationError> {
    super::validate_project_limits(configuration.project_limits)?;
    let loaded = super::loader::load_project_linux(path, configuration)?;
    let expected = crate::project::lock::LockManifest::generate(
        &loaded,
        configuration.standard_library.as_ref(),
    )
    .map_err(super::map_generated_lock_error)?;
    let status = match super::read_lock(&loaded)? {
        None => ProjectAnalysisLockStatus::Missing,
        Some(actual)
            if super::compare_lock(&actual, &expected).is_ok()
                && super::read_graph_lock(&loaded)?.is_none() =>
        {
            ProjectAnalysisLockStatus::Current
        }
        Some(_) => ProjectAnalysisLockStatus::Drift,
    };
    let mut analysis = ProjectAnalysis::from_loaded(&loaded, configuration)
        .map_err(super::ProjectOperationError::Editor)?;
    analysis.lock_status = status;
    Ok(analysis)
}

//! Loading a project and analyzing the snapshot requested by the editor.
//!
//! The worker loads, synchronizes overlays, analyzes and publishes. `Ready` keeps
//! the project and active versions; `Failed` keeps the error until the next reload.
//! Cancellation and generation determine whether a result may still reach the
//! editor.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, mpsc::SyncSender};

use syrox_engine::{
    project::CheckConfiguration, project::ProjectAnalysis, project::ProjectAnalysisLockStatus,
    project::ProjectAnalysisSnapshot, project::open_project_analysis_with,
    project::open_standard_library_analysis_with,
};
use syrox_lang::{
    analysis::AnalysisCancellation, analysis::AnalysisSnapshot, analysis::SemanticAnalysis,
    source::SourceId,
};

use super::{Event, file_uri};

#[derive(Debug)]
pub(super) struct Job {
    pub mode: WorkspaceMode,
    pub generation: u64,
    pub reload: u64,
    pub root: PathBuf,
    pub documents: AnalysisSnapshot,
    pub cancellation: AnalysisCancellation,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) enum WorkspaceMode {
    #[default]
    Project,
    StandardLibrary,
}

#[derive(Debug)]
pub(super) struct ResultSet {
    pub generation: u64,
    pub analysis: Result<Arc<SemanticAnalysis>, String>,
    pub paths: BTreeMap<SourceId, String>,
    pub lock_status: ProjectAnalysisLockStatus,
    pub metadata_truncated: bool,
}

impl ResultSet {
    pub(super) fn uri(&self, id: SourceId) -> String {
        self.paths.get(&id).cloned().unwrap_or_else(|| {
            format!(
                "syrox-source://{}/{}/{}.srx",
                std::process::id(),
                self.generation,
                id.index()
            )
        })
    }

    pub(super) fn virtual_source(&self, uri: &str) -> Option<&syrox_lang::source::Source> {
        if !uri.starts_with("syrox-source:") {
            return None;
        }
        self.analysis
            .as_ref()
            .ok()?
            .sources()
            .iter()
            .find(|(id, _)| !self.paths.contains_key(id) && self.uri(*id) == uri)
            .map(|(_, source)| source)
    }
}

/// One active job and one replaceable pending job; rapid edits cannot queue an
/// unbounded history of snapshots. The coordinator owns cancellation/publication.
#[derive(Debug, Default)]
pub(super) struct Jobs {
    pending: Mutex<(Option<Job>, bool)>,
    ready: Condvar,
}

impl Jobs {
    pub fn submit(&self, job: Job) {
        self.pending.lock().expect("job lock").0 = Some(job);
        self.ready.notify_one();
    }
    pub fn stop(&self) {
        *self.pending.lock().expect("job lock") = (None, true);
        self.ready.notify_one();
    }
    fn next(&self) -> Option<Job> {
        let mut pending = self.pending.lock().expect("job lock");
        loop {
            if pending.1 {
                return None;
            }
            if let Some(job) = pending.0.take() {
                return Some(job);
            }
            pending = self.ready.wait(pending).expect("job lock");
        }
    }
}

#[derive(Debug, Default)]
enum WorkspaceState {
    #[default]
    Unloaded,
    Ready {
        reload: u64,
        workspace: Box<ReadyWorkspace>,
    },
    Failed {
        reload: u64,
        error: String,
    },
}

#[derive(Debug)]
struct ReadyWorkspace {
    project: ProjectAnalysis,
    active: BTreeMap<SourceId, i32>,
}

impl WorkspaceState {
    fn load(&mut self, job: &Job, configuration: &CheckConfiguration) {
        if matches!(self, Self::Ready { reload, .. } | Self::Failed { reload, .. } if *reload == job.reload)
        {
            return;
        }
        let loaded = match job.mode {
            WorkspaceMode::Project => open_project_analysis_with(&job.root, configuration),
            WorkspaceMode::StandardLibrary => {
                open_standard_library_analysis_with(&job.root, configuration)
            }
        };
        *self = match loaded {
            Ok(project) => Self::Ready {
                reload: job.reload,
                workspace: Box::new(ReadyWorkspace {
                    project,
                    active: BTreeMap::new(),
                }),
            },
            Err(error) => Self::Failed {
                reload: job.reload,
                error: error.to_string(),
            },
        };
    }

    fn synchronize(&mut self, job: &Job) -> SynchronizedJob {
        match self {
            Self::Ready {
                workspace,
                ..
            } => {
                let paths = workspace
                    .project
                    .snapshot()
                    .source_paths()
                    .iter()
                    .filter_map(|(id, path)| file_uri(path).map(|uri| (*id, uri)))
                    .collect();
                let synchronized = workspace.synchronize_overlays(job, &paths);
                let snapshot = workspace.project.snapshot();
                SynchronizedJob {
                    paths,
                    lock_status: snapshot.lock_status(),
                    snapshot: synchronized.map(|()| snapshot),
                }
            }
            Self::Failed {
                error,
                ..
            } => SynchronizedJob {
                paths: BTreeMap::new(),
                lock_status: ProjectAnalysisLockStatus::Unchecked,
                snapshot: Err(error.clone()),
            },
            Self::Unloaded => unreachable!("load precedes overlay synchronization"),
        }
    }
}

impl ReadyWorkspace {
    fn synchronize_overlays(
        &mut self,
        job: &Job,
        paths: &BTreeMap<SourceId, String>,
    ) -> Result<(), String> {
        let mut present = BTreeSet::new();
        let mut update_error = None;
        for (id, uri) in paths {
            if let Some(document) = job.documents.document(uri) {
                let version = document
                    .overlay_version()
                    .expect("open buffer version");
                present.insert(*id);
                if self.active.get(id) != Some(&version) {
                    // Preserve content caches on ordinary newer versions;
                    // only a reopened sequence needs its old overlay closed.
                    let reset = if self
                        .active
                        .get(id)
                        .is_some_and(|old| version <= *old)
                    {
                        self.project.close_overlay(*id).map(|_| ())
                    } else {
                        Ok(())
                    };
                    let result = reset.and_then(|()| {
                        self.project
                            .set_overlay(*id, version, document.source().text())
                    });
                    match result {
                        Ok(_) => {
                            self.active.insert(*id, version);
                        }
                        Err(error) => {
                            update_error = Some(error.to_string());
                        }
                    }
                }
            }
        }
        for id in self
            .active
            .keys()
            .copied()
            .filter(|id| !present.contains(id))
            .collect::<Vec<_>>()
        {
            if let Err(error) = self.project.close_overlay(id) {
                update_error = Some(error.to_string());
            }
            self.active.remove(&id);
        }
        update_error.map_or(Ok(()), Err)
    }
}

struct SynchronizedJob {
    snapshot: Result<ProjectAnalysisSnapshot, String>,
    paths: BTreeMap<SourceId, String>,
    lock_status: ProjectAnalysisLockStatus,
}

impl SynchronizedJob {
    fn analyze(self, job: &Job) -> ResultSet {
        let mut metadata_truncated = false;
        let analysis = self
            .snapshot
            .and_then(|snapshot| {
                snapshot
                    .analyze(&job.cancellation)
                    .map_err(|error| error.to_string())
            })
            .and_then(|analysis| {
                analysis
                    .occurrences(&job.cancellation)
                    .map_err(|error| error.to_string())?;
                let symbols_truncated = analysis
                    .symbols_truncated(&job.cancellation)
                    .map_err(|error| error.to_string())?;
                let interfaces_truncated = analysis
                    .type_interfaces_truncated(&job.cancellation)
                    .map_err(|error| error.to_string())?;
                metadata_truncated = analysis.editor_facts_truncated()
                    || analysis.resolution_owners_truncated()
                    || symbols_truncated
                    || interfaces_truncated;
                Ok(analysis)
            });
        ResultSet {
            generation: job.generation,
            analysis,
            paths: self.paths,
            lock_status: self.lock_status,
            metadata_truncated,
        }
    }
}

pub(super) fn spawn(jobs: Arc<Jobs>, events: SyncSender<Event>, configuration: CheckConfiguration) {
    std::thread::spawn(move || {
        let mut state = WorkspaceState::Unloaded;
        while let Some(job) = jobs.next() {
            if job.cancellation.check().is_err() {
                continue;
            }
            state.load(&job, &configuration);
            if job.cancellation.check().is_err() {
                continue;
            }
            let synchronized = state.synchronize(&job);
            let result = synchronized.analyze(&job);
            if job.cancellation.check().is_ok() && events.send(Event::Analyzed(result)).is_err() {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_workspace_retries_only_after_reload_and_publishes_no_old_paths() {
        let root = tempfile::tempdir().unwrap();
        let host = syrox_lang::analysis::AnalysisHost::default();
        let mut job = Job {
            mode: WorkspaceMode::Project,
            generation: 1,
            reload: 1,
            root: root.path().join("missing"),
            documents: host.snapshot(),
            cancellation: AnalysisCancellation::default(),
        };
        let configuration = CheckConfiguration::default();
        let mut state = WorkspaceState::Unloaded;
        state.load(&job, &configuration);
        let WorkspaceState::Failed {
            error,
            ..
        } = &state
        else {
            panic!("missing project must fail")
        };
        let first = error.clone();
        job.root = root.path().join("different-missing-project");
        state.load(&job, &configuration);
        let result = state.synchronize(&job).analyze(&job);
        assert_eq!(result.analysis.unwrap_err(), first);
        assert!(result.paths.is_empty());
        job.reload += 1;
        state.load(&job, &configuration);
        let WorkspaceState::Failed {
            reload,
            error,
        } = state
        else {
            panic!("missing project must fail")
        };
        assert_eq!(reload, 2);
        assert_ne!(error, first);
    }

    #[test]
    fn pending_work_is_coalesced_to_the_latest_snapshot() {
        let jobs = Jobs::default();
        let host = syrox_lang::analysis::AnalysisHost::default();
        for generation in 0..100 {
            jobs.submit(Job {
                mode: WorkspaceMode::Project,
                generation,
                reload: 0,
                root: PathBuf::new(),
                documents: host.snapshot(),
                cancellation: AnalysisCancellation::default(),
            });
        }
        assert_eq!(jobs.next().unwrap().generation, 99);
        jobs.stop();
        assert!(jobs.next().is_none());
    }
}

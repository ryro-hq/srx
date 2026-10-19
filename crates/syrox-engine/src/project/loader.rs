use std::io::{self, Read};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::os::fd::BorrowedFd;

use syrox_lang::{MAX_SOURCE_BYTES, MAX_SOURCES, source::SourceDomainId, source::SourceSet};

#[cfg(target_os = "linux")]
use crate::platform::linux::fd::{self as linux_fd, FileIdentity, FileType, OpenError, OpenedPath};

#[cfg(target_os = "linux")]
use super::LoadedProjectAsset;
#[cfg(target_os = "linux")]
use super::analyze::{check_sources, validate_loaded};
#[cfg(target_os = "linux")]
use super::locator::{InputLocator, root_input_locators};
use super::{
    CheckConfiguration, CheckFailure, LoadedProject, LoadedProjectInput, LoadedProjectSource,
    ProjectLimits, ValidatedProject,
};
#[cfg(target_os = "linux")]
use crate::project::lock::graph::ProjectEdge;
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};

fn add_standard_library(
    sources: &mut SourceSet,
    budget: &mut LoadBudget,
    configuration: &CheckConfiguration,
) -> Result<(), CheckFailure> {
    let Some(standard_library) = &configuration.standard_library else {
        return Ok(());
    };
    for authenticated in standard_library.sources() {
        budget.reserve_bytes(authenticated.text().len())?;
        budget.reserve_source()?;
        sources.add_standard_library(authenticated.name(), authenticated.text())?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) struct InputRoot {
    pub(super) name: String,
    pub(super) relative: PathBuf,
    pub(super) opened: OpenedPath,
}

#[cfg(target_os = "linux")]
struct GraphLoad {
    ancestry: Vec<FileIdentity>,
    snapshots: HashMap<FileIdentity, LoadedSnapshot>,
    github: crate::acquire::github::GithubSession,
}

#[derive(Default)]
struct LoadOrigin {
    top: bool,
    snapshot: Option<Arc<crate::acquire::github::Snapshot>>,
}

#[cfg(target_os = "linux")]
struct LoadedSnapshot {
    project: Arc<LoadedProject>,
    depth: usize,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct LoadedInput {
    name: String,
    relative: PathBuf,
    modules: bool,
    files: Vec<(PathBuf, String)>,
}

#[cfg(target_os = "linux")]
pub(super) fn check_path_linux(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<super::CheckReport, CheckFailure> {
    let mut budget = LoadBudget::new(configuration.project_limits);
    let opened = open_top(path, &mut budget)?;
    if file_type(&opened) == FileType::Directory {
        Ok(validate_loaded(
            load_open_project(
                path,
                opened,
                configuration,
                &mut budget,
                crate::acquire::github::InputMode::Offline,
            )?,
            configuration,
        )?
        .report())
    } else {
        check_open_file(path, opened, configuration, &mut budget)
    }
}

#[cfg(target_os = "linux")]
pub(super) fn check_project_linux(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<super::CheckReport, CheckFailure> {
    let mut budget = LoadBudget::new(configuration.project_limits);
    let opened = open_top(path, &mut budget)?;
    if file_type(&opened) != FileType::Directory {
        return Err(CheckFailure::InputNotDirectory {
            path: path.to_path_buf(),
        });
    }
    Ok(validate_loaded(
        load_open_project(
            path,
            opened,
            configuration,
            &mut budget,
            crate::acquire::github::InputMode::Offline,
        )?,
        configuration,
    )?
    .report())
}

#[cfg(target_os = "linux")]
pub(super) fn load_project_linux(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<LoadedProject, CheckFailure> {
    load_project_mode(
        path,
        configuration,
        crate::acquire::github::InputMode::Offline,
    )
}

pub(super) fn load_project_mode(
    path: &Path,
    configuration: &CheckConfiguration,
    mode: crate::acquire::github::InputMode,
) -> Result<LoadedProject, CheckFailure> {
    let mut budget = LoadBudget::new(configuration.project_limits);
    let opened = open_top(path, &mut budget)?;
    if file_type(&opened) != FileType::Directory {
        return Err(CheckFailure::InputNotDirectory {
            path: path.to_path_buf(),
        });
    }
    load_open_project(path, opened, configuration, &mut budget, mode)
}

#[cfg(target_os = "linux")]
pub(super) fn validate_project_linux(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<ValidatedProject, CheckFailure> {
    validate_loaded(
        load_project_linux(path, configuration)?,
        configuration,
    )
}

#[cfg(target_os = "linux")]
fn check_open_file(
    path: &Path,
    opened: OpenedPath,
    configuration: &CheckConfiguration,
    budget: &mut LoadBudget,
) -> Result<super::CheckReport, CheckFailure> {
    validate_source_handle(&opened, path)?;
    budget.reserve_source()?;
    let text = read_source_handle(opened, path, budget)?;
    let mut sources = SourceSet::new();
    sources.add(path.display().to_string(), text)?;
    add_standard_library(&mut sources, budget, configuration)?;
    check_sources(path, sources, configuration)
}

#[cfg(target_os = "linux")]
fn load_open_project(
    path: &Path,
    project: OpenedPath,
    configuration: &CheckConfiguration,
    budget: &mut LoadBudget,
    mode: crate::acquire::github::InputMode,
) -> Result<LoadedProject, CheckFailure> {
    let mut graph = GraphLoad {
        ancestry: vec![identity(&project)],
        snapshots: HashMap::new(),
        github: crate::acquire::github::GithubSession::new(path, &configuration.github, mode),
    };
    load_open_project_graph(
        path,
        project,
        configuration,
        budget,
        &mut graph,
        LoadOrigin {
            top: true,
            snapshot: None,
        },
    )
}

#[cfg(target_os = "linux")]
fn load_open_project_graph(
    path: &Path,
    project: OpenedPath,
    configuration: &CheckConfiguration,
    budget: &mut LoadBudget,
    graph: &mut GraphLoad,
    origin: LoadOrigin,
) -> Result<LoadedProject, CheckFailure> {
    let main_path = path.join("main.srx");
    let main = match open_beneath(
        project.fd(),
        Path::new("main.srx"),
        &main_path,
        false,
        budget,
    ) {
        Err(CheckFailure::Inspect {
            source,
            ..
        }) if source.kind() == io::ErrorKind::NotFound => {
            return Err(CheckFailure::MissingMain {
                path: main_path,
            });
        }
        result => result?,
    };
    validate_source_handle(&main, &main_path)?;
    budget.reserve_source()?;
    let main_identity = identity(&main);
    let main_text = read_source_handle(main, &main_path, budget)?;

    let mut main_sources = SourceSet::new();
    main_sources.add(main_path.display().to_string(), main_text.clone())?;
    let parsed_main = syrox_lang::syntax::parse_sources(&main_sources).map_err(|errors| {
        CheckFailure::Diagnostics {
            input: main_sources,
            errors,
        }
    })?;
    let locators = root_input_locators(&parsed_main)?;
    validate_input_paths(path, &locators, budget)?;
    let mut directory_identities = HashMap::new();
    directory_identities.insert(identity(&project), path.to_path_buf());
    let mut file_identities = HashMap::new();
    file_identities.insert(main_identity, main_path);
    let loaded = load_local_inputs(
        path,
        &project,
        &locators,
        &mut directory_identities,
        &mut file_identities,
        budget,
    )?;
    let assets = load_assets(
        path,
        &project,
        &mut directory_identities,
        &mut file_identities,
        budget,
    )?;

    let mut sources = SourceSet::new();
    let main_source = sources.add(
        path.join("main.srx").display().to_string(),
        main_text,
    )?;
    let retained_inputs = load_input_sources(&mut sources, SourceDomainId::project(), loaded)?;
    if origin.top {
        add_standard_library(&mut sources, budget, configuration)?;
    }
    let children = load_child_edges(
        &mut sources,
        &locators,
        path,
        &project,
        configuration,
        budget,
        graph,
        &origin,
    )?;
    Ok(LoadedProject {
        path: path.to_path_buf(),
        root: project,
        sources,
        main_source,
        inputs: retained_inputs,
        assets,
        child_edges: children.edges,
        children: children.projects,
        snapshot: origin.snapshot,
    })
}

#[cfg(target_os = "linux")]
fn load_local_inputs(
    path: &Path,
    project: &OpenedPath,
    locators: &[InputLocator],
    directories: &mut HashMap<FileIdentity, PathBuf>,
    files: &mut HashMap<FileIdentity, PathBuf>,
    budget: &mut LoadBudget,
) -> Result<Vec<LoadedInput>, CheckFailure> {
    let mut loaded = Vec::with_capacity(locators.len());
    for locator in locators.iter().filter(|locator| !locator.child) {
        if locator.relative.starts_with("assets") {
            return Err(CheckFailure::AliasedInputPaths {
                first: path.join("assets"),
                second: path.join(&locator.relative),
            });
        }
        let root = open_input_root(
            path,
            project.fd(),
            &locator.name,
            &locator.relative,
            directories,
            budget,
        )?;
        let name = root.name.clone();
        let relative = root.relative.clone();
        let files = walk_input(path, root, directories, files, budget)?;
        loaded.push(LoadedInput {
            name,
            relative,
            modules: locator.modules,
            files,
        });
    }
    Ok(loaded)
}

#[cfg(target_os = "linux")]
struct LoadedChildren {
    edges: Vec<ProjectEdge>,
    projects: Vec<(String, Arc<LoadedProject>)>,
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)] // Carry source, dependency, traversal-budget and diagnostic ownership explicitly through loading.
fn load_child_edges(
    sources: &mut SourceSet,
    locators: &[InputLocator],
    path: &Path,
    project: &OpenedPath,
    configuration: &CheckConfiguration,
    budget: &mut LoadBudget,
    graph: &mut GraphLoad,
    origin: &LoadOrigin,
) -> Result<LoadedChildren, CheckFailure> {
    let mut child_edges = Vec::new();
    let mut children = Vec::new();
    let mut grafts = HashMap::new();
    let refresh = origin.top && graph.github.mode == crate::acquire::github::InputMode::Refresh;
    let locked = if !refresh
        && locators
            .iter()
            .any(|locator| locator.github.is_some())
    {
        super::read_lock_handle(project).map_err(|error| CheckFailure::InvalidInputLock {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?
    } else {
        None
    };
    for locator in locators.iter().filter(|locator| locator.child) {
        budget.charge_work()?;
        if child_edges.len() >= crate::project::lock::graph::MAX_PROJECT_EDGES {
            return Err(CheckFailure::TooManyProjectEdges {
                limit: crate::project::lock::graph::MAX_PROJECT_EDGES,
            });
        }
        if graph.ancestry.len() >= configuration.project_limits.max_directory_depth {
            return Err(CheckFailure::ProjectGraphDepth {
                limit: configuration.project_limits.max_directory_depth,
            });
        }
        let locked_edge = locator.github.as_ref().and_then(|github| {
            locked
                .as_ref()?
                .edge(&locator.name, &github.origin)
        });
        let snapshot = if let Some(github) = &locator.github {
            let pin = if refresh {
                None
            } else {
                Some(
                    locked_edge
                        .and_then(ProjectEdge::github_pin)
                        .ok_or_else(|| {
                            crate::acquire::github::GithubError::Unpinned(github.origin.clone())
                        })?,
                )
            };
            Some(graph.github.load(github, pin)?)
        } else {
            None
        };
        let (child_path, child) = if let Some(snapshot) = &snapshot {
            let child_path = snapshot.path().to_path_buf();
            let opened = open_top(&child_path, budget)?;
            (child_path, opened)
        } else {
            if origin.snapshot.is_some() {
                return Err(crate::acquire::github::GithubError::ExternalPath.into());
            }
            let child_path = path.join("..").join(&locator.relative);
            let opened = open_child_root(
                project,
                path,
                &locator.relative,
                &child_path,
                budget,
            )?;
            (child_path, opened)
        };
        let child_identity = identity(&child);
        if graph.ancestry.contains(&child_identity) {
            return Err(CheckFailure::ChildProjectCycle {
                path: child_path,
            });
        }
        let pinned = if let Some(snapshot) = graph.snapshots.get(&child_identity) {
            if graph
                .ancestry
                .len()
                .saturating_add(snapshot.depth)
                > configuration.project_limits.max_directory_depth
            {
                return Err(CheckFailure::ProjectGraphDepth {
                    limit: configuration.project_limits.max_directory_depth,
                });
            }
            Arc::clone(&snapshot.project)
        } else {
            graph.ancestry.push(child_identity);
            let result = load_open_project_graph(
                &child_path,
                child,
                configuration,
                budget,
                graph,
                LoadOrigin {
                    top: false,
                    snapshot: snapshot.clone(),
                },
            );
            graph.ancestry.pop();
            Arc::new(result?)
        };
        let expected = crate::project::lock::LockManifest::generate(
            &pinned,
            configuration.standard_library.as_ref(),
        )
        .map_err(|error| CheckFailure::InvalidChildLock {
            path: child_path.clone(),
            reason: error.to_string(),
        })?;
        let actual = verify_child_lock(&pinned, &expected)?;
        if locked_edge.is_some_and(|edge| edge.child_lock() != actual.digest()) {
            return Err(crate::acquire::github::GithubError::ContentMismatch.into());
        }
        let mut depth = 1;
        for (_, descendant) in &pinned.children {
            budget.charge_work()?;
            depth = depth.max(1 + graph.snapshots[&identity(&descendant.root)].depth);
        }
        graph
            .snapshots
            .entry(child_identity)
            .or_insert_with(|| LoadedSnapshot {
                project: Arc::clone(&pinned),
                depth,
            });
        let edge = if let (Some(github), Some(snapshot)) = (&locator.github, snapshot) {
            ProjectEdge::github(
                &locator.name,
                &github.origin,
                *actual.digest(),
                snapshot.pin.clone(),
            )
        } else {
            ProjectEdge::new(
                &locator.name,
                &format!("path:../{}", locator.relative.display()),
                *actual.digest(),
            )
        };
        child_edges.push(
            edge.map_err(|error| CheckFailure::InvalidChildLock {
                path: child_path.clone(),
                reason: error.to_string(),
            })?,
        );
        graft_child(
            sources,
            SourceDomainId::project(),
            &locator.name,
            &pinned,
            budget,
            &mut grafts,
        )?;
        children.push((locator.name.clone(), pinned));
    }
    Ok(LoadedChildren {
        edges: child_edges,
        projects: children,
    })
}

#[cfg(target_os = "linux")]
fn load_input_sources(
    sources: &mut SourceSet,
    parent: SourceDomainId,
    loaded: Vec<LoadedInput>,
) -> Result<Vec<LoadedProjectInput>, CheckFailure> {
    let mut retained_inputs = Vec::with_capacity(loaded.len());
    for input in loaded {
        let domain = sources.create_child_input_domain(parent, &input.name)?;
        let mut retained_files = Vec::with_capacity(input.files.len());
        let mut module_owners = std::collections::BTreeMap::new();
        for (relative, text) in input.files {
            let logical_name = format!("{}/{}", input.name, relative.display());
            let source_id = if input.modules {
                let mut module = relative
                    .iter()
                    .map(|part| part.to_string_lossy().into_owned())
                    .collect::<Vec<_>>();
                let file = module
                    .pop()
                    .expect("input source has a file name");
                let stem = file
                    .strip_suffix(".srx")
                    .expect("input source is .srx");
                if stem != "package" || module.is_empty() {
                    module.push(stem.to_owned());
                }
                if let Some(first) = module_owners.insert(module.clone(), relative.clone()) {
                    return Err(CheckFailure::InvalidModuleInput {
                        reason: format!(
                            "files `{}` and `{}` share one recipe module",
                            first.display(),
                            relative.display()
                        ),
                    });
                }
                sources.add_to_input_module(domain, logical_name, text, module)?
            } else {
                sources.add_to_input_domain(domain, logical_name, text)?
            };
            retained_files.push(LoadedProjectSource {
                relative_path: relative,
                source_id,
            });
        }
        retained_inputs.push(LoadedProjectInput {
            name: input.name,
            locator: format!(
                "{}:{}",
                if input.modules {
                    "modules"
                } else {
                    "path"
                },
                input.relative.display()
            ),
            domain,
            files: retained_files,
        });
    }
    Ok(retained_inputs)
}

#[cfg(target_os = "linux")]
fn load_assets(
    path: &Path,
    project: &OpenedPath,
    directories: &mut HashMap<FileIdentity, PathBuf>,
    files: &mut HashMap<FileIdentity, PathBuf>,
    budget: &mut LoadBudget,
) -> Result<Vec<LoadedProjectAsset>, CheckFailure> {
    let assets_path = path.join("assets");
    let root = match open_beneath(
        project.fd(),
        Path::new("assets"),
        &assets_path,
        true,
        budget,
    ) {
        Err(CheckFailure::Inspect {
            source,
            ..
        }) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        result => result?,
    };
    if let Some(first) = directories.insert(identity(&root), assets_path.clone()) {
        return Err(CheckFailure::AliasedInputPaths {
            first,
            second: assets_path,
        });
    }
    let mut assets = Vec::new();
    let mut pending = vec![(PathBuf::new(), identity(&root), 0_usize)];
    while let Some((relative_dir, expected, depth)) = pending.pop() {
        let display = assets_path.join(&relative_dir);
        let directory = reopen_directory(
            root.fd(),
            if relative_dir.as_os_str().is_empty() {
                Path::new(".")
            } else {
                &relative_dir
            },
            &display,
            expected,
            budget,
        )?;
        budget.charge_work()?;
        let entries = linux_fd::read_directory(&directory, |name| {
            budget.charge_entry()?;
            budget.charge_work()?;
            if name.to_str().is_none() {
                return Err(CheckFailure::InvalidPathEncoding {
                    path: display.join(name),
                });
            }
            Ok(())
        })
        .map_err(|error| match error {
            linux_fd::ReadDirectoryError::Io(source) => CheckFailure::Read {
                path: display.clone(),
                source,
            },
            linux_fd::ReadDirectoryError::Admission(error) => error,
        })?;
        for name in entries {
            let relative = relative_dir.join(&name);
            let display = assets_path.join(&relative);
            let opened = open_beneath(
                directory.fd(),
                Path::new(&name),
                &display,
                false,
                budget,
            )?;
            // Markdown is local documentation (ignored by the published
            // repositories). Still inspect the inode before excluding it so
            // symlinks cannot bypass traversal rules by using a .md suffix.
            if file_type(&opened) == FileType::Regular
                && display.extension() == Some(OsStr::new("md"))
            {
                continue;
            }
            match file_type(&opened) {
                FileType::Directory => {
                    if depth >= budget.limits.max_directory_depth {
                        return Err(CheckFailure::DirectoryDepth {
                            path: display,
                            limit: budget.limits.max_directory_depth,
                        });
                    }
                    if let Some(first) = directories.insert(identity(&opened), display.clone()) {
                        return Err(CheckFailure::AliasedInputPaths {
                            first,
                            second: display,
                        });
                    }
                    pending.push((relative, identity(&opened), depth + 1));
                }
                FileType::Regular => {
                    if let Some(first) = files.insert(identity(&opened), display.clone()) {
                        return Err(CheckFailure::AliasedSourceFiles {
                            first,
                            second: display,
                        });
                    }
                    let digest = hash_asset(opened, &display, budget)?;
                    assets.push(LoadedProjectAsset {
                        relative_path: Path::new("assets").join(relative),
                        size: digest.size,
                        digest: digest.digest,
                        content: digest.content,
                    });
                }
                FileType::Other => {
                    return Err(CheckFailure::InvalidAssetFile {
                        path: display,
                    });
                }
            }
        }
    }
    assets.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(assets)
}

#[cfg(target_os = "linux")]
struct AuthenticatedAsset {
    digest: [u8; 32],
    size: u64,
    content: Arc<[u8]>,
}

#[cfg(target_os = "linux")]
fn hash_asset(
    opened: OpenedPath,
    path: &Path,
    budget: &mut LoadBudget,
) -> Result<AuthenticatedAsset, CheckFailure> {
    let mut hasher = Sha256::new();
    let mut content = Vec::new();
    let mut reader = opened.into_file();
    let mut buffer = [0_u8; 16 * 1024];
    let mut size = 0_u64;
    loop {
        budget.charge_work()?;
        let read = reader
            .read(&mut buffer)
            .map_err(|source| CheckFailure::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        budget.reserve_bytes(read)?;
        size += read as u64;
        hasher.update(&buffer[..read]);
        content.extend_from_slice(&buffer[..read]);
    }
    Ok(AuthenticatedAsset {
        digest: hasher.finalize().into(),
        size,
        content: content.into(),
    })
}

#[cfg(target_os = "linux")]
fn verify_child_lock(
    project: &LoadedProject,
    expected: &crate::project::lock::LockManifest,
) -> Result<crate::project::lock::LockManifest, CheckFailure> {
    let path = project.path();
    let invalid = |reason: String| CheckFailure::InvalidChildLock {
        path: path.to_path_buf(),
        reason,
    };
    let actual = super::read_lock(project)
        .map_err(|error| invalid(error.to_string()))?
        .ok_or_else(|| CheckFailure::MissingChildLock {
            path: path.to_path_buf(),
            name: crate::project::lock::LOCK_FILE_NAME,
        })?;
    super::compare_lock(&actual, expected).map_err(|error| invalid(error.to_string()))?;
    Ok(actual)
}

#[cfg(target_os = "linux")]
fn open_child_root(
    project: &OpenedPath,
    path: &Path,
    relative: &Path,
    display: &Path,
    budget: &mut LoadBudget,
) -> Result<OpenedPath, CheckFailure> {
    // Revalidate the visible root without symlinks, then resolve its parent
    // through the pinned descriptor. A root spelled `.` has no basename.
    let pinned = open_top(path, budget)?;
    if identity(&pinned) != identity(project) {
        return Err(CheckFailure::ChildProjectCycle {
            path: path.to_path_buf(),
        });
    }
    budget.charge_work()?;
    let parent = linux_fd::open_project_parent(project.fd())
        .map_err(|source| open_error(&path.join(".."), source))?;
    budget.charge_work()?;
    let child = open_beneath(parent.fd(), relative, display, true, budget)?;
    if file_type(&child) != FileType::Directory {
        return Err(CheckFailure::InputNotDirectory {
            path: display.to_path_buf(),
        });
    }
    Ok(child)
}

#[cfg(target_os = "linux")]
fn graft_child(
    sources: &mut SourceSet,
    parent: SourceDomainId,
    alias: &str,
    child: &LoadedProject,
    budget: &mut LoadBudget,
    grafts: &mut HashMap<FileIdentity, SourceDomainId>,
) -> Result<(), CheckFailure> {
    budget.charge_work()?;
    let child_identity = identity(&child.root);
    if let Some(&domain) = grafts.get(&child_identity) {
        sources.bind_project_domain(parent, alias, domain)?;
        return Ok(());
    }
    let domain = sources.create_project_domain(parent, alias)?;
    grafts.insert(child_identity, domain);
    sources.add_to_project_domain(
        domain,
        child.main_source().name(),
        child.main_source().text(),
    )?;
    for input in child.inputs() {
        let target = sources.create_child_input_domain(domain, input.name())?;
        for file in input.files() {
            let source = child
                .sources()
                .get(file.source_id())
                .expect("pinned child source");
            let name = source.name();
            if input.locator().starts_with("modules:") {
                let mut module = file
                    .relative_path()
                    .iter()
                    .map(|part| part.to_string_lossy().into_owned())
                    .collect::<Vec<_>>();
                let file_name = module.pop().expect("source has file name");
                let stem = file_name
                    .strip_suffix(".srx")
                    .expect("source is .srx");
                if stem != "package" || module.is_empty() {
                    module.push(stem.to_owned());
                }
                sources.add_to_input_module(target, name, source.text(), module)?;
            } else {
                sources.add_to_input_domain(target, name, source.text())?;
            }
        }
    }
    for (alias, grandchild) in &child.children {
        graft_child(sources, domain, alias, grandchild, budget, grafts)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_input_paths(
    project_path: &Path,
    locators: &[InputLocator],
    budget: &mut LoadBudget,
) -> Result<(), CheckFailure> {
    for (index, locator) in locators
        .iter()
        .enumerate()
        .filter(|(_, locator)| locator.github.is_none())
    {
        let relative = &locator.relative;
        budget.charge_work()?;
        let display = if locator.child {
            project_path.join("..").join(relative)
        } else {
            project_path.join(relative)
        };
        if relative.as_os_str().is_empty() {
            return Err(CheckFailure::AliasedInputPaths {
                first: project_path.to_path_buf(),
                second: display,
            });
        }
        for existing in &locators[..index] {
            budget.charge_work()?;
            if existing.github.is_none()
                && locator.child == existing.child
                && (relative.starts_with(&existing.relative)
                    || existing.relative.starts_with(relative))
            {
                let first = if existing.child {
                    project_path.join("..").join(&existing.relative)
                } else {
                    project_path.join(&existing.relative)
                };
                return Err(CheckFailure::AliasedInputPaths {
                    first,
                    second: display,
                });
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_input_root(
    project_path: &Path,
    project_fd: BorrowedFd<'_>,
    name: &str,
    relative: &Path,
    identities: &mut HashMap<FileIdentity, PathBuf>,
    budget: &mut LoadBudget,
) -> Result<InputRoot, CheckFailure> {
    let display = project_path.join(relative);
    let opened = match open_beneath(project_fd, relative, &display, true, budget) {
        Err(CheckFailure::Inspect {
            source,
            ..
        }) if source.kind() == io::ErrorKind::NotADirectory => {
            return Err(CheckFailure::InputNotDirectory {
                path: display,
            });
        }
        result => result?,
    };
    let file_identity = identity(&opened);
    if let Some(first) = identities.insert(file_identity, display.clone()) {
        return Err(CheckFailure::AliasedInputPaths {
            first,
            second: display,
        });
    }
    Ok(InputRoot {
        name: name.to_owned(),
        relative: relative.to_path_buf(),
        opened,
    })
}

#[cfg(target_os = "linux")]
pub(super) fn walk_input(
    project_path: &Path,
    root: InputRoot,
    directory_identities: &mut HashMap<FileIdentity, PathBuf>,
    file_identities: &mut HashMap<FileIdentity, PathBuf>,
    budget: &mut LoadBudget,
) -> Result<Vec<(PathBuf, String)>, CheckFailure> {
    let root_display = project_path.join(&root.relative);
    let root_directory = root.opened;
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut relative_directory = PathBuf::new();
    let mut current_directory = None;
    let mut depth = 0_usize;
    loop {
        let directory = current_directory
            .as_ref()
            .unwrap_or(&root_directory);
        let directory_path = root_display.join(&relative_directory);
        budget.charge_work()?;
        let children = linux_fd::read_directory(directory, |name| {
            budget.charge_entry()?;
            budget.charge_work()?;
            if name.to_str().is_none() {
                return Err(CheckFailure::InvalidPathEncoding {
                    path: directory_path.join(name),
                });
            }
            Ok(())
        })
        .map_err(|source| match source {
            linux_fd::ReadDirectoryError::Io(source) => CheckFailure::Read {
                path: directory_path.clone(),
                source,
            },
            linux_fd::ReadDirectoryError::Admission(source) => source,
        })?;

        let mut child_directories = Vec::new();
        for name in children {
            let relative = relative_directory.join(&name);
            let display = root_display.join(&relative);
            let opened = open_beneath(
                directory.fd(),
                Path::new(&name),
                &display,
                false,
                budget,
            )?;
            let kind = file_type(&opened);
            if kind == FileType::Directory {
                let child_depth = depth.saturating_add(1);
                if child_depth > budget.limits.max_directory_depth {
                    return Err(CheckFailure::DirectoryDepth {
                        path: display,
                        limit: budget.limits.max_directory_depth,
                    });
                }
                let file_identity = identity(&opened);
                if let Some(first) = directory_identities.insert(file_identity, display.clone()) {
                    return Err(CheckFailure::AliasedInputPaths {
                        first,
                        second: display,
                    });
                }
                child_directories.push((relative, file_identity, child_depth));
            } else if kind == FileType::Regular && display.extension() == Some(OsStr::new("srx")) {
                let file_identity = identity(&opened);
                if let Some(first) = file_identities.insert(file_identity, display.clone()) {
                    return Err(CheckFailure::AliasedSourceFiles {
                        first,
                        second: display,
                    });
                }
                budget.reserve_source()?;
                let text = read_source_handle(opened, &display, budget)?;
                files.push((relative, text));
            } else {
                return Err(CheckFailure::InvalidSourceFile {
                    path: display,
                });
            }
        }
        directories.extend(child_directories.into_iter().rev());
        drop(current_directory.take());
        let Some((relative, expected_identity, next_depth)) = directories.pop() else {
            break;
        };
        let display = root_display.join(&relative);
        let reopened = reopen_directory(
            root_directory.fd(),
            &relative,
            &display,
            expected_identity,
            budget,
        )?;
        relative_directory = relative;
        current_directory = Some(reopened);
        depth = next_depth;
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
}

#[cfg(target_os = "linux")]
pub(super) fn reopen_directory(
    root: BorrowedFd<'_>,
    relative: &Path,
    display: &Path,
    expected_identity: FileIdentity,
    budget: &mut LoadBudget,
) -> Result<OpenedPath, CheckFailure> {
    let reopened = open_beneath(root, relative, display, true, budget)?;
    if identity(&reopened) != expected_identity {
        return Err(CheckFailure::Inspect {
            path: display.to_path_buf(),
            source: io::Error::other("directory identity changed during traversal"),
        });
    }
    Ok(reopened)
}

#[cfg(target_os = "linux")]
pub(super) fn open_top(path: &Path, budget: &mut LoadBudget) -> Result<OpenedPath, CheckFailure> {
    budget.charge_work()?;
    let opened = linux_fd::open_top(path).map_err(|source| open_error(path, source))?;
    budget.charge_work()?;
    Ok(opened)
}

#[cfg(target_os = "linux")]
pub(super) fn open_beneath(
    directory: BorrowedFd<'_>,
    relative: &Path,
    display: &Path,
    directory_only: bool,
    budget: &mut LoadBudget,
) -> Result<OpenedPath, CheckFailure> {
    budget.charge_work()?;
    let opened = linux_fd::open_beneath(directory, relative, directory_only)
        .map_err(|source| open_error(display, source))?;
    budget.charge_work()?;
    Ok(opened)
}

#[cfg(target_os = "linux")]
pub(super) fn open_error(path: &Path, source: OpenError) -> CheckFailure {
    match source {
        OpenError::Unsupported(source) => CheckFailure::UnsupportedKernel {
            source,
        },
        OpenError::Symlink => CheckFailure::SymbolicLink {
            path: path.to_path_buf(),
        },
        OpenError::Other(source) => CheckFailure::Inspect {
            path: path.to_path_buf(),
            source,
        },
    }
}

#[cfg(target_os = "linux")]
fn file_type(opened: &OpenedPath) -> FileType {
    opened.metadata().file_type()
}

#[cfg(target_os = "linux")]
pub(super) fn identity(opened: &OpenedPath) -> FileIdentity {
    opened.metadata().identity()
}

#[cfg(target_os = "linux")]
fn validate_source_handle(opened: &OpenedPath, path: &Path) -> Result<(), CheckFailure> {
    if file_type(opened) != FileType::Regular || path.extension() != Some(OsStr::new("srx")) {
        return Err(CheckFailure::InvalidSourceFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_source_handle(
    opened: OpenedPath,
    path: &Path,
    budget: &mut LoadBudget,
) -> Result<String, CheckFailure> {
    budget.charge_work()?;
    let text = read_source(opened.into_file(), path)?;
    budget.reserve_bytes(text.len())?;
    Ok(text)
}

pub(super) fn read_source(reader: impl Read, path: &Path) -> Result<String, CheckFailure> {
    let mut bytes = Vec::with_capacity(MAX_SOURCE_BYTES.min(64 * 1024));
    reader
        .take((MAX_SOURCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CheckFailure::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(CheckFailure::TooLarge {
            path: path.to_path_buf(),
        });
    }
    String::from_utf8(bytes).map_err(|source| CheckFailure::InvalidUtf8 {
        path: path.to_path_buf(),
        source,
    })
}

pub(super) struct LoadBudget {
    limits: ProjectLimits,
    total_bytes: usize,
    sources: usize,
    entries: usize,
    work: usize,
}

impl LoadBudget {
    pub(super) const fn new(limits: ProjectLimits) -> Self {
        Self {
            limits,
            total_bytes: 0,
            sources: 0,
            entries: 0,
            work: 0,
        }
    }

    fn reserve_bytes(&mut self, bytes: usize) -> Result<(), CheckFailure> {
        let total = self.total_bytes.saturating_add(bytes);
        if total > self.limits.max_total_bytes {
            return Err(CheckFailure::ProjectTooLarge {
                limit: self.limits.max_total_bytes,
            });
        }
        self.total_bytes = total;
        Ok(())
    }

    fn reserve_source(&mut self) -> Result<(), CheckFailure> {
        if self.sources >= self.limits.max_sources.min(MAX_SOURCES) {
            return Err(CheckFailure::TooManySources {
                limit: self.limits.max_sources.min(MAX_SOURCES),
            });
        }
        self.sources += 1;
        Ok(())
    }

    fn charge_entry(&mut self) -> Result<(), CheckFailure> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > self.limits.max_directory_entries {
            return Err(CheckFailure::TooManyDirectoryEntries {
                limit: self.limits.max_directory_entries,
            });
        }
        Ok(())
    }

    fn charge_work(&mut self) -> Result<(), CheckFailure> {
        self.work = self.work.saturating_add(1);
        if self.work > self.limits.max_work {
            return Err(CheckFailure::WorkLimit {
                limit: self.limits.max_work,
            });
        }
        Ok(())
    }
}

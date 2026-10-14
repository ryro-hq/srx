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

mod consumers;
mod editor;
mod evaluation;
mod generic_build;
mod imported;
mod package_set;
mod recipe_ref;
mod reference_graph;
mod versioned;

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
// The public project planner rejects these values as Os/Shell destinations.
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

#[test]
fn external_child_lock_binds_its_sources_and_parent_edge() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(
        child.join("main.srx"),
        "pub struct X {} pub fn make() -> X { X {} }",
    )
    .unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { pkgs = \"path:../child\"; } outputs { selected: pkgs::X = pkgs::make(); }",
    )
    .unwrap();
    lock_project(&child).unwrap();
    assert!(matches!(
        lock_project(&consumer).unwrap().status(),
        lock::LockStatus::Created
    ));
    check_project_lock(&consumer).unwrap();
    fs::write(
        child.join("main.srx"),
        "pub struct X {} pub fn make() -> X { X {} } // drift",
    )
    .unwrap();
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::Check(
            CheckFailure::InvalidChildLock { .. }
        ))
    ));
    lock_project(&child).unwrap();
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::GraphDrift)
    ));
    lock_project(&consumer).unwrap();
    check_project_lock(&consumer).unwrap();
}

#[test]
fn external_child_rejects_symlink_and_cycle() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(child.join("main.srx"), "pub struct X {}").unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { pkgs = \"path:../child\"; }",
    )
    .unwrap();
    symlink(&child, workspace.0.join("linked")).unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { pkgs = \"path:../linked\"; }",
    )
    .unwrap();
    assert!(matches!(
        check_project(&consumer),
        Err(CheckFailure::SymbolicLink { .. })
    ));
    fs::write(
        consumer.join("main.srx"),
        "inputs { pkgs = \"path:../consumer\"; }",
    )
    .unwrap();
    assert!(matches!(
        check_project(&consumer),
        Err(CheckFailure::ChildProjectCycle { .. })
    ));
}

#[test]
fn external_origin_requires_canonical_relative_spelling() {
    for locator in [
        "path:../child/./nested",
        "path:../child//nested",
        "path:../child/",
        "path:../child/../nested",
    ] {
        let project = TempProject::new();
        project.write(
            "main.srx",
            &format!("inputs {{ dep = \"{locator}\"; }}"),
        );
        assert!(
            matches!(
                check_project(&project.0),
                Err(CheckFailure::UnsafeInputPath { .. })
            ),
            "{locator}"
        );
    }
}

#[test]
fn external_child_modules_are_imported_from_its_own_root() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir_all(child.join("recipes")).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(child.join("main.srx"), "inputs { recipes = \"modules:recipes\"; } pub type X = recipes::hello::X; pub fn make() -> X { recipes::hello::make() }").unwrap();
    fs::write(
        child.join("recipes/hello.srx"),
        "pub struct X {} pub fn make() -> X { X {} }",
    )
    .unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { pkgs = \"path:../child\"; } outputs { selected: pkgs::X = pkgs::make(); }",
    )
    .unwrap();
    lock_project(&child).unwrap();
    lock_project(&consumer).unwrap();
    assert!(
        fs::read(consumer.join(lock::LOCK_FILE_NAME))
            .unwrap()
            .starts_with(b"syrox-lock-v2\n")
    );
    assert!(!consumer.join("Syrox.graph.lock").exists());
    check_project_lock(&consumer).unwrap();
    fs::write(
        child.join("recipes/hello.srx"),
        "pub struct X {} pub fn make() -> X { X {} } // changed",
    )
    .unwrap();
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::Check(
            CheckFailure::InvalidChildLock { .. }
        ))
    ));
}

#[test]
fn child_assets_are_pinned_and_new_files_require_relock() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir_all(child.join("assets/patches")).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(child.join("main.srx"), "pub struct X {}").unwrap();
    fs::write(
        child.join("assets/patches/fix.patch"),
        b"first\0patch",
    )
    .unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { child = \"path:../child\"; } outputs { selected: child::X = child::X {}; }",
    )
    .unwrap();
    lock_project(&child).unwrap();
    assert!(
        fs::read(child.join(lock::LOCK_FILE_NAME))
            .unwrap()
            .starts_with(b"syrox-lock-v3\n")
    );
    lock_project(&consumer).unwrap();
    check_project_lock(&consumer).unwrap();
    fs::write(
        child.join("assets/patches/fix.patch"),
        b"second patch",
    )
    .unwrap();
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::Check(
            CheckFailure::InvalidChildLock { .. }
        ))
    ));
    lock_project(&child).unwrap();
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::GraphDrift)
    ));
    lock_project(&consumer).unwrap();
    fs::write(
        child.join("assets/patches/another.patch"),
        b"added",
    )
    .unwrap();
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::Check(
            CheckFailure::InvalidChildLock { .. }
        ))
    ));
}

#[test]
fn plan_does_not_resolve_imported_asset_from_a_homonymous_consumer_path() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir_all(child.join("assets")).unwrap();
    fs::create_dir_all(consumer.join("assets")).unwrap();
    fs::write(child.join("main.srx"), "pub struct X {}").unwrap();
    fs::write(child.join("assets/source.tar.gz"), b"child").unwrap();
    fs::write(consumer.join("assets/source.tar.gz"), b"consumer").unwrap();
    let child_digest = sha2::Sha256::digest(b"child");
    let digest = child_digest
        .iter()
        .fold(String::new(), |mut result, byte| {
            write!(result, "{byte:02x}").unwrap();
            result
        });
    fs::write(consumer.join("main.srx"), format!(r#"inputs {{ child = "path:../child"; }} mod published {{ mod package {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "app"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [
            std::SourceRequest {{ url = "project:assets/source.tar.gz"; sha256 = "{digest}"; maximum_bytes = 100; }}
        ]; }}); }} }} }} }} pub publish(published, recipe): std::Recipe;"#)).unwrap();
    let configuration = package_configuration();
    lock_project_with(&child, &configuration).unwrap();
    lock_project_with(&consumer, &configuration).unwrap();
    assert!(matches!(
        plan_project_with(&consumer, &configuration),
        Err(ProjectOperationError::UnpinnedProjectAsset { .. })
    ));
}

#[test]
fn imported_source_request_uses_its_own_locked_project_asset() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir_all(child.join("assets")).unwrap();
    fs::create_dir_all(consumer.join("assets")).unwrap();
    let digest = "ddc9e669194254cef019a29d3619a2c16592e5d52e1a81e98b01bd52319149a3";
    fs::write(child.join("assets/source.tar.gz"), b"child").unwrap();
    fs::write(consumer.join("assets/source.tar.gz"), b"consumer").unwrap();
    fs::write(child.join("main.srx"), format!(r#"
        pub fn source() -> std::Acquisition {{
            std::Acquisition {{ sources = [
                std::SourceRequest {{ url = "project:assets/source.tar.gz"; sha256 = "{digest}"; maximum_bytes = 100; }}
            ]; }}
        }}
    "#)).unwrap();
    fs::write(
        consumer.join("main.srx"),
        r#"
        inputs { child = "path:../child"; }
        mod published { mod package { pub fn recipe() -> std::Recipe { std::Recipe {
                package = std::Package { id = "app"; dependencies = []; };
                acquisition = std::Option::Some(child::source());
            } } } } pub publish(published, recipe): std::Recipe;
    "#,
    )
    .unwrap();
    let configuration = package_configuration();
    lock_project_with(&child, &configuration).unwrap();
    lock_project_with(&consumer, &configuration).unwrap();
    let prepared = prepare_project_with(&consumer, &configuration).unwrap();
    let plan = prepared.plan();
    let request = plan
        .acquisitions()
        .next()
        .unwrap()
        .sources()
        .next()
        .unwrap();
    assert_eq!(
        fs::canonicalize(
            prepared
                .project_root(request.owner().unwrap())
                .unwrap()
        )
        .unwrap(),
        fs::canonicalize(&child).unwrap()
    );
    let origin = prepared
        .project_root(request.owner().unwrap())
        .unwrap();
    let root = crate::store::RootName::new(format!("source_{}", request.digest())).unwrap();
    let store = crate::store::Store::initialize(&workspace.0.join("store")).unwrap();
    let acquire = |store: &crate::store::Store| {
        crate::realize::acquire_build_local(
            store,
            origin,
            "assets/source.tar.gz",
            request.digest(),
            request.maximum_bytes(),
            &root,
            &crate::cancellation::Cancellation::default(),
        )
    };
    acquire(&store).unwrap(); // miss must read the child's bytes, not the homonymous consumer file
    fs::remove_file(child.join("assets/source.tar.gz")).unwrap();
    acquire(&store).unwrap(); // hit must use the pinned cached bytes
    symlink(
        consumer.join("assets/source.tar.gz"),
        child.join("assets/source.tar.gz"),
    )
    .unwrap();
    let empty_store = crate::store::Store::initialize(&workspace.0.join("uncached-store")).unwrap();
    assert!(acquire(&empty_store).is_err()); // no symlink traversal on a miss
    fs::remove_file(child.join("assets/source.tar.gz")).unwrap();
    fs::write(child.join("assets/source.tar.gz"), b"child").unwrap();
    let moved_child = workspace.0.join("moved-child");
    fs::rename(&child, &moved_child).unwrap();
    symlink(&moved_child, &child).unwrap();
    assert!(acquire(&empty_store).is_err()); // root substitution is rejected too
    fs::remove_file(&child).unwrap();
    fs::rename(&moved_child, &child).unwrap();
    fs::write(child.join("assets/source.tar.gz"), b"changed").unwrap();
    assert!(plan_project_with(&consumer, &configuration).is_err());
    fs::write(consumer.join("assets/source.tar.gz"), b"child").unwrap();
    lock_project_with(&child, &configuration).unwrap();
    lock_project_with(&consumer, &configuration).unwrap();
    assert!(matches!(
        plan_project_with(&consumer, &configuration),
        Err(ProjectOperationError::UnpinnedProjectAsset { .. })
    ));
}

#[test]
fn transitive_import_preserves_the_leaf_source_origin() {
    let workspace = TempProject::new();
    let leaf = workspace.0.join("leaf");
    let middle = workspace.0.join("middle");
    let consumer = workspace.0.join("consumer");
    for project in [&leaf, &middle, &consumer] {
        fs::create_dir_all(project.join("assets")).unwrap();
    }
    fs::write(leaf.join("assets/source"), b"child").unwrap();
    fs::write(middle.join("assets/source"), b"middle").unwrap();
    fs::write(consumer.join("assets/source"), b"consumer").unwrap();
    fs::write(
        leaf.join("main.srx"),
        r#"
        pub fn source() -> std::Acquisition {
            std::Acquisition { sources = [std::SourceRequest {
                url = "project:assets/source";
                sha256 = "ddc9e669194254cef019a29d3619a2c16592e5d52e1a81e98b01bd52319149a3";
                maximum_bytes = 100;
            }]; }
        }
    "#,
    )
    .unwrap();
    fs::write(
        middle.join("main.srx"),
        r#"
        inputs { leaf = "path:../leaf"; }
        pub fn source() -> std::Acquisition { leaf::source() }
    "#,
    )
    .unwrap();
    fs::write(
        consumer.join("main.srx"),
        r#"
        inputs { middle = "path:../middle"; }
        mod published { mod package { pub fn recipe() -> std::Recipe { std::Recipe {
                package = std::Package { id = "app"; dependencies = []; };
                acquisition = std::Option::Some(middle::source());
            } } } } pub publish(published, recipe): std::Recipe;
    "#,
    )
    .unwrap();
    let configuration = package_configuration();
    for project in [&leaf, &middle, &consumer] {
        lock_project_with(project, &configuration).unwrap();
    }
    let prepared = prepare_project_with(&consumer, &configuration).unwrap();
    let plan = prepared.plan();
    let source = plan
        .acquisitions()
        .next()
        .unwrap()
        .sources()
        .next()
        .unwrap();
    assert_eq!(
        fs::canonicalize(
            prepared
                .project_root(source.owner().unwrap())
                .unwrap()
        )
        .unwrap(),
        fs::canonicalize(leaf).unwrap()
    );
}

#[test]
fn diamond_imports_share_snapshot_identity_and_source_budget() {
    let workspace = TempProject::new();
    for directory in ["leaf", "left", "right", "consumer"] {
        fs::create_dir(workspace.0.join(directory)).unwrap();
    }
    let leaf = "pub struct Item {} outputs { item: Item = Item {}; }";
    let left = r#"inputs { leaf = "path:../leaf"; } pub type Item = leaf::Item; pub fn make() -> Item { leaf::item }"#;
    let right = r#"inputs { leaf = "path:../leaf"; } pub type Item = leaf::Item; pub fn accept(item: Item) -> Item { item }"#;
    let consumer = r#"inputs { left = "path:../left"; right = "path:../right"; } outputs { shared: right::Item = right::accept(left::make()); }"#;
    for (name, text) in [
        ("leaf", leaf),
        ("left", left),
        ("right", right),
        ("consumer", consumer),
    ] {
        fs::write(workspace.0.join(name).join("main.srx"), text).unwrap();
        lock_project(&workspace.0.join(name)).unwrap();
    }
    let mut configuration = CheckConfiguration::default();
    configuration.project_limits.max_total_bytes =
        leaf.len() + left.len() + right.len() + consumer.len();
    let root = workspace.0.join("consumer");
    let loaded = loader::load_project_linux(&root, &configuration).unwrap();
    let a = &loaded.children[0].1.children[0].1;
    let b = &loaded.children[1].1.children[0].1;
    assert!(std::sync::Arc::ptr_eq(a, b));
    assert_eq!(loaded.sources().len(), 4);
    assert!(value_projection_plan(&root, &configuration).is_ok());
    configuration.project_limits.max_total_bytes -= 1;
    assert!(matches!(
        check_project_with(&root, &configuration),
        Err(CheckFailure::ProjectTooLarge { .. })
    ));
    fs::write(
        workspace.0.join("leaf/main.srx"),
        "pub struct Changed {}",
    )
    .unwrap();
    assert!(check_project_lock(&root).is_err());
}

#[test]
fn cached_snapshot_cannot_bypass_graph_depth_limit() {
    let workspace = TempProject::new();
    for (name, text) in [
        ("bottom", "pub struct Item {}"),
        (
            "shared",
            "inputs { bottom = \"path:../bottom\"; }",
        ),
        (
            "middle",
            "inputs { shared = \"path:../shared\"; }",
        ),
        ("deep", "inputs { middle = \"path:../middle\"; }"),
        (
            "root",
            "inputs { a = \"path:../shared\"; z = \"path:../deep\"; }",
        ),
    ] {
        fs::create_dir(workspace.0.join(name)).unwrap();
        fs::write(workspace.0.join(name).join("main.srx"), text).unwrap();
        lock_project(&workspace.0.join(name)).unwrap();
    }
    let mut configuration = CheckConfiguration::default();
    configuration.project_limits.max_directory_depth = 4;
    assert!(matches!(
        check_project_with(&workspace.0.join("root"), &configuration),
        Err(CheckFailure::ProjectGraphDepth {
            limit: 4
        })
    ));
}

#[test]
fn standard_source_helper_preserves_the_child_asset_origin_in_the_plan() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir_all(child.join("assets")).unwrap();
    fs::create_dir_all(&consumer).unwrap();
    fs::write(child.join("assets/source"), b"child").unwrap();
    fs::write(
        child.join("main.srx"),
        r#"
        pub fn source() -> std::Acquisition {
            std::Acquisition { sources = [std::source_request(
                "project:assets/source",
                "ddc9e669194254cef019a29d3619a2c16592e5d52e1a81e98b01bd52319149a3",
                100,
            )]; }
        }
    "#,
    )
    .unwrap();
    fs::write(
        consumer.join("main.srx"),
        r#"
        inputs { child = "path:../child"; }
        mod published { mod package { pub fn recipe() -> std::Recipe { std::Recipe {
                package = std::Package { id = "app"; dependencies = []; };
                acquisition = std::Option::Some(child::source());
            } } } } pub publish(published, recipe): std::Recipe;
    "#,
    )
    .unwrap();
    let configuration = package_configuration();
    lock_project_with(&child, &configuration).unwrap();
    lock_project_with(&consumer, &configuration).unwrap();
    let prepared = prepare_project_with(&consumer, &configuration).unwrap();
    let plan = prepared.plan();
    let source = plan
        .acquisitions()
        .next()
        .unwrap()
        .sources()
        .next()
        .unwrap();
    assert_eq!(
        fs::canonicalize(
            prepared
                .project_root(source.owner().unwrap())
                .unwrap()
        )
        .unwrap(),
        fs::canonicalize(child).unwrap()
    );
}

#[test]
fn standard_list_helpers_compose_project_defined_types() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r"
        value Number(int);
        struct Wrapped<T> { item: T; }
        fn wrap<T>(item: T) -> Wrapped<T> { Wrapped<T> { item = item; } }
        outputs {
            transformed: [Wrapped<Number>] = std::map<Number, Wrapped<Number>>(
                std::flatten<Number>([[Number(1)], [Number(2)]]), wrap<Number>
            );
        }
    ",
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = value_projection_plan(&project.0, &configuration).unwrap();
    assert!(plan.to_string().contains("transformed"));
}

#[test]
fn imported_filter_map_keeps_affine_payloads_and_plan_enum_arguments() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(
        child.join("main.srx"),
        r"
        pub resource Ticket(int);
        pub enum Entry { Keep(Ticket), Drop }
        pub fn keep(entry: Entry) -> std::Option<Entry> {
            match entry {
                Keep(ticket) => std::Option::Some(Entry::Keep(ticket)),
                Drop => std::Option::None(),
            }
        }
        pub fn select(entry: Entry) -> std::Option<Ticket> {
            match entry {
                Keep(ticket) => std::Option::Some(ticket),
                Drop => std::Option::None(),
            }
        }
    ",
    )
    .unwrap();
    fs::write(consumer.join("main.srx"), r#"
        inputs { child = "path:../child"; }
        value Label(str);
        outputs {
            selected: [child::Ticket] = std::filter_map(
                std::filter(
                    [child::Entry::Keep(child::Ticket(1)), child::Entry::Drop, child::Entry::Keep(child::Ticket(2))],
                    child::keep
                ),
                child::select
            );
            status: std::Result<Label, Label> = std::Result::Ok(Label("done"));
        }
    "#).unwrap();
    let configuration = package_configuration();
    lock_project_with(&child, &configuration).unwrap();
    lock_project_with(&consumer, &configuration).unwrap();
    let plan = value_projection_plan(&consumer, &configuration).unwrap();
    let selected = plan
        .roots()
        .find(|root| root.name() == "selected")
        .unwrap();
    assert_eq!(selected.claims().count(), 2);
    let crate::plan::PlanValue::List {
        items,
        ..
    } = selected.value()
    else {
        panic!("expected selected list");
    };
    assert_eq!(items.len(), 2);
    let status = plan
        .roots()
        .find(|root| root.name() == "status")
        .unwrap();
    assert!(
        matches!(status.value(), crate::plan::PlanValue::Variant { index: 0, payload, .. } if payload.len() == 1)
    );
    assert!(plan.to_string().contains("done"));
}

#[test]
fn ordered_maps_sort_independently_of_insertion_and_reject_duplicate_keys() {
    let project = TempProject::new();
    project.write("main.srx", r#"
        value I(int);
        outputs {
            forward: std::Result<std::OrderedMap<I>, std::MapKey> = std::map_from_entries([
                std::MapEntry::Entry("a", I(1)), std::MapEntry::Entry("z", I(2)), std::MapEntry::Entry("é", I(3))
            ]);
            reverse: std::Result<std::OrderedMap<I>, std::MapKey> = std::map_from_entries([
                std::MapEntry::Entry("é", I(3)), std::MapEntry::Entry("z", I(2)), std::MapEntry::Entry("a", I(1))
            ]);
            duplicate: std::Result<std::OrderedMap<I>, std::MapKey> = std::map_from_entries([
                std::MapEntry::Entry("a", I(1)), std::MapEntry::Entry("a", I(2))
            ]);
            empty: std::Option<I> = std::map_get(std::map_empty<I>(), "missing");
        }
    "#);
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = value_projection_plan(&project.0, &configuration).unwrap();
    let root = |name| {
        plan.roots()
            .find(|root| root.name() == name)
            .unwrap()
            .value()
    };
    assert_eq!(root("forward"), root("reverse"));
    assert!(matches!(
        root("forward"),
        crate::plan::PlanValue::Variant {
            index: 0,
            ..
        }
    ));
    assert!(
        matches!(root("duplicate"), crate::plan::PlanValue::Variant { index: 1, payload, .. } if matches!(payload.as_slice(), [crate::plan::PlanValue::Nominal { value, .. }] if **value == crate::plan::PlanValue::Str("a".into())))
    );
    assert!(
        matches!(root("empty"), crate::plan::PlanValue::Variant { index: 0, payload, .. } if payload.is_empty())
    );
}

#[test]
fn ordered_map_factories_are_importable_and_unselected_factories_stay_dormant() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(
        child.join("main.srx"),
        r#"
        pub resource Ticket(int) where 1..=2;
        fn good() -> Ticket { Ticket(1) }
        fn disconnected() -> Ticket { Ticket(9) }
        fn make() -> std::OrderedMap<fn() -> Ticket> {
            match std::map_from_entries([
                std::MapEntry::Entry("z-unused", disconnected),
                std::MapEntry::Entry("a-selected", good)
            ]) {
                Ok(items) => items,
                Err(_) => std::map_empty(),
            }
        }
        outputs { factories: std::OrderedMap<fn() -> Ticket> = make(); }
    "#,
    )
    .unwrap();
    fs::write(
        consumer.join("main.srx"),
        r#"
        inputs { child = "path:../child"; }
        outputs {
            names: [std::MapKey] = std::map_keys(child::factories);
            selected: child::Ticket = match std::map_get(child::factories, "a-selected") {
                Some(factory) => factory(),
                None => child::Ticket(2),
            };
        }
    "#,
    )
    .unwrap();
    let configuration = package_configuration();
    lock_project_with(&child, &configuration).unwrap();
    lock_project_with(&consumer, &configuration).unwrap();
    let plan = value_projection_plan(&consumer, &configuration).unwrap();
    let names = plan
        .roots()
        .find(|root| root.name() == "names")
        .unwrap();
    assert_eq!(names.claims().count(), 0);
    let crate::plan::PlanValue::List {
        items,
        ..
    } = names.value()
    else {
        panic!("expected names");
    };
    let keys: Vec<_> = items
        .iter()
        .map(|item| match item {
            crate::plan::PlanValue::Nominal {
                value,
                ..
            } => value.as_ref(),
            _ => panic!("expected key"),
        })
        .collect();
    assert_eq!(
        keys,
        vec![
            &crate::plan::PlanValue::Str("a-selected".into()),
            &crate::plan::PlanValue::Str("z-unused".into())
        ]
    );
    let selected = plan
        .roots()
        .find(|root| root.name() == "selected")
        .unwrap();
    assert_eq!(selected.claims().count(), 1);
    assert!(
        matches!(selected.value(), crate::plan::PlanValue::Nominal { value, .. } if **value == crate::plan::PlanValue::Int(1))
    );
}

#[test]
fn module_exports_discover_locked_factories_without_a_central_recipe_list() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir_all(child.join("recipes/group")).unwrap();
    fs::create_dir(&consumer).unwrap();
    let main = r#"
        inputs { recipes = "modules:recipes"; }
        fn collect() -> std::OrderedMap<fn() -> std::Package> {
            match std::map_from_entries(module_exports(recipes, recipe, std::MapEntry::Entry<fn() -> std::Package>)) {
                Ok(items) => items, Err(_) => std::map_empty(),
            }
        }
        outputs { factories: std::OrderedMap<fn() -> std::Package> = collect(); }
    "#;
    fs::write(child.join("main.srx"), main).unwrap();
    fs::write(child.join("recipes/group/selected.srx"), r#"pub fn recipe() -> std::Package { std::Package { id = "selected"; dependencies = []; } }"#).unwrap();
    fs::write(child.join("recipes/z_unused.srx"), r#"
        resource R(int);
        pub fn recipe() -> std::Package { let conflict = [R(1), R(1)]; std::Package { id = "unused"; dependencies = []; } }
    "#).unwrap();
    fs::write(
        child.join("recipes/private.srx"),
        r#"fn recipe() -> std::Package { std::Package { id = "private"; dependencies = []; } }"#,
    )
    .unwrap();
    fs::write(
        consumer.join("main.srx"),
        r#"
        inputs { pkgs = "path:../child"; }
        outputs {
            names: [std::MapKey] = std::map_keys(pkgs::factories);
            selected: std::Package = match std::map_get(pkgs::factories, "group::selected") {
                Some(factory) => factory(),
                None => std::Package { id = "missing"; dependencies = []; },
            };
        }
    "#,
    )
    .unwrap();
    let config = package_configuration();
    lock_project_with(&child, &config).unwrap();
    lock_project_with(&consumer, &config).unwrap();
    let plan = value_projection_plan(&consumer, &config).unwrap();
    assert_eq!(plan.packages().count(), 1);
    assert!(plan.to_string().contains("package \"selected\""));
    let names = plan
        .roots()
        .find(|root| root.name() == "names")
        .unwrap();
    let crate::plan::PlanValue::List {
        items,
        ..
    } = names.value()
    else {
        panic!("expected names");
    };
    assert_eq!(items.len(), 2);
    assert!(
        matches!(&items[0], crate::plan::PlanValue::Nominal { value, .. } if **value == crate::plan::PlanValue::Str("group::selected".into()))
    );
    fs::write(
        child.join("recipes/added.srx"),
        r#"pub fn recipe() -> std::Package { std::Package { id = "added"; dependencies = []; } }"#,
    )
    .unwrap();
    assert!(matches!(
        value_projection_plan(&consumer, &config),
        Err(ProjectOperationError::Check(
            CheckFailure::InvalidChildLock { .. }
        ))
    ));
    lock_project_with(&child, &config).unwrap();
    assert!(matches!(
        value_projection_plan(&consumer, &config),
        Err(ProjectOperationError::GraphDrift)
    ));
    lock_project_with(&consumer, &config).unwrap();
    let plan = value_projection_plan(&consumer, &config).unwrap();
    let names = plan
        .roots()
        .find(|root| root.name() == "names")
        .unwrap();
    assert!(
        matches!(names.value(), crate::plan::PlanValue::List { items, .. } if items.len() == 3)
    );
    assert_eq!(
        fs::read_to_string(child.join("main.srx")).unwrap(),
        main
    );
}

#[test]
fn module_exports_respect_input_visibility_and_reexport_identity() {
    let project = TempProject::new();
    project.write("main.srx", r#"
        inputs { modules = "modules:modules"; child = "path:child"; }
        outputs {
            exposed: [std::MapKey] = module_exports(modules, recipe, fn(key: std::MapKey, factory: fn() -> std::Package) -> std::MapKey { key });
            hidden: [std::MapKey] = module_exports(child::hidden, recipe, fn(key: std::MapKey, factory: fn() -> std::Package) -> std::MapKey { key });
        }
    "#);
    project.write(
        "modules/implementation.srx",
        r#"pub fn recipe() -> std::Package { std::Package { id = "public"; dependencies = []; } }"#,
    );
    project.write(
        "modules/facade.srx",
        "pub use implementation::recipe;",
    );
    project.write("child/main.srx", r#"mod hidden { pub fn recipe() -> std::Package { std::Package { id = "private"; dependencies = []; } } }"#);
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let plan = value_projection_plan(&project.0, &config).unwrap();
    let hidden = plan
        .roots()
        .find(|root| root.name() == "hidden")
        .unwrap();
    assert!(
        matches!(hidden.value(), crate::plan::PlanValue::List { items, .. } if items.is_empty())
    );
    let exposed = plan
        .roots()
        .find(|root| root.name() == "exposed")
        .unwrap();
    assert!(
        matches!(exposed.value(), crate::plan::PlanValue::List { items, .. } if items.len() == 2)
    );
}

#[test]
fn module_exports_keep_the_original_asset_owner_through_reexports() {
    let workspace = TempProject::new();
    let leaf = workspace.0.join("leaf");
    let catalog = workspace.0.join("catalog");
    let consumer = workspace.0.join("consumer");
    for project in [&leaf, &catalog, &consumer] {
        fs::create_dir_all(project.join("assets")).unwrap();
    }
    fs::write(leaf.join("assets/source"), b"child").unwrap();
    fs::write(catalog.join("assets/source"), b"catalog").unwrap();
    fs::write(consumer.join("assets/source"), b"consumer").unwrap();
    fs::write(leaf.join("main.srx"), r#"
        pub fn source() -> std::Acquisition {
            std::Acquisition { sources = [std::source_request(
                "project:assets/source", "ddc9e669194254cef019a29d3619a2c16592e5d52e1a81e98b01bd52319149a3", 100
            )]; }
        }
    "#).unwrap();
    fs::write(catalog.join("main.srx"), r#"
        inputs { leaf = "path:../leaf"; }
        mod facade { pub use leaf::source; }
        fn collect() -> std::OrderedMap<fn() -> std::Acquisition> {
            match std::map_from_entries(module_exports(facade, source, std::MapEntry::Entry<fn() -> std::Acquisition>)) {
                Ok(items) => items, Err(_) => std::map_empty(),
            }
        }
        outputs { sources: std::OrderedMap<fn() -> std::Acquisition> = collect(); }
    "#).unwrap();
    fs::write(consumer.join("main.srx"), r#"
        inputs { catalog = "path:../catalog"; }
        mod published { mod package { pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = "app"; dependencies = []; };
                acquisition = std::Option::Some(match std::map_get(catalog::sources, "") {
                    Some(factory) => factory(), None => std::Acquisition { sources = []; },
                });
            } } } } pub publish(published, recipe): std::Recipe;
    "#).unwrap();
    let config = package_configuration();
    for project in [&leaf, &catalog, &consumer] {
        lock_project_with(project, &config).unwrap();
    }
    let prepared = prepare_project_with(&consumer, &config).unwrap();
    let plan = prepared.plan();
    let request = plan
        .acquisitions()
        .next()
        .unwrap()
        .sources()
        .next()
        .unwrap();
    let origin = prepared
        .project_root(request.owner().unwrap())
        .unwrap();
    assert_eq!(
        fs::canonicalize(origin).unwrap(),
        fs::canonicalize(&leaf).unwrap()
    );
    let store = crate::store::Store::initialize(&workspace.0.join("store")).unwrap();
    crate::realize::acquire_build_local(
        &store,
        origin,
        "assets/source",
        request.digest(),
        request.maximum_bytes(),
        &crate::store::RootName::new(format!("source_{}", request.digest())).unwrap(),
        &crate::cancellation::Cancellation::default(),
    )
    .unwrap();
}

#[test]
fn ordered_map_affine_values_move_in_key_order() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        resource Ticket(int);
        outputs {
            tickets: [Ticket] = match std::map_from_entries([
                std::MapEntry::Entry("z", Ticket(2)), std::MapEntry::Entry("a", Ticket(1))
            ]) {
                Ok(items) => std::map_values(items),
                Err(_) => [],
            };
        }
    "#,
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = value_projection_plan(&project.0, &configuration).unwrap();
    let root = plan.roots().next().unwrap();
    assert_eq!(root.claims().count(), 2);
    let crate::plan::PlanValue::List {
        items,
        ..
    } = root.value()
    else {
        panic!("expected tickets");
    };
    assert_eq!(items.len(), 2);
    for (item, expected) in items.iter().zip(1..=2) {
        assert!(
            matches!(item, crate::plan::PlanValue::Nominal { value, .. } if **value == crate::plan::PlanValue::Int(expected))
        );
    }
}

#[test]
fn ordered_map_constructor_and_affine_access_cannot_bypass_invariants() {
    for (source, expected) in [
        (
            "value I(int); outputs { forged: std::OrderedMap<I> = std::OrderedMap<I> { entries = []; }; }",
            "opaque struct constructor is private",
        ),
        (
            "resource R(int); fn bad(items: std::OrderedMap<R>) -> [std::Option<R>] { [std::map_get(items, \"a\"), std::map_get(items, \"b\")] }",
            "use of moved affine value",
        ),
        (
            "resource R(int); fn bad(items: std::OrderedMap<once fn() -> R>) -> [std::OrderedMap<once fn() -> R>] { [items, items] }",
            "use of moved affine value",
        ),
    ] {
        let project = TempProject::new();
        project.write("main.srx", source);
        let result = check_project_with(&project.0, &package_configuration());
        assert!(
            matches!(&result, Err(CheckFailure::Diagnostics { errors, .. }) if errors.iter().any(|error| error.message.contains(expected))),
            "{result:?}"
        );
    }
}

#[test]
fn ordered_map_merge_preserves_values_and_reports_collisions() {
    let project = TempProject::new();
    project.write("main.srx", r#"
        resource Ticket(int);
        fn one(key: std::MapKey, item: Ticket) -> std::OrderedMap<Ticket> {
            match std::map_insert(std::map_empty<Ticket>(), key, item) {
                Ok(items) => items, Err(_) => std::map_empty(),
            }
        }
        outputs {
            joined: [Ticket] = match std::map_merge(one("z", Ticket(2)), one("a", Ticket(1))) {
                Ok(items) => std::map_values(items), Err(_) => [],
            };
            duplicate: std::Result<std::OrderedMap<Ticket>, std::MapKey> = std::map_merge(one("a", Ticket(1)), one("a", Ticket(2)));
        }
    "#);
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = value_projection_plan(&project.0, &configuration).unwrap();
    let joined = plan
        .roots()
        .find(|root| root.name() == "joined")
        .unwrap();
    assert_eq!(joined.claims().count(), 2);
    let crate::plan::PlanValue::List {
        items,
        ..
    } = joined.value()
    else {
        panic!("expected tickets");
    };
    assert_eq!(items.len(), 2);
    for (item, expected) in items.iter().zip(1..=2) {
        assert!(
            matches!(item, crate::plan::PlanValue::Nominal { value, .. } if **value == crate::plan::PlanValue::Int(expected))
        );
    }
    let duplicate = plan
        .roots()
        .find(|root| root.name() == "duplicate")
        .unwrap();
    assert!(matches!(
        duplicate.value(),
        crate::plan::PlanValue::Variant {
            index: 1,
            ..
        }
    ));
}

#[test]
fn ordered_map_composition_respects_evaluation_work_and_expansion_limits() {
    let project = TempProject::new();
    let entries = (0..16)
        .rev()
        .map(|index| format!("std::MapEntry::Entry(\"key-{index:02}\", I({index}))"))
        .collect::<Vec<_>>()
        .join(",");
    project.write("main.srx", &format!("value I(int); outputs {{ items: std::Result<std::OrderedMap<I>, std::MapKey> = std::map_from_entries([{entries}]); }}"));
    assert!(check_project_with(&project.0, &package_configuration()).is_ok());
    for work_limit in [true, false] {
        let mut configuration = package_configuration();
        if work_limit {
            configuration.evaluation_limits.max_steps_per_root = 100;
        } else {
            configuration
                .evaluation_limits
                .max_expansion_bytes = 4096;
        }
        let expected = if work_limit {
            "step limit"
        } else {
            "expansion byte limit"
        };
        let result = check_project_with(&project.0, &configuration);
        assert!(
            matches!(&result, Err(CheckFailure::Evaluation { errors, .. }) if errors.iter().any(|error| error.message.contains(expected))),
            "{result:?}"
        );
    }
}

#[test]
fn asset_tree_refuses_symlinks_before_publishing_a_lock() {
    let project = TempProject::new();
    project.write("main.srx", "pub struct X {}");
    fs::create_dir(project.0.join("assets")).unwrap();
    symlink(
        project.0.join("main.srx"),
        project.0.join("assets/patch.diff"),
    )
    .unwrap();
    assert!(matches!(
        lock_project(&project.0),
        Err(ProjectOperationError::Check(
            CheckFailure::SymbolicLink { .. }
        ))
    ));
    assert!(!project.0.join(lock::LOCK_FILE_NAME).exists());
}

#[test]
fn local_markdown_in_assets_does_not_change_the_published_snapshot() {
    let project = TempProject::new();
    project.write("main.srx", "pub struct X {}");
    project.write("assets/fix.patch", "patch");
    project.write("assets/README.md", "local notes");
    lock_project(&project.0).unwrap();
    let snapshot = fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    fs::remove_file(project.0.join("assets/README.md")).unwrap();
    check_project_lock(&project.0).unwrap();
    assert_eq!(
        fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap(),
        snapshot
    );
}

#[test]
fn transitive_child_lock_and_exports_are_verified_at_each_edge() {
    let workspace = TempProject::new();
    let leaf = workspace.0.join("leaf");
    let middle = workspace.0.join("middle");
    let consumer = workspace.0.join("consumer");
    for path in [&leaf, &middle, &consumer] {
        fs::create_dir(path).unwrap();
    }
    fs::write(
        leaf.join("main.srx"),
        "pub struct X {} pub fn make() -> X { X {} }",
    )
    .unwrap();
    fs::write(middle.join("main.srx"), "inputs { leaf = \"path:../leaf\"; } pub type X = leaf::X; pub fn make() -> X { leaf::make() }").unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { middle = \"path:../middle\"; } outputs { selected: middle::X = middle::make(); }",
    )
    .unwrap();
    lock_project(&leaf).unwrap();
    lock_project(&middle).unwrap();
    lock_project(&consumer).unwrap();
    check_project_lock(&consumer).unwrap();
    fs::write(
        leaf.join("main.srx"),
        "pub struct X {} pub fn make() -> X { X {} } // drift",
    )
    .unwrap();
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::Check(
            CheckFailure::InvalidChildLock { .. }
        ))
    ));
    lock_project(&leaf).unwrap();
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::Check(
            CheckFailure::InvalidChildLock { .. }
        ))
    ));
    lock_project(&middle).unwrap();
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::GraphDrift)
    ));
}

#[test]
fn transitive_cycle_and_graph_depth_fail_before_any_lock_publication() {
    let workspace = TempProject::new();
    let left = workspace.0.join("left");
    let right = workspace.0.join("right");
    fs::create_dir(&left).unwrap();
    fs::create_dir(&right).unwrap();
    fs::write(
        left.join("main.srx"),
        "inputs { right = \"path:../right\"; }",
    )
    .unwrap();
    fs::write(
        right.join("main.srx"),
        "inputs { left = \"path:../left\"; }",
    )
    .unwrap();
    assert!(matches!(
        lock_project(&left),
        Err(ProjectOperationError::Check(
            CheckFailure::ChildProjectCycle { .. }
        ))
    ));
    assert!(!left.join(lock::LOCK_FILE_NAME).exists());
    fs::write(right.join("main.srx"), "pub struct X {}").unwrap();
    lock_project(&right).unwrap();
    let mut configuration = CheckConfiguration::default();
    configuration.project_limits.max_directory_depth = 1;
    assert!(matches!(
        check_project_with(&left, &configuration),
        Err(CheckFailure::ProjectGraphDepth { .. })
    ));
}

#[test]
fn transitive_project_domain_keeps_local_aliases_scoped() {
    let workspace = TempProject::new();
    let leaf = workspace.0.join("leaf");
    let middle = workspace.0.join("middle");
    let consumer = workspace.0.join("consumer");
    fs::create_dir_all(leaf.join("recipes")).unwrap();
    fs::create_dir_all(middle.join("recipes")).unwrap();
    fs::create_dir_all(consumer.join("recipes")).unwrap();
    fs::write(leaf.join("main.srx"), "inputs { recipes = \"modules:recipes\"; } pub type X = recipes::leaf::X; pub fn make() -> X { recipes::leaf::make() }").unwrap();
    fs::write(
        leaf.join("recipes/leaf.srx"),
        "pub struct X {} pub fn make() -> X { X {} }",
    )
    .unwrap();
    fs::write(middle.join("main.srx"), "inputs { recipes = \"modules:recipes\"; leaf = \"path:../leaf\"; } pub type X = leaf::X; pub fn make() -> X { leaf::make() }").unwrap();
    fs::write(
        middle.join("recipes/middle.srx"),
        "pub struct Local {}",
    )
    .unwrap();
    fs::write(consumer.join("main.srx"), "inputs { recipes = \"modules:recipes\"; middle = \"path:../middle\"; } outputs { selected: middle::X = middle::make(); }").unwrap();
    fs::write(
        consumer.join("recipes/consumer.srx"),
        "pub struct Local {}",
    )
    .unwrap();
    lock_project(&leaf).unwrap();
    lock_project(&middle).unwrap();
    lock_project(&consumer).unwrap();
    check_project_lock(&consumer).unwrap();
}

#[test]
fn imported_projects_share_one_standard_library_budget() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    let configuration = package_configuration();
    fs::write(child.join("main.srx"), "pub struct X {}").unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { child = \"path:../child\"; } outputs { selected: child::X = child::X {}; }",
    )
    .unwrap();
    lock_project_with(&child, &configuration).unwrap();
    let total = configuration
        .standard_library
        .as_ref()
        .unwrap()
        .sources()
        .map(|source| source.text().len())
        .sum::<usize>()
        + fs::read(child.join("main.srx")).unwrap().len()
        + fs::read(consumer.join("main.srx")).unwrap().len();
    let mut limited = configuration.clone();
    limited.project_limits.max_total_bytes = total;
    lock_project_with(&consumer, &limited).unwrap();
    limited.project_limits.max_total_bytes = total - 1;
    assert!(matches!(
        check_project_with(&consumer, &limited),
        Err(CheckFailure::ProjectTooLarge { .. })
    ));
}

#[test]
fn imported_project_work_budget_is_shared_across_the_graph() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(child.join("main.srx"), "pub struct X {}").unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { child = \"path:../child\"; }",
    )
    .unwrap();
    lock_project(&child).unwrap();
    let mut configuration = CheckConfiguration::default();
    configuration.project_limits.max_work = 1;
    assert!(matches!(
        check_project_with(&consumer, &configuration),
        Err(CheckFailure::WorkLimit { .. })
    ));
}

#[test]
fn external_and_local_inputs_with_the_same_relative_name_do_not_alias() {
    let workspace = TempProject::new();
    let child = workspace.0.join("dep");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir_all(consumer.join("dep")).unwrap();
    fs::write(child.join("main.srx"), "pub struct X {}").unwrap();
    fs::write(consumer.join("dep/local.srx"), "pub struct Y {}").unwrap();
    fs::write(consumer.join("main.srx"), "inputs { local = \"path:dep\"; external = \"path:../dep\"; } outputs { x: external::X = external::X {}; y: local::Y = local::Y {}; }").unwrap();
    lock_project(&child).unwrap();
    lock_project(&consumer).unwrap();
    check_project_lock(&consumer).unwrap();
}

#[test]
fn removing_the_last_child_does_not_silently_retain_a_stale_graph_lock() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(child.join("main.srx"), "pub struct X {}").unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { dep = \"path:../child\"; }",
    )
    .unwrap();
    lock_project(&child).unwrap();
    lock_project(&consumer).unwrap();
    fs::write(consumer.join("main.srx"), "pub struct Answer {}").unwrap();
    assert!(matches!(
        lock_project(&consumer).unwrap().status(),
        lock::LockStatus::Updated
    ));
    assert!(!consumer.join("Syrox.graph.lock").exists());
    check_project_lock(&consumer).unwrap();
}

#[test]
fn removing_a_child_refuses_a_symlinked_graph_lock_without_mutating_the_parent() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(child.join("main.srx"), "pub struct X {}").unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { dep = \"path:../child\"; }",
    )
    .unwrap();
    lock_project(&child).unwrap();
    lock_project(&consumer).unwrap();
    let old_parent = fs::read(consumer.join(lock::LOCK_FILE_NAME)).unwrap();
    symlink(
        child.join("main.srx"),
        consumer.join("Syrox.graph.lock"),
    )
    .unwrap();
    fs::write(consumer.join("main.srx"), "pub struct Answer {}").unwrap();
    assert!(matches!(
        lock_project(&consumer),
        Err(ProjectOperationError::LockSymlink)
    ));
    assert_eq!(
        fs::read(consumer.join(lock::LOCK_FILE_NAME)).unwrap(),
        old_parent
    );
}

#[test]
fn descriptor_pinned_child_snapshot_resolves_its_own_modules() {
    let workspace = TempProject::new();
    workspace.write("child/main.srx", "inputs { recipes = \"modules:recipes\"; } pub type X = recipes::hello::X; pub fn get() -> X { recipes::hello::make() }");
    workspace.write(
        "child/recipes/hello.srx",
        "pub struct X {} pub fn make() -> X { X {} }",
    );
    workspace.write(
        "consumer/main.srx",
        "inputs { pkgs = \"path:../child\"; } outputs { selected: pkgs::X = pkgs::get(); }",
    );
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    let config = CheckConfiguration::default();
    lock_project_with(&child, &config).unwrap();
    lock_project_with(&consumer, &config).unwrap();
    let loaded = loader::load_project_linux(&consumer, &config).unwrap();
    let domain = loaded
        .sources()
        .child_project_domain(SourceDomainId::project(), "pkgs")
        .unwrap();
    assert_ne!(domain, SourceDomainId::project());
    assert_eq!(loaded.children.len(), 1);
    assert_eq!(
        value_projection_plan(&consumer, &config)
            .unwrap()
            .roots()
            .len(),
        1
    );
}

#[test]
fn child_snapshot_refuses_a_symlinked_source_before_granting_a_domain() {
    let workspace = TempProject::new();
    workspace.write(
        "child/main.srx",
        "inputs { recipes = \"modules:recipes\"; }",
    );
    workspace.write("child/recipes/hello.srx", "pub struct X {}");
    workspace.write(
        "consumer/main.srx",
        "inputs { pkgs = \"path:../child\"; }",
    );
    let target = workspace.0.join("child/recipes/hello.srx");
    fs::rename(&target, workspace.0.join("child/real.srx")).unwrap();
    symlink(workspace.0.join("child/real.srx"), &target).unwrap();
    let result = loader::load_project_linux(
        &workspace.0.join("consumer"),
        &CheckConfiguration::default(),
    );
    assert!(matches!(
        result,
        Err(CheckFailure::SymbolicLink { .. })
    ));
}

#[test]
fn child_library_exports_a_recipe_to_its_consumer() {
    let workspace = TempProject::new();
    workspace.write(
        "child/main.srx",
        r#"inputs { catalog = "modules:recipes"; }
        pub publish(catalog, hello): std::Recipe;"#,
    );
    workspace.write(
        "child/recipes/hello.srx",
        "pub fn hello() -> std::Recipe { std::Recipe { package = std::Package { id = \"hello\"; dependencies = []; }; } }",
    );
    workspace.write(
        "consumer/main.srx",
        r#"inputs { pkgs = "path:../child"; } pub use pkgs::hello;"#,
    );
    let configuration = package_configuration();
    let consumer = workspace.0.join("consumer");
    lock_project_with(&workspace.0.join("child"), &configuration).unwrap();
    lock_project_with(&consumer, &configuration).unwrap();
    let plan = plan_project_with(&consumer, &configuration).unwrap();
    assert_eq!(
        plan.packages().next().unwrap().export(),
        Some("hello")
    );
}

#[test]
fn child_snapshot_requires_its_own_current_lock_before_exposing_sources() {
    let workspace = TempProject::new();
    workspace.write("child/main.srx", "inputs { dep = \"path:dep\"; }");
    workspace.write("child/dep/one.srx", "pub struct One {}");
    workspace.write(
        "consumer/main.srx",
        "inputs { child = \"path:../child\"; }",
    );
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    let load = || loader::load_project_linux(&consumer, &CheckConfiguration::default());
    let missing = load();
    assert!(matches!(
        missing,
        Err(CheckFailure::MissingChildLock { .. })
    ));

    lock_project_with(&child, &CheckConfiguration::default()).unwrap();
    assert!(load().is_ok());
    workspace.write("child/dep/two.srx", "pub struct Two {}");
    let drift = load();
    assert!(matches!(
        drift,
        Err(CheckFailure::InvalidChildLock { .. })
    ));

    fs::remove_file(child.join(lock::LOCK_FILE_NAME)).unwrap();
    symlink(
        child.join("main.srx"),
        child.join(lock::LOCK_FILE_NAME),
    )
    .unwrap();
    let linked = load();
    assert!(matches!(
        linked,
        Err(CheckFailure::InvalidChildLock { .. })
    ));
}

#[test]
fn project_plan_rejects_non_consumer_values_before_serialization() {
    let result = package_plan(
        "struct Holder { function: fn(std::Package) -> std::Package; } fn same(package: std::Package) -> std::Package { package } outputs { holder: Holder = Holder { function = same; }; }",
    );
    assert!(matches!(
        result,
        Err(ProjectOperationError::InvalidConsumerOutput { .. })
    ));
}

#[test]
fn package_factory_closure_composes_without_a_rust_package_case() {
    let plan = package_plan(
        "fn apply(factory: fn() -> std::Package) -> std::Package { factory() } mod catalog { mod pkg { pub fn recipe() -> std::Recipe { std::Recipe { package = apply(fn() -> std::Package { std::Package { id = \"closure-pkg\"; dependencies = []; } }); } } } } pub publish(catalog, recipe): std::Recipe;",
    ).unwrap();
    assert_eq!(
        plan.packages()
            .map(|package| package.id().as_str())
            .collect::<Vec<_>>(),
        ["closure-pkg"]
    );
}

#[test]
fn locked_catalog_discovers_factories_across_files_and_requires_relock_on_addition() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"inputs { catalog = "modules:recipes"; }
         pub publish(catalog, recipe): std::Recipe;"#,
    );
    project.write(
        "recipes/hello.srx",
        r#"
        pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = "hello"; dependencies = []; }; } }
    "#,
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages()
            .map(|p| p.id().as_str())
            .collect::<Vec<_>>(),
        ["hello"]
    );
    assert_eq!(
        plan.packages().next().unwrap().export(),
        Some("hello")
    );

    project.write(
        "recipes/glibc.srx",
        r#"
        pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = "glibc"; dependencies = []; }; } }
    "#,
    );
    assert!(matches!(
        plan_project_with(&project.0, &configuration),
        Err(ProjectOperationError::ProjectDrift)
    ));
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages()
            .map(|p| p.id().as_str())
            .collect::<Vec<_>>(),
        ["glibc", "hello"]
    );
    assert_eq!(
        plan.packages()
            .map(|p| p.export())
            .collect::<Vec<_>>(),
        [Some("glibc"), Some("hello")]
    );
}

#[test]
fn single_composite_recipe_exports_package_source_and_build() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"inputs { catalog = "modules:recipes"; }
         pub publish(catalog, recipe): std::Recipe;"#,
    );
    project.write(
        "recipes/glibc.srx",
        r#"pub fn recipe() -> std::Recipe {
            std::Recipe {
                package = std::Package { id = "glibc"; dependencies = []; };
                acquisition = std::Option::Some(std::Acquisition {
                    sources = [std::SourceRequest {
                        url = "https://example.test/glibc.tar.xz";
                        sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
                        maximum_bytes = 33554432;
                    }];
                });
                build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap;
                    source_directory = "glibc-2.44";
                    timeout_seconds = 1800;
                 source_format = std::BuildSourceFormat::Xz; produces = ["dev", "out"]; steps = [std::BuildStep::Extract(std::BuildPath::Work("source"))]; });
                build_inputs = std::Option::None;
                commands = [];
            }
        }
        "#,
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages().next().unwrap().export(),
        Some("glibc")
    );
    assert_eq!(plan.acquisitions().count(), 1);
    assert_eq!(
        plan.builds()
            .next()
            .unwrap()
            .program()
            .source_format,
        crate::build::BuildSourceFormat::Xz
    );
    assert_eq!(
        plan.roots()
            .filter(|root| root.name() == "glibc")
            .count(),
        1
    );
}

#[test]
fn public_factory_needs_no_repeated_output_signature() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"inputs { catalog = "modules:recipes"; }
         pub publish(catalog, hello): std::Recipe;"#,
    );
    project.write(
        "recipes/hello.srx",
        r#"
        fn private() -> std::Recipe { std::Recipe { package = std::Package { id = "hello"; dependencies = []; }; } }
        pub fn hello() -> std::Recipe { private() }
    "#,
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages().next().unwrap().export(),
        Some("hello")
    );
    assert_eq!(plan.packages().count(), 1);
    project.write(
        "main.srx",
        r#"inputs { catalog = "modules:recipes"; }
        outputs { secret: std::Package = catalog::private(); }"#,
    );
    let result = check_project_with(&project.0, &configuration);
    assert!(
        matches!(&result,
        Err(CheckFailure::Diagnostics { errors, .. }) if errors.iter().any(|error| error.message.contains("private"))),
        "{result:?}"
    );
}

#[test]
fn catalog_files_have_distinct_modules_and_package_entrypoints() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"inputs { catalog = "modules:recipes"; }
         pub publish(catalog, recipe): std::Recipe;"#,
    );
    project.write(
        "recipes/hello/package.srx",
        r#"
        fn make() -> std::Recipe { std::Recipe { package = std::Package { id = "hello"; dependencies = []; }; } }
        pub fn recipe() -> std::Recipe { make() }
    "#,
    );
    project.write(
        "recipes/glibc/package.srx",
        r#"
        fn make() -> std::Recipe { std::Recipe { package = std::Package { id = "glibc"; dependencies = []; }; } }
        pub fn recipe() -> std::Recipe { make() }
    "#,
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages()
            .map(|pkg| pkg.export())
            .collect::<Vec<_>>(),
        [Some("glibc"), Some("hello")]
    );
    project.write(
        "main.srx",
        r#"inputs { catalog = "modules:recipes"; }
        pub publish(catalog, recipe): std::Recipe;
        outputs { private: std::Recipe = catalog::hello::make(); }"#,
    );
    let result = check_project_with(&project.0, &configuration);
    assert!(
        matches!(&result,
        Err(CheckFailure::Diagnostics { errors, .. }) if errors.iter().any(|error| error.message.contains("private"))),
        "{result:?}"
    );
    project.write(
        "recipes/hello.srx",
        "pub fn extra() -> std::Recipe { std::Recipe { package = std::Package { id = \"extra\"; dependencies = []; }; } }",
    );
    assert!(
        matches!(check_project_with(&project.0, &configuration),
        Err(CheckFailure::InvalidModuleInput { reason }) if reason.contains("share one recipe module"))
    );
}

#[test]
fn modules_locator_is_a_general_locked_input_without_catalog_marker() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"inputs { dep = "modules:dep"; }
        pub publish(dep, make): std::Recipe;"#,
    );
    for name in ["hello", "glibc"] {
        project.write(
            &format!("dep/{name}.srx"),
            &format!(
                r#"
            fn private() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "{name}"; dependencies = []; }}; }} }}
            pub fn make() -> std::Recipe {{ private() }}
        "#
            ),
        );
    }
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages()
            .map(|pkg| pkg.export())
            .collect::<Vec<_>>(),
        [Some("glibc"), Some("hello")]
    );
    project.write(
        "dep/other.srx",
        "pub fn unused() -> std::Recipe { std::Recipe { package = std::Package { id = \"other\"; dependencies = []; }; } }",
    );
    assert!(matches!(
        plan_project_with(&project.0, &configuration),
        Err(ProjectOperationError::ProjectDrift)
    ));
}

#[test]
fn development_output_is_an_explicit_validated_build_edge() {
    let config = package_configuration();
    let recipe = r#"mod catalog { mod glibc { pub fn recipe() -> std::Recipe { std::Recipe {
        package = std::Package { id = "glibc"; dependencies = []; };
        acquisition = std::Option::Some(std::Acquisition { sources = [std::SourceRequest { url = "project:glibc.tar.xz"; sha256 = "0000000000000000000000000000000000000000000000000000000000000000"; maximum_bytes = 33554432; }]; });
        build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "glibc-2.44"; timeout_seconds = 1800;  source_format = std::BuildSourceFormat::Xz; produces = ["dev", "out"]; steps = [std::BuildStep::Extract(std::BuildPath::Work("source"))]; });
    } } }
    mod hello { pub fn recipe() -> std::Recipe { std::Recipe {
            package = std::Package { id = "hello"; dependencies = []; };
            acquisition = std::Option::Some(std::Acquisition { sources = [std::SourceRequest { url = "project:hello.tar.gz"; sha256 = "0000000000000000000000000000000000000000000000000000000000000000"; maximum_bytes = 2097152; }]; });
            build = std::Option::Some(std::autotools_with_libc(std::BuildOptions { source_directory = "hello-2.12.1"; timeout_seconds = 120; }));
            commands = [std::Command { name = "main"; output = "out"; path = "usr/bin/hello";  loader = [std::RuntimeFile { output = std::recipe_output(project::glibc, "out"); path = "usr/lib/ld-linux-x86-64.so.2"; }]; libraries = [std::recipe_output(project::glibc, "out")]; }];
            build_inputs = std::Option::Some(std::BuildInputs { selected = [std::recipe_output(project::glibc, "dev"), std::recipe_output(project::glibc, "out")]; });
        } } }
    } pub publish(catalog, recipe): std::Recipe;"#;
    let plan = |source: &str| {
        let project = TempProject::new();
        project.write("main.srx", source);
        lock_project_with(&project.0, &config).unwrap();
        plan_project_with(&project.0, &config)
    };
    let valid = plan(recipe).unwrap();
    let store_directory = tempfile::tempdir().unwrap();
    fs::create_dir(store_directory.path().join("store")).unwrap();
    let store = crate::store::Store::open(&store_directory.path().join("store")).unwrap();
    let root = crate::store::RootName::new("test_build_request").unwrap();
    let glibc = valid
        .builds()
        .find(|build| build.package().as_str() == "glibc")
        .unwrap();
    let mut changed = glibc.request();
    changed.source_directory = "other-directory".into();
    assert!(matches!(
        crate::build::execute_build(
            &valid,
            &changed,
            &store,
            &root,
            std::path::Path::new("/usr"),
            std::path::Path::new("/usr/bin/false")
        ),
        Err(crate::build::BuildError::UnsupportedInputs)
    ));
    let hello = valid
        .builds()
        .find(|build| build.package().as_str() == "hello")
        .unwrap();
    assert!(matches!(
        crate::build::execute_build(
            &valid,
            &hello.request(),
            &store,
            &root,
            std::path::Path::new("/usr"),
            std::path::Path::new("/usr/bin/false")
        ),
        Err(crate::build::BuildError::UnsupportedInputs)
    ));
    assert_eq!(
        valid
            .builds()
            .find(|build| build.package().as_str() == "hello")
            .unwrap()
            .inputs()[0]
            .package
            .as_str(),
        "glibc"
    );
    assert!(
        plan(&recipe.replace(
            "(project::glibc, \"dev\")",
            "(project::glibc, \"missing\")"
        ))
        .is_err()
    );
    let additional_reference = plan(&recipe.replace(
        "std::recipe_output(project::glibc, \"dev\")",
        "std::recipe_output(std::recipe_ref(project::catalog::glibc::recipe), \"dev\")",
    ));
    assert!(
        additional_reference.is_ok(),
        "{additional_reference:?}"
    );
}

#[test]
fn source_is_rejected_after_reading_one_byte_beyond_the_limit() {
    let input = vec![b'x'; MAX_SOURCE_BYTES + 1];
    let error = read_source(Cursor::new(input), Path::new("large.srx")).unwrap_err();
    assert!(matches!(error, CheckFailure::TooLarge { .. }));
}

#[test]
fn project_merges_input_files_in_deterministic_relative_order() {
    let project = TempProject::new();
    project.write("main.srx", "inputs { dep = \"path:dep\"; }");
    project.write(
        "dep/z.srx",
        "mod shared { struct Item { name: Name; } }",
    );
    project.write("dep/a.srx", "mod shared { value Name(str); }");

    let report = check_project(&project.0).unwrap();
    assert_eq!(report.declarations, 3);

    project.write("dep/z.srx", "mod shared { value Name(str); }");
    let CheckFailure::Diagnostics {
        input,
        errors,
    } = check_project(&project.0).unwrap_err()
    else {
        panic!("expected duplicate declaration diagnostic");
    };
    let duplicate = errors
        .iter()
        .find(|error| error.message == "duplicate item declaration in module")
        .unwrap();
    assert_eq!(
        input
            .get(duplicate.span.source_id())
            .unwrap()
            .name(),
        "dep/z.srx"
    );
}

#[test]
fn syntax_errors_do_not_cross_file_boundaries() {
    let project = TempProject::new();
    project.write("main.srx", "inputs { dep = \"path:dep\"; }");
    project.write("dep/a.srx", "mod shared {");
    project.write("dep/b.srx", "}");

    let CheckFailure::Diagnostics {
        errors,
        ..
    } = check_project(&project.0).unwrap_err()
    else {
        panic!("expected syntax diagnostics");
    };
    assert!(errors.len() >= 2);
}

#[test]
fn project_rejects_unsafe_and_unsupported_locators() {
    for (locator, expected) in [
        ("path:../../outside", "relative"),
        ("https:example.invalid", "unsupported locator"),
    ] {
        let project = TempProject::new();
        project.write(
            "main.srx",
            &format!("inputs {{ dep = \"{locator}\"; }}"),
        );
        assert!(
            check_project(&project.0)
                .unwrap_err()
                .to_string()
                .contains(expected)
        );
    }
}

#[test]
fn locator_overlap_is_rejected_before_input_roots_are_opened() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "inputs { missing = \"path:missing\"; nested = \"path:missing/nested\"; }",
    );

    assert!(matches!(
        check_project(&project.0).unwrap_err(),
        CheckFailure::AliasedInputPaths { .. }
    ));
}

#[cfg(unix)]
#[test]
fn project_rejects_symlinked_inputs_and_files() {
    use std::os::unix::fs::symlink;

    let project = TempProject::new();
    project.write("main.srx", "inputs { dep = \"path:dep\"; }");
    project.write("real/source.srx", "value V(str);");
    symlink(project.0.join("real"), project.0.join("dep")).unwrap();
    let error = check_project(&project.0).unwrap_err();
    assert!(
        matches!(error, CheckFailure::SymbolicLink { .. }),
        "{error:?}"
    );

    fs::remove_file(project.0.join("dep")).unwrap();
    fs::create_dir(project.0.join("dep")).unwrap();
    symlink(
        project.0.join("real/source.srx"),
        project.0.join("dep/source.srx"),
    )
    .unwrap();
    assert!(matches!(
        check_project(&project.0).unwrap_err(),
        CheckFailure::SymbolicLink { .. }
    ));

    fs::remove_file(project.0.join("dep/source.srx")).unwrap();
    fs::remove_file(project.0.join("main.srx")).unwrap();
    symlink(
        project.0.join("real/source.srx"),
        project.0.join("main.srx"),
    )
    .unwrap();
    assert!(matches!(
        check_project(&project.0).unwrap_err(),
        CheckFailure::SymbolicLink { .. }
    ));
}

#[test]
fn traversal_keeps_using_the_opened_directory_after_a_path_swap() {
    use std::os::unix::fs::symlink;

    let project = TempProject::new();
    project.write("main.srx", "value Main(str);");
    project.write("dep/source.srx", "value Original(str);");
    project.write(
        "replacement/source.srx",
        "value Replacement(str);",
    );

    let mut budget = LoadBudget::new(ProjectLimits::default());
    let project_handle = open_top(&project.0, &mut budget).unwrap();
    let dep_path = project.0.join("dep");
    let dep = open_beneath(
        project_handle.fd(),
        Path::new("dep"),
        &dep_path,
        true,
        &mut budget,
    )
    .unwrap();
    let root = InputRoot {
        name: "dep".to_owned(),
        relative: PathBuf::from("dep"),
        opened: dep,
    };
    let mut directories = HashMap::new();
    directories.insert(identity(&project_handle), project.0.clone());
    directories.insert(identity(&root.opened), dep_path.clone());

    fs::rename(&dep_path, project.0.join("original-dep")).unwrap();
    symlink(project.0.join("replacement"), &dep_path).unwrap();
    let files = walk_input(
        &project.0,
        root,
        &mut directories,
        &mut HashMap::new(),
        &mut budget,
    )
    .unwrap();
    assert_eq!(files.len(), 1);
    assert!(files[0].1.contains("Original"));

    fs::remove_file(&dep_path).unwrap();
    fs::rename(project.0.join("original-dep"), dep_path).unwrap();
}

#[test]
fn reopened_descendant_must_match_its_discovered_identity() {
    let project = TempProject::new();
    fs::create_dir_all(project.0.join("dep/child")).unwrap();
    fs::create_dir_all(project.0.join("replacement")).unwrap();

    let mut budget = LoadBudget::new(ProjectLimits::default());
    let project_handle = open_top(&project.0, &mut budget).unwrap();
    let dep_path = project.0.join("dep");
    let dep = open_beneath(
        project_handle.fd(),
        Path::new("dep"),
        &dep_path,
        true,
        &mut budget,
    )
    .unwrap();
    let child = open_beneath(
        dep.fd(),
        Path::new("child"),
        &dep_path.join("child"),
        true,
        &mut budget,
    )
    .unwrap();
    let expected = identity(&child);
    drop(child);

    fs::rename(
        dep_path.join("child"),
        project.0.join("original-child"),
    )
    .unwrap();
    fs::rename(
        project.0.join("replacement"),
        dep_path.join("child"),
    )
    .unwrap();

    assert!(matches!(
        reopen_directory(
            dep.fd(),
            Path::new("child"),
            &dep_path.join("child"),
            expected,
            &mut budget,
        ),
        Err(CheckFailure::Inspect { .. })
    ));
}

fn run_with_low_descriptor_limit(test_name: &str, marker: &str) {
    let executable = crate::reexec_test_executable(test_name, false);
    let output = Command::new("sh")
        .args([
            "-c",
            "ulimit -n 32 && exec \"$1\" --exact \"$2\" --nocapture",
            "sh",
        ])
        .arg(executable)
        .arg(test_name)
        .env(marker, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "low-descriptor child failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    crate::assert_reexec_result(&output.stdout, test_name);
}

#[test]
fn traversal_does_not_retain_sibling_directory_descriptors() {
    const MARKER: &str = "SYROX_TEST_LOW_FD_SIBLINGS";
    if std::env::var_os(MARKER).is_none() {
        run_with_low_descriptor_limit(
            "project::tests::traversal_does_not_retain_sibling_directory_descriptors",
            MARKER,
        );
        return;
    }

    let project = TempProject::new();
    project.write("main.srx", "inputs { dep = \"path:dep\"; }");
    for index in 0..64 {
        fs::create_dir_all(project.0.join(format!("dep/child-{index:02}"))).unwrap();
    }
    check_project(&project.0).unwrap();
}

#[test]
fn project_does_not_retain_all_input_root_descriptors() {
    const MARKER: &str = "SYROX_TEST_LOW_FD_ROOTS";
    if std::env::var_os(MARKER).is_none() {
        run_with_low_descriptor_limit(
            "project::tests::project_does_not_retain_all_input_root_descriptors",
            MARKER,
        );
        return;
    }

    let project = TempProject::new();
    let mut main = String::from("inputs {");
    for index in 0..64 {
        write!(main, " dep{index} = \"path:dep{index}\";").unwrap();
        fs::create_dir(project.0.join(format!("dep{index}"))).unwrap();
    }
    main.push_str(" }");
    project.write("main.srx", &main);
    check_project(&project.0).unwrap();
}

#[test]
fn hard_linked_sources_cannot_receive_distinct_domain_authority() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "inputs { first = \"path:first\"; second = \"path:second\"; }",
    );
    project.write("first/source.srx", "value V(str);");
    fs::create_dir(project.0.join("second")).unwrap();
    fs::hard_link(
        project.0.join("first/source.srx"),
        project.0.join("second/source.srx"),
    )
    .unwrap();

    assert!(matches!(
        check_project(&project.0).unwrap_err(),
        CheckFailure::AliasedSourceFiles { .. }
    ));
}

#[test]
fn every_configurable_project_limit_has_a_hard_maximum() {
    let limits = [
        ProjectLimits {
            max_total_bytes: MAX_PROJECT_BYTES + 1,
            ..ProjectLimits::default()
        },
        ProjectLimits {
            max_sources: MAX_SOURCES + 1,
            ..ProjectLimits::default()
        },
        ProjectLimits {
            max_directory_entries: MAX_DIRECTORY_ENTRIES + 1,
            ..ProjectLimits::default()
        },
        ProjectLimits {
            max_work: MAX_PROJECT_WORK + 1,
            ..ProjectLimits::default()
        },
        ProjectLimits {
            max_directory_depth: MAX_DIRECTORY_DEPTH + 1,
            ..ProjectLimits::default()
        },
    ];
    for project_limits in limits {
        let configuration = CheckConfiguration {
            project_limits,
            ..CheckConfiguration::default()
        };
        assert!(matches!(
            check_project_with(Path::new("unused"), &configuration).unwrap_err(),
            CheckFailure::InvalidProjectLimit { .. }
        ));
    }
}

#[test]
fn zero_work_rejects_a_main_only_project_before_opening_it() {
    let project = TempProject::new();
    project.write("main.srx", "value V(str);");
    let mut configuration = CheckConfiguration::default();
    configuration.project_limits.max_work = 0;

    assert!(matches!(
        check_project_with(&project.0, &configuration).unwrap_err(),
        CheckFailure::WorkLimit {
            limit: 0
        }
    ));
}

#[test]
fn unavailable_openat2_is_never_mapped_to_a_path_fallback() {
    assert!(matches!(
        open_error(
            Path::new("project"),
            OpenError::Unsupported(io::Error::other("openat2 unavailable")),
        ),
        CheckFailure::UnsupportedKernel { .. }
    ));
}

#[test]
fn configurable_total_byte_and_work_limits_fail_closed() {
    let project = TempProject::new();
    project.write("main.srx", "inputs { dep = \"path:dep\"; }");
    project.write("dep/a.srx", "value V(str);");

    let mut configuration = CheckConfiguration::default();
    configuration.project_limits.max_total_bytes = 1;
    assert!(matches!(
        check_project_with(&project.0, &configuration).unwrap_err(),
        CheckFailure::ProjectTooLarge { .. }
    ));

    configuration.project_limits.max_total_bytes = MAX_PROJECT_BYTES;
    configuration.project_limits.max_work = 0;
    assert!(matches!(
        check_project_with(&project.0, &configuration).unwrap_err(),
        CheckFailure::WorkLimit { .. }
    ));
}

#[test]
fn directory_entry_limit_rejects_during_enumeration_without_changing_later_output() {
    let project = TempProject::new();
    project.write("main.srx", "inputs { dep = \"path:dep\"; }");
    project.write("dep/z.srx", "value Z(str);");
    project.write("dep/a.srx", "value A(str);");
    let mut configuration = CheckConfiguration::default();
    configuration.project_limits.max_directory_entries = 1;

    assert!(matches!(
        check_project_with(&project.0, &configuration).unwrap_err(),
        CheckFailure::TooManyDirectoryEntries {
            limit: 1
        }
    ));

    let loaded = loader::load_project_linux(&project.0, &CheckConfiguration::default()).unwrap();
    let paths: Vec<_> = loaded
        .inputs()
        .next()
        .unwrap()
        .files()
        .map(|source| source.relative_path().to_path_buf())
        .collect();
    assert_eq!(
        paths,
        [
            PathBuf::from("a.srx"),
            PathBuf::from("z.srx")
        ]
    );
}

#[test]
fn failed_root_without_diagnostic_capacity_is_still_an_evaluation_failure() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "resource R(int); outputs { bad: [R] = [R(1), R(1)]; }",
    );
    let mut configuration = CheckConfiguration::default();
    configuration.evaluation_limits.max_diagnostics = 0;
    let error = check_path_with(&project.0.join("main.srx"), &configuration).unwrap_err();
    let CheckFailure::Evaluation {
        errors,
        failed_roots,
        ..
    } = error
    else {
        panic!("expected structured evaluation failure");
    };
    assert!(errors.is_empty());
    assert_eq!(failed_roots, ["bad"]);
}

#[test]
fn evaluation_setup_failure_is_structured() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value V(int); outputs { out: V = 1; }",
    );
    let mut configuration = CheckConfiguration::default();
    configuration.evaluation_limits.max_setup_steps = 0;
    let error = check_path_with(&project.0.join("main.srx"), &configuration).unwrap_err();
    assert!(matches!(
        error,
        CheckFailure::EvaluationSetup {
            source: EvaluationSetupError::SetupWorkLimit
        }
    ));
}

#[test]
fn lock_is_idempotent_and_detects_project_drift() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 42; }",
    );

    let created = lock_project(&project.0).unwrap();
    assert_eq!(created.status(), lock::LockStatus::Created);
    let first = fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    assert_eq!(
        lock_project(&project.0).unwrap().status(),
        lock::LockStatus::Unchanged
    );
    assert_eq!(
        fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap(),
        first
    );
    assert_eq!(
        check_project_lock(&project.0).unwrap().status(),
        lock::LockStatus::Unchanged
    );

    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 43; }",
    );
    assert!(matches!(
        check_project_lock(&project.0),
        Err(ProjectOperationError::ProjectDrift)
    ));
    assert_eq!(
        lock_project(&project.0).unwrap().status(),
        lock::LockStatus::Updated
    );
}

#[test]
fn lock_detects_input_and_standard_library_drift() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); inputs { dep = \"path:dep\"; } outputs { answer: Number = 42; }",
    );
    project.write("dep/a.srx", "value Name(str);");
    lock_project(&project.0).unwrap();
    project.write("dep/a.srx", "value Other(str);");
    assert!(matches!(
        check_project_lock(&project.0),
        Err(ProjectOperationError::ProjectDrift)
    ));

    project.write("dep/a.srx", "value Name(str);");
    let source =
        AuthenticatedStandardSource::from_authenticated("std.srx", "value Std(str);").unwrap();
    let configured = CheckConfiguration {
        standard_library: Some(
            AuthenticatedStandardLibrary::from_authenticated(vec![source]).unwrap(),
        ),
        ..CheckConfiguration::default()
    };
    assert!(matches!(
        check_project_lock_with(&project.0, &configured),
        Err(ProjectOperationError::StandardLibraryDrift)
    ));
}

#[test]
fn standard_library_rejects_an_empty_snapshot() {
    let source =
        AuthenticatedStandardSource::from_authenticated("std.srx", "value Std(str);").unwrap();
    assert!(AuthenticatedStandardLibrary::from_authenticated(vec![source]).is_ok());
    assert_eq!(
        AuthenticatedStandardLibrary::from_authenticated(vec![]).unwrap_err(),
        StandardLibraryError::InvalidSourceCount
    );
}

#[test]
fn locked_operations_reject_scope_and_erasure_policies() {
    let identity = |name| CanonicalItemIdentity::new(SourceDomainId::project(), [name]).unwrap();
    let policies = [
        CheckPolicy::new("scope")
            .unwrap()
            .with_scope("network")
            .unwrap(),
        CheckPolicy::new("erasure")
            .unwrap()
            .with_erasure(identity("Private"), identity("Public"))
            .unwrap(),
    ];
    for policy in policies {
        let configuration = CheckConfiguration {
            environment: EvaluationEnvironment::new(&policy),
            policy,
            ..CheckConfiguration::default()
        };
        assert!(matches!(
            lock_project_with(Path::new("unused"), &configuration),
            Err(ProjectOperationError::PolicyProvenanceRequired)
        ));
        assert!(matches!(
            check_project_lock_with(Path::new("unused"), &configuration),
            Err(ProjectOperationError::PolicyProvenanceRequired)
        ));
        assert!(matches!(
            plan_project_with(Path::new("unused"), &configuration),
            Err(ProjectOperationError::PolicyProvenanceRequired)
        ));
    }
}

#[test]
fn lock_rejects_an_environment_for_a_different_policy() {
    let environment_policy = CheckPolicy::new("other").unwrap();
    let configuration = CheckConfiguration {
        environment: EvaluationEnvironment::new(&environment_policy),
        ..CheckConfiguration::default()
    };
    assert!(matches!(
        lock_project_with(Path::new("unused"), &configuration),
        Err(ProjectOperationError::PolicyProvenanceRequired)
    ));
}

#[test]
fn generated_lock_size_failure_has_a_distinct_operation_error() {
    assert!(matches!(
        map_generated_lock_error(lock::LockFormatError::TooLarge),
        ProjectOperationError::GeneratedLockTooLarge
    ));
}

#[test]
fn lock_refuses_missing_malformed_symlink_nonregular_and_hardlinked_destinations() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 42; }",
    );
    assert!(matches!(
        check_project_lock(&project.0),
        Err(ProjectOperationError::MissingLock { .. })
    ));

    project.write(lock::LOCK_FILE_NAME, "not a lock\n");
    assert!(matches!(
        lock_project(&project.0),
        Err(ProjectOperationError::MalformedLock { .. })
    ));
    fs::remove_file(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    fs::create_dir(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    assert!(matches!(
        lock_project(&project.0),
        Err(ProjectOperationError::LockNonRegular)
    ));
    fs::remove_dir(project.0.join(lock::LOCK_FILE_NAME)).unwrap();

    project.write("target", "not a lock\n");
    symlink("target", project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    assert!(matches!(
        lock_project(&project.0),
        Err(ProjectOperationError::LockSymlink)
    ));
    fs::remove_file(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    fs::hard_link(
        project.0.join("target"),
        project.0.join(lock::LOCK_FILE_NAME),
    )
    .unwrap();
    assert!(matches!(
        lock_project(&project.0),
        Err(ProjectOperationError::LockHardLinked)
    ));
}

#[test]
fn lock_failure_before_rename_preserves_the_previous_bytes() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 1; }",
    );
    lock_project(&project.0).unwrap();
    let previous = fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 2; }",
    );
    crate::platform::linux::fd::fail_next_lock_before_rename();

    let error = lock_project(&project.0).unwrap_err();

    assert!(matches!(
        error,
        ProjectOperationError::LockPublication(LockPublicationError::BeforeRename { .. })
    ));
    assert_eq!(
        fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap(),
        previous
    );
    assert_eq!(fs::read_dir(&project.0).unwrap().count(), 2);
}

#[test]
fn graph_lock_failure_before_rename_preserves_the_whole_previous_manifest() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(child.join("main.srx"), "pub struct X {}").unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { child = \"path:../child\"; }",
    )
    .unwrap();
    lock_project(&child).unwrap();
    lock_project(&consumer).unwrap();
    let previous = fs::read(consumer.join(lock::LOCK_FILE_NAME)).unwrap();
    assert!(previous.starts_with(b"syrox-lock-v2\n"));
    assert!(!consumer.join("Syrox.graph.lock").exists());
    fs::write(
        child.join("main.srx"),
        "pub struct X {} // changed",
    )
    .unwrap();
    lock_project(&child).unwrap();
    crate::platform::linux::fd::fail_next_lock_before_rename();
    assert!(matches!(
        lock_project(&consumer),
        Err(ProjectOperationError::LockPublication(
            LockPublicationError::BeforeRename { .. }
        ))
    ));
    assert_eq!(
        fs::read(consumer.join(lock::LOCK_FILE_NAME)).unwrap(),
        previous
    );
    assert!(!consumer.join("Syrox.graph.lock").exists());
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::GraphDrift)
    ));
    lock_project(&consumer).unwrap();
    check_project_lock(&consumer).unwrap();
}

#[test]
fn legacy_sidecar_requires_relock_and_is_removed_after_single_manifest_publication() {
    let workspace = TempProject::new();
    let child = workspace.0.join("child");
    let consumer = workspace.0.join("consumer");
    fs::create_dir(&child).unwrap();
    fs::create_dir(&consumer).unwrap();
    fs::write(child.join("main.srx"), "pub struct X {}").unwrap();
    fs::write(
        consumer.join("main.srx"),
        "inputs { child = \"path:../child\"; }",
    )
    .unwrap();
    lock_project(&child).unwrap();
    lock_project(&consumer).unwrap();
    let current = fs::read(consumer.join(lock::LOCK_FILE_NAME)).unwrap();
    let expected = lock::graph::GraphLock::generate([0; 32], vec![]).unwrap();
    fs::write(consumer.join("Syrox.graph.lock"), expected.data()).unwrap();
    assert!(matches!(
        check_project_lock(&consumer),
        Err(ProjectOperationError::GraphDrift)
    ));
    assert!(matches!(
        lock_project(&consumer).unwrap().status(),
        lock::LockStatus::Updated
    ));
    assert!(!consumer.join("Syrox.graph.lock").exists());
    assert_eq!(
        fs::read(consumer.join(lock::LOCK_FILE_NAME)).unwrap(),
        current
    );
    check_project_lock(&consumer).unwrap();
}

#[test]
fn lock_failure_after_rename_reports_uncertainty_and_keeps_new_bytes() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 1; }",
    );
    lock_project(&project.0).unwrap();
    let previous = fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 2; }",
    );
    crate::platform::linux::fd::fail_next_lock_after_rename();

    let error = lock_project(&project.0).unwrap_err();

    assert!(matches!(
        error,
        ProjectOperationError::LockPublicationUncertain { .. }
    ));
    assert_ne!(
        fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap(),
        previous
    );
    check_project_lock(&project.0).unwrap();
    assert_eq!(fs::read_dir(&project.0).unwrap().count(), 2);
}

#[test]
fn lock_failure_preserves_the_primary_and_cleanup_sync_errors() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 1; }",
    );
    lock_project(&project.0).unwrap();
    let previous = fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 2; }",
    );
    crate::platform::linux::fd::fail_next_lock_before_rename();
    crate::platform::linux::fd::fail_next_lock_cleanup_sync();

    let error = lock_project(&project.0).unwrap_err();
    let ProjectOperationError::LockPublication(LockPublicationError::CleanupFailed {
        source,
        cleanup,
    }) = error
    else {
        panic!("expected primary and cleanup failures");
    };

    assert_eq!(
        source.to_string(),
        "injected lock failure before rename"
    );
    let LockCleanupError::Synchronization {
        source,
    } = cleanup
    else {
        panic!("expected cleanup synchronization failure");
    };
    assert_eq!(
        source.to_string(),
        "injected lock cleanup sync failure"
    );
    assert_eq!(
        fs::read(project.0.join(lock::LOCK_FILE_NAME)).unwrap(),
        previous
    );
    assert_eq!(fs::read_dir(&project.0).unwrap().count(), 2);
}

#[test]
fn plan_is_deterministic_and_projects_values() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); value Text(str); struct Pair { left: Number; right: [Text]; } outputs { pair: Pair = Pair { left = 7; right = [\"a\", \"b\"]; }; }",
    );
    lock_project(&project.0).unwrap();
    let first = value_projection_plan(&project.0, &CheckConfiguration::default())
        .unwrap()
        .to_string();
    let plan = value_projection_plan(&project.0, &CheckConfiguration::default()).unwrap();
    let second = plan.to_string();
    assert_eq!(first, second);
    assert_eq!(plan.policy_identity(), "syrox.empty");
    assert_eq!(plan.lock_digest().len(), 32);
    assert!(plan.standard_library().is_none());
    assert_eq!(plan.packages().len(), 0);
    assert!(first.contains("lock sha256 "));
    assert!(first.contains("policy syrox.empty"));
    assert!(first.contains("std absent"));
    assert!(first.contains("left = 0:Number(7)"));
    assert!(first.contains("right = [0:Text(\"a\"), 0:Text(\"b\")]"));
}

#[test]
fn plan_extracts_only_exact_authenticated_package_roots_with_explicit_ids() {
    let mut source = recipe_graph_source(&[
        ("root_name_is_not_the_id", "app", &[]),
        ("z", "z", &[]),
        ("library_root", "lib", &[]),
    ]);
    source.push_str(r#"
        value FakeId(str); struct FakeDependency { package: FakeId; }
        struct Package { id: FakeId; dependencies: [FakeDependency]; }
        mod fake { mod impostor { pub fn make() -> Package { Package { id = "ignored"; dependencies = []; } } } }
        pub publish(fake, make): Package;
    "#);
    let plan = package_plan(&source).unwrap();

    let packages: Vec<_> = plan.packages().collect();
    assert_eq!(
        packages
            .iter()
            .map(|package| package.id().as_str())
            .collect::<Vec<_>>(),
        ["app", "lib", "z"]
    );
    assert_eq!(
        packages[0]
            .dependencies()
            .map(crate::plan::PlanPackageId::as_str)
            .collect::<Vec<_>>(),
        [] as [&str; 0]
    );
    let display = plan.to_string();
    assert!(display.contains("syrox plan\n"));
    assert!(display.contains("package dependency graph\npackages 3 edges 0"));
    assert!(display.find("package \"lib\"").unwrap() < display.find("root ").unwrap());
}

#[test]
fn acquisition_roots_are_pure_explicit_and_multi_source() {
    let digest = "0".repeat(64);
    let text = format!(
        r#"
        mod catalog {{
            mod aggregate {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "aggregate"; dependencies = []; }}; }} }} }}
            mod app {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "app"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{
                sources = [
                    std::SourceRequest {{ url = "file:///tmp/pinned.tar"; sha256 = "{digest}"; maximum_bytes = 0; }},
                    std::SourceRequest {{ url = "https://example.org/pinned.tar"; sha256 = "{digest}"; maximum_bytes = 1024; }},
                ];
            }}); }} }} }}
        }} pub publish(catalog, recipe): std::Recipe;
    "#
    );
    let plan = package_plan(&text).unwrap();
    assert_eq!(plan.packages().len(), 2);
    let acquisition = plan.acquisitions().next().unwrap();
    assert_eq!(acquisition.package().as_str(), "app");
    assert_eq!(acquisition.sources().len(), 2);
    assert_eq!(
        acquisition
            .sources()
            .next()
            .unwrap()
            .maximum_bytes(),
        0
    );
    assert!(
        plan.to_string()
            .contains("acquisition \"app\" sources 2")
    );
}

#[test]
fn plan_refuses_unowned_and_invalid_source_requests() {
    let missing = package_plan(
        r"outputs {
        request: std::Acquisition = std::Acquisition { sources = []; };
    }",
    )
    .unwrap_err();
    assert!(matches!(
        missing,
        ProjectOperationError::InvalidConsumerOutput { .. }
    ));

    let invalid = package_plan(&format!(r#"mod published {{ mod package {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "app"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [
            std::SourceRequest {{ url = "http://example.org/plain"; sha256 = "{}"; maximum_bytes = 1; }}
        ]; }}); }} }} }} }} pub publish(published, recipe): std::Recipe;"#, "0".repeat(64))).unwrap_err();
    assert!(matches!(
        invalid,
        ProjectOperationError::Plan(crate::plan::PlanError::InvalidSourceRequest { .. })
    ));
    let local_project = TempProject::new();
    local_project.write("assets/runtime.tar.gz", "a");
    local_project.write("main.srx", &format!(r#"mod published {{ mod package {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "app"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [
            std::SourceRequest {{ url = "project:assets/runtime.tar.gz"; sha256 = "{}"; maximum_bytes = 2048; }}
        ]; }}); }} }} }} }} pub publish(published, recipe): std::Recipe;"#, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"));
    let configuration = package_configuration();
    lock_project_with(&local_project.0, &configuration).unwrap();
    let local = plan_project_with(&local_project.0, &configuration).unwrap();
    assert_eq!(
        local
            .acquisitions()
            .next()
            .unwrap()
            .sources()
            .next()
            .unwrap()
            .url(),
        "project:assets/runtime.tar.gz"
    );
    let traversal = package_plan(&format!(
        r#"mod published {{ mod package {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "app"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [
            std::SourceRequest {{ url = "project:../outside.tar.gz"; sha256 = "{}"; maximum_bytes = 2048; }}
        ]; }}); }} }} }} }} pub publish(published, recipe): std::Recipe;"#,
        "0".repeat(64)
    ));
    assert!(matches!(
        traversal,
        Err(ProjectOperationError::Plan(
            crate::plan::PlanError::InvalidSourceRequest { .. }
        ))
    ));
}

#[test]
fn input_domain_package_lookalike_is_not_extracted() {
    let project = TempProject::new();
    project.write("main.srx", "inputs { fake = \"path:fake\"; }");
    project.write(
        "fake/package.srx",
        "value Id(str); struct Dependency { package: Id; } struct Package { id: Id; dependencies: [Dependency]; } outputs { lookalike: Package = Package { id = \"ignored\"; dependencies = []; }; }",
    );
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(plan.packages().len(), 0);
}

fn build_fixture() -> String {
    format!(
        r#"mod catalog {{ mod app {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{
        package = std::Package {{ id = "internal-app"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [
            std::SourceRequest {{ url = "https://nonexistent.invalid/source"; sha256 = "{}"; maximum_bytes = 100; }}
        ]; }});
        build = std::Option::Some(std::autotools(std::BuildOptions {{
            source_directory = "app-1.0"; timeout_seconds = 30;
        }}));
        commands = [];
        }} }} }}
        mod aggregate {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "aggregate"; dependencies = []; }}; }} }} }}
        }}
        pub publish(catalog, recipe): std::Recipe;"#,
        "0".repeat(64)
    )
}

#[test]
fn recipe_build_projection_preserves_package_generality_and_public_selection() {
    let plan = package_plan(&build_fixture()).unwrap();
    assert_eq!(plan.builds().len(), 1);
    let build = plan.builds().next().unwrap();
    assert_eq!(build.package().as_str(), "internal-app");
    assert_eq!(build.source_directory(), "app-1.0");
    assert_eq!(
        plan.packages()
            .find(|package| package.id() == build.package())
            .unwrap()
            .export(),
        Some("app")
    );
    assert!(
        plan.to_string()
            .contains("build \"internal-app\" protocol program-v2")
    );
    // An ordinary project struct with the same spelling does not request a build.
    let lookalike = package_plan(
        "value Id(str); struct Build { package: Id; } outputs { fake: Build = Build { package = \"absent\"; }; }",
    );
    assert!(matches!(
        lookalike,
        Err(ProjectOperationError::InvalidConsumerOutput { .. })
    ));
}

#[test]
fn commands_project_names_outputs_paths_and_explicit_runtime_roles() {
    let command =
        r#"commands = [std::Command { name = "main"; output = "out"; path = "usr/bin/app"; }];"#;
    let source = build_fixture().replace("commands = [];", command);
    let plan = package_plan(&source).unwrap();
    let command = plan.commands().next().unwrap();
    assert_eq!(command.name(), "main");
    assert_eq!(command.output(), "out");
    assert_eq!(command.path(), "usr/bin/app");
    assert!(command.loader().is_none());
    for (from, to) in [
        (r#"name = "main""#, r#"name = "../escape""#),
        (r#"output = "out""#, r#"output = "missing""#),
        (
            r#"path = "usr/bin/app""#,
            r#"path = "/usr/bin/app""#,
        ),
        (
            r#"path = "usr/bin/app";"#,
            r#"path = "usr/bin/app"; libraries = [std::recipe_output(project::aggregate, "out")];"#,
        ),
    ] {
        assert!(matches!(
            package_plan(&source.replace(from, to)),
            Err(ProjectOperationError::Plan(
                crate::plan::PlanError::InvalidCommand { .. }
            ))
        ));
    }
    let self_library = source.replace(
        r#"path = "usr/bin/app";"#,
        r#"path = "usr/bin/app"; libraries = [std::recipe_output(project::app, "out")];"#,
    );
    assert_eq!(
        package_plan(&self_library)
            .unwrap()
            .commands()
            .next()
            .unwrap()
            .libraries()
            .len(),
        1
    );
    let multiple = source.replace(r#"path = "usr/bin/app"; }];"#, r#"path = "usr/bin/app"; }, std::Command { name = "admin"; output = "out"; path = "usr/bin/admin"; }];"#);
    assert_eq!(
        package_plan(&multiple).unwrap().commands().len(),
        2
    );
    assert!(package_plan(&multiple.replace(r#"name = "admin""#, r#"name = "main""#)).is_err());
}

#[test]
fn cancelled_realization_has_no_store_or_host_effects() {
    let project = TempProject::new();
    project.write("main.srx", &build_fixture());
    let checks = package_configuration();
    lock_project_with(&project.0, &checks).unwrap();
    let store = project.0.join("not-created");
    let user =
        crate::config::UserConfiguration::parse("[build]\nhost-toolchain='/usr'", store.clone())
            .unwrap();
    let selected = crate::realize::resolve_build(
        &format!("{}#app", project.0.display()),
        &user,
        &checks,
    )
    .unwrap();
    let cancellation = crate::cancellation::Cancellation::default();
    cancellation.cancel();
    let result = crate::realize::realize_build(
        &selected,
        crate::realize::RealizeOptions {
            configuration: &user,
            worker: Path::new("/absent-worker"),
            offline: true,
        },
        &cancellation,
        |_| panic!("no progress after pre-cancellation"),
    );
    assert!(matches!(
        result,
        Err(crate::realize::RealizeError::Cancelled)
    ));
    assert!(!store.exists());
}

#[test]
fn invalid_build_relationships_and_paths_fail_during_pure_planning() {
    for (from, to) in [
        (
            "source_directory = \"app-1.0\"",
            "source_directory = \"../escape\"",
        ),
        ("timeout_seconds = 30", "timeout_seconds = 1801"),
    ] {
        // Only replace the first package's dependencies; avoid an unrelated cycle.
        let text = build_fixture().replacen(from, to, 1);
        assert!(
            matches!(
                package_plan(&text),
                Err(ProjectOperationError::Plan(
                    crate::plan::PlanError::InvalidBuild { .. }
                ))
            ),
            "{text}"
        );
    }
}

#[test]
fn authenticated_input_factory_flows_through_lock_check_and_plan() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        inputs { catalog = "path:catalog"; }
        mod published { mod package { pub fn recipe() -> std::Recipe { std::Recipe { package = catalog::zlib(); } } } } pub publish(published, recipe): std::Recipe;
        "#,
    );
    project.write(
        "catalog/package.srx",
        r#"
        fn make_zlib() -> std::Package {
            std::Package { id = "zlib"; dependencies = []; }
        }
        outputs { zlib: fn() -> std::Package = make_zlib; }
        "#,
    );
    let configuration = package_configuration();

    lock_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        check_project_lock_with(&project.0, &configuration)
            .unwrap()
            .status(),
        lock::LockStatus::Unchanged
    );
    let plan = plan_project_with(&project.0, &configuration).unwrap();
    assert_eq!(
        plan.packages()
            .map(|package| package.id().as_str())
            .collect::<Vec<_>>(),
        ["zlib"]
    );
}

#[test]
fn package_graph_errors_are_structured_and_deterministic() {
    let homonyms = package_plan(&recipe_graph_source(&[
        ("z", "same", &[]),
        ("a", "same", &[]),
    ]))
    .unwrap();
    assert_eq!(homonyms.packages().len(), 2);
    assert_ne!(
        homonyms.packages().next().unwrap().id(),
        homonyms.packages().last().unwrap().id()
    );

    let duplicate_edge = package_plan(&recipe_graph_source(&[
        ("app", "app", &["lib", "lib"]),
        ("lib", "lib", &[]),
    ]))
    .unwrap_err();
    assert!(matches!(
        duplicate_edge,
        ProjectOperationError::Plan(crate::plan::PlanError::DuplicateDependency {
            ref package,
            ref dependency,
        }) if package.as_str() == "app" && dependency.as_str() == "lib"
    ));

    let missing_source = recipe_graph_source(&[("app", "app", &["missing"])]).replace(
        "mod catalog {",
        "mod catalog { mod missing { pub fn recipe() -> std::Recipe { recipe() } }",
    );
    let missing = package_plan(&missing_source).unwrap_err();
    assert!(matches!(
        missing,
        ProjectOperationError::Check(CheckFailure::Evaluation { .. })
    ));
}

#[test]
fn package_ids_and_cycle_witnesses_are_canonical() {
    let invalid_ids = [
        String::new(),
        "Upper".to_owned(),
        "a/b".to_owned(),
        "é".to_owned(),
        "a".repeat(256),
    ];
    for invalid in invalid_ids {
        let source = recipe_graph_source(&[("p", &invalid, &[])]);
        assert!(matches!(
            package_plan(&source),
            Err(ProjectOperationError::Plan(
                crate::plan::PlanError::InvalidPackageId { .. }
            ))
        ));
    }

    let self_cycle = package_plan(&recipe_graph_source(&[(
        "self_node",
        "self",
        &["self_node"],
    )]))
    .unwrap_err();
    assert!(matches!(
        self_cycle,
        ProjectOperationError::Plan(crate::plan::PlanError::Cycle { ref packages })
            if packages.iter().map(crate::plan::PlanPackageId::as_str).collect::<Vec<_>>() == ["self"]
    ));

    let cycle = package_plan(&recipe_graph_source(&[
        ("c", "c", &["b"]),
        ("a", "a", &["c"]),
        ("b", "b", &["a"]),
    ]))
    .unwrap_err();
    assert!(matches!(
        cycle,
        ProjectOperationError::Plan(crate::plan::PlanError::Cycle { ref packages })
            if packages.iter().map(crate::plan::PlanPackageId::as_str).collect::<Vec<_>>() == ["a", "c", "b"]
    ));
}

#[test]
fn reference_package_chain_is_planned_iteratively() {
    let names: Vec<_> = (0..512)
        .map(|index| format!("p{index}"))
        .collect();
    let nodes: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let dependencies: Vec<&str> = if index == 0 {
                Vec::new()
            } else {
                vec![names[index - 1].as_str()]
            };
            (name.as_str(), name.as_str(), dependencies)
        })
        .collect();
    let borrowed: Vec<_> = nodes
        .iter()
        .map(|(name, id, dependencies)| (*name, *id, dependencies.as_slice()))
        .collect();
    let source = recipe_graph_source(&borrowed);
    let plan = package_plan(&source).unwrap();
    assert_eq!(plan.packages().len(), 512);
    assert_eq!(
        plan.packages().next().unwrap().id().as_str(),
        "p0"
    );
    assert_eq!(
        plan.packages().last().unwrap().id().as_str(),
        "p511"
    );
}

#[test]
fn plan_carries_authenticated_standard_library_provenance() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value Number(int); outputs { answer: Number = 42; }",
    );
    let source =
        AuthenticatedStandardSource::from_authenticated("std.srx", "value Std(str);").unwrap();
    let library = AuthenticatedStandardLibrary::from_authenticated(vec![source]).unwrap();
    let configuration = CheckConfiguration {
        standard_library: Some(library.clone()),
        ..CheckConfiguration::default()
    };

    lock_project_with(&project.0, &configuration).unwrap();
    let plan = value_projection_plan(&project.0, &configuration).unwrap();
    let standard = plan.standard_library().unwrap();
    assert_eq!(standard.digest(), library.digest());
    assert!(plan.to_string().contains("std sha256 "));
}

#[test]
fn lock_io_stays_relative_to_retained_root_after_path_swap() {
    let project = TempProject::new();
    project.write("main.srx", "value Number(int);");
    let loaded = loader::load_project_linux(&project.0, &CheckConfiguration::default()).unwrap();
    let moved = project.0.with_extension("opened");
    fs::rename(&project.0, &moved).unwrap();
    fs::create_dir(&project.0).unwrap();

    crate::platform::linux::fd::write_atomic_beneath(
        loaded.root.fd(),
        Path::new(lock::LOCK_FILE_NAME),
        b"retained\n",
    )
    .unwrap();
    assert_eq!(
        fs::read(moved.join(lock::LOCK_FILE_NAME)).unwrap(),
        b"retained\n"
    );
    assert!(!project.0.join(lock::LOCK_FILE_NAME).exists());

    fs::remove_dir(&project.0).unwrap();
    fs::rename(moved, &project.0).unwrap();
}

#[test]
fn explicit_selection_rejects_unpublished_packages_and_non_consumers_before_evaluation() {
    let project = TempProject::new();
    project.write("main.srx", "value Number(int); fn forever() -> Number { forever() } outputs { invalid: Number = forever(); }");
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    assert!(matches!(
        plan_project_with(&project.0, &config),
        Err(ProjectOperationError::InvalidConsumerOutput { .. })
    ));
    assert!(matches!(
        plan_project_outputs_with(&project.0, &config, &["invalid"]),
        Err(ProjectOperationError::InvalidConsumerOutput { .. })
    ));
    assert!(matches!(
        plan_project_package_with(&project.0, &config, "invalid"),
        Err(ProjectOperationError::MissingPackageReference { .. })
    ));
}

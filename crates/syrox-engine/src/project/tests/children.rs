use super::*;

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
            .starts_with(b"syrox-lock\n")
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

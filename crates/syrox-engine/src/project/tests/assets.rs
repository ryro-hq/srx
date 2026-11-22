use super::*;

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
            .starts_with(b"syrox-lock\n")
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

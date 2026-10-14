use super::*;
use syrox_lang::{analysis::AnalysisCancellation, checker::Ty, diagnostic::DiagnosticCode};

#[test]
fn publication_invalidation_crosses_factory_signatures_imports_and_reexports() {
    let workspace = TempProject::new();
    let config = package_configuration();
    let factory = r#"pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = "one"; dependencies = []; }; } }"#;
    workspace.write("catalog/collection/factories/one.srx", factory);
    workspace.write(
        "catalog/collection/factories/two.srx",
        &factory.replace("\"one\"", "\"two\""),
    );
    workspace.write(
        "catalog/collection/item.srx",
        "pub use factories::one::recipe;",
    );
    workspace.write(
        "catalog/main.srx",
        r#"inputs { recipes = "modules:collection"; } pub publish(recipes, recipe): std::Recipe;"#,
    );
    lock_project_with(&workspace.0.join("catalog"), &config).unwrap();
    workspace.write(
        "facade/main.srx",
        r#"inputs { catalog = "path:../catalog"; } pub use catalog::item;"#,
    );
    lock_project_with(&workspace.0.join("facade"), &config).unwrap();
    let consumer = r#"inputs { facade = "path:../facade"; } outputs { selected: std::Recipe = std::recipe_value(facade::item); }"#;
    workspace.write("consumer/main.srx", consumer);
    let mut editor = open_project_analysis_with(&workspace.0.join("consumer"), &config).unwrap();
    let snapshot = editor.snapshot();
    let source = |suffix: &str| {
        *snapshot
            .source_paths()
            .iter()
            .find(|(_, path)| path.ends_with(suffix))
            .unwrap()
            .0
    };
    let main = source("consumer/main.srx");
    let one = source("factories/one.srx");
    let two = source("factories/two.srx");
    let reexport = source("collection/item.srx");
    let facade = source("facade/main.srx");
    let position = u32::try_from(consumer.rfind("item").unwrap()).unwrap();
    let cancellation = AnalysisCancellation::default();
    let original = snapshot.analyze(&cancellation).unwrap();
    assert!(
        original.diagnostics().is_empty(),
        "{:?}",
        original.diagnostics()
    );
    assert_eq!(
        original
            .definition_at(main, position)
            .unwrap()
            .source_id(),
        one
    );
    for (id, text) in [
        (one, factory.replace("id = \"one\"", "id = 1")),
        (one, "pub fn recipe() -> std::Package { std::Package { id = \"changed\"; dependencies = []; } }".into()),
        (reexport, "pub use factories::two::recipe;".into()),
        (facade, "inputs { catalog = \"path:../catalog\"; } pub use catalog::absent;".into()),
    ] {
        editor.set_overlay(id, 1, &text).unwrap();
        let warm = editor.snapshot().analyze(&cancellation).unwrap();
        let mut cold_editor = open_project_analysis_with(&workspace.0.join("consumer"), &config).unwrap();
        cold_editor.set_overlay(id, 1, &text).unwrap();
        let cold = cold_editor.snapshot().analyze(&cancellation).unwrap();
        assert_eq!(warm.diagnostics(), cold.diagnostics());
        assert_eq!(warm.definition_at(main, position), cold.definition_at(main, position));
        if id == reexport {
            assert!(warm.diagnostics().is_empty(), "{:?}", warm.diagnostics());
            assert_eq!(warm.definition_at(main, position).unwrap().source_id(), two);
        } else { assert!(!warm.diagnostics().is_empty()); }
        assert!(original.diagnostics().is_empty());
        assert_eq!(original.definition_at(main, position).unwrap().source_id(), one);
        editor.close_overlay(id).unwrap();
    }
}

#[test]
fn project_completion_in_imported_modules_keeps_its_owner_after_publication_changes() {
    let workspace = TempProject::new();
    let config = package_configuration();
    for name in ["left", "right"] {
        workspace.write(
            &format!("{name}/main.srx"),
            r#"
            inputs { recipes = "modules:recipes"; }
            pub publish(recipes, recipe): std::Recipe;
        "#,
        );
        workspace.write(
            &format!("{name}/recipes/only_{name}.srx"),
            &format!(
                "pub fn recipe() -> std::Recipe {{ std::recipe_value(project::only_{name}) }}"
            ),
        );
        lock_project_with(&workspace.0.join(name), &config).unwrap();
    }
    workspace.write(
        "consumer/main.srx",
        r#"
        inputs { left = "path:../left"; right = "path:../right"; }
        outputs { consumer_only: std::RecipeRef<std::Recipe> = left::only_left; }
    "#,
    );
    let mut editor = open_project_analysis_with(&workspace.0.join("consumer"), &config).unwrap();
    let snapshot = editor.snapshot();
    let cancellation = AnalysisCancellation::default();
    let original = snapshot.analyze(&cancellation).unwrap();
    assert!(
        original.diagnostics().is_empty(),
        "{:?}",
        original.diagnostics()
    );
    for name in ["left", "right"] {
        let (source, file) = snapshot
            .sources()
            .iter()
            .find(|(_, file)| file.name().ends_with(&format!("only_{name}.srx")))
            .unwrap();
        let offset =
            u32::try_from(file.text().find("project::").unwrap() + "project::".len()).unwrap();
        let completions = original.complete_path(source, offset, &["project".into()], "");
        assert!(
            completions
                .iter()
                .any(|(label, _)| label == &format!("only_{name}"))
        );
        assert!(
            !completions
                .iter()
                .any(|(label, _)| label == "consumer_only"
                    || label
                        == if name == "left" {
                            "only_right"
                        } else {
                            "only_left"
                        })
        );
        editor
            .set_overlay(
                source,
                1,
                &file
                    .text()
                    .replace("pub fn recipe", "pub fn renamed"),
            )
            .unwrap();
        let changed = editor.snapshot().analyze(&cancellation).unwrap();
        assert!(
            !changed
                .complete_path(source, offset, &["project".into()], "")
                .iter()
                .any(|(label, _)| label == &format!("only_{name}"))
        );
        assert!(
            original
                .complete_path(source, offset, &["project".into()], "")
                .iter()
                .any(|(label, _)| label == &format!("only_{name}"))
        );
        editor.close_overlay(source).unwrap();
    }
}

#[test]
fn standard_library_authoring_loads_all_files_and_maps_physical_definitions() {
    let workspace = TempProject::new();
    let standard = AuthenticatedStandardLibrary::bundled();
    for source in standard.sources() {
        workspace.write(source.name(), source.text());
    }
    let config = CheckConfiguration {
        standard_library: Some(standard.clone()),
        ..CheckConfiguration::default()
    };
    let mut editor =
        open_standard_library_analysis_with(&workspace.0.join("std"), &config).unwrap();
    let snapshot = editor.snapshot();
    assert_eq!(snapshot.sources().len(), standard.sources().len());
    assert_eq!(
        snapshot.source_paths().len(),
        snapshot.sources().len()
    );
    assert_eq!(
        snapshot.lock_status(),
        ProjectAnalysisLockStatus::Unchecked
    );
    let cancel = AnalysisCancellation::default();
    let result = snapshot.analyze(&cancel).unwrap();
    assert!(
        result.diagnostics().is_empty(),
        "{:?}",
        result.diagnostics()
    );
    let main = snapshot
        .sources()
        .iter()
        .find(|(_, source)| source.name().ends_with("/main.srx"))
        .unwrap();
    let offset = u32::try_from(main.1.text().find("PackageId").unwrap()).unwrap();
    let definition = result.definition_at(main.0, offset).unwrap();
    assert!(snapshot.source_paths()[&definition.source_id()].ends_with("std/package.srx"));
    let package = snapshot
        .sources()
        .get(definition.source_id())
        .unwrap();
    editor
        .set_overlay(
            definition.source_id(),
            1,
            &package
                .text()
                .replace("mod std::pkg", "mod std::other"),
        )
        .unwrap();
    let changed = editor.snapshot().analyze(&cancel).unwrap();
    assert!(
        changed
            .diagnostics()
            .iter()
            .any(|error| error.span.source_id() == main.0)
    );
    assert!(result.diagnostics().is_empty());
    editor
        .close_overlay(definition.source_id())
        .unwrap();
    assert!(
        editor
            .snapshot()
            .analyze(&cancel)
            .unwrap()
            .diagnostics()
            .is_empty()
    );
    // An ordinary project still does not promote local disk files to std.
    let ordinary = open_project_analysis_with(&workspace.0.join("std"), &config).unwrap();
    assert!(
        !ordinary
            .snapshot()
            .analyze(&cancel)
            .unwrap()
            .diagnostics()
            .is_empty()
    );
}

#[test]
fn content_equivalent_revisions_reuse_semantics_with_fresh_publication_stamps() {
    let project = TempProject::new();
    let text = "value I(int); fn run() -> I { I(1) }";
    project.write("main.srx", text);
    let mut editor =
        open_project_analysis_with(&project.0, &CheckConfiguration::default()).unwrap();
    let first_snapshot = editor.snapshot();
    let id = first_snapshot.sources().iter().next().unwrap().0;
    // Reuse must also work when the old snapshot finishes after the input update.
    editor.set_overlay(id, 1, text).unwrap();
    let cancellation = AnalysisCancellation::default();
    let first = first_snapshot.analyze(&cancellation).unwrap();
    let next = editor.snapshot().analyze(&cancellation).unwrap();
    assert_ne!(first.revision(), next.revision());
    assert!(!editor.is_current(&first.revision()));
    assert!(editor.is_current(&next.revision()));
    assert!(std::ptr::eq(first.sources(), next.sources()));
    assert!(std::sync::Arc::ptr_eq(
        &next,
        &editor.snapshot().analyze(&cancellation).unwrap()
    ));
    editor.set_overlay(id, 2, text).unwrap();
    editor.set_overlay(id, 3, text).unwrap();
    let unchanged = editor.snapshot().analyze(&cancellation).unwrap();
    assert!(std::ptr::eq(first.sources(), unchanged.sources()));
    editor.close_overlay(id).unwrap();
    let closed = editor.snapshot().analyze(&cancellation).unwrap();
    assert!(std::ptr::eq(first.sources(), closed.sources()));
    editor
        .set_overlay(id, 1, "value I(int); fn run() -> I { missing() }")
        .unwrap();
    let changed = editor.snapshot().analyze(&cancellation).unwrap();
    assert!(!changed.diagnostics().is_empty());
    assert!(!std::ptr::eq(first.sources(), changed.sources()));
    assert!(first.diagnostics().is_empty());
    cancellation.cancel();
    assert!(editor.snapshot().analyze(&cancellation).is_err());
}

#[test]
fn editor_maps_homonymous_child_modules_to_their_physical_files() {
    let workspace = TempProject::new();
    let config = CheckConfiguration::default();
    for name in ["left", "right"] {
        workspace.write(
            &format!("{name}/main.srx"),
            "inputs { lib = \"modules:recipes\"; } pub fn call() { lib::one::run(); }",
        );
        workspace.write(
            &format!("{name}/recipes/one.srx"),
            "pub fn run() {}",
        );
        lock_project_with(&workspace.0.join(name), &config).unwrap();
    }
    workspace.write("consumer/main.srx", "inputs { left = \"path:../left\"; right = \"path:../right\"; } fn run() { left::call(); right::call(); }");
    let editor = open_project_analysis_with(&workspace.0.join("consumer"), &config).unwrap();
    let snapshot = editor.snapshot();
    let modules: Vec<_> = snapshot
        .sources()
        .iter()
        .filter(|(_, source)| source.name() == "lib/one.srx")
        .map(|(id, _)| id)
        .collect();
    assert_eq!(modules.len(), 2);
    let paths: std::collections::BTreeSet<_> = modules
        .iter()
        .map(|id| fs::canonicalize(&snapshot.source_paths()[id]).unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            workspace.0.join("left/recipes/one.srx"),
            workspace.0.join("right/recipes/one.srx")
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn editor_uses_loaded_module_and_std_domains_with_incomplete_imported_bodies() {
    let project = TempProject::new();
    let main_text = "inputs { recipes = \"modules:recipes\"; } fn good() -> std::Package { recipes::one::recipe() }";
    project.write("main.srx", main_text);
    // A recursive factory must remain dormant during every editor query.
    project.write(
        "recipes/one.srx",
        "pub fn recipe() -> std::Package { recipe() }",
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let mut editor = open_project_analysis_with(&project.0, &config).unwrap();
    let before = editor.snapshot();
    assert_eq!(
        before.lock_status(),
        ProjectAnalysisLockStatus::Current
    );
    let main = before
        .sources()
        .iter()
        .find(|(_, source)| source.text() == main_text)
        .unwrap()
        .0;
    let recipe = before
        .sources()
        .iter()
        .find(|(_, source)| source.name().ends_with("one.srx"))
        .unwrap()
        .0;
    let cancellation = AnalysisCancellation::default();
    let result = before.analyze(&cancellation).unwrap();
    assert!(
        result.diagnostics().is_empty(),
        "{:?}",
        result.diagnostics()
    );
    assert!(std::sync::Arc::ptr_eq(
        &result,
        &before.analyze(&cancellation).unwrap()
    ));
    let offset = u32::try_from(main_text.find("recipes::one::recipe").unwrap()).unwrap();
    assert_eq!(
        result
            .definition_at(main, offset)
            .unwrap()
            .source_id(),
        recipe
    );
    editor
        .set_overlay(
            recipe,
            1,
            "pub fn recipe() -> std::Package { std::Package { id = ; dependencies = []; } }",
        )
        .unwrap();
    let edited = editor.snapshot().analyze(&cancellation).unwrap();
    assert!(
        edited
            .diagnostics()
            .iter()
            .any(|error| error.span.source_id() == recipe
                && error.code == DiagnosticCode::ExpectedExpression)
    );
    assert!(!editor.is_current(&result.revision()));
    assert!(result.diagnostics().is_empty());
    let good = edited
        .items()
        .find(|item| item.path().segments() == ["good"])
        .unwrap();
    assert!(
        matches!(edited.function_type(good.id()), Some(Ty::Function { result, .. }) if matches!(**result, Ty::Nominal(_)))
    );
    editor.close_overlay(recipe).unwrap();
    assert!(
        editor
            .snapshot()
            .analyze(&cancellation)
            .unwrap()
            .diagnostics()
            .is_empty()
    );
    assert!(check_project_lock_with(&project.0, &config).is_ok());
}

#[test]
fn root_lock_drift_does_not_prevent_editor_queries_or_make_execution_current() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        "value I(int); fn good() -> I { I(1) }",
    );
    let config = CheckConfiguration::default();
    let editor = open_project_analysis_with(&project.0, &config).unwrap();
    assert_eq!(
        editor.snapshot().lock_status(),
        ProjectAnalysisLockStatus::Missing
    );
    lock_project_with(&project.0, &config).unwrap();
    project.write(
        "main.srx",
        "value I(int); fn good() -> I { I(2) }",
    );
    let editor = open_project_analysis_with(&project.0, &config).unwrap();
    assert_eq!(
        editor.snapshot().lock_status(),
        ProjectAnalysisLockStatus::Drift
    );
    assert!(
        editor
            .snapshot()
            .analyze(&AnalysisCancellation::default())
            .unwrap()
            .diagnostics()
            .is_empty()
    );
    assert!(open_locked_project_with(&project.0, &config).is_err());
}

#[test]
fn input_edits_require_topology_reload_and_cached_queries_honor_cancellation() {
    let project = TempProject::new();
    let text = "inputs { dep = \"path:dep\"; } fn good() { dep::call(); }";
    project.write("main.srx", text);
    project.write("dep/main.srx", "pub fn call() {}");
    let config = CheckConfiguration::default();
    let mut editor = open_project_analysis_with(&project.0, &config).unwrap();
    let initial = editor.snapshot();
    let id = initial
        .sources()
        .iter()
        .find(|(_, source)| source.text() == text)
        .unwrap()
        .0;
    let cancellation = AnalysisCancellation::default();
    assert!(
        initial
            .analyze(&cancellation)
            .unwrap()
            .diagnostics()
            .is_empty()
    );
    editor
        .set_overlay(id, 1, &text.replace("path:dep", "path:other"))
        .unwrap();
    assert!(matches!(
        editor.snapshot().analyze(&cancellation),
        Err(ProjectAnalysisError::TopologyChanged)
    ));
    assert!(
        editor
            .snapshot()
            .document(id)
            .unwrap()
            .parsed(&cancellation)
            .is_ok()
    );
    editor
        .set_overlay(id, 2, "inputs { dep = ")
        .unwrap();
    assert!(matches!(
        editor.snapshot().analyze(&cancellation),
        Err(ProjectAnalysisError::TopologyChanged)
    ));
    cancellation.cancel();
    assert!(matches!(
        initial.analyze(&cancellation),
        Err(ProjectAnalysisError::Cancelled(_))
    ));
}

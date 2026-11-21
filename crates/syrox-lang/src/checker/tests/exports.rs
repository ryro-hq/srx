use super::*;

#[test]
fn public_type_and_function_are_exported_without_an_outputs_block() {
    let mut sources = SourceSet::new();
    sources
        .add(
            "main.srx",
            r#"inputs { dep = "path:dep"; }
        outputs { result: dep::Box<dep::Item> = dep::make(); }"#,
        )
        .unwrap();
    let input = sources.create_input_domain("dep").unwrap();
    sources
        .add_to_input_domain(
            input,
            "dep/lib.srx",
            r"
        pub struct Item {}
        pub struct Box<T> { item: T; }
        pub fn make() -> Box<Item> { Box<Item> { item = Item {}; } }
    ",
        )
        .unwrap();
    check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap();
}

#[test]
fn public_declarations_cannot_repeat_explicit_exports() {
    let mut sources = SourceSet::new();
    sources.add("main.srx", "pub fn make() -> Item { Item {} } struct Item {} outputs { make: fn() -> Item = make; }").unwrap();
    assert!(
        resolve(parse_sources(&sources).unwrap())
            .unwrap_err()
            .iter()
            .any(|error| error.message.contains("duplicate output name"))
    );
}

#[test]
fn public_import_reexports_the_original_item_identity() {
    let mut sources = SourceSet::new();
    sources
        .add(
            "main.srx",
            r#"inputs { dep = "path:dep"; }
        mod facade { pub use dep::Item; }
        outputs { result: facade::Item = dep::Item {}; }"#,
        )
        .unwrap();
    let dep = sources.create_input_domain("dep").unwrap();
    sources
        .add_to_input_domain(dep, "dep/item.srx", "pub struct Item {}")
        .unwrap();
    check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap();
}

#[test]
fn module_exports_require_concrete_public_function_signatures_and_reusable_mappers() {
    for (declarations, mapper, expected) in [
        (
            "value Key(str); value I(int); mod collection { pub fn make() -> I { I(1) } }",
            "once fn(key: Key, make: fn() -> I) -> Key { key }",
            "module mapper must be a reusable function",
        ),
        (
            "resource Key(str); value I(int); mod collection { pub fn make() -> I { I(1) } }",
            "fn(key: Key, make: fn() -> I) -> Key { key }",
            "module key must be a reusable value(str)",
        ),
        (
            "value Key(str); value I(int); mod collection { pub fn make<T>(item: T) -> T { item } }",
            "fn(key: Key, make: fn() -> I) -> Key { key }",
            "requires explicit generic specialization",
        ),
        (
            "value Key(str); value I(int); mod collection { pub fn make(item: I) -> I { item } }",
            "fn(key: Key, make: fn() -> I) -> Key { key }",
            "module export `` type mismatch",
        ),
    ] {
        let source = format!(
            "{declarations} outputs {{ keys: [Key] = module_exports(collection, make, {mapper}); }}"
        );
        let errors = messages(&source);
        assert!(
            errors
                .iter()
                .any(|message| message.contains(expected)),
            "{errors:?}"
        );
    }
}

#[test]
fn imported_projects_resolve_their_own_input_aliases() {
    let mut sources = SourceSet::new();
    sources
        .add(
            "consumer/main.srx",
            r#"inputs { pkgs = "path:../pkgs"; recipes = "path:local"; }
        outputs { from_child: pkgs::X = pkgs::get(); from_local: recipes::X = recipes::make(); }"#,
        )
        .unwrap();
    let child = sources
        .create_project_domain(SourceDomainId::project(), "pkgs")
        .unwrap();
    sources
        .add_to_project_domain(
            child,
            "pkgs/main.srx",
            r#"inputs { recipes = "path:recipes"; }
        pub type X = recipes::X; pub fn get() -> X { recipes::make() }"#,
        )
        .unwrap();
    let child_recipes = sources
        .create_child_input_domain(child, "recipes")
        .unwrap();
    sources
        .add_to_input_domain(
            child_recipes,
            "pkgs/recipes/item.srx",
            "pub struct X {} pub fn make() -> X { X {} }",
        )
        .unwrap();
    let local = sources.create_input_domain("recipes").unwrap();
    sources
        .add_to_input_domain(
            local,
            "consumer/local/item.srx",
            "pub struct X {} pub fn make() -> X { X {} }",
        )
        .unwrap();
    let checked = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap();
    let policy = CheckPolicy::default();
    let result = crate::evaluator::evaluate(
        &checked,
        &policy,
        &crate::evaluator::EvaluationEnvironment::new(&policy),
    )
    .unwrap();
    assert_eq!(result.roots().count(), 2);
    assert!(result.is_success());

    let mut isolated = SourceSet::new();
    isolated
        .add(
            "consumer/main.srx",
            "inputs { pkgs = \"path:../pkgs\"; recipes = \"path:local\"; }",
        )
        .unwrap();
    let child = isolated
        .create_project_domain(SourceDomainId::project(), "pkgs")
        .unwrap();
    isolated
        .add_to_project_domain(
            child,
            "pkgs/main.srx",
            "pub fn bad(x: recipes::X) -> recipes::X { x }",
        )
        .unwrap();
    let local = isolated.create_input_domain("recipes").unwrap();
    isolated
        .add_to_input_domain(
            local,
            "consumer/local/item.srx",
            "pub struct X {}",
        )
        .unwrap();
    assert!(
        resolve(parse_sources(&isolated).unwrap())
            .unwrap_err()
            .iter()
            .any(|error| error.message.contains("unknown type"))
    );
}

#[test]
fn imported_project_value_outputs_are_checked_and_realized_on_reference() {
    let mut sources = SourceSet::new();
    sources
        .add(
            "consumer/main.srx",
            "inputs { dep = \"path:child\"; } outputs { selected: dep::X = dep::selected; }",
        )
        .unwrap();
    let child = sources
        .create_project_domain(SourceDomainId::project(), "dep")
        .unwrap();
    sources.add_to_project_domain(child, "child/main.srx", "pub struct X {} fn forever() -> X { forever() } outputs { selected: X = X {}; disconnected: X = forever(); }").unwrap();
    let policy = CheckPolicy::default();
    let checked = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &policy,
    )
    .unwrap();
    let result = crate::evaluator::evaluate(
        &checked,
        &policy,
        &crate::evaluator::EvaluationEnvironment::new(&policy),
    )
    .unwrap();
    assert_eq!(result.roots().count(), 1);
    assert!(result.is_success());

    let mut cyclic = SourceSet::new();
    cyclic
        .add(
            "consumer/main.srx",
            "inputs { dep = \"path:child\"; } outputs { selected: dep::X = dep::a; }",
        )
        .unwrap();
    let child = cyclic
        .create_project_domain(SourceDomainId::project(), "dep")
        .unwrap();
    cyclic
        .add_to_project_domain(
            child,
            "child/main.srx",
            "pub struct X {} outputs { a: X = b; b: X = a; }",
        )
        .unwrap();
    let checked = check(
        resolve(parse_sources(&cyclic).unwrap()).unwrap(),
        &policy,
    )
    .unwrap();
    let result = crate::evaluator::evaluate(
        &checked,
        &policy,
        &crate::evaluator::EvaluationEnvironment::new(&policy),
    )
    .unwrap();
    assert!(result.diagnostics().any(|error| {
        error
            .message
            .contains("cycle in imported value outputs")
    }));
    let mut affine = SourceSet::new();
    affine
        .add(
            "consumer/main.srx",
            "inputs { dep = \"path:child\"; } outputs { selected: dep::R = dep::port; }",
        )
        .unwrap();
    let child = affine
        .create_project_domain(SourceDomainId::project(), "dep")
        .unwrap();
    affine
        .add_to_project_domain(
            child,
            "child/main.srx",
            "pub resource R(int); outputs { port: R = R(1); }",
        )
        .unwrap();
    assert!(
        check(
            resolve(parse_sources(&affine).unwrap()).unwrap(),
            &policy
        )
        .unwrap_err()
        .iter()
        .any(|error| error
            .message
            .contains("imported value output cannot carry an affine resource"))
    );
}

#[test]
fn public_import_conflicts_with_a_repeated_output_export() {
    let mut sources = SourceSet::new();
    sources.add("main.srx", "mod base { struct Item {} outputs { type Item = Item; } } mod facade { pub use base::Item; outputs { type Item = base::Item; } }").unwrap();
    let errors = resolve(parse_sources(&sources).unwrap()).unwrap_err();
    assert!(
        errors.iter().any(|error| error
            .message
            .contains("public import conflicts with an export")),
        "{errors:?}"
    );
}

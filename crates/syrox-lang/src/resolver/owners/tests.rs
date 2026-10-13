use super::*;
use crate::{source::SourceSet, syntax::ParsedSource, syntax::ParsedSources};

fn parsed(files: &[(&str, &str)]) -> ParsedSources {
    let mut sources = SourceSet::new();
    for (name, text) in files {
        sources.add(*name, *text).unwrap();
    }
    ParsedSources {
        sources: sources
            .iter()
            .map(|(id, source)| ParsedSource {
                source_id: id,
                domain: SourceDomainId::project(),
                module: Vec::new(),
                program: crate::syntax::parser::parse_file_in(id, source)
                    .recovered_program()
                    .clone(),
            })
            .collect(),
        input_domains: BTreeMap::new(),
        project_roots: std::collections::BTreeSet::new(),
    }
}

fn resolved(files: &[(&str, &str)]) -> ResolvedProgram {
    let (program, _, exhausted) = crate::resolver::resolve_partial(
        parsed(files),
        Some(&AnalysisCancellation::default()),
    );
    assert!(!exhausted);
    program
}

fn key(name: &str, part: ResolutionOwnerPart) -> ResolutionOwnerKey {
    ResolutionOwnerKey {
        domain: SourceDomainId::project(),
        path: vec![name.into()],
        part,
    }
}

fn query(program: &ResolvedProgram, key: &ResolutionOwnerKey) -> OwnerResolution {
    program
        .owner_resolution(key, &AnalysisCancellation::default())
        .unwrap()
        .unwrap()
}

fn assert_same_facts(before: &OwnerResolution, after: &OwnerResolution) {
    assert_eq!(before.key, after.key);
    assert_eq!(before.locals, after.locals);
    assert_eq!(before.references, after.references);
    assert_eq!(before.diagnostics, after.diagnostics);
    assert_eq!(
        before.diagnostics_truncated,
        after.diagnostics_truncated
    );
    assert_eq!(
        before.namespace_dependencies,
        after.namespace_dependencies
    );
    assert_eq!(
        before.namespace_dependencies_complete,
        after.namespace_dependencies_complete
    );
}

#[test]
fn earlier_edits_relocate_owner_spans_and_global_ids_without_changing_local_keys() {
    let body = "fn inspect(x: I) -> I { let x = x; let f = fn(y: I) -> I { x }; f(x) }";
    let before = format!("value I(int); fn earlier() {{}} {body}");
    let after = format!(
        "// é😀\nvalue I(int); fn aaa() {{ let a = I(0); }} fn earlier() {{ let b = I(1); let c = b; }} {body}"
    );
    let old_program = resolved(&[("main.srx", &before)]);
    let new_program = resolved(&[("main.srx", &after)]);
    let key = key("inspect", ResolutionOwnerPart::Declaration);
    let old = query(&old_program, &key);
    let new = query(&new_program, &key);
    assert_same_facts(&old, &new);
    assert_ne!(old.source_map.span(), new.source_map.span());
    assert_ne!(old.source_map.local(0), new.source_map.local(0));
    for reference in &new.references {
        let span = new
            .source_map
            .absolute_span(reference.span)
            .unwrap();
        assert_eq!(
            new.source_map.relative_span(span),
            Some(reference.span)
        );
        let original = old
            .source_map
            .absolute_span(reference.span)
            .unwrap();
        assert_eq!(&after[span.range()], &before[original.range()]);
        if let OwnerReferenceTarget::Local {
            owner,
            ordinal,
        } = &reference.target
        {
            assert_eq!(owner.as_ref(), &key);
            let target = new_program
                .references()
                .find(|candidate| candidate.span() == span)
                .unwrap();
            assert_eq!(
                target.target(),
                &ResolvedTarget::Local(new.source_map.local(*ordinal).unwrap())
            );
        }
    }
    assert!(
        new.source_map
            .absolute_span(OwnerRelativeSpan {
                start: 1,
                end: 0
            })
            .is_none()
    );
    assert!(
        new.source_map
            .absolute_span(OwnerRelativeSpan {
                start: 0,
                end: u32::MAX
            })
            .is_none()
    );
    assert!(
        new.source_map
            .relative_span(old.source_map.span())
            .is_none()
    );
}

#[test]
fn file_order_and_source_ids_do_not_enter_owner_or_target_keys() {
    let a = (
        "a.srx",
        "value I(int); fn helper(x: I) -> I { x }",
    );
    let b = ("b.srx", "fn inspect(x: I) -> I { helper(x) }");
    let key = key("inspect", ResolutionOwnerPart::Declaration);
    let old = query(&resolved(&[a, b]), &key);
    let new = query(&resolved(&[b, a]), &key);
    assert_same_facts(&old, &new);
    assert_ne!(
        old.source_map.span().source_id(),
        new.source_map.span().source_id()
    );
}

#[test]
fn defaults_have_independent_locals_and_reference_the_declaration_generic_owner() {
    let old = "struct Holder<T> { callback: fn(T) -> T = fn(x: T) -> T { x }; }";
    let new = "struct Holder<T> { other: fn(T) -> T = fn(y: T) -> T { let z = y; z }; callback: fn(T) -> T = fn(x: T) -> T { x }; }";
    let old_program = resolved(&[("main.srx", old)]);
    let new_program = resolved(&[("main.srx", new)]);
    let default = key(
        "Holder",
        ResolutionOwnerPart::FieldDefault("callback".into()),
    );
    let old = query(&old_program, &default);
    let new = query(&new_program, &default);
    assert_same_facts(&old, &new);
    assert_eq!(new.locals.len(), 1);
    assert_ne!(old.source_map.local(0), new.source_map.local(0));
    let parent = key("Holder", ResolutionOwnerPart::Declaration);
    assert!(new.references.iter().any(|reference| matches!(&reference.target,OwnerReferenceTarget::Local {owner,ordinal:0} if owner.as_ref() == &parent)));
    let parent = query(&new_program, &parent);
    assert_eq!(parent.locals.len(), 1);
    assert_eq!(parent.locals[0].name, "T");
}

#[test]
fn recovered_scopes_and_resolution_errors_relocate_without_losing_shadowing() {
    let body = "fn inspect(x: I) { let x: I = ; let later = x; missing(later); }";
    let old = format!("value I(int); {body}");
    let new = format!("value I(int); fn prior() {{ let a = I(1); }} {body}");
    let key = key("inspect", ResolutionOwnerPart::Declaration);
    let old = query(&resolved(&[("main.srx", &old)]), &key);
    let new = query(&resolved(&[("main.srx", &new)]), &key);
    assert_same_facts(&old, &new);
    assert_eq!(
        new.locals
            .iter()
            .map(|local| local.name.as_str())
            .collect::<Vec<_>>(),
        vec!["x", "x", "later"]
    );
    assert!(!new.locals[1].scopes.is_empty());
    assert!(!new.diagnostics.is_empty());
}

#[test]
fn namespace_observations_keep_negative_lookups_and_ignore_unrelated_body_edits() {
    let text = "value I(int); fn target() -> I { I(1) } fn inspect() -> I { target() } fn missing() { later(); }";
    let baseline = resolved(&[("main.srx", text)]);
    let inspect = key("inspect", ResolutionOwnerPart::Declaration);
    let before = query(&baseline, &inspect);
    assert!(before.namespace_dependencies_complete);
    assert!(!before.namespace_dependencies.is_empty());
    for changed in [
        text.replace("I(1)", "I(2)"),
        format!("fn aaa() {{}} {text}"),
    ] {
        let after = query(&resolved(&[("main.srx", &changed)]), &inspect);
        assert_eq!(
            before.namespace_dependencies,
            after.namespace_dependencies
        );
    }
    let missing = key("missing", ResolutionOwnerPart::Declaration);
    let before = query(&baseline, &missing);
    assert!(
        before
            .namespace_dependencies
            .iter()
            .any(|dependency| dependency.path == ["later"]
                && dependency.outcome == NamespaceOutcome::Target(None))
    );
    let changed = format!("fn later() {{}} {text}");
    let after = query(&resolved(&[("main.srx", &changed)]), &missing);
    assert_ne!(
        before.namespace_dependencies,
        after.namespace_dependencies
    );
}

#[test]
fn namespace_observations_detect_shadowing_visibility_and_reexport_changes() {
    let cases = [
        (
            "fn target() {} mod m { fn inspect() { target(); } }",
            "fn target() {} mod m { fn target() {} fn inspect() { target(); } }",
            vec!["m".into(), "inspect".into()],
        ),
        (
            "mod api { fn target() {} outputs {} } fn inspect() { api::target(); }",
            "mod api { pub fn target() {} outputs {} } fn inspect() { api::target(); }",
            vec!["inspect".into()],
        ),
        (
            "mod a { pub fn target() {} } mod b { pub fn target() {} } mod api { pub use a::target; } fn inspect() { api::target(); }",
            "mod a { pub fn target() {} } mod b { pub fn target() {} } mod api { pub use b::target; } fn inspect() { api::target(); }",
            vec!["inspect".into()],
        ),
    ];
    for (old, new, path) in cases {
        let key = ResolutionOwnerKey {
            domain: SourceDomainId::project(),
            path,
            part: ResolutionOwnerPart::Declaration,
        };
        let old = query(&resolved(&[("main.srx", old)]), &key);
        let new = query(&resolved(&[("main.srx", new)]), &key);
        assert!(old.namespace_dependencies_complete && new.namespace_dependencies_complete);
        assert_ne!(
            old.namespace_dependencies, new.namespace_dependencies,
            "{key:?}"
        );
    }
}

#[test]
fn namespace_observations_detect_variant_and_discovery_inventory_changes() {
    let old = "enum E { A } fn inspect() { E::B(); }";
    let new = "enum E { A, B } fn inspect() { E::B(); }";
    let key = key("inspect", ResolutionOwnerPart::Declaration);
    let old = query(&resolved(&[("main.srx", old)]), &key);
    let new = query(&resolved(&[("main.srx", new)]), &key);
    assert!(
        old.namespace_dependencies
            .iter()
            .any(|dependency| dependency.query == NamespaceQuery::Variant)
    );
    assert_ne!(
        old.namespace_dependencies,
        new.namespace_dependencies
    );
    let original = "mod recipes { mod a { pub fn recipe() {} } } fn mapper() {} fn inspect() { module_exports(recipes, recipe, mapper); }";
    let changed = original.replace(
        "mod recipes {",
        "mod recipes { mod b { pub fn recipe() {} }",
    );
    let old = query(&resolved(&[("main.srx", original)]), &key);
    let new = query(&resolved(&[("main.srx", &changed)]), &key);
    let inventory = |resolution: &OwnerResolution| {
        resolution
            .namespace_dependencies
            .iter()
            .find(|dependency| {
                matches!(
                    dependency.query,
                    NamespaceQuery::ModuleExports { .. }
                )
            })
            .unwrap()
            .outcome
            .clone()
    };
    assert!(old.namespace_dependencies_complete && new.namespace_dependencies_complete);
    let NamespaceOutcome::Exports {
        entries: Some(entries),
        ..
    } = inventory(&new)
    else {
        panic!("inventory");
    };
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.key.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
    assert_ne!(inventory(&old), inventory(&new));
}

#[test]
fn namespace_equality_does_not_claim_signature_or_type_interface_equality() {
    let text =
        "value I(int); value S(str); fn target() -> I { I(1) } fn inspect() -> I { target() }";
    let changed = text.replace(
        "fn target() -> I { I(1) }",
        "fn target() -> S { S(\"changed\") }",
    );
    let key = key("inspect", ResolutionOwnerPart::Declaration);
    let old_program = resolved(&[("main.srx", text)]);
    let new_program = resolved(&[("main.srx", &changed)]);
    let old = query(&old_program, &key);
    let new = query(&new_program, &key);
    assert_eq!(
        old.namespace_dependencies,
        new.namespace_dependencies
    );
    assert!(
        crate::checker::check(
            old_program,
            &crate::checker::CheckPolicy::default()
        )
        .is_ok()
    );
    assert!(
        crate::checker::check(
            new_program,
            &crate::checker::CheckPolicy::default()
        )
        .is_err()
    );
}

#[test]
fn canonical_targets_keep_domains_distinct_and_outputs_have_owners() {
    let mut sources = SourceSet::new();
    sources.add("main.srx", "inputs { dep = \"path:dep\"; } value I(int); fn g() {} fn f() { g(); dep::g(); } outputs { factory: fn() -> I = fn() -> I { I(1) }; }").unwrap();
    let domain = sources.create_input_domain("dep").unwrap();
    sources
        .add_to_input_domain(domain, "dep.srx", "pub fn g() {}")
        .unwrap();
    let (program, errors, exhausted) = crate::resolver::resolve_partial(
        crate::syntax::parse_sources(&sources).unwrap(),
        Some(&AnalysisCancellation::default()),
    );
    assert!(errors.is_empty(), "{errors:?}");
    assert!(!exhausted);
    let f = query(
        &program,
        &key("f", ResolutionOwnerPart::Declaration),
    );
    let targets = f
        .references
        .iter()
        .filter_map(|reference| match &reference.target {
            OwnerReferenceTarget::Item {
                domain,
                path,
            } if path == &["g"] => Some(*domain),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(targets, vec![SourceDomainId::project(), domain]);
    let output = query(
        &program,
        &key("factory", ResolutionOwnerPart::Declaration),
    );
    assert!(!output.references.is_empty());
    assert!(
        program
            .resolution_owners()
            .any(|(key, _)| key.domain == domain && key.path == ["g"])
    );
}

#[test]
fn duplicate_owner_keys_and_their_defaults_are_unavailable() {
    let program = resolved(&[(
        "main.srx",
        "struct S { callback: fn() -> S = fn() -> S { S {} }; } struct S {} fn f() {} fn f() {}",
    )]);
    for key in [
        key("S", ResolutionOwnerPart::Declaration),
        key(
            "S",
            ResolutionOwnerPart::FieldDefault("callback".into()),
        ),
        key("f", ResolutionOwnerPart::Declaration),
    ] {
        assert!(
            program
                .owner_resolution(&key, &AnalysisCancellation::default())
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(program.resolution_owners().count(), 0);
}

#[test]
fn saturated_diagnostics_do_not_make_a_later_owner_appear_error_free() {
    let text = format!(
        "fn noisy() {{ {} }} fn later() {{ unknown(); }}",
        "unknown();".repeat(crate::MAX_DIAGNOSTICS)
    );
    let program = resolved(&[("main.srx", &text)]);
    let later = query(
        &program,
        &key("later", ResolutionOwnerPart::Declaration),
    );
    assert!(later.diagnostics.is_empty());
    assert!(later.diagnostics_truncated);
    assert!(!later.namespace_dependencies_complete);
}

#[test]
fn exhausted_owner_without_namespace_lookups_is_incomplete() {
    let parsed = parsed(&[("main.srx", "fn inspect() { let local = 1; }")]);
    let cancel = AnalysisCancellation::default();
    let mut resolver = Resolver::new(&parsed);
    resolver.cancellation = Some(&cancel);
    resolver.collect();
    resolver.bind_interfaces();
    resolver.bind_imports();
    resolver.work = crate::resolver::MAX_RESOLUTION_WORK - 1;
    resolver.resolve_contents();
    assert!(resolver.exhausted);
    let owner = resolver.owners.owners.first().unwrap();
    assert!(owner.dependencies.is_empty());
    assert!(!owner.dependencies_complete);
}

#[test]
fn owner_metadata_limits_do_not_change_resolution_work_or_diagnostics() {
    let parsed = parsed(&[(
        "main.srx",
        "value I(int); fn f(x: I) -> I { let y = x; y } fn broken() { unknown(); } mod recipes { pub fn recipe() {} } fn discover() { module_exports(recipes, recipe, f); }",
    )]);
    let cancel = AnalysisCancellation::default();
    let mut strict = Resolver::new(&parsed);
    strict.collect();
    strict.bind_interfaces();
    strict.bind_imports();
    strict.resolve_contents();
    let mut tracked = Resolver::new(&parsed);
    tracked.cancellation = Some(&cancel);
    tracked.collect();
    tracked.bind_interfaces();
    tracked.bind_imports();
    tracked.resolve_contents();
    assert!(!tracked.owners.truncated);
    assert!(
        tracked
            .owners
            .owners
            .iter()
            .any(|owner| !owner.dependencies.is_empty())
    );
    assert_eq!(strict.work, tracked.work);
    assert_eq!(strict.diagnostics, tracked.diagnostics);
    assert_eq!(strict.module_exports, tracked.module_exports);
    assert_eq!(strict.locals, tracked.locals);
    assert_eq!(strict.references.len(), tracked.references.len());
    for (left, right) in strict.references.iter().zip(&tracked.references) {
        assert_eq!(left.span(), right.span());
        assert_eq!(left.target(), right.target());
    }
    let mut bounded = Resolver::new(&parsed);
    bounded.cancellation = Some(&cancel);
    bounded.owners.units = MAX_UNITS;
    bounded.collect();
    bounded.bind_interfaces();
    bounded.bind_imports();
    bounded.resolve_contents();
    assert!(bounded.owners.truncated);
    assert!(bounded.owners.owners.is_empty());
    assert_eq!(strict.work, bounded.work);
    assert_eq!(strict.diagnostics, bounded.diagnostics);
    assert_eq!(strict.locals, bounded.locals);
    assert_eq!(strict.references.len(), bounded.references.len());
    for (left, right) in strict.references.iter().zip(&bounded.references) {
        assert_eq!(left.span(), right.span());
        assert_eq!(left.target(), right.target());
    }
    let program = resolved(&[("main.srx", "fn f() {}")]);
    cancel.cancel();
    assert!(
        program
            .owner_resolution(
                &key("f", ResolutionOwnerPart::Declaration),
                &cancel
            )
            .is_err()
    );
}

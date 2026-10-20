use super::*;
use crate::{
    analysis::AnalysisHost, checker::check, diagnostic::DiagnosticCode, resolver::resolve,
    source::SourceDomainId, syntax::parse_sources,
};

fn host_for(sources: &SourceSet) -> (AnalysisHost, BTreeMap<SourceId, String>) {
    let mut host = AnalysisHost::default();
    let mut bindings = BTreeMap::new();
    for (id, source) in sources.iter() {
        let key = format!("source:{}", id.index());
        host.set_disk(&key, source.text()).unwrap();
        bindings.insert(id, key);
    }
    (host, bindings)
}

#[test]
fn owner_queries_relocate_overlay_definitions_and_preserve_old_snapshot_maps() {
    let mut sources = SourceSet::new();
    let text = "value I(int); fn earlier() {} fn later(x: I) -> I { let y = x; y }";
    let source = sources.add("main.srx", text).unwrap();
    let (mut host, bindings) = host_for(&sources);
    let cancel = AnalysisCancellation::default();
    let policy = CheckPolicy::default();
    let before = host
        .snapshot()
        .analyze_project(&sources, &bindings, &policy, &cancel)
        .unwrap();
    let key = before
        .resolution_owners()
        .find(|(key, _)| key.path == ["later"])
        .unwrap()
        .0
        .clone();
    let old = before
        .owner_resolution(&key, &cancel)
        .unwrap()
        .unwrap();
    let changed = text.replace(
        "fn earlier() {}",
        "fn earlier() { let inserted = I(0); }",
    );
    host.set_overlay(&bindings[&source], 1, &changed)
        .unwrap();
    let after = host
        .snapshot()
        .analyze_project(&sources, &bindings, &policy, &cancel)
        .unwrap();
    let new = after
        .owner_resolution(&key, &cancel)
        .unwrap()
        .unwrap();
    assert_eq!(old.locals, new.locals);
    assert_eq!(old.references, new.references);
    assert_ne!(old.source_map.local(0), new.source_map.local(0));
    let usage = new.references.last().unwrap();
    let crate::resolver::OwnerReferenceTarget::Local {
        ordinal,
        ..
    } = usage.target
    else {
        panic!("local use");
    };
    let current_span = new.source_map.absolute_span(usage.span).unwrap();
    let definition = after
        .definition_at(source, current_span.start())
        .unwrap();
    assert_eq!(
        definition,
        new.source_map
            .absolute_span(new.locals[ordinal as usize].declaration)
            .unwrap()
    );
    let old_again = before
        .owner_resolution(&key, &cancel)
        .unwrap()
        .unwrap();
    assert_eq!(old.source_map.span(), old_again.source_map.span());
    assert!(!after.resolution_owners_truncated());
}

#[test]
fn construction_completion_respects_erasure_policy_without_hiding_projection() {
    let mut sources = SourceSet::new();
    let source = sources
        .add(
            "main.srx",
            "value I(int); struct Raw<T> { payload: I; } struct Erased { payload: I; } fn inspect() {}",
        )
        .unwrap();
    let (host, bindings) = host_for(&sources);
    let policy = CheckPolicy::default()
        .with_erasure(
            crate::checker::CanonicalItemIdentity::new(SourceDomainId::project(), ["Raw"]).unwrap(),
            crate::checker::CanonicalItemIdentity::new(SourceDomainId::project(), ["Erased"])
                .unwrap(),
        )
        .unwrap();
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &policy,
            &AnalysisCancellation::default(),
        )
        .unwrap();
    assert!(
        analysis.diagnostics().is_empty(),
        "{:?}",
        analysis.diagnostics()
    );
    let item = analysis
        .items()
        .find(|item| item.path().segments() == ["Erased"])
        .unwrap()
        .id();
    let ty = Ty::Nominal(item);
    assert_eq!(analysis.fields_at(source, 0, &ty).len(), 1);
    assert!(
        analysis
            .construction_fields_at(source, 0, &ty)
            .is_empty()
    );
}

#[test]
fn recovered_struct_fields_keep_specialization_and_ownership_regions() {
    let text = "value I(int); resource R(int); struct Box<T> { first: T; second: T; third: T; } fn inspect(r: R) { let broken = Box<R> { first = r; missing = ; second = r; third = r; }; let later = I(1); }";
    let mut sources = SourceSet::new();
    let source = sources.add("main.srx", text).unwrap();
    assert!(parse_sources(&sources).is_err());
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    let at = u32::try_from(text.find("Box<R> {").unwrap() + "Box<R> ".len()).unwrap();
    let expression = analysis.expression_at(source, at).unwrap();
    assert_eq!(analysis.display_type(expression.ty()), "Box<R>");
    assert!(
        !analysis
            .construction_fields_at(source, at, expression.ty())
            .is_empty()
    );
    let uses: Vec<_> = analysis
        .ownership_uses()
        .iter()
        .filter(|usage| usage.affine)
        .collect();
    assert_eq!(uses.len(), 3);
    assert!(uses[0].is_valid());
    assert!(uses[1].is_uncertain());
    assert!(!uses[2].is_valid() && !uses[2].is_uncertain());
    assert_eq!(
        analysis
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == DiagnosticCode::MovedValue)
            .count(),
        1
    );
    let later = analysis
        .locals()
        .find(|local| local.name() == "later")
        .unwrap()
        .id();
    assert_eq!(
        analysis
            .checked_locals()
            .find(|local| local.id == later)
            .unwrap()
            .status,
        crate::checker::TypeStatus::Known
    );
}

#[test]
fn statement_recovery_preserves_suffix_shadowing_and_unknown_ownership() {
    let text = "value I(int); resource R(int); fn take(r: R) {} fn inspect(r: R) { let shadow = I(1); let shadow: I = ; let dependent = shadow; let later = I(2); take(r); take(r); }";
    let mut sources = SourceSet::new();
    let source = sources.add("main.srx", text).unwrap();
    assert!(parse_sources(&sources).is_err());
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    let at = u32::try_from(text.find("take(r); take(r)").unwrap()).unwrap();
    let ResolvedTarget::Local(shadow) = analysis
        .lookup_path(source, at, &["shadow".into()])
        .unwrap()
    else {
        panic!("shadow binding");
    };
    let recovered = analysis
        .checked_locals()
        .find(|local| local.id == shadow)
        .unwrap();
    assert_eq!(
        recovered.status,
        crate::checker::TypeStatus::Unknown
    );
    assert_eq!(analysis.display_type(&recovered.ty), "I");
    for (name, status) in [
        ("dependent", crate::checker::TypeStatus::Unknown),
        ("later", crate::checker::TypeStatus::Known),
    ] {
        let id = analysis
            .locals()
            .find(|local| local.name() == name)
            .unwrap()
            .id();
        assert_eq!(
            analysis
                .checked_locals()
                .find(|local| local.id == id)
                .unwrap()
                .status,
            status
        );
    }
    let uses: Vec<_> = analysis
        .ownership_uses()
        .iter()
        .filter(|usage| usage.affine && usage.span.start() >= at)
        .collect();
    assert_eq!(uses.len(), 2);
    assert!(uses[0].is_uncertain() && !uses[0].is_valid());
    assert!(!uses[1].is_uncertain() && uses[1].previous_move.is_some());
    assert_eq!(
        analysis
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == DiagnosticCode::MovedValue)
            .count(),
        1
    );
}

#[test]
fn malformed_nested_closure_keeps_its_locals_scoped_and_outer_ownership_unknown() {
    let text = "value I(int); resource R(int); fn inspect(r: R) { let deferred = once fn() -> R { let hidden = I(1); hidden.; r }; let later = I(2); r; }";
    let mut sources = SourceSet::new();
    let source = sources.add("main.srx", text).unwrap();
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    let at = u32::try_from(text.find("let later").unwrap()).unwrap();
    assert!(
        analysis
            .lookup_path(source, at, &["hidden".into()])
            .is_none()
    );
    assert!(
        !analysis
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::MovedValue)
    );
    assert!(
        analysis
            .ownership_uses()
            .iter()
            .any(|usage| usage.span.start() > at && usage.is_uncertain())
    );
}

#[test]
fn type_labels_are_bounded_and_disambiguate_identical_paths_across_domains() {
    let parameter = "T".repeat(16_384);
    let text = format!(
        "inputs {{ dep = \"path:dep\"; }} value I(int); fn identity<{parameter}>(item: {parameter}) -> {parameter} {{ item }}"
    );
    let mut sources = SourceSet::new();
    sources.add("main.srx", text).unwrap();
    let dep = sources.create_input_domain("dep").unwrap();
    sources
        .add_to_input_domain(dep, "dep.srx", "pub value I(int);")
        .unwrap();
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    assert!(
        analysis.diagnostics().is_empty(),
        "{:?}",
        analysis.diagnostics()
    );
    let labels: Vec<_> = analysis
        .items()
        .filter(|item| item.path().segments() == ["I"])
        .map(|item| analysis.display_type(&Ty::Nominal(item.id())))
        .collect();
    assert_eq!(labels.len(), 2);
    assert_ne!(labels[0], labels[1]);
    let function = analysis
        .items()
        .find(|item| item.path().segments() == ["identity"])
        .unwrap();
    let label = analysis.display_type(analysis.function_type(function.id()).unwrap());
    assert!(label.len() < 1024);
    assert!(label.contains('…'));
}

#[test]
fn ownership_distinguishes_definite_moves_from_conditional_moves() {
    let text = "resource R(int); enum Flag { Yes, No } fn take(r: R) {} fn all(flag: Flag, r: R) { match flag { Yes => take(r), No => take(r) }; take(r); } fn some(flag: Flag, r: R) { match flag { Yes => take(r), No => idle() }; take(r); } fn compared(r: R) { compare(1, 2, take(r), take(r), take(r)); take(r); } fn idle() {}";
    let mut sources = SourceSet::new();
    sources.add("main.srx", text).unwrap();
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    let mut reuses: Vec<_> = analysis
        .ownership_uses()
        .iter()
        .filter(|usage| usage.previous_move.is_some())
        .collect();
    reuses.sort_by_key(|usage| usage.span.start());
    assert_eq!(reuses.len(), 3, "{:?}", analysis.diagnostics());
    assert!(!reuses[0].conditional);
    assert!(reuses[1].conditional);
    assert!(!reuses[2].conditional);
}

#[test]
fn invalid_initializers_do_not_become_proven_inferred_types() {
    let text = "value I(int); value S(str); fn inspect() { let invalid: I = S(\"wrong\"); let propagated = invalid; let broken = I(\"wrong\"); let valid = I(1); }";
    let mut sources = SourceSet::new();
    sources.add("main.srx", text).unwrap();
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    let status = |name| {
        let id = analysis
            .locals()
            .find(|local| local.name() == name)
            .unwrap()
            .id();
        analysis
            .checked_locals()
            .find(|local| local.id == id)
            .unwrap()
            .status
    };
    assert_eq!(
        status("invalid"),
        crate::checker::TypeStatus::Invalid
    );
    assert_eq!(
        status("propagated"),
        crate::checker::TypeStatus::Invalid
    );
    assert_eq!(
        status("broken"),
        crate::checker::TypeStatus::Invalid
    );
    assert_eq!(status("valid"), crate::checker::TypeStatus::Known);
}

#[test]
fn capture_facts_distinguish_invalid_capture_and_body_consumption() {
    let text = "resource R(int); fn allowed(r: R) { let deferred = once fn() -> R { r }; } fn forbidden(r: R) { let reusable = fn() -> R { r }; }";
    let mut sources = SourceSet::new();
    sources.add("main.srx", text).unwrap();
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    let captures: Vec<_> = analysis
        .ownership_uses()
        .iter()
        .filter(|usage| usage.kind == crate::checker::OwnershipUseKind::Capture)
        .collect();
    assert_eq!(captures.len(), 2);
    assert!(captures[0].is_valid());
    assert!(!captures[1].is_valid());
    assert_eq!(
        analysis
            .ownership_uses()
            .iter()
            .filter(|usage| usage.span == captures[0].span
                && usage.kind == crate::checker::OwnershipUseKind::Consume)
            .count(),
        1
    );
}

#[test]
fn typed_bindings_patterns_captures_and_branch_moves_are_inspectable() {
    let text = "value I(int); resource R(int); enum Maybe<T> { None, Some(T) } fn id<T>(x: T) -> T { x } fn inspect(r: R, m: Maybe<I>) { let values: [I] = []; let inferred = id(I(1)); match m { Some(element) => element, None => I(0) }; let deferred = once fn() -> R { r }; deferred(); deferred(); } fn branch(m: Maybe<I>, r: R) { match m { Some(element) => take(r), None => nothing() }; take(r); } fn take(r: R) {} fn nothing() {}";
    let mut sources = SourceSet::new();
    let source = sources.add("main.srx", text).unwrap();
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    let local = |name: &str| {
        analysis
            .locals()
            .find(|local| local.name() == name)
            .unwrap()
    };
    assert_eq!(
        analysis.display_type(
            analysis
                .local_type(local("inferred").id())
                .unwrap()
        ),
        "I"
    );
    assert_eq!(
        analysis.display_type(analysis.local_type(local("values").id()).unwrap()),
        "[I]"
    );
    assert_eq!(
        analysis.display_type(
            analysis
                .local_type(local("element").id())
                .unwrap()
        ),
        "I"
    );
    let function = analysis
        .items()
        .find(|item| item.path().segments() == ["id"])
        .unwrap();
    assert_eq!(
        analysis.display_type(analysis.function_type(function.id()).unwrap()),
        "fn(T) -> T"
    );
    assert!(
        analysis
            .ownership_uses()
            .iter()
            .any(
                |usage| usage.kind == crate::checker::OwnershipUseKind::Capture
                    && usage.affine
                    && usage.closure.is_some()
            )
    );
    assert!(
        analysis
            .ownership_uses()
            .iter()
            .any(|usage| usage.previous_move.is_some() && usage.conditional)
    );
    let expected = analysis
        .expected_type_at(
            source,
            u32::try_from(text.find("[]").unwrap()).unwrap(),
        )
        .unwrap();
    assert_eq!(analysis.display_type(expected), "[I]");
    assert_eq!(
        analysis
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == DiagnosticCode::MovedValue)
            .count(),
        2
    );
}

#[test]
fn incomplete_statement_retains_prior_bindings_and_never_checks_unknown_suffix() {
    let text = "value I(int); resource R(int); fn broken(r: R) { let previous: I = 1; let moved = r; previous. ; r; }";
    let mut sources = SourceSet::new();
    let source = sources.add("main.srx", text).unwrap();
    assert!(parse_sources(&sources).is_err());
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    let offset = u32::try_from(text.find("previous.").unwrap()).unwrap();
    let ResolvedTarget::Local(previous) = analysis
        .lookup_path(source, offset, &["previous".into()])
        .unwrap()
    else {
        panic!("local");
    };
    assert_eq!(
        analysis.display_type(analysis.local_type(previous).unwrap()),
        "I"
    );
    assert!(
        !analysis
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::MovedValue)
    );
}

#[test]
fn fields_and_contextual_variants_share_definitions_and_opaque_authority() {
    let text = "value I(int); struct Box<T> { entry: T; } mod vault { pub opaque struct Secret { hidden: I; } fn inside(x: Secret) -> I { x.hidden } } enum Maybe<T> { None, Some(T) } fn inspect(b: Box<I>, s: vault::Secret, m: Maybe<I>) -> I { match m { Some(payload) => b.entry, None => I(0) } }";
    let mut sources = SourceSet::new();
    let source = sources.add("main.srx", text).unwrap();
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    assert!(
        analysis.diagnostics().is_empty(),
        "{:?}",
        analysis.diagnostics()
    );
    let offset = u32::try_from(text.find("b.entry").unwrap()).unwrap();
    let b = analysis
        .locals()
        .find(|local| local.name() == "b")
        .unwrap();
    let fields = analysis.fields_at(
        source,
        offset,
        analysis.local_type(b.id()).unwrap(),
    );
    assert_eq!(fields.len(), 1);
    assert_eq!(analysis.display_type(&fields[0].ty), "I");
    assert_eq!(
        analysis.definition_at(source, offset + 2),
        Some(fields[0].declaration)
    );
    let secret = analysis
        .locals()
        .find(|local| local.name() == "s")
        .unwrap();
    assert!(
        analysis
            .fields_at(
                source,
                offset,
                analysis.local_type(secret.id()).unwrap()
            )
            .is_empty()
    );
    let inside = u32::try_from(text.find("x.hidden").unwrap()).unwrap();
    assert_eq!(
        analysis
            .fields_at(
                source,
                inside,
                analysis.local_type(secret.id()).unwrap()
            )
            .len(),
        1
    );
    let some = u32::try_from(text.find("Some(payload)").unwrap()).unwrap();
    assert_eq!(
        analysis
            .definition_at(source, some)
            .unwrap()
            .start() as usize,
        text.find("Some(T)").unwrap()
    );
}

#[test]
fn imported_methods_retain_definitions_and_specialized_types_across_overlays() {
    let text = r#"inputs { dep = "path:dep"; } let packages = dep::PackageSet {}; outputs { ordinary: dep::I = packages.ordinary(7); selected: dep::I = packages.selected(8); }"#;
    let library = "pub value I(int); pub struct PackageSet {} impl PackageSet { fn ordinary(packages: Self, n: I) -> I { n } fn selected(const packages: Self, const n: I) -> _ { n } }";
    let mut sources = SourceSet::new();
    let source = sources.add("main.srx", text).unwrap();
    let domain = sources.create_input_domain("dep").unwrap();
    let imported = sources
        .add_to_input_domain(domain, "dep.srx", library)
        .unwrap();
    let (mut host, bindings) = host_for(&sources);
    let cancel = AnalysisCancellation::default();
    let policy = CheckPolicy::default();
    let before = host
        .snapshot()
        .analyze_project(&sources, &bindings, &policy, &cancel)
        .unwrap();
    let shifted_text = format!("// caller overlay\n{text}");
    let shifted_library = format!("// dependency overlay\n{library}");
    host.set_overlay(&bindings[&source], 1, &shifted_text)
        .unwrap();
    host.set_overlay(&bindings[&imported], 1, &shifted_library)
        .unwrap();
    let after = host
        .snapshot()
        .analyze_project(&sources, &bindings, &policy, &cancel)
        .unwrap();
    for (analysis, caller, dependency) in [
        (&before, text, library),
        (
            &after,
            shifted_text.as_str(),
            shifted_library.as_str(),
        ),
        (&before, text, library),
    ] {
        assert!(
            analysis.diagnostics().is_empty(),
            "{:?}",
            analysis.diagnostics()
        );
        for method in ["ordinary", "selected"] {
            let offset = u32::try_from(
                caller
                    .find(&format!("packages.{method}"))
                    .unwrap()
                    + "packages.".len(),
            )
            .unwrap();
            let declaration = analysis.definition_at(source, offset).unwrap();
            assert_eq!(declaration.source_id(), imported);
            assert_eq!(
                declaration.start() as usize,
                dependency.find(&format!("fn {method}")).unwrap() + 3
            );
            let symbol = analysis
                .symbol_at(source, offset, &cancel)
                .unwrap()
                .unwrap();
            assert_eq!(symbol.name, method);
            assert_eq!(
                symbol.kind,
                crate::analysis::SemanticSymbolKind::Function
            );
            let Ty::Function {
                parameters,
                result,
                once,
            } = analysis.type_at(source, offset).unwrap()
            else {
                panic!("method hover must retain the callable type");
            };
            assert_eq!(parameters.len(), 2);
            assert!(!once);
            assert_eq!(analysis.display_type(result), "I");
        }
    }
}

#[test]
fn semantic_revalidation_uses_effective_text_and_cannot_mask_a_dependency_edit() {
    let mut sources = SourceSet::new();
    let root = sources
        .add("main", "fn run() { helper(); }")
        .unwrap();
    let dep = sources.add("helper", "fn helper() {}").unwrap();
    let (mut host, bindings) = host_for(&sources);
    let cancellation = AnalysisCancellation::default();
    let first = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &cancellation,
        )
        .unwrap();
    host.set_overlay(
        &bindings[&root],
        1,
        sources.get(root).unwrap().text(),
    )
    .unwrap();
    host.set_disk(&bindings[&root], "invalid disk hidden by overlay")
        .unwrap();
    let snapshot = host.snapshot();
    let reused = snapshot
        .revalidate_project_analysis(&first, &cancellation)
        .unwrap()
        .unwrap();
    assert_eq!(reused.revision(), snapshot.revision());
    assert!(Arc::ptr_eq(&first.resolved, &reused.resolved));
    host.set_disk(&bindings[&dep], "fn renamed() {}")
        .unwrap();
    assert!(
        host.snapshot()
            .revalidate_project_analysis(&first, &cancellation)
            .unwrap()
            .is_none()
    );
    cancellation.cancel();
    assert!(
        snapshot
            .revalidate_project_analysis(&first, &cancellation)
            .is_err()
    );
}

#[test]
fn completion_uses_input_domains_reexports_and_closed_interfaces() {
    let mut sources = SourceSet::new();
    let text = "inputs { dep = \"path:dep\"; } fn run() { dep::make(); }";
    let main = sources.add("main.srx", text).unwrap();
    let dep = sources.create_input_domain("dep").unwrap();
    sources.add_to_input_domain(dep, "dep.srx", "mod internal { pub fn make() {} fn secret() {} } pub use internal::make; fn private() {}").unwrap();
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    let offset = u32::try_from(text.find("dep::make").unwrap()).unwrap();
    let candidates = analysis.complete_path(main, offset, &["dep".into()], "");
    assert_eq!(
        candidates
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["make"]
    );
    let target = analysis
        .lookup_path(main, offset, &["dep".into(), "make".into()])
        .unwrap();
    assert_eq!(candidates[0].1, target);
    assert!(
        analysis
            .complete_path(
                main,
                offset,
                &["dep".into(), "internal".into()],
                ""
            )
            .is_empty()
    );
    assert!(
        analysis
            .complete_path(main, offset, &[], "d")
            .iter()
            .any(|(name, target)| name == "dep" && matches!(target, ResolvedTarget::Module(_)))
    );
    assert!(
        analysis
            .complete_path(main, u32::MAX, &[], "")
            .is_empty()
    );
}

#[test]
fn completion_tracks_initializer_order_closure_shadowing_and_incomplete_parameters() {
    let mut sources = SourceSet::new();
    let text = "value I(int); fn run(outer: I) { let saved = outer; let closure = fn(outer: I) -> I { outer }; saved; } fn broken(argument: I) { argument. }";
    let main = sources.add("main.srx", text).unwrap();
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    let offset = |needle: &str| u32::try_from(text.find(needle).unwrap()).unwrap();
    let initial = analysis.complete_path(main, offset("outer;"), &[], "");
    assert!(!initial.iter().any(|(name, _)| name == "saved"));
    let inner = analysis
        .lookup_path(main, offset("outer }"), &["outer".into()])
        .unwrap();
    let outer = analysis
        .lookup_path(main, offset("saved; }"), &["outer".into()])
        .unwrap();
    assert_ne!(inner, outer);
    assert!(
        analysis
            .complete_path(main, offset("saved; }"), &[], "")
            .iter()
            .any(|(name, _)| name == "closure")
    );
    assert!(
        analysis
            .complete_path(main, offset("argument."), &[], "arg")
            .iter()
            .any(|(name, _)| name == "argument")
    );
}

#[test]
fn valid_preview_matches_strict_types_and_definitions_across_imported_reexports() {
    let mut sources = SourceSet::new();
    let main = sources
        .add(
            "same.srx",
            "inputs { dep = \"path:dep\"; } fn good() -> std::I { dep::make() }",
        )
        .unwrap();
    sources
        .add_standard_library("std.srx", "mod std { pub value I(int); }")
        .unwrap();
    let dep = sources.create_input_domain("dep").unwrap();
    let imported = sources.add_to_input_domain(dep, "same.srx", "mod implementation { pub fn make() -> std::I { std::I(1) } } pub use implementation::make;").unwrap();
    let checked = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap();
    let (host, bindings) = host_for(&sources);
    let result = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    assert!(
        result.diagnostics().is_empty(),
        "{:?}",
        result.diagnostics()
    );
    for expression in checked.expressions() {
        let found = result
            .expressions
            .iter()
            .find(|candidate| candidate.span() == expression.span())
            .unwrap();
        assert_eq!(found.ty(), expression.ty());
    }
    let offset = u32::try_from(
        sources
            .get(main)
            .unwrap()
            .text()
            .find("dep::make")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        result
            .definition_at(main, offset)
            .unwrap()
            .source_id(),
        imported
    );
    assert_eq!(result.sources().domain(imported), Some(dep));
    assert!(
        result
            .items()
            .any(|item| item.domain() == SourceDomainId::standard_library())
    );
}

#[test]
fn incomplete_bodies_and_unresolved_names_do_not_erase_independent_types() {
    let mut sources = SourceSet::new();
    let main = sources.add("main.srx", "value I(int); mod nested { pub fn broken(x: I) -> I { x. } } fn unresolved() -> I { missing() } fn good() -> I { nested::broken(I(1)) }").unwrap();
    let (host, bindings) = host_for(&sources);
    let result = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    assert!(
        result
            .diagnostics()
            .iter()
            .any(|error| error.code == DiagnosticCode::ExpectedToken)
    );
    assert!(
        result
            .diagnostics()
            .iter()
            .any(|error| error.code == DiagnosticCode::Resolution)
    );
    assert!(
        !result.diagnostics().iter().any(|error| error
            .message
            .contains("function return type mismatch")),
        "{:?}",
        result.diagnostics()
    );
    let good = result
        .items()
        .find(|item| item.path().segments() == ["good"])
        .unwrap();
    let broken = result
        .items()
        .find(|item| item.path().segments() == ["nested", "broken"])
        .unwrap();
    assert!(
        matches!(result.function_type(good.id()), Some(Ty::Function { result, .. }) if matches!(**result, Ty::Nominal(_)))
    );
    assert!(
        matches!(result.function_type(broken.id()), Some(Ty::Function { parameters, .. }) if parameters.len() == 1)
    );
    let offset = u32::try_from(
        sources
            .get(main)
            .unwrap()
            .text()
            .find("nested::broken")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        result.definition_at(main, offset),
        Some(broken.span())
    );
    assert!(parse_sources(&sources).is_err());
}

#[test]
fn edited_dependency_rechecks_consumers_and_old_results_keep_their_types() {
    let mut sources = SourceSet::new();
    let main = sources
        .add(
            "main.srx",
            "fn use_it() -> I { make() } value I(int); value S(str);",
        )
        .unwrap();
    let library = sources
        .add("library.srx", "pub fn make() -> I { I(1) }")
        .unwrap();
    let (mut host, bindings) = host_for(&sources);
    let cancellation = AnalysisCancellation::default();
    let old = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &cancellation,
        )
        .unwrap();
    assert!(old.diagnostics().is_empty());
    host.set_overlay(
        &bindings[&library],
        1,
        "pub fn make() -> S { S(\"text\") }",
    )
    .unwrap();
    let new = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &cancellation,
        )
        .unwrap();
    assert!(new.diagnostics().iter().any(|error| {
        error.span.source_id() == main
            && error
                .message
                .contains("function return type mismatch")
    }));
    assert!(old.diagnostics().is_empty());
    assert!(!host.is_current(&old.revision()));
    assert_eq!(
        old.sources().get(library).unwrap().text(),
        "pub fn make() -> I { I(1) }"
    );
}

#[test]
fn recovery_handles_partial_modules_duplicate_parameters_and_missing_function_bodies() {
    for text in [
        "mod inner { value I(int); pub fn f() -> I { I(1) }",
        "value I(int); fn f<T, T>(x: T) -> T { x } fn g() -> I { f<I, I>(I(1)) }",
        "value I(int); fn f(x: I, x: I) -> I { x } fn g() -> I { I(1) }",
        "value I(int); fn f() -> I fn g() -> I { I(1) }",
        "value I(int); value I(str); fn g() -> I { I(1) }",
        "pub use absent::thing; fn g() { absent(); }",
    ] {
        let mut sources = SourceSet::new();
        sources.add("main.srx", text).unwrap();
        let (host, bindings) = host_for(&sources);
        let result = host
            .snapshot()
            .analyze_project(
                &sources,
                &bindings,
                &CheckPolicy::default(),
                &AnalysisCancellation::default(),
            )
            .unwrap();
        assert!(!result.diagnostics().is_empty(), "{text}");
        assert!(
            !result.items().collect::<Vec<_>>().is_empty(),
            "{text}"
        );
    }
}

#[test]
fn cancelled_semantics_returns_control_error_and_never_language_diagnostics() {
    let mut sources = SourceSet::new();
    sources.add("main.srx", "fn f() {}").unwrap();
    let (host, bindings) = host_for(&sources);
    let cancellation = AnalysisCancellation::default();
    cancellation.cancel();
    assert!(matches!(
        host.snapshot().analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &cancellation
        ),
        Err(SemanticAnalysisError::Cancelled(_))
    ));
    let (_, diagnostics, exhausted) = crate::resolver::resolve_partial(
        parse_sources(&sources).unwrap(),
        Some(&cancellation),
    );
    assert!(exhausted);
    assert!(diagnostics.is_empty());
}

#[test]
fn editing_prefixes_retains_a_bounded_inspection_result_without_panicking() {
    let text = "value I(int); value S(str); mod nested { pub fn id<T>(item: T) -> T { item } } fn use_it() -> I { let f = fn(x: I) -> I { x }; nested::id<I>(f(I(1))) } outputs { text: S = S(\"é 😀\"); }";
    for (offset, _) in text.char_indices() {
        let mut sources = SourceSet::new();
        sources
            .add("editing.srx", &text[..offset])
            .unwrap();
        let (host, bindings) = host_for(&sources);
        let result = host
            .snapshot()
            .analyze_project(
                &sources,
                &bindings,
                &CheckPolicy::default(),
                &AnalysisCancellation::default(),
            )
            .unwrap();
        assert!(result.diagnostics().len() <= MAX_DIAGNOSTICS);
        for error in result.diagnostics() {
            assert!(error.span.start() <= error.span.end());
            assert!(error.span.end() as usize <= offset);
        }
    }
}

#[test]
fn bound_parsing_reuses_completed_document_work_and_checks_coordinates_and_cancellation() {
    let mut sources = SourceSet::new();
    let first = sources.add("first.srx", "fn first() {}").unwrap();
    let second = sources
        .add("second.srx", "fn second() {}")
        .unwrap();
    let (mut host, bindings) = host_for(&sources);
    let cancel = AnalysisCancellation::default();
    let snapshot = host.snapshot();
    let document = snapshot.document(&bindings[&first]).unwrap();
    let parsed = document
        .document
        .analysis
        .parse_bound(first, &cancel)
        .unwrap();
    let cached = document
        .document
        .analysis
        .parse_bound(first, &cancel)
        .unwrap();
    assert!(Arc::ptr_eq(&parsed, &cached));
    let rebound = document
        .document
        .analysis
        .parse_bound(second, &cancel)
        .unwrap();
    assert!(!Arc::ptr_eq(&parsed, &rebound));
    assert_eq!(
        rebound.tokens().next().unwrap().span.source_id(),
        second
    );
    host.set_overlay(&bindings[&first], 1, "fn changed() {}")
        .unwrap();
    let changed = host
        .snapshot()
        .document(&bindings[&first])
        .unwrap();
    let changed = changed
        .document
        .analysis
        .parse_bound(first, &cancel)
        .unwrap();
    assert!(!Arc::ptr_eq(&parsed, &changed));
    assert_eq!(parsed.source().text(), "fn first() {}");
    cancel.cancel();
    assert!(
        document
            .document
            .analysis
            .parse_bound(second, &cancel)
            .is_err()
    );
}

#[test]
fn unknown_source_and_missing_document_bindings_never_publish_semantics() {
    let mut sources = SourceSet::new();
    let first = sources.add("first.srx", "fn first() {}").unwrap();
    let (host, mut bindings) = host_for(&sources);
    let second = sources
        .add("second.srx", "fn second() {}")
        .unwrap();
    bindings.insert(second, "missing".into());
    let cancel = AnalysisCancellation::default();
    let policy = CheckPolicy::default();
    assert!(matches!(
        host.snapshot()
            .analyze_project(&sources, &bindings, &policy, &cancel),
        Err(SemanticAnalysisError::InvalidBinding)
    ));
    let mut smaller = SourceSet::new();
    assert_eq!(
        smaller.add("first.srx", "fn first() {}").unwrap(),
        first
    );
    assert!(matches!(
        host.snapshot()
            .analyze_project(&smaller, &bindings, &policy, &cancel),
        Err(SemanticAnalysisError::InvalidBinding)
    ));
}

#[test]
fn parsing_diagnostic_precedence_survives_later_resolution_and_checking() {
    let mut sources = SourceSet::new();
    let malformed = sources
        .add("first.srx", "@".repeat(MAX_DIAGNOSTICS + 1))
        .unwrap();
    sources
        .add("second.srx", "fn later() { missing; }")
        .unwrap();
    let analysis = AnalysisHost::default()
        .snapshot()
        .analyze_project(
            &sources,
            &BTreeMap::new(),
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    assert_eq!(analysis.diagnostics().len(), MAX_DIAGNOSTICS);
    assert!(
        analysis
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.span.source_id() == malformed)
    );
    assert!(
        analysis
            .items()
            .any(|item| item.path().segments() == ["later"])
    );
}

#[test]
fn global_known_values_participate_in_transitive_owner_dependencies() {
    let mut sources = SourceSet::new();
    let text = r#"value S(str); value I(int); let libc: S = "gnu"; fn select(const name: S) -> _ { match name { "gnu" => I(1), "musl" => S("musl") } } let selected = select(libc); fn inspect() -> I { selected }"#;
    sources.add("main.srx", text).unwrap();
    let (mut host, bindings) = host_for(&sources);
    let policy = CheckPolicy::default();
    let cancel = AnalysisCancellation::default();
    let before = host
        .snapshot()
        .analyze_project(&sources, &bindings, &policy, &cancel)
        .unwrap();
    assert!(
        before.diagnostics().is_empty(),
        "{:?}",
        before.diagnostics()
    );
    let key = crate::resolver::ResolutionOwnerKey {
        domain: SourceDomainId::project(),
        path: vec!["inspect".into()],
        part: crate::resolver::ResolutionOwnerPart::Declaration,
    };
    let baseline = before
        .owner_type_dependencies(&key, &cancel)
        .unwrap()
        .unwrap();
    let source = sources.iter().next().unwrap().0;
    host.set_overlay(
        &bindings[&source],
        1,
        &text.replace("= \"gnu\"", "= \"musl\""),
    )
    .unwrap();
    let after = host
        .snapshot()
        .analyze_project(&sources, &bindings, &policy, &cancel)
        .unwrap();
    assert!(!after.diagnostics().is_empty());
    assert_ne!(
        Some(baseline),
        after
            .owner_type_dependencies(&key, &cancel)
            .unwrap()
    );
}

#[test]
fn computed_default_edits_refresh_global_and_output_contracts() {
    let text = r#"
        value S(str); value I(int);
        struct Inner { name: S = choose("new"); }
        struct Selection { inner: Inner = Inner {}; }
        struct Old { port: I; } struct New { host: S; }
        fn choose(const name: S) -> S { name }
        fn select(const selection: Selection) -> _ {
            match selection.inner.name {
                "old" => Old { port = 7; }, "new" => New { host = "server"; }
            }
        }
        let selected = select(Selection {});
        fn inspect() -> New { selected }
        outputs { implicit: New = select(Selection {}); }
    "#;
    let mut sources = SourceSet::new();
    let source = sources.add("main.srx", text).unwrap();
    let (mut host, bindings) = host_for(&sources);
    let policy = CheckPolicy::default();
    let cancel = AnalysisCancellation::default();
    let before = host
        .snapshot()
        .analyze_project(&sources, &bindings, &policy, &cancel)
        .unwrap();
    assert!(
        before.diagnostics().is_empty(),
        "{:?}",
        before.diagnostics()
    );
    let key = crate::resolver::ResolutionOwnerKey {
        domain: SourceDomainId::project(),
        path: vec!["inspect".into()],
        part: crate::resolver::ResolutionOwnerPart::Declaration,
    };
    let dependencies = before
        .owner_type_dependencies(&key, &cancel)
        .unwrap()
        .unwrap();
    let usage = u32::try_from(text.find("{ selected }").unwrap()).unwrap() + 2;
    assert_eq!(
        before.display_type(before.type_at(source, usage).unwrap()),
        "New"
    );
    for (version, changed, expected, errors) in [
        (
            1,
            text.replace("choose(\"new\")", "choose(\"old\")"),
            "Old",
            true,
        ),
        (2, text.to_owned(), "New", false),
    ] {
        host.set_overlay(&bindings[&source], version, &changed)
            .unwrap();
        let after = host
            .snapshot()
            .analyze_project(&sources, &bindings, &policy, &cancel)
            .unwrap();
        assert_eq!(
            after.display_type(after.type_at(source, usage).unwrap()),
            expected
        );
        assert_eq!(
            !after.diagnostics().is_empty(),
            errors,
            "{:?}",
            after.diagnostics()
        );
        if errors {
            assert!(
                after
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains("function return"))
            );
            assert!(
                after
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains("output"))
            );
            assert_ne!(
                Some(dependencies.clone()),
                after
                    .owner_type_dependencies(&key, &cancel)
                    .unwrap()
            );
        }
    }
    assert!(before.diagnostics().is_empty());
    assert_eq!(
        before.display_type(before.type_at(source, usage).unwrap()),
        "New"
    );
}

#[test]
fn variant_edits_refresh_unknown_names_in_discarded_global_branches() {
    let mut sources = SourceSet::new();
    let text =
        "enum Target { Gnu } let selected: Target = match Target::Gnu { Gnu => Gnu, _ => Musl };";
    let source = sources.add("main.srx", text).unwrap();
    let (mut host, bindings) = host_for(&sources);
    let policy = CheckPolicy::default();
    let cancel = AnalysisCancellation::default();
    for (version, text, missing) in [
        (1, text.to_owned(), true),
        (2, text.replace("{ Gnu }", "{ Gnu, Musl }"), false),
        (3, text.to_owned(), true),
    ] {
        host.set_overlay(&bindings[&source], version, &text)
            .unwrap();
        let analysis = host
            .snapshot()
            .analyze_project(&sources, &bindings, &policy, &cancel)
            .unwrap();
        assert_eq!(
            analysis
                .diagnostics()
                .iter()
                .any(|diagnostic| { diagnostic.message == "unknown value or enum variant `Musl`" }),
            missing,
            "{:?}",
            analysis.diagnostics()
        );
        if !missing {
            assert!(
                analysis.diagnostics().is_empty(),
                "{:?}",
                analysis.diagnostics()
            );
        }
    }
}

#[test]
fn global_package_contract_is_available_in_output_configuration() {
    let declaration = r#"
        struct PlatformSelection { system: PackagePinText; libc: PackagePinText = "gnu"; }
        struct Platform { system: PackagePinText; libc: PackagePinText; }
        struct PackageSet { platform: Platform; }
        fn forPlatform(const selection: PlatformSelection) -> PackageSet { PackageSet { platform = Platform { system = selection.system; libc = selection.libc; }; } }
        struct Selection { version: PackagePinText; }
        impl PackageSet { fn nginx(const packages: Self, const selection: Selection) -> _ { match packages.platform.libc { "gnu" => match selection.version { "1" => old(), "2" => newer() }, "musl" => old() } } }
        value S(str); struct Old { listen: S = "old"; } struct New { listen: S = "new"; proxyPass: S = "http://localhost"; }
        fn newer() -> PackageRef<New> { package_ref(recipe_ref(recipe), "2", "minimal", "linux-x86_64-gnu", "new", render_new) }
        fn old() -> PackageRef<Old> { package_ref(recipe_ref(recipe), "1", "minimal", "linux-x86_64-musl", "old", render_old) }
        fn recipe() -> Recipe { Recipe { package = Package { id = "nginx"; dependencies = []; }; } }
        fn render_new(settings: New) -> ConfigText { "" } fn render_old(settings: Old) -> ConfigText { "" }
        fn configure<C>(package: PackageRef<C>, settings: C) -> ConfigText { package_config(package, settings) }
    "#.split_whitespace().collect::<Vec<_>>().join(" ");
    let text = format!(
        r#"{declaration} let packages = forPlatform({{ system = "linux-x86_64"; libc = "gnu"; }}); let selected = packages.nginx {{ version = "2"; }}; outputs {{ config: ConfigText = configure(selected, {{  }}); }}"#
    );
    let mut sources = SourceSet::new();
    // Use the bundled std as authenticated sources, as the LSP does.
    sources.add_standard_library("std.srx", "mod std { pub value PackagePinText(str); pub value ConfigText(str); pub struct Recipe { package: Package; } pub struct Package { id: PackagePinText; dependencies: [PackagePinText]; } pub struct PackageRef<T> { factory: fn() -> Recipe; } pub fn recipe_ref(factory: fn() -> Recipe) -> fn() -> Recipe { factory } pub fn package_ref<T>(factory: fn() -> Recipe, version: PackagePinText, variant: PackagePinText, system: PackagePinText, contract: PackagePinText, render: fn(T) -> ConfigText) -> PackageRef<T> { PackageRef<T> { factory = factory; } } pub fn package_config<T>(package: PackageRef<T>, settings: T) -> ConfigText { \"\" } }").unwrap();
    let source = sources.add("main.srx", text.as_str()).unwrap();
    let (host, bindings) = host_for(&sources);
    let analysis = host
        .snapshot()
        .analyze_project(
            &sources,
            &bindings,
            &CheckPolicy::default(),
            &AnalysisCancellation::default(),
        )
        .unwrap();
    assert!(
        analysis.diagnostics().is_empty(),
        "{:?}",
        analysis.diagnostics()
    );
    let offset = u32::try_from(text.rfind("{  }").unwrap()).unwrap();
    let ty = analysis
        .expression_at(source, offset)
        .unwrap()
        .ty();
    let fields = analysis.construction_fields_at(source, offset + 2, ty);
    assert_eq!(
        fields
            .iter()
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>(),
        ["listen", "proxyPass"],
        "type {ty:?}, expression {:?}",
        analysis.expression_at(source, offset)
    );
}

#[test]
fn callback_body_edits_refresh_global_effect_diagnostics_and_preserve_old_snapshots() {
    let text = "resource R(int); value I(int); let callback = fn() -> I { let consumed = I(7); I(1) }; let answer = callback();";
    let mut sources = SourceSet::new();
    let source = sources.add("main.srx", text).unwrap();
    let (mut host, bindings) = host_for(&sources);
    let policy = CheckPolicy::default();
    let cancel = AnalysisCancellation::default();
    let before = host
        .snapshot()
        .analyze_project(&sources, &bindings, &policy, &cancel)
        .unwrap();
    assert!(
        before.diagnostics().is_empty(),
        "{:?}",
        before.diagnostics()
    );
    for (version, changed, should_fail) in [
        (1, text.replace("I(7)", "R(7)"), true),
        (2, text.to_owned(), false),
    ] {
        host.set_overlay(&bindings[&source], version, &changed)
            .unwrap();
        let after = host
            .snapshot()
            .analyze_project(&sources, &bindings, &policy, &cancel)
            .unwrap();
        assert_eq!(
            after
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic
                    .message
                    .contains("affine resource through a callback")),
            should_fail,
            "{:?}",
            after.diagnostics()
        );
        assert!(before.diagnostics().is_empty());
    }
}

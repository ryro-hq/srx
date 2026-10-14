use super::*;
use crate::{
    diagnostic::DiagnosticCode, line_index::TextPosition, syntax::SyntaxKind,
    syntax::SyntaxTokenKind,
};

#[test]
fn snapshots_keep_old_buffers_and_reuse_only_unchanged_file_analysis() {
    let mut host = AnalysisHost::default();
    host.set_disk("a.srx", "value A(int);").unwrap();
    host.set_disk("b.srx", "value B(int);").unwrap();
    let before = host.snapshot();
    let a = before.document("a.srx").unwrap();
    let b = before.document("b.srx").unwrap();
    let cancellation = AnalysisCancellation::default();
    let a_parsed = a.parsed(&cancellation).unwrap();
    let b_parsed = b.parsed(&cancellation).unwrap();
    let revision = host
        .set_overlay("a.srx", 1, "outputs { item: A = ")
        .unwrap();
    let after = host.snapshot();
    assert!(host.is_current(&revision));
    assert!(!host.is_current(&before.revision()));
    let edited = after.document("a.srx").unwrap();
    let unchanged = after.document("b.srx").unwrap();
    assert!(!std::ptr::eq(
        a_parsed,
        edited.parsed(&cancellation).unwrap()
    ));
    assert!(std::ptr::eq(
        b_parsed,
        unchanged.parsed(&cancellation).unwrap()
    ));
    assert!(a.diagnostics(&cancellation).unwrap().is_empty());
    assert!(
        !edited
            .diagnostics(&cancellation)
            .unwrap()
            .is_empty()
    );
    assert_eq!(edited.overlay_version(), Some(1));
    assert_eq!(a.overlay_version(), None);
    assert_eq!(a.source().text(), "value A(int);");
    assert_eq!(edited.revision(), after.revision());
    assert_eq!(
        edited
            .syntax_context(
                TextPosition {
                    line: 0,
                    character: 20
                },
                PositionEncoding::Utf16,
                &cancellation
            )
            .unwrap()
            .unwrap()
            .kind(),
        SyntaxKind::MissingExpression
    );
}

#[test]
fn overlays_shadow_disk_changes_and_close_reveals_the_latest_disk() {
    let mut host = AnalysisHost::default();
    host.set_disk("file.srx", "value Disk(int);")
        .unwrap();
    host.set_overlay("file.srx", 7, "value Buffer(int);")
        .unwrap();
    let buffer = host.snapshot().document("file.srx").unwrap();
    let cancellation = AnalysisCancellation::default();
    let cached = buffer.parsed(&cancellation).unwrap();
    host.set_disk("file.srx", "value Updated(int);")
        .unwrap();
    let shadowed = host.snapshot().document("file.srx").unwrap();
    assert!(std::ptr::eq(
        cached,
        shadowed.parsed(&cancellation).unwrap()
    ));
    assert_eq!(shadowed.source().text(), "value Buffer(int);");
    host.close_overlay("file.srx").unwrap();
    assert_eq!(
        host.snapshot()
            .document("file.srx")
            .unwrap()
            .source()
            .text(),
        "value Updated(int);"
    );
    host.set_overlay("file.srx", 1, "value Reopened(int);")
        .unwrap();
    host.remove_disk("file.srx").unwrap();
    assert_eq!(
        host.snapshot()
            .document("file.srx")
            .unwrap()
            .source()
            .text(),
        "value Reopened(int);"
    );
    host.close_overlay("file.srx").unwrap();
    assert!(host.snapshot().document("file.srx").is_none());
    assert_eq!(buffer.source().text(), "value Buffer(int);");
}

#[test]
fn unchanged_content_reuses_parse_but_editor_versions_still_change_publication_stamp() {
    let mut host = AnalysisHost::default();
    let first = host
        .set_disk("file.srx", "value I(int);")
        .unwrap();
    assert_eq!(
        host.set_disk("file.srx", "value I(int);")
            .unwrap(),
        first
    );
    let old = host.snapshot().document("file.srx").unwrap();
    let cancellation = AnalysisCancellation::default();
    let parsed = old.parsed(&cancellation).unwrap();
    let lines = old.line_index(&cancellation).unwrap();
    host.set_overlay("file.srx", 1, "value I(int);")
        .unwrap();
    let current = host.snapshot().document("file.srx").unwrap();
    assert!(std::ptr::eq(
        parsed,
        current.parsed(&cancellation).unwrap()
    ));
    assert!(std::ptr::eq(
        lines,
        current.line_index(&cancellation).unwrap()
    ));
    assert_ne!(first, current.revision());
    assert!(!host.is_current(&first));
    assert_eq!(
        host.set_overlay("file.srx", 1, "broken"),
        Err(AnalysisUpdateError::StaleVersion)
    );
    assert_eq!(
        host.set_overlay("file.srx", 0, "broken"),
        Err(AnalysisUpdateError::StaleVersion)
    );
    assert!(host.is_current(&current.revision()));
    host.set_overlay("file.srx", 2, "value I(int);")
        .unwrap();
    assert!(!host.is_current(&current.revision()));
    assert_eq!(
        host.snapshot()
            .document("file.srx")
            .unwrap()
            .overlay_version(),
        Some(2)
    );
}

#[test]
fn rejected_updates_are_atomic_and_input_limits_count_hidden_disk_text() {
    let mut host = AnalysisHost::new(AnalysisLimits {
        max_documents: 1,
        max_source_bytes: 30,
    });
    host.set_disk("a", "value I(int);").unwrap();
    let before = host.snapshot();
    assert_eq!(
        host.set_disk("b", ""),
        Err(AnalysisUpdateError::InputLimit)
    );
    assert_eq!(
        host.set_overlay("a", 1, &" ".repeat(31)),
        Err(AnalysisUpdateError::InputLimit)
    );
    assert_eq!(
        host.set_overlay("a", 1, &" ".repeat(crate::MAX_SOURCE_BYTES + 1)),
        Err(AnalysisUpdateError::Source(SourceError::TooLarge))
    );
    assert!(host.is_current(&before.revision()));
    host.set_overlay("a", 1, "value I(int);").unwrap();
    let overlay = host.snapshot();
    assert_eq!(
        host.set_disk("a", &" ".repeat(20)),
        Err(AnalysisUpdateError::InputLimit)
    );
    assert!(host.is_current(&overlay.revision()));
    host.close_overlay("a").unwrap();
    assert_eq!(
        host.snapshot()
            .document("a")
            .unwrap()
            .source()
            .text(),
        "value I(int);"
    );
}

#[test]
fn cancellation_is_query_control_and_does_not_poison_lazy_caches() {
    let mut host = AnalysisHost::default();
    host.set_overlay("a", 1, "fn f() { item.")
        .unwrap();
    let document = host.snapshot().document("a").unwrap();
    let cancellation = AnalysisCancellation::default();
    let other_handle = cancellation.clone();
    other_handle.cancel();
    assert!(matches!(
        document.parsed(&cancellation),
        Err(AnalysisCancelled)
    ));
    assert!(matches!(
        document.line_index(&cancellation),
        Err(AnalysisCancelled)
    ));
    assert!(document.document.analysis.parsed.get().is_none());
    assert!(document.document.analysis.lines.get().is_none());
    let active = AnalysisCancellation::default();
    let diagnostics = document.diagnostics(&active).unwrap();
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::ExpectedToken)
    );
    let position = TextPosition {
        line: 0,
        character: 14,
    };
    assert_eq!(
        document
            .syntax_context(position, PositionEncoding::Utf16, &active)
            .unwrap()
            .unwrap()
            .kind(),
        SyntaxKind::MissingToken(SyntaxTokenKind::Ident)
    );
    assert!(matches!(
        document.diagnostics(&cancellation),
        Err(AnalysisCancelled)
    ));
    assert!(document.parsed(&active).is_ok());
}

#[test]
fn independent_hosts_cannot_accept_each_others_revision_and_shared_queries_are_thread_safe() {
    let mut host = AnalysisHost::default();
    let foreign = AnalysisHost::default();
    assert!(!host.is_current(&foreign.snapshot().revision()));
    host.set_disk("a", "value I(int);").unwrap();
    let document = host.snapshot().document("a").unwrap();
    let cancellation = AnalysisCancellation::default();
    std::thread::scope(|scope| {
        let first = scope.spawn(|| document.parsed(&cancellation).unwrap());
        let second = scope.spawn(|| document.parsed(&cancellation).unwrap());
        assert!(std::ptr::eq(
            first.join().unwrap(),
            second.join().unwrap()
        ));
    });
    drop(host);
    assert!(
        document
            .diagnostics(&cancellation)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn signatures_survive_broken_bodies_and_keep_lexical_modules_and_generic_types() {
    let mut host = AnalysisHost::default();
    let source =
        "mod pkg { pub fn make<T>(item: T) -> T { item. } fn stable() {} } fn outside() {}";
    host.set_overlay("main.srx", 1, source).unwrap();
    let broken = host.snapshot().document("main.srx").unwrap();
    let cancellation = AnalysisCancellation::default();
    let signatures: Vec<_> = broken
        .function_signatures(&cancellation)
        .unwrap()
        .collect();
    assert_eq!(
        signatures
            .iter()
            .map(|signature| signature.name.text.as_str())
            .collect::<Vec<_>>(),
        ["make", "stable", "outside"]
    );
    assert_eq!(&*signatures[0].module, ["pkg"]);
    assert!(signatures[0].public);
    assert_eq!(signatures[0].type_parameters.len(), 1);
    assert_eq!(signatures[0].parameters.len(), 1);
    assert!(signatures[0].result.is_some());
    assert!(!signatures[1].public);
    assert_eq!(&*signatures[1].module, ["pkg"]);
    assert!(signatures[2].module.is_empty());
    assert_eq!(
        &source[signatures[0].span.range()],
        "pub fn make<T>(item: T) -> T"
    );
    assert!(
        broken
            .parsed(&cancellation)
            .unwrap()
            .clone()
            .into_program()
            .is_err()
    );
    let fixed = source.replace("item.", "item");
    host.set_overlay("main.srx", 2, &fixed).unwrap();
    let current = host.snapshot().document("main.srx").unwrap();
    let updated: Vec<_> = current
        .function_signatures(&cancellation)
        .unwrap()
        .collect();
    assert_eq!(signatures[0], updated[0]);
    assert!(!host.is_current(&broken.revision()));
    assert!(
        current
            .diagnostics(&cancellation)
            .unwrap()
            .is_empty()
    );
    // Following declarations get positions from the new source, not stale
    // locations reused merely because their header text did not change.
    assert_eq!(
        signatures[2].span.start(),
        updated[2].span.start() + 1
    );
}

#[test]
fn malformed_headers_are_not_indexed_and_unsaved_documents_need_no_disk_entry() {
    let mut host = AnalysisHost::default();
    host.set_overlay(
        "untitled:test",
        0,
        "fn broken(item:) {} fn good() {}",
    )
    .unwrap();
    let snapshot = host.snapshot();
    assert_eq!(
        snapshot.document_names().collect::<Vec<_>>(),
        ["untitled:test"]
    );
    let document = snapshot.document("untitled:test").unwrap();
    let cancellation = AnalysisCancellation::default();
    assert_eq!(
        document
            .function_signatures(&cancellation)
            .unwrap()
            .map(|signature| signature.name.text.as_str())
            .collect::<Vec<_>>(),
        ["good"]
    );
    host.close_overlay("untitled:test").unwrap();
    assert_eq!(host.snapshot().document_names().len(), 0);
    assert!(
        !document
            .diagnostics(&cancellation)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn unicode_editor_cursor_and_diagnostics_share_the_same_revision_and_ranges() {
    let source = "outputs { x: S = S(\"😀\"); y: I = ; }";
    let mut host = AnalysisHost::default();
    host.set_overlay("unicode.srx", 1, source)
        .unwrap();
    let document = host.snapshot().document("unicode.srx").unwrap();
    let cancellation = AnalysisCancellation::default();
    let error = document
        .diagnostics(&cancellation)
        .unwrap()
        .iter()
        .find(|error| error.code == DiagnosticCode::ExpectedExpression)
        .unwrap();
    let lines = document.line_index(&cancellation).unwrap();
    let position = lines
        .position(error.span.start(), PositionEncoding::Utf16)
        .unwrap();
    assert_eq!(position.character + 2, error.span.start());
    assert_eq!(
        document
            .syntax_context(position, PositionEncoding::Utf16, &cancellation)
            .unwrap()
            .unwrap()
            .kind(),
        SyntaxKind::MissingExpression
    );
    assert!(host.is_current(&document.revision()));
    host.set_overlay(
        "unicode.srx",
        2,
        &source.replace("= ;", "= I(1);"),
    )
    .unwrap();
    assert!(!host.is_current(&document.revision()));
    assert_eq!(
        lines.offset(position, PositionEncoding::Utf16),
        Some(error.span.start())
    );
}

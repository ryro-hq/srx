use super::*;

#[test]
fn global_callback_effects_are_reported_before_evaluation_with_the_call_path() {
    let source = "resource R(int); value I(int); let callback = fn() -> I { let consumed = R(7); I(1) }; fn invoke(f: fn() -> I) -> I { f() } let answer = invoke(callback); outputs { result: I = I(0); }";
    let diagnostics = check(resolved(source), &CheckPolicy::default()).unwrap_err();
    let diagnostic = diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                .contains("affine resource through a callback")
        })
        .unwrap();
    assert_eq!(
        diagnostic.span.start() as usize,
        source.find("invoke(callback)").unwrap()
    );
    let path = diagnostic.note.as_ref().unwrap();
    assert!(path.contains("answer -> invoke -> f"), "{path}");
    assert!(path.contains('R'), "{path}");
    assert!(
        diagnostic
            .related
            .iter()
            .any(|related| related.span.start() as usize == source.find("R(7)").unwrap())
    );
    assert!(
        diagnostic
            .related
            .iter()
            .any(|related| related.span.start() as usize == source.find("f() }").unwrap())
    );
}

#[test]
fn global_callback_effects_follow_aliases_captures_defaults_methods_and_selected_branches() {
    let prefix = r#"mod std { pub enum Bool { False, True } } resource R(int); value I(int); value S(str);
        let bad = fn() -> I { let consumed = R(7); I(1) };
        let pure = fn() -> I { I(2) };
        fn wrap(f: fn() -> I) -> fn() -> I { fn() -> I { f() } }
        struct Box { run: fn() -> I = bad; }
        struct Empty {} impl Empty { fn invoke(receiver: Self, f: fn() -> I) -> I { f() } }
        fn selected(const mode: S, f: fn() -> I) -> I { match mode { "yes" => f(), "no" => 2 } }
    "#;
    for initializer in [
        "bad()",
        "wrap(bad)()",
        "Box {}.run()",
        "Empty {}.invoke(bad)",
        "let alias = bad; in alias()",
        "memoize(bad)()",
        "selected(\"yes\", bad)",
        "if std::Bool::True { bad() } else { pure() }",
        "match std::Bool::True { True => bad(), False => pure() }",
        "exposed()",
    ] {
        let text =
            format!("{prefix} let answer = {initializer}; outputs {{ exposed: fn() -> I = bad; }}");
        assert!(
            messages(&text)
                .iter()
                .any(|message| message.contains("affine resource through a callback")),
            "{initializer}"
        );
    }
    for initializer in [
        "pure()",
        "wrap(pure)()",
        "Box { run = pure; }.run()",
        "Empty {}.invoke(pure)",
        "memoize(pure)()",
        "selected(\"no\", bad)",
        "if std::Bool::False { bad() } else { pure() }",
        "match std::Bool::False { True => bad(), False => pure() }",
        "wrap(bad)",
        "memoize(bad)",
        "Box {}",
    ] {
        checked(&format!("{prefix} let answer = {initializer};"));
    }
}

#[test]
fn global_callback_effect_analysis_is_bounded_for_recursive_and_expanding_callbacks() {
    for text in [
        "value I(int); fn recur(f: fn() -> I) -> I { recur(f) } let callback = fn() -> I { recur(fn() -> I { I(1) }) }; let answer = callback();",
        "value I(int); fn recur(f: fn() -> I) -> I { recur(fn() -> I { f() }) } let callback = fn() -> I { recur(fn() -> I { I(1) }) }; let answer = callback();",
    ] {
        let diagnostics = check_with_limits(
            resolved(text),
            &CheckPolicy::default(),
            CheckLimits {
                max_specialization_depth: 12,
                ..CheckLimits::default()
            },
        )
        .unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("limit")),
            "{diagnostics:?}"
        );
    }
}

#[test]
fn global_callback_effects_retain_specialized_closure_facts_and_trait_dispatch() {
    let declarations = r#"
        resource R(int); value I(int); value S(str);
        trait Run { fn run(item: Self) -> I; }
        struct Pure {} struct Affine {}
        impl Run for Pure { fn run(item: Pure) -> I { 2 } }
        impl Run for Affine { fn run(item: Affine) -> I { let consumed = R(7); 1 } }
        fn wrap<T: Run>(item: T) -> fn() -> I { fn() -> I { Run::run(item) } }
        fn factory(const target: S) -> fn() -> I {
            match target { "pure" => wrap(Pure {}), "affine" => wrap(Affine {}) }
        }
    "#;
    checked(&format!(
        "{declarations} let callback = factory(\"pure\"); let answer = callback();"
    ));
    assert!(
        messages(&format!(
            "{declarations} let callback = factory(\"affine\"); let answer = callback();"
        ))
        .iter()
        .any(|message| message.contains("affine resource through a callback"))
    );
}

#[test]
fn global_callback_effects_bound_expanding_call_graphs_by_work_and_metadata() {
    use std::fmt::Write as _;
    let mut text = "value I(int); fn twice(f: fn() -> I) -> fn() -> I { fn() -> I { f(); f() } } let base = fn() -> I { I(1) }; ".to_owned();
    for index in 0..12 {
        let previous = if index == 0 {
            "base".to_owned()
        } else {
            format!("layer{}", index - 1)
        };
        write!(text, "let layer{index} = twice({previous}); ").unwrap();
    }
    text.push_str("let answer = layer11();");
    for (limits, expected) in [
        (
            CheckLimits {
                max_work: 5_000,
                ..CheckLimits::default()
            },
            "global effect analysis work limit",
        ),
        (
            CheckLimits {
                max_metadata_units: 5_000,
                ..CheckLimits::default()
            },
            "global effect analysis metadata limit",
        ),
    ] {
        let diagnostics =
            check_with_limits(resolved(&text), &CheckPolicy::default(), limits).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains(expected)),
            "{diagnostics:?}"
        );
    }
}

#[test]
fn global_effect_analysis_widens_unknown_fold_accumulators_before_following_callbacks() {
    let text = r#"
        mod std { pub enum Bool { False, True } }
        resource R(int); value I(int); value S(str);
        let key: S = "x";
        let rendered: S = "${key}";
        let items: [I] = sort_by_keys([I(1), I(2)], [rendered, rendered]);
        let bad = fn() -> I { let consumed = R(7); 0 };
        let answer = fold(items, std::Bool::False, fn(seen: std::Bool, item: I) -> std::Bool {
            if seen { bad(); std::Bool::True } else { std::Bool::True }
        });
    "#;
    assert!(
        messages(text)
            .iter()
            .any(|message| message.contains("affine resource through a callback"))
    );
}

#[test]
fn global_callback_effects_reject_once_closure_creation_only_when_invoked() {
    let declarations =
        "value I(int); let callback = fn() -> I { let f = once fn() -> I { I(1) }; f() };";
    checked(declarations);
    checked(&format!(
        "{declarations} outputs {{ result: I = callback(); }}"
    ));
    assert!(
        messages(&format!(
            "{declarations} let result = callback();"
        ))
        .iter()
        .any(|message| message.contains("affine closure through a callback"))
    );
}

#[test]
fn global_callback_text_analysis_shares_literals_and_bounds_comparison_work() {
    let calls = vec!["callback()"; 400].join(",");
    let text = format!(
        "value S(str); let callback = fn() -> S {{ S(\"{}\") }}; let texts: [S] = [{calls}];",
        "x".repeat(65_536)
    );
    check_with_limits(
        resolved(&text),
        &CheckPolicy::default(),
        CheckLimits {
            max_work: 100_000,
            max_metadata_units: 10_000,
            ..CheckLimits::default()
        },
    )
    .unwrap();
    let calls = vec!["callback()"; 64].join(",");
    let text = format!(
        "mod std {{ pub enum Bool {{ False, True }} }} value S(str); let left: S = \"{}\"; let right: S = \"{}\"; let callback = fn() -> std::Bool {{ left == right }}; let flags: [std::Bool] = [{calls}];",
        "x".repeat(8_192),
        "x".repeat(8_192)
    );
    let diagnostics = check_with_limits(
        resolved(&text),
        &CheckPolicy::default(),
        CheckLimits {
            max_work: 100_000,
            ..CheckLimits::default()
        },
    )
    .unwrap_err();
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("global effect analysis work limit")),
        "{diagnostics:?}"
    );
}

#[test]
fn global_callback_folds_preserve_known_list_alternatives_and_stable_key_order() {
    let declarations = r#"
        mod std { pub enum Bool { False, True } }
        resource R(int); value I(int); value S(str);
        let bad = fn() -> I { let consumed = R(7); 0 };
        let pure = fn() -> I { 1 };
        let key: S = "x";
        let rendered: S = "${key}";
        let items: [I] = if rendered == "x" { [1] } else { [] };
        let chosen = fold(items, pure, fn(acc: fn() -> I, item: I) -> fn() -> I { acc });
        let answer = chosen();
    "#;
    checked(declarations);
    for (items, keys, affine) in [
        (
            "bad, pure, pure",
            "S(\"a\"), S(\"b\"), S(\"c\")",
            false,
        ),
        (
            "bad, pure, pure",
            "S(\"z\"), S(\"b\"), S(\"c\")",
            true,
        ),
        ("bad, pure", "S(\"a\"), S(\"a\")", false),
        ("pure, bad", "S(\"a\"), S(\"a\")", true),
    ] {
        let source = format!(
            "{declarations} let sorted = sort_by_keys([{items}], [{keys}]); let last = fold(sorted, pure, fn(acc: fn() -> I, item: fn() -> I) -> fn() -> I {{ item }}); let result = last();"
        );
        if affine {
            assert!(
                messages(&source)
                    .iter()
                    .any(|message| message.contains("affine resource through a callback"))
            );
        } else {
            checked(&source);
        }
    }
}

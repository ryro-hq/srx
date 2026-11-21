use super::*;

#[test]
fn ordinary_control_flow_checks_coverage_branch_types_and_affine_moves() {
    checked(
        r#"mod std { pub enum Bool { False, True } } value S(str); value I(int); fn f(x: S) -> I { if x == "yes" { 1 } else { match x { "no" => 2, _ => 3 } } }"#,
    );
    for (source, expected) in [
        (
            r#"value S(str); value I(int); fn f(x: S) -> I { match x { "a" => 1 } }"#,
            "not exhaustive",
        ),
        (
            r"value I(int); fn f(x: I) -> I { match x { 1 => 1, 1 => 2, _ => 3 } }",
            "more than once",
        ),
        (
            r#"mod std { pub enum Bool { False, True } } value I(int); value S(str); fn f(x: std::Bool) -> I { if x { I(1) } else { S("bad") } }"#,
            "if branch",
        ),
        (
            r"mod std { pub enum Bool { False, True } } resource R(int); fn f(b: std::Bool, r: R) -> R { if b { let used = r; } else {}; r }",
            "moved",
        ),
        (
            r"mod std { pub enum Bool { False, True } } value I(int); fn f() -> I { if 1 { 1 } else { 2 } }",
            "if condition",
        ),
    ] {
        assert!(
            messages(source)
                .iter()
                .any(|message| message.contains(expected)),
            "{source}"
        );
    }
}

#[test]
fn comparisons_join_affine_moves_and_require_ordered_matching_operands() {
    checked("resource R(int); fn pick(r: R) -> R { compare(1, 2, r, r, r) }");
    for (source, expected) in [
        (
            "resource R(int); fn bad(r: R) -> [R] { let selected = compare(1, 2, [r], [], []); selected ++ [r] }",
            "use of moved affine value",
        ),
        (
            "resource R(int); fn bad(r: R) -> R { compare(1, 2, r, r, r); r }",
            "use of moved affine value",
        ),
        (
            "value I(int); fn bad() -> I { compare(1, \"x\", I(1), I(2), I(3)) }",
            "comparison operand type mismatch",
        ),
        (
            "resource R(int); value I(int); fn bad(a: R, b: R) -> I { compare(a, b, I(1), I(2), I(3)) }",
            "comparison requires",
        ),
        (
            "value I(int); fn bad() -> I { compare([], [], I(1), I(2), I(3)) }",
            "empty list requires",
        ),
        (
            "value I(int); value S(str); fn bad() -> I { compare(1, 2, I(1), S(\"x\"), I(3)) }",
            "comparison branch type mismatch",
        ),
    ] {
        let diagnostics = messages(source);
        assert!(
            diagnostics
                .iter()
                .any(|message| message.contains(expected)),
            "{source}: {diagnostics:?}"
        );
    }
}

#[test]
fn payload_enum_patterns_are_exhaustive_scoped_and_affine() {
    for (source, expected) in [
        (
            "resource R(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<[[R]]>) -> [Maybe<[[R]]>] { [x, x] }",
            "use of moved affine value",
        ),
        (
            "value I(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<once fn() -> I>) -> [I] { match x { Some(f) => [f(), f()], None => [] } }",
            "use of moved affine value",
        ),
        (
            "resource R(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<R>) -> [R] { match x { Some(r) => [r, r], None => [] } }",
            "use of moved affine value",
        ),
        (
            "resource R(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<R>) -> [Maybe<R>] { [x, x] }",
            "use of moved affine value",
        ),
        (
            "value I(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<I>) -> [I] { match x { None => [] } }",
            "match is not exhaustive",
        ),
        (
            "value I(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<I>) -> [I] { match x { Some => [], None => [] } }",
            "pattern payload binding count mismatch",
        ),
        (
            "value I(int); enum Maybe<T> { None, Some(T) } fn bad(x: Maybe<I>) -> [I] { match x { Some(a, b) => [a], None => [] } }",
            "pattern payload binding count mismatch",
        ),
        (
            "value I(int); enum Maybe<T> { None, Some(T) } outputs { bad: Maybe<I> = Maybe::Some<I>(); }",
            "expected 1 argument",
        ),
        (
            "value I(int); enum Maybe<T> { None, Some(T) } outputs { bad: Maybe<I> = Maybe::Some; }",
            "payload requires a constructor",
        ),
    ] {
        assert!(
            messages(source)
                .iter()
                .any(|message| message.contains(expected)),
            "{source}"
        );
    }
}

#[test]
fn affine_values_cannot_be_reused_and_branch_moves_join() {
    checked("resource R(int); struct Phantom<T> {} fn f(x: Phantom<R>) { x; x; }");
    assert!(
        messages("resource R(int); struct Box<T> { item: T; } fn f(x: Box<R>) { x; x; }")
            .iter()
            .any(|message| message.contains("moved affine"))
    );
    assert!(
        messages("resource R(int); fn f(x: R) { x; x; }")
            .iter()
            .any(|message| message.contains("moved affine"))
    );
    let errors = messages(
        "resource R(int); enum E { A, B } fn take(x: R) {} fn nothing() {} fn f(e: E, x: R) { match e { A => take(x), B => nothing() }; take(x); }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("moved affine"))
    );
}

#[test]
fn direct_calls_cannot_copy_affine_outputs_or_call_plain_values() {
    let errors = messages(
        "value I(int); outputs { factory: once fn() -> I = once fn() -> I { I(1) }; bad: I = factory(); }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("value output cannot carry an affine resource")),
        "{errors:?}"
    );
    let errors = messages("value I(int); outputs { number: I = I(1); bad: I = number(); }");
    assert!(
        errors
            .iter()
            .any(|message| message.contains("callee is not a function value")),
        "{errors:?}"
    );
}

use super::*;

#[test]
fn contextual_variants_literals_and_empty_lists_are_elaborated() {
    let program = checked(
        "value Name(str); enum Mode { Fast, Slow } struct C { name: Name; modes: [Mode]; } outputs { c: C = C { name = \"x\"; modes = [Fast, Slow]; }; }",
    );
    assert!(program.expressions().any(|expression| matches!(
        expression.elaboration(),
        Some(Elaboration::ValueLiteral(_))
    )));
    assert_eq!(
        program
            .expressions()
            .filter(|expression| matches!(
                expression.elaboration(),
                Some(Elaboration::ContextualVariant { .. })
            ))
            .count(),
        2
    );
    checked("enum E { A } outputs { values: [E] = []; }");
    assert!(
        messages("fn f() { []; }")
            .iter()
            .any(|message| message.contains("empty list requires"))
    );
}

#[test]
fn calls_structs_returns_and_outputs_must_match_exactly() {
    let errors = messages(
        "value V(str); struct S { v: V; } fn make(v: V) -> S { S { v = 1; extra = v; } } outputs { bad: V = make(\"x\"); }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("struct field type mismatch"))
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("unknown field"))
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("output value type mismatch"))
    );

    assert!(
        messages("value V(str); fn f(x: V) -> V { 1 }")
            .iter()
            .any(|message| message.contains("function return type mismatch"))
    );
}

#[test]
fn match_requires_unique_reachable_exhaustive_homogeneous_arms() {
    let errors =
        messages("value I(int); enum E { A, B } fn f(e: E) -> I { match e { A => 1, A => 2 } }");
    assert!(
        errors
            .iter()
            .any(|message| message.contains("more than once"))
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("not exhaustive"))
    );
    assert!(
        messages("value I(int); enum E { A } fn f(e: E) -> I { match e { _ => 1, A => \"x\" } }")
            .iter()
            .any(|message| message.contains("unreachable"))
    );
}

#[test]
fn contextual_match_patterns_are_validated_and_recorded() {
    let errors = messages(
        "enum E { A } enum Other { Bogus } fn f(e: E) -> E { match e { Bogus => E::A, _ => E::A } }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("enum has no variant `Bogus`"))
    );

    let program = checked("enum E { A } fn f(e: E) -> E { match e { A => E::A } }");
    let pattern = program.patterns().next().unwrap();
    assert_eq!(pattern.index(), 0);
}

#[test]
fn declared_return_type_elaborates_function_tails() {
    checked(
        "enum E { A } value V(int); fn enum_value() -> E { A } fn wrapped() -> V { 1 } fn empty() -> [E] { [] }",
    );
}

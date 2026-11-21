use super::*;

#[test]
fn function_value_signature_and_callee_are_checked() {
    assert!(messages("value I(int); value S(str); fn id(x: I) -> I { x } fn use_it(f: fn(S) -> S) -> S { f(S(\"ok\")) } outputs { bad: S = use_it(id); }")
        .iter().any(|message| message.contains("call argument type mismatch")));
    assert!(
        messages("value I(int); fn bad(x: I) -> I { x(I(2)) }")
            .iter()
            .any(|message| message.contains("callee is not a function value"))
    );
}

#[test]
fn consumable_closures_move_captures_and_cannot_be_called_twice() {
    for source in [
        "resource R(int); fn bad(r: R) -> R { let f = once fn() -> R { r }; r }",
        "resource R(int); fn bad(r: R) -> [R] { let f = once fn() -> R { r }; [f(), f()] }",
        "resource R(int); fn bad(r: R) -> [R] { let moved = r; let f = once fn() -> R { r }; [moved, f()] }",
        "resource R(int); struct H { deferred: once fn() -> R; } fn bad(h: H) -> [H] { [h, h] }",
        "resource R(int); fn bad(r: R) -> fn() -> R { once fn() -> R { r } }",
        "resource R(int); fn bad(r: R) -> [R] { fold([r], [], once fn(acc: [R], x: R) -> [R] { acc ++ [x] }) }",
    ] {
        assert!(!messages(source).is_empty(), "{source}");
    }
}

#[test]
fn function_list_element_signature_must_match() {
    assert!(messages(
        "value I(int); value S(str); fn id(x: I) -> I { x } outputs { bad: [fn(S) -> S] = [id]; }"
    ).iter().any(|message| message.contains("type mismatch")));
    check(
        resolved("value I(int); outputs { good: [[I]] = [[I(1)], []]; }"),
        &CheckPolicy::default(),
    )
    .unwrap();
    assert!(messages("resource R(int); struct Holder { items: [[R]]; } fn bad(h: Holder) -> Holder { let first = h; h }")
        .iter().any(|message| message.contains("use of moved affine value")));
}

#[test]
fn closure_rejects_affine_capture_and_checks_return_type() {
    assert!(
        messages("resource R(int); fn bad(r: R) -> fn() -> R { fn() -> R { r } }")
            .iter()
            .any(|message| message.contains("closure cannot capture an affine value"))
    );
    assert!(
        messages(
            "value I(int); value S(str); fn bad() -> fn() -> I { fn() -> I { S(\"wrong\") } }"
        )
        .iter()
        .any(|message| message.contains("closure return type mismatch"))
    );
}

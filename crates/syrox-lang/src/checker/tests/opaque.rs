use super::*;

#[test]
fn opaque_construction_rejects_a_different_authenticated_domain() {
    let mut sources = SourceSet::new();
    sources
        .add_standard_library(
            "std.srx",
            "mod std { opaque struct Secret {} outputs { type Secret = Secret; } }",
        )
        .unwrap();
    sources
        .add(
            "main.srx",
            "outputs { bad: std::Secret = std::Secret {}; }",
        )
        .unwrap();
    let errors = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap_err();
    assert!(errors.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("opaque struct constructor")
    }));
}

#[test]
fn opaque_fields_are_private_through_aliases_projection_chains_and_interpolation() {
    for body in [
        "fn leak(item: vault::Secret<I>) -> I { item.payload }",
        "type Alias = vault::Secret<I>; fn leak(item: Alias) -> I { item.payload }",
        "struct Holder { hidden: vault::Secret<I>; } fn leak(item: Holder) -> I { item.hidden.payload }",
        "fn leak(item: vault::Secret<I>) -> S { S(\"${item.payload}\") }",
        "mod impostor { pub use vault::Secret; fn leak(item: Secret<I>) -> I { item.payload } }",
    ] {
        let source = format!(
            r"
            value I(int); value S(str);
            mod vault {{
                pub opaque struct Secret<T> {{ payload: T; }}
                pub fn reveal<T>(item: Secret<T>) -> T {{ item.payload }}
                mod nested {{ fn reveal<T>(item: Secret<T>) -> T {{ item.payload }} }}
            }}
            {body}
        "
        );
        let errors = messages(&source);
        assert!(
            errors
                .iter()
                .any(|message| message.contains("opaque struct fields are private")),
            "{errors:?}"
        );
        assert_eq!(
            errors
                .iter()
                .filter(|message| message.contains("opaque struct fields are private"))
                .count(),
            1
        );
    }
}

#[test]
fn opaque_representation_authority_is_lexical_or_explicitly_delegated() {
    check(
        resolved(
            r"
        value I(int);
        mod vault {
            pub opaque struct Secret<owner O> { payload: I; }
            pub fn reveal(item: Secret<agent::Owner>) -> I { item.payload }
        }
        mod agent {
            pub struct Owner {}
            pub fn make() -> vault::Secret<Owner> { vault::Secret<Owner> { payload = I(1); } }
            pub fn reveal(item: vault::Secret<Owner>) -> I { item.payload }
        }
        outputs { result: I = vault::reveal(agent::make()); }
    ",
        ),
        &CheckPolicy::default(),
    )
    .unwrap();
}

#[test]
fn opaque_field_access_cannot_be_obtained_by_reexporting_an_authenticated_type() {
    let mut sources = SourceSet::new();
    sources
        .add_standard_library(
            "std.srx",
            r"
        mod std {
            pub value I(int);
            pub opaque struct Secret { payload: I; }
            pub fn reveal(item: Secret) -> I { item.payload }
        }
    ",
        )
        .unwrap();
    sources
        .add(
            "main.srx",
            r"
        pub use std::Secret;
        fn valid(item: Secret) -> std::I { std::reveal(item) }
        fn invalid(item: Secret) -> std::I { item.payload }
    ",
        )
        .unwrap();
    let errors = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &CheckPolicy::default(),
    )
    .unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0]
            .message
            .contains("opaque struct fields are private")
    );
}

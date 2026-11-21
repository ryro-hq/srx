use super::*;

fn identity(path: &str) -> CanonicalItemIdentity {
    CanonicalItemIdentity::new(SourceDomainId::project(), path.split("::")).unwrap()
}

#[test]
fn refinements_are_validated_against_closed_policy_data() {
    let policy = CheckPolicy::new("test")
        .unwrap()
        .with_scope("net")
        .unwrap()
        .with_predicate("path::clean", PrimitiveType::Str)
        .unwrap();
    let errors = check(
            resolved(
                "resource Mixed(int) where in [1, \"x\"]; resource Bad(str) where 2..2; value V(str) in net; value P(int) where path::clean(self);",
            ),
            &policy,
        )
        .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("homogeneous"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("only refine `int`"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("ownership scope"))
    );
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("wrong primitive"))
    );
}

#[test]
fn erasure_is_explicitly_policy_controlled() {
    let source = "struct Public { n: N; } value N(int); struct Box<T> { n: N; hidden: T; } outputs { p: Public = erase<Public>(Box<N> { n = 1; hidden = 2; }); }";
    assert!(
        messages(source)
            .iter()
            .any(|message| message.contains("not allowed"))
    );
    check(
        resolved(source),
        &CheckPolicy::new("erase-v1")
            .unwrap()
            .with_erasure(identity("Box"), identity("Public"))
            .unwrap(),
    )
    .unwrap();
}

#[test]
fn checked_program_carries_policy_identity_and_detects_mismatch() {
    let first = CheckPolicy::new("first").unwrap();
    let program = check(resolved("struct S {}"), &first).unwrap();
    assert_eq!(program.policy_identity(), "first");
    assert!(program.require_policy(&first).is_ok());
    let mismatch = program
        .require_policy(&CheckPolicy::new("second").unwrap())
        .unwrap_err();
    assert_ne!(mismatch.checked, mismatch.supplied);
}

#[test]
fn policy_is_canonical_bounded_and_rejects_conflicts() {
    let once = CheckPolicy::new("policy")
        .unwrap()
        .with_scope("net")
        .unwrap()
        .with_predicate("p", PrimitiveType::Int)
        .unwrap();
    let duplicate = once
        .clone()
        .with_scope("net")
        .unwrap()
        .with_predicate("p", PrimitiveType::Int)
        .unwrap();
    assert_eq!(once, duplicate);
    assert_eq!(once.fingerprint(), duplicate.fingerprint());
    assert_eq!(once.predicates().count(), 1);
    assert!(matches!(
        once.with_predicate("p", PrimitiveType::Str),
        Err(PolicyError::ConflictingPredicate { .. })
    ));
    assert!(matches!(
        CheckPolicy::new("x".repeat(MAX_POLICY_BYTES + 1)),
        Err(PolicyError::TooManyBytes)
    ));

    let mut policy = CheckPolicy::new("entries").unwrap();
    for index in 0..MAX_POLICY_ENTRIES {
        policy = policy.with_scope(format!("s{index}")).unwrap();
    }
    assert_eq!(
        policy.with_scope("overflow").unwrap_err(),
        PolicyError::TooManyEntries
    );
}

#[test]
fn policy_matching_is_exact_and_erasure_authority_includes_domain() {
    let first = CheckPolicy::new("same")
        .unwrap()
        .with_scope("a")
        .unwrap();
    let second = CheckPolicy::new("same")
        .unwrap()
        .with_scope("b")
        .unwrap();
    let checked = check(resolved("struct S {}"), &first).unwrap();
    assert!(checked.require_policy(&second).is_err());

    let mut sources = SourceSet::new();
    sources
            .add_standard_library(
                "std.srx",
                "mod std { value N(int); struct Public { n: N; } struct Box<T> { n: N; hidden: T; } outputs { type N = N; type Public = Public; type BoxN = Box<N>; } }",
            )
            .unwrap();
    sources
            .add(
                "main.srx",
                "mod std { value N(int); struct Public { n: N; } struct Box<T> { n: N; hidden: T; } fn exploit() -> Public { erase<Public>(Box<N> { n = 1; hidden = 2; }) } }",
            )
            .unwrap();
    let policy = CheckPolicy::new("domain erasure")
        .unwrap()
        .with_erasure(
            CanonicalItemIdentity::new(SourceDomainId::standard_library(), ["std", "Box"]).unwrap(),
            CanonicalItemIdentity::new(
                SourceDomainId::standard_library(),
                ["std", "Public"],
            )
            .unwrap(),
        )
        .unwrap();
    let errors = check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        &policy,
    )
    .unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("erasure is not allowed"))
    );
}

use super::*;

#[test]
fn role_binding_is_comparison_data_and_owner_cannot_be_a_service() {
    let session = SessionId::parse(&"a".repeat(32)).unwrap();
    let unit = SystemdUnitName::new("syrox-owner.service").unwrap();
    let owner = AttemptBinding::new(unit.clone(), [1; 16]).unwrap();
    let pin = ContentDigest::sha256(b"role");
    assert!(
        RoleBinding::new(
            session.clone(),
            "owner",
            pin,
            pin,
            SystemdUnitName::new("syrox-service.service").unwrap(),
            owner.clone(),
            ProcessRestart::Never
        )
        .is_err()
    );
    assert!(
        RoleBinding::new(
            session,
            "daemon/main",
            pin,
            pin,
            unit,
            owner,
            ProcessRestart::Never
        )
        .is_err()
    );
}

#[test]
fn role_digest_pins_policy_and_authority_but_not_mutable_head() {
    let role = RoleBinding::new(
        SessionId::parse(&"1".repeat(32)).unwrap(),
        "service:example:main",
        ContentDigest::sha256(b"manifest"),
        ContentDigest::sha256(b"command"),
        SystemdUnitName::new("syrox-example.service").unwrap(),
        AttemptBinding::new(
            SystemdUnitName::new("syrox-owner.service").unwrap(),
            [1; 16],
        )
        .unwrap(),
        ProcessRestart::Never,
    )
    .unwrap();
    let pin = role.digest();
    let mut record = RoleRecord::from_binding(&role, &AttemptId::parse(&"2".repeat(32)).unwrap());
    record.authorized = false;
    record.head = "3".repeat(32);
    assert_eq!(record.binding().unwrap().digest(), pin);
    let mut variants = Vec::new();
    let mut changed = role.clone();
    changed.name.push('x');
    variants.push(changed);
    let mut changed = role.clone();
    changed.command = ContentDigest::sha256(b"other command");
    variants.push(changed);
    let mut changed = role.clone();
    changed.manifest = ContentDigest::sha256(b"other manifest");
    variants.push(changed);
    let mut changed = role.clone();
    changed.session = SessionId::parse(&"4".repeat(32)).unwrap();
    variants.push(changed);
    let mut changed = role.clone();
    changed.unit = SystemdUnitName::new("syrox-other.service").unwrap();
    variants.push(changed);
    let mut changed = role.clone();
    changed.owner = AttemptBinding::new(role.owner.unit().clone(), [2; 16]).unwrap();
    variants.push(changed);
    let mut changed = role.clone();
    changed.restart =
        ProcessRestart::OnFailure(crate::execution::restart::RestartLimits::new(1, 10, 3).unwrap());
    variants.push(changed);
    for changed in variants {
        assert_ne!(changed.digest(), pin);
    }
}

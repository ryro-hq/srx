use super::*;

#[test]
fn rollback_provenance_persists_without_claiming_execution() {
    let (temp, journal, apply) = fixture();
    let cancel = Cancellation::default();
    let before = journal.snapshot(&cancel, deadline()).unwrap();
    assert_eq!(
        before.operations[&apply].kind,
        OperationKind::Apply
    );
    let bytes = before.bytes().unwrap();
    assert!(
        !String::from_utf8(bytes.clone())
            .unwrap()
            .contains("\"kind\"")
    );
    assert_eq!(
        ActivationSnapshot::parse(&bytes, &journal.installation)
            .unwrap()
            .bytes()
            .unwrap(),
        bytes
    );
    let target = pin(b"retained candidate never executed");
    let operation = journal
        .begin_pin_kind(
            target,
            Some(pin(b"generation")),
            OperationKind::Rollback,
            epoch(),
            &cancel,
            deadline(),
        )
        .unwrap();
    drop(journal);
    let journal = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
    let state = journal.snapshot(&cancel, deadline()).unwrap();
    let rollback = &state.operations[&operation];
    assert_eq!(rollback.kind, OperationKind::Rollback);
    assert_eq!(
        rollback.previous.as_deref(),
        Some(pin(b"generation").to_string().as_str())
    );
    assert_eq!(state.desired, Some(target.to_string()));
    assert!(rollback.effects.is_empty());
    assert!(state.bindings.is_empty() && state.attempts.is_empty());
    assert!(admit(&journal, "77777777777777777777777777777777").is_err());
}

#[test]
fn rollback_requires_distinct_current_selection_and_resolved_effects() {
    let (_temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    let original = journal
        .snapshot(&cancel, deadline())
        .unwrap()
        .bytes()
        .unwrap();
    for (target, expected) in [
        (pin(b"old"), None),
        (pin(b"generation"), Some(pin(b"generation"))),
        (pin(b"old"), Some(pin(b"wrong"))),
    ] {
        assert!(
            journal
                .begin_pin_kind(
                    target,
                    expected,
                    OperationKind::Rollback,
                    epoch(),
                    &cancel,
                    deadline()
                )
                .is_err()
        );
        assert_eq!(
            journal
                .snapshot(&cancel, deadline())
                .unwrap()
                .bytes()
                .unwrap(),
            original
        );
    }
    journal
        .plan_effect(
            &operation,
            "test/server",
            EffectKind::Publish,
            None,
            journal.binding_pin(),
            &cancel,
            deadline(),
        )
        .unwrap();
    assert!(
        journal
            .begin_pin_kind(
                pin(b"old"),
                Some(pin(b"generation")),
                OperationKind::Rollback,
                epoch(),
                &cancel,
                deadline()
            )
            .is_err()
    );
}

#[test]
fn wire_rejects_rollback_without_a_distinct_previous_selection() {
    let (_temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    for previous in [
        None,
        Some(pin(b"generation").to_string()),
    ] {
        let mut state = journal.snapshot(&cancel, deadline()).unwrap();
        let operation = state.operations.get_mut(&operation).unwrap();
        operation.kind = OperationKind::Rollback;
        operation.previous = previous;
        assert!(state.bytes().is_err());
        let mut bytes = b"syrox-os-activation-v1\n".to_vec();
        serde_json::to_writer(&mut bytes, &state).unwrap();
        assert!(ActivationSnapshot::parse(&bytes, &journal.installation).is_err());
    }
}

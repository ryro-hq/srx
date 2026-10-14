use super::*;

#[test]
fn abandon_preserves_authority_and_only_repeats_the_latest_withdrawal() {
    let (temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    let publication = publish(&journal, &operation);
    let admission = admit(&journal, "77777777777777777777777777777777").unwrap();
    let before = journal.snapshot(&cancel, deadline()).unwrap();
    let old_bytes = before.bytes().unwrap();
    assert!(
        !String::from_utf8(old_bytes.clone())
            .unwrap()
            .contains("abandoned")
    );
    assert_eq!(
        ActivationSnapshot::parse(&old_bytes, &journal.installation)
            .unwrap()
            .bytes()
            .unwrap(),
        old_bytes
    );
    assert_eq!(
        journal
            .abandon(&operation, &cancel, deadline())
            .unwrap(),
        pin(b"generation")
    );
    drop(journal);
    let journal = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
    let after = journal.snapshot(&cancel, deadline()).unwrap();
    assert!(after.desired.is_none() && after.active_operation.is_none());
    assert!(after.operations[&operation].abandoned);
    assert_eq!(
        serde_json::to_value(&before.bindings).unwrap(),
        serde_json::to_value(&after.bindings).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&before.attempts).unwrap(),
        serde_json::to_value(&after.attempts).unwrap()
    );
    assert!(
        journal
            .record_observed(
                &operation,
                &publication,
                journal.binding_pin(),
                None,
                &cancel,
                deadline()
            )
            .is_err()
    );
    assert!(
        journal
            .record_unknown(&operation, &publication, &cancel, deadline())
            .is_err()
    );
    assert!(
        journal
            .record_accepted(
                &operation,
                &publication,
                "/job/1",
                &cancel,
                deadline()
            )
            .is_err()
    );
    assert!(
        journal
            .plan_effect(
                &operation,
                "new",
                EffectKind::Publish,
                None,
                pin(b"new"),
                &cancel,
                deadline()
            )
            .is_err()
    );
    journal
        .abandon(&operation, &cancel, deadline())
        .unwrap();
    // A previously authorized attempt remains valid: abandonment is not revocation.
    journal
        .with_consumed_start(admission, &cancel, deadline(), || Ok(()))
        .unwrap();
    let next = journal
        .begin_pin(pin(b"next"), None, epoch(), &cancel, deadline())
        .unwrap();
    assert!(
        journal
            .abandon(&operation, &cancel, deadline())
            .is_err()
    );
    journal
        .abandon(&next, &cancel, deadline())
        .unwrap();
    assert!(
        journal
            .abandon(&operation, &cancel, deadline())
            .is_err()
    );
    journal
        .abandon(&next, &cancel, deadline())
        .unwrap();
}

#[test]
fn unresolved_effects_prevent_abandonment_and_malformed_abandoned_states_fail_closed() {
    for phase in 0..3 {
        let (_temp, journal, operation) = fixture();
        let cancel = Cancellation::default();
        let effect = journal
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
        if phase == 1 {
            journal
                .record_unknown(&operation, &effect, &cancel, deadline())
                .unwrap();
        }
        if phase == 2 {
            journal
                .record_accepted(&operation, &effect, "/job/1", &cancel, deadline())
                .unwrap();
        }
        assert!(
            journal
                .abandon(&operation, &cancel, deadline())
                .is_err()
        );
        let mut state = journal.snapshot(&cancel, deadline()).unwrap();
        state
            .operations
            .get_mut(&operation)
            .unwrap()
            .abandoned = true;
        state.active_operation = None;
        state.desired = None;
        state.last_abandoned = Some(operation.clone());
        assert!(state.bytes().is_err());
    }
    let (_temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    let mut state = journal.snapshot(&cancel, deadline()).unwrap();
    state
        .operations
        .get_mut(&operation)
        .unwrap()
        .abandoned = true;
    assert!(state.bytes().is_err());
    state.active_operation = None;
    state.desired = None;
    assert!(state.bytes().is_err());
    state.last_abandoned = Some(operation.clone());
    assert!(state.bytes().is_ok());
    state.last_abandoned = Some("88888888888888888888888888888888".into());
    assert!(state.bytes().is_err());
}

#[test]
fn publication_not_applied_can_be_abandoned_without_authorization() {
    let (_temp, journal, operation) = fixture();
    let cancel = Cancellation::default();
    let effect = journal
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
    journal
        .record_not_applied(&operation, &effect, &cancel, deadline())
        .unwrap();
    journal
        .abandon(&operation, &cancel, deadline())
        .unwrap();
    assert!(
        journal
            .snapshot(&cancel, deadline())
            .unwrap()
            .bindings
            .is_empty()
    );
    assert!(admit(&journal, "77777777777777777777777777777777").is_err());
}

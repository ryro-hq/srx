use super::*;

fn intent(journal: &ActivationJournal, operation: &str, kind: EffectKind) -> String {
    journal
        .plan_effect(
            operation,
            "test/server",
            kind,
            None,
            journal.binding_pin(),
            &Cancellation::default(),
            deadline(),
        )
        .unwrap()
}

#[test]
fn terminal_publication_survives_reopen_without_granting_authorization() {
    for unknown in [false, true] {
        let (temp, journal, operation) = fixture();
        let cancel = Cancellation::default();
        let effect = intent(&journal, &operation, EffectKind::Publish);
        if unknown {
            journal
                .record_unknown(&operation, &effect, &cancel, deadline())
                .unwrap();
        }
        journal
            .record_not_applied(&operation, &effect, &cancel, deadline())
            .unwrap();
        drop(journal);
        let journal = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
        assert_eq!(
            journal
                .snapshot(&cancel, deadline())
                .unwrap()
                .operations[&operation]
                .effects[&effect]
                .state,
            EffectState::NotApplied
        );
        assert!(
            journal
                .authorize_binding(
                    &operation,
                    &effect,
                    &journal.binding(),
                    &cancel,
                    deadline()
                )
                .is_err()
        );
        assert!(admit(&journal, "77777777777777777777777777777777").is_err());
        assert!(
            journal
                .record_unknown(&operation, &effect, &cancel, deadline())
                .is_err()
        );
        assert!(
            journal
                .record_accepted(&operation, &effect, "/job/1", &cancel, deadline())
                .is_err()
        );
        assert!(
            journal
                .record_observed(
                    &operation,
                    &effect,
                    journal.binding_pin(),
                    None,
                    &cancel,
                    deadline()
                )
                .is_err()
        );
        assert!(
            journal
                .record_not_applied(&operation, &effect, &cancel, deadline())
                .is_err()
        );
        journal
            .begin_pin(
                pin(b"next"),
                Some(pin(b"generation")),
                epoch(),
                &cancel,
                deadline(),
            )
            .unwrap();
        assert!(
            journal
                .record_not_applied(&operation, &effect, &cancel, deadline())
                .is_err()
        );
    }
}

#[test]
fn only_unaccepted_unobserved_publication_can_be_not_applied() {
    let cancel = Cancellation::default();
    for kind in [
        EffectKind::Reload,
        EffectKind::Start,
        EffectKind::Stop,
    ] {
        let (_temp, journal, operation) = fixture();
        let effect = intent(&journal, &operation, kind);
        assert!(
            journal
                .record_not_applied(&operation, &effect, &cancel, deadline())
                .is_err()
        );
        let mut state = journal.snapshot(&cancel, deadline()).unwrap();
        state
            .operations
            .get_mut(&operation)
            .unwrap()
            .effects
            .get_mut(&effect)
            .unwrap()
            .state = EffectState::NotApplied;
        assert!(state.bytes().is_err());
        let mut invalid_wire = b"syrox-os-activation-v1\n".to_vec();
        serde_json::to_writer(&mut invalid_wire, &state).unwrap();
        assert!(ActivationSnapshot::parse(&invalid_wire, &journal.installation).is_err());
    }
    for accepted in [false, true] {
        let (_temp, journal, operation) = fixture();
        let effect = intent(&journal, &operation, EffectKind::Publish);
        if accepted {
            journal
                .record_accepted(&operation, &effect, "/job/1", &cancel, deadline())
                .unwrap();
        } else {
            journal
                .record_observed(
                    &operation,
                    &effect,
                    journal.binding_pin(),
                    None,
                    &cancel,
                    deadline(),
                )
                .unwrap();
        }
        assert!(
            journal
                .record_not_applied(&operation, &effect, &cancel, deadline())
                .is_err()
        );
    }
}

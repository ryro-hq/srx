use super::{Event, Settlement, State, Stop};

#[test]
fn aborted_stop_neither_restores_nor_changes_job_state() {
    for previous in [
        Stop::Running,
        Stop::Preparing {
            pause: 1,
            signal: libc::SIGTSTP,
        },
        Stop::Internal(1),
        Stop::External,
    ] {
        let mut state = State {
            executed: true,
            aborted: true,
            stop: previous,
            ..State::default()
        };
        assert_eq!(state.observe_stop(libc::SIGTSTP).unwrap(), None);
        assert!(
            state
                .ack_pause(1, || panic!(
                    "restore before namespace settlement"
                ))
                .is_err()
        );
        assert_eq!(state.stop, previous);
        assert!(state.settlement == Settlement::Active);
        assert!(state.exit.is_none());
    }
}

#[test]
fn live_stop_requires_exact_relay_ack_before_restoring_and_cannot_replay() {
    let mut state = State::default();
    assert_eq!(
        state.observe_stop(libc::SIGTSTP).unwrap(),
        Some(Event::StopPreparing {
            pause: 1,
            signal: libc::SIGTSTP
        })
    );
    assert_eq!(
        state.stop,
        Stop::Preparing {
            pause: 1,
            signal: libc::SIGTSTP
        }
    );
    assert!(
        state
            .ack_pause(2, || panic!("mismatched ack restored"))
            .is_err()
    );
    let mut restored = false;
    assert_eq!(
        state
            .ack_pause(1, || {
                restored = true;
                Ok(())
            })
            .unwrap(),
        libc::SIGTSTP
    );
    assert!(restored);
    assert_eq!(state.stop, Stop::Internal(1));
    assert!(
        state
            .ack_pause(1, || panic!("replayed ack restored"))
            .is_err()
    );
    assert!(state.observe_stop(libc::SIGTSTP).is_err());
    assert!(state.settlement == Settlement::Active);
    state.stop = Stop::Running;
    assert_eq!(
        state.observe_stop(libc::SIGSTOP).unwrap(),
        Some(Event::StopPreparing {
            pause: 2,
            signal: libc::SIGSTOP
        })
    );
    assert!(
        state
            .ack_pause(1, || panic!("old pause restored"))
            .is_err()
    );
}

#[test]
fn fatal_signal_is_not_a_pause_and_failed_restore_cannot_grant_stop_ready() {
    let mut state = State::default();
    assert!(state.observe_stop(libc::SIGKILL).is_err());
    assert_eq!(state.stop, Stop::Running);
    state.observe_stop(libc::SIGSTOP).unwrap();
    assert!(
        state
            .ack_pause(1, || Err(std::io::Error::other("ownership lost")))
            .is_err()
    );
    assert_eq!(
        state.stop,
        Stop::Preparing {
            pause: 1,
            signal: libc::SIGSTOP
        }
    );
}

#[test]
fn watcher_failure_preserves_primary_without_claiming_restore() {
    let error = super::cleanup_failure(
        Err(std::io::Error::other("lost local channel")),
        std::io::Error::other("group wakeup failed"),
    );
    let text = error.to_string();
    assert!(text.contains("lost local channel"));
    assert!(text.contains("group wakeup failed"));
}

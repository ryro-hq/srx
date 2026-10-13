use std::io;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct PauseState {
    sequence: u64,
    phase: Phase,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Phase {
    #[default]
    Idle,
    Preparing,
    Armed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Effect {
    Abort,
    Abandon,
    Pause,
    Resume,
}
impl PauseState {
    pub(super) fn register(&mut self, sequence: u64) -> io::Result<()> {
        if self.phase != Phase::Idle || self.sequence.checked_add(1) != Some(sequence) {
            return Err(invalid());
        }
        self.sequence = sequence;
        self.phase = Phase::Preparing;
        Ok(())
    }
    /// Pure protocol validation. No transition establishes descendant settlement.
    pub(super) fn transition(self, tag: u8, sequence: u64) -> io::Result<(Self, Effect)> {
        if tag == b'B' {
            return Ok((
                Self {
                    phase: Phase::Idle,
                    ..self
                },
                Effect::Abort,
            ));
        }
        if sequence != self.sequence || self.phase == Phase::Idle {
            return Err(invalid());
        }
        let (phase, effect) = match (tag, self.phase) {
            (b'P', Phase::Preparing) => (Phase::Armed, Effect::Pause),
            (b'R', Phase::Armed) => (Phase::Idle, Effect::Resume),
            (b'X', Phase::Preparing | Phase::Armed) => (Phase::Idle, Effect::Abandon),
            _ => return Err(invalid()),
        };
        Ok((
            Self {
                phase,
                ..self
            },
            effect,
        ))
    }
    pub(super) fn armed(self) -> bool {
        self.phase == Phase::Armed
    }
    pub(super) fn abort(&mut self) {
        self.phase = Phase::Idle;
    }
}
fn invalid() -> io::Error {
    io::Error::other("root control does not match stop phase")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_resume_requires_exact_registered_sequence_and_arm() {
        let mut state = PauseState::default();
        for tag in *b"PRX" {
            assert!(state.transition(tag, 0).is_err());
        }
        assert!(state.register(0).is_err());
        state.register(1).unwrap();
        assert!(state.register(2).is_err());
        assert!(state.transition(b'R', 1).is_err());
        for tag in *b"PRX" {
            assert!(state.transition(tag, 2).is_err());
        }
        let (armed, effect) = state.transition(b'P', 1).unwrap();
        assert_eq!(effect, Effect::Pause);
        assert!(armed.armed());
        assert!(armed.transition(b'P', 1).is_err());
        let (mut idle, effect) = armed.transition(b'R', 1).unwrap();
        assert_eq!(effect, Effect::Resume);
        assert!(!idle.armed());
        for tag in *b"PRX" {
            assert!(idle.transition(tag, 1).is_err());
        }
        assert!(idle.register(1).is_err());
        idle.register(2).unwrap();
    }
    #[test]
    fn abandon_accepts_both_phases_without_resume_or_replay() {
        let mut preparing = PauseState::default();
        preparing.register(1).unwrap();
        let armed = preparing.transition(b'P', 1).unwrap().0;
        for state in [preparing, armed] {
            let (next, effect) = state.transition(b'X', 1).unwrap();
            assert_eq!(effect, Effect::Abandon);
            assert!(!next.armed());
            assert!(next.transition(b'X', 1).is_err());
        }
    }
    #[test]
    fn abort_clears_all_phases_without_consuming_new_sequence() {
        let mut preparing = PauseState::default();
        preparing.register(1).unwrap();
        for state in [
            PauseState::default(),
            preparing,
            preparing.transition(b'P', 1).unwrap().0,
        ] {
            let (next, effect) = state.transition(b'B', 0).unwrap();
            assert_eq!(effect, Effect::Abort);
            assert!(!next.armed());
            assert_eq!(next.sequence, state.sequence);
        }
    }
    #[test]
    fn descendant_exit_does_not_change_protocol_validation() {
        // The guardian keeps this same state across obtaining its ECHILD proof;
        // only effect execution changes. In particular R before P stays invalid.
        let mut state = PauseState::default();
        state.register(1).unwrap();
        let after_exit = state;
        assert!(after_exit.transition(b'R', 1).is_err());
        let (armed, _) = after_exit.transition(b'P', 1).unwrap();
        assert!(armed.armed());
        assert_eq!(
            armed.transition(b'R', 1).unwrap().1,
            Effect::Resume
        );
        assert_eq!(
            armed.transition(b'X', 1).unwrap().1,
            Effect::Abandon
        );
    }
}

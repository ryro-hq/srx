use std::io;
use std::process::ExitStatus;

use super::super::launch_contract::RootEvent;

#[derive(Default)]
pub(super) struct RootProgress {
    sequence: u64,
    phase: Phase,
    status: Option<ExitStatus>,
    pause_pending: bool,
}
#[derive(Default)]
enum Phase {
    #[default]
    Running,
    Preparing(i32),
    AwaitResume,
    AwaitContinued,
    Finished,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    PauseRelay(u64),
    Suspend {
        sequence: u64,
        signal: i32,
    },
    None,
}
impl RootProgress {
    /// A successfully sent resume ends the frontend's pending-stop obligation.
    /// Only then may the monitor report continuation; exit remains valid.
    pub(super) fn resume_sent(&mut self, sequence: u64) -> io::Result<()> {
        if sequence != self.sequence
            || !matches!(self.phase, Phase::AwaitResume)
            || !self.pause_pending
        {
            return Err(invalid());
        }
        self.pause_pending = false;
        self.phase = Phase::AwaitContinued;
        Ok(())
    }
    /// Retire only frontend job control, never descendant cleanup authority.
    /// Preserve this obligation across Exited until the guardian is notified.
    pub(super) fn abandon_pause(&mut self) -> Option<u64> {
        std::mem::take(&mut self.pause_pending).then_some(self.sequence)
    }
    /// Observe all immediately available events before applying job control:
    /// an already queued exit must prevent suspension of the frontend.
    pub(super) fn drain(
        &mut self,
        mut receive: impl FnMut() -> io::Result<Option<RootEvent>>,
    ) -> io::Result<Action> {
        let mut action = Action::None;
        for _ in 0..4096 {
            if self.status.is_some() {
                return Ok(Action::None);
            }
            let Some(event) = receive()? else {
                return Ok(action);
            };
            action = self.accept(event)?;
        }
        Err(io::Error::other(
            "root event drain limit exceeded",
        ))
    }

    pub(super) fn status(&self) -> Option<ExitStatus> {
        self.status
    }

    pub(super) fn accept(&mut self, event: RootEvent) -> io::Result<Action> {
        if matches!(self.phase, Phase::Finished) {
            return Err(invalid());
        }
        match event {
            RootEvent::Stopping {
                sequence,
                signal,
            } => {
                if !matches!(self.phase, Phase::Running)
                    || sequence != self.sequence.checked_add(1).ok_or_else(invalid)?
                    || sequence == u64::MAX
                {
                    return Err(invalid());
                }
                self.sequence = sequence;
                self.pause_pending = true;
                self.phase = Phase::Preparing(signal);
                Ok(Action::PauseRelay(sequence))
            }
            RootEvent::Stopped {
                sequence,
                signal,
            } => {
                if sequence != self.sequence
                    || !matches!(self.phase, Phase::Preparing(expected) if signal == expected)
                {
                    return Err(invalid());
                }
                self.phase = Phase::AwaitResume;
                Ok(Action::Suspend {
                    sequence,
                    signal,
                })
            }
            RootEvent::Continued {
                sequence,
            } => {
                if sequence != self.sequence || !matches!(self.phase, Phase::AwaitContinued) {
                    return Err(invalid());
                }
                self.phase = Phase::Running;
                self.pause_pending = false;
                Ok(Action::None)
            }
            RootEvent::Exited(status) => {
                self.status = Some(status);
                self.phase = Phase::Finished;
                Ok(Action::None)
            }
        }
    }
}
fn invalid() -> io::Error {
    io::Error::other("root job-control sequence mismatch")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt as _;

    #[test]
    fn exit_after_resume_sent_does_not_send_a_second_pause_completion() {
        let mut root = RootProgress::default();
        assert!(root.resume_sent(1).is_err());
        root.accept(RootEvent::Stopping {
            sequence: 1,
            signal: libc::SIGTSTP,
        })
        .unwrap();
        assert!(root.resume_sent(1).is_err());
        root.accept(RootEvent::Stopped {
            sequence: 1,
            signal: libc::SIGTSTP,
        })
        .unwrap();
        assert!(root.resume_sent(2).is_err());
        root.resume_sent(1).unwrap();
        assert!(root.resume_sent(1).is_err());
        root.accept(RootEvent::Exited(ExitStatus::from_raw(
            libc::SIGKILL,
        )))
        .unwrap();
        assert_eq!(root.abandon_pause(), None);
    }

    #[test]
    fn queued_exit_prevents_suspending_frontend_for_dead_root() {
        let mut root = RootProgress::default();
        root.accept(RootEvent::Stopping {
            sequence: 1,
            signal: libc::SIGTSTP,
        })
        .unwrap();
        let status = ExitStatus::from_raw(libc::SIGKILL);
        let mut queue = [
            RootEvent::Stopped {
                sequence: 1,
                signal: libc::SIGTSTP,
            },
            RootEvent::Exited(status),
        ]
        .into_iter();
        assert_eq!(
            root.drain(|| Ok(queue.next())).unwrap(),
            Action::None
        );
        assert_eq!(root.status(), Some(status));
        assert_eq!(root.abandon_pause(), Some(1));
        assert_eq!(root.abandon_pause(), None);
    }

    #[test]
    fn restoration_and_continuation_cannot_skip_or_replay_pause_phases() {
        let mut root = RootProgress::default();
        let stop = RootEvent::Stopped {
            sequence: 1,
            signal: libc::SIGTSTP,
        };
        assert!(root.accept(stop).is_err());
        assert!(
            root.accept(RootEvent::Continued {
                sequence: 1
            })
            .is_err()
        );
        let preparing = RootEvent::Stopping {
            sequence: 1,
            signal: libc::SIGTSTP,
        };
        assert_eq!(
            root.accept(preparing).unwrap(),
            Action::PauseRelay(1)
        );
        assert!(root.accept(preparing).is_err());
        assert!(
            root.accept(RootEvent::Stopped {
                sequence: 1,
                signal: libc::SIGSTOP
            })
            .is_err()
        );
        assert_eq!(
            root.accept(stop).unwrap(),
            Action::Suspend {
                sequence: 1,
                signal: libc::SIGTSTP
            }
        );
        assert!(root.status().is_none());
        assert!(root.accept(stop).is_err());
        assert!(
            root.accept(RootEvent::Continued {
                sequence: 2
            })
            .is_err()
        );
        assert!(
            root.accept(RootEvent::Continued {
                sequence: 1
            })
            .is_err()
        );
        root.resume_sent(1).unwrap();
        assert_eq!(
            root.accept(RootEvent::Continued {
                sequence: 1
            })
            .unwrap(),
            Action::None
        );
        assert!(root.accept(preparing).is_err());
        assert_eq!(
            root.accept(RootEvent::Stopping {
                sequence: 2,
                signal: libc::SIGSTOP
            })
            .unwrap(),
            Action::PauseRelay(2)
        );
    }

    #[test]
    fn exit_during_pause_is_terminal_but_is_not_a_settlement_proof() {
        let mut root = RootProgress::default();
        root.accept(RootEvent::Stopping {
            sequence: 1,
            signal: libc::SIGSTOP,
        })
        .unwrap();
        let status = ExitStatus::from_raw(libc::SIGKILL);
        assert_eq!(
            root.accept(RootEvent::Exited(status)).unwrap(),
            Action::None
        );
        assert_eq!(root.status(), Some(status));
        assert!(
            root.accept(RootEvent::Continued {
                sequence: 1
            })
            .is_err()
        );
        assert!(root.accept(RootEvent::Exited(status)).is_err());
    }
}

use super::{DRAIN, NEGOTIATION};
use std::io;
use std::time::{Duration, Instant};

pub(super) enum Budget {
    Negotiating(Instant),
    Running,
    Draining {
        remaining: Duration,
        observed: Instant,
        paused: bool,
    },
}
impl Budget {
    pub(super) fn new(now: Instant) -> Self {
        Self::Negotiating(now + NEGOTIATION)
    }
    pub(super) fn draining(now: Instant, armed: bool) -> Self {
        Self::Draining {
            remaining: DRAIN,
            observed: now,
            paused: armed,
        }
    }
    pub(super) fn check(&mut self, now: Instant, armed: bool) -> io::Result<()> {
        let expired = match self {
            Self::Negotiating(deadline) => now >= *deadline,
            Self::Running => false,
            Self::Draining {
                remaining,
                observed,
                paused,
            } => {
                if !*paused {
                    *remaining = remaining.saturating_sub(now.saturating_duration_since(*observed));
                }
                *observed = now;
                *paused = armed;
                remaining.is_zero()
            }
        };
        if expired {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guardian phase timed out",
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn armed_stop_suspends_drain_but_records_do_not_renew_remaining_time() {
        let start = Instant::now();
        let mut budget = Budget::draining(start, false);
        budget
            .check(start + Duration::from_secs(10), true)
            .unwrap();
        budget
            .check(start + Duration::from_secs(500), true)
            .unwrap();
        budget
            .check(start + Duration::from_secs(600), false)
            .unwrap();
        budget
            .check(start + Duration::from_secs(619), false)
            .unwrap();
        assert!(
            budget
                .check(start + Duration::from_secs(620), false)
                .is_err()
        );
    }
    #[test]
    fn negotiation_is_not_extended_by_stop_state_and_drain_can_start_paused() {
        let start = Instant::now();
        assert!(
            Budget::new(start)
                .check(start + NEGOTIATION, true)
                .is_err()
        );
        let mut budget = Budget::draining(start, true);
        budget
            .check(start + Duration::from_secs(1000), false)
            .unwrap();
        assert!(
            budget
                .check(start + Duration::from_secs(1000) + DRAIN, false)
                .is_err()
        );
    }
}

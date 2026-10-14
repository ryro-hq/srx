use std::time::{Duration, Instant};

/// One budget across all drain bytes; protocol suspension consumes no time.
pub(super) struct DrainBudget {
    deadline: Option<Instant>,
    suspended: Option<Duration>,
}
impl DrainBudget {
    pub(super) fn new(deadline: Option<Instant>) -> Self {
        Self {
            deadline,
            suspended: None,
        }
    }
    pub(super) fn expired(&mut self, now: Instant, armed: bool) -> bool {
        if armed {
            if self.suspended.is_none() {
                self.suspended = self
                    .deadline
                    .take()
                    .map(|end| end.saturating_duration_since(now));
            }
            return false;
        }
        if let Some(remaining) = self.suspended.take() {
            self.deadline = Some(now + remaining);
        }
        self.deadline.is_some_and(|end| now >= end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn suspension_preserves_remaining_budget_across_crossed_abort_bytes() {
        let start = Instant::now();
        let mut budget = DrainBudget::new(Some(start + Duration::from_secs(40)));
        assert!(!budget.expired(start + Duration::from_secs(5), false));
        assert!(!budget.expired(start + Duration::from_secs(10), true));
        // A crossed B causes another receive, with the same budget object.
        assert!(!budget.expired(start + Duration::from_secs(200), true));
        assert!(!budget.expired(start + Duration::from_secs(300), false));
        assert!(!budget.expired(start + Duration::from_secs(329), false));
        assert!(budget.expired(start + Duration::from_secs(330), false));
    }
    #[test]
    fn ordinary_bytes_and_repeated_suspensions_do_not_refresh_budget() {
        let start = Instant::now();
        let mut budget = DrainBudget::new(Some(start + Duration::from_secs(10)));
        assert!(!budget.expired(start + Duration::from_secs(3), true));
        assert!(!budget.expired(start + Duration::from_secs(100), false));
        assert!(!budget.expired(start + Duration::from_secs(102), true));
        assert!(!budget.expired(start + Duration::from_secs(200), false));
        assert!(!budget.expired(start + Duration::from_secs(204), false));
        assert!(budget.expired(start + Duration::from_secs(205), false));
    }
}

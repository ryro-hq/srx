use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", from = "PolicyWire")]
pub enum ProcessRestart {
    #[default]
    Never,
    OnFailure(RestartLimits),
}

// A struct variant, including the empty Never case, rejects unknown fields.
// Serde's internally tagged unit variant otherwise discards those fields.
#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum PolicyWire {
    Never {},
    OnFailure(RestartLimits),
}

impl From<PolicyWire> for ProcessRestart {
    fn from(value: PolicyWire) -> Self {
        match value {
            PolicyWire::Never {} => Self::Never,
            PolicyWire::OnFailure(limits) => Self::OnFailure(limits),
        }
    }
}

/// No implicit limits are supplied when restart is enabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LimitsWire")]
pub struct RestartLimits {
    delay_seconds: u32,
    window_seconds: u32,
    burst: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsWire {
    delay_seconds: u32,
    window_seconds: u32,
    burst: u32,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error(
    "restart requires delay 1..=300 seconds, window 1..=3600 seconds not shorter than delay, and burst 1..=100 starts"
)]
pub struct RestartPolicyError;

impl RestartLimits {
    pub fn new(
        delay_seconds: u32,
        window_seconds: u32,
        burst: u32,
    ) -> Result<Self, RestartPolicyError> {
        if !(1..=300).contains(&delay_seconds)
            || !(1..=3600).contains(&window_seconds)
            || window_seconds < delay_seconds
            || !(1..=100).contains(&burst)
        {
            return Err(RestartPolicyError);
        }
        Ok(Self {
            delay_seconds,
            window_seconds,
            burst,
        })
    }
    pub const fn delay_seconds(self) -> u32 {
        self.delay_seconds
    }
    pub const fn window_seconds(self) -> u32 {
        self.window_seconds
    }
    /// Maximum starts per window, including the initial start; not total retries.
    pub const fn burst(self) -> u32 {
        self.burst
    }
}
impl TryFrom<LimitsWire> for RestartLimits {
    type Error = RestartPolicyError;
    fn try_from(value: LimitsWire) -> Result<Self, Self::Error> {
        Self::new(
            value.delay_seconds,
            value.window_seconds,
            value.burst,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_limits_are_checked_on_construction_and_deserialization() {
        for values in [(1, 1, 1), (300, 3600, 100)] {
            let limits = RestartLimits::new(values.0, values.1, values.2).unwrap();
            let policy = ProcessRestart::OnFailure(limits);
            assert_eq!(
                serde_json::from_slice::<ProcessRestart>(&serde_json::to_vec(&policy).unwrap())
                    .unwrap(),
                policy
            );
        }
        for (delay, window, burst) in [
            (0, 1, 1),
            (301, 3600, 1),
            (1, 0, 1),
            (1, 3601, 1),
            (2, 1, 1),
            (1, 1, 0),
            (1, 1, 101),
        ] {
            assert!(RestartLimits::new(delay, window, burst).is_err());
            let wire = serde_json::json!({"mode":"on_failure","delay_seconds":delay,"window_seconds":window,"burst":burst});
            assert!(serde_json::from_value::<ProcessRestart>(wire).is_err());
        }
        for wire in [
            r#"{"mode":"on_failure"}"#,
            r#"{"mode":"never","burst":1}"#,
            r#"{"mode":"on_failure","delay_seconds":1,"window_seconds":2,"burst":3,"extra":0}"#,
        ] {
            assert!(serde_json::from_str::<ProcessRestart>(wire).is_err());
        }
        assert_eq!(
            serde_json::from_str::<ProcessRestart>(r#"{"mode":"never"}"#).unwrap(),
            ProcessRestart::Never
        );
    }
}

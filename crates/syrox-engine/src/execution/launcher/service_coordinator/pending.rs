use super::ServiceError;
use crate::execution::journal::{AttemptId, AttemptPhase, AttemptSnapshot, RoleBinding};
use crate::{execution::restart::ProcessRestart, systemd::SystemdUnitStatus};
use std::time::{Duration, Instant};

pub(super) const START_TIMEOUT: Duration = Duration::from_secs(30);
#[derive(Default)]
pub(crate) struct ServicePending {
    pending: Option<(AttemptId, Instant)>,
}
impl ServicePending {
    pub(crate) fn observe(
        &mut self,
        role: &RoleBinding,
        head: &AttemptSnapshot,
        status: &SystemdUnitStatus,
        now: Instant,
    ) -> Result<(), ServiceError> {
        if status.unit != *role.unit() || head.role != role.name() {
            return Err(ServiceError::State(
                "service role/head unit differs",
            ));
        }
        if status.active_state == "active"
            && head.phase == AttemptPhase::Consumed
            && head
                .binding
                .as_ref()
                .is_some_and(|binding| status.invocation == binding.invocation())
        {
            self.pending = None;
            return Ok(());
        }
        let ProcessRestart::OnFailure(limits) = role.restart() else {
            return Err(ServiceError::State(
                "service policy prohibits a pending restart",
            ));
        };
        if status.active_state != "activating"
            || status.result == "start-limit-hit"
            || !matches!(
                status.sub_state.as_str(),
                "auto-restart" | "auto-restart-queued" | "start-pre" | "start" | "start-post"
            )
            || !matches!(
                head.phase,
                AttemptPhase::Prepared | AttemptPhase::Authorized | AttemptPhase::Consumed
            )
        {
            return Err(ServiceError::State(
                "service lacks an admitted active head or bounded restart phase",
            ));
        }
        if self
            .pending
            .as_ref()
            .is_none_or(|(attempt, _)| attempt != &head.id)
        {
            self.pending = Some((
                head.id.clone(),
                now + START_TIMEOUT + Duration::from_secs(u64::from(limits.delay_seconds())),
            ));
        }
        if now
            >= self
                .pending
                .as_ref()
                .expect("pending deadline initialized")
                .1
        {
            return Err(ServiceError::State(
                "observed service restart wait expired",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::journal::{AttemptBinding, SessionId};
    use crate::{
        execution::restart::RestartLimits, store::ContentDigest, systemd::SystemdUnitName,
    };
    #[test]
    fn pending_deadline_survives_queries_invocation_and_substate_changes() {
        let unit = SystemdUnitName::new("syrox-watchdog.service").unwrap();
        let role = RoleBinding::new(
            SessionId::parse(&"1".repeat(32)).unwrap(),
            "service:watchdog:main",
            ContentDigest::sha256(b"manifest"),
            ContentDigest::sha256(b"command"),
            unit.clone(),
            AttemptBinding::new(
                SystemdUnitName::new("syrox-owner.service").unwrap(),
                [1; 16],
            )
            .unwrap(),
            ProcessRestart::OnFailure(RestartLimits::new(2, 10, 3).unwrap()),
        )
        .unwrap();
        let mut head = AttemptSnapshot {
            service_processes: None,
            id: AttemptId::parse(&"2".repeat(32)).unwrap(),
            role: role.name().into(),
            phase: AttemptPhase::Authorized,
            binding: Some(AttemptBinding::new(unit.clone(), [2; 16]).unwrap()),
        };
        let mut status = SystemdUnitStatus {
            unit,
            invocation: vec![2; 16],
            active_state: "activating".into(),
            sub_state: "auto-restart".into(),
            result: "exit-code".into(),
            control_group: String::new(),
            main_pid: 0,
            exec_main_code: 0,
            exec_main_status: 0,
        };
        let now = Instant::now();
        let mut pending = ServicePending::default();
        pending
            .observe(&role, &head, &status, now)
            .unwrap();
        // Authorization progressing to consumption is the same attempt. It
        // cannot renew the deadline while the service is still activating.
        head.phase = AttemptPhase::Consumed;
        status.invocation = vec![3; 16];
        status.sub_state = "start".into();
        pending
            .observe(
                &role,
                &head,
                &status,
                now + Duration::from_secs(31),
            )
            .unwrap();
        assert!(
            pending
                .observe(
                    &role,
                    &head,
                    &status,
                    now + Duration::from_secs(32)
                )
                .is_err()
        );
        // Only an authenticated, durably advanced head represents progress.
        head.id = AttemptId::parse(&"3".repeat(32)).unwrap();
        head.binding = Some(AttemptBinding::new(status.unit.clone(), [3; 16]).unwrap());
        pending
            .observe(
                &role,
                &head,
                &status,
                now + Duration::from_secs(32),
            )
            .unwrap();
        status.sub_state = "unrecognized".into();
        assert!(
            pending
                .observe(
                    &role,
                    &head,
                    &status,
                    now + Duration::from_secs(33)
                )
                .is_err()
        );
        status.active_state = "active".into();
        pending
            .observe(
                &role,
                &head,
                &status,
                now + Duration::from_secs(34),
            )
            .unwrap();
        assert!(pending.pending.is_none());
    }
}

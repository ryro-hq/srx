use crate::execution::journal::roles::RoleSnapshot;
use crate::execution::journal::roles::retention::RoleRetentionPhase;
use crate::{cancellation::Cancellation, store::Store};
use std::path::Path;
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoleRetentionRecoveryOutcome {
    /// Matching existing bytes and Store; process settlement remains unproven.
    Verified,
    Retired,
    Pending {
        message: String,
    },
    Unprepared,
    /// The journal records successful retirement, not a new recovery action.
    RecordedRetired,
    Failed {
        message: String,
    },
}
#[derive(Clone, Debug)]
pub struct RoleRetentionRecovery {
    pub role: String,
    pub first_attempt: Option<String>,
    pub phase: &'static str,
    pub outcome: RoleRetentionRecoveryOutcome,
}

pub(super) fn inspect(
    roles: &[RoleSnapshot],
    path: &Path,
    cancel: &Cancellation,
    deadline: Instant,
) -> Vec<RoleRetentionRecovery> {
    let store = roles
        .iter()
        .any(|role| {
            matches!(
                role.retention.phase,
                RoleRetentionPhase::Intent
                    | RoleRetentionPhase::Retained
                    | RoleRetentionPhase::Retiring
            )
        })
        .then(|| {
            check_budget(cancel, deadline).map_err(crate::store::StoreError::Io)?;
            Store::open_existing(path)
        });
    roles
        .iter()
        .map(|role| {
            let retention = &role.retention;
            let phase = match retention.phase {
                RoleRetentionPhase::Unprepared => "unprepared",
                RoleRetentionPhase::Intent => "intent",
                RoleRetentionPhase::Retained => "retained",
                RoleRetentionPhase::Retiring => "retiring",
                RoleRetentionPhase::Retired => "retired",
            };
            let outcome = match retention.phase {
                RoleRetentionPhase::Unprepared => RoleRetentionRecoveryOutcome::Unprepared,
                RoleRetentionPhase::Retired => RoleRetentionRecoveryOutcome::RecordedRetired,
                _ => verify(
                    role,
                    store.as_ref().expect("interests require Store"),
                    cancel,
                    deadline,
                ),
            };
            RoleRetentionRecovery {
                role: role.binding.name().into(),
                first_attempt: retention
                    .identity
                    .as_ref()
                    .map(|identity| identity.first.to_string()),
                phase,
                outcome,
            }
        })
        .collect()
}
fn verify(
    role: &RoleSnapshot,
    store: &Result<Store, crate::store::StoreError>,
    cancel: &Cancellation,
    deadline: Instant,
) -> RoleRetentionRecoveryOutcome {
    let result = (|| {
        let store = store.as_ref().map_err(ToString::to_string)?;
        let identity = role
            .retention
            .identity
            .as_ref()
            .ok_or_else(|| "retention identity missing".to_owned())?;
        store
            .reopen_durable_interest_checked(
                identity.first.as_str(),
                identity.pin,
                identity.store_anchor,
                || check_budget(cancel, deadline),
            )
            .map_err(|error| error.to_string())?;
        // Dropping the reopened handle never removes a durable interest.
        Ok::<_, String>(())
    })();
    match result {
        Ok(()) => RoleRetentionRecoveryOutcome::Verified,
        Err(message) => RoleRetentionRecoveryOutcome::Failed {
            message: message
                .chars()
                .take(super::MAX_DIAGNOSTIC_CHARACTERS)
                .collect(),
        },
    }
}

fn check_budget(cancel: &Cancellation, deadline: Instant) -> std::io::Result<()> {
    cancel
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())?;
    if Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "retention inspection deadline",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::journal::roles::retention::{
        RoleRetentionIdentity, RoleRetentionSnapshot,
    };
    use crate::execution::journal::{AttemptBinding, AttemptId, RoleBinding, SessionId};
    use crate::{
        execution::restart::ProcessRestart, store::ContentDigest, systemd::SystemdUnitName,
    };
    use std::time::Duration;

    #[test]
    fn recovery_reopens_exact_hold_without_creating_or_retiring_evidence() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store");
        let store = Store::initialize(&path).unwrap();
        let operation = store.operation().unwrap();
        let bytes = b"retained role";
        let digest = ContentDigest::sha256(bytes);
        operation
            .ingest(bytes.as_slice(), digest, bytes.len() as u64)
            .unwrap();
        let lease = operation.retain_objects(&[digest], &[]).unwrap();
        let first = AttemptId::parse(&"1".repeat(32)).unwrap();
        let hold = lease
            .persist_checked(first.as_str(), || Ok(()))
            .unwrap();
        let role = RoleSnapshot {
            binding: RoleBinding::new(
                SessionId::parse(&"2".repeat(32)).unwrap(),
                "service:probe:main",
                digest,
                digest,
                SystemdUnitName::new("syrox-probe.service").unwrap(),
                AttemptBinding::new(
                    SystemdUnitName::new("syrox-owner.service").unwrap(),
                    [3; 16],
                )
                .unwrap(),
                ProcessRestart::Never,
            )
            .unwrap(),
            head: first.clone(),
            authorized: false,
            retention: RoleRetentionSnapshot {
                phase: RoleRetentionPhase::Retained,
                identity: Some(RoleRetentionIdentity::new(
                    first,
                    hold.digest(),
                    hold.store_anchor(),
                )),
            },
        };
        drop((lease, operation));
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(10);
        let roles = [role];
        assert_eq!(
            inspect(&roles, &path, &cancel, deadline)[0].outcome,
            RoleRetentionRecoveryOutcome::Verified
        );
        hold.verify_current_checked(|| Ok(())).unwrap();
        assert!(matches!(
            inspect(&roles, &path, &cancel, Instant::now())[0].outcome,
            RoleRetentionRecoveryOutcome::Failed { .. }
        ));
        hold.verify_current_checked(|| Ok(())).unwrap();
        let missing = root.path().join("missing-store");
        assert!(matches!(
            inspect(&roles, &missing, &cancel, deadline)[0].outcome,
            RoleRetentionRecoveryOutcome::Failed { .. }
        ));
        assert!(!missing.exists());
        // No process was launched by this Store-only fixture.
        hold.retire_checked(|| Ok(())).unwrap();
        assert!(matches!(
            inspect(&roles, &path, &cancel, deadline)[0].outcome,
            RoleRetentionRecoveryOutcome::Failed { .. }
        ));
        let id = roles[0].retention.identity.as_ref().unwrap();
        assert!(
            !path
                .join(".syrox-store/interests")
                .join(format!("hold-{}", id.first))
                .exists()
        );
    }
}

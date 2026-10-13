use super::activation::{ActivationJournal, EffectKind, EffectState, OperationKind};
use crate::{cancellation::Cancellation, store::ContentDigest};
use std::path::Path;
use std::time::Instant;

#[derive(Debug, thiserror::Error)]
#[error("cannot observe Os installation journal")]
pub struct OsStatusError;

#[derive(Debug)]
pub struct OsStatus {
    pub installation: String,
    pub desired: Option<ContentDigest>,
    pub active_operation: Option<String>,
    pub active_kind: Option<&'static str>,
    pub boot_fences: Vec<OsStatusBootFence>,
    pub abandoned_operations: Vec<String>,
    pub bindings: Vec<OsStatusBinding>,
    pub pending_effects: Vec<OsStatusEffect>,
}
#[derive(Debug)]
pub struct OsStatusBootFence {
    pub previous_boot: String,
    pub current: OsStatusEpoch,
}
#[derive(Debug)]
pub struct OsStatusBinding {
    pub resource: String,
    pub generation: ContentDigest,
    pub pin: ContentDigest,
    pub unit: String,
    pub authorized: bool,
    pub epoch: OsStatusEpoch,
}
#[derive(Debug)]
pub struct OsStatusEpoch {
    pub boot: String,
    pub manager: String,
    pub scope: String,
}
#[derive(Debug)]
pub struct OsStatusEffect {
    pub operation: String,
    pub effect: String,
    pub kind: &'static str,
    pub resource: String,
    pub target: ContentDigest,
    pub phase: &'static str,
    pub job: Option<String>,
}

/// Read one coherent, validated snapshot of existing installation evidence.
/// This never selects a generation, repairs state, or observes live services.
pub fn inspect_os_status(
    installation: &Path,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsStatus, OsStatusError> {
    let journal = ActivationJournal::open_existing(installation, cancellation, deadline)
        .map_err(|_| OsStatusError)?;
    let snapshot = journal
        .snapshot(cancellation, deadline)
        .map_err(|_| OsStatusError)?;
    let active_kind = snapshot
        .active_operation
        .as_ref()
        .map(|id| {
            snapshot
                .operations
                .get(id)
                .ok_or(OsStatusError)
                .map(|operation| match operation.kind {
                    OperationKind::Apply => "apply",
                    OperationKind::Rollback => "rollback",
                })
        })
        .transpose()?;
    let mut result = OsStatus {
        installation: snapshot.installation,
        desired: snapshot
            .desired
            .as_deref()
            .map(digest)
            .transpose()?,
        active_operation: snapshot.active_operation,
        active_kind,
        boot_fences: Vec::with_capacity(snapshot.boot_fences.len()),
        abandoned_operations: Vec::new(),
        bindings: Vec::with_capacity(snapshot.bindings.len()),
        pending_effects: Vec::new(),
    };
    for (previous_boot, current) in snapshot.boot_fences {
        check(cancellation, deadline)?;
        result.boot_fences.push(OsStatusBootFence {
            previous_boot,
            current: OsStatusEpoch {
                boot: current.boot.as_str().into(),
                manager: current.manager,
                scope: current.scope,
            },
        });
    }
    for (resource, binding) in snapshot.bindings {
        check(cancellation, deadline)?;
        result.bindings.push(OsStatusBinding {
            resource,
            generation: digest(&binding.generation)?,
            pin: digest(&binding.pin)?,
            unit: binding.unit,
            authorized: binding.authorized,
            epoch: OsStatusEpoch {
                boot: binding.epoch.boot.as_str().into(),
                manager: binding.epoch.manager,
                scope: binding.epoch.scope,
            },
        });
    }
    for (operation, record) in snapshot.operations {
        check(cancellation, deadline)?;
        if record.abandoned {
            result
                .abandoned_operations
                .push(operation.clone());
        }
        for (effect, record) in record.effects {
            check(cancellation, deadline)?;
            let (phase, job) = match record.state {
                EffectState::Intent => ("intent", None),
                EffectState::Accepted {
                    job,
                } => ("accepted", Some(job)),
                EffectState::Unknown => ("unknown", None),
                EffectState::Observed {
                    ..
                }
                | EffectState::NotApplied
                | EffectState::BootFenced {
                    ..
                }
                | EffectState::ManagerFenced {
                    ..
                } => continue,
            };
            result.pending_effects.push(OsStatusEffect {
                operation: operation.clone(),
                effect,
                kind: match record.kind {
                    EffectKind::Publish => "publish",
                    EffectKind::Reload => "reload",
                    EffectKind::Start => "start",
                    EffectKind::Stop => "stop",
                },
                resource: record.resource,
                target: digest(&record.target)?,
                phase,
                job,
            });
        }
    }
    check(cancellation, deadline)?;
    Ok(result)
}
fn digest(value: &str) -> Result<ContentDigest, OsStatusError> {
    value.parse().map_err(|_| OsStatusError)
}
fn check(cancellation: &Cancellation, deadline: Instant) -> Result<(), OsStatusError> {
    if cancellation.is_cancelled() || Instant::now() >= deadline {
        return Err(OsStatusError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::os::{
        LauncherIdentity,
        activation::ExecutionEpoch,
        installation::GenerationInstallation,
        launch_binding::{LaunchBindingInput, OsLaunchBinding, OsLaunchContext},
    };
    use crate::{systemd::SystemdScope, systemd::SystemdUnitName};
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }
    fn pin(text: &[u8]) -> ContentDigest {
        ContentDigest::sha256(text)
    }
    fn directory() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    fn context() -> OsLaunchContext {
        OsLaunchContext::new(
            SystemdScope::System,
            "/private/store".into(),
            "/private/units/syrox-status-test.service".into(),
            1000,
            1000,
            Duration::from_secs(30),
            Duration::from_secs(5),
        )
        .unwrap()
    }
    fn epoch() -> ExecutionEpoch {
        ExecutionEpoch {
            boot: crate::platform::linux::boot::BootId::parse(
                "11111111-1111-4111-8111-111111111111",
            )
            .unwrap(),
            manager: "recorded-manager".into(),
            scope: context().scope_key(),
        }
    }
    fn published_binding(
        installation: &GenerationInstallation,
        journal: &ActivationJournal,
        operation: &str,
        cancel: &Cancellation,
    ) -> OsLaunchBinding {
        let binding = OsLaunchBinding::new(LaunchBindingInput {
            installation: installation.id().into(),
            generation: pin(b"old generation"),
            service: "alpha".into(),
            process: "server".into(),
            command: "run".into(),
            unit: SystemdUnitName::new("syrox-status-test.service").unwrap(),
            launcher: LauncherIdentity::new(pin(b"launcher"), 1).unwrap(),
            spec: pin(b"spec"),
            epoch: epoch(),
            context: context(),
            configuration: "/private/config/alpha".into(),
            cwd: "/work".into(),
        })
        .unwrap();
        let publication = journal
            .plan_effect(
                operation,
                "alpha/server",
                EffectKind::Publish,
                None,
                binding.digest().unwrap(),
                cancel,
                deadline(),
            )
            .unwrap();
        journal
            .record_observed(
                operation,
                &publication,
                binding.digest().unwrap(),
                None,
                cancel,
                deadline(),
            )
            .unwrap();
        journal
            .authorize_binding(
                operation,
                &publication,
                &binding,
                cancel,
                deadline(),
            )
            .unwrap();
        binding
    }

    #[test]
    fn status_separates_desired_generation_from_recorded_bindings_and_pending_effects() {
        let root = directory();
        let cancel = Cancellation::default();
        let installation =
            GenerationInstallation::initialize(root.path(), &cancel, deadline()).unwrap();
        let journal = ActivationJournal::open_existing(root.path(), &cancel, deadline()).unwrap();
        let original = journal
            .begin_test_pin(
                pin(b"old generation"),
                None,
                epoch(),
                &cancel,
                deadline(),
            )
            .unwrap();
        let binding = published_binding(&installation, &journal, &original, &cancel);
        let current = journal
            .begin_test_pin(
                pin(b"new generation"),
                Some(pin(b"old generation")),
                epoch(),
                &cancel,
                deadline(),
            )
            .unwrap();
        let target = pin(b"pending unit");
        journal
            .plan_effect(
                &current,
                "unit/alpha/server",
                EffectKind::Publish,
                None,
                target,
                &cancel,
                deadline(),
            )
            .unwrap();
        let accepted = journal
            .plan_effect(
                &current,
                "beta/server",
                EffectKind::Start,
                None,
                target,
                &cancel,
                deadline(),
            )
            .unwrap();
        journal
            .record_accepted(
                &current,
                &accepted,
                "/org/freedesktop/systemd1/job/12",
                &cancel,
                deadline(),
            )
            .unwrap();
        let unknown = journal
            .plan_effect(
                &current,
                "removed/server",
                EffectKind::Stop,
                None,
                target,
                &cancel,
                deadline(),
            )
            .unwrap();
        journal
            .record_unknown(&current, &unknown, &cancel, deadline())
            .unwrap();
        let before = journal.snapshot(&cancel, deadline()).unwrap();
        let status = inspect_os_status(root.path(), &cancel, deadline()).unwrap();
        assert_eq!(status.installation, installation.id());
        assert_eq!(status.desired, Some(pin(b"new generation")));
        assert_eq!(
            status.active_operation.as_deref(),
            Some(current.as_str())
        );
        assert_eq!(status.active_kind, Some("apply"));
        assert_eq!(status.bindings.len(), 1);
        let recorded = &status.bindings[0];
        assert_eq!(recorded.resource, "alpha/server");
        assert_eq!(recorded.generation, binding.generation());
        assert_eq!(recorded.pin, binding.digest().unwrap());
        assert!(recorded.authorized);
        assert_eq!(recorded.epoch.boot, epoch().boot.as_str());
        assert_eq!(status.pending_effects.len(), 3);
        let phases: std::collections::BTreeSet<_> = status
            .pending_effects
            .iter()
            .map(|e| e.phase)
            .collect();
        assert_eq!(phases, ["accepted", "intent", "unknown"].into());
        for effect in &status.pending_effects {
            assert_eq!(effect.operation, current);
            assert_eq!(effect.target, target);
            assert_eq!(effect.job.is_some(), effect.phase == "accepted");
        }
        assert!(!format!("{status:?}").contains(&before.bindings["alpha/server"].authorization));
        assert_eq!(
            serde_json::to_vec(&before).unwrap(),
            serde_json::to_vec(&journal.snapshot(&cancel, deadline()).unwrap()).unwrap()
        );
    }

    #[test]
    fn missing_cancelled_expired_and_corrupt_status_never_initialize_or_repair() {
        let root = directory();
        let missing = root.path().join("missing");
        assert!(inspect_os_status(&missing, &Cancellation::default(), deadline()).is_err());
        assert!(!missing.exists());
        let cancel = Cancellation::default();
        GenerationInstallation::initialize(root.path(), &cancel, deadline()).unwrap();
        let before: Vec<_> = fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        cancel.cancel();
        assert!(inspect_os_status(root.path(), &cancel, deadline()).is_err());
        assert!(
            inspect_os_status(
                root.path(),
                &Cancellation::default(),
                Instant::now()
            )
            .is_err()
        );
        assert_eq!(
            before,
            fs::read_dir(root.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<Vec<_>>()
        );
        // Corruption remains available for diagnosis; the parser's details are not exposed.
        fs::write(
            root.path().join("activation"),
            b"private malformed journal",
        )
        .unwrap();
        fs::set_permissions(
            root.path().join("activation"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let error =
            inspect_os_status(root.path(), &Cancellation::default(), deadline()).unwrap_err();
        assert!(!error.to_string().contains("private"));
        assert_eq!(
            fs::read(root.path().join("activation")).unwrap(),
            b"private malformed journal"
        );
    }

    #[test]
    fn terminal_not_applied_is_not_pending_and_does_not_mean_desired_was_applied() {
        let root = directory();
        let cancel = Cancellation::default();
        let installation =
            GenerationInstallation::initialize(root.path(), &cancel, deadline()).unwrap();
        let _execution = installation
            .execution(&cancel, deadline())
            .unwrap();
        let journal = ActivationJournal::open_existing(root.path(), &cancel, deadline()).unwrap();
        let candidate = pin(b"selected but not applied");
        let operation = journal
            .begin_test_pin(candidate, None, epoch(), &cancel, deadline())
            .unwrap();
        let effect = journal
            .plan_effect(
                &operation,
                "alpha/server",
                EffectKind::Publish,
                None,
                pin(b"unpublished binding"),
                &cancel,
                deadline(),
            )
            .unwrap();
        // Exercise the stored-state projection only: filesystem evidence is the
        // recovery coordinator's responsibility and is not manufactured by status.
        journal
            .record_not_applied(&operation, &effect, &cancel, deadline())
            .unwrap();
        let pending = journal
            .plan_effect(
                &operation,
                "beta/server",
                EffectKind::Publish,
                None,
                pin(b"uncertain binding"),
                &cancel,
                deadline(),
            )
            .unwrap();
        journal
            .record_unknown(&operation, &pending, &cancel, deadline())
            .unwrap();
        let before = serde_json::to_vec(&journal.snapshot(&cancel, deadline()).unwrap()).unwrap();
        let status = inspect_os_status(root.path(), &cancel, deadline()).unwrap();
        assert_eq!(status.desired, Some(candidate));
        assert_eq!(status.pending_effects.len(), 1);
        assert_eq!(status.pending_effects[0].effect, pending);
        assert_eq!(status.pending_effects[0].phase, "unknown");
        assert!(status.bindings.is_empty());
        assert_eq!(
            serde_json::to_vec(&journal.snapshot(&cancel, deadline()).unwrap()).unwrap(),
            before
        );
    }

    #[test]
    fn abandoned_operations_remain_visible_without_revoking_old_bindings() {
        let root = directory();
        let cancel = Cancellation::default();
        let installation =
            GenerationInstallation::initialize(root.path(), &cancel, deadline()).unwrap();
        let _execution = installation
            .execution(&cancel, deadline())
            .unwrap();
        let journal = ActivationJournal::open_existing(root.path(), &cancel, deadline()).unwrap();
        let original = journal
            .begin_test_pin(
                pin(b"old generation"),
                None,
                epoch(),
                &cancel,
                deadline(),
            )
            .unwrap();
        let binding = published_binding(&installation, &journal, &original, &cancel);
        let first = journal
            .begin_test_pin(
                pin(b"withdrawn generation"),
                Some(binding.generation()),
                epoch(),
                &cancel,
                deadline(),
            )
            .unwrap();
        journal
            .abandon(&first, &cancel, deadline())
            .unwrap();
        let status = inspect_os_status(root.path(), &cancel, deadline()).unwrap();
        assert!(status.desired.is_none());
        assert!(status.active_operation.is_none());
        assert!(status.active_kind.is_none());
        assert_eq!(
            status.abandoned_operations.as_slice(),
            std::slice::from_ref(&first)
        );
        assert!(status.pending_effects.is_empty());
        assert_eq!(status.bindings.len(), 1);
        assert!(status.bindings[0].authorized);
        assert_eq!(
            status.bindings[0].generation,
            binding.generation()
        );
        assert_eq!(status.bindings[0].pin, binding.digest().unwrap());

        let next = journal
            .begin_test_pin(
                pin(b"next generation"),
                None,
                epoch(),
                &cancel,
                deadline(),
            )
            .unwrap();
        let selected = inspect_os_status(root.path(), &cancel, deadline()).unwrap();
        assert_eq!(selected.desired, Some(pin(b"next generation")));
        assert_eq!(
            selected.active_operation.as_deref(),
            Some(next.as_str())
        );
        assert_eq!(selected.active_kind, Some("apply"));
        assert_eq!(
            selected.abandoned_operations.as_slice(),
            std::slice::from_ref(&first)
        );
        journal
            .abandon(&next, &cancel, deadline())
            .unwrap();
        let before = journal.snapshot(&cancel, deadline()).unwrap();
        let status = inspect_os_status(root.path(), &cancel, deadline()).unwrap();
        let mut expected = vec![first, next];
        expected.sort();
        assert_eq!(status.abandoned_operations, expected);
        assert!(status.desired.is_none() && status.active_operation.is_none());
        assert!(status.bindings[0].authorized);
        assert_eq!(
            status.bindings[0].generation,
            binding.generation()
        );
        assert!(!format!("{status:?}").contains(&before.bindings["alpha/server"].authorization));
        assert_eq!(
            serde_json::to_vec(&before).unwrap(),
            serde_json::to_vec(&journal.snapshot(&cancel, deadline()).unwrap()).unwrap()
        );
    }

    #[test]
    fn status_exposes_boot_transition_without_reporting_old_remote_effect_pending() {
        let root = directory();
        let cancel = Cancellation::default();
        let installation =
            GenerationInstallation::initialize(root.path(), &cancel, deadline()).unwrap();
        let _execution = installation
            .execution(&cancel, deadline())
            .unwrap();
        let journal = ActivationJournal::open_existing(root.path(), &cancel, deadline()).unwrap();
        let old = epoch();
        let operation = journal
            .begin_test_pin(
                pin(b"candidate"),
                None,
                old.clone(),
                &cancel,
                deadline(),
            )
            .unwrap();
        let start = journal
            .plan_effect(
                &operation,
                "alpha/server",
                EffectKind::Start,
                None,
                pin(b"binding"),
                &cancel,
                deadline(),
            )
            .unwrap();
        journal
            .record_accepted(
                &operation,
                &start,
                "/org/freedesktop/systemd1/job/42",
                &cancel,
                deadline(),
            )
            .unwrap();
        let publication = journal
            .plan_effect(
                &operation,
                "unit/alpha/server",
                EffectKind::Publish,
                None,
                pin(b"unit"),
                &cancel,
                deadline(),
            )
            .unwrap();
        let current = ExecutionEpoch {
            boot: crate::platform::linux::boot::BootId::parse(
                "22222222-2222-4222-8222-222222222222",
            )
            .unwrap(),
            manager: "new-manager".into(),
            scope: old.scope.clone(),
        };
        // This tests recorded evidence projection, not a host reboot or quiescence proof.
        journal
            .fence_previous_boot(&operation, &current, &cancel, deadline())
            .unwrap();
        let before = serde_json::to_vec(&journal.snapshot(&cancel, deadline()).unwrap()).unwrap();
        let status = inspect_os_status(root.path(), &cancel, deadline()).unwrap();
        assert_eq!(status.boot_fences.len(), 1);
        let fence = &status.boot_fences[0];
        assert_eq!(fence.previous_boot, old.boot.as_str());
        assert_eq!(fence.current.boot, current.boot.as_str());
        assert_eq!(fence.current.manager, current.manager);
        assert_eq!(fence.current.scope, old.scope);
        assert_eq!(status.pending_effects.len(), 1);
        assert_eq!(status.pending_effects[0].effect, publication);
        assert!(status.bindings.is_empty());
        assert_eq!(
            serde_json::to_vec(&journal.snapshot(&cancel, deadline()).unwrap()).unwrap(),
            before
        );
    }
}

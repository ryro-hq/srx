use super::{activation::ActivationJournal, installation::GenerationInstallation};
use crate::{cancellation::Cancellation, store::ContentDigest};
use std::path::Path;
use std::time::Instant;

#[derive(Debug, thiserror::Error)]
#[error("cannot abandon Os operation: {stage}")]
pub struct OsAbandonmentError {
    stage: &'static str,
}
fn failure(stage: &'static str) -> OsAbandonmentError {
    OsAbandonmentError {
        stage,
    }
}
#[derive(Debug)]
pub struct OsAbandonment {
    pub installation: String,
    pub operation: String,
    pub candidate: ContentDigest,
}

/// Clear desired selection only after all recorded effects are terminal.
/// Existing authorizations, services, files and roots remain unchanged. This
/// neither rolls back the candidate nor establishes process quiescence.
pub fn abandon_os_operation(
    installation: &Path,
    operation: &str,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsAbandonment, OsAbandonmentError> {
    if operation.len() != 32
        || operation.bytes().all(|byte| byte == b'0')
        || !operation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(failure("invalid operation identifier"));
    }
    let installation =
        std::path::absolute(installation).map_err(|_| failure("invalid installation path"))?;
    let opened = GenerationInstallation::open_existing(&installation, cancellation, deadline)
        .map_err(|_| failure("open existing installation"))?;
    let _execution = opened
        .execution(cancellation, deadline)
        .map_err(|_| failure("acquire execution authority"))?;
    let journal = ActivationJournal::open_existing(&installation, cancellation, deadline)
        .map_err(|_| failure("open activation journal"))?;
    opened
        .validate_path(&installation, cancellation, deadline)
        .map_err(|_| failure("installation changed"))?;
    let candidate = journal
        .abandon(operation, cancellation, deadline)
        .map_err(|_| failure("selection changed or effects require reconciliation"))?;
    Ok(OsAbandonment {
        installation: opened.id().into(),
        operation: operation.into(),
        candidate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::os::activation::{EffectKind, ExecutionEpoch};
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }
    fn epoch() -> ExecutionEpoch {
        ExecutionEpoch {
            boot: crate::platform::linux::boot::BootId::parse(
                "11111111-1111-4111-8111-111111111111",
            )
            .unwrap(),
            manager: "test-manager".into(),
            scope: "test-scope".into(),
        }
    }
    fn fixture() -> (
        tempfile::TempDir,
        GenerationInstallation,
        ActivationJournal,
        String,
    ) {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let cancel = Cancellation::default();
        let installation =
            GenerationInstallation::initialize(temp.path(), &cancel, deadline()).unwrap();
        let journal = ActivationJournal::open_existing(temp.path(), &cancel, deadline()).unwrap();
        let operation = journal
            .begin_test_pin(
                ContentDigest::sha256(b"candidate"),
                None,
                epoch(),
                &cancel,
                deadline(),
            )
            .unwrap();
        (temp, installation, journal, operation)
    }

    #[test]
    fn public_abandonment_clears_selection_without_store_and_is_repeatable() {
        let (temp, installation, journal, operation) = fixture();
        let cancel = Cancellation::default();
        let report = abandon_os_operation(temp.path(), &operation, &cancel, deadline()).unwrap();
        assert_eq!(report.installation, installation.id());
        assert_eq!(report.operation, operation);
        assert_eq!(
            report.candidate,
            ContentDigest::sha256(b"candidate")
        );
        let snapshot = journal.snapshot(&cancel, deadline()).unwrap();
        assert!(snapshot.desired.is_none());
        assert!(snapshot.active_operation.is_none());
        assert!(snapshot.operations[&operation].abandoned);
        abandon_os_operation(temp.path(), &operation, &cancel, deadline()).unwrap();
        let next = journal
            .begin_test_pin(
                ContentDigest::sha256(b"next"),
                None,
                epoch(),
                &cancel,
                deadline(),
            )
            .unwrap();
        assert!(abandon_os_operation(temp.path(), &operation, &cancel, deadline()).is_err());
        assert_eq!(
            journal
                .snapshot(&cancel, deadline())
                .unwrap()
                .active_operation,
            Some(next)
        );
    }

    #[test]
    fn unresolved_effect_and_execution_owner_prevent_abandonment() {
        let (temp, installation, journal, operation) = fixture();
        let cancel = Cancellation::default();
        let effect = journal
            .plan_effect(
                &operation,
                "service/process",
                EffectKind::Publish,
                None,
                ContentDigest::sha256(b"binding"),
                &cancel,
                deadline(),
            )
            .unwrap();
        assert!(abandon_os_operation(temp.path(), &operation, &cancel, deadline()).is_err());
        assert_eq!(
            journal
                .snapshot(&cancel, deadline())
                .unwrap()
                .active_operation
                .as_deref(),
            Some(operation.as_str())
        );
        let guard = installation
            .execution(&cancel, deadline())
            .unwrap();
        journal
            .record_not_applied(&operation, &effect, &cancel, deadline())
            .unwrap();
        assert!(
            abandon_os_operation(
                temp.path(),
                &operation,
                &cancel,
                Instant::now() + Duration::from_millis(20)
            )
            .is_err()
        );
        drop(guard);
        abandon_os_operation(temp.path(), &operation, &cancel, deadline()).unwrap();
    }

    #[test]
    fn invalid_missing_and_cancelled_requests_do_not_initialize_state() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        for operation in [
            "invalid",
            "11111111111111111111111111111111",
        ] {
            assert!(
                abandon_os_operation(
                    &missing,
                    operation,
                    &Cancellation::default(),
                    deadline()
                )
                .is_err()
            );
            assert!(!missing.exists());
        }
        let (temp, _installation, journal, operation) = fixture();
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(abandon_os_operation(temp.path(), &operation, &cancel, deadline()).is_err());
        assert_eq!(
            journal
                .snapshot(&Cancellation::default(), deadline())
                .unwrap()
                .active_operation,
            Some(operation)
        );
    }

    #[test]
    fn relative_installation_path_is_accepted_without_changing_process_cwd() {
        let temp = tempfile::Builder::new()
            .prefix(".syrox-abandon-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(".")
            .unwrap();
        let cancel = Cancellation::default();
        let path = temp.path().file_name().unwrap();
        let relative = Path::new(path);
        GenerationInstallation::initialize(relative, &cancel, deadline()).unwrap();
        let journal = ActivationJournal::open_existing(relative, &cancel, deadline()).unwrap();
        let operation = journal
            .begin_test_pin(
                ContentDigest::sha256(b"relative"),
                None,
                epoch(),
                &cancel,
                deadline(),
            )
            .unwrap();
        abandon_os_operation(relative, &operation, &cancel, deadline()).unwrap();
        assert!(
            journal
                .snapshot(&cancel, deadline())
                .unwrap()
                .desired
                .is_none()
        );
    }
}

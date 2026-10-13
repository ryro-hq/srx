use super::{
    BuildError, Cancellation, FILE, Instant, LIMIT, ManagedAttemptContext, Operation, Record,
    SETTLED_FILE, State, acquire_guard, awaiting_record, check, invalid, linux_fd, read,
    settlement, validate_context, validate_current_context, validate_guard,
    validate_shared_attempt, write,
};

pub(in crate::build) struct LocalManagedPreparation<'a> {
    operation: &'a Operation,
    guard: linux_fd::OpenedPath,
    installed: Option<Vec<u8>>,
    finished: bool,
}
impl Operation {
    #[cfg(test)]
    pub(in crate::build) fn with_managed_preparation<T>(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
        build: impl FnOnce(&mut LocalManagedPreparation<'_>) -> Result<T, BuildError>,
    ) -> Result<T, BuildError> {
        self.with_managed_preparation_cleanup(cancellation, deadline, build, |_| Ok(()))
    }
    pub(in crate::build) fn with_managed_preparation_cleanup<T>(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
        build: impl FnOnce(&mut LocalManagedPreparation<'_>) -> Result<T, BuildError>,
        discard: impl FnOnce(T) -> std::io::Result<()>,
    ) -> Result<T, BuildError> {
        // Cancellation must not strand a fresh local operation before its owner
        // exists. This independent, bounded lock budget grants no remote rights.
        let local_cancel = Cancellation::default();
        let local_deadline = Instant::now() + std::time::Duration::from_secs(5);
        let guard = acquire_guard(self, &local_cancel, local_deadline)?;
        for name in [
            FILE,
            SETTLED_FILE,
            "authorized",
            "revoked",
            "cleaned",
            "cgroup",
        ] {
            if read(&self.directory, name, LIMIT)?.is_some() {
                return Err(invalid("operation already has admission state"));
            }
        }
        let mut local = LocalManagedPreparation {
            operation: self,
            guard,
            installed: None,
            finished: false,
        };
        let result = check(cancellation, deadline).and_then(|()| build(&mut local));
        let result = match result {
            Ok(value) => {
                let validation = check(cancellation, deadline)
                    .and_then(|()| local.validate())
                    .and_then(|()| {
                        if local.installed.is_none() {
                            Err(invalid(
                                "managed preparation did not install an attempt",
                            ))
                        } else {
                            Ok(())
                        }
                    });
                match validation {
                    Ok(()) => Ok(value),
                    Err(primary) => Err(match discard(value) {
                        Ok(()) => primary,
                        Err(cleanup) => BuildError::FailureAndCleanup {
                            primary: Box::new(primary),
                            cleanup,
                        },
                    }),
                }
            }
            Err(error) => Err(error),
        };
        local.finished = true;
        match result {
            Ok(value) => Ok(value),
            Err(primary) => Err(match local.abort() {
                Ok(()) => primary,
                Err(cleanup) => BuildError::FailureAndJournal {
                    primary: Box::new(primary),
                    journal: cleanup.to_string(),
                },
            }),
        }
    }
}
impl LocalManagedPreparation<'_> {
    pub(in crate::build) fn install(
        &mut self,
        context: &ManagedAttemptContext,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<String, BuildError> {
        if self.installed.is_some() {
            return Err(invalid("managed attempt already installed"));
        }
        check(cancellation, deadline)?;
        self.validate()?;
        validate_context(context)?;
        validate_current_context(self.operation, context)?;
        validate_shared_attempt(&self.operation.directory, context.action)?;
        let record = awaiting_record(context)?;
        let bytes = record.encode()?;
        Record::parse(&bytes)?;
        // Preserve exact ownership even if write reports an error after rename.
        self.installed = Some(bytes.clone());
        write(&self.operation.directory, FILE, &bytes)?;
        Ok(record.nonce)
    }
    fn validate(&self) -> Result<(), BuildError> {
        validate_guard(self.operation, &self.guard)?;
        for name in [
            SETTLED_FILE,
            "authorized",
            "revoked",
            "cleaned",
            "cgroup",
        ] {
            if read(&self.operation.directory, name, LIMIT)?.is_some() {
                return Err(invalid(
                    "local managed preparation changed admission state",
                ));
            }
        }
        if read(&self.operation.directory, FILE, LIMIT)? != self.installed {
            return Err(invalid(
                "local managed preparation attempt changed",
            ));
        }
        Ok(())
    }
    fn abort(&self) -> Result<(), BuildError> {
        validate_guard(self.operation, &self.guard)?;
        let actual = read(&self.operation.directory, FILE, LIMIT)?;
        if actual.is_some() && actual != self.installed {
            return Err(invalid(
                "cannot abandon a foreign managed attempt",
            ));
        }
        for name in [
            SETTLED_FILE,
            "authorized",
            "revoked",
            "cleaned",
            "cgroup",
        ] {
            if read(&self.operation.directory, name, LIMIT)?.is_some() {
                return Err(invalid("cannot abandon changed admission state"));
            }
        }
        if let Some(bytes) = actual {
            let mut record = Record::parse(&bytes)?;
            if record.state != State::Awaiting
                || record.binding.is_some()
                || record.namespace.is_some()
            {
                return Err(invalid(
                    "local preparation is no longer unstarted",
                ));
            }
            record.state = State::LocalAborted;
            settlement::record_unstarted(self.operation, &self.guard, &record)
        } else {
            // The exclusive token was obtained before any admission existed;
            // no service description escaped from this local callback.
            super::super::validate_tree(&self.operation.directory)?;
            write(
                &self.operation.directory,
                "revoked",
                super::super::REVOKED,
            )?;
            super::super::remove_stage(&self.operation.directory)?;
            write(
                &self.operation.directory,
                "cleaned",
                super::super::CLEANED,
            )
        }
    }
}
impl Drop for LocalManagedPreparation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{boot_id, settled_managed};
    use super::*;
    use crate::build::journal::lock_existing;
    use crate::{store::ContentDigest, store::Store, systemd::SystemdUnitName};
    use std::time::Duration;

    fn fixture() -> (
        tempfile::TempDir,
        Store,
        Operation,
        ManagedAttemptContext,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::initialize(&directory.path().join("store")).unwrap();
        let operation = Operation::create(&store.operation().unwrap()).unwrap();
        operation
            .write_stage("source", b"preserved", false)
            .unwrap();
        let context = ManagedAttemptContext {
            action: ContentDigest::sha256(b"action"),
            worker: ContentDigest::sha256(b"worker"),
            boot: boot_id().unwrap(),
            manager: ContentDigest::sha256(b"manager"),
            scope: "user:/run/user/1000/bus".into(),
            unit: SystemdUnitName::new(operation.unit()).unwrap(),
            uid: linux_fd::real_uid(),
            gid: linux_fd::real_gid(),
        };
        (directory, store, operation, context)
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn local_error_before_install_cleans_without_claiming_remote_settlement() {
        let (_directory, store, operation, _context) = fixture();
        let result =
            operation.with_managed_preparation(&Cancellation::default(), deadline(), |_| {
                Err::<(), _>(BuildError::InputChanged)
            });
        assert!(matches!(result, Err(BuildError::InputChanged)));
        assert!(
            read(&operation.directory, FILE, LIMIT)
                .unwrap()
                .is_none()
        );
        assert!(super::super::super::terminal_settlement(&operation.directory).unwrap());
        drop(operation);
        assert_eq!(
            super::super::super::recover(&store)
                .unwrap()
                .entries[0]
                .state,
            crate::build::BuildRecoveryState::Recovered
        );
    }

    #[test]
    fn cancellation_after_install_records_terminal_without_deleting_stage() {
        let (_directory, store, operation, context) = fixture();
        let cancel = Cancellation::default();
        let result = operation.with_managed_preparation(&cancel, deadline(), |local| {
            local.install(&context, &cancel, deadline())?;
            cancel.cancel();
            Ok(())
        });
        assert!(matches!(result, Err(BuildError::Cancelled)));
        assert!(settled_managed(&operation.directory).unwrap());
        assert!(operation.stage_path().join("source").exists());
        assert!(
            operation
                .with_managed_preparation(&Cancellation::default(), deadline(), |_| Ok(()))
                .is_err()
        );
        drop(operation);
        assert_eq!(
            super::super::super::recover(&store)
                .unwrap()
                .entries[0]
                .state,
            crate::build::BuildRecoveryState::Recovered
        );
    }

    #[test]
    fn uncertain_record_write_can_be_closed_only_by_its_live_local_token() {
        let (_directory, _store, operation, context) = fixture();
        let cancel = Cancellation::default();
        let result = operation.with_managed_preparation(&cancel, deadline(), |local| {
            linux_fd::fail_next_lock_after_rename();
            local.install(&context, &cancel, deadline())
        });
        assert!(result.is_err());
        assert!(settled_managed(&operation.directory).unwrap());
    }

    #[test]
    fn preexisting_or_substituted_attempt_never_gains_local_abort_authority() {
        let (_directory, _store, operation, context) = fixture();
        let cancel = Cancellation::default();
        let mut foreign = context.clone();
        foreign.manager = ContentDigest::sha256(b"foreign manager");
        let result = operation.with_managed_preparation(&cancel, deadline(), |local| {
            local.install(&context, &cancel, deadline())?;
            let replacement = awaiting_record(&foreign)?.encode()?;
            write(&operation.directory, FILE, &replacement)?;
            Err::<(), _>(BuildError::InputChanged)
        });
        assert!(matches!(
            result,
            Err(BuildError::FailureAndJournal { .. })
        ));
        assert!(!settled_managed(&operation.directory).unwrap());
        assert!(
            operation
                .with_managed_preparation::<()>(&cancel, deadline(), |_| panic!(
                    "must refuse before callback"
                ))
                .is_err()
        );
        assert!(operation.stage_path().join("source").exists());
    }

    #[test]
    fn already_cancelled_or_expired_request_still_closes_only_its_fresh_operation() {
        for cancelled in [false, true] {
            let (_directory, _store, operation, _context) = fixture();
            let cancel = Cancellation::default();
            let deadline = if cancelled {
                cancel.cancel();
                deadline()
            } else {
                Instant::now()
            };
            assert!(
                operation
                    .with_managed_preparation::<()>(&cancel, deadline, |_| panic!(
                        "request must not enter builder"
                    ))
                    .is_err()
            );
            assert!(super::super::super::terminal_settlement(&operation.directory).unwrap());
        }
    }

    #[test]
    fn successful_description_does_not_prove_settlement_or_allow_repreparation() {
        let (_directory, _store, operation, context) = fixture();
        let cancel = Cancellation::default();
        let nonce = operation
            .with_managed_preparation(&cancel, deadline(), |local| {
                assert!(lock_existing(&operation.directory, "gate")?.is_none());
                local.install(&context, &cancel, deadline())
            })
            .unwrap();
        assert!(!nonce.is_empty());
        assert!(!settled_managed(&operation.directory).unwrap());
        assert!(
            operation
                .with_managed_preparation::<()>(&cancel, deadline(), |_| panic!(
                    "must refuse preexisting attempt"
                ))
                .is_err()
        );
        assert!(!settled_managed(&operation.directory).unwrap());
    }

    #[test]
    fn final_validation_preserves_output_cleanup_failure_and_closes_local_attempt() {
        let (_directory, _store, operation, context) = fixture();
        let cancel = Cancellation::default();
        let discarded = std::cell::Cell::new(false);
        let result = operation.with_managed_preparation_cleanup(
            &cancel,
            deadline(),
            |local| {
                local.install(&context, &cancel, deadline())?;
                cancel.cancel();
                Ok(())
            },
            |()| {
                discarded.set(true);
                Err(std::io::Error::other("cleanup evidence"))
            },
        );
        assert!(discarded.get());
        assert!(
            matches!(result, Err(BuildError::FailureAndCleanup { primary, .. }) if matches!(*primary, BuildError::Cancelled))
        );
        assert!(settled_managed(&operation.directory).unwrap());
    }
}

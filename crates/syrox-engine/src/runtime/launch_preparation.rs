//! Prepara a descrição e os descritores de uma invocação.
//!
//! A sessão conserva a configuração enquanto algum consumidor ainda pode usá-la.
//! Esta preparação reúne os recursos; iniciar o processo e publicar a autorização
//! são etapas do launcher.

use std::ffi::OsString;
use std::fs::File;
use std::os::fd::AsFd as _;
use std::os::fd::OwnedFd;
use std::path::Path;

use crate::cancellation::Cancellation;
use crate::execution::resources::{
    MAX_SERVICE_ARGUMENT_BYTES, MAX_SERVICE_ARGUMENTS, ServiceMount, ServiceMountKind, ServiceSpec,
};

use super::{RuntimeClosure, RuntimeConfiguration, RuntimeError, check_runtime, invalid};
use crate::store::ObjectLease;

pub(crate) struct PreparedRuntimeLaunch {
    pub(crate) spec: ServiceSpec,
    pub(crate) descriptors: Vec<OwnedFd>,
    pub(crate) retention: File,
    /// Only local preparation has authenticated Store provenance for durable holds.
    pub(crate) origin_interest: Option<Box<ObjectLease>>,
}

pub(crate) fn prepare_runtime_launch(
    closure: &RuntimeClosure,
    argv: &[OsString],
    working_directory: &Path,
    configuration: &RuntimeConfiguration,
    cancellation: &Cancellation,
) -> Result<PreparedRuntimeLaunch, RuntimeError> {
    check_runtime(cancellation)?;
    if argv.len() > MAX_SERVICE_ARGUMENTS
        || argv
            .iter()
            .any(|argument| argument.len() > MAX_SERVICE_ARGUMENT_BYTES)
    {
        return Err(invalid("managed service argument bound exceeded"));
    }
    let arguments = argv
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("managed service arguments must be UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let prepared = super::prepare_runtime_mounts(closure, working_directory, configuration)?;
    crate::execution::resources::validate_managed_working_descriptor(prepared.cwd_descriptor.fd())?;
    let mut mounts = Vec::new();
    let mut descriptors = Vec::new();
    for (mount, directory) in prepared.mounts {
        check_runtime(cancellation)?;
        mounts.push(ServiceMount {
            kind: ServiceMountKind::Output,
            slot: slot(descriptors.len())?,
            target: mount.target,
        });
        descriptors.push(directory.try_clone_to_owned()?);
    }
    if let Some(directory) = &configuration.directory {
        super::configuration::validate_configuration_directory(directory.fd())?;
        mounts.push(ServiceMount {
            kind: ServiceMountKind::Configuration,
            slot: slot(descriptors.len())?,
            target: configuration
                .prefix()
                .expect("validated configuration prefix")
                .into(),
        });
        descriptors.push(directory.fd().try_clone_to_owned()?);
    }
    if let Some((target, directory)) = &configuration.state {
        super::configuration::validate_state_directory(directory.fd())?;
        mounts.push(ServiceMount {
            kind: ServiceMountKind::State,
            slot: slot(descriptors.len())?,
            target: target.clone(),
        });
        descriptors.push(directory.fd().try_clone_to_owned()?);
    }
    for (target, file) in &configuration.secrets {
        check_runtime(cancellation)?;
        crate::platform::linux::fd::sealed_file::validate(file.as_fd())?;
        mounts.push(ServiceMount {
            kind: ServiceMountKind::Secret,
            slot: slot(descriptors.len())?,
            target: target.clone(),
        });
        descriptors.push(file.as_fd().try_clone_to_owned()?);
    }
    let cwd = path_text(&prepared.cwd)?;
    mounts.push(ServiceMount {
        kind: ServiceMountKind::Working,
        slot: slot(descriptors.len())?,
        target: cwd.clone(),
    });
    descriptors.push(
        prepared
            .cwd_descriptor
            .fd()
            .try_clone_to_owned()?,
    );
    let spec = ServiceSpec {
        mounts,
        masked_store: prepared
            .masked_store
            .as_deref()
            .map(path_text)
            .transpose()?,
        cwd,
        locale: closure.utf8_locale.clone(),
        environment: configuration.environment.clone(),
        program: closure.entry(),
        arguments,
    };
    spec.validate()
        .map_err(|error| invalid(&format!("invalid prepared service: {error}")))?;
    check_runtime(cancellation)?;
    // This is a separate flock description, not an incidental duplicate of the
    // coordinator's ordinary lease that could be explicitly unlocked on Drop.
    let interests: Vec<_> = std::iter::once(&closure.application().output)
        .chain(closure.loader().map(|file| &file.output))
        .chain(closure.libraries().iter())
        .map(crate::result::MaterializedArtifact::object_lease)
        .collect();
    let origin_interest = ObjectLease::combine(&interests)?;
    let retention = origin_interest.process_retention()?;
    Ok(PreparedRuntimeLaunch {
        spec,
        descriptors,
        retention,
        origin_interest: Some(Box::new(origin_interest)),
    })
}

fn slot(index: usize) -> Result<u16, RuntimeError> {
    u16::try_from(index).map_err(|_| invalid("too many runtime descriptor slots"))
}

fn path_text(path: &Path) -> Result<String, RuntimeError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("managed service paths must be UTF-8"))
}

pub(crate) struct ReusableRuntimeLaunch {
    spec: ServiceSpec,
    descriptors: Vec<OwnedFd>,
    interest: ObjectLease,
}
impl PreparedRuntimeLaunch {
    /// A descriptor received over IPC does not establish Store provenance. Only
    /// locally prepared launches can become a role with durable retention.
    pub(crate) fn into_reusable(self) -> Result<ReusableRuntimeLaunch, RuntimeError> {
        let interest = self
            .origin_interest
            .ok_or_else(|| invalid("received runtime resources cannot create a reusable role"))?;
        Ok(ReusableRuntimeLaunch {
            spec: self.spec,
            descriptors: self.descriptors,
            interest: *interest,
        })
    }
}
impl ReusableRuntimeLaunch {
    #[cfg(test)]
    pub(crate) fn spec(&self) -> &ServiceSpec {
        &self.spec
    }

    /// Comparison data for the durable publication intent. Neither pin grants
    /// authority to start a process or to retire an existing interest.
    pub(crate) fn retention_identity(
        &self,
    ) -> Result<
        (
            crate::store::ContentDigest,
            crate::store::ContentDigest,
        ),
        RuntimeError,
    > {
        Ok((
            self.interest.durable_digest(),
            self.interest.durable_store_anchor()?,
        ))
    }

    /// Reuses already pinned configuration, state and sealed secret descriptors;
    /// it never reopens an original source. The retention file has a new OFD for
    /// each invocation, independent of both the role lease and other attempts.
    pub(crate) fn prepare_attempt(
        &self,
        cancel: &Cancellation,
    ) -> Result<PreparedRuntimeLaunch, RuntimeError> {
        check_runtime(cancel)?;
        self.spec
            .worker_request(&self.descriptors)
            .map_err(|_| invalid("pinned role resource validation failed"))?;
        let mut descriptors = Vec::with_capacity(self.descriptors.len());
        for descriptor in &self.descriptors {
            check_runtime(cancel)?;
            descriptors.push(descriptor.as_fd().try_clone_to_owned()?);
        }
        let retention = self.interest.process_retention()?;
        check_runtime(cancel)?;
        Ok(PreparedRuntimeLaunch {
            spec: self.spec.clone(),
            descriptors,
            retention,
            origin_interest: None,
        })
    }

    /// The initial attempt ID must already be journaled. Publish before Start;
    /// uncertain admission or lost supervision preserves this hold on Drop.
    /// This method does not authorize spawning or determine settlement.
    pub(crate) fn persist_role(
        &self,
        first_attempt: &str,
        cancel: &Cancellation,
    ) -> Result<crate::store::DurableInterest, RuntimeError> {
        check_runtime(cancel)?;
        self.interest
            .persist_checked(first_attempt, || {
                cancel
                    .check()
                    .map_err(|_| crate::cancellation::cancellation_io())
            })
            .map_err(|error| match error {
                crate::store::StoreError::Io(source)
                    if crate::cancellation::is_cancellation_io(&source) =>
                {
                    RuntimeError::Cancelled
                }
                error => RuntimeError::Store(error),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        runtime::RuntimeFile, runtime::RuntimeOutput, runtime::RuntimeRequest, store::Store,
    };
    use std::fs;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn fixture() -> (tempfile::TempDir, Store, RuntimeClosure) {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("store")).unwrap();
        fs::create_dir(temp.path().join("cwd")).unwrap();
        let store = Store::open(&temp.path().join("store")).unwrap();
        let result = {
            let lease = store.operation().unwrap();
            crate::build::cache::tests::retained(
                &lease,
                &crate::build::cache::tests::action(),
                &crate::runtime::tests::elf(2, None, &[], None, None),
            )
        };
        let closure = crate::runtime::verify_runtime(
            &store,
            &RuntimeRequest {
                application: RuntimeFile {
                    output: RuntimeOutput {
                        root: result.root,
                        receipt: result.receipt,
                        output: "out".into(),
                    },
                    path: "bin/hello".into(),
                },
                loader: None,
                libraries: Vec::new(),
            },
        )
        .unwrap();
        (temp, store, closure)
    }
    fn error(result: Result<PreparedRuntimeLaunch, RuntimeError>) -> RuntimeError {
        match result {
            Ok(_) => panic!("preparation should fail"),
            Err(error) => error,
        }
    }
    #[test]
    fn independent_retention_survives_original_closure_and_descriptor_handoff() {
        // CLOEXEC does not stop other harness threads' fork children from extending
        // this descriptor's lifetime. Keep the last-close assertion in isolation.
        if crate::platform::linux::fd::retention_fork_tests::isolate_test(
            "runtime::launch_preparation::tests::independent_retention_survives_original_closure_and_descriptor_handoff",
            "SYROX_GC_RETENTION_ISOLATED",
        ) {
            return;
        }
        let (temp, store, closure) = fixture();
        let prepared = prepare_runtime_launch(
            &closure,
            &["hello".into()],
            &temp.path().join("cwd"),
            &RuntimeConfiguration::default(),
            &Cancellation::default(),
        )
        .unwrap();
        let artifact_identity =
            crate::platform::linux::fd::metadata(closure.application().output.mount_fd())
                .unwrap()
                .identity();
        assert_eq!(
            crate::platform::linux::fd::metadata(prepared.descriptors[0].as_fd())
                .unwrap()
                .identity(),
            artifact_identity
        );
        let prepared_request = prepared
            .spec
            .worker_request(&prepared.descriptors)
            .unwrap();
        assert_eq!(
            prepared_request.arguments,
            [OsString::from("hello")]
        );
        let artifact = closure.application().output.artifact();
        let operation = store.operation().unwrap();
        let roots = operation.managed_build_roots().unwrap();
        let garbage = crate::store::ContentDigest::sha256(b"unrelated preparation garbage");
        operation
            .ingest(&b"unrelated preparation garbage"[..], garbage, 29)
            .unwrap();
        drop(operation);
        let handoff = prepared.retention.try_clone().unwrap();
        drop(closure);
        {
            let mut maintenance = store.maintenance().unwrap();
            let report = maintenance
                .garbage_collect(&crate::store::GcRequest {
                    collect: true,
                    remove_roots: roots,
                    ..crate::store::GcRequest::default()
                })
                .unwrap();
            assert_eq!(report.removed_objects, [garbage]);
            assert_eq!(
                crate::result::clear_materializations(&mut maintenance).unwrap(),
                0
            );
        }
        drop(prepared);
        {
            let mut maintenance = store.maintenance().unwrap();
            assert!(
                maintenance
                    .garbage_collect(&crate::store::GcRequest {
                        collect: true,
                        ..crate::store::GcRequest::default()
                    })
                    .unwrap()
                    .removed_objects
                    .is_empty()
            );
            assert_eq!(
                crate::result::clear_materializations(&mut maintenance).unwrap(),
                0
            );
        }
        drop(handoff);
        let mut maintenance = store.maintenance().unwrap();
        let collected = maintenance
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                ..crate::store::GcRequest::default()
            })
            .unwrap();
        assert!(collected.removed_objects.contains(&artifact));
        assert_eq!(
            crate::result::clear_materializations(&mut maintenance).unwrap(),
            1
        );
    }
    #[test]
    fn cancellation_and_invalid_arguments_precede_working_directory_access() {
        let (temp, store, closure) = fixture();
        let missing = temp.path().join("missing-directory");
        let configuration = RuntimeConfiguration::default();
        let cancellation = Cancellation::default();
        cancellation.cancel();
        assert!(matches!(
            error(prepare_runtime_launch(
                &closure,
                &[],
                &missing,
                &configuration,
                &cancellation
            )),
            RuntimeError::Cancelled
        ));
        for arguments in [
            vec![OsString::from_vec(vec![0xff])],
            vec![OsString::from("x"); MAX_SERVICE_ARGUMENTS + 1],
            vec![OsString::from(
                "x".repeat(MAX_SERVICE_ARGUMENT_BYTES + 1),
            )],
        ] {
            let failure = error(prepare_runtime_launch(
                &closure,
                &arguments,
                &missing,
                &configuration,
                &Cancellation::default(),
            ));
            assert!(
                matches!(failure,RuntimeError::Invalid(message) if message.contains("argument"))
            );
        }
        assert!(!missing.exists());
        drop(closure);
        assert!(store.maintenance().is_ok());
    }
    #[test]
    fn store_inside_working_directory_is_masked_but_store_as_cwd_is_refused() {
        let (temp, store, closure) = fixture();
        let configuration = RuntimeConfiguration::default();
        let cancellation = Cancellation::default();
        let launch = prepare_runtime_launch(
            &closure,
            &[],
            temp.path(),
            &configuration,
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            launch.spec.masked_store.as_deref(),
            temp.path().join("store").to_str()
        );
        launch
            .spec
            .worker_request(&launch.descriptors)
            .unwrap();
        assert!(
            prepare_runtime_launch(
                &closure,
                &[],
                &temp.path().join("store"),
                &configuration,
                &cancellation
            )
            .is_err()
        );
        drop(launch);
        drop(closure);
        assert!(store.maintenance().is_ok());
    }
    #[test]
    fn non_utf8_working_directory_is_rejected_without_a_retention_leak() {
        let (temp, store, closure) = fixture();
        let path = temp
            .path()
            .join(OsString::from_vec(vec![b'w', 0xff]));
        fs::create_dir(&path).unwrap();
        let failure = error(prepare_runtime_launch(
            &closure,
            &[],
            &path,
            &RuntimeConfiguration::default(),
            &Cancellation::default(),
        ));
        assert!(matches!(failure,RuntimeError::Invalid(message) if message.contains("UTF-8")));
        drop(closure);
        assert!(store.maintenance().is_ok());
    }
    #[test]
    fn configuration_overlap_and_permissions_are_checked_again_before_retention() {
        let (temp, store, closure) = fixture();
        let directory = temp.path().join("configuration");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("settings");
        fs::write(&file, b"public configuration").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        let configuration = RuntimeConfiguration::new(
            "service",
            File::open(&directory).unwrap(),
            std::collections::BTreeMap::new(),
        )
        .unwrap();
        let cancellation = Cancellation::default();
        assert!(
            prepare_runtime_launch(
                &closure,
                &[],
                temp.path(),
                &configuration,
                &cancellation
            )
            .is_err()
        );
        let launch = prepare_runtime_launch(
            &closure,
            &[],
            &temp.path().join("cwd"),
            &configuration,
            &cancellation,
        )
        .unwrap();
        assert!(
            launch
                .spec
                .mounts
                .iter()
                .any(|mount| mount.kind == ServiceMountKind::Configuration)
        );
        drop(launch);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            prepare_runtime_launch(
                &closure,
                &[],
                &temp.path().join("cwd"),
                &configuration,
                &cancellation
            )
            .is_err()
        );
        drop(closure);
        assert!(store.maintenance().is_ok());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[test]
    fn renamed_view_keeps_verified_inode_instead_of_the_replacement_directory() {
        let (temp, store, closure) = fixture();
        let identity =
            crate::platform::linux::fd::metadata(closure.application().output.mount_fd())
                .unwrap()
                .identity();
        let path = closure.application().output.directory().unwrap();
        let renamed = path.with_extension("old");
        fs::rename(&path, &renamed).unwrap();
        fs::create_dir(&path).unwrap();
        let replacement = crate::platform::linux::fd::open_top_directory(&path).unwrap();
        assert_ne!(replacement.metadata().identity(), identity);
        let launch = prepare_runtime_launch(
            &closure,
            &[],
            &temp.path().join("cwd"),
            &RuntimeConfiguration::default(),
            &Cancellation::default(),
        )
        .unwrap();
        assert_eq!(
            crate::platform::linux::fd::metadata(launch.descriptors[0].as_fd())
                .unwrap()
                .identity(),
            identity
        );
        assert_eq!(
            closure.application().output.directory().unwrap(),
            renamed
        );
        assert!(path.read_dir().unwrap().next().is_none());
        drop(launch);
        drop(closure);
        assert!(store.maintenance().is_ok());
    }

    #[test]
    fn session_state_handoff_is_writable_data_and_distinct_from_configuration() {
        let (temp, _store, closure) = fixture();
        let state = temp.path().join("session-state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(state.join("existing"), b"mutable data").unwrap();
        let directory = File::open(&state).unwrap();
        let configuration = RuntimeConfiguration::default()
            .with_session_state("database", directory.as_fd())
            .unwrap();
        let prepared = prepare_runtime_launch(
            &closure,
            &[],
            &temp.path().join("cwd"),
            &configuration,
            &Cancellation::default(),
        )
        .unwrap();
        let state_mount = prepared
            .spec
            .mounts
            .iter()
            .find(|m| m.kind == ServiceMountKind::State)
            .unwrap();
        assert_eq!(state_mount.target, "/syrox/state/database");
        let fd = &prepared.descriptors[usize::from(state_mount.slot)];
        assert_eq!(
            crate::platform::linux::fd::metadata(fd.as_fd())
                .unwrap()
                .identity(),
            crate::platform::linux::fd::metadata(directory.as_fd())
                .unwrap()
                .identity()
        );
        let request = prepared
            .spec
            .worker_request(&prepared.descriptors)
            .unwrap();
        assert!(
            request
                .mounts
                .iter()
                .any(|m| m.kind == crate::execution::configuration::MountKind::State)
        );
        let wire = prepared.spec.canonical_bytes().unwrap();
        assert!(
            !String::from_utf8(wire)
                .unwrap()
                .contains("mutable data")
        );
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            prepared
                .spec
                .worker_request(&prepared.descriptors)
                .is_err()
        );
    }

    mod reusable {
        use super::*;
        use crate::build::cache::tests::{action, retained, retained_with_library};
        use crate::runtime::tests::elf;
        use std::io::{Seek as _, SeekFrom};
        use std::os::unix::fs::FileExt as _;
        const FIRST: &str = "12121212121212121212121212121212";

        fn prepared(temp: &tempfile::TempDir, closure: &RuntimeClosure) -> PreparedRuntimeLaunch {
            prepare_runtime_launch(
                closure,
                &[],
                &temp.path().join("cwd"),
                &RuntimeConfiguration::default(),
                &Cancellation::default(),
            )
            .unwrap()
        }
        #[test]
        fn attempts_reuse_sealed_snapshot_but_have_independent_retention_descriptions() {
            let (temp, _store, closure) = fixture();
            let source = temp.path().join("source");
            fs::write(&source, b"first snapshot").unwrap();
            let cancel = Cancellation::default();
            let snapshot = crate::platform::linux::fd::sealed_file::snapshot(
                File::open(&source).unwrap(),
                &cancel,
                64,
            )
            .unwrap();
            let config = RuntimeConfiguration::default()
                .with_secret("service", "token", snapshot.as_fd())
                .unwrap();
            let template = prepare_runtime_launch(
                &closure,
                &[],
                &temp.path().join("cwd"),
                &config,
                &cancel,
            )
            .unwrap()
            .into_reusable()
            .unwrap();
            let slot = usize::from(
                template
                    .spec()
                    .mounts
                    .iter()
                    .find(|mount| mount.kind == ServiceMountKind::Secret)
                    .unwrap()
                    .slot,
            );
            drop((snapshot, config, closure));
            fs::write(&source, b"second snapshot").unwrap();
            let mut first = template.prepare_attempt(&cancel).unwrap();
            let mut second = template.prepare_attempt(&cancel).unwrap();
            assert_eq!(
                first.spec.canonical_bytes().unwrap(),
                second.spec.canonical_bytes().unwrap()
            );
            for attempt in [&first, &second] {
                let descriptor = attempt.descriptors[slot].as_fd();
                crate::platform::linux::fd::sealed_file::validate(descriptor).unwrap();
                let file = File::from(descriptor.try_clone_to_owned().unwrap());
                let mut bytes = [0; 14];
                file.read_exact_at(&mut bytes, 0).unwrap();
                assert_eq!(&bytes, b"first snapshot");
            }
            // A dup would share the seek offset; process_retention opens a fresh OFD.
            first.retention.seek(SeekFrom::Start(1)).unwrap();
            assert_eq!(second.retention.stream_position().unwrap(), 0);
            assert_eq!(first.retention.stream_position().unwrap(), 1);
        }
        #[test]
        fn durable_role_survives_all_runtime_descriptors_and_hold_handle_drop() {
            if crate::platform::linux::fd::retention_fork_tests::isolate_test(
                "runtime::launch_preparation::tests::reusable::durable_role_survives_all_runtime_descriptors_and_hold_handle_drop",
                "SYROX_ROLE_RETENTION_ISOLATED",
            ) {
                return;
            }
            let (temp, store, closure) = fixture();
            let artifact = closure.application().output.artifact();
            let template = prepared(&temp, &closure).into_reusable().unwrap();
            let cancel = Cancellation::default();
            let expected = template.retention_identity().unwrap();
            let first = template.persist_role(FIRST, &cancel).unwrap();
            assert_eq!((first.digest(), first.store_anchor()), expected);
            let retained = template.persist_role(FIRST, &cancel).unwrap();
            let attempt = template.prepare_attempt(&cancel).unwrap();
            let roots = store
                .operation()
                .unwrap()
                .managed_build_roots()
                .unwrap();
            drop((first, attempt, template, closure));
            {
                let mut maintenance = store.maintenance().unwrap();
                let report = maintenance
                    .garbage_collect(&crate::store::GcRequest {
                        collect: true,
                        remove_roots: roots,
                        ..crate::store::GcRequest::default()
                    })
                    .unwrap();
                assert!(!report.removed_objects.contains(&artifact));
                assert_eq!(
                    crate::result::clear_materializations(&mut maintenance).unwrap(),
                    0
                );
            }
            // No process has ever been launched in this store-only test. A production
            // coordinator must additionally prove every role attempt settled first.
            retained.retire_checked(|| Ok(())).unwrap();
            let mut maintenance = store.maintenance().unwrap();
            let report = maintenance
                .garbage_collect(&crate::store::GcRequest {
                    collect: true,
                    ..crate::store::GcRequest::default()
                })
                .unwrap();
            assert!(report.removed_objects.contains(&artifact));
            assert_eq!(
                crate::result::clear_materializations(&mut maintenance).unwrap(),
                1
            );
        }
        #[test]
        fn received_resources_cannot_create_role_and_cancellation_preserves_its_type() {
            let (temp, _store, closure) = fixture();
            let mut received = prepared(&temp, &closure);
            received.origin_interest = None;
            assert!(matches!(
                received.into_reusable(),
                Err(RuntimeError::Invalid(_))
            ));
            let template = prepared(&temp, &closure).into_reusable().unwrap();
            let cancel = Cancellation::default();
            cancel.cancel();
            assert!(matches!(
                template.prepare_attempt(&cancel),
                Err(RuntimeError::Cancelled)
            ));
            assert!(matches!(
                template.persist_role(FIRST, &cancel),
                Err(RuntimeError::Cancelled)
            ));
            assert!(
                template
                    .persist_role("not-an-attempt", &Cancellation::default())
                    .is_err()
            );
        }

        #[test]
        fn template_alone_retains_application_loader_and_library_until_drop() {
            if crate::platform::linux::fd::retention_fork_tests::isolate_test(
                "runtime::launch_preparation::tests::reusable::template_alone_retains_application_loader_and_library_until_drop",
                "SYROX_TEMPLATE_UNION_ISOLATED",
            ) {
                return;
            }
            let (temp, store, closure, receipts) = union_fixture();
            let artifacts = [
                closure.application().output.artifact(),
                closure.loader().unwrap().output.artifact(),
                closure.libraries()[0].artifact(),
            ];
            assert_eq!(
                artifacts
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                3
            );
            let roots = store
                .operation()
                .unwrap()
                .managed_build_roots()
                .unwrap();
            let template = prepared(&temp, &closure).into_reusable().unwrap();
            drop(closure);
            // No durable interest or attempt retention descriptor has been created.
            {
                let mut maintenance = store.maintenance().unwrap();
                let report = maintenance
                    .garbage_collect(&crate::store::GcRequest {
                        collect: true,
                        remove_roots: roots,
                        ..crate::store::GcRequest::default()
                    })
                    .unwrap();
                for digest in artifacts.iter().chain(&receipts) {
                    assert!(!report.removed_objects.contains(digest));
                }
                assert_eq!(
                    crate::result::clear_materializations(&mut maintenance).unwrap(),
                    0
                );
            }
            drop(template);
            let mut maintenance = store.maintenance().unwrap();
            let report = maintenance
                .garbage_collect(&crate::store::GcRequest {
                    collect: true,
                    ..crate::store::GcRequest::default()
                })
                .unwrap();
            for digest in artifacts.iter().chain(&receipts) {
                assert!(
                    report.removed_objects.contains(digest),
                    "unreleased object {digest}"
                );
            }
            assert_eq!(
                crate::result::clear_materializations(&mut maintenance).unwrap(),
                3
            );
        }

        fn union_fixture() -> (
            tempfile::TempDir,
            Store,
            RuntimeClosure,
            [crate::store::ContentDigest; 3],
        ) {
            // Reuse the existing runtime ELF-format helper. These bytes test verified
            // closure retention only; no ELF, worker or namespace is executed.
            let temp = tempfile::tempdir().unwrap();
            fs::create_dir(temp.path().join("cwd")).unwrap();
            fs::create_dir(temp.path().join("store")).unwrap();
            let store = Store::open(&temp.path().join("store")).unwrap();
            let operation = store.operation().unwrap();
            let mut identity = action();
            identity.directory = "template-loader".into();
            let loader = retained(
                &operation,
                &identity,
                &elf(3, None, &[], None, None),
            );
            identity.directory = "template-library".into();
            let library = retained_with_library(
                &operation,
                &identity,
                &elf(3, None, &[], None, None),
                "libtemplate.so.1",
                &elf(3, None, &[], Some("libtemplate.so.1"), None),
            );
            identity.directory = "template-application".into();
            let application = retained(
                &operation,
                &identity,
                &elf(
                    3,
                    Some(&format!(
                        "/syrox/store/{}/out/bin/hello",
                        loader.action
                    )),
                    &["libtemplate.so.1"],
                    None,
                    Some(&format!(
                        "/syrox/store/{}/out/usr/lib",
                        library.action
                    )),
                ),
            );
            let output = |result: &crate::build::BuildResult| RuntimeOutput {
                root: result.root.clone(),
                receipt: result.receipt,
                output: "out".into(),
            };
            let closure = crate::runtime::verify_runtime(
                &store,
                &RuntimeRequest {
                    application: RuntimeFile {
                        output: output(&application),
                        path: "bin/hello".into(),
                    },
                    loader: Some(RuntimeFile {
                        output: output(&loader),
                        path: "bin/hello".into(),
                    }),
                    libraries: vec![output(&library)],
                },
            )
            .unwrap();
            let receipts = [
                application.receipt,
                loader.receipt,
                library.receipt,
            ];
            drop((operation, application, loader, library));
            (temp, store, closure, receipts)
        }
    }
}

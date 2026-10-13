use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::path::{Path, PathBuf};

use crate::deployment::manifest::commands::PreparedCommandIndex;
use crate::deployment::shell::commands::PreparedCommandDirectory;
use crate::platform::linux::fd::{self as linux_fd, OpenedPath};
use crate::runtime::launch_preparation::{PreparedRuntimeLaunch, prepare_runtime_launch};
use crate::{
    cancellation::Cancellation, plan::PlanConsumerKind, runtime::RuntimeConfiguration,
    store::ContentDigest, store::ObjectLease,
};

use super::super::{SessionError, ShellSession, render};

#[derive(Clone, Copy)]
pub(crate) struct BrokerPreparation<'a> {
    pub(crate) parent: &'a Path,
    pub(crate) session: &'a str,
    pub(crate) socket_identity: linux_fd::FileIdentity,
    pub(crate) worker: &'a [u8],
    pub(crate) worker_digest: ContentDigest,
    pub(crate) cwd: &'a Path,
}

pub(crate) struct PreparedCommandBroker<'a> {
    session: super::super::ownership::SessionId,
    shell: &'a ShellSession,
    index: PreparedCommandIndex<'a>,
    directory: PreparedCommandDirectory,
    retention: ObjectLease,
    context: crate::runtime::command_proxy::ProxyContext,
    worker_digest: ContentDigest,
    cwd: PathBuf,
    cwd_anchor: OpenedPath,
}

impl<'a> PreparedCommandBroker<'a> {
    pub(crate) fn prepare(
        shell: &'a ShellSession,
        options: BrokerPreparation<'_>,
        cancel: &Cancellation,
    ) -> Result<Self, SessionError> {
        check(cancel)?;
        if shell.prepared.consumer().kind() != PlanConsumerKind::Shell {
            return Err(SessionError::NotShell);
        }
        let index = PreparedCommandIndex::new(shell.prepared.exposures())?;
        if index.names().len() == 0 {
            return Err(SessionError::Supervision(
                "Shell has no public commands".into(),
            ));
        }
        // Cover all selected outputs, including data-only selections, and every
        // runtime role. A command's application need not contain its loader.
        let mut interests: Vec<_> = shell
            .prepared
            .outputs()
            .values()
            .map(crate::result::MaterializedArtifact::object_lease)
            .collect();
        for invocation in shell.prepared.invocations().values() {
            check(cancel)?;
            let closure = invocation.closure();
            interests.extend(
                std::iter::once(&closure.application().output)
                    .chain(closure.loader().map(|file| &file.output))
                    .chain(closure.libraries())
                    .map(crate::result::MaterializedArtifact::object_lease),
            );
        }
        let retention = ObjectLease::combine(&interests)
            .map_err(crate::deployment::manifest::DeploymentError::from)?;
        let cwd = std::path::absolute(options.cwd)?;
        if cwd.starts_with(options.parent) || options.parent.starts_with(&cwd) {
            return Err(SessionError::Supervision(
                "command directory overlaps working directory".into(),
            ));
        }
        let cwd_anchor = linux_fd::open_top_directory(&cwd)
            .map_err(|_| SessionError::Supervision("invalid command working directory".into()))?;
        crate::execution::resources::validate_managed_working_descriptor(cwd_anchor.fd())?;
        // Verify every public invocation before publishing the command tree,
        // without retaining a duplicate set of descriptors for every alias.
        for alias in index.names() {
            check(cancel)?;
            drop(prepare_invocation(
                shell,
                &index,
                alias,
                &cwd,
                &cwd_anchor,
                cancel,
            )?);
        }
        check(cancel)?;
        let session = super::super::ownership::SessionId::parse(options.session)
            .map_err(|_| SessionError::Supervision("invalid command session identity".into()))?;
        let context = crate::runtime::command_proxy::ProxyContext::new(
            &session,
            index.digest(),
            options.socket_identity,
            &cwd,
        )
        .map_err(session_io)?;
        let directory = PreparedCommandDirectory::prepare(
            &index,
            options.parent,
            &context,
            options.worker,
            options.worker_digest,
            cancel,
        )
        .map_err(session_io)?;
        Ok(Self {
            session,
            shell,
            index,
            directory,
            retention,
            context,
            worker_digest: options.worker_digest,
            cwd,
            cwd_anchor,
        })
    }

    pub(crate) fn index(&self) -> &PreparedCommandIndex<'a> {
        &self.index
    }

    pub(crate) fn session(&self) -> &super::super::ownership::SessionId {
        &self.session
    }

    pub(crate) fn durable_retention_digest(&self) -> ContentDigest {
        self.retention.durable_digest()
    }

    /// Alias names alone do not identify the resources authorized for execution.
    /// Check the retained union before serving either resources or a gate ACK.
    pub(crate) fn matches_execution(
        &self,
        execution: &super::super::ownership::execution::ExecutionGuard<'_>,
    ) -> bool {
        self.session() == execution.session()
            && self.index().digest() == execution.index()
            && Some(self.durable_retention_digest()) == execution.retention_digest()
    }

    pub(crate) fn directory(&self) -> &PreparedCommandDirectory {
        &self.directory
    }

    pub(crate) fn context(&self) -> &crate::runtime::command_proxy::ProxyContext {
        &self.context
    }

    pub(crate) fn worker_digest(&self) -> ContentDigest {
        self.worker_digest
    }

    pub(crate) fn cwd_descriptor(&self) -> BorrowedFd<'_> {
        self.cwd_anchor.fd()
    }

    /// Independent OFD: releasing local leases must not unlock the monitor's
    /// interest before all sibling namespaces have settled.
    pub(crate) fn process_retention(&self) -> Result<File, SessionError> {
        self.retention
            .process_retention()
            .map_err(crate::deployment::manifest::DeploymentError::from)
            .map_err(Into::into)
    }

    /// Base arguments remain in the private canonical `ServiceSpec`. Validated
    /// arbitrary-byte arguments from the proxy are appended only after admission.
    pub(crate) fn prepare_invocation(
        &self,
        alias: &str,
        cancel: &Cancellation,
    ) -> Result<PreparedRuntimeLaunch, SessionError> {
        prepare_invocation(
            self.shell,
            &self.index,
            alias,
            &self.cwd,
            &self.cwd_anchor,
            cancel,
        )
    }

    /// Retain the complete public-command union across loss of all process
    /// descriptors. The execution identity must be journaled before spawning
    /// the guardian; callers retire this only after its settlement proof.
    pub(crate) fn persist_execution(
        &self,
        execution: &super::super::ownership::ExecutionId,
        cancel: &Cancellation,
    ) -> Result<crate::store::DurableInterest, SessionError> {
        self.retention
            .persist_checked(&execution.to_string(), || {
                cancel
                    .check()
                    .map_err(|_| crate::cancellation::cancellation_io())
            })
            .map_err(|error| match error {
                crate::store::StoreError::Io(source)
                    if crate::cancellation::is_cancellation_io(&source) =>
                {
                    SessionError::Cancelled
                }
                error => crate::deployment::manifest::DeploymentError::from(error).into(),
            })
    }

    /// Caller must prove settlement before consuming this inventory for cleanup.
    pub(crate) fn close(self, cancel: &Cancellation) -> Result<(), SessionError> {
        self.directory.close(cancel).map_err(session_io)
    }
}

fn prepare_invocation(
    shell: &ShellSession,
    index: &PreparedCommandIndex<'_>,
    alias: &str,
    cwd: &Path,
    cwd_anchor: &OpenedPath,
    cancel: &Cancellation,
) -> Result<PreparedRuntimeLaunch, SessionError> {
    check(cancel)?;
    let key = index
        .resolve(alias)
        .ok_or_else(|| SessionError::MissingCommand(alias.into()))?;
    let invocation = shell
        .prepared
        .invocations()
        .get(key)
        .ok_or_else(|| {
            SessionError::Supervision("public command lacks prepared invocation".into())
        })?;
    let service = key.0.as_deref();
    let arguments = invocation
        .arguments()
        .iter()
        .map(|argument| render(argument, service).map(OsString::from))
        .collect::<Result<Vec<_>, _>>()?;
    let environment = invocation
        .environment()
        .iter()
        .map(|entry| Ok((entry.name.clone(), render(&entry.value, service)?)))
        .collect::<Result<BTreeMap<_, _>, SessionError>>()?;
    let configuration = if let Some(service) = service {
        let configuration = RuntimeConfiguration::new(
            service,
            shell.files.service(service)?,
            environment,
        )?;
        let configuration = shell.secrets.configure(service, configuration)?;
        if let Some(state) = &shell.state {
            state.configure(service, configuration)?
        } else {
            configuration
        }
    } else {
        RuntimeConfiguration::default()
    };
    let launch = prepare_runtime_launch(
        invocation.closure(),
        &arguments,
        cwd,
        &configuration,
        cancel,
    )?;
    let working = launch
        .spec
        .mounts
        .iter()
        .find(|mount| mount.kind == crate::execution::resources::ServiceMountKind::Working)
        .ok_or_else(|| SessionError::Supervision("command lacks working directory".into()))?;
    if linux_fd::metadata(launch.descriptors[usize::from(working.slot)].as_fd())?.identity()
        != cwd_anchor.metadata().identity()
        || linux_fd::directory_path(cwd_anchor)? != cwd
    {
        return Err(SessionError::Supervision(
            "command working directory changed".into(),
        ));
    }
    check(cancel)?;
    Ok(launch)
}

fn check(cancel: &Cancellation) -> Result<(), SessionError> {
    if cancel.is_cancelled() {
        Err(SessionError::Cancelled)
    } else {
        Ok(())
    }
}

fn session_io(error: std::io::Error) -> SessionError {
    if crate::cancellation::is_cancellation_io(&error) {
        SessionError::Cancelled
    } else {
        SessionError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{BrokerPreparation, PreparedCommandBroker};
    use crate::deployment::shell::{
        SessionError, ShellSession, files::SessionFiles, secrets::SessionSecrets,
        state::SessionState,
    };
    use crate::execution::resources::ServiceMountKind;
    use crate::{cancellation::Cancellation, config::ShellSecretSources, store::ContentDigest};
    use std::fs;
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::{FileExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const SESSION: &str = "1234567890abcdef1234567890abcdef";

    struct Fixture {
        root: tempfile::TempDir,
        shell: ShellSession,
        private: PathBuf,
        cwd: PathBuf,
        worker: Vec<u8>,
    }
    impl Fixture {
        fn new() -> Self {
            let mut worker = crate::runtime::tests::elf(2, None, &[], None, None);
            worker[24..32].copy_from_slice(&0x0040_0100_u64.to_le_bytes());
            worker[68..72].copy_from_slice(&5_u32.to_le_bytes());
            let args = r#"std::CommandArgument::Literal("literal;$HOME"), std::CommandArgument::File("nested/config"), std::CommandArgument::StateDirectory, std::CommandArgument::SecretFile("token")"#;
            let (root, prepared) =
                crate::deployment::manifest::tests::prepared_service_payload_fixture_with_source(
                    &worker,
                    args,
                    "Shell",
                    None,
                    |text| {
                        text.replace("pkgs = []; services", "pkgs = [std::select_command(first, \"out\", \"run\")]; services")
                        .replace("id = \"probe\";", "id = \"probe\"; state = std::ServiceState::Session; secrets = [\"token\"];")
                        .replace("name = \"serve\";", "name = \"serve\"; expose = std::Option::Some(\"alpha\");")
                        .replace("services = [", r#"services = [std::Service {
                            id = "second"; state = std::ServiceState::Session; secrets = ["other"];
                            files = [std::ConfigFile { path = "settings"; text = "second configuration"; }];
                            commands = [std::ServiceCommand { name = "private"; command = std::recipe_command(first, "run"); expose = std::Option::Some("beta");
                                arguments = [std::CommandArgument::SecretFile("other")];
                                environment = [std::CommandEnvironment { name = "SECOND_CONFIG"; argument = std::CommandArgument::File("settings"); }];
                            }];
                        },"#)
                    },
                );
            let private = root.path().join("private");
            let cwd = root.path().join("work");
            fs::create_dir(&private).unwrap();
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(&cwd).unwrap();
            let sources = [
                root.path().join("source-a"),
                root.path().join("source-b"),
            ];
            for (path, bytes) in sources.iter().zip([
                b"first-private".as_slice(),
                b"second-private".as_slice(),
            ]) {
                fs::write(path, bytes).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let grants = ShellSecretSources::new([
                ("probe".into(), "token".into(), sources[0].clone()),
                (
                    "second".into(),
                    "other".into(),
                    sources[1].clone(),
                ),
            ])
            .unwrap();
            let cancel = Cancellation::default();
            let files =
                SessionFiles::new_retained_in(prepared.consumer(), &private, &cancel).unwrap();
            let state = SessionState::create(prepared.consumer(), &private, &cancel).unwrap();
            let secrets =
                SessionSecrets::snapshot(prepared.consumer(), &grants, &cwd, &cancel).unwrap();
            Self {
                root,
                shell: ShellSession {
                    prepared,
                    files,
                    state,
                    secrets,
                },
                private,
                cwd,
                worker,
            }
        }
        fn options(&self) -> BrokerPreparation<'_> {
            BrokerPreparation {
                parent: &self.private,
                session: SESSION,
                socket_identity: crate::platform::linux::fd::FileIdentity {
                    device: 1,
                    inode: 2,
                },
                worker: &self.worker,
                worker_digest: ContentDigest::sha256(&self.worker),
                cwd: &self.cwd,
            }
        }
        fn close(mut self) {
            // No process was started; all launch descriptor holders must already be dropped.
            if let Some(state) = self.shell.state.take() {
                state
                    .close(
                        &Cancellation::default(),
                        Instant::now() + Duration::from_secs(5),
                    )
                    .unwrap();
            }
            self.shell.close().unwrap();
        }
    }

    fn assert_resource_descriptors(
        launch: &crate::runtime::launch_preparation::PreparedRuntimeLaunch,
        fixture: &Fixture,
        owner: &str,
    ) {
        let descriptor = |kind| {
            let mount = launch
                .spec
                .mounts
                .iter()
                .find(|mount| mount.kind == kind)
                .unwrap();
            launch.descriptors[usize::from(mount.slot)].as_fd()
        };
        let secret = fs::File::from(
            descriptor(ServiceMountKind::Secret)
                .try_clone_to_owned()
                .unwrap(),
        );
        let expected = if owner == "probe" {
            b"first-private".as_slice()
        } else {
            b"second-private".as_slice()
        };
        let mut bytes = [0_u8; 64];
        let count = secret.read_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes[..count], expected);
        let config = fixture.shell.files.service(owner).unwrap();
        assert_eq!(
            crate::platform::linux::fd::metadata(descriptor(ServiceMountKind::Configuration))
                .unwrap()
                .identity(),
            crate::platform::linux::fd::metadata(config.as_fd())
                .unwrap()
                .identity(),
        );
        let state = fs::File::open(
            fixture
                .shell
                .state
                .as_ref()
                .unwrap()
                .path()
                .join(owner),
        )
        .unwrap();
        assert_eq!(
            crate::platform::linux::fd::metadata(descriptor(ServiceMountKind::State))
                .unwrap()
                .identity(),
            crate::platform::linux::fd::metadata(state.as_fd())
                .unwrap()
                .identity(),
        );
    }

    #[test]
    fn same_alias_index_cannot_authorize_a_different_retained_union() {
        use crate::execution::journal::{AttemptBinding, SessionJournal};
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        let deadline = || Instant::now() + Duration::from_secs(5);
        let registry = fixture.root.path().join("sessions");
        fs::create_dir(&registry).unwrap();
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
        let journal = SessionJournal::open(&registry).unwrap();
        let manifest = b"broker association fixture";
        let session = journal
            .create(
                manifest,
                ContentDigest::sha256(manifest),
                &cancel,
                deadline(),
            )
            .unwrap();
        // This authorizes a journal fixture, not a real systemd owner.
        let attempt = journal
            .prepare_attempt(&session, "owner", &cancel, deadline())
            .unwrap();
        let binding = AttemptBinding::new(
            crate::systemd::SystemdUnitName::new("syrox-broker-fixture.service").unwrap(),
            [1; 16],
        )
        .unwrap();
        journal
            .authorize_attempt(&session, &attempt, &binding, &cancel, deadline())
            .unwrap();
        let mut options = fixture.options();
        options.session = session.as_str();
        let broker = PreparedCommandBroker::prepare(&fixture.shell, options, &cancel).unwrap();
        let mut correct = journal
            .prepare_execution(
                &session,
                broker.index().digest(),
                &cancel,
                deadline(),
            )
            .unwrap();
        assert!(!broker.matches_execution(&correct));
        correct
            .retain(
                broker
                    .persist_execution(correct.execution(), &cancel)
                    .unwrap(),
                &cancel,
                deadline(),
            )
            .unwrap();
        assert!(broker.matches_execution(&correct));

        // A valid hold from the same Store and execution ID still cannot substitute
        // a different set of outputs merely because its alias index is identical.
        let operation = broker.retention.operation().unwrap();
        let bytes: &[u8] = b"unrelated output with the same public alias";
        let digest = ContentDigest::sha256(bytes);
        operation
            .ingest(bytes, digest, bytes.len() as u64)
            .unwrap();
        let other = operation
            .retain_objects(&[digest], &[digest])
            .unwrap();
        let mut wrong = journal
            .prepare_execution(
                &session,
                broker.index().digest(),
                &cancel,
                deadline(),
            )
            .unwrap();
        wrong
            .retain(
                other
                    .persist_checked(wrong.execution().as_str(), || Ok(()))
                    .unwrap(),
                &cancel,
                deadline(),
            )
            .unwrap();
        assert_eq!(correct.session(), wrong.session());
        assert_eq!(correct.index(), wrong.index());
        assert!(!broker.matches_execution(&wrong));
        drop((correct, wrong, other, operation));
        broker.close(&cancel).unwrap();
        fixture.close();
    }

    #[test]
    fn aliases_prepare_distinct_private_service_resources_and_root_has_none() {
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        let broker =
            PreparedCommandBroker::prepare(&fixture.shell, fixture.options(), &cancel).unwrap();
        assert_eq!(
            broker.index().names().collect::<Vec<_>>(),
            ["alpha", "beta", "run"]
        );
        let root = broker.prepare_invocation("run", &cancel).unwrap();
        assert!(root.spec.arguments.is_empty());
        assert!(root.spec.environment.is_empty());
        assert!(root.spec.mounts.iter().all(|mount| matches!(
            mount.kind,
            ServiceMountKind::Output | ServiceMountKind::Working
        )));
        let first = broker
            .prepare_invocation("alpha", &cancel)
            .unwrap();
        assert_eq!(
            first.spec.arguments,
            [
                "literal;$HOME",
                "/syrox/config/probe/nested/config",
                "/syrox/state/probe",
                "/syrox/secrets/probe/token"
            ]
        );
        assert_eq!(
            first.spec.environment["APP_CONFIG"],
            "/syrox/config/probe/nested/config"
        );
        let second = broker
            .prepare_invocation("beta", &cancel)
            .unwrap();
        assert_eq!(
            second.spec.arguments,
            ["/syrox/secrets/second/other"]
        );
        assert_eq!(
            second.spec.environment["SECOND_CONFIG"],
            "/syrox/config/second/settings"
        );
        for (launch, owner, name, other) in [
            (&first, "probe", "token", "second"),
            (&second, "second", "other", "probe"),
        ] {
            assert!(
                launch
                    .spec
                    .mounts
                    .iter()
                    .any(|mount| mount.kind == ServiceMountKind::State
                        && mount.target == format!("/syrox/state/{owner}"))
            );
            let secrets = launch
                .spec
                .mounts
                .iter()
                .filter(|mount| mount.kind == ServiceMountKind::Secret)
                .collect::<Vec<_>>();
            assert_eq!(secrets.len(), 1);
            assert_eq!(
                secrets[0].target,
                format!("/syrox/secrets/{owner}/{name}")
            );
            crate::platform::linux::fd::sealed_file::validate(
                launch.descriptors[usize::from(secrets[0].slot)].as_fd(),
            )
            .unwrap();
            assert_resource_descriptors(launch, &fixture, owner);
            assert!(!launch.spec.mounts.iter().any(|mount| {
                mount
                    .target
                    .starts_with(&format!("/syrox/config/{other}"))
                    || mount
                        .target
                        .starts_with(&format!("/syrox/state/{other}"))
                    || mount
                        .target
                        .starts_with(&format!("/syrox/secrets/{other}"))
            }));
            let bytes = launch.spec.canonical_bytes().unwrap();
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(!text.contains("first-private") && !text.contains("second-private"));
            assert!(!text.contains("source-a") && !text.contains("source-b"));
            assert_eq!(
                launch
                    .spec
                    .worker_request(&launch.descriptors)
                    .unwrap()
                    .arguments
                    .len(),
                launch.spec.arguments.len()
            );
        }
        let lease = broker.process_retention().unwrap();
        assert!(lease.metadata().unwrap().is_file());
        drop((root, first, second, lease));
        let directory = broker.directory().path().to_path_buf();
        broker.close(&cancel).unwrap();
        assert!(!directory.exists());
        fixture.close();
    }

    #[test]
    fn unknown_alias_and_cancellation_do_not_publish_or_select_private_commands() {
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        let before = fs::read_dir(&fixture.private).unwrap().count();
        cancel.cancel();
        assert!(matches!(
            PreparedCommandBroker::prepare(&fixture.shell, fixture.options(), &cancel),
            Err(SessionError::Cancelled)
        ));
        assert_eq!(
            fs::read_dir(&fixture.private).unwrap().count(),
            before
        );
        let active = Cancellation::default();
        let broker =
            PreparedCommandBroker::prepare(&fixture.shell, fixture.options(), &active).unwrap();
        for alias in [
            "serve",
            "private",
            "probe/serve",
            "missing",
            "../alpha",
        ] {
            assert!(matches!(
                broker.prepare_invocation(alias, &active),
                Err(SessionError::MissingCommand(_))
            ));
        }
        assert!(matches!(
            broker.prepare_invocation("alpha", &cancel),
            Err(SessionError::Cancelled)
        ));
        broker.directory().revalidate(&active).unwrap();
        broker.close(&active).unwrap();
        fixture.close();
    }

    #[test]
    fn invalid_cwd_fails_before_command_tree_publication() {
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        let before = fs::read_dir(&fixture.private).unwrap().count();
        let mut options = fixture.options();
        options.cwd = Path::new("/syrox/config");
        assert!(PreparedCommandBroker::prepare(&fixture.shell, options, &cancel).is_err());
        assert_eq!(
            fs::read_dir(&fixture.private).unwrap().count(),
            before
        );
        assert!(fixture.root.path().join("source-a").exists());
        fixture.close();
    }

    #[test]
    fn replaced_working_directory_is_not_rebound_to_a_different_authority() {
        let fixture = Fixture::new();
        let cancel = Cancellation::default();
        let broker =
            PreparedCommandBroker::prepare(&fixture.shell, fixture.options(), &cancel).unwrap();
        let moved = fixture.root.path().join("original-work");
        fs::rename(&fixture.cwd, &moved).unwrap();
        fs::create_dir(&fixture.cwd).unwrap();
        fs::write(
            fixture.cwd.join("unrelated"),
            b"preserve replacement",
        )
        .unwrap();
        assert!(broker.prepare_invocation("run", &cancel).is_err());
        assert!(
            broker
                .prepare_invocation("alpha", &cancel)
                .is_err()
        );
        broker.close(&cancel).unwrap();
        assert_eq!(
            fs::read(fixture.cwd.join("unrelated")).unwrap(),
            b"preserve replacement"
        );
        assert!(moved.is_dir());
        fixture.close();
    }

    #[test]
    fn cancelled_close_preserves_command_directory_and_reports_cancellation() {
        let fixture = Fixture::new();
        let active = Cancellation::default();
        let broker =
            PreparedCommandBroker::prepare(&fixture.shell, fixture.options(), &active).unwrap();
        let directory = broker.directory().path().to_path_buf();
        let worker = fs::read(directory.join("worker")).unwrap();
        let cancelled = Cancellation::default();
        cancelled.cancel();
        assert!(matches!(
            broker.close(&cancelled),
            Err(SessionError::Cancelled)
        ));
        assert_eq!(
            fs::read(directory.join("worker")).unwrap(),
            worker
        );
        assert!(directory.join("bin/alpha").is_file());
        // Test-only teardown of a retained tree; this is not production settlement.
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            directory.join("bin"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fixture.close();
    }
}

use super::*;
use crate::deployment::os::activation::{ActivationJournal, EffectState, ExecutionEpoch};
use crate::deployment::os::apply::conservation::{PreservedResource, prepare_conservation};
use crate::deployment::os::apply::manager::{ApplyManagerError, Budget};
use crate::deployment::os::apply::preparation::{ResourcePreparation, prepare_resources};
use crate::deployment::os::launch_binding::{OsLaunchBinding, OsLaunchContext};
use crate::deployment::os::{LauncherIdentity, PreparedGeneration};
use crate::systemd::persistent::OsUnitContract;
use crate::{
    cancellation::Cancellation, store::Store, systemd::SystemdFdStoreObserved,
    systemd::SystemdJobCompletion, systemd::SystemdJobResult, systemd::SystemdScope,
    systemd::SystemdUnitStatus,
};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(15)
}
fn private() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
fn config_consumer() -> (
    tempfile::TempDir,
    crate::deployment::manifest::PreparedConsumer,
) {
    let directory = private();
    fs::write(
        directory.path().join("main.srx"),
        r#"outputs {
        target: std::Os = std::Os { pkgs = []; services = [std::Service {
            id = "config"; files = [std::ConfigFile { path = "only"; text = "data"; }];
        }]; };
    }"#,
    )
    .unwrap();
    let checks = crate::project::CheckConfiguration {
        standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
        ..crate::project::CheckConfiguration::default()
    };
    crate::project::lock_project_with(directory.path(), &checks).unwrap();
    let plan =
        crate::project::prepare_project_consumer_with(directory.path(), &checks, "target").unwrap();
    let user = crate::config::UserConfiguration::parse("", directory.path().join("store")).unwrap();
    let consumer = crate::deployment::manifest::prepare_consumer(
        plan,
        "target",
        &user,
        Path::new("missing-worker"),
        true,
        &Cancellation::default(),
        |_, _| panic!("configuration requires no build"),
    )
    .unwrap();
    (directory, consumer)
}
struct Fixture {
    directories: Vec<tempfile::TempDir>,
    installation: GenerationInstallation,
    candidate: RetainedGeneration,
    paths: OsExecutionPaths,
    units: UnitFiles,
    journal: ActivationJournal,
    operation: String,
    epoch: ExecutionEpoch,
    cancel: Cancellation,
    resources: BTreeMap<String, PreparedResource>,
}
impl Fixture {
    fn new(config_only: bool) -> Self {
        Self::new_with_transform(config_only, |source| source)
    }
    fn new_with_transform(config_only: bool, transform: impl FnOnce(String) -> String) -> Self {
        let (project, consumer) = if config_only {
            config_consumer()
        } else {
            crate::deployment::manifest::tests::prepared_service_payload_fixture_with_source(
                &crate::runtime::tests::elf(2, None, &[], None, None),
                "",
                "Os",
                None,
                transform,
            )
        };
        let worker = project.path().join("worker");
        fs::write(&worker, b"coordinator candidate worker").unwrap();
        let prepared = PreparedGeneration::freeze(
            consumer,
            LauncherIdentity::new(
                ContentDigest::sha256(b"coordinator candidate worker"),
                1,
            )
            .unwrap(),
        )
        .unwrap();
        let store_path = project.path().join("store");
        let store = Store::initialize(&store_path).unwrap();
        let install = private();
        let cwd = private();
        let units_dir = private();
        let cancel = Cancellation::default();
        let installation =
            GenerationInstallation::initialize(install.path(), &cancel, deadline()).unwrap();
        let candidate = installation
            .prepare(&prepared, &store, &worker, &cancel, deadline())
            .unwrap();
        let paths = OsExecutionPaths::open(
            install.path(),
            &store_path,
            cwd.path(),
            &cancel,
            deadline(),
        )
        .unwrap();
        let context = OsLaunchContext::new(
            SystemdScope::System,
            store_path,
            units_dir.path().join("placeholder.service"),
            1000,
            1000,
            Duration::from_secs(30),
            Duration::from_secs(10),
        )
        .unwrap();
        let epoch = ExecutionEpoch {
            boot: crate::platform::linux::boot::BootId::parse(
                "11111111-1111-4111-8111-111111111111",
            )
            .unwrap(),
            manager: "fake-manager".into(),
            scope: context.scope_key(),
        };
        let resources = prepare_resources(
            &ResourcePreparation {
                installation: &installation,
                generation: &candidate,
                store: &store,
                paths: &paths,
                units: units_dir.path(),
                epoch: &epoch,
                scope: SystemdScope::System,
                uid: 1000,
                gid: 1000,
                start_timeout: Duration::from_secs(30),
                stop_timeout: Duration::from_secs(10),
            },
            &cancel,
            deadline(),
        )
        .unwrap();
        let units = UnitFiles::open(
            units_dir.path(),
            installation.id(),
            &cancel,
            deadline(),
        )
        .unwrap();
        let journal =
            ActivationJournal::open_existing(install.path(), &cancel, deadline()).unwrap();
        let operation = journal
            .begin(
                &candidate,
                None,
                epoch.clone(),
                &cancel,
                deadline(),
            )
            .unwrap();
        Self {
            directories: vec![project, install, cwd, units_dir],
            installation,
            candidate,
            paths,
            units,
            journal,
            operation,
            epoch,
            cancel,
            resources,
        }
    }
    fn run(
        &self,
        manager: &mut Fake<'_>,
        resources: &BTreeMap<String, PreparedResource>,
    ) -> OsApplyReport {
        self.run_preserved(manager, resources, &BTreeMap::new())
    }
    fn run_preserved(
        &self,
        manager: &mut Fake<'_>,
        resources: &BTreeMap<String, PreparedResource>,
        preserved: &BTreeMap<String, PreservedResource>,
    ) -> OsApplyReport {
        let driver = ApplyManager {
            manager,
            journal: &self.journal,
            operation: &self.operation,
            epoch: &self.epoch,
            cancellation: &self.cancel,
            deadline: deadline(),
        };
        apply(
            driver,
            &self.installation,
            &self.candidate,
            &self.paths,
            &self.units,
            resources,
            preserved,
        )
    }
}
struct Fake<'a> {
    fixture: &'a Fixture,
    binding: Option<OsLaunchBinding>,
    lose_reload: bool,
    started: bool,
    invocation: u8,
    next_invocation: u8,
    supersede_on_query: bool,
    query_error: Option<std::io::ErrorKind>,
    boot_job: Option<u32>,
    calls: Vec<&'static str>,
}
type FakeResult<T> = std::result::Result<T, ApplyManagerError>;
impl<'a> Fake<'a> {
    fn new(fixture: &'a Fixture, binding: Option<OsLaunchBinding>) -> Self {
        Self {
            fixture,
            binding,
            lose_reload: false,
            started: false,
            invocation: 7,
            next_invocation: 7,
            supersede_on_query: false,
            query_error: None,
            boot_job: None,
            calls: Vec::new(),
        }
    }
    fn effects(&self, kind: EffectKind, state: &EffectState) -> usize {
        self.fixture
            .journal
            .snapshot(&self.fixture.cancel, deadline())
            .unwrap()
            .operations[&self.fixture.operation]
            .effects
            .values()
            .filter(|e| e.kind == kind && &e.state == state)
            .count()
    }
}
impl Manager for Fake<'_> {
    type Job = String;
    fn unit_idle_without_job(&mut self, _: &SystemdUnitName, _: &Budget<'_>) -> FakeResult<bool> {
        self.calls.push("idle");
        Ok(!self.started && self.boot_job.is_none())
    }
    fn epoch(&mut self, expected: &ExecutionEpoch, _: &Budget<'_>) -> FakeResult<()> {
        assert_eq!(expected, &self.fixture.epoch);
        self.calls.push("epoch");
        Ok(())
    }
    fn query(
        &mut self,
        unit: &SystemdUnitName,
        _: &Budget<'_>,
    ) -> FakeResult<Option<SystemdUnitStatus>> {
        self.calls.push("query");
        if let Some(kind) = self.query_error {
            return Err(ApplyManagerError::caused_by(
                "query unit",
                std::io::Error::new(kind, "manager connection lost"),
            ));
        }
        if self.supersede_on_query {
            self.supersede_on_query = false;
            self.fixture
                .journal
                .begin(
                    &self.fixture.candidate,
                    Some(self.fixture.candidate.digest()),
                    self.fixture.epoch.clone(),
                    &self.fixture.cancel,
                    deadline(),
                )
                .unwrap();
        }
        Ok(self.started.then(|| SystemdUnitStatus {
            unit: unit.clone(),
            invocation: vec![self.invocation; 16],
            active_state: "active".into(),
            sub_state: "running".into(),
            control_group: "/fake".into(),
            result: String::new(),
            main_pid: 42,
            exec_main_code: 0,
            exec_main_status: 0,
        }))
    }
    fn fd_store(
        &mut self,
        _: &SystemdUnitName,
        _: &Budget<'_>,
    ) -> FakeResult<Option<SystemdFdStoreObserved>> {
        Ok(Some(SystemdFdStoreObserved {
            invocation: vec![self.invocation; 16],
            count: 1,
            max: 1,
            notify_access: "main".into(),
        }))
    }
    fn recorded_job_absent(&mut self, _: &str, _: &Budget<'_>) -> FakeResult<bool> {
        self.calls.push("job");
        Ok(true)
    }
    fn loaded(&mut self, contract: &OsUnitContract, _: &Budget<'_>) -> FakeResult<ContentDigest> {
        self.calls.push("loaded");
        assert_eq!(
            self.fixture
                .units
                .observe(contract.unit(), &self.fixture.cancel, deadline())
                .unwrap(),
            Some(contract.file_digest())
        );
        Ok(ContentDigest::sha256(
            b"fake effective properties",
        ))
    }
    fn reload(&mut self, _: &Budget<'_>) -> FakeResult<()> {
        self.calls.push("reload");
        assert_eq!(
            self.effects(EffectKind::Reload, &EffectState::Intent),
            1
        );
        let snapshot = self
            .fixture
            .journal
            .snapshot(&self.fixture.cancel, deadline())
            .unwrap();
        assert!(
            snapshot
                .bindings
                .values()
                .all(|binding| !binding.authorized)
        );
        let publications: Vec<_> = snapshot.operations[&self.fixture.operation]
            .effects
            .values()
            .filter(|e| e.kind == EffectKind::Publish)
            .collect();
        assert_eq!(publications.len(), 2);
        assert!(
            publications
                .iter()
                .all(|e| matches!(e.state, EffectState::Observed { .. }))
        );
        if self.lose_reload {
            Err(ApplyManagerError::for_test("lost reload reply"))
        } else {
            Ok(())
        }
    }
    fn start(&mut self, unit: &SystemdUnitName, _: &Budget<'_>) -> FakeResult<Self::Job> {
        self.calls.push("start");
        assert_eq!(
            self.effects(EffectKind::Start, &EffectState::Intent),
            1
        );
        let snapshot = self
            .fixture
            .journal
            .snapshot(&self.fixture.cancel, deadline())
            .unwrap();
        assert!(
            snapshot.operations[&self.fixture.operation]
                .effects
                .values()
                .any(|e| e.kind == EffectKind::Reload
                    && matches!(e.state, EffectState::Observed { .. }))
        );
        let binding = self.binding.as_ref().unwrap();
        assert_eq!(unit, &binding.unit());
        self.invocation = self.next_invocation;
        let admission = self
            .fixture
            .journal
            .admit_start(
                &binding.process_key(),
                binding.digest().unwrap(),
                unit,
                &format!("{:02x}", self.invocation).repeat(16),
                &self.fixture.epoch,
                &self.fixture.cancel,
                deadline(),
            )
            .unwrap();
        self.fixture
            .journal
            .with_consumed_start(
                admission,
                &self.fixture.cancel,
                deadline(),
                || Ok(()),
            )
            .unwrap();
        self.started = true;
        Ok("/job/1".into())
    }
    fn stop(&mut self, _: &SystemdUnitName, _: &Budget<'_>) -> FakeResult<Self::Job> {
        self.calls.push("stop");
        assert_eq!(
            self.effects(EffectKind::Stop, &EffectState::Intent),
            1
        );
        self.started = false;
        Ok("/job/stop".into())
    }
    fn job_path(job: &Self::Job) -> &str {
        job
    }
    fn wait(&mut self, job: &Self::Job, _: &Budget<'_>) -> FakeResult<SystemdJobCompletion> {
        assert_eq!(
            self.effects(
                if job == "/job/stop" {
                    EffectKind::Stop
                } else {
                    EffectKind::Start
                },
                &EffectState::Accepted {
                    job: job.clone()
                }
            ),
            1
        );
        Ok(SystemdJobCompletion::Observed {
            result: SystemdJobResult::Done,
        })
    }
}

#[test]
fn publication_reload_and_start_are_ordered_with_durable_intents() {
    let mut fixture = Fixture::new(false);
    let resources = std::mem::take(&mut fixture.resources);
    let binding = resources.values().next().unwrap().binding.clone();
    let mut manager = Fake::new(&fixture, Some(binding));
    let report = fixture.run(&mut manager, &resources);
    assert!(!report.needs_reconciliation);
    assert_eq!(
        report.resources[0].state,
        OsApplyResourceState::Started
    );
    let effects: Vec<_> = manager
        .calls
        .iter()
        .copied()
        .filter(|call| matches!(*call, "reload" | "start"))
        .collect();
    assert_eq!(effects, ["reload", "start"]);
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert_eq!(
        snapshot.operations[&fixture.operation]
            .effects
            .len(),
        4
    );
    assert!(
        snapshot.operations[&fixture.operation]
            .effects
            .values()
            .all(|e| matches!(e.state, EffectState::Observed { .. }))
    );
    let bytes_before = serde_json::to_vec(&snapshot).unwrap();
    let previous_calls = manager.calls.len();
    let repeated = fixture.run(&mut manager, &resources);
    assert!(!repeated.needs_reconciliation);
    assert_eq!(
        repeated.resources[0].state,
        OsApplyResourceState::Unchanged
    );
    assert!(
        manager.calls[previous_calls..]
            .iter()
            .all(|call| !matches!(*call, "reload" | "start" | "stop"))
    );
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&snapshot).unwrap(),
        bytes_before
    );
}

#[test]
fn unowned_unit_is_preserved_without_reload_or_start() {
    let mut fixture = Fixture::new(false);
    let resources = std::mem::take(&mut fixture.resources);
    let binding = resources.values().next().unwrap().binding.clone();
    fs::write(binding.context().fragment(), b"foreign unit").unwrap();
    let mut manager = Fake::new(&fixture, Some(binding.clone()));
    let report = fixture.run(&mut manager, &resources);
    assert!(report.needs_reconciliation);
    assert_eq!(
        report.resources[0].state,
        OsApplyResourceState::Pending
    );
    assert_eq!(
        fs::read(binding.context().fragment()).unwrap(),
        b"foreign unit"
    );
    assert!(manager.calls.is_empty());
    assert!(
        fixture
            .journal
            .snapshot(&fixture.cancel, deadline())
            .unwrap()
            .bindings
            .values()
            .all(|binding| !binding.authorized)
    );
}

#[test]
fn lost_reload_reply_preserves_unknown_and_never_starts() {
    let mut fixture = Fixture::new(false);
    let resources = std::mem::take(&mut fixture.resources);
    let binding = resources.values().next().unwrap().binding.clone();
    let mut manager = Fake::new(&fixture, Some(binding.clone()));
    manager.lose_reload = true;
    let report = fixture.run(&mut manager, &resources);
    assert!(report.needs_reconciliation);
    assert_eq!(
        report.resources[0].state,
        OsApplyResourceState::Pending
    );
    assert_eq!(
        manager.effects(EffectKind::Reload, &EffectState::Unknown),
        1
    );
    assert!(!manager.calls.contains(&"start"));
    assert!(
        fixture
            .journal
            .snapshot(&fixture.cancel, deadline())
            .unwrap()
            .bindings
            .values()
            .all(|binding| !binding.authorized)
    );
    assert!(binding.context().fragment().exists());
    assert!(
        fixture
            .installation
            .read_launch_binding(
                binding.digest().unwrap(),
                &fixture.cancel,
                deadline()
            )
            .is_ok()
    );
    let calls = manager.calls.clone();
    let repeated = fixture.run(&mut manager, &resources);
    assert!(repeated.needs_reconciliation);
    assert_eq!(
        repeated.resources[0].state,
        OsApplyResourceState::Pending
    );
    assert_eq!(
        manager.calls, calls,
        "pending reload must not be replayed"
    );
}

#[test]
fn configuration_only_candidate_performs_no_manager_effect() {
    let mut fixture = Fixture::new(true);
    let resources = std::mem::take(&mut fixture.resources);
    assert!(resources.is_empty());
    assert_eq!(fixture.candidate.manifest().configs.len(), 1);
    let mut manager = Fake::new(&fixture, None);
    let report = fixture.run(&mut manager, &resources);
    assert!(!report.needs_reconciliation);
    assert!(report.resources.is_empty());
    assert!(manager.calls.is_empty());
    assert!(
        fixture
            .journal
            .snapshot(&fixture.cancel, deadline())
            .unwrap()
            .operations[&fixture.operation]
            .effects
            .is_empty()
    );
}

fn started_fixture() -> Fixture {
    let mut fixture = Fixture::new(false);
    let resources = std::mem::take(&mut fixture.resources);
    let binding = resources.values().next().unwrap().binding.clone();
    let mut manager = Fake::new(&fixture, Some(binding));
    let report = fixture.run(&mut manager, &resources);
    assert_eq!(
        report.resources[0].state,
        OsApplyResourceState::Started
    );
    assert!(!report.needs_reconciliation);
    drop(manager);
    fixture.resources = resources;
    fixture
}

impl Fixture {
    fn next_candidate(&mut self) -> BTreeMap<String, PreservedResource> {
        let preserved = self.next_candidate_with_transform(|source| {
            source.replace("services = [std::Service {", r#"services = [std::Service { id = "unrelated"; files = [std::ConfigFile { path = "extra"; text = "independent"; }]; }, std::Service {"#)
        });
        assert_eq!(preserved.len(), 1);
        preserved
    }
    fn next_candidate_with_transform(
        &mut self,
        transform: impl FnOnce(String) -> String,
    ) -> BTreeMap<String, PreservedResource> {
        let previous = self.candidate.digest();
        let units_path = self
            .resources
            .values()
            .next()
            .unwrap()
            .binding
            .context()
            .fragment()
            .parent()
            .unwrap()
            .to_owned();
        let (project, consumer) =
            crate::deployment::manifest::tests::prepared_service_payload_fixture_with_source(
                &crate::runtime::tests::elf(2, None, &[], None, None),
                "",
                "Os",
                Some(self.paths.store()),
                transform,
            );
        let worker = project.path().join("worker");
        fs::write(&worker, b"coordinator candidate worker").unwrap();
        let prepared = PreparedGeneration::freeze(
            consumer,
            LauncherIdentity::new(
                ContentDigest::sha256(b"coordinator candidate worker"),
                1,
            )
            .unwrap(),
        )
        .unwrap();
        let store = Store::open_existing(self.paths.store()).unwrap();
        self.candidate = self
            .installation
            .prepare(
                &prepared,
                &store,
                &worker,
                &self.cancel,
                deadline(),
            )
            .unwrap();
        assert_ne!(previous, self.candidate.digest());
        let input = ResourcePreparation {
            installation: &self.installation,
            generation: &self.candidate,
            store: &store,
            paths: &self.paths,
            units: &units_path,
            epoch: &self.epoch,
            scope: SystemdScope::System,
            uid: 1000,
            gid: 1000,
            start_timeout: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(10),
        };
        self.resources = prepare_resources(&input, &self.cancel, deadline()).unwrap();
        let snapshot = self
            .journal
            .snapshot(&self.cancel, deadline())
            .unwrap();
        let preserved = prepare_conservation(
            &input,
            &self.resources,
            &snapshot,
            &self.cancel,
            deadline(),
        )
        .unwrap();
        self.operation = self
            .journal
            .begin(
                &self.candidate,
                Some(previous),
                self.epoch.clone(),
                &self.cancel,
                deadline(),
            )
            .unwrap();
        self.directories.push(project);
        preserved
    }
}

#[test]
fn cross_generation_preservation_keeps_binding_unit_and_authorization_unchanged() {
    let mut fixture = started_fixture();
    let old_generation = fixture.candidate.digest();
    let old_binding = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    let unit_bytes = fs::read(old_binding.context().fragment()).unwrap();
    let preserved = fixture.next_candidate();
    let mut manager = Fake::new(&fixture, Some(old_binding.clone()));
    manager.started = true;
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    let bytes = serde_json::to_vec(&snapshot).unwrap();
    assert_eq!(
        snapshot.desired.as_deref(),
        Some(fixture.candidate.digest().to_string().as_str())
    );
    let report = fixture.run_preserved(&mut manager, &fixture.resources, &preserved);
    assert_eq!(
        report.resources[0].state,
        OsApplyResourceState::Unchanged
    );
    assert!(!report.needs_reconciliation);
    assert!(
        manager
            .calls
            .iter()
            .all(|call| !matches!(*call, "reload" | "start" | "stop"))
    );
    let after = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert_eq!(serde_json::to_vec(&after).unwrap(), bytes);
    assert_eq!(
        after.bindings[&old_binding.process_key()].generation,
        old_generation.to_string()
    );
    assert_eq!(
        after.bindings[&old_binding.process_key()].pin,
        old_binding.digest().unwrap().to_string()
    );
    assert_eq!(
        fs::read(old_binding.context().fragment()).unwrap(),
        unit_bytes
    );
}

#[test]
fn inactive_preservable_resource_starts_the_new_candidate() {
    let mut fixture = started_fixture();
    let old_binding = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    let preserved = fixture.next_candidate();
    let next = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    assert_ne!(
        next.digest().unwrap(),
        old_binding.digest().unwrap()
    );
    let mut manager = Fake::new(&fixture, Some(next.clone()));
    manager.next_invocation = 8;
    let report = fixture.run_preserved(&mut manager, &fixture.resources, &preserved);
    assert_eq!(
        report.resources[0].state,
        OsApplyResourceState::Started
    );
    assert!(!report.needs_reconciliation);
    assert_eq!(
        manager
            .calls
            .iter()
            .filter(|call| **call == "start")
            .count(),
        1
    );
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert_eq!(
        snapshot.bindings[&next.process_key()].generation,
        fixture.candidate.digest().to_string()
    );
    assert_eq!(
        snapshot.bindings[&next.process_key()].pin,
        next.digest().unwrap().to_string()
    );
}

#[test]
fn preservation_cannot_adopt_a_replaced_invocation() {
    let mut fixture = started_fixture();
    let old = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    let preserved = fixture.next_candidate();
    let mut manager = Fake::new(&fixture, Some(old));
    manager.started = true;
    manager.invocation = 8;
    let before = serde_json::to_vec(
        &fixture
            .journal
            .snapshot(&fixture.cancel, deadline())
            .unwrap(),
    )
    .unwrap();
    let report = fixture.run_preserved(&mut manager, &fixture.resources, &preserved);
    assert_eq!(
        report.resources[0].state,
        OsApplyResourceState::Pending
    );
    assert!(report.needs_reconciliation);
    assert!(
        manager
            .calls
            .iter()
            .all(|call| !matches!(*call, "reload" | "start" | "stop"))
    );
    assert_eq!(
        serde_json::to_vec(
            &fixture
                .journal
                .snapshot(&fixture.cancel, deadline())
                .unwrap()
        )
        .unwrap(),
        before
    );
}

#[test]
fn supersession_during_live_observation_cannot_report_current_preservation() {
    let mut fixture = started_fixture();
    let old = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    let preserved = fixture.next_candidate();
    let mut manager = Fake::new(&fixture, Some(old.clone()));
    manager.started = true;
    manager.supersede_on_query = true;
    let report = fixture.run_preserved(&mut manager, &fixture.resources, &preserved);
    assert_eq!(
        report.resources[0].state,
        OsApplyResourceState::Pending
    );
    assert!(report.needs_reconciliation);
    assert!(
        manager
            .calls
            .iter()
            .all(|call| !matches!(*call, "reload" | "start" | "stop"))
    );
    let snapshot = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert_ne!(
        snapshot.active_operation.as_deref(),
        Some(fixture.operation.as_str())
    );
    assert!(
        snapshot.operations[&fixture.operation]
            .effects
            .is_empty()
    );
    assert_eq!(
        snapshot.bindings[&old.process_key()].pin,
        old.digest().unwrap().to_string()
    );
    assert!(snapshot.bindings[&old.process_key()].authorized);
}

mod recovery;
mod rollback;
mod stop;

#[test]
fn fresh_selection_after_abandonment_preserves_the_existing_authorized_invocation() {
    let mut fixture = started_fixture();
    let old_operation = fixture.operation.clone();
    let before = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    let binding = fixture
        .resources
        .values()
        .next()
        .unwrap()
        .binding
        .clone();
    let unit_bytes = fs::read(binding.context().fragment()).unwrap();
    let _execution = fixture
        .installation
        .execution(&fixture.cancel, deadline())
        .unwrap();
    fixture
        .journal
        .abandon(&old_operation, &fixture.cancel, deadline())
        .unwrap();
    fixture.operation = fixture
        .journal
        .begin(
            &fixture.candidate,
            None,
            fixture.epoch.clone(),
            &fixture.cancel,
            deadline(),
        )
        .unwrap();
    let mut manager = Fake::new(&fixture, Some(binding.clone()));
    manager.started = true;
    let report = fixture.run(&mut manager, &fixture.resources);
    assert!(!report.needs_reconciliation, "{report:?}");
    assert_eq!(
        report.resources[0].state,
        OsApplyResourceState::Unchanged
    );
    assert!(
        manager
            .calls
            .iter()
            .all(|call| !matches!(*call, "reload" | "start" | "stop"))
    );
    let after = fixture
        .journal
        .snapshot(&fixture.cancel, deadline())
        .unwrap();
    assert!(after.operations[&old_operation].abandoned);
    assert_eq!(
        serde_json::to_value(&before.bindings).unwrap(),
        serde_json::to_value(&after.bindings).unwrap()
    );
    assert_eq!(
        fs::read(binding.context().fragment()).unwrap(),
        unit_bytes
    );
}

mod boot;

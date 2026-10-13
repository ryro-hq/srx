use super::*;
use crate::deployment::os::{
    LauncherIdentity,
    installation::GenerationInstallation,
    launch_binding::{LaunchBindingInput, OsLaunchContext},
};
use crate::systemd::SystemdScope;
use crate::systemd::persistent::OsUnitInput;
use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt as _;

fn pin(value: &[u8]) -> ContentDigest {
    ContentDigest::sha256(value)
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
struct Fixture {
    _directory: tempfile::TempDir,
    journal: ActivationJournal,
    operation: String,
    binding: OsLaunchBinding,
    contract: OsUnitContract,
    epoch: ExecutionEpoch,
    cancel: Cancellation,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let cancel = Cancellation::default();
        let installation =
            GenerationInstallation::initialize(directory.path(), &cancel, deadline()).unwrap();
        let journal =
            ActivationJournal::open_existing(directory.path(), &cancel, deadline()).unwrap();
        let context = OsLaunchContext::new(
            SystemdScope::System,
            "/state/store".into(),
            "/units/syrox-os-driver.service".into(),
            1000,
            1000,
            Duration::from_secs(30),
            Duration::from_secs(5),
        )
        .unwrap();
        let epoch = ExecutionEpoch {
            boot: crate::platform::linux::boot::BootId::parse(
                "11111111-1111-1111-1111-111111111111",
            )
            .unwrap(),
            manager: "manager-fixed".into(),
            scope: context.scope_key(),
        };
        let operation = journal
            .begin_test_pin(
                pin(b"generation"),
                None,
                epoch.clone(),
                &cancel,
                deadline(),
            )
            .unwrap();
        let binding = OsLaunchBinding::new(LaunchBindingInput {
            installation: installation.id().into(),
            generation: pin(b"generation"),
            service: "probe".into(),
            process: "server".into(),
            command: "run".into(),
            unit: SystemdUnitName::new("syrox-os-driver.service").unwrap(),
            launcher: LauncherIdentity::new(pin(b"launcher"), 1).unwrap(),
            spec: pin(b"spec"),
            epoch: epoch.clone(),
            context,
            configuration: "/state/install/config/probe".into(),
            cwd: "/project".into(),
        })
        .unwrap();
        let binding_pin = binding.digest().unwrap();
        let publication = journal
            .plan_effect(
                &operation,
                &binding.process_key(),
                EffectKind::Publish,
                None,
                binding_pin,
                &cancel,
                deadline(),
            )
            .unwrap();
        journal
            .record_observed(
                &operation,
                &publication,
                binding_pin,
                None,
                &cancel,
                deadline(),
            )
            .unwrap();
        journal
            .authorize_binding(
                &operation,
                &publication,
                &binding,
                &cancel,
                deadline(),
            )
            .unwrap();
        let contract = OsUnitContract::new(OsUnitInput {
            restart: crate::execution::restart::ProcessRestart::Never,
            unit: binding.unit(),
            scope: SystemdScope::System,
            worker: "/snapshot/worker".into(),
            installation: "/state/install".into(),
            store: "/state/store".into(),
            binding: binding_pin,
            fragment: binding.context().fragment().into(),
            uid: 1000,
            gid: 1000,
            start_timeout: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(5),
        })
        .unwrap();
        Self {
            _directory: directory,
            journal,
            operation,
            binding,
            contract,
            epoch,
            cancel,
        }
    }
    fn driver<'a, 'b>(&'a self, manager: &'a mut Fake<'b>) -> ApplyManager<'a, Fake<'b>> {
        ApplyManager {
            manager,
            journal: &self.journal,
            operation: &self.operation,
            epoch: &self.epoch,
            cancellation: &self.cancel,
            deadline: deadline(),
        }
    }
    fn revoke(&self) {
        self.journal
            .revoke_binding(
                &self.binding.process_key(),
                self.binding.digest().unwrap(),
                &self.cancel,
                deadline(),
            )
            .unwrap();
    }
    fn status(&self, invocation: u8, active: &str) -> SystemdUnitStatus {
        SystemdUnitStatus {
            unit: self.binding.unit(),
            invocation: vec![invocation; 16],
            active_state: active.into(),
            sub_state: "running".into(),
            control_group: "/unit".into(),
            result: String::new(),
            main_pid: 42,
            exec_main_code: 0,
            exec_main_status: 0,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Submit,
    Unobserved,
    GateUnused,
    Loaded,
    CancelReload,
    JobPresent,
    EpochAfterIdle,
}
struct Fake<'a> {
    fixture: &'a Fixture,
    queries: VecDeque<Option<SystemdUnitStatus>>,
    calls: Vec<&'static str>,
    fault: Fault,
    fd_count: u32,
}
impl<'a> Fake<'a> {
    fn new(fixture: &'a Fixture, queries: Vec<Option<SystemdUnitStatus>>) -> Self {
        Self {
            fixture,
            queries: queries.into(),
            calls: Vec::new(),
            fault: Fault::None,
            fd_count: 1,
        }
    }
    fn assert_intent(&self, kind: EffectKind) {
        let snapshot = self
            .fixture
            .journal
            .snapshot(&self.fixture.cancel, deadline())
            .unwrap();
        assert!(
            snapshot.operations[&self.fixture.operation]
                .effects
                .values()
                .any(|effect| effect.kind == kind
                    && effect.state == crate::deployment::os::activation::EffectState::Intent)
        );
    }
    fn consume_gate(&self) {
        let fixture = self.fixture;
        let admission = fixture
            .journal
            .admit_start(
                &fixture.binding.process_key(),
                fixture.binding.digest().unwrap(),
                &fixture.binding.unit(),
                &invocation_hex(&[7; 16]),
                &fixture.epoch,
                &fixture.cancel,
                deadline(),
            )
            .unwrap();
        fixture
            .journal
            .with_consumed_start(admission, &fixture.cancel, deadline(), || Ok(()))
            .unwrap();
    }
}
impl Manager for Fake<'_> {
    type Job = String;
    fn unit_idle_without_job(&mut self, _: &SystemdUnitName, _: &Budget<'_>) -> Result<bool> {
        self.calls.push("idle");
        Ok(true)
    }
    fn epoch(&mut self, _: &ExecutionEpoch, budget: &Budget<'_>) -> Result<()> {
        budget.remaining()?;
        self.calls.push("epoch");
        if self.fault == Fault::EpochAfterIdle && self.calls.contains(&"idle") {
            return Err(ApplyManagerError("changed epoch"));
        }
        Ok(())
    }
    fn query(
        &mut self,
        _: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<Option<SystemdUnitStatus>> {
        budget.remaining()?;
        self.calls.push("query");
        Ok(self
            .queries
            .pop_front()
            .expect("bounded expected query"))
    }
    fn fd_store(
        &mut self,
        _: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<Option<SystemdFdStoreObserved>> {
        budget.remaining()?;
        Ok(Some(SystemdFdStoreObserved {
            invocation: vec![7; 16],
            count: self.fd_count,
            max: 1,
            notify_access: "main".into(),
        }))
    }
    fn recorded_job_absent(&mut self, path: &str, budget: &Budget<'_>) -> Result<bool> {
        budget.remaining()?;
        assert_eq!(path, "/org/freedesktop/systemd1/job/2");
        self.calls.push("job");
        Ok(self.fault != Fault::JobPresent)
    }
    fn loaded(&mut self, _: &OsUnitContract, budget: &Budget<'_>) -> Result<ContentDigest> {
        budget.remaining()?;
        self.calls.push("loaded");
        if self.fault == Fault::Loaded {
            Err(ApplyManagerError("loaded mismatch"))
        } else {
            Ok(pin(b"effective properties"))
        }
    }
    fn reload(&mut self, budget: &Budget<'_>) -> Result<()> {
        budget.remaining()?;
        self.assert_intent(EffectKind::Reload);
        self.calls.push("reload");
        if self.fault == Fault::CancelReload {
            self.fixture.cancel.cancel();
        }
        Ok(())
    }
    fn start(&mut self, _: &SystemdUnitName, budget: &Budget<'_>) -> Result<Self::Job> {
        budget.remaining()?;
        self.assert_intent(EffectKind::Start);
        self.calls.push("start");
        if self.fault == Fault::Submit {
            return Err(ApplyManagerError("lost start reply"));
        }
        if self.fault != Fault::GateUnused {
            self.consume_gate();
        }
        Ok("/job/1".into())
    }
    fn stop(&mut self, _: &SystemdUnitName, budget: &Budget<'_>) -> Result<Self::Job> {
        budget.remaining()?;
        self.assert_intent(EffectKind::Stop);
        self.calls.push("stop");
        if self.fault == Fault::Submit {
            return Err(ApplyManagerError("lost stop reply"));
        }
        Ok("/job/2".into())
    }
    fn job_path(job: &Self::Job) -> &str {
        job
    }
    fn wait(&mut self, _: &Self::Job, budget: &Budget<'_>) -> Result<SystemdJobCompletion> {
        budget.remaining()?;
        self.calls.push("wait");
        let snapshot = self
            .fixture
            .journal
            .snapshot(&self.fixture.cancel, deadline())
            .unwrap();
        assert!(
            snapshot.operations[&self.fixture.operation]
                .effects
                .values()
                .any(|effect| matches!(
                    effect.state,
                    crate::deployment::os::activation::EffectState::Accepted { .. }
                ))
        );

        if self.fault == Fault::Unobserved {
            Ok(SystemdJobCompletion::Unobserved {
                status: None,
            })
        } else {
            Ok(SystemdJobCompletion::Observed {
                result: SystemdJobResult::Done,
            })
        }
    }
}
#[test]
fn start_requires_independent_exec_gate_and_fd_store_evidence() {
    for (gate, count, observed) in [
        (true, 1, true),
        (false, 1, false),
        (true, 0, false),
    ] {
        let f = Fixture::new();
        let mut manager = Fake::new(
            &f,
            vec![
                None,
                Some(f.status(7, "active")),
                Some(f.status(7, "active")),
            ],
        );
        manager.fault = if gate {
            Fault::None
        } else {
            Fault::GateUnused
        };
        manager.fd_count = count;
        let outcome = f
            .driver(&mut manager)
            .start(&f.binding.process_key(), &f.binding, &f.contract)
            .unwrap();
        assert_eq!(
            matches!(outcome.state, EffectStatus::Observed { .. }),
            observed
        );
        assert_eq!(
            manager
                .calls
                .iter()
                .filter(|call| **call == "start")
                .count(),
            1
        );
        let state = f.journal.snapshot(&f.cancel, deadline()).unwrap();
        assert_eq!(
            matches!(
                state.operations[&f.operation].effects[&outcome.effect].state,
                crate::deployment::os::activation::EffectState::Observed { .. }
            ),
            observed
        );
    }
}
#[test]
fn stop_conflict_never_signals_and_absence_is_not_quiescence() {
    for (status, observed) in [(Some(8), false), (None, true)] {
        let f = Fixture::new();
        f.revoke();
        let mut manager = Fake::new(&f, vec![status.map(|id| f.status(id, "active"))]);
        let outcome = f
            .driver(&mut manager)
            .stop(
                &f.binding.process_key(),
                &f.binding.unit(),
                &[7; 16],
                pin(b"stopped"),
            )
            .unwrap();
        assert_eq!(
            matches!(outcome.state, EffectStatus::Observed { .. }),
            observed
        );
        assert!(!manager.calls.contains(&"stop"));
    }
}
#[test]
fn lost_stop_reply_is_not_retried_and_intent_precedes_send() {
    let f = Fixture::new();
    f.revoke();
    let mut manager = Fake::new(&f, vec![Some(f.status(7, "active"))]);
    manager.fault = Fault::Submit;
    let outcome = f
        .driver(&mut manager)
        .stop(
            &f.binding.process_key(),
            &f.binding.unit(),
            &[7; 16],
            pin(b"stopped"),
        )
        .unwrap();
    assert!(matches!(
        outcome.state,
        EffectStatus::Uncertain { .. }
    ));
    assert!(
        f.driver(&mut manager)
            .stop(
                &f.binding.process_key(),
                &f.binding.unit(),
                &[7; 16],
                pin(b"stopped")
            )
            .is_err()
    );
    assert_eq!(
        manager
            .calls
            .iter()
            .filter(|call| **call == "stop")
            .count(),
        1
    );
}
#[test]
fn reload_reply_without_effective_contract_is_not_observed() {
    let f = Fixture::new();
    let mut manager = Fake::new(&f, vec![]);
    manager.fault = Fault::Loaded;
    let contracts = [&f.contract];
    let outcome = f
        .driver(&mut manager)
        .reload("manager", reload_target(&contracts), &contracts)
        .unwrap();
    assert!(matches!(
        outcome.state,
        EffectStatus::Uncertain { .. }
    ));
    assert_eq!(
        manager
            .calls
            .iter()
            .filter(|call| **call == "reload")
            .count(),
        1
    );
}
#[test]
fn expired_budget_and_invalid_batch_have_no_effect() {
    let f = Fixture::new();
    let mut manager = Fake::new(&f, vec![]);
    let mut driver = f.driver(&mut manager);
    driver.deadline = Instant::now();
    assert!(
        driver
            .start(&f.binding.process_key(), &f.binding, &f.contract)
            .is_err()
    );
    assert!(manager.calls.is_empty());
    let contracts = [&f.contract, &f.contract];
    assert!(
        f.driver(&mut manager)
            .reload("manager", reload_target(&contracts), &contracts)
            .is_err()
    );
    assert!(manager.calls.is_empty());
}
#[test]
fn identical_running_binding_is_read_only_and_cannot_adopt_an_invocation() {
    let f = Fixture::new();
    let mut manager = Fake::new(
        &f,
        vec![
            Some(f.status(7, "active")),
            Some(f.status(7, "active")),
        ],
    );
    manager.consume_gate();
    assert!(
        f.driver(&mut manager)
            .verify_running(
                &f.binding.process_key(),
                &f.binding,
                &f.contract,
                &[7; 16]
            )
            .unwrap()
    );
    assert!(!manager.calls.contains(&"start"));
    manager
        .queries
        .push_back(Some(f.status(8, "active")));
    assert!(
        f.driver(&mut manager)
            .verify_running(
                &f.binding.process_key(),
                &f.binding,
                &f.contract,
                &[7; 16]
            )
            .is_err()
    );
    assert_eq!(
        f.journal
            .snapshot(&f.cancel, deadline())
            .unwrap()
            .operations[&f.operation]
            .effects
            .len(),
        1
    );
}

#[test]
fn missing_job_completion_is_not_promoted_from_unit_state() {
    let f = Fixture::new();
    let mut manager = Fake::new(&f, vec![None]);
    manager.fault = Fault::Unobserved;
    let outcome = f
        .driver(&mut manager)
        .start(&f.binding.process_key(), &f.binding, &f.contract)
        .unwrap();
    assert!(matches!(
        outcome.state,
        EffectStatus::Uncertain { .. }
    ));
    assert_eq!(
        manager
            .calls
            .iter()
            .filter(|call| **call == "start")
            .count(),
        1
    );
}

#[test]
fn reload_records_desired_batch_separately_from_loaded_properties() {
    let f = Fixture::new();
    let mut manager = Fake::new(&f, vec![]);
    let contracts = [&f.contract];
    let target = reload_target(&contracts);
    let outcome = f
        .driver(&mut manager)
        .reload("manager", target, &contracts)
        .unwrap();
    assert!(matches!(
        outcome.state,
        EffectStatus::Observed {
            invocation: None
        }
    ));
    assert_eq!(
        outcome.loaded,
        vec![(f.binding.unit(), pin(b"effective properties"))]
    );
    assert_ne!(target, outcome.loaded[0].1);
    assert_ne!(f.contract.file_digest(), outcome.loaded[0].1);
}

#[test]
fn confirmed_stop_rechecks_invocation_and_does_not_clean_retention() {
    let f = Fixture::new();
    f.revoke();
    let mut manager = Fake::new(
        &f,
        vec![
            Some(f.status(7, "active")),
            Some(f.status(7, "inactive")),
        ],
    );
    let outcome = f
        .driver(&mut manager)
        .stop(
            &f.binding.process_key(),
            &f.binding.unit(),
            &[7; 16],
            pin(b"stopped"),
        )
        .unwrap();
    assert!(matches!(
        outcome.state,
        EffectStatus::Observed {
            invocation: Some(_)
        }
    ));
    assert_eq!(
        manager
            .calls
            .iter()
            .filter(|call| **call == "stop")
            .count(),
        1
    );
    assert!(
        f.journal
            .snapshot(&f.cancel, deadline())
            .unwrap()
            .bindings
            .contains_key(&f.binding.process_key())
    );
}

#[test]
fn cancellation_after_reload_preserves_intent_without_reading_next_contract() {
    let f = Fixture::new();
    let mut manager = Fake::new(&f, vec![]);
    manager.fault = Fault::CancelReload;
    let contracts = [&f.contract];
    let outcome = f
        .driver(&mut manager)
        .reload("manager", reload_target(&contracts), &contracts)
        .unwrap();
    assert!(matches!(
        outcome.state,
        EffectStatus::Uncertain { .. }
    ));
    assert!(!manager.calls.contains(&"loaded"));
    let snapshot = f
        .journal
        .snapshot(&Cancellation::default(), deadline())
        .unwrap();
    assert_eq!(
        snapshot.operations[&f.operation].effects[&outcome.effect].state,
        crate::deployment::os::activation::EffectState::Intent
    );
}

#[test]
fn lost_start_reply_never_retries_or_invents_job_acceptance() {
    let f = Fixture::new();
    let mut manager = Fake::new(&f, vec![None]);
    manager.fault = Fault::Submit;
    let outcome = f
        .driver(&mut manager)
        .start(&f.binding.process_key(), &f.binding, &f.contract)
        .unwrap();
    assert!(matches!(
        outcome.state,
        EffectStatus::Uncertain { .. }
    ));
    assert!(
        f.driver(&mut manager)
            .start(&f.binding.process_key(), &f.binding, &f.contract)
            .is_err()
    );
    assert_eq!(
        manager
            .calls
            .iter()
            .filter(|call| **call == "start")
            .count(),
        1
    );
    assert!(!manager.calls.contains(&"wait"));
}

#[path = "../recovery/tests.rs"]
mod recovery;

#[test]
fn boot_idle_observation_is_bracketed_by_epoch_and_never_mutates_manager() {
    for changed in [false, true] {
        let fixture = Fixture::new();
        let mut manager = Fake::new(&fixture, vec![]);
        if changed {
            manager.fault = Fault::EpochAfterIdle;
        }
        let result = fixture
            .driver(&mut manager)
            .verify_boot_idle(&fixture.binding.unit());
        if changed {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap());
        }
        assert_eq!(manager.calls, ["epoch", "idle", "epoch"]);
    }
}

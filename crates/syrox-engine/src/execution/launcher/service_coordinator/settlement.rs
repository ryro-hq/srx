use super::{ServiceError, ServiceOwner};
#[cfg(test)]
use crate::execution::journal::{AttemptBinding, AttemptId, RoleBinding};
pub(crate) use crate::execution::service_evidence::{
    CapturedServiceLauncher, CapturedServiceProcesses, ObservedSessionOwnerAlive,
};
use crate::{cancellation::Cancellation, systemd::SystemdManager};
#[cfg(test)]
use crate::{platform::linux::fd as linux_fd, store::ContentDigest};
use std::os::fd::AsFd as _;
#[cfg(test)]
use std::os::fd::BorrowedFd;
use std::time::Instant;

pub(super) fn observe_live_owner(
    owner: &ServiceOwner,
    manager: &mut SystemdManager,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<ObservedSessionOwnerAlive, ServiceError> {
    Ok(
        crate::execution::service_evidence::observe_live_owner(
            &crate::execution::service_evidence::OwnerObservation {
                session: &owner.session,
                manifest: owner.manifest,
                binding: &owner.binding,
                process: owner.process.as_fd(),
                main_pid: owner.main_pid,
            },
            manager,
            cancel,
            deadline,
        )?,
    )
}
pub(crate) use crate::execution::service_evidence::ObservedServiceAttemptSettlement;
pub(crate) use crate::execution::service_evidence::observe_processes;
pub(crate) use crate::execution::service_evidence::observe_recorded_processes;
pub(crate) use crate::execution::service_evidence::require_live;
#[cfg(test)]
mod tests {
    //! Real process/namespace exit evidence plus a journal fixture. Manager identity
    //! is supplied as fixture data here; this is not a live systemd restart gate.
    use super::*;
    use crate::execution::journal::{AttemptPhase, SessionJournal};
    use crate::platform::linux::fd::persisted_namespace::tests::capture;
    use crate::{
        execution::restart::ProcessRestart, execution::restart::RestartLimits,
        systemd::SystemdUnitName,
    };
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    const TEST: &str = "execution::launcher::service_coordinator::settlement::tests::successor_requires_real_launcher_and_namespace_exit_and_preserves_authority";
    const HELPER: &str = "SYROX_SERVICE_SETTLEMENT_TEST";
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn wait_file(path: &Path) -> String {
        let limit = deadline();
        loop {
            if let Ok(value) = fs::read_to_string(path)
                && !value.is_empty()
            {
                return value;
            }
            assert!(
                Instant::now() < limit,
                "launcher fixture did not publish evidence"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn launcher(root: &Path) {
        let (mut init, gate) = capture::spawn_init();
        fs::write(root.join("init"), init.pid.to_string()).unwrap();
        let mut byte = [0];
        std::io::stdin().read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"N");
        fs::File::from(gate).write_all(b"X").unwrap();
        init.wait();
        fs::write(root.join("namespace-gone"), b"observed").unwrap();
        std::io::stdin().read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"L");
    }
    struct Fixture {
        root: tempfile::TempDir,
        journal: SessionJournal,
        role: RoleBinding,
        first: AttemptId,
        binding: AttemptBinding,
        owner: ObservedSessionOwnerAlive,
    }
    impl Fixture {
        fn new(restart: ProcessRestart) -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let journal = SessionJournal::open(root.path()).unwrap();
            let cancel = Cancellation::default();
            let manifest = ContentDigest::sha256(b"service restart journal fixture");
            let session = journal
                .create(
                    b"service restart journal fixture",
                    manifest,
                    &cancel,
                    deadline(),
                )
                .unwrap();
            let owner_binding = AttemptBinding::new(
                SystemdUnitName::new("syrox-owner-fixture.service").unwrap(),
                [1; 16],
            )
            .unwrap();
            let owner_attempt = journal
                .prepare_attempt(&session, "owner", &cancel, deadline())
                .unwrap();
            journal
                .authorize_attempt(
                    &session,
                    &owner_attempt,
                    &owner_binding,
                    &cancel,
                    deadline(),
                )
                .unwrap();
            journal
                .consume_attempt(
                    &session,
                    &owner_attempt,
                    manifest,
                    &owner_binding,
                    &cancel,
                    deadline(),
                )
                .unwrap();
            // Only the manager observation is simulated; the owner pidfd is live.
            let owner = ObservedSessionOwnerAlive::fixture(
                session.clone(),
                manifest,
                owner_binding.clone(),
                linux_fd::pidfd_open(std::process::id()).unwrap(),
            );
            let unit = SystemdUnitName::new("syrox-service-fixture.service").unwrap();
            let role = RoleBinding::new(
                session.clone(),
                "daemon/main",
                manifest,
                ContentDigest::sha256(b"spec"),
                unit.clone(),
                owner_binding,
                restart,
            )
            .unwrap();
            let first = journal
                .prepare_attempt(&session, role.name(), &cancel, deadline())
                .unwrap();
            journal
                .register_role(&role, &first, &owner, &cancel, deadline())
                .unwrap();
            retain_role(&root, &journal, &role, &first, &owner);
            let binding = AttemptBinding::new(unit, [2; 16]).unwrap();
            Self {
                root,
                journal,
                role,
                first,
                binding,
                owner,
            }
        }
        fn authorize(&self, launcher: BorrowedFd<'_>) -> CapturedServiceLauncher {
            let cancel = Cancellation::default();
            let captured = CapturedServiceLauncher::fixture(
                &self.role,
                &self.first,
                &self.binding,
                launcher,
                &cancel,
                deadline(),
            )
            .unwrap();
            self.journal
                .authorize_service_attempt(&captured, &self.owner, &cancel, deadline())
                .unwrap();
            captured
        }
        fn gate(&self, processes: &CapturedServiceProcesses) {
            self.journal
                .with_service_namespace_gate(
                    processes,
                    &self.owner,
                    &Cancellation::default(),
                    deadline(),
                    || Ok(()),
                )
                .unwrap();
        }
        fn capture(
            &self,
            launcher: BorrowedFd<'_>,
            namespace: BorrowedFd<'_>,
        ) -> CapturedServiceProcesses {
            let captured = self
                .authorize(launcher)
                .capture_namespace(namespace, &Cancellation::default(), deadline())
                .unwrap();
            self.consume();
            self.gate(&captured);
            captured
        }
        fn consume(&self) {
            self.journal
                .consume_attempt(
                    self.role.session(),
                    &self.first,
                    self.role.manifest(),
                    &self.binding,
                    &Cancellation::default(),
                    deadline(),
                )
                .unwrap();
        }
    }

    #[test]
    fn successor_requires_real_launcher_and_namespace_exit_and_preserves_authority() {
        if let Some(path) = std::env::var_os(HELPER) {
            launcher(Path::new(&path));
            return;
        }
        if capture::reexec(TEST) {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let mut child = ChildGuard(
            Command::new(crate::reexec_test_executable(TEST, false))
                .args([
                    "--exact",
                    TEST,
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(HELPER, root.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let launcher = linux_fd::pidfd_open(child.0.id()).unwrap();
        let pid = wait_file(&root.path().join("init"))
            .parse()
            .unwrap();
        let namespace = linux_fd::pidfd_open(pid).unwrap();
        let cancel = Cancellation::default();
        let fixture = Fixture::new(ProcessRestart::OnFailure(
            RestartLimits::new(1, 10, 3).unwrap(),
        ));
        let captured = fixture
            .authorize(launcher.as_fd())
            .capture_namespace(namespace.as_fd(), &cancel, deadline())
            .unwrap();
        assert!(
            fixture
                .journal
                .with_service_namespace_gate(
                    &captured,
                    &fixture.owner,
                    &cancel,
                    deadline(),
                    || Ok(())
                )
                .is_err(),
            "resources have not been consumed"
        );
        fixture.consume();
        fixture.gate(&captured);
        let foreign = Fixture::new(ProcessRestart::OnFailure(
            RestartLimits::new(1, 10, 3).unwrap(),
        ));
        let foreign_capture = foreign.capture(launcher.as_fd(), namespace.as_fd());
        let never = Fixture::new(ProcessRestart::Never);
        let never_capture = never.capture(launcher.as_fd(), namespace.as_fd());
        let observe = || observe_processes(&captured).unwrap();
        assert!(observe().is_none());
        child
            .0
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"N")
            .unwrap();
        wait_file(&root.path().join("namespace-gone"));
        assert!(linux_fd::pidfd_exited(namespace.as_fd()).unwrap());
        assert!(!linux_fd::pidfd_exited(launcher.as_fd()).unwrap());
        assert!(
            observe().is_none(),
            "namespace exit alone must not produce settlement"
        );
        child
            .0
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"L")
            .unwrap();
        let limit = deadline();
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < limit);
            std::thread::sleep(Duration::from_millis(5));
        }
        let proof = observe().expect("both pinned processes exited");
        check_journal(
            &fixture,
            &proof,
            &foreign_capture,
            &never,
            &never_capture,
        );
    }

    fn check_journal(
        fixture: &Fixture,
        proof: &ObservedServiceAttemptSettlement,
        foreign: &CapturedServiceProcesses,
        never: &Fixture,
        never_capture: &CapturedServiceProcesses,
    ) {
        let cancel = Cancellation::default();
        let prepare = |journal: &SessionJournal, proof: &ObservedServiceAttemptSettlement| {
            journal.prepare_successor(
                &fixture.role,
                proof,
                &fixture.owner,
                &cancel,
                deadline(),
            )
        };
        check_recovered_evidence(fixture, proof);
        let foreign_proof = observe_processes(foreign).unwrap().unwrap();
        assert!(prepare(&fixture.journal, &foreign_proof).is_err());
        let never_proof = observe_processes(never_capture).unwrap().unwrap();
        assert!(
            never
                .journal
                .prepare_successor(
                    &never.role,
                    &never_proof,
                    &never.owner,
                    &cancel,
                    deadline()
                )
                .is_err()
        );
        let next = prepare(&fixture.journal, proof).unwrap();
        assert!(
            prepare(&fixture.journal, proof).is_err(),
            "settlement replay"
        );
        let current = linux_fd::pidfd_open(std::process::id()).unwrap();
        let replay = CapturedServiceLauncher::fixture(
            &fixture.role,
            &next,
            &fixture.binding,
            current.as_fd(),
            &cancel,
            deadline(),
        )
        .unwrap();
        assert!(
            fixture
                .journal
                .authorize_service_attempt(&replay, &fixture.owner, &cancel, deadline())
                .is_err(),
            "invocation replay"
        );
        let reopened = SessionJournal::open_existing(fixture.root.path()).unwrap();
        let snapshot = reopened
            .snapshot(fixture.role.session(), &cancel, deadline())
            .unwrap();
        assert_eq!(
            snapshot
                .attempts
                .iter()
                .find(|entry| entry.id == fixture.first)
                .unwrap()
                .phase,
            AttemptPhase::Settled
        );
        assert_eq!(
            snapshot
                .attempts
                .iter()
                .find(|entry| entry.id == next)
                .unwrap()
                .phase,
            AttemptPhase::Prepared
        );
        reopened
            .begin_closing(
                fixture.role.session(),
                "test close",
                &cancel,
                deadline(),
            )
            .unwrap();
        assert!(prepare(&reopened, proof).is_err());
        let binding = AttemptBinding::new(fixture.binding.unit().clone(), [3; 16]).unwrap();
        assert!(
            reopened
                .authorize_attempt(
                    fixture.role.session(),
                    &next,
                    &binding,
                    &cancel,
                    deadline()
                )
                .is_err()
        );
    }

    #[test]
    fn definitive_successor_denial_requires_durable_policy_and_current_consumed_head() {
        if capture::reexec(
            "execution::launcher::service_coordinator::settlement::tests::definitive_successor_denial_requires_durable_policy_and_current_consumed_head",
        ) {
            return;
        }
        let fixture = Fixture::new(ProcessRestart::Never);
        let pinned = linux_fd::pidfd_open(std::process::id()).unwrap();
        let _captured = fixture.authorize(pinned.as_fd());
        let calls = std::cell::Cell::new(0);
        let cancel = Cancellation::default();
        let deny = || {
            calls.set(calls.get() + 1);
            Ok(())
        };
        assert!(
            fixture
                .journal
                .with_forbidden_successor(
                    &fixture.role,
                    &fixture.first,
                    &cancel,
                    deadline(),
                    deny
                )
                .is_err()
        );
        assert_eq!(calls.get(), 0);
        fixture.consume();
        fixture
            .journal
            .with_forbidden_successor(
                &fixture.role,
                &fixture.first,
                &cancel,
                deadline(),
                deny,
            )
            .unwrap();
        assert_eq!(calls.get(), 1);
        let foreign = Fixture::new(ProcessRestart::Never);
        assert!(
            fixture
                .journal
                .with_forbidden_successor(
                    &foreign.role,
                    &fixture.first,
                    &cancel,
                    deadline(),
                    deny
                )
                .is_err()
        );
        assert!(
            fixture
                .journal
                .with_forbidden_successor(
                    &fixture.role,
                    &foreign.first,
                    &cancel,
                    deadline(),
                    deny
                )
                .is_err()
        );
        cancel.cancel();
        assert!(
            fixture
                .journal
                .with_forbidden_successor(
                    &fixture.role,
                    &fixture.first,
                    &cancel,
                    deadline(),
                    deny
                )
                .is_err()
        );
        assert_eq!(
            calls.get(),
            1,
            "uncertainty must not emit a definitive denial"
        );
    }

    fn retain_role(
        root: &tempfile::TempDir,
        journal: &SessionJournal,
        role: &RoleBinding,
        first: &AttemptId,
        owner: &ObservedSessionOwnerAlive,
    ) {
        let path = root.path().join("role-store");
        fs::create_dir(&path).unwrap();
        let store = crate::store::Store::open(&path).unwrap();
        let interest = store
            .operation()
            .unwrap()
            .retain_objects(&[], &[])
            .unwrap();
        let identity = crate::execution::journal::roles::retention::RoleRetentionIdentity::new(
            first.clone(),
            interest.durable_digest(),
            interest.durable_store_anchor().unwrap(),
        );
        let cancel = Cancellation::default();
        journal
            .begin_role_retention(role, &identity, owner, &cancel, deadline())
            .unwrap();
        let hold = interest
            .persist_checked(first.as_str(), || Ok(()))
            .unwrap();
        journal
            .confirm_role_retention(role, &hold, owner, &cancel, deadline())
            .unwrap();
    }

    mod retention {
        use super::*;
        use crate::execution::journal::roles::retention::{
            RoleRetentionIdentity, RoleRetentionPhase,
        };
        use crate::store::DurableInterest;

        struct Pending {
            store: crate::store::Store,
            interest: crate::store::ObjectLease,
            role: RoleBinding,
            first: AttemptId,
            identity: RoleRetentionIdentity,
        }
        fn pending(fixture: &Fixture) -> Pending {
            let cancel = Cancellation::default();
            let role = RoleBinding::new(
                fixture.role.session().clone(),
                "second",
                fixture.role.manifest(),
                fixture.role.command(),
                SystemdUnitName::new("syrox-second.service").unwrap(),
                fixture.role.owner().clone(),
                ProcessRestart::Never,
            )
            .unwrap();
            let first = fixture
                .journal
                .prepare_attempt(role.session(), role.name(), &cancel, deadline())
                .unwrap();
            fixture
                .journal
                .register_role(&role, &first, &fixture.owner, &cancel, deadline())
                .unwrap();
            let store = crate::store::Store::open(&fixture.root.path().join("role-store")).unwrap();
            let interest = store
                .operation()
                .unwrap()
                .retain_objects(&[], &[])
                .unwrap();
            let identity = RoleRetentionIdentity::new(
                first.clone(),
                interest.durable_digest(),
                interest.durable_store_anchor().unwrap(),
            );
            fixture
                .journal
                .begin_role_retention(
                    &role,
                    &identity,
                    &fixture.owner,
                    &cancel,
                    deadline(),
                )
                .unwrap();
            Pending {
                store,
                interest,
                role,
                first,
                identity,
            }
        }
        fn phase(fixture: &Fixture, role: &RoleBinding) -> RoleRetentionPhase {
            fixture
                .journal
                .snapshot(
                    role.session(),
                    &Cancellation::default(),
                    deadline(),
                )
                .unwrap()
                .roles
                .into_iter()
                .find(|entry| entry.binding == *role)
                .unwrap()
                .retention
                .phase
        }
        #[test]
        fn stale_published_handles_never_confirm_journal_retention() {
            let fixture = Fixture::new(ProcessRestart::Never);
            let pending = pending(&fixture);
            let cancel = Cancellation::default();
            let first = pending
                .interest
                .persist_checked(pending.first.as_str(), || Ok(()))
                .unwrap();
            let stale = pending
                .interest
                .persist_checked(pending.first.as_str(), || Ok(()))
                .unwrap();
            first.retire_checked(|| Ok(())).unwrap();
            assert!(
                fixture
                    .journal
                    .confirm_role_retention(
                        &pending.role,
                        &stale,
                        &fixture.owner,
                        &cancel,
                        deadline()
                    )
                    .is_err()
            );
            assert_eq!(
                phase(&fixture, &pending.role),
                RoleRetentionPhase::Intent
            );
            assert!(
                pending
                    .store
                    .reopen_durable_interest_checked(
                        pending.first.as_str(),
                        pending.identity.pin,
                        pending.identity.store_anchor,
                        || Ok(())
                    )
                    .is_err()
            );
            let current = pending
                .interest
                .persist_checked(pending.first.as_str(), || Ok(()))
                .unwrap();
            let path = fixture
                .root
                .path()
                .join("role-store/.syrox-store/interests")
                .join(format!("hold-{}", pending.first));
            let bytes = fs::read(&path).unwrap();
            fs::rename(&path, fixture.root.path().join("displaced-hold")).unwrap();
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                fixture
                    .journal
                    .confirm_role_retention(
                        &pending.role,
                        &current,
                        &fixture.owner,
                        &cancel,
                        deadline()
                    )
                    .is_err()
            );
            assert_eq!(
                phase(&fixture, &pending.role),
                RoleRetentionPhase::Intent
            );
            let binding = AttemptBinding::new(pending.role.unit().clone(), [8; 16]).unwrap();
            assert!(
                fixture
                    .journal
                    .authorize_attempt(
                        pending.role.session(),
                        &pending.first,
                        &binding,
                        &cancel,
                        deadline()
                    )
                    .is_err()
            );
        }
        fn hold(fixture: &Fixture) -> DurableInterest {
            let state = fixture
                .journal
                .snapshot(
                    fixture.role.session(),
                    &Cancellation::default(),
                    deadline(),
                )
                .unwrap();
            let identity = state
                .roles
                .into_iter()
                .find(|role| role.binding == fixture.role)
                .unwrap()
                .retention
                .identity
                .unwrap();
            crate::store::Store::open(&fixture.root.path().join("role-store"))
                .unwrap()
                .reopen_durable_interest_checked(
                    identity.first.as_str(),
                    identity.pin,
                    identity.store_anchor,
                    || Ok(()),
                )
                .unwrap()
        }
        const RETIRE_TEST: &str = "execution::launcher::service_coordinator::settlement::tests::retention::retirement_requires_real_exit_evidence_and_records_failed_removal";
        #[test]
        fn retirement_requires_real_exit_evidence_and_records_failed_removal() {
            if capture::reexec(RETIRE_TEST) {
                return;
            }
            let fixture = Fixture::new(ProcessRestart::Never);
            let root = tempfile::tempdir().unwrap();
            let mut child = ChildGuard(
                Command::new(crate::reexec_test_executable(TEST, false))
                    .args([
                        "--exact",
                        TEST,
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(HELPER, root.path())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let launcher = linux_fd::pidfd_open(child.0.id()).unwrap();
            let namespace = linux_fd::pidfd_open(
                wait_file(&root.path().join("init"))
                    .parse()
                    .unwrap(),
            )
            .unwrap();
            let cancel = Cancellation::default();
            let captured = fixture.capture(launcher.as_fd(), namespace.as_fd());
            let failed = Fixture::new(ProcessRestart::Never);
            let failed_capture = failed.capture(launcher.as_fd(), namespace.as_fd());
            assert!(observe_processes(&captured).unwrap().is_none());
            fixture
                .journal
                .begin_closing(
                    fixture.role.session(),
                    "retention test",
                    &cancel,
                    deadline(),
                )
                .unwrap();
            assert!(
                fixture
                    .journal
                    .retire_role_retention(
                        &fixture.role,
                        &[],
                        hold(&fixture),
                        &cancel,
                        deadline()
                    )
                    .is_err()
            );
            child
                .0
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"N")
                .unwrap();
            wait_file(&root.path().join("namespace-gone"));
            assert!(observe_processes(&captured).unwrap().is_none());
            child
                .0
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"L")
                .unwrap();
            wait_launcher(&mut child);
            let proof = observe_processes(&captured).unwrap().unwrap();
            fixture
                .journal
                .retire_role_retention(
                    &fixture.role,
                    std::slice::from_ref(&proof),
                    hold(&fixture),
                    &cancel,
                    deadline(),
                )
                .unwrap();
            assert_eq!(
                phase(&fixture, &fixture.role),
                RoleRetentionPhase::Retired
            );
            // A second, independent journal uses the same real exited-process producer
            // as comparison fixture data. No caller manufactures the exit capability.
            failed_retirement(&failed, &failed_capture);
        }
        fn wait_launcher(child: &mut ChildGuard) {
            let end = deadline();
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success());
                    return;
                }
                assert!(Instant::now() < end);
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        fn failed_retirement(fixture: &Fixture, captured: &CapturedServiceProcesses) {
            let cancel = Cancellation::default();
            fixture
                .journal
                .begin_closing(
                    fixture.role.session(),
                    "retirement failure",
                    &cancel,
                    deadline(),
                )
                .unwrap();
            let proof = observe_processes(captured).unwrap().unwrap();
            let stale = hold(fixture);
            let path = fixture
                .root
                .path()
                .join("role-store/.syrox-store/interests")
                .join(format!("hold-{}", fixture.first));
            let bytes = fs::read(&path).unwrap();
            fs::rename(&path, fixture.root.path().join("displaced")).unwrap();
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                fixture
                    .journal
                    .retire_role_retention(
                        &fixture.role,
                        std::slice::from_ref(&proof),
                        stale,
                        &cancel,
                        deadline()
                    )
                    .is_err()
            );
            assert_eq!(
                phase(fixture, &fixture.role),
                RoleRetentionPhase::Retiring
            );
            assert!(path.exists());
            assert!(
                fixture
                    .journal
                    .retire_role_retention(
                        &fixture.role,
                        &[proof],
                        hold(fixture),
                        &cancel,
                        deadline()
                    )
                    .is_err()
            );
            assert_eq!(
                phase(fixture, &fixture.role),
                RoleRetentionPhase::Retiring
            );
        }
    }
    mod processes {
        //! Manager context is fixture data; launcher/child identities are real captures.
        use super::*;
        use crate::execution::journal::processes::ServiceProcessRecord;
        const PAIR: &str = "execution::launcher::service_coordinator::settlement::tests::processes::process_pair_rejects_wrong_namespace_and_gate_replay";
        #[test]
        fn process_pair_rejects_wrong_namespace_and_gate_replay() {
            if capture::reexec(PAIR) {
                return;
            }
            let cancel = Cancellation::default();
            let fixture = Fixture::new(ProcessRestart::Never);
            let launcher = linux_fd::pidfd_open(std::process::id()).unwrap();
            let invalid = CapturedServiceLauncher::fixture(
                &fixture.role,
                &fixture.first,
                &fixture.binding,
                launcher.as_fd(),
                &cancel,
                deadline(),
            )
            .unwrap();
            assert!(
                invalid
                    .capture_namespace(launcher.as_fd(), &cancel, deadline())
                    .is_err()
            );
            let captured = fixture.authorize(launcher.as_fd());
            let state = fixture
                .journal
                .snapshot(fixture.role.session(), &cancel, deadline())
                .unwrap();
            let records = state
                .attempts
                .iter()
                .find(|attempt| attempt.id == fixture.first)
                .unwrap()
                .service_processes
                .as_ref()
                .unwrap();
            assert_eq!(&records.launcher, captured.launcher_record());
            assert!(records.namespace.is_none());
            assert!(!records.gate_used);
            assert!(
                observe_recorded_processes(
                    &fixture.role,
                    &fixture.first,
                    &fixture.binding,
                    records,
                    &cancel,
                    deadline()
                )
                .unwrap()
                .is_none()
            );
            let (mut init, gate) = capture::spawn_init();
            let namespace = linux_fd::pidfd_open(init.pid.try_into().unwrap()).unwrap();
            let pair = captured
                .capture_namespace(namespace.as_fd(), &cancel, deadline())
                .unwrap();
            pair.revalidate(&cancel, deadline()).unwrap();
            fixture.consume();
            assert!(
                fixture
                    .journal
                    .with_service_namespace_gate(
                        &pair,
                        &fixture.owner,
                        &cancel,
                        deadline(),
                        || Err::<(), _>(std::io::Error::other("uncertain send"))
                    )
                    .is_err()
            );
            let calls = std::cell::Cell::new(0);
            assert!(
                fixture
                    .journal
                    .with_service_namespace_gate(&pair, &fixture.owner, &cancel, deadline(), || {
                        calls.set(calls.get() + 1);
                        Ok(())
                    })
                    .is_err()
            );
            assert_eq!(
                calls.get(),
                0,
                "a repeated gate cannot call COMMIT"
            );
            let state = fixture
                .journal
                .snapshot(fixture.role.session(), &cancel, deadline())
                .unwrap();
            let records = state
                .attempts
                .iter()
                .find(|attempt| attempt.id == fixture.first)
                .unwrap()
                .service_processes
                .as_ref()
                .unwrap();
            assert_eq!(
                records,
                &ServiceProcessRecord::from_captured(&pair)
            );
            check_closing(launcher.as_fd(), namespace.as_fd());
            fs::File::from(gate).write_all(b"X").unwrap();
            init.wait();
            assert!(pair.revalidate(&cancel, deadline()).is_err());
            assert!(
                observe_processes(&pair).unwrap().is_none(),
                "live launcher prevents settlement after init exit"
            );
        }

        fn check_closing(launcher: BorrowedFd<'_>, namespace: BorrowedFd<'_>) {
            let fixture = Fixture::new(ProcessRestart::Never);
            let cancel = Cancellation::default();
            let pair = fixture
                .authorize(launcher)
                .capture_namespace(namespace, &cancel, deadline())
                .unwrap();
            fixture.consume();
            fixture
                .journal
                .begin_closing(
                    fixture.role.session(),
                    "closing before gate",
                    &cancel,
                    deadline(),
                )
                .unwrap();
            let calls = std::cell::Cell::new(0);
            assert!(
                fixture
                    .journal
                    .with_service_namespace_gate(&pair, &fixture.owner, &cancel, deadline(), || {
                        calls.set(calls.get() + 1);
                        Ok(())
                    })
                    .is_err()
            );
            assert_eq!(calls.get(), 0);
        }
    }
    fn check_recovered_evidence(fixture: &Fixture, proof: &ObservedServiceAttemptSettlement) {
        let cancel = Cancellation::default();
        let reopened = SessionJournal::open_existing(fixture.root.path()).unwrap();
        let state = reopened
            .snapshot(fixture.role.session(), &cancel, deadline())
            .unwrap();
        let records = state
            .attempts
            .iter()
            .find(|entry| entry.id == fixture.first)
            .unwrap()
            .service_processes
            .as_ref()
            .unwrap();
        let recovered = observe_recorded_processes(
            &fixture.role,
            &fixture.first,
            &fixture.binding,
            records,
            &cancel,
            deadline(),
        )
        .unwrap()
        .unwrap();
        assert!(proof.matches_processes(records));
        assert!(recovered.matches_processes(records));
        let mut incomplete = records.clone();
        incomplete.namespace = None;
        assert!(
            observe_recorded_processes(
                &fixture.role,
                &fixture.first,
                &fixture.binding,
                &incomplete,
                &cancel,
                deadline()
            )
            .unwrap()
            .is_none()
        );
        let mut changed = records.clone();
        changed.manager = ContentDigest::sha256(b"different manager epoch");
        assert!(!recovered.matches_processes(&changed));
        changed = records.clone();
        changed.gate_used = false;
        assert!(!recovered.matches_processes(&changed));
    }
}

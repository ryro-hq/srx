use super::*;
use crate::platform::linux::fd::persisted_namespace::tests::capture::{reexec, spawn_init};
use crate::platform::linux::fd::persisted_namespace::{CapturedLauncher, CapturedNamespace};
use std::io::{Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::process::{Command, Stdio};

const TEST: &str = "deployment::os::activation::tests::closed_inventory::nonempty_inventory_requires_every_launcher_and_namespace";
const SHARED_TEST: &str = "deployment::os::activation::tests::closed_inventory::same_binding_inventory_requires_both_invocations";
const RESOURCE: &str = "SYROX_CLOSED_INVENTORY_RESOURCE";
const CHILD: &str = "SYROX_CLOSED_INVENTORY_CHILD";
const DIRECTORY: &str = "SYROX_CLOSED_INVENTORY_DIRECTORY";

fn live_epoch() -> ExecutionEpoch {
    ExecutionEpoch {
        boot: BootId::current(&Cancellation::default(), deadline()).unwrap(),
        ..epoch()
    }
}

fn binding(journal: &ActivationJournal, name: &str) -> OsLaunchBinding {
    let mut input = journal.binding_input();
    input.epoch = live_epoch();
    input.process = name.into();
    input.unit = SystemdUnitName::new(format!("syrox-os-{name}.service")).unwrap();
    input.context = crate::deployment::os::launch_binding::OsLaunchContext::new(
        context().scope().clone(),
        "/private/store".into(),
        format!("/private/units/syrox-os-{name}.service").into(),
        1000,
        1000,
        Duration::from_secs(30),
        Duration::from_secs(5),
    )
    .unwrap();
    OsLaunchBinding::new(input).unwrap()
}

fn publish_actual(journal: &ActivationJournal, operation: &str, name: &str) {
    let cancel = Cancellation::default();
    let value = binding(journal, name);
    let pin = value.digest().unwrap();
    let effect = journal
        .plan_effect(
            operation,
            &format!("test/{name}"),
            EffectKind::Publish,
            None,
            pin,
            &cancel,
            deadline(),
        )
        .unwrap();
    journal
        .record_observed(operation, &effect, pin, None, &cancel, deadline())
        .unwrap();
    journal
        .authorize_binding(operation, &effect, &value, &cancel, deadline())
        .unwrap();
}

fn launcher(name: &str, resource: &str, directory: &Path) {
    let cancel = Cancellation::default();
    let journal = ActivationJournal::open_existing(directory, &cancel, deadline()).unwrap();
    let value = binding(&journal, resource);
    let launcher = CapturedLauncher::capture_self(&cancel, deadline()).unwrap();
    let invocation = if name == "first" {
        "22222222222222222222222222222222"
    } else {
        "33333333333333333333333333333333"
    };
    let admission = journal
        .admit_captured_start(
            &format!("test/{resource}"),
            value.digest().unwrap(),
            &value.unit(),
            invocation,
            &live_epoch(),
            &launcher,
            &cancel,
            deadline(),
        )
        .unwrap();
    let (mut init, gate) = spawn_init();
    let descriptor = crate::platform::linux::fd::pidfd_open(init.pid.cast_unsigned()).unwrap();
    let namespace = CapturedNamespace::capture(descriptor.as_fd(), &cancel, deadline()).unwrap();
    let mut gate = fs::File::from(gate);
    journal
        .with_namespace_start(admission, &namespace, &cancel, deadline(), || {
            gate.write_all(b"G")
        })
        .unwrap();
    drop(namespace);
    drop(descriptor);
    drop(launcher);
    fs::write(directory.join(format!("{name}.ready")), b"ready").unwrap();
    let mut byte = [0];
    io::stdin().read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"N");
    gate.write_all(b"X").unwrap();
    drop(gate);
    init.wait();
    fs::write(
        directory.join(format!("{name}.namespace-exited")),
        b"exited",
    )
    .unwrap();
    io::stdin().read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"L");
}

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Child {
    fn start(test: &str, name: &str, resource: &str, directory: &Path) -> Self {
        Self(
            Command::new(crate::reexec_test_executable(test, false))
                .args([
                    "--exact",
                    test,
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, name)
                .env(RESOURCE, resource)
                .env(DIRECTORY, directory)
                .stdin(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    }
    fn send(&mut self, bytes: &[u8]) {
        self.0
            .stdin
            .as_mut()
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    fn await_file(&mut self, path: &Path) {
        let limit = deadline();
        while !path.exists() {
            assert!(
                self.0.try_wait().unwrap().is_none(),
                "launcher failed before checkpoint"
            );
            assert!(
                Instant::now() < limit,
                "launcher checkpoint timeout"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn wait(&mut self) {
        let limit = deadline();
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            assert!(Instant::now() < limit, "launcher exit timeout");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[test]
fn nonempty_inventory_requires_every_launcher_and_namespace() {
    run_inventory(TEST, &["first", "second"]);
}

#[test]
fn same_binding_inventory_requires_both_invocations() {
    run_inventory(SHARED_TEST, &["shared"]);
}

fn run_inventory(test: &str, resources: &[&str]) {
    if let Some(name) = std::env::var_os(CHILD) {
        launcher(
            name.to_str().unwrap(),
            &std::env::var(RESOURCE).unwrap(),
            Path::new(&std::env::var_os(DIRECTORY).unwrap()),
        );
        return;
    }
    if reexec(test) {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(
        directory.path(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let cancel = Cancellation::default();
    GenerationInstallation::initialize(directory.path(), &cancel, deadline()).unwrap();
    let journal = ActivationJournal::open_existing(directory.path(), &cancel, deadline()).unwrap();
    let previous = live_epoch();
    let operation = journal
        .begin_pin(
            pin(b"generation"),
            None,
            previous.clone(),
            &cancel,
            deadline(),
        )
        .unwrap();
    for name in resources {
        publish_actual(&journal, &operation, name);
    }
    let mut first = Child::start(test, "first", resources[0], directory.path());
    let mut second = Child::start(
        test,
        "second",
        resources.last().unwrap(),
        directory.path(),
    );
    first.await_file(&directory.path().join("first.ready"));
    second.await_file(&directory.path().join("second.ready"));
    let current = ExecutionEpoch {
        manager: "new-manager".into(),
        ..previous
    };
    let key = journal
        .begin_manager_change(&operation, &current, &cancel, deadline())
        .unwrap();
    assert_inventory_shape(&journal, &key, resources);
    assert!(
        journal
            .observe_closed_process_inventory(&key, &cancel, deadline())
            .unwrap()
            .is_none()
    );
    first.send(b"NL");
    first.wait();
    assert!(
        journal
            .observe_closed_process_inventory(&key, &cancel, deadline())
            .unwrap()
            .is_none()
    );
    second.send(b"N");
    second.await_file(&directory.path().join("second.namespace-exited"));
    assert!(
        journal
            .observe_changed_namespaces(&key, &cancel, deadline())
            .unwrap()
            .is_some()
    );
    assert!(
        journal
            .observe_closed_process_inventory(&key, &cancel, deadline())
            .unwrap()
            .is_none()
    );
    second.send(b"L");
    second.wait();
    drop(journal);
    assert_reopened_inventory(directory.path(), &key);
}

fn assert_reopened_inventory(directory: &Path, key: &str) {
    let cancel = Cancellation::default();
    let reopened = ActivationJournal::open_existing(directory, &cancel, deadline()).unwrap();
    let proof = reopened
        .observe_closed_process_inventory(key, &cancel, deadline())
        .unwrap()
        .expect("all real launchers and namespaces exited");
    let state = reopened.snapshot(&cancel, deadline()).unwrap();
    assert!(proof.matches(&state, key));
    assert!(
        !state.manager_changes[key].settled,
        "inventory is not epoch settlement"
    );
    let mut omitted = state.clone();
    let id = omitted.manager_changes[key]
        .attempts
        .iter()
        .next()
        .unwrap()
        .clone();
    omitted
        .manager_changes
        .get_mut(key)
        .unwrap()
        .attempts
        .remove(&id);
    assert!(!proof.matches(&omitted, key));
    let mut missing_launcher = state;
    missing_launcher
        .attempts
        .get_mut(&id)
        .unwrap()
        .launcher = None;
    assert!(!proof.matches(&missing_launcher, key));
}

fn assert_inventory_shape(journal: &ActivationJournal, key: &str, resources: &[&str]) {
    use super::super::manager_change::ResourceExecution;
    let state = journal
        .snapshot(&Cancellation::default(), deadline())
        .unwrap();
    let change = &state.manager_changes[key];
    assert_eq!(change.attempts.len(), 2);
    assert_eq!(change.resources.len(), resources.len());
    let invocations = change
        .attempts
        .iter()
        .map(|id| state.attempts[id].invocation.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        invocations,
        [
            "22222222222222222222222222222222",
            "33333333333333333333333333333333"
        ]
        .into_iter()
        .collect()
    );
    for name in resources {
        assert_eq!(
            state
                .changed_execution(key, &format!("test/{name}"))
                .unwrap(),
            ResourceExecution::Started
        );
    }
    if resources.len() == 1 {
        let entry = &change.resources[&format!("test/{}", resources[0])];
        assert_eq!(entry.invocations.len(), 2);
        assert_eq!(
            entry
                .invocations
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            invocations
        );
        assert_eq!(
            entry
                .invocations
                .values()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            change.attempts
        );
        let bindings = change
            .attempts
            .iter()
            .map(|id| state.attempts[id].binding.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            bindings.len(),
            1,
            "both invocations must share the exact binding"
        );
    }
}

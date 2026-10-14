use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};
use syrox_engine::{
    cancellation::Cancellation, store::ContentDigest, systemd::SystemdManager,
    systemd::SystemdScope, systemd::SystemdUnitName, systemd::SystemdUnitReference,
};

fn bounded(path: impl AsRef<Path>, maximum: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(
        bytes.len() as u64 <= maximum,
        "proc/journal byte limit"
    );
    bytes
}
fn start(pid: u32) -> (u32, u64) {
    let text = String::from_utf8(bounded(format!("/proc/{pid}/stat"), 8192)).unwrap();
    let fields = text
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    (
        fields[1].parse().unwrap(),
        fields[19].parse().unwrap(),
    )
}
fn children(pid: u32) -> BTreeSet<u32> {
    let mut result = BTreeSet::new();
    for (index, task) in fs::read_dir(format!("/proc/{pid}/task"))
        .unwrap()
        .enumerate()
    {
        assert!(index < 128, "thread enumeration bound");
        let bytes = bounded(task.unwrap().path().join("children"), 8192);
        for entry in std::str::from_utf8(&bytes)
            .unwrap()
            .split_ascii_whitespace()
        {
            result.insert(entry.parse().unwrap());
            assert!(result.len() <= 128);
        }
    }
    result
}
struct Process {
    pid: u32,
    fd: OwnedFd,
}
impl Process {
    fn child(parent: u32, worker: ContentDigest) -> Self {
        let children_before = children(parent);
        assert_eq!(
            children_before.len(),
            1,
            "expected one dedicated worker child"
        );
        let process = Self::pin(
            *children_before.first().unwrap(),
            worker,
            Some(parent),
        );
        assert_eq!(children(parent), children_before);
        process
    }

    fn pin(pid: u32, worker: ContentDigest, parent: Option<u32>) -> Self {
        let before = start(pid);
        if let Some(parent) = parent {
            assert_eq!(before.0, parent);
        }
        // SAFETY: pidfd_open returns a new process descriptor, never signals a numeric PID.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(
            raw >= 0,
            "pidfd_open: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: ownership transfers once from the successful syscall.
        let fd = unsafe { OwnedFd::from_raw_fd(i32::try_from(raw).unwrap()) };
        assert_eq!(
            ContentDigest::sha256(&bounded(
                format!("/proc/{pid}/exe"),
                super::fixture::MAX_BINARY
            )),
            worker
        );
        assert_eq!(
            start(pid),
            before,
            "process identity changed during pin"
        );
        let process = Self {
            pid,
            fd,
        };
        assert!(!process.exited());
        process
    }
    fn exited(&self) -> bool {
        let mut event = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd; descriptor remains owned.
        let result = unsafe { libc::poll(&raw mut event, 1, 0) };
        assert!(result >= 0);
        assert_eq!(event.revents & libc::POLLNVAL, 0);
        result != 0 && event.revents & libc::POLLIN != 0
    }
    fn wait(&self, deadline: Instant) {
        while !self.exited() {
            assert!(
                Instant::now() < deadline,
                "process {} did not exit",
                self.pid
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
/// Pinned observations before CLI death. Unit state alone is never a process proof.
pub(super) struct Observation {
    guardian: Process,
    monitor: Process,
    namespace: Process,
    owner: Process,
    manager: SystemdManager,
    reference: SystemdUnitReference,
    invocation: Vec<u8>,
    session: String,
}
impl Observation {
    pub(super) fn capture(root: &Path, bus: &Path, cli: u32) -> Self {
        let worker: ContentDigest = fs::read_to_string(root.join("worker-pin"))
            .unwrap()
            .parse()
            .unwrap();
        let guardian = Process::child(cli, worker);
        let monitor_pid = guardian.pid;
        let monitor = Process::child(monitor_pid, worker);
        let namespace = Process::child(monitor.pid, worker);
        let init_pid = namespace.pid;
        let status = String::from_utf8(bounded(format!("/proc/{init_pid}/status"), 65536)).unwrap();
        let ids = status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:"))
            .unwrap()
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        assert!(ids.len() >= 2 && ids.last() == Some(&"1"));
        assert_ne!(
            fs::read_link(format!("/proc/{init_pid}/ns/pid")).unwrap(),
            fs::read_link(format!("/proc/{}/ns/pid", monitor.pid)).unwrap()
        );
        let cancel = Cancellation::default();
        let entries = syrox_engine::deployment::shell::list_managed_shell_sessions(
            &root.join("state"),
            &cancel,
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
        let session = entries[0].session.clone();
        let evidence = entries[0].evidence.as_ref().unwrap();
        assert_ne!(evidence.phase, "closed");
        let record = bounded(
            root.join("state/journal")
                .join(&session)
                .join("state"),
            1024 * 1024,
        );
        let json: serde_json::Value = serde_json::from_slice(
            record
                .strip_prefix(b"syrox-session-state-v2\n")
                .unwrap(),
        )
        .unwrap();
        let attempts = json["attempts"].as_object().unwrap();
        assert_eq!(
            attempts.len(),
            1,
            "gate has owner only, no configured services"
        );
        let owner_record = attempts.values().next().unwrap();
        assert_eq!(owner_record["role"], "owner");
        assert_eq!(owner_record["phase"], "consumed");
        let unit = SystemdUnitName::new(
            owner_record["binding"]["unit"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap();
        let invocation = owner_record["binding"]["invocation"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| u8::try_from(n.as_u64().unwrap()).unwrap())
            .collect::<Vec<_>>();
        let mut manager = SystemdManager::connect(
            SystemdScope::User {
                bus_socket: bus.to_path_buf(),
            },
            Duration::from_secs(10),
            &cancel,
        )
        .unwrap();
        let reference = manager
            .reference_unit(&unit, Duration::from_secs(10), &cancel)
            .unwrap();
        let first = manager
            .query(&unit, Duration::from_secs(10), &cancel)
            .unwrap()
            .expect("owner unit must be present");
        assert_eq!(first.invocation, invocation);
        assert!(first.main_pid > 1);
        let owner = Process::pin(first.main_pid, worker, None);
        let second = manager
            .query(&unit, Duration::from_secs(10), &cancel)
            .unwrap()
            .unwrap();
        assert_eq!(second.invocation, invocation);
        assert_eq!(second.main_pid, first.main_pid);
        manager
            .verify_unit_reference(&reference, Duration::from_secs(10), &cancel)
            .unwrap();
        Self {
            guardian,
            monitor,
            namespace,
            owner,
            manager,
            reference,
            invocation,
            session,
        }
    }
    pub(super) fn settled(&mut self, root: &Path, deadline: Instant, abrupt: bool) {
        self.namespace.wait(deadline);
        self.monitor.wait(deadline);
        self.guardian.wait(deadline);
        self.owner.wait(deadline);
        let cancel = Cancellation::default();
        loop {
            assert!(
                Instant::now() < deadline,
                "owner retention settlement deadline"
            );
            self.manager
                .verify_unit_reference(&self.reference, Duration::from_secs(5), &cancel)
                .unwrap();
            let observed = self
                .manager
                .query_fd_store(
                    self.reference.unit(),
                    Duration::from_secs(5),
                    &cancel,
                )
                .unwrap()
                .expect("absence is not settlement evidence");
            assert_eq!(
                observed.invocation, self.invocation,
                "owner invocation replaced"
            );
            if observed.count == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        super::fixture::verify_retained(root);
        let entries = syrox_engine::deployment::shell::list_managed_shell_sessions(
            &root.join("state"),
            &cancel,
        )
        .unwrap();
        let evidence = entries
            .iter()
            .find(|entry| entry.session == self.session)
            .unwrap()
            .evidence
            .as_ref()
            .unwrap();
        // Current cleanup deliberately never invents journal Closed or GC authority.
        assert_ne!(evidence.phase, "closed");
        if abrupt {
            assert!(
                evidence.configuration_hint.is_dir(),
                "abrupt exit must conserve configuration evidence"
            );
        }
        self.manager
            .unreference_unit(
                &mut self.reference,
                Duration::from_secs(5),
                &cancel,
            )
            .unwrap();
    }
}

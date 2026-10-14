//! Opt-in deterministic syscall-boundary race on the actual pinned CLI.
//! No shell parsing, synthetic settlement, or fallback when ptrace is denied.
use super::{driver, fixture};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read as _;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use syrox_engine::{cancellation::Cancellation, store::ContentDigest};

#[path = "stop_exit/tracer.rs"]
mod tracer;
const ANCHOR: &str = "SYROX_STOP_EXIT_ANCHOR";
const LIMIT: Duration = Duration::from_secs(90);

#[test]
#[ignore = "requires pinned CLI/worker/payload, explicit user bus/parent, user/PID/mount namespaces, ptrace SEIZE/SYSCALL/DETACH and external guardian wake"]
fn root_exit_between_protocol_pause_and_frontend_sigstop_restores_terminal() {
    assert_eq!(
        std::env::consts::ARCH,
        "x86_64",
        "syscall barrier profile"
    );
    let bus = fixture::absolute("SYROX_INTERACTIVE_BUS");
    let root = fixture::create();
    let outcome = std::panic::catch_unwind(|| run_anchor(&root, &bus));
    if outcome.is_err() {
        let cancel = Cancellation::default();
        if let Ok(sessions) = syrox_engine::deployment::shell::list_managed_shell_sessions(
            &root.join("state"),
            &cancel,
        ) {
            for session in sessions {
                let result = syrox_engine::deployment::shell::recover_managed_shell_session(
                    &root.join("state"),
                    &session.session,
                    &bus,
                    &root.join("store"),
                    &cancel,
                );
                eprintln!("stop/exit gate cleanup: {result:?}");
            }
        }
    }
    if let Err(error) = outcome {
        std::panic::resume_unwind(error);
    }
}
fn run_anchor(root: &Path, bus: &Path) {
    let mut terminal = driver::Terminal::open();
    let master = terminal.master.as_raw_fd();
    let slave = terminal.slave.as_raw_fd();
    let parent = std::process::id();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "interactive::stop_exit::anchor_process",
            "--ignored",
            "--nocapture",
        ])
        .env(ANCHOR, root)
        .env("SYROX_STOP_EXIT_MASTER", master.to_string())
        .env("SYROX_INTERACTIVE_BUS", bus)
        .env("RUST_BACKTRACE", "0");
    // SAFETY: pre-exec changes only this dedicated child's tty/session/FDs.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                || libc::getppid().cast_unsigned() != parent
                || libc::setsid() < 0
                || libc::ioctl(slave, libc::TIOCSCTTY, 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            for fd in 0..=2 {
                if libc::dup2(slave, fd) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::fcntl(master, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut anchor = driver::GuardedChild::spawn(&mut command);
    let deadline = Instant::now() + LIMIT + Duration::from_secs(30);
    let mut capture = Vec::new();
    let status = loop {
        terminal.drain(&mut capture);
        if let Some(status) = anchor.poll() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "anchor timeout; not settlement"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    terminal.drain(&mut capture);
    fs::write(root.join("stop-exit-transcript"), &capture).unwrap();
    assert!(
        status.success(),
        "gate failed; evidence {}: {}",
        root.display(),
        String::from_utf8_lossy(&capture)
    );
    assert!(
        root.join("stop-exit-success").is_file(),
        "anchor did not complete the syscall-race assertions"
    );
}

fn spawn_cli(root: &Path, bus: &Path) -> tracer::Tracer {
    let mut command = driver::command(root);
    command
        .current_dir(root.join("project"))
        .args([
            "shell",
            ".#shell",
            "--command",
            "payload",
            "--interactive",
            "--offline",
            "--store",
        ])
        .arg(root.join("store"))
        .arg("--session-state")
        .arg(root.join("state"))
        .arg("--systemd-user-bus")
        .arg(bus)
        .arg("--cwd")
        .arg(root.join("work"))
        .args([
            "--",
            "terminal",
            "literal ; $HOME *",
            "41",
            "113",
        ]);
    let parent = std::process::id();
    // The anchor must NOT share the foreground job's group: kill(0,SIGSTOP)
    // would otherwise stop the tracer itself and invalidate the barrier.
    unsafe {
        command.pre_exec(move || {
            let mut block = MaybeUninit::<libc::sigset_t>::zeroed();
            let mut previous = MaybeUninit::<libc::sigset_t>::zeroed();
            if libc::sigemptyset(block.as_mut_ptr()) < 0
                || libc::sigaddset(block.as_mut_ptr(), libc::SIGTTOU) < 0
                || libc::sigprocmask(
                    libc::SIG_BLOCK,
                    block.as_ptr(),
                    previous.as_mut_ptr(),
                ) < 0
                || libc::setpgid(0, 0) < 0
                || libc::tcsetpgrp(0, libc::getpgrp()) < 0
                || libc::sigprocmask(
                    libc::SIG_SETMASK,
                    previous.as_ptr(),
                    std::ptr::null_mut(),
                ) < 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                || libc::getppid().cast_unsigned() != parent
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    tracer::Tracer::new(command.spawn().unwrap())
}

#[test]
#[ignore = "reexecuted syscall-race fixture; exercised by the stop/exit gate"]
fn anchor_process() {
    let root = std::env::var_os(ANCHOR).expect("stop/exit fixture requires its owning gate");
    let root = PathBuf::from(root);
    let bus = fixture::absolute("SYROX_INTERACTIVE_BUS");
    let master: i32 = std::env::var("SYROX_STOP_EXIT_MASTER")
        .unwrap()
        .parse()
        .unwrap();
    assert!(master >= 3);
    // SAFETY: transferred master is unique; own a new slave duplicate, both CLOEXEC.
    let mut terminal = unsafe {
        assert_eq!(
            libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC),
            0
        );
        let slave = libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3);
        assert!(slave >= 3);
        driver::Terminal {
            master: File::from_raw_fd(master),
            slave: OwnedFd::from_raw_fd(slave),
        }
    };
    let original = driver::attributes(terminal.slave.as_raw_fd());
    let untouched = driver::Terminal::open();
    let untouched_attributes = driver::attributes(untouched.slave.as_raw_fd());
    let mut cli = spawn_cli(&root, &bus);
    let deadline = Instant::now() + LIMIT;
    let mut bytes = Vec::new();
    loop {
        terminal.drain(&mut bytes);
        if bytes
            .windows(b"SYROX_SESSION_V1 READY terminal 24 80".len())
            .any(|w| w == b"SYROX_SESSION_V1 READY terminal 24 80")
        {
            break;
        }
        assert!(
            cli.running_untraced(),
            "CLI exited before readiness: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(Instant::now() < deadline, "readiness timeout");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!driver::same_attributes(
        &original,
        &driver::attributes(terminal.slave.as_raw_fd())
    ));
    let tree = Tree::capture(&root, cli.pid());
    cli.attach()
        .expect("ptrace capability required; denial is a failed/pending host gate");
    tree.payload.signal(libc::SIGSTOP);
    cli.before_stop(deadline, || terminal.drain(&mut bytes));
    // We now hold the exact syscall entry after the last userspace observation.
    // Exit of this one payload is intentionally NOT global settlement evidence.
    tree.payload.signal(libc::SIGKILL);
    tree.payload.wait(deadline);
    fs::write(
        root.join("stop-exit-barrier"),
        b"root exited while CLI held before kill(0,SIGSTOP)\n",
    )
    .unwrap();
    cli.release_stop();
    let status = cli.finish(deadline, || terminal.drain(&mut bytes));
    assert_eq!(status.code(), Some(137));
    tree.settled(deadline);
    assert!(driver::same_attributes(
        &original,
        &driver::attributes(terminal.slave.as_raw_fd())
    ));
    assert!(driver::same_attributes(
        &untouched_attributes,
        &driver::attributes(untouched.slave.as_raw_fd())
    ));
    // CLI's own group remained foreground throughout; recovery must not steal it.
    assert_eq!(
        unsafe { libc::tcgetpgrp(terminal.slave.as_raw_fd()) }.cast_unsigned(),
        cli.pid()
    );
    verify_execution(&root);
    fs::write(root.join("stop-exit-success"), b"actual syscall barrier, observed group stop, guardian wake, authentic settlement and tty restoration\n").unwrap();
}

fn bounded(path: impl AsRef<Path>, maximum: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() as u64 <= maximum);
    bytes
}
fn children(pid: u32) -> BTreeSet<u32> {
    let mut result = BTreeSet::new();
    for (index, task) in fs::read_dir(format!("/proc/{pid}/task"))
        .unwrap()
        .enumerate()
    {
        assert!(index < 128);
        let bytes = bounded(task.unwrap().path().join("children"), 8192);
        for pid in std::str::from_utf8(&bytes)
            .unwrap()
            .split_ascii_whitespace()
        {
            result.insert(pid.parse().unwrap());
        }
        assert!(result.len() <= 128);
    }
    result
}
fn process_identity(pid: u32) -> (u32, u64) {
    let bytes = bounded(format!("/proc/{pid}/stat"), 8192);
    let fields = std::str::from_utf8(&bytes)
        .unwrap()
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
struct Process {
    fd: OwnedFd,
}
impl Process {
    fn child(parent: u32, expected: ContentDigest) -> (Self, u32) {
        let ids = children(parent);
        assert_eq!(ids.len(), 1, "exact dedicated process chain");
        let pid = *ids.first().unwrap();
        let before = process_identity(pid);
        assert_eq!(before.0, parent);
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0);
        let process = Self {
            fd: unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).unwrap()) },
        };
        assert_eq!(
            ContentDigest::sha256(&bounded(
                format!("/proc/{pid}/exe"),
                fixture::MAX_BINARY
            )),
            expected
        );
        assert_eq!(process_identity(pid), before);
        assert_eq!(children(parent), ids);
        assert!(!process.exited());
        (process, pid)
    }
    fn exited(&self) -> bool {
        let mut event = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(unsafe { libc::poll(&raw mut event, 1, 0) } >= 0);
        assert_eq!(event.revents & libc::POLLNVAL, 0);
        event.revents & libc::POLLIN != 0
    }
    fn signal(&self, signal: i32) {
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.fd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            },
            0
        );
    }
    fn wait(&self, deadline: Instant) {
        while !self.exited() {
            assert!(
                Instant::now() < deadline,
                "pinned process did not exit"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
struct Tree {
    guardian: Process,
    monitor: Process,
    init: Process,
    payload: Process,
}
impl Tree {
    fn capture(root: &Path, cli: u32) -> Self {
        let worker = fs::read_to_string(root.join("worker-pin"))
            .unwrap()
            .parse()
            .unwrap();
        let payload_pin = std::env::var("SYROX_INTERACTIVE_PAYLOAD_SHA256")
            .unwrap()
            .parse()
            .unwrap();
        let (guardian, guardian_pid) = Process::child(cli, worker);
        let (monitor, monitor_pid) = Process::child(guardian_pid, worker);
        let (init, init_pid) = Process::child(monitor_pid, worker);
        let (payload, _) = Process::child(init_pid, payload_pin);
        let status = bounded(format!("/proc/{init_pid}/status"), 65536);
        let ids = std::str::from_utf8(&status)
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("NSpid:"))
            .unwrap()
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        assert!(ids.len() >= 2 && ids.last() == Some(&"1"));
        Self {
            guardian,
            monitor,
            init,
            payload,
        }
    }
    fn settled(&self, deadline: Instant) {
        for process in [
            &self.payload,
            &self.init,
            &self.monitor,
            &self.guardian,
        ] {
            process.wait(deadline);
        }
    }
}
fn verify_execution(root: &Path) {
    let sessions = syrox_engine::deployment::shell::list_managed_shell_sessions(
        &root.join("state"),
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(sessions.len(), 1);
    let path = root
        .join("state/journal")
        .join(&sessions[0].session)
        .join("state");
    let bytes = bounded(path, 1024 * 1024);
    let json: serde_json::Value = serde_json::from_slice(
        bytes
            .strip_prefix(b"syrox-session-state-v2\n")
            .unwrap(),
    )
    .unwrap();
    let executions = json["executions"].as_object().unwrap();
    assert_eq!(executions.len(), 1);
    let (id, record) = executions.iter().next().unwrap();
    assert_eq!(record["phase"], "settled");
    assert_eq!(record["next_gate"], 1);
    assert!(record["guardian"].is_object());
    assert!(
        !root
            .join("store/.syrox-store/interests")
            .join(format!("hold-{id}"))
            .exists()
    );
    fixture::verify_retained(root);
}

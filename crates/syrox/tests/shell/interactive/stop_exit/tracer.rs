//! A test-only syscall barrier. Never follows worker forks or manufactures SIGCONT.
use std::collections::BTreeSet;
use std::io::{self, Read as _, Write as _};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub(super) struct Tracer {
    child: Child,
    tasks: BTreeSet<i32>,
    initializing: BTreeSet<i32>,
    held: Option<i32>,
    status: Option<ExitStatus>,
    pub(super) group_stopped: bool,
    stop_released: bool,
}
fn ptrace(
    request: libc::c_uint,
    pid: i32,
    address: usize,
    data: usize,
) -> io::Result<libc::c_long> {
    // SAFETY: scalar requests or live buffers owned at each call site; only our child/tasks.
    let result = unsafe {
        libc::ptrace(
            request,
            pid,
            address as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}
fn task_ids(pid: u32) -> io::Result<BTreeSet<i32>> {
    let mut tasks = BTreeSet::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/task"))? {
        if tasks.len() >= 128 {
            return Err(io::Error::other("CLI thread bound"));
        }
        tasks.insert(
            entry?
                .file_name()
                .to_str()
                .ok_or_else(|| io::Error::other("task name"))?
                .parse()
                .map_err(io::Error::other)?,
        );
    }
    Ok(tasks)
}
impl Tracer {
    pub(super) fn new(child: Child) -> Self {
        Self {
            child,
            tasks: BTreeSet::new(),
            initializing: BTreeSet::new(),
            held: None,
            status: None,
            group_stopped: false,
            stop_released: false,
        }
    }
    pub(super) fn pid(&self) -> u32 {
        self.child.id()
    }
    pub(super) fn running_untraced(&mut self) -> bool {
        assert!(self.tasks.is_empty());
        self.status = self.child.try_wait().unwrap();
        self.status.is_none()
    }
    pub(super) fn attach(&mut self) -> io::Result<()> {
        // Attach the stable ready CLI task set. A new task racing this inventory
        // is a failed fixture precondition, never silently untraced execution.
        let tasks = task_ids(self.pid())?;
        for pid in &tasks {
            ptrace(
                libc::PTRACE_SEIZE,
                *pid,
                0,
                (libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_EXITKILL)
                    as usize,
            )?;
            self.tasks.insert(*pid);
            self.initializing.insert(*pid);
            ptrace(libc::PTRACE_INTERRUPT, *pid, 0, 0)?;
        }
        if task_ids(self.pid())? != tasks {
            return Err(io::Error::other(
                "CLI tasks changed during attach",
            ));
        }
        Ok(())
    }
    pub(super) fn before_stop(&mut self, deadline: Instant, mut drain: impl FnMut()) {
        while self.held.is_none() {
            self.tick(true).unwrap();
            drain();
            assert!(
                self.status.is_none(),
                "CLI exited before protocol stop syscall"
            );
            assert!(
                Instant::now() < deadline,
                "protocol stop syscall barrier timeout"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    pub(super) fn release_stop(&mut self) {
        let pid = self
            .held
            .take()
            .expect("held kill(0,SIGSTOP) entry");
        self.stop_released = true;
        ptrace(libc::PTRACE_SYSCALL, pid, 0, 0).unwrap();
    }
    pub(super) fn finish(&mut self, deadline: Instant, mut drain: impl FnMut()) -> ExitStatus {
        while self.status.is_none() || !self.tasks.is_empty() {
            self.tick(false).unwrap();
            drain();
            assert!(
                Instant::now() < deadline,
                "CLI did not wake/exit; no test SIGCONT was sent"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            self.group_stopped,
            "kill syscall did not produce an observed group stop"
        );
        self.status.unwrap()
    }
    fn tick(&mut self, intercept: bool) -> io::Result<()> {
        if self.tasks.is_empty() && self.group_stopped && self.status.is_none() {
            self.status = self.child.try_wait()?;
            return Ok(());
        }
        for pid in self.tasks.clone() {
            if self.held == Some(pid) {
                continue;
            }
            let mut status = 0;
            // SAFETY: exact traced TID only, never waitpid(-1) in libtest.
            let found =
                unsafe { libc::waitpid(pid, &raw mut status, libc::__WALL | libc::WNOHANG) };
            if found == 0 {
                continue;
            }
            if found < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                self.tasks.remove(&pid);
                if pid.cast_unsigned() == self.pid() {
                    self.status = Some(ExitStatus::from_raw(status));
                }
                continue;
            }
            if !libc::WIFSTOPPED(status) {
                return Err(io::Error::other("unexpected ptrace wait status"));
            }
            self.stopped(pid, status, intercept)?;
        }
        Ok(())
    }
    fn stopped(&mut self, pid: i32, status: i32, intercept: bool) -> io::Result<()> {
        let signal = libc::WSTOPSIG(status);
        let event = status >> 16;
        if event == libc::PTRACE_EVENT_CLONE {
            let mut task = 0_u64;
            ptrace(
                libc::PTRACE_GETEVENTMSG,
                pid,
                0,
                (&raw mut task) as usize,
            )?;
            if self.tasks.len() >= 128 {
                return Err(io::Error::other("traced thread bound"));
            }
            let task = i32::try_from(task).map_err(io::Error::other)?;
            self.tasks.insert(task);
            self.initializing.insert(task);
        }
        if self.group_stopped {
            // Once the leader's actual group-stop was observed, leave every
            // task untraced. A real pending signal delivery is preserved;
            // debugger-generated traps are never injected into the candidate.
            let delivery = if event != 0 || signal == libc::SIGTRAP | 0x80 {
                0
            } else {
                signal
            };
            return self.detach(pid, delivery);
        }
        if event == libc::PTRACE_EVENT_STOP && self.initializing.remove(&pid) {
            // Initial SEIZE/CLONE stops are debugger attachment, not job stops.
            ptrace(libc::PTRACE_SYSCALL, pid, 0, 0)?;
        } else if event == libc::PTRACE_EVENT_STOP && signal == libc::SIGSTOP {
            self.group_stopped = self.stop_released && pid.cast_unsigned() == self.pid();
            // DETACH with signal zero reinstates the pending kernel group stop.
            // LISTEN would leave /proc State 't', masking production's real-T
            // wakeup authority. This path sends no SIGCONT.
            self.detach(pid, 0)?;
            if self.group_stopped {
                for task in &self.tasks {
                    ptrace(libc::PTRACE_INTERRUPT, *task, 0, 0)?;
                }
            }
        } else if signal == libc::SIGTRAP | 0x80 {
            let mut info = [0_u64; 16];
            let count = ptrace(
                libc::PTRACE_GET_SYSCALL_INFO,
                pid,
                size_of_val(&info),
                info.as_mut_ptr() as usize,
            )?;
            if intercept && stop_entry(&info, usize::try_from(count).unwrap_or(0)) {
                self.held = Some(pid);
                return Ok(());
            }
            ptrace(libc::PTRACE_SYSCALL, pid, 0, 0)?;
        } else if event != 0 {
            ptrace(libc::PTRACE_SYSCALL, pid, 0, 0)?;
        } else {
            // Forward only signals genuinely reported by ptrace, never invent
            // SIGCONT to help the candidate complete the test.
            ptrace(
                libc::PTRACE_SYSCALL,
                pid,
                0,
                signal.cast_unsigned() as usize,
            )?;
        }
        Ok(())
    }
    fn detach(&mut self, pid: i32, signal: i32) -> io::Result<()> {
        ptrace(
            libc::PTRACE_DETACH,
            pid,
            0,
            signal.cast_unsigned() as usize,
        )?;
        self.tasks.remove(&pid);
        self.initializing.remove(&pid);
        Ok(())
    }
}
fn stop_entry(info: &[u64; 16], count: usize) -> bool {
    // Linux ptrace_syscall_info: op0, arch4, ip8, sp16, entry.nr24,args32.
    count >= 48
        && info[0] & 0xff == 1
        && info[0] >> 32 == 0xc000_003e
        && info[3] == libc::SYS_kill.cast_unsigned()
        && info[4] == 0
        && info[5] == libc::SIGSTOP as u64
}
impl Drop for Tracer {
    fn drop(&mut self) {
        self.held = None;
        if self.status.is_none() {
            // Direct child still unreaped: Child::kill cannot target a reused PID.
            let _ = self.child.kill();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.tasks.is_empty() && Instant::now() < deadline {
            if self.tick(false).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if self.status.is_none() {
            let _ = self.child.wait();
        }
    }
}
#[test]
fn syscall_barrier_requires_entry_architecture_and_exact_signal_target() {
    let mut record = [0; 16];
    record[0] = (0xc000_003e << 32) | 1;
    record[3] = libc::SYS_kill.cast_unsigned();
    record[5] = libc::SIGSTOP as u64;
    assert!(stop_entry(&record, 48));
    assert!(!stop_entry(&record, 47));
    for field in [0, 3, 4, 5] {
        let mut wrong = record;
        wrong[field] ^= 1;
        assert!(!stop_entry(&wrong, 48));
    }
}

#[test]
#[ignore = "reexecuted process-group fixture; exercised by the detach regression"]
fn stopping_child() {
    let ready = std::env::var_os("SYROX_TRACER_STOP_CHILD")
        .expect("stopping fixture requires its owning gate");
    std::fs::write(ready, b"ready").unwrap();
    let mut byte = [0];
    io::stdin().read_exact(&mut byte).unwrap();
    assert_eq!(byte, [b'x']);
    // SAFETY: this reexecuted fixture owns its private process group.
    assert_eq!(unsafe { libc::kill(0, libc::SIGSTOP) }, 0);
    panic!("fixture was resumed unexpectedly; no waker is authorized");
}

#[test]
fn detach_preserves_real_stopped_state_without_a_waker() {
    let root = tempfile::tempdir().unwrap();
    let ready = root.path().join("ready");
    let parent = std::process::id();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "interactive::stop_exit::tracer::stopping_child",
            "--ignored",
            "--nocapture",
        ])
        .env("SYROX_TRACER_STOP_CHILD", &ready)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    // SAFETY: only the dedicated child's group and parent-death signal change.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) < 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                || libc::getppid().cast_unsigned() != parent
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = Tracer::new(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.is_file() {
        assert!(child.running_untraced());
        assert!(
            Instant::now() < deadline,
            "fixture readiness deadline"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    child
        .attach()
        .expect("ptrace denied: real stop regression remains pending");
    child
        .child
        .stdin
        .take()
        .unwrap()
        .write_all(b"x")
        .unwrap();
    child.before_stop(deadline, || {});
    child.release_stop();
    while !child.group_stopped || !child.tasks.is_empty() {
        child.tick(false).unwrap();
        assert!(
            Instant::now() < deadline,
            "detach deadline is not a stop proof"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    loop {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.pid())).unwrap();
        let state = stat.rsplit_once(") ").unwrap().1.as_bytes()[0];
        if state == b'T' {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "detached tracee did not reach State T"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // Kill and reap only after actual State T was observed. Drop never continues
    // the tracee, and no namespace/systemd or terminal restoration is claimed.
    drop(child);
}

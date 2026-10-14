use super::{
    OpenedPath, open_beneath, open_top_directory, pidfd_exited, pidfd_open, require_unique_pidfd,
};
use std::io::{self, Read as _};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::path::Path;

const PROCESS_GROUP: libc::c_uint = 1 << 2;
const MAX_STAT: u64 = 8192;

pub(crate) struct PinnedProcessGroup {
    group: OwnedFd,
    frontend: OwnedFd,
    process: OpenedPath,
    identity: ProcessIdentity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    session: u32,
    group: u32,
    start: u64,
}
impl PinnedProcessGroup {
    pub(crate) fn capture(frontend_pid: u32) -> io::Result<Self> {
        if frontend_pid != std::process::id() {
            return Err(invalid());
        }
        let frontend = pidfd_open(frontend_pid)?;
        let process = process_directory(frontend_pid)?;
        let (identity, _) = read_process(&process)?;
        let group = pidfd_open(identity.group)?;
        Self::from_received(
            group,
            frontend.as_fd(),
            frontend_pid,
            identity.session,
            identity.group,
        )
    }
    pub(crate) fn from_received(
        group: OwnedFd,
        frontend: BorrowedFd<'_>,
        expected_frontend: u32,
        expected_session: u32,
        expected_group: u32,
    ) -> io::Result<Self> {
        // Noninteractive callers can belong to PID 1's session. That session
        // number is comparison data; only the separately pinned group (>1)
        // receives signals. PID 1 and its process group remain excluded.
        if expected_frontend <= 1 || expected_session == 0 || expected_group <= 1 {
            return Err(invalid());
        }
        let actual_frontend = pidfd_open(expected_frontend)?;
        let actual_group = pidfd_open(expected_group)?;
        if require_unique_pidfd(frontend)?.identity()
            != require_unique_pidfd(actual_frontend.as_fd())?.identity()
            || require_unique_pidfd(group.as_fd())?.identity()
                != require_unique_pidfd(actual_group.as_fd())?.identity()
            || pidfd_exited(frontend)?
            || pidfd_exited(group.as_fd())?
        {
            return Err(invalid());
        }
        let process = process_directory(expected_frontend)?;
        let (identity, _) = read_process(&process)?;
        let leader = process_directory(expected_group)?;
        let (leader_identity, _) = read_process(&leader)?;
        if identity.pid != expected_frontend
            || identity.session != expected_session
            || identity.group != expected_group
            || leader_identity.pid != expected_group
            || leader_identity.group != expected_group
            || leader_identity.session != expected_session
        {
            return Err(invalid());
        }
        let result = Self {
            group,
            frontend: frontend.try_clone_to_owned()?,
            process,
            identity,
        };
        // Capability and permission probe before Ready/raw/Start; no fallback to kill(-pgid).
        result.signal(0)?;
        result.revalidate()?;
        Ok(result)
    }
    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.group.as_fd()
    }
    /// No foreground mutation and no payload signal. A stopped frontend must
    /// belong to this originally admitted group throughout the observation.
    pub(crate) fn continue_if_stopped(&self) -> io::Result<bool> {
        let stopped = self.revalidate()?;
        if stopped {
            self.signal(libc::SIGCONT)?;
        }
        Ok(stopped)
    }
    fn revalidate(&self) -> io::Result<bool> {
        if pidfd_exited(self.frontend.as_fd())? {
            return Err(invalid());
        }
        let (identity, state) = read_process(&self.process)?;
        if identity != self.identity || pidfd_exited(self.frontend.as_fd())? {
            return Err(invalid());
        }
        // Lowercase t is a ptrace stop, not the protocol's group stop.
        Ok(state == b'T')
    }
    fn signal(&self, signal: libc::c_int) -> io::Result<()> {
        loop {
            // SAFETY: pinned process-group leader identity; null siginfo selects
            // ordinary permission checks, with explicit process-group scope.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.group.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    PROCESS_GROUP,
                )
            };
            if result == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}
fn process_directory(pid: u32) -> io::Result<OpenedPath> {
    let root = open_top_directory(Path::new("/proc")).map_err(|_| invalid())?;
    if super::filesystem_type(root.fd())? != 0x9fa0 {
        return Err(invalid());
    }
    open_beneath(root.fd(), Path::new(&pid.to_string()), true).map_err(|_| invalid())
}
fn read_process(process: &OpenedPath) -> io::Result<(ProcessIdentity, u8)> {
    let status = open_beneath(process.fd(), Path::new("stat"), false).map_err(|_| invalid())?;
    if super::filesystem_type(status.fd())? != 0x9fa0 {
        return Err(invalid());
    }
    let mut text = String::new();
    status
        .into_file()
        .take(MAX_STAT + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_STAT {
        return Err(invalid());
    }
    parse_process(&text)
}
fn parse_process(text: &str) -> io::Result<(ProcessIdentity, u8)> {
    let (pid, _) = text.split_once(' ').ok_or_else(invalid)?;
    let (_, suffix) = text.rsplit_once(") ").ok_or_else(invalid)?;
    let mut fields = suffix.split_ascii_whitespace();
    let state = fields
        .next()
        .filter(|state| state.len() == 1)
        .ok_or_else(invalid)?
        .as_bytes()[0];
    let group = fields
        .nth(1)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    let session = fields
        .next()
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    let start = fields
        .nth(15)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    Ok((
        ProcessIdentity {
            pid: pid.parse().map_err(|_| invalid())?,
            group,
            session,
            start,
        },
        state,
    ))
}
fn invalid() -> io::Error {
    io::Error::other("external terminal process-group identity unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    fn proc_identity_parsing_preserves_comm_delimiters_and_stop_kind() {
        let fields = "7 (unusual ) name) T 2 7 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 99 0";
        let (identity, state) = parse_process(fields).unwrap();
        assert_eq!(
            identity,
            ProcessIdentity {
                pid: 7,
                group: 7,
                session: 3,
                start: 99
            }
        );
        assert_eq!(state, b'T');
        assert!(parse_process("7 (name) T 2 7").is_err());
        assert!(parse_process("invalid").is_err());
    }

    #[test]
    fn group_wakeup_reaches_all_members_after_the_stop_barrier() {
        const NAME: &str = "platform::linux::fd::group_pidfd::tests::group_wakeup_reaches_all_members_after_the_stop_barrier";
        match std::env::var("SYROX_GROUP_WAKE_ROLE").as_deref() {
            Ok("frontend") => {
                frontend(NAME);
                return;
            }
            Ok("member") => {
                loop {
                    // SAFETY: reexec fixture waits for the group's signals only.
                    unsafe {
                        libc::pause();
                    }
                }
            }
            _ => {}
        }
        if super::super::retention_fork_tests::isolate_test(NAME, "SYROX_GROUP_WAKE_ISOLATED") {
            return;
        }
        let mut command = fixture(NAME, "frontend");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = ChildGuard(command.spawn().unwrap());
        let mut input = child.0.stdin.take().unwrap();
        let mut output = child.0.stdout.take().unwrap();
        super::super::set_nonblocking(output.as_fd()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        let member = read_marker(&mut output, "MEMBER ", deadline)
            .parse::<u32>()
            .unwrap();
        let pid = child.0.id();
        let descriptor = pidfd_open(pid).unwrap();
        // SAFETY: observe the pinned child's current session before admission.
        let session = unsafe { libc::getsid(pid.cast_signed()) }.cast_unsigned();
        let group = PinnedProcessGroup::from_received(
            descriptor.try_clone().unwrap(),
            descriptor.as_fd(),
            pid,
            session,
            pid,
        )
        .unwrap();
        assert!(!group.continue_if_stopped().unwrap());
        let foreign = pidfd_open(std::process::id()).unwrap();
        assert!(
            PinnedProcessGroup::from_received(foreign, descriptor.as_fd(), pid, session, pid)
                .is_err()
        );
        assert!(
            PinnedProcessGroup::from_received(
                descriptor.try_clone().unwrap(),
                descriptor.as_fd(),
                pid,
                session + 1,
                pid
            )
            .is_err()
        );
        let member_directory = process_directory(member).unwrap();
        for round in 0..2 {
            // This release models root exit after the frontend's last liveness
            // check, but before SIGSTOP. No early CONT is considered sufficient.
            input.write_all(b"s").unwrap();
            loop {
                assert!(
                    Instant::now() < deadline,
                    "group never entered its protocol stop"
                );
                if group.revalidate().unwrap() && read_process(&member_directory).unwrap().1 == b'T'
                {
                    break;
                }
                std::thread::yield_now();
            }
            assert!(group.continue_if_stopped().unwrap());
            assert_eq!(
                read_marker(&mut output, "RESUMED ", deadline),
                round.to_string()
            );
            while read_process(&member_directory).unwrap().1 == b'T' {
                assert!(
                    Instant::now() < deadline,
                    "second group member was not resumed"
                );
                std::thread::yield_now();
            }
        }
        input.write_all(b"x").unwrap();
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "frontend did not finish"
            );
            std::thread::yield_now();
        }
    }
    fn fixture(name: &str, role: &str) -> Command {
        let mut command = Command::new(crate::reexec_test_executable(name, false));
        command
            .args([
                "--exact",
                name,
                "--nocapture",
                "--quiet",
            ])
            .env("SYROX_GROUP_WAKE_ROLE", role);
        let parent = std::process::id().cast_signed();
        let new_session = matches!(role, "frontend" | "leader");
        let parent_death = role != "orphan-member";
        // SAFETY: callback only invokes async-signal-safe syscalls in fork child.
        unsafe {
            command.pre_exec(move || {
                if (parent_death && libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0)
                    || libc::getppid() != parent
                {
                    return Err(io::Error::other("fixture parent disappeared"));
                }
                if new_session && libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
    }
    fn frontend(name: &str) {
        let mut member = ChildGuard(
            fixture(name, "member")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        println!("MEMBER {}", member.0.id());
        io::stdout().flush().unwrap();
        for round in 0..2 {
            let mut command = [0];
            io::stdin().read_exact(&mut command).unwrap();
            assert_eq!(command, *b"s");
            // SAFETY: reexec fixture has its own process group, also containing its
            // sole child; no harness or external shell shares this group.
            assert_eq!(unsafe { libc::kill(0, libc::SIGSTOP) }, 0);
            println!("RESUMED {round}");
            io::stdout().flush().unwrap();
        }
        let mut command = [0];
        io::stdin().read_exact(&mut command).unwrap();
        assert_eq!(command, *b"x");
        member.0.kill().unwrap();
        member.0.wait().unwrap();
    }
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn read_marker(reader: &mut impl io::Read, prefix: &str, deadline: Instant) -> String {
        let mut line = Vec::new();
        loop {
            assert!(
                Instant::now() < deadline,
                "fixture marker deadline"
            );
            let mut byte = [0];
            match reader.read(&mut byte) {
                Ok(1) if byte[0] == b'\n' => {
                    let text = String::from_utf8(std::mem::take(&mut line)).unwrap();
                    if let Some(value) = text.strip_prefix(prefix) {
                        return value.to_owned();
                    }
                }
                Ok(1) => {
                    line.push(byte[0]);
                    assert!(line.len() <= 4096);
                }
                Ok(_) => panic!("fixture closed before marker"),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::yield_now();
                }
                Err(error) => panic!("fixture read: {error}"),
            }
        }
    }

    #[test]
    fn admitted_group_survives_reaped_leader_with_live_frontend_member() {
        const NAME: &str = "platform::linux::fd::group_pidfd::tests::admitted_group_survives_reaped_leader_with_live_frontend_member";
        match std::env::var("SYROX_GROUP_WAKE_ROLE").as_deref() {
            Ok("leader") => {
                orphaning_leader(NAME);
                return;
            }
            Ok("orphan-member") => adopted_member(),
            _ => {}
        }
        if super::super::retention_fork_tests::isolate_test(NAME, "SYROX_GROUP_LEADER_ISOLATED") {
            return;
        }
        // SAFETY: isolated test process owns all descendants in this fixture.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let mut leader = ChildGuard(
            fixture(NAME, "leader")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut output = leader.0.stdout.take().unwrap();
        super::super::set_nonblocking(output.as_fd()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        let member = read_marker(&mut output, "MEMBER ", deadline)
            .parse::<u32>()
            .unwrap();
        let member_fd = pidfd_open(member).unwrap();
        let cleanup = AdoptedMember {
            pid: member,
            descriptor: member_fd.try_clone().unwrap(),
        };
        let leader_pid = leader.0.id();
        let leader_fd = pidfd_open(leader_pid).unwrap();
        let group = PinnedProcessGroup::from_received(
            leader_fd,
            member_fd.as_fd(),
            member,
            leader_pid,
            leader_pid,
        )
        .unwrap();
        let foreign = pidfd_open(std::process::id()).unwrap();
        assert!(
            PinnedProcessGroup::from_received(
                foreign,
                member_fd.as_fd(),
                member,
                leader_pid,
                leader_pid
            )
            .is_err()
        );
        leader
            .0
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"x")
            .unwrap();
        loop {
            if let Some(status) = leader.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(
            read_marker(&mut output, "ADOPTED ", deadline),
            "ready"
        );
        assert!(!pidfd_exited(member_fd.as_fd()).unwrap());
        group.signal(libc::SIGSTOP).unwrap();
        while !group.revalidate().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(group.continue_if_stopped().unwrap());
        while group.revalidate().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        drop(cleanup);
    }
    struct AdoptedMember {
        pid: u32,
        descriptor: OwnedFd,
    }
    impl Drop for AdoptedMember {
        fn drop(&mut self) {
            // SAFETY: live pinned fixture child, then reap this exact adopted PID.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.descriptor.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
                while libc::waitpid(self.pid.cast_signed(), std::ptr::null_mut(), 0) < 0
                    && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
                {
                }
            }
        }
    }

    // The leader must exit first: custody transfers to the isolated subreaper,
    // whose AdoptedMember guard explicitly kills and waitpid-reaps this child.
    #[allow(clippy::zombie_processes)] // This fixture deliberately proves an orphaned group member outlives its frontend; the group observer reaps settlement.
    fn orphaning_leader(name: &str) {
        let member = fixture(name, "orphan-member")
            .env(
                "SYROX_GROUP_LEADER_PID",
                std::process::id().to_string(),
            )
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        println!("MEMBER {}", member.id());
        io::stdout().flush().unwrap();
        let mut byte = [0];
        io::stdin().read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"x");
    }

    fn adopted_member() -> ! {
        // The leader sends its PID via the inherited fixture environment.
        // Wait for adoption before arming parent death on the subreaper.
        let original = std::env::var("SYROX_GROUP_LEADER_PID")
            .unwrap()
            .parse::<i32>()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        // SAFETY: scalar parent query in a dedicated fixture.
        while unsafe { libc::getppid() } == original {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        // SAFETY: arm death of the adopting isolated supervisor, with race check.
        unsafe {
            let parent = libc::getppid();
            assert!(parent > 1);
            assert_eq!(
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0),
                0
            );
            assert_eq!(libc::getppid(), parent);
        }
        println!("ADOPTED ready");
        io::stdout().flush().unwrap();
        loop {
            // SAFETY: dedicated reexec member waits only for group signals.
            unsafe {
                libc::pause();
            }
        }
    }
}

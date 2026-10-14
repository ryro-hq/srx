use std::fs::File;
use std::io::{Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub(super) const TIMEOUT: Duration = Duration::from_secs(60);
pub(super) struct GuardedChild {
    child: Child,
    reaped: bool,
}
impl GuardedChild {
    pub(super) fn spawn(command: &mut Command) -> Self {
        Self {
            child: command.spawn().unwrap(),
            reaped: false,
        }
    }
    pub(super) fn id(&self) -> u32 {
        self.child.id()
    }
    pub(super) fn kill(&mut self) {
        self.child.kill().unwrap();
    }
    pub(super) fn poll(&mut self) -> Option<ExitStatus> {
        let status = self.child.try_wait().unwrap();
        self.reaped |= status.is_some();
        status
    }
    pub(super) fn wait(&mut self, deadline: Instant) -> ExitStatus {
        loop {
            if let Some(status) = self.poll() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "child deadline expired"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for GuardedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        // kill/wait is required cleanup, not a hard guarantee against kernel stalls.
    }
}
pub(super) fn command(root: &Path) -> Command {
    let mut command = Command::new(root.join("bin/srx"));
    command
        .env_clear()
        .env("HOME", root.join("home"))
        .env("PATH", "")
        .env("LC_ALL", "C");
    command
}
fn checked(value: libc::c_int) {
    assert!(value >= 0, "{}", std::io::Error::last_os_error());
}
fn owned(value: libc::c_int) -> OwnedFd {
    checked(value);
    // SAFETY: successful open/ioctl transferred exactly one descriptor.
    unsafe { OwnedFd::from_raw_fd(value) }
}
pub(super) struct Terminal {
    pub(super) master: File,
    pub(super) slave: OwnedFd,
}
impl Terminal {
    pub(super) fn open() -> Self {
        // SAFETY: integer-only PTY allocation; CLOEXEC is atomic.
        let master = owned(unsafe {
            libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK)
        });
        // SAFETY: the newly allocated master is live and exclusive to the fixture.
        checked(unsafe { libc::grantpt(master.as_raw_fd()) });
        checked(unsafe { libc::unlockpt(master.as_raw_fd()) });
        let slave = owned(unsafe {
            libc::ioctl(
                master.as_raw_fd(),
                libc::TIOCGPTPEER,
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        });
        let terminal = Self {
            master: master.into(),
            slave,
        };
        terminal.resize(24, 80);
        let mut attrs = attributes(terminal.slave.as_raw_fd());
        attrs.c_lflag |= libc::ISIG | libc::ICANON | libc::ECHO;
        attrs.c_cc[libc::VINTR] = 3;
        attrs.c_cc[libc::VMIN] = 1;
        attrs.c_cc[libc::VTIME] = 0;
        // SAFETY: initialized termios is applied to the owned test PTY only.
        checked(unsafe {
            libc::tcsetattr(
                terminal.slave.as_raw_fd(),
                libc::TCSANOW,
                &raw const attrs,
            )
        });
        terminal
    }
    pub(super) fn resize(&self, rows: u16, cols: u16) {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: ioctl reads one initialized winsize from live storage.
        checked(unsafe {
            libc::ioctl(
                self.master.as_raw_fd(),
                libc::TIOCSWINSZ,
                &raw const size,
            )
        });
    }
    pub(super) fn send(&mut self, bytes: &[u8], deadline: Instant) {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            match self.master.write(remaining) {
                Ok(0) => panic!("PTY write closed"),
                Ok(count) => remaining = &remaining[count..],
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => panic!("PTY write: {error}"),
            }
            assert!(Instant::now() < deadline, "PTY write deadline");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub(super) fn drain(&mut self, bytes: &mut Vec<u8>) {
        let mut buffer = [0_u8; 8192];
        loop {
            match self.master.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    assert!(
                        bytes.len() + count <= 1024 * 1024,
                        "PTY capture exceeds 1MiB"
                    );
                    bytes.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(libc::EIO) =>
                {
                    break;
                }
                Err(error) => panic!("PTY capture: {error}"),
            }
        }
    }
    pub(super) fn until(
        &mut self,
        marker: &[u8],
        child: &mut GuardedChild,
        bytes: &mut Vec<u8>,
        deadline: Instant,
    ) {
        loop {
            self.drain(bytes);
            if bytes
                .windows(marker.len())
                .any(|part| part == marker)
            {
                return;
            }
            assert!(
                child.poll().is_none(),
                "CLI exited before {:?}: {}",
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(bytes)
            );
            assert!(
                Instant::now() < deadline,
                "PTY marker deadline: {}",
                String::from_utf8_lossy(bytes)
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
pub(super) fn attributes(fd: libc::c_int) -> libc::termios {
    let mut value = MaybeUninit::<libc::termios>::zeroed();
    // SAFETY: tcgetattr initializes the complete structure on success.
    checked(unsafe { libc::tcgetattr(fd, value.as_mut_ptr()) });
    unsafe { value.assume_init() }
}
pub(super) fn same_attributes(a: &libc::termios, b: &libc::termios) -> bool {
    a.c_iflag == b.c_iflag
        && a.c_oflag == b.c_oflag
        && a.c_cflag == b.c_cflag
        && a.c_lflag == b.c_lflag
        && a.c_line == b.c_line
        && a.c_cc == b.c_cc
        && a.c_ispeed == b.c_ispeed
        && a.c_ospeed == b.c_ospeed
}
pub(super) fn anchor(root: &Path, mode: &str, bus: &Path) {
    let mut terminal = Terminal::open();
    let master = terminal.master.as_raw_fd();
    let slave = terminal.slave.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "interactive::anchor_process",
            "--ignored",
            "--nocapture",
        ])
        .env("SYROX_INTERACTIVE_ANCHOR", root)
        .env("SYROX_INTERACTIVE_MODE", mode)
        .env("SYROX_INTERACTIVE_MASTER", master.to_string())
        .env("SYROX_INTERACTIVE_BUS", bus)
        .env("RUST_BACKTRACE", "0");
    // SAFETY: dedicated pre-exec child changes only its own session/stdio and
    // descriptor flags. Parent descriptor owners remain alive until spawn.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 || libc::ioctl(slave, libc::TIOCSCTTY, 0) < 0 {
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
    let mut child = GuardedChild::spawn(&mut command);
    let status = child.wait(Instant::now() + TIMEOUT + TIMEOUT);
    let mut output = Vec::new();
    terminal.drain(&mut output);
    assert!(
        status.success(),
        "interactive anchor failed; evidence retained at {}: {}",
        root.display(),
        String::from_utf8_lossy(&output)
    );
    assert!(
        root.join("interactive-anchor-success").is_file(),
        "anchor did not complete its lifecycle assertions"
    );
}
pub(super) fn cli(root: &Path, bus: &Path, args: &[String]) -> GuardedChild {
    let mut command = command(root);
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
        .arg("--")
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // Keep failure/timeout cleanup tied to the dedicated anchor, without ever
    // signaling a PID observed from procfs or a foreign manager unit.
    // SAFETY: getpid only queries the anchor; pre_exec runs in its fork child.
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0
                || libc::getppid() != parent
            {
                return Err(std::io::Error::other("anchor ownership lost"));
            }
            Ok(())
        });
    }
    GuardedChild::spawn(&mut command)
}

use std::ffi::OsStr;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

#[derive(Debug)]
pub(crate) struct PreparedLaunch<'a> {
    strings: Vec<u8>,
    arguments: Vec<usize>,
    inherited: Vec<BorrowedFd<'a>>,
}

impl<'a> PreparedLaunch<'a> {
    pub(crate) fn new(program: &OsStr) -> io::Result<Self> {
        let mut launch = Self {
            strings: Vec::new(),
            arguments: Vec::new(),
            inherited: Vec::new(),
        };
        launch.arg(program)?;
        Ok(launch)
    }

    pub(crate) fn arg(&mut self, value: impl AsRef<OsStr>) -> io::Result<&mut Self> {
        let bytes = value.as_ref().as_bytes();
        if bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NUL in process argument",
            ));
        }
        self.arguments.push(self.strings.len());
        self.strings.extend_from_slice(bytes);
        self.strings.push(0);
        Ok(self)
    }

    pub(crate) fn args(
        &mut self,
        values: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> io::Result<&mut Self> {
        for value in values {
            self.arg(value)?;
        }
        Ok(self)
    }

    pub(crate) fn inherit(&mut self, fd: BorrowedFd<'a>) {
        self.inherited.push(fd);
    }

    pub(crate) fn spawn(mut self) -> io::Result<Spawned> {
        let mut environment = Vec::new();
        // vars_os snapshots the environment under std's environment lock. OS
        // environment entries cannot contain NUL; all bytes are owned here.
        for (key, value) in std::env::vars_os() {
            environment.push(self.strings.len());
            self.strings.extend_from_slice(key.as_bytes());
            self.strings.push(b'=');
            self.strings.extend_from_slice(value.as_bytes());
            self.strings.push(0);
        }
        // Freeze storage before constructing pointers; moving the Box does not
        // move its allocation. libc only reads argv/envp during this call.
        let mut strings = self.strings.into_boxed_slice();
        let base = strings.as_mut_ptr().cast::<libc::c_char>();
        let pointers = |offsets: &[usize]| {
            offsets
                .iter()
                .map(|&at| base.wrapping_add(at))
                .chain(std::iter::once(std::ptr::null_mut()))
                .collect::<Vec<_>>()
        };
        let argv = pointers(&self.arguments);
        let envp = pointers(&environment);
        let mut actions = Actions::new()?;
        self.inherited
            .sort_unstable_by_key(AsRawFd::as_raw_fd);
        self.inherited.dedup_by_key(|fd| fd.as_raw_fd());
        for fd in self.inherited {
            // SAFETY: actions is initialized and fd is borrowed through spawn.
            // POSIX dup2 actions clear CLOEXEC even when source == destination;
            // the parent's descriptor flags are never changed.
            result(unsafe {
                libc::posix_spawn_file_actions_adddup2(
                    &raw mut actions.0,
                    fd.as_raw_fd(),
                    fd.as_raw_fd(),
                )
            })?;
        }
        let mut attributes = Attributes::new()?;
        // SAFETY: initialized opaque POSIX objects and sigset, live until spawn.
        unsafe {
            result(libc::posix_spawnattr_setpgroup(
                &raw mut attributes.0,
                0,
            ))?;
            let mut defaults = MaybeUninit::<libc::sigset_t>::zeroed();
            result(libc::sigemptyset(defaults.as_mut_ptr()))?;
            let mut defaults = defaults.assume_init();
            result(libc::sigaddset(&raw mut defaults, libc::SIGPIPE))?;
            result(libc::posix_spawnattr_setsigdefault(
                &raw mut attributes.0,
                &raw const defaults,
            ))?;
            result(libc::posix_spawnattr_setflags(
                &raw mut attributes.0,
                (libc::POSIX_SPAWN_SETPGROUP | libc::POSIX_SPAWN_SETSIGDEF) as libc::c_short,
            ))?;
        }
        let mut pid = 0;
        // SAFETY: strings, null-terminated pointer arrays, actions and attributes
        // remain live. posix_spawn uses the explicit program path, never PATH.
        result(unsafe {
            libc::posix_spawn(
                &raw mut pid,
                argv[0],
                &raw const actions.0,
                &raw const attributes.0,
                argv.as_ptr(),
                envp.as_ptr(),
            )
        })?;
        Ok(Spawned {
            pid,
            status: None,
        })
    }
}

fn result(code: libc::c_int) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code))
    }
}

struct Actions(libc::posix_spawn_file_actions_t);
impl Actions {
    fn new() -> io::Result<Self> {
        let mut value = MaybeUninit::zeroed();
        // SAFETY: init writes the opaque object on success, before any use.
        result(unsafe { libc::posix_spawn_file_actions_init(value.as_mut_ptr()) })?;
        // SAFETY: successful init initialized the complete opaque object.
        Ok(Self(unsafe { value.assume_init() }))
    }
}
impl Drop for Actions {
    fn drop(&mut self) {
        // SAFETY: exactly one destructor for this initialized actions object.
        unsafe {
            libc::posix_spawn_file_actions_destroy(&raw mut self.0);
        }
    }
}

struct Attributes(libc::posix_spawnattr_t);
impl Attributes {
    fn new() -> io::Result<Self> {
        let mut value = MaybeUninit::zeroed();
        // SAFETY: init writes the opaque object on success, before any use.
        result(unsafe { libc::posix_spawnattr_init(value.as_mut_ptr()) })?;
        // SAFETY: successful init initialized the complete opaque object.
        Ok(Self(unsafe { value.assume_init() }))
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: exactly one destructor for this initialized attributes object.
        unsafe {
            libc::posix_spawnattr_destroy(&raw mut self.0);
        }
    }
}

/// Like `std::process::Child`, the launch coordinator explicitly owns settlement.
#[derive(Debug)]
pub(crate) struct Spawned {
    pid: libc::pid_t,
    status: Option<ExitStatus>,
}
impl Spawned {
    pub(crate) fn id(&self) -> u32 {
        self.pid.cast_unsigned()
    }
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.reap(libc::WNOHANG)
    }
    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        self.reap(0)?
            .ok_or_else(|| io::Error::other("blocking wait returned no child"))
    }
    fn reap(&mut self, flags: i32) -> io::Result<Option<ExitStatus>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        loop {
            let mut status = 0;
            // SAFETY: this unreaped direct child is exclusively owned here.
            let found = unsafe { libc::waitpid(self.pid, &raw mut status, flags) };
            if found == self.pid {
                self.status = Some(ExitStatus::from_raw(status));
                return Ok(self.status);
            }
            if found == 0 {
                return Ok(None);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;

    #[test]
    fn signal_defaults_match_command_without_changing_the_parent() {
        use std::os::unix::process::CommandExt as _;
        const PROBE: &str = "SYROX_SPAWN_SIGNAL_PROBE";
        if std::env::var_os(PROBE).is_some() {
            for (signal, expected) in [("PIPE", None), ("XFSZ", Some(7))] {
                let mut launch = PreparedLaunch::new(OsStr::new("/bin/sh")).unwrap();
                launch
                    .args([
                        "-c",
                        &format!("kill -{signal} $$; exit 7"),
                    ])
                    .unwrap();
                let status = launch.spawn().unwrap().wait().unwrap();
                assert_eq!(status.code(), expected);
                if expected.is_none() {
                    assert_eq!(status.signal(), Some(libc::SIGPIPE));
                }
            }
            return;
        }
        let mut command = std::process::Command::new(crate::reexec_test_executable(
            "platform::linux::fd::launch::tests::signal_defaults_match_command_without_changing_the_parent",
            false,
        ));
        command.args(["--exact", "platform::linux::fd::launch::tests::signal_defaults_match_command_without_changing_the_parent"]).env(PROBE, "1");
        // SAFETY: only the forked test child changes its disposition; signal is
        // async-signal-safe and no parent process-global state is mutated.
        unsafe {
            command.pre_exec(|| {
                if libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        assert!(command.status().unwrap().success());
    }

    #[test]
    fn spawn_transfers_only_selected_fds_and_preserves_argument_bytes() {
        let (mut read, write) = UnixStream::pair().unwrap();
        let (unused, _) = UnixStream::pair().unwrap();
        let unused_target =
            std::fs::read_link(format!("/proc/self/fd/{}", unused.as_raw_fd())).unwrap();
        // Bash accepts redirections to inherited descriptors above 9; dash does not.
        let mut command = PreparedLaunch::new(OsStr::new("/bin/bash")).unwrap();
        command.inherit(write.as_fd());
        command
            .args([
                "-c",
                &format!(
                    "test \"$(readlink /proc/self/fd/{})\" != '{}' || exit 9; printf '%s' \"$1\" >&{}",
                    unused.as_raw_fd(),
                    unused_target.display(),
                    write.as_raw_fd()
                ),
                "sh",
                " spaces ' \" ",
            ])
            .unwrap();
        let mut child = command.spawn().unwrap();
        drop(write);
        let mut bytes = String::new();
        read.read_to_string(&mut bytes).unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(bytes, " spaces ' \" ");
        assert!(child.try_wait().unwrap().unwrap().success());
        let command = PreparedLaunch::new(OsStr::new("/missing-syrox-worker")).unwrap();
        assert_eq!(
            command.spawn().unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}

/// Build IR commands have an explicit, closed environment and working directory.
/// Calling libc directly avoids Rust's `AF_UNIX` fallback for chdir with static
/// glibc. The inherited seccomp/Landlock policy remains unchanged.
pub(crate) fn run_build_command(command: &std::process::Command) -> io::Result<ExitStatus> {
    use std::ffi::CString;
    use std::path::Path;
    if !Path::new(command.get_program()).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "build executable must be absolute",
        ));
    }
    let argument_strings = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|value| CString::new(value.as_bytes()).map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?;
    let environment_strings = command
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key, value)))
        .map(|(key, value)| {
            let mut entry = key.as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            CString::new(entry).map_err(io::Error::other)
        })
        .collect::<io::Result<Vec<_>>>()?;
    let pointers = |values: &[CString]| {
        values
            .iter()
            .map(|value| value.as_ptr().cast_mut())
            .chain(std::iter::once(std::ptr::null_mut()))
            .collect::<Vec<_>>()
    };
    let argv = pointers(&argument_strings);
    let environment = pointers(&environment_strings);
    let directory = command
        .get_current_dir()
        .map(|directory| CString::new(directory.as_os_str().as_bytes()).map_err(io::Error::other))
        .transpose()?;
    let mut actions = Actions::new()?;
    let mut attributes = Attributes::new()?;
    // SAFETY: all POSIX objects, argument/environment arrays, C strings and
    // descriptors remain live through spawn. Actions run in libc's child;
    // no Rust callback or parent-global cwd/environment mutation occurs.
    unsafe {
        result(libc::posix_spawn_file_actions_addopen(
            &raw mut actions.0,
            0,
            c"/dev/null".as_ptr(),
            libc::O_RDONLY,
            0,
        ))?;
        result(libc::posix_spawn_file_actions_adddup2(
            &raw mut actions.0,
            2,
            1,
        ))?;
        if let Some(directory) = &directory {
            result(libc::posix_spawn_file_actions_addchdir_np(
                &raw mut actions.0,
                directory.as_ptr(),
            ))?;
        }
        let mut defaults = MaybeUninit::<libc::sigset_t>::zeroed();
        result(libc::sigemptyset(defaults.as_mut_ptr()))?;
        let mut defaults = defaults.assume_init();
        result(libc::sigaddset(&raw mut defaults, libc::SIGPIPE))?;
        result(libc::posix_spawnattr_setsigdefault(
            &raw mut attributes.0,
            &raw const defaults,
        ))?;
        result(libc::posix_spawnattr_setflags(
            &raw mut attributes.0,
            libc::POSIX_SPAWN_SETSIGDEF as libc::c_short,
        ))?;
        let mut pid = 0;
        result(libc::posix_spawn(
            &raw mut pid,
            argv[0],
            &raw const actions.0,
            &raw const attributes.0,
            argv.as_ptr(),
            environment.as_ptr(),
        ))?;
        Spawned {
            pid,
            status: None,
        }
        .wait()
    }
}

#[cfg(test)]
#[test]
fn build_spawn_keeps_cwd_environment_and_socket_denial_under_seccomp() {
    const PROBE: &str = "SYROX_BUILD_SPAWN_PROBE";
    if let Some(directory) = std::env::var_os(PROBE) {
        let bytes = crate::build::policy::seccomp_filter();
        let mut instructions: Vec<libc::sock_filter> = bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|entry| libc::sock_filter {
                code: u16::from_le_bytes(entry[..2].try_into().unwrap()),
                jt: entry[2],
                jf: entry[3],
                k: u32::from_le_bytes(entry[4..].try_into().unwrap()),
            })
            .collect();
        let filter = libc::sock_fprog {
            len: u16::try_from(instructions.len()).unwrap(),
            filter: instructions.as_mut_ptr(),
        };
        // SAFETY: dedicated reexec test owns its permanent process policy;
        // aligned BPF storage remains live through the kernel's copy.
        unsafe {
            assert_eq!(
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
                0
            );
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &raw const filter,
                    0,
                    0
                ),
                0
            );
        }
        assert_eq!(
            std::os::unix::net::UnixStream::pair()
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        let mut command = std::process::Command::new("/bin/sh");
        command.env_clear().env("VALUE"," space value ").env("EXPECTED_CWD",&directory).current_dir(&directory)
            .args(["-c","test \"$VALUE\" = ' space value ' && test -z \"${SYROX_BUILD_SPAWN_PROBE+x}\" && test \"$(pwd)\" = \"$EXPECTED_CWD\" && test ! -s /dev/stdin && printf 'build-spawn-output\\n'"]);
        assert!(run_build_command(&command).unwrap().success());
        command.current_dir("/missing-build-cwd");
        assert_eq!(
            run_build_command(&command).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(crate::reexec_test_executable("platform::linux::fd::launch::build_spawn_keeps_cwd_environment_and_socket_denial_under_seccomp", false))
        .args([
            "--exact",
            "platform::linux::fd::launch::build_spawn_keeps_cwd_environment_and_socket_denial_under_seccomp",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROBE, directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("build-spawn-output"));
}

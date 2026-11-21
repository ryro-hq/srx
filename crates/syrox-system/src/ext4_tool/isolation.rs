use super::{policy, refused, reopen::Reopen};
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};

pub(super) struct Setup {
    directory: Reopen,
    tool: i32,
    image: CString,
    image_fd: i32,
    reopen_image: Reopen,
    arguments: Vec<CString>,
    writable: bool,
    image_bytes: u64,
    filter: Vec<libc::sock_filter>,
    filter_len: u16,
    progress: i32,
    parent: i32,
}

#[repr(C)]
struct Header {
    version: u32,
    pid: i32,
}
#[repr(C)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

impl Setup {
    pub(super) fn new(
        tool: BorrowedFd<'_>,
        image: BorrowedFd<'_>,
        directory: BorrowedFd<'_>,
        writable: bool,
        image_bytes: u64,
        progress: BorrowedFd<'_>,
        arguments: Vec<String>,
    ) -> io::Result<Self> {
        // stdio redirection must not replace one of the setup descriptors.
        if [tool, image, directory, progress]
            .iter()
            .any(|fd| fd.as_raw_fd() < 3)
        {
            return Err(refused(
                "tool setup descriptions must be above stdio",
            ));
        }
        let filter = policy::filter();
        let filter_len =
            u16::try_from(filter.len()).map_err(|_| refused("tool filter length overflow"))?;
        let mut argv = vec![CString::from(c"/tool")];
        for argument in arguments {
            argv.push(CString::new(argument).map_err(|_| refused("NUL in fixed tool argument"))?);
        }
        if argv.len() >= 32 {
            return Err(refused("too many fixed tool arguments"));
        }
        Ok(Self {
            directory: Reopen::new(directory, true)?,
            tool: tool.as_raw_fd(),
            image: CString::new(format!("/proc/self/fd/{}", image.as_raw_fd()))
                .map_err(|_| refused("NUL in image descriptor path"))?,
            image_fd: image.as_raw_fd(),
            reopen_image: Reopen::new(image, false)?,
            arguments: argv,
            writable,
            image_bytes,
            filter,
            filter_len,
            progress: progress.as_raw_fd(),
            // SAFETY: observation in the parent before Command forks.
            parent: unsafe { libc::getpid() },
        })
    }

    // Called only in pre_exec. All dynamic storage was prepared in the parent;
    // this path uses syscalls, fixed C strings and stack ABI structs only.
    pub(super) fn apply(&self) -> io::Result<()> {
        // SAFETY: arm termination on helper death, then close the race where
        // the parent exited before prctl. Neither call mutates the parent.
        ok(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) })?;
        // SAFETY: getppid takes no arguments and only reads this process's parent id.
        if unsafe { libc::getppid() } != self.parent {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.mark(1)?;
        // SAFETY: fixed namespace flags; no project-controlled pointers.
        ok(unsafe {
            libc::unshare(
                libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS,
            )
        })?;
        self.mark(2)?;
        mount(
            None,
            c"/",
            None,
            libc::MS_PRIVATE | libc::MS_REC,
            None,
        )?;
        let directory = self.directory.open()?;
        // SAFETY: reopened identity-checked directory in THIS mount namespace.
        ok(unsafe { libc::fchdir(directory) })?;
        // SAFETY: `directory` was opened above by this child and is closed exactly once.
        ok(unsafe { libc::close(directory) })?;
        let image = self.reopen_image.open()?;
        // SAFETY: replace only our inherited image descriptor in the child.
        // Its proc-fd path now refers to the same inode in the new namespace.
        ok(unsafe { libc::dup3(image, self.image_fd, libc::O_CLOEXEC) })?;
        // SAFETY: `image` is the fresh reopened descriptor, now duplicated; close it once.
        ok(unsafe { libc::close(image) })?;
        self.mark(3)?;
        mount(
            Some(c"tmpfs"),
            c"tool-root",
            Some(c"tmpfs"),
            libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
            Some(c"size=1M,nr_inodes=16,mode=0700"),
        )?;
        // chdir resolves the NEW mount; fchdir to the covered directory would
        // retain the host filesystem and defeat the intended root isolation.
        // SAFETY: a static NUL-terminated relative path; chdir only reads it.
        ok(unsafe { libc::chdir(c"tool-root".as_ptr()) })?;
        self.mark(4)?;
        for path in [c"image", c"config"] {
            // SAFETY: fixed relative placeholders on the new private tmpfs.
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
                    0o600,
                )
            };
            ok(fd)?;
            // SAFETY: `fd` was just created by open above, succeeded, and is closed once.
            ok(unsafe { libc::close(fd) })?;
        }
        self.mark(5)?;
        null_device()?;
        self.mark(6)?;
        mount(
            Some(&self.image),
            c"image",
            None,
            libc::MS_BIND,
            None,
        )?;
        let image_flags = libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_NOSUID
            | libc::MS_NODEV
            | libc::MS_NOEXEC
            | if self.writable {
                0
            } else {
                libc::MS_RDONLY
            };
        mount(None, c"image", None, image_flags, None)?;
        self.mark(7)?;
        mount(
            None,
            c".",
            None,
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
            None,
        )?;
        self.mark(8)?;
        // SAFETY: static NUL-terminated path; the child owns its private mount namespace.
        ok(unsafe { libc::chroot(c".".as_ptr()) })?;
        // SAFETY: static NUL-terminated path; chdir only reads it.
        ok(unsafe { libc::chdir(c"/".as_ptr()) })?;
        // All unknown inherited FDs, including the original image, tool and
        // operation directory, close on exec. Keep Rust's spawn error pipe
        // usable until exec so setup failure is reported without running tool.
        self.mark(9)?;
        // SAFETY: close_range with CLOSE_RANGE_CLOEXEC (4) only marks descriptors >= 3
        // close-on-exec; it takes no pointers and closes nothing before exec.
        ok(unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) })?;
        self.mark(10)?;
        limit(libc::RLIMIT_CORE, 0)?;
        limit(libc::RLIMIT_AS, 256 * 1024 * 1024)?;
        limit(libc::RLIMIT_STACK, 8 * 1024 * 1024)?;
        limit(libc::RLIMIT_CPU, 60)?;
        limit(libc::RLIMIT_NOFILE, 64)?;
        limit(libc::RLIMIT_NPROC, 0)?;
        limit(libc::RLIMIT_FSIZE, self.image_bytes)?;
        self.mark(11)?;
        // SAFETY: a zero-length group list; the kernel does not read the null pointer.
        ok(unsafe { libc::setgroups(0, std::ptr::null()) })?;
        // SAFETY: fixed prctl option with integer arguments only; affects this child.
        ok(unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        })?;
        // NOROOT, NO_SETUID_FIXUP, !KEEP_CAPS, NO_CAP_AMBIENT_RAISE, all locked.
        self.mark(12)?;
        // SAFETY: fixed prctl option with integer arguments only; affects this child.
        ok(unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 239, 0, 0, 0) })?;
        let header = Header {
            version: 0x2008_0522,
            pid: 0,
        };
        let data = [
            Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        self.mark(13)?;
        // SAFETY: fixed version-3 Linux capabilities ABI, exactly two records.
        ok(unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) })?;
        self.mark(14)?;
        // SAFETY: fixed prctl option with integer arguments only; affects this child.
        ok(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?;
        let program = libc::sock_fprog {
            len: self.filter_len,
            filter: self.filter.as_ptr().cast_mut(),
        };
        self.mark(15)?;
        // SAFETY: filter storage was constructed before fork and remains live;
        // fixed SECCOMP_SET_MODE_FILTER, no listener or TSYNC flags.
        ok(unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                1_u32,
                0_u32,
                &raw const program,
            )
        })?;
        self.mark(16)?;
        let mut arguments = [std::ptr::null::<libc::c_char>(); 32];
        for (slot, argument) in arguments.iter_mut().zip(&self.arguments) {
            *slot = argument.as_ptr();
        }
        let environment = [
            c"LC_ALL=C".as_ptr(),
            c"TZ=UTC".as_ptr(),
            c"MKE2FS_CONFIG=/config".as_ptr(),
            c"E2FSCK_CONFIG=/config".as_ptr(),
            std::ptr::null(),
        ];
        // SAFETY: pinned static executable stays live, argv/envp are terminated
        // arrays of parent-prepared/fixed C strings. CLOEXEC closes all nonstdio
        // descriptions, including this tool, during a successful ELF exec.
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                self.tool,
                c"".as_ptr(),
                arguments.as_ptr(),
                environment.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
        }
        Err(io::Error::last_os_error())
    }

    fn mark(&self, stage: u64) -> io::Result<()> {
        let bytes = stage.to_le_bytes();
        loop {
            // SAFETY: private progress file remains live through spawn, exact
            // stack buffer and fixed offset. No allocation or shared seek.
            let count = unsafe {
                libc::pwrite(
                    self.progress,
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    0,
                )
            };
            if count == 8 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if count < 0 && error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(if count < 0 {
                error
            } else {
                io::ErrorKind::WriteZero.into()
            });
        }
    }
}

#[cfg(target_env = "gnu")]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
type Resource = libc::c_int;

fn limit(resource: Resource, bytes: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: bytes,
        rlim_max: bytes,
    };
    // SAFETY: fixed supported resource and initialized ABI record.
    ok(unsafe { libc::setrlimit(resource, &raw const limit) })
}

fn null_device() -> io::Result<()> {
    // SAFETY: fixed path in the cloned guest/helper namespace, excluding a
    // final symlink. No project-selected device or arbitrary ioctl is accepted.
    let fd = unsafe {
        libc::open(
            c"/dev/null".as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    ok(fd)?;
    // SAFETY: exact stat output storage and our fresh owned descriptor.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is our fresh descriptor and `stat` is writable storage of the exact type.
    ok(unsafe { libc::fstat(fd, &raw mut stat) })?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFCHR || stat.st_rdev != libc::makedev(1, 3) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // Replace stdin only in this child with the namespace-local description,
    // so its fixed proc-fd path can be bind-mounted without a path race.
    // SAFETY: `fd` is our validated null device; dup3 replaces stdin in this child only.
    ok(unsafe { libc::dup3(fd, 0, 0) })?;
    // SAFETY: `fd` is now duplicated to stdin and is closed exactly once.
    ok(unsafe { libc::close(fd) })?;
    // SAFETY: static NUL-terminated relative path on the private tmpfs.
    ok(unsafe { libc::mkdir(c"dev".as_ptr(), 0o755) })?;
    // SAFETY: static NUL-terminated relative path; O_EXCL creates a fresh file.
    let placeholder = unsafe {
        libc::open(
            c"dev/null".as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
            0o600,
        )
    };
    ok(placeholder)?;
    // SAFETY: `placeholder` was just created above, succeeded, and is closed once.
    ok(unsafe { libc::close(placeholder) })?;
    mount(
        Some(c"/proc/self/fd/0"),
        c"dev/null",
        None,
        libc::MS_BIND,
        None,
    )?;
    // This one leaf deliberately permits the validated null device. Its parent
    // remains nodev; the leaf is nosuid/noexec and later the root is read-only.
    mount(
        None,
        c"dev/null",
        None,
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID | libc::MS_NOEXEC,
        None,
    )
}

fn mount(
    source: Option<&CStr>,
    target: &CStr,
    kind: Option<&CStr>,
    flags: libc::c_ulong,
    data: Option<&CStr>,
) -> io::Result<()> {
    // SAFETY: all C strings remain valid throughout this fixed mount syscall.
    ok(unsafe {
        libc::mount(
            source.map_or(std::ptr::null(), CStr::as_ptr),
            target.as_ptr(),
            kind.map_or(std::ptr::null(), CStr::as_ptr),
            flags,
            data.map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    })
}

fn ok(value: impl Into<i64>) -> io::Result<()> {
    if value.into() < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

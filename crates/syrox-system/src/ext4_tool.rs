//! Fixed operations on a helper-owned regular scratch image using a pinned tool.
//!
//! This is an execution primitive, not an authorization protocol. The privileged
//! caller must own a new exclusive operation directory and image, select the
//! tool pin from administrator policy and durably journal intent before calling.
//! Failure leaves evidence in place; it never authorizes replay or reformatting.

use crate::descriptor::{self, pinned_tool::PinnedTool};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _};
use std::os::unix::fs::{FileExt as _, FileTypeExt as _, MetadataExt as _};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

mod isolation;
mod policy;
mod reopen;

const MAX_OUTPUT: usize = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(120);

/// Geometry for a newly allocated image. The inode request is rounded down to
/// ext4's group/table granularity, never above the admitted ceiling. Observation
/// after formatting/mount remains mandatory; these arguments are not evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    bytes: u64,
    inodes: u64,
}

impl Geometry {
    pub fn new(bytes: u64, inode_ceiling: u64) -> io::Result<Self> {
        if !(64 * 1024 * 1024..=128 * 1024 * 1024 * 1024).contains(&bytes)
            || !bytes.is_multiple_of(4096)
        {
            return Err(refused(
                "scratch image requires 64 MiB..128 GiB in 4 KiB blocks",
            ));
        }
        let groups = (bytes / 4096).div_ceil(32768);
        let granularity = groups * 16;
        let inodes = inode_ceiling.min(u64::from(u32::MAX)) / granularity * granularity;
        if inodes < granularity {
            return Err(refused(
                "inode ceiling cannot accommodate one inode table per group",
            ));
        }
        Ok(Self {
            bytes,
            inodes,
        })
    }

    pub const fn image_bytes(self) -> u64 {
        self.bytes
    }
    pub const fn requested_inodes(self) -> u64 {
        self.inodes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Destructive: valid only after independent authorization of a NEW image.
    Format(Geometry),
    /// Forced read-only verification; no repair flags or automatic retry.
    Check,
}

impl Operation {
    fn arguments(self) -> Vec<String> {
        match self {
            Self::Check => ["-f", "-n", "/image"].map(str::to_owned).into(),
            Self::Format(geometry) => {
                let mut args = [
                    "-q", "-F", "-t", "ext4", "-b", "4096", "-I", "256", "-g", "32768", "-N",
                ]
                .map(str::to_owned)
                .to_vec();
                args.push(geometry.inodes.to_string());
                args.extend(
                    [
                        "-m",
                        "0",
                        "-E",
                        "lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0",
                        "/image",
                    ]
                    .map(str::to_owned),
                );
                args.push((geometry.bytes / 4096).to_string());
                args
            }
        }
    }
}

/// Bounded output of a completed fixed operation. A nonzero status is an
/// observed tool result, never permission to retry, repair or delete the image.
#[derive(Debug)]
pub struct ToolResult {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Run a fixed operation in a private mount/network/IPC/UTS namespace. The new
/// root exposes only a regular image, empty config and validated null device.
/// The sealed executable
/// is invoked through execveat and its descriptor closes during exec.
/// Capabilities are cleared, root privilege recovery locked out and a narrow
/// `x86_64` syscall allowlist installed. No processes/threads can be created.
/// The root is read-only; only Format gets a writable bind of the image.
///
/// The caller must provide a root-owned 0700 directory exclusively for this
/// single attempt. `tool-root` is created once and retained, including on error.
/// There is no weaker isolation fallback. Fixed CPU/address-space/FD/output/time
/// ceilings contain tool execution; they are not system build budget admission.
pub fn run(
    tool: &PinnedTool,
    image: &File,
    operation_directory: &File,
    operation: Operation,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<ToolResult> {
    check()?;
    validate(image, operation_directory, operation)?;
    let image_bytes = image.metadata()?.len();
    let executable = tool.descriptor()?;
    if [
        executable,
        image.as_fd(),
        operation_directory.as_fd(),
    ]
    .iter()
    .any(|fd| fd.as_raw_fd() < 3)
    {
        return Err(refused(
            "tool setup descriptions must be above stdio",
        ));
    }
    let input = File::open("/dev/null")?;
    let null = input.metadata()?;
    if !null.file_type().is_char_device() || null.rdev() != libc::makedev(1, 3) {
        return Err(refused(
            "tool stdin must be the fixed null device",
        ));
    }
    check()?;
    // SAFETY: creation relative to a live, validated private directory, fixed
    // name and mode. EEXIST refuses repeat execution; no cleanup/reuse occurs.
    if unsafe {
        libc::mkdirat(
            operation_directory.as_raw_fd(),
            c"tool-root".as_ptr(),
            0o700,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fixed new diagnostic file relative to the validated directory;
    // no symlink/replacement or reuse. The caller retains it after failure.
    let progress = unsafe {
        libc::openat(
            operation_directory.as_raw_fd(),
            c"tool-stage".as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if progress < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh openat result has no other Rust owner.
    let progress = unsafe { File::from_raw_fd(progress) };
    let setup = isolation::Setup::new(
        executable,
        image.as_fd(),
        operation_directory.as_fd(),
        matches!(operation, Operation::Format(_)),
        image_bytes,
        progress.as_fd(),
        operation.arguments(),
    )?;
    operation_directory.sync_all()?;
    check()?;
    let start = Instant::now();
    let mut command = Command::new("/tool");
    command
        .env_clear()
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: Setup::apply uses only fixed raw syscalls and stack storage after
    // fork. It captures no locks, allocator-dependent code or project callback.
    unsafe {
        command.pre_exec(move || setup.apply());
    }
    let child = command.spawn().map_err(|error| {
        let mut bytes = [0; 8];
        let stage = progress
            .read_exact_at(&mut bytes, 0)
            .map_or(0, |()| u64::from_le_bytes(bytes));
        io::Error::new(
            error.kind(),
            format!("tool setup stage {stage}: {error}"),
        )
    })?;
    let result = collect(child, start, &mut check)?;
    validate(image, operation_directory, operation)?;
    if image.metadata()?.len() != image_bytes {
        return Err(refused("tool changed scratch image length"));
    }
    image.sync_all()?;
    check()?;
    Ok(result)
}

fn validate(image: &File, directory: &File, operation: Operation) -> io::Result<()> {
    // SAFETY: credential query has no pointers or effects.
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "tool runner requires existing root authority",
        ));
    }
    let node = image.metadata()?;
    let parent = directory.metadata()?;
    descriptor::require_readonly(directory.as_fd())?;
    let flags = descriptor::status_flags(image.as_fd())?;
    if !node.is_file()
        || node.uid() != 0
        || node.nlink() != 1
        || node.mode() & 0o7777 != 0o600
        || flags & libc::O_ACCMODE != libc::O_RDWR
        || flags & (libc::O_PATH | libc::O_APPEND | libc::O_DIRECT) != 0
        || !parent.is_dir()
        || parent.uid() != 0
        || parent.mode() & 0o7777 != 0o700
    {
        return Err(refused(
            "tool requires a private root-owned regular image and operation directory",
        ));
    }
    let geometry = Geometry::new(node.len(), 16_777_216)?;
    if let Operation::Format(expected) = operation
        && expected.bytes != geometry.bytes
    {
        return Err(refused(
            "image length changed from authorized format geometry",
        ));
    }
    Ok(())
}

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        // Child::kill targets this unreaped child's PID. Fork/clone are denied
        // before tool exec, so no tool descendants can retain descriptors.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn collect(
    child: Child,
    start: Instant,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<ToolResult> {
    let mut child = Reap(child);
    let mut stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing stdout pipe"))?;
    let mut stderr = child
        .0
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing stderr pipe"))?;
    nonblocking(stdout.as_fd())?;
    nonblocking(stderr.as_fd())?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut total = 0;
    let mut eof = [false; 2];
    loop {
        check()?;
        if start.elapsed() >= TIMEOUT {
            return Err(io::ErrorKind::TimedOut.into());
        }
        for (index, (source, destination)) in [
            (&mut stdout as &mut dyn io::Read, &mut out),
            (&mut stderr as &mut dyn io::Read, &mut err),
        ]
        .into_iter()
        .enumerate()
        {
            let mut bytes = [0_u8; 8192];
            match source.read(&mut bytes) {
                Ok(0) => eof[index] = true,
                Ok(count) => {
                    if count > MAX_OUTPUT - total {
                        return Err(refused("tool output exceeded 256 KiB"));
                    }
                    total += count;
                    destination.extend_from_slice(&bytes[..count]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        if let Some(status) = child.0.try_wait()?
            && eof == [true; 2]
        {
            return Ok(ToolResult {
                status,
                stdout: out,
                stderr: err,
            });
        }
        // Poll only when both pipes would otherwise spin. A 20 ms bound keeps
        // cancellation responsive without an unbounded blocking pipe read.
        let mut polls = [
            libc::pollfd {
                fd: if eof[0] {
                    -1
                } else {
                    stdout.as_raw_fd()
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if eof[1] {
                    -1
                } else {
                    stderr.as_raw_fd()
                },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: two initialized pollfd outputs with exact count and timeout.
        if unsafe { libc::poll(polls.as_mut_ptr(), 2, 20) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

fn nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    let flags = descriptor::status_flags(fd)?;
    // SAFETY: fixed integer descriptor flags on the owned pipe endpoint.
    if unsafe {
        libc::fcntl(
            fd.as_raw_fd(),
            libc::F_SETFL,
            flags | libc::O_NONBLOCK,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests;

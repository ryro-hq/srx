//! Linux descriptors and calls into the ABI.
//!
//! Each raw handle is checked before becoming an owned Rust type. A successful
//! transfer leaves one owner responsible for closing it. Safety comments beside
//! the calls explain ABI requirements.
//!
//! Atomic publication retains and revalidates descriptor identity. Concurrent
//! third-party writes in a mutable project directory must still be considered by
//! the caller that authorized that directory. [`process`] covers process identity;
//! [`terminal`] covers PTYs and restoration.

use self::process::pidfs_metadata;

pub(crate) mod sealed_file;
pub(crate) mod tree;

use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::{self, MaybeUninit, size_of};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(test)]
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::ptr::NonNull;

mod buffer;
mod process;
pub(crate) use process::{
    PidfdNamespace, descriptor_status_flags, effective_gid, effective_uid, kill_pidfd,
    namespace_parent, open_proc_executable, pidfd_exited, pidfd_namespace, pidfd_open,
    proc_self_pid, real_gid, real_uid, require_unique_pidfd, validate_pidfd, wait_pidfd,
};
mod group_pidfd;
mod launch;
pub(crate) use group_pidfd::PinnedProcessGroup;
#[cfg(test)]
pub(crate) mod retention_fork_tests;
pub(crate) mod terminal;
mod transport;
pub(crate) use buffer::{ReadBuffer, TailBuffer, read_exact_at};
pub(crate) use launch::{PreparedLaunch, Spawned, run_build_command};
pub(crate) use transport::{receive_fd, send_fd, seqpacket_pair};

/// Inherit one live descriptor only in this command's forked child. The parent
/// retains CLOEXEC so unrelated concurrent spawns cannot extend its lifetime.
#[cfg(test)]
pub(crate) fn pass_fd_to_child(command: &mut std::process::Command, fd: std::os::fd::RawFd) {
    // SAFETY: pre_exec runs after fork, before exec; fcntl is async-signal-safe.
    // The caller retains ownership of fd until Command::spawn returns.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_ATOMIC: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
    static FAIL_NEXT_MAINTENANCE_UNLINK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_MAINTENANCE_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_LOCK_BEFORE_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_LOCK_AFTER_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_LOCK_CLEANUP_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AtomicFault {
    Write,
    FileSync,
    TemporaryReopen,
    Rename,
    PublishedReopen,
    DirectorySync,
    SourceDirectorySync,
    CleanupUnlink,
    CleanupSync,
}

#[cfg(test)]
fn atomic_fault(point: AtomicFault) -> io::Result<()> {
    let bit = 1_u16 << point as u8;
    let faults = FAIL_NEXT_ATOMIC.get();
    if faults & bit != 0 {
        FAIL_NEXT_ATOMIC.set(faults & !bit);
        Err(io::Error::other(format!(
            "injected atomic {point:?} failure"
        )))
    } else {
        Ok(())
    }
}

const TOP_LEVEL_RESOLUTION: u64 = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;

/// Used only by the dedicated single-threaded build worker, before it spawns
/// payloads. Orphans from double-fork/setsid remain children of this worker.
pub(crate) fn become_build_subreaper() -> io::Result<()> {
    // SAFETY: these prctl operations take integer arguments, affect only this
    // process, and do not dereference any userspace address.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // Hide the collector's proc descriptors/memory from same-UID payloads.
    // SAFETY: PR_SET_DUMPABLE takes one integer, not a pointer.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wait for a child of the dedicated worker; None is the kernel's ECHILD
/// evidence, not an observation of a process listing or a recycled PID.
pub(crate) fn reap_build_descendant() -> io::Result<Option<std::process::ExitStatus>> {
    use std::os::unix::process::ExitStatusExt as _;
    loop {
        let mut status = 0;
        // SAFETY: status points to one writable int. waitpid returns only a child
        // of this process, whose wait status is consumed exactly once here.
        let pid = unsafe { libc::waitpid(-1, &raw mut status, 0) };
        if pid > 0 {
            return Ok(Some(std::process::ExitStatus::from_raw(status)));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(None);
        }
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Read the shared open-file-description status flags without changing them.
pub(crate) fn status_flags(fd: BorrowedFd<'_>) -> io::Result<i32> {
    // SAFETY: F_GETFL only queries the live borrowed descriptor.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

/// Require an actual read-only descriptor, excluding path-only handles.
pub(crate) fn require_readonly(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: fcntl reads descriptor flags; the borrowed descriptor remains live.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_PATH != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descriptor is not read-only",
        ));
    }
    Ok(())
}

pub(crate) fn set_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: the borrowed descriptor stays valid and these fcntl operations
    // take integer flags only. Existing status flags are preserved.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe {
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

/// The caller owns an unreaped Child whose process group was set to its PID at
/// spawn. That unreaped leader pins the identifier while its launcher group is killed.
pub(crate) fn kill_launcher_group(pid: u32) -> io::Result<()> {
    let pid = i32::try_from(pid)
        .ok()
        .filter(|pid| *pid > 1)
        .ok_or_else(|| io::Error::other("invalid launcher group"))?;
    // SAFETY: kill takes integers only. The caller establishes ownership of this
    // exact process group. Its leader remains an unreaped child until this call
    // completes, so the group number cannot be reused to signal a stranger.
    loop {
        let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(error);
    }
}

/// Require the Landlock ABI used by the build worker, including device ioctl
/// mediation. The actual restriction is installed after namespace setup by setpriv.
pub(crate) fn require_build_landlock() -> io::Result<()> {
    // SAFETY: the version query takes a null attribute, zero length, and flag 1;
    // it neither dereferences user memory nor creates a ruleset descriptor.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0_usize,
            1_u32,
        )
    };
    if abi < 6 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "build requires Landlock ABI >= 6",
        ));
    }
    Ok(())
}
const BENEATH_RESOLUTION: u64 =
    libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileType {
    Directory,
    Regular,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Metadata {
    file_type: FileType,
    identity: FileIdentity,
    links: u64,
    owner: u32,
    mode: u32,
    size: u64,
    rdev: u64,
}

impl Metadata {
    pub(crate) const fn file_type(self) -> FileType {
        self.file_type
    }

    pub(crate) const fn identity(self) -> FileIdentity {
        self.identity
    }

    pub(crate) const fn rdev(self) -> u64 {
        self.rdev
    }

    pub(crate) const fn size(self) -> u64 {
        self.size
    }

    pub(crate) const fn links(self) -> u64 {
        self.links
    }

    pub(crate) const fn mode(self) -> u32 {
        self.mode
    }

    pub(crate) fn is_trusted_directory(self) -> bool {
        // SAFETY: `geteuid` has no pointer arguments and cannot violate Rust memory safety.
        let effective_user = unsafe { libc::geteuid() };
        self.file_type == FileType::Directory
            && self.owner == effective_user
            && self.mode & 0o022 == 0
    }

    pub(crate) fn is_trusted_regular(self) -> bool {
        // SAFETY: `geteuid` has no pointer arguments and cannot violate Rust memory safety.
        let effective_user = unsafe { libc::geteuid() };
        self.file_type == FileType::Regular
            && self.links == 1
            && self.owner == effective_user
            && self.mode & 0o022 == 0
    }
}

#[derive(Debug)]
pub(crate) struct OpenedPath {
    fd: OwnedFd,
    metadata: Metadata,
}

impl OpenedPath {
    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub(crate) const fn metadata(&self) -> Metadata {
        self.metadata
    }

    pub(crate) fn into_file(self) -> File {
        File::from(self.fd)
    }
}

#[derive(Debug)]
pub(crate) enum OpenError {
    Unsupported(io::Error),
    Symlink,
    Other(io::Error),
}

pub(crate) fn open_top(path: &Path) -> Result<OpenedPath, OpenError> {
    open_at2(libc::AT_FDCWD, path, false, TOP_LEVEL_RESOLUTION)
}

pub(crate) fn open_top_directory(path: &Path) -> Result<OpenedPath, OpenError> {
    open_at2(libc::AT_FDCWD, path, true, TOP_LEVEL_RESOLUTION)
}

/// Open the parent of an explicitly authorized project root. Unlike a path
/// basename this also works for roots spelled `.` or `..`.
pub(crate) fn open_project_parent(directory: BorrowedFd<'_>) -> Result<OpenedPath, OpenError> {
    open_at2(
        directory.as_raw_fd(),
        Path::new(".."),
        true,
        TOP_LEVEL_RESOLUTION,
    )
}

pub(crate) fn open_beneath(
    directory: BorrowedFd<'_>,
    path: &Path,
    directory_only: bool,
) -> Result<OpenedPath, OpenError> {
    open_at2(
        directory.as_raw_fd(),
        path,
        directory_only,
        BENEATH_RESOLUTION,
    )
}

/// Traverse only the pinned filesystem; never cross even a same-device bind mount.
pub(crate) fn open_beneath_no_mounts(
    directory: BorrowedFd<'_>,
    path: &Path,
    directory_only: bool,
) -> Result<OpenedPath, OpenError> {
    open_at2(
        directory.as_raw_fd(),
        path,
        directory_only,
        BENEATH_RESOLUTION | libc::RESOLVE_NO_XDEV,
    )
}

#[derive(Debug)]
pub(crate) enum ReadDirectoryError<E> {
    Io(io::Error),
    Admission(E),
}

pub(crate) fn read_directory<E>(
    directory: &OpenedPath,
    mut admit: impl FnMut(&OsStr) -> Result<(), E>,
) -> Result<Vec<OsString>, ReadDirectoryError<E>> {
    // A duplicate shares the directory offset. Opening `.` creates an independent open-file
    // description, so concurrent and repeated enumeration always starts from a private offset.
    let fresh = open_beneath(directory.fd(), Path::new("."), true).map_err(|source| {
        ReadDirectoryError::Io(match source {
            OpenError::Unsupported(source) | OpenError::Other(source) => source,
            OpenError::Symlink => io::Error::other("directory became a symbolic link"),
        })
    })?;
    let fresh = fresh.fd;
    let raw_fd = fresh.as_raw_fd();
    // SAFETY: `raw_fd` is a valid directory descriptor. On success `fdopendir` takes ownership;
    // on failure `fresh` remains its sole owner and closes it on return.
    let raw_directory = unsafe { libc::fdopendir(raw_fd) };
    let Some(raw_directory) = NonNull::new(raw_directory) else {
        return Err(ReadDirectoryError::Io(io::Error::last_os_error()));
    };
    let _ = fresh.into_raw_fd();
    let stream = DirectoryStream(raw_directory);
    // SAFETY: `stream` owns a live `DIR`; rewinding gives each traversal a defined start offset.
    unsafe { libc::rewinddir(stream.0.as_ptr()) };
    let mut entries = Vec::new();
    loop {
        set_errno(0);
        // SAFETY: `stream` owns a live `DIR`; `readdir`'s result is used only until the next call.
        let entry = unsafe { libc::readdir(stream.0.as_ptr()) };
        if entry.is_null() {
            let error = errno();
            if error == 0 {
                break;
            }
            if error == libc::EINTR {
                continue;
            }
            return Err(ReadDirectoryError::Io(
                io::Error::from_raw_os_error(error),
            ));
        }
        // Linux directory records are variable-length, so only inspect the bytes covered by
        // `d_reclen` rather than forming a reference to libc's full `d_name` array.
        // SAFETY: a non-null `readdir` result points to a live record until the next call.
        let record_length = usize::from(unsafe { (*entry).d_reclen });
        let name_offset = mem::offset_of!(libc::dirent, d_name);
        let name_length = record_length
            .checked_sub(name_offset)
            .ok_or_else(|| {
                ReadDirectoryError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid directory record length",
                ))
            })?;
        // SAFETY: `d_reclen` bounds this record and `name_offset` was checked above.
        let name = unsafe {
            std::slice::from_raw_parts(
                std::ptr::addr_of!((*entry).d_name).cast::<u8>(),
                name_length,
            )
        };
        let nul = name
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| {
                ReadDirectoryError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unterminated directory entry",
                ))
            })?;
        let bytes = &name[..nul];
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        admit(OsStr::from_bytes(bytes)).map_err(ReadDirectoryError::Admission)?;
        entries.push(OsString::from_vec(bytes.to_vec()));
    }
    entries.sort();
    Ok(entries)
}

pub(crate) fn read_bounded_beneath(
    directory: BorrowedFd<'_>,
    path: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>, LockIoError> {
    let opened = match open_beneath(directory, path, false) {
        Ok(opened) => opened,
        Err(OpenError::Other(source)) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(OpenError::Symlink) => return Err(LockIoError::Symlink),
        Err(OpenError::Unsupported(source) | OpenError::Other(source)) => {
            return Err(LockIoError::Io(source));
        }
    };
    if opened.metadata.file_type != FileType::Regular {
        return Err(LockIoError::NonRegular);
    }
    if opened.metadata.links != 1 {
        return Err(LockIoError::HardLinked);
    }
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    opened
        .into_file()
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(LockIoError::Io)?;
    if bytes.len() > maximum {
        return Err(LockIoError::TooLarge);
    }
    Ok(Some(bytes))
}

pub(crate) fn ensure_directory_beneath(
    directory: BorrowedFd<'_>,
    name: &Path,
) -> Result<OpenedPath, DirectoryError> {
    ensure_directory_beneath_with_status(directory, name).map(|(opened, _created)| opened)
}

pub(crate) fn ensure_directory_beneath_with_status(
    directory: BorrowedFd<'_>,
    name: &Path,
) -> Result<(OpenedPath, bool), DirectoryError> {
    let name = c_name(name).map_err(DirectoryError::Io)?;
    let created = loop {
        // SAFETY: the directory descriptor and C string are live and the mode is valid.
        let result = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
        if result == 0 {
            break true;
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if source.kind() == io::ErrorKind::AlreadyExists {
            break false;
        }
        return Err(DirectoryError::Io(source));
    };
    let path = Path::new(OsStr::from_bytes(name.as_bytes()));
    let opened = open_beneath(directory, path, true).map_err(|source| match source {
        OpenError::Unsupported(source) | OpenError::Other(source) => DirectoryError::Io(source),
        OpenError::Symlink => DirectoryError::Symlink,
    })?;
    if !opened.metadata().is_trusted_directory() {
        return Err(DirectoryError::Untrusted);
    }
    sync_directory(directory).map_err(DirectoryError::Io)?;
    Ok((opened, created))
}

#[derive(Debug)]
pub(crate) enum DirectoryError {
    Symlink,
    Untrusted,
    Io(io::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublishStatus {
    Published,
    AlreadyExists,
}

#[derive(Debug)]
pub(crate) struct PublishError {
    pub(crate) source: io::Error,
    pub(crate) committed: bool,
}

#[derive(Debug)]
pub(crate) struct CreateAtomicError {
    pub(crate) source: io::Error,
    pub(crate) cleanup: Option<CleanupError>,
}

#[derive(Debug)]
pub(crate) enum CleanupError {
    Removal(io::Error),
    Synchronization(io::Error),
    RemovalAndSynchronization {
        removal: io::Error,
        synchronization: io::Error,
    },
}

#[derive(Debug)]
pub(crate) enum WriteAtomicError {
    BeforeRename {
        source: io::Error,
        cleanup: Option<CleanupError>,
    },
    AfterRename {
        source: io::Error,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AtomicFileState {
    Active,
    Removed,
    Published,
}

#[derive(Debug)]
pub(crate) struct AtomicFile {
    directory: OwnedFd,
    name: CString,
    identity: FileIdentity,
    file: File,
    state: AtomicFileState,
}

impl AtomicFile {
    pub(crate) fn directory(&self) -> BorrowedFd<'_> {
        self.directory.as_fd()
    }

    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        atomic_fault(AtomicFault::Write)?;
        self.file.write_all(bytes)
    }

    pub(crate) fn publish_noreplace(
        &mut self,
        destination: &Path,
    ) -> Result<PublishStatus, PublishError> {
        self.publish_noreplace_in(None, destination)
    }

    pub(crate) fn publish_noreplace_in(
        &mut self,
        target_directory: Option<BorrowedFd<'_>>,
        destination: &Path,
    ) -> Result<PublishStatus, PublishError> {
        let target = target_directory.unwrap_or(self.directory.as_fd());
        let before_commit = |source| PublishError {
            source,
            committed: false,
        };
        let destination = c_name(destination).map_err(before_commit)?;
        #[cfg(test)]
        atomic_fault(AtomicFault::FileSync).map_err(before_commit)?;
        self.file.sync_all().map_err(before_commit)?;
        let temporary_path = Path::new(OsStr::from_bytes(self.name.as_bytes()));
        #[cfg(test)]
        atomic_fault(AtomicFault::TemporaryReopen).map_err(before_commit)?;
        let reopened = reopen_publication_name(
            self.directory.as_fd(),
            temporary_path,
            self.identity,
        )
        .map_err(before_commit)?;
        #[cfg(test)]
        atomic_fault(AtomicFault::Rename).map_err(before_commit)?;
        let result = loop {
            // SAFETY: both names and the retained directory descriptor are live. The
            // syscall works with both glibc and musl; `RENAME_NOREPLACE` preserves
            // an existing content-addressed object atomically.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    self.directory.as_raw_fd(),
                    self.name.as_ptr(),
                    target.as_raw_fd(),
                    destination.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if result == 0 {
                break Ok(());
            }
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break Err(source);
        };
        if let Err(source) = result {
            if source.kind() == io::ErrorKind::AlreadyExists {
                drop(reopened);
                return Ok(PublishStatus::AlreadyExists);
            }
            return Err(before_commit(source));
        }
        self.state = AtomicFileState::Published;
        drop(reopened);
        let destination_path = Path::new(OsStr::from_bytes(destination.as_bytes()));
        let after_commit = |source| PublishError {
            source,
            committed: true,
        };
        #[cfg(test)]
        atomic_fault(AtomicFault::PublishedReopen).map_err(after_commit)?;
        let published = reopen_publication_name(target, destination_path, self.identity)
            .map_err(after_commit)?;
        #[cfg(test)]
        atomic_fault(AtomicFault::DirectorySync).map_err(after_commit)?;
        sync_directory(target).map_err(after_commit)?;
        if target_directory.is_some() {
            // A cross-directory rename is durable only after syncing both the
            // destination entry and removal of the recoverable temporary name.
            #[cfg(test)]
            atomic_fault(AtomicFault::SourceDirectorySync).map_err(after_commit)?;
            sync_directory(self.directory.as_fd()).map_err(after_commit)?;
        }
        drop(published);
        Ok(PublishStatus::Published)
    }

    pub(crate) fn discard(&mut self) -> Result<(), CleanupError> {
        if self.state == AtomicFileState::Published {
            return Err(CleanupError::Removal(io::Error::other(
                "published file cannot be discarded",
            )));
        }
        let removal = if self.state == AtomicFileState::Active {
            let path = Path::new(OsStr::from_bytes(self.name.as_bytes()));
            reopen_publication_name(self.directory.as_fd(), path, self.identity).and_then(
                |opened| {
                    #[cfg(test)]
                    atomic_fault(AtomicFault::CleanupUnlink)?;
                    retry_zero(|| {
                        // SAFETY: the name was revalidated against the retained created inode.
                        unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) }
                    })?;
                    self.state = AtomicFileState::Removed;
                    drop(opened);
                    Ok(())
                },
            )
        } else {
            Ok(())
        };
        let synchronization = {
            #[cfg(test)]
            {
                atomic_fault(AtomicFault::CleanupSync)
                    .and_then(|()| sync_directory(self.directory.as_fd()))
            }
            #[cfg(not(test))]
            sync_directory(self.directory.as_fd())
        };
        combine_cleanup(removal, synchronization)
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if self.state != AtomicFileState::Active {
            return;
        }
        let path = Path::new(OsStr::from_bytes(self.name.as_bytes()));
        let Ok(opened) = reopen_publication_name(self.directory.as_fd(), path, self.identity)
        else {
            return;
        };
        drop(opened);
        // SAFETY: the temporary name was revalidated against the retained created inode.
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
        }
    }
}

pub(crate) fn create_atomic_beneath(
    directory: BorrowedFd<'_>,
) -> Result<AtomicFile, CreateAtomicError> {
    create_atomic_beneath_with_prefix(directory, ".syrox-store.tmp.")
}

pub(crate) fn create_atomic_beneath_with_prefix(
    directory: BorrowedFd<'_>,
    prefix: &str,
) -> Result<AtomicFile, CreateAtomicError> {
    let without_cleanup = |source| CreateAtomicError {
        source,
        cleanup: None,
    };
    let directory = duplicate_cloexec(directory).map_err(without_cleanup)?;
    let mut last_collision = None;
    for _ in 0..64 {
        let name = random_temporary_name(prefix).map_err(without_cleanup)?;
        let raw_fd = loop {
            // SAFETY: the descriptor and C string are live; flags create a new regular file.
            let result = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if result >= 0 {
                break result;
            }
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if source.kind() == io::ErrorKind::AlreadyExists {
                last_collision = Some(source);
                break -1;
            }
            return Err(without_cleanup(source));
        };
        if raw_fd < 0 {
            continue;
        }
        // SAFETY: successful `openat` returned a new descriptor owned by this call.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let created = match metadata(fd.as_fd()) {
            Ok(created) => created,
            Err(source) => {
                let cleanup = unlink_name_synced(directory.as_fd(), &name).err();
                return Err(CreateAtomicError {
                    source,
                    cleanup,
                });
            }
        };
        if let Err(source) = require_publication_identity(created, created.identity) {
            let cleanup = unlink_name_synced(directory.as_fd(), &name).err();
            return Err(CreateAtomicError {
                source,
                cleanup,
            });
        }
        return Ok(AtomicFile {
            directory,
            name,
            identity: created.identity,
            file: File::from(fd),
            state: AtomicFileState::Active,
        });
    }
    Err(without_cleanup(last_collision.unwrap_or_else(
        || io::Error::other("temporary store name retries exhausted"),
    )))
}

pub(crate) fn write_atomic_beneath(
    directory: BorrowedFd<'_>,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), WriteAtomicError> {
    write_atomic_beneath_with_prefix(directory, destination, bytes, ".Syrox.lock.tmp.")
}

pub(crate) fn write_atomic_beneath_with_prefix(
    directory: BorrowedFd<'_>,
    destination: &Path,
    bytes: &[u8],
    prefix: &str,
) -> Result<(), WriteAtomicError> {
    let before_rename = |source| WriteAtomicError::BeforeRename {
        source,
        cleanup: None,
    };
    let destination = c_name(destination).map_err(before_rename)?;
    let mut last_collision = None;
    for _ in 0..64 {
        let temporary = random_temporary_name(prefix).map_err(before_rename)?;
        let raw_fd = loop {
            // SAFETY: both descriptors and C strings are live; flags create a new regular file.
            let result = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    temporary.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if result >= 0 {
                break result;
            }
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if source.kind() == io::ErrorKind::AlreadyExists {
                last_collision = Some(source);
                break -1;
            }
            return Err(before_rename(source));
        };
        if raw_fd < 0 {
            continue;
        }
        // SAFETY: successful `openat` returned a new descriptor owned by this call.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let created = match metadata(fd.as_fd()) {
            Ok(created) => created,
            Err(source) => {
                let cleanup = unlink_name_synced(directory, &temporary).err();
                return Err(WriteAtomicError::BeforeRename {
                    source,
                    cleanup,
                });
            }
        };
        let mut cleanup = TemporaryFile {
            directory,
            name: &temporary,
            identity: created.identity,
            state: TemporaryFileState::Active,
        };
        require_publication_identity(created, created.identity)
            .map_err(|source| cleanup.fail_before_rename(source))?;
        let mut file = File::from(fd);
        file.write_all(bytes)
            .map_err(|source| cleanup.fail_before_rename(source))?;
        file.sync_all()
            .map_err(|source| cleanup.fail_before_rename(source))?;
        let temporary_path = Path::new(OsStr::from_bytes(temporary.as_bytes()));
        let reopened = reopen_publication_name(directory, temporary_path, created.identity)
            .map_err(|source| cleanup.fail_before_rename(source))?;
        #[cfg(test)]
        if FAIL_NEXT_LOCK_BEFORE_RENAME.replace(false) {
            return Err(cleanup.fail_before_rename(io::Error::other(
                "injected lock failure before rename",
            )));
        }
        retry_zero(|| {
            // SAFETY: both names are valid and interpreted relative to the same live directory.
            unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    temporary.as_ptr(),
                    directory.as_raw_fd(),
                    destination.as_ptr(),
                )
            }
        })
        .map_err(|source| cleanup.fail_before_rename(source))?;
        cleanup.state = TemporaryFileState::Published;
        drop(reopened);
        #[cfg(test)]
        if FAIL_NEXT_LOCK_AFTER_RENAME.replace(false) {
            return Err(WriteAtomicError::AfterRename {
                source: io::Error::other("injected lock failure after rename"),
            });
        }
        let destination_path = Path::new(OsStr::from_bytes(destination.as_bytes()));
        let published = reopen_publication_name(directory, destination_path, created.identity)
            .map_err(|source| WriteAtomicError::AfterRename {
                source,
            })?;
        retry_zero(|| {
            // SAFETY: `directory` is a live descriptor and `fsync` takes no pointer arguments.
            unsafe { libc::fsync(directory.as_raw_fd()) }
        })
        .map_err(|source| WriteAtomicError::AfterRename {
            source,
        })?;
        drop(published);
        drop(file);
        return Ok(());
    }
    Err(before_rename(last_collision.unwrap_or_else(
        || io::Error::other("temporary lock name retries exhausted"),
    )))
}

#[cfg(test)]
pub(crate) fn fail_next_lock_before_rename() {
    FAIL_NEXT_LOCK_BEFORE_RENAME.set(true);
}

#[cfg(test)]
pub(crate) fn fail_next_lock_after_rename() {
    FAIL_NEXT_LOCK_AFTER_RENAME.set(true);
}

#[cfg(test)]
pub(crate) fn fail_next_lock_cleanup_sync() {
    FAIL_NEXT_LOCK_CLEANUP_SYNC.set(true);
}

fn random_temporary_name(prefix: &str) -> io::Result<CString> {
    let mut random = [0_u8; 16];
    let mut filled = 0;
    while filled < random.len() {
        // SAFETY: the syscall number is supplied by libc and the slice tail is valid writable
        // storage for the length passed. A zero result is rejected rather than weakening entropy.
        let result = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                random[filled..].as_mut_ptr(),
                random.len() - filled,
                0_u32,
            )
        };
        if result > 0 {
            let read = usize::try_from(result)
                .map_err(|_| io::Error::other("getrandom returned an invalid length"))?;
            filled = filled
                .checked_add(read)
                .filter(|filled| *filled <= random.len())
                .ok_or_else(|| io::Error::other("getrandom returned an invalid length"))?;
            continue;
        }
        if result == 0 {
            return Err(io::Error::other("getrandom returned no data"));
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::EINTR) {
            return Err(source);
        }
    }
    let mut name = String::with_capacity(prefix.len() + random.len() * 2);
    name.push_str(prefix);
    for byte in random {
        use std::fmt::Write as _;
        write!(name, "{byte:02x}").expect("writing to a String cannot fail");
    }
    CString::new(name).map_err(|_| io::Error::other("generated temporary name contains NUL"))
}

fn reopen_publication_name(
    directory: BorrowedFd<'_>,
    path: &Path,
    identity: FileIdentity,
) -> io::Result<OpenedPath> {
    let opened = open_beneath(directory, path, false).map_err(|source| match source {
        OpenError::Unsupported(source) | OpenError::Other(source) => source,
        OpenError::Symlink => io::Error::other("publication name resolves through a symlink"),
    })?;
    require_publication_identity(opened.metadata, identity)?;
    Ok(opened)
}

fn require_publication_identity(metadata: Metadata, identity: FileIdentity) -> io::Result<()> {
    if metadata.file_type != FileType::Regular
        || metadata.identity != identity
        || metadata.links != 1
    {
        return Err(io::Error::other(
            "publication file identity, type, or link count changed",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum LockIoError {
    Symlink,
    NonRegular,
    HardLinked,
    TooLarge,
    Io(io::Error),
}

fn open_at2(
    directory: libc::c_int,
    path: &Path,
    directory_only: bool,
    resolve: u64,
) -> Result<OpenedPath, OpenError> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        OpenError::Other(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL byte",
        ))
    })?;
    let mut flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;
    if directory_only {
        flags |= libc::O_DIRECTORY;
    }
    // SAFETY: all-zero is a valid initial `open_how`; every currently defined field is then set.
    let mut how: libc::open_how = unsafe { mem::zeroed() };
    how.flags = u64::try_from(flags).expect("Linux open flags are nonnegative");
    how.mode = 0;
    how.resolve = resolve;
    let raw_fd = loop {
        // SAFETY: the syscall number and `open_how` ABI come from libc, and both pointers remain
        // valid for the duration of the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                directory,
                path.as_ptr(),
                &raw const how,
                size_of::<libc::open_how>(),
            )
        };
        if result >= 0 {
            break libc::c_int::try_from(result).map_err(|_| {
                OpenError::Other(io::Error::other(
                    "openat2 returned a descriptor outside the supported range",
                ))
            })?;
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(classify_open_error(source));
    };
    // SAFETY: a nonnegative successful `openat2` result is a new descriptor owned by this call.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let metadata = metadata(fd.as_fd()).map_err(OpenError::Other)?;
    Ok(OpenedPath {
        fd,
        metadata,
    })
}

/// Inspect the filesystem backing an already pinned descriptor.
pub(crate) fn filesystem_type(fd: BorrowedFd<'_>) -> io::Result<u64> {
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    loop {
        // SAFETY: the borrowed fd is live and stat points to writable statfs storage.
        if unsafe { libc::fstatfs(fd.as_raw_fd(), stat.as_mut_ptr()) } == 0 {
            // SAFETY: successful fstatfs initialized the whole structure.
            let stat = unsafe { stat.assume_init() };
            return u64::try_from(stat.f_type)
                .map_err(|_| io::Error::other("negative filesystem type"));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(crate) fn metadata(fd: BorrowedFd<'_>) -> io::Result<Metadata> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    loop {
        // SAFETY: `fd` is live and `stat` points to writable storage of libc's declared type.
        let result = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
        if result == 0 {
            // SAFETY: successful `fstat` initialized the complete structure.
            let stat = unsafe { stat.assume_init() };
            let mode = stat.st_mode & libc::S_IFMT;
            let file_type = if mode == libc::S_IFDIR {
                FileType::Directory
            } else if mode == libc::S_IFREG {
                FileType::Regular
            } else {
                FileType::Other
            };
            return Ok(Metadata {
                file_type,
                identity: FileIdentity {
                    device: widen(stat.st_dev),
                    inode: widen(stat.st_ino),
                },
                rdev: widen(stat.st_rdev),
                links: widen(stat.st_nlink),
                owner: stat.st_uid,
                mode: stat.st_mode,
                size: u64::try_from(stat.st_size)
                    .map_err(|_| io::Error::other("file has a negative size"))?,
            });
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::EINTR) {
            return Err(source);
        }
    }
}

fn widen(value: impl Into<u64>) -> u64 {
    value.into()
}

fn duplicate_cloexec(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    loop {
        // SAFETY: `fd` is live; `F_DUPFD_CLOEXEC` takes one integer argument and returns a new fd.
        let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate >= 0 {
            // SAFETY: successful `F_DUPFD_CLOEXEC` returned a new descriptor owned by this call.
            return Ok(unsafe { OwnedFd::from_raw_fd(duplicate) });
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::EINTR) {
            return Err(source);
        }
    }
}

fn classify_open_error(source: io::Error) -> OpenError {
    match source.raw_os_error() {
        Some(libc::ENOSYS) => OpenError::Unsupported(source),
        Some(libc::ELOOP | libc::EXDEV) => OpenError::Symlink,
        _ => OpenError::Other(source),
    }
}

fn c_name(path: &Path) -> io::Result<CString> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not one safe component",
        ));
    }
    CString::new(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL byte",
        )
    })
}

fn retry_zero(mut operation: impl FnMut() -> libc::c_int) -> io::Result<()> {
    loop {
        if operation() == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::EINTR) {
            return Err(source);
        }
    }
}

pub(crate) fn sync_directory(directory: BorrowedFd<'_>) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_MAINTENANCE_SYNC.replace(false) {
        return Err(io::Error::other(
            "injected maintenance sync failure",
        ));
    }
    retry_zero(|| {
        // SAFETY: `directory` is a live descriptor and `fsync` takes no pointer arguments.
        unsafe { libc::fsync(directory.as_raw_fd()) }
    })
}

pub(crate) fn sync_file(file: BorrowedFd<'_>) -> io::Result<()> {
    retry_zero(|| {
        // SAFETY: `file` is a live descriptor and `fsync` takes no pointer arguments.
        unsafe { libc::fsync(file.as_raw_fd()) }
    })
}

pub(crate) fn initialize_regular(
    directory: BorrowedFd<'_>,
    name: &Path,
) -> Result<(OpenedPath, bool), io::Error> {
    let name = c_name(name)?;
    let raw_fd = loop {
        // SAFETY: the directory and C name are live; O_EXCL establishes one initializing inode.
        let result = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if result >= 0 {
            break Some(result);
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if source.kind() == io::ErrorKind::AlreadyExists {
            break None;
        }
        return Err(source);
    };
    let Some(raw_fd) = raw_fd else {
        return open_existing_regular(
            directory,
            Path::new(OsStr::from_bytes(name.as_bytes())),
        )
        .map(|opened| (opened, false));
    };
    // SAFETY: successful `openat` returned a new descriptor owned by this call.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let metadata = metadata(fd.as_fd())?;
    if !metadata.is_trusted_regular() {
        return Err(io::Error::other(
            "lease inode is not a trusted regular file",
        ));
    }
    Ok((
        OpenedPath {
            fd,
            metadata,
        },
        true,
    ))
}

pub(crate) fn open_existing_regular(
    directory: BorrowedFd<'_>,
    name: &Path,
) -> Result<OpenedPath, io::Error> {
    let opened = open_beneath(directory, name, false).map_err(|source| match source {
        OpenError::Unsupported(source) | OpenError::Other(source) => source,
        OpenError::Symlink => io::Error::other("regular file resolves through a symbolic link"),
    })?;
    if !opened.metadata.is_trusted_regular() {
        return Err(io::Error::other(
            "file is not a trusted regular file",
        ));
    }
    Ok(opened)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlockMode {
    Unlock,
    Shared,
    Exclusive,
    ExclusiveNonblocking,
}

pub(crate) fn flock(file: BorrowedFd<'_>, mode: FlockMode) -> io::Result<bool> {
    let operation = match mode {
        FlockMode::Unlock => libc::LOCK_UN,
        FlockMode::Shared => libc::LOCK_SH | libc::LOCK_NB,
        FlockMode::Exclusive => libc::LOCK_EX,
        FlockMode::ExclusiveNonblocking => libc::LOCK_EX | libc::LOCK_NB,
    };
    loop {
        // SAFETY: `file` is live and `operation` is one of flock's documented values.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(true);
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if source.raw_os_error() == Some(libc::EWOULDBLOCK)
            || source.raw_os_error() == Some(libc::EAGAIN)
        {
            return Ok(false);
        }
        return Err(source);
    }
}

pub(crate) fn unlink_opened(
    directory: BorrowedFd<'_>,
    name: &Path,
    expected: FileIdentity,
) -> io::Result<()> {
    let name = c_name(name)?;
    let opened = reopen_publication_name(
        directory,
        Path::new(OsStr::from_bytes(name.as_bytes())),
        expected,
    )?;
    #[cfg(test)]
    if FAIL_NEXT_MAINTENANCE_UNLINK.replace(false) {
        return Err(io::Error::other(
            "injected maintenance unlink failure",
        ));
    }
    retry_zero(|| {
        // SAFETY: the name was revalidated against the retained expected inode.
        unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) }
    })?;
    drop(opened);
    Ok(())
}

/// A random component with 128 bits of entropy, for engine-owned operation names.
pub(crate) fn operation_name() -> io::Result<String> {
    random_temporary_name("op-")?
        .into_string()
        .map_err(|_| io::Error::other("invalid operation name"))
}

pub(crate) fn rename_directory(
    parent: BorrowedFd<'_>,
    from: &Path,
    to: &Path,
    expected: FileIdentity,
) -> io::Result<()> {
    require_directory_identity(parent, from, expected)?;
    let from = c_name(from)?;
    let to = c_name(to)?;
    retry_zero(|| {
        // SAFETY: both single-component C names and the parent descriptor are
        // live. NOREPLACE never overwrites another operation. Call the kernel
        // directly so this boundary does not require a libc renameat2 symbol.
        let renamed = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if renamed == 0 {
            0
        } else {
            -1
        }
    })?;
    sync_directory(parent)
}

pub(crate) fn remove_directory(
    parent: BorrowedFd<'_>,
    name: &Path,
    expected: FileIdentity,
) -> io::Result<()> {
    require_directory_identity(parent, name, expected)?;
    let name = c_name(name)?;
    retry_zero(|| {
        // SAFETY: the validated name belongs to parent; AT_REMOVEDIR removes
        // only an empty directory and never traverses a tree or symbolic link.
        unsafe {
            libc::unlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        }
    })?;
    sync_directory(parent)
}

fn require_directory_identity(
    parent: BorrowedFd<'_>,
    name: &Path,
    expected: FileIdentity,
) -> io::Result<()> {
    let opened = open_beneath(parent, name, true)
        .map_err(|error| io::Error::other(format!("directory reopen failed: {error:?}")))?;
    if !opened.metadata().is_trusted_directory() || opened.metadata().identity() != expected {
        return Err(io::Error::other("directory identity changed"));
    }
    Ok(())
}

/// Resolve only for trusted external-program arguments, then verify the path
/// still names our descriptor. All engine I/O remains descriptor-relative.
pub(crate) fn directory_path(directory: &OpenedPath) -> io::Result<std::path::PathBuf> {
    let path = std::fs::read_link(format!(
        "/proc/self/fd/{}",
        directory.fd().as_raw_fd()
    ))?;
    let reopened = open_top_directory(&path)
        .map_err(|error| io::Error::other(format!("directory path unavailable: {error:?}")))?;
    if reopened.metadata().identity() != directory.metadata().identity() {
        return Err(io::Error::other("directory path changed"));
    }
    Ok(path)
}

#[cfg(test)]
pub(crate) fn fail_next_atomic(point: AtomicFault) {
    FAIL_NEXT_ATOMIC.set(FAIL_NEXT_ATOMIC.get() | (1_u16 << point as u8));
}

#[cfg(test)]
pub(crate) fn fail_next_maintenance_unlink() {
    FAIL_NEXT_MAINTENANCE_UNLINK.set(true);
}

#[cfg(test)]
pub(crate) fn fail_next_maintenance_sync() {
    FAIL_NEXT_MAINTENANCE_SYNC.set(true);
}

fn unlink_name_synced(directory: BorrowedFd<'_>, name: &CString) -> Result<(), CleanupError> {
    let removal = retry_zero(|| {
        // SAFETY: the descriptor and O_EXCL-created C name remain live for this call.
        unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) }
    });
    let synchronization = sync_directory(directory);
    combine_cleanup(removal, synchronization)
}

fn combine_cleanup(
    removal: io::Result<()>,
    synchronization: io::Result<()>,
) -> Result<(), CleanupError> {
    match (removal, synchronization) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(source), Ok(())) => Err(CleanupError::Removal(source)),
        (Ok(()), Err(source)) => Err(CleanupError::Synchronization(source)),
        (Err(removal), Err(synchronization)) => Err(CleanupError::RemovalAndSynchronization {
            removal,
            synchronization,
        }),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TemporaryFileState {
    Active,
    Removed,
    Published,
}

struct TemporaryFile<'a> {
    directory: BorrowedFd<'a>,
    name: &'a CString,
    identity: FileIdentity,
    state: TemporaryFileState,
}

impl TemporaryFile<'_> {
    fn fail_before_rename(&mut self, source: io::Error) -> WriteAtomicError {
        WriteAtomicError::BeforeRename {
            source,
            cleanup: self.discard().err(),
        }
    }

    fn discard(&mut self) -> Result<(), CleanupError> {
        let removal = if self.state == TemporaryFileState::Active {
            let path = Path::new(OsStr::from_bytes(self.name.as_bytes()));
            reopen_publication_name(self.directory, path, self.identity).and_then(|opened| {
                retry_zero(|| {
                    // SAFETY: the name was revalidated against the retained created inode.
                    unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) }
                })?;
                self.state = TemporaryFileState::Removed;
                drop(opened);
                Ok(())
            })
        } else {
            Ok(())
        };
        let synchronization = {
            #[cfg(test)]
            if FAIL_NEXT_LOCK_CLEANUP_SYNC.replace(false) {
                Err(io::Error::other(
                    "injected lock cleanup sync failure",
                ))
            } else {
                sync_directory(self.directory)
            }
            #[cfg(not(test))]
            sync_directory(self.directory)
        };
        combine_cleanup(removal, synchronization)
    }
}

impl Drop for TemporaryFile<'_> {
    fn drop(&mut self) {
        if self.state != TemporaryFileState::Active {
            return;
        }
        let path = Path::new(OsStr::from_bytes(self.name.as_bytes()));
        let Ok(opened) = reopen_publication_name(self.directory, path, self.identity) else {
            return;
        };
        drop(opened);
        // The identity was checked immediately before this call. The project directory must not
        // be concurrently mutated by an adversary; if it was already replaced, cleanup abstains.
        // SAFETY: the C name and directory descriptor remain live for this guard's lifetime.
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
        }
    }
}

fn errno() -> libc::c_int {
    // SAFETY: libc exposes thread-local errno through this pointer on Linux.
    unsafe { *libc::__errno_location() }
}

fn set_errno(value: libc::c_int) {
    // SAFETY: libc exposes thread-local errno through this pointer on Linux.
    unsafe { *libc::__errno_location() = value };
}

struct DirectoryStream(NonNull<libc::DIR>);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this wrapper is the sole owner after `fdopendir`; `Drop` runs exactly once.
        unsafe {
            libc::closedir(self.0.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(std::path::PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "syrox-linux-fd-test-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn directory_stream_uses_a_fresh_description_and_keeps_the_opened_fd_owned() {
        let temp = TempDirectory::new();
        fs::write(temp.0.join("source.srx"), "value V(str);").unwrap();
        let directory = open_top(&temp.0).unwrap();

        assert_eq!(
            read_directory(&directory, |_| Ok::<(), ()>(())).unwrap(),
            ["source.srx"]
        );
        assert!(open_beneath(directory.fd(), Path::new("source.srx"), false).is_ok());
    }

    #[test]
    fn beneath_open_refuses_symlinks() {
        let temp = TempDirectory::new();
        fs::write(temp.0.join("target.srx"), "value V(str);").unwrap();
        symlink("target.srx", temp.0.join("link.srx")).unwrap();
        let directory = open_top(&temp.0).unwrap();

        assert!(matches!(
            open_beneath(directory.fd(), Path::new("link.srx"), false),
            Err(OpenError::Symlink)
        ));
    }

    #[test]
    fn directory_entries_are_sorted_and_dot_entries_are_hidden() {
        let temp = TempDirectory::new();
        fs::write(temp.0.join("z"), "z").unwrap();
        fs::write(temp.0.join("a"), "a").unwrap();

        let entries = read_directory(&open_top(&temp.0).unwrap(), |_| Ok::<(), ()>(())).unwrap();
        assert_eq!(entries, ["a", "z"]);
    }

    #[test]
    fn directory_admission_rejection_stops_record_processing() {
        let temp = TempDirectory::new();
        fs::write(temp.0.join("first"), "first").unwrap();
        fs::write(temp.0.join("second"), "second").unwrap();
        fs::write(temp.0.join("third"), "third").unwrap();
        let mut callbacks = 0;

        let error = read_directory(&open_top(&temp.0).unwrap(), |_| {
            callbacks += 1;
            if callbacks > 1 {
                Err("limit")
            } else {
                Ok(())
            }
        })
        .unwrap_err();

        assert!(matches!(
            error,
            ReadDirectoryError::Admission("limit")
        ));
        assert_eq!(callbacks, 2);
    }

    #[test]
    fn metadata_preserves_hardlink_identity() {
        let temp = TempDirectory::new();
        fs::write(temp.0.join("first"), "content").unwrap();
        fs::hard_link(temp.0.join("first"), temp.0.join("second")).unwrap();
        let directory = open_top(&temp.0).unwrap();
        let first = open_beneath(directory.fd(), Path::new("first"), false).unwrap();
        let second = open_beneath(directory.fd(), Path::new("second"), false).unwrap();

        assert_eq!(
            first.metadata().identity(),
            second.metadata().identity()
        );
    }

    #[test]
    fn opened_descriptor_converts_to_a_readable_file() {
        let temp = TempDirectory::new();
        fs::write(temp.0.join("source.srx"), "descriptor text").unwrap();
        let directory = open_top(&temp.0).unwrap();
        let opened = open_beneath(directory.fd(), Path::new("source.srx"), false).unwrap();
        let mut text = String::new();

        opened
            .into_file()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "descriptor text");
    }

    #[test]
    fn paths_with_nul_bytes_are_rejected_before_the_syscall() {
        let path = std::path::PathBuf::from(OsString::from_vec(b"bad\0path".to_vec()));
        let Err(OpenError::Other(error)) = open_top(&path) else {
            panic!("expected invalid path error");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn random_temporary_names_are_well_formed_and_distinct() {
        let first = random_temporary_name(".Syrox.lock.tmp.").unwrap();
        let second = random_temporary_name(".Syrox.lock.tmp.").unwrap();
        assert_ne!(first, second);
        assert!(first.as_bytes().starts_with(b".Syrox.lock.tmp."));
        assert_eq!(
            first.as_bytes().len(),
            b".Syrox.lock.tmp.".len() + 32
        );
    }

    #[test]
    fn atomic_publication_replaces_with_one_regular_created_inode() {
        let temp = TempDirectory::new();
        let directory = open_top(&temp.0).unwrap();
        write_atomic_beneath(directory.fd(), Path::new("Syrox.lock"), b"first").unwrap();
        write_atomic_beneath(directory.fd(), Path::new("Syrox.lock"), b"second").unwrap();

        let published = open_beneath(directory.fd(), Path::new("Syrox.lock"), false).unwrap();
        assert_eq!(published.metadata.file_type, FileType::Regular);
        assert_eq!(published.metadata.links, 1);
        let mut contents = String::new();
        published
            .into_file()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "second");
        assert_eq!(
            read_directory(&directory, |_| Ok::<(), ()>(())).unwrap(),
            ["Syrox.lock"]
        );
    }

    #[test]
    fn cleanup_retains_simultaneous_removal_and_sync_failures() {
        let error = combine_cleanup(
            Err(io::Error::other("remove failed")),
            Err(io::Error::other("sync failed")),
        )
        .unwrap_err();
        let CleanupError::RemovalAndSynchronization {
            removal,
            synchronization,
        } = error
        else {
            panic!("expected both cleanup failures");
        };
        assert_eq!(removal.to_string(), "remove failed");
        assert_eq!(synchronization.to_string(), "sync failed");
    }
}

pub(crate) mod persisted_namespace;

/// Linux libc bindings expose statfs magic as either signed or unsigned words.
/// Reject out-of-range words instead of truncating them into an expected magic.
pub(crate) fn filesystem_magic_matches(actual: impl TryInto<i64>, expected: i64) -> bool {
    actual.try_into().ok() == Some(expected)
}

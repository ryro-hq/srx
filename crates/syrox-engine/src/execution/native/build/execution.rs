use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Command, Stdio};

use super::super::{checked, process, signals::SignalFd};
use super::{BuildCapture, NamespaceLayout};

pub(super) struct Writers {
    pub artifacts: File,
    pub logs: File,
}
pub(super) fn pipes() -> io::Result<(BuildCapture, Writers)> {
    // No channel may accidentally become a standard descriptor.
    for descriptor in 0..3 {
        // SAFETY: queries only the dedicated process's fixed stdio numbers.
        checked(unsafe { libc::fcntl(descriptor, libc::F_GETFD) }.into())?;
    }
    let (artifacts, artifact_writer) = pipe()?;
    let (logs, log_writer) = pipe()?;
    Ok((
        BuildCapture::from_received(artifacts.into(), logs.into())?,
        Writers {
            artifacts: artifact_writer,
            logs: log_writer,
        },
    ))
}
pub(super) fn validate_capture(
    artifacts: BorrowedFd<'_>,
    logs: BorrowedFd<'_>,
) -> io::Result<[crate::platform::linux::fd::FileIdentity; 2]> {
    let mut identities = Vec::with_capacity(2);
    for descriptor in [artifacts, logs] {
        let metadata = crate::platform::linux::fd::metadata(descriptor)?;
        let flags = crate::platform::linux::fd::status_flags(descriptor)?;
        // SAFETY: fcntl only queries a live borrowed descriptor.
        let fd_flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
        if fd_flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if crate::platform::linux::fd::filesystem_type(descriptor)? != 0x5049_5045
            || metadata.mode() & libc::S_IFMT != libc::S_IFIFO
            || flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & libc::O_NONBLOCK == 0
            || flags & !(libc::O_NONBLOCK | libc::O_LARGEFILE) != 0
            || fd_flags & libc::FD_CLOEXEC == 0
        {
            return Err(io::Error::other(
                "expected nonblocking readonly anonymous capture pipe",
            ));
        }
        identities.push(metadata.identity());
    }
    if identities[0] == identities[1] {
        return Err(io::Error::other("build capture channels alias"));
    }
    Ok([identities[0], identities[1]])
}

fn pipe() -> io::Result<(File, File)> {
    let mut descriptors = [-1; 2];
    // SAFETY: two writable descriptor slots; successful pipe2 transfers ownership.
    checked(unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) }.into())?;
    // SAFETY: both successful descriptors are new and uniquely owned.
    let (reader, writer) = unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        )
    };
    crate::platform::linux::fd::set_nonblocking(reader.as_fd())?;
    Ok((reader, writer))
}

pub(super) fn null_stdio(null: BorrowedFd<'_>) -> io::Result<()> {
    for target in 0..3 {
        // SAFETY: pinned null is a live fd >=3; this is namespace init only.
        checked(unsafe { libc::dup2(null.as_raw_fd(), target) }.into())?;
    }
    Ok(())
}

pub(super) fn execute(
    layout: &NamespaceLayout,
    signals: &SignalFd,
    mut acknowledged: UnixStream,
    writers: Writers,
) -> io::Result<i32> {
    let mut command = Command::new("/syrox-worker");
    command
        .args([
            "__build-managed-worker",
            &layout.source_directory,
            &layout.action.to_string(),
        ])
        .env_clear()
        .current_dir("/work")
        .stdin(Stdio::from(
            super::super::environment::open_null()?
        ))
        .stdout(Stdio::from(writers.artifacts))
        .stderr(Stdio::from(writers.logs));
    let original = signals.original();
    // SAFETY: only the dedicated payload fork child changes group and signal
    // mask; the callback does not allocate, access Rust locks or perform I/O.
    unsafe {
        command.pre_exec(move || {
            checked(libc::setpgid(0, 0).into())?;
            super::super::signals::payload_mask(original)
        });
    }
    let payload = command.spawn()?;
    // Command still owns parent-side Stdio originals after spawn. Closing them
    // now makes EOF depend only on payload descendants, not namespace init.
    drop(command);
    acknowledged.write_all(b"e")?;
    drop(acknowledged);
    let status = process::wait_payload_managed(payload, signals)?;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    #[test]
    fn capture_channels_are_separate_nonblocking_and_end_with_the_last_writer() {
        let (mut capture, mut writers) = pipes().unwrap();
        for file in [
            &capture.artifacts,
            &capture.logs,
            &writers.artifacts,
            &writers.logs,
        ] {
            assert!(file.as_raw_fd() >= 3);
            // SAFETY: fcntl queries only an owned live test descriptor.
            assert_ne!(
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
        writers.artifacts.write_all(b"artifact").unwrap();
        writers.logs.write_all(b"log").unwrap();
        let mut bytes = [0; 8];
        assert_eq!(capture.artifacts.read(&mut bytes).unwrap(), 8);
        assert_eq!(&bytes, b"artifact");
        assert_eq!(capture.logs.read(&mut bytes).unwrap(), 3);
        assert_eq!(&bytes[..3], b"log");
        assert_eq!(
            capture
                .artifacts
                .read(&mut bytes)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let inherited_writer = writers.artifacts.try_clone().unwrap();
        drop(writers);
        assert_eq!(capture.logs.read(&mut bytes).unwrap(), 0);
        assert_eq!(
            capture
                .artifacts
                .read(&mut bytes)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(inherited_writer);
        assert_eq!(capture.artifacts.read(&mut bytes).unwrap(), 0);
    }

    #[test]
    fn received_capture_rejects_regular_writable_and_aliased_descriptors() {
        let (capture, writers) = pipes().unwrap();
        capture.revalidate().unwrap();
        assert!(
            BuildCapture::from_received(
                capture.artifacts.try_clone().unwrap().into(),
                capture.artifacts.try_clone().unwrap().into()
            )
            .is_err()
        );
        assert!(
            BuildCapture::from_received(
                writers.artifacts.into(),
                capture.logs.try_clone().unwrap().into()
            )
            .is_err()
        );
        assert!(
            BuildCapture::from_received(
                tempfile::tempfile().unwrap().into(),
                capture.logs.try_clone().unwrap().into()
            )
            .is_err()
        );
        let received =
            BuildCapture::from_received(capture.artifacts.into(), capture.logs.into()).unwrap();
        received.revalidate().unwrap();
    }

    #[test]
    fn capture_revalidation_rejects_changed_open_file_description_flags() {
        let (capture, _writers) = pipes().unwrap();
        // SAFETY: only this test's pipe open file description changes flags.
        assert_eq!(
            unsafe { libc::fcntl(capture.artifacts.as_raw_fd(), libc::F_SETFL, 0) },
            0
        );
        assert!(capture.revalidate().is_err());
        // No F_SETOWN is installed, so this cannot send SIGIO to another process.
        // SAFETY: flags change only this test's read pipe description.
        assert_eq!(
            unsafe {
                libc::fcntl(
                    capture.artifacts.as_raw_fd(),
                    libc::F_SETFL,
                    libc::O_NONBLOCK | libc::O_ASYNC,
                )
            },
            0
        );
        assert!(capture.revalidate().is_err());
    }

    #[test]
    fn named_fifo_and_path_only_descriptors_are_not_capture_channels() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("named-fifo");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: NUL-terminated path is private to this test; no payload executes.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let (capture, _writers) = pipes().unwrap();
        let fifo = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .unwrap();
        assert!(
            BuildCapture::from_received(
                fifo.into(),
                capture.logs.try_clone().unwrap().into()
            )
            .is_err()
        );
        let path_only = crate::platform::linux::fd::open_path(&path).unwrap();
        assert!(BuildCapture::from_received(path_only.into(), capture.logs.into()).is_err());
    }
}

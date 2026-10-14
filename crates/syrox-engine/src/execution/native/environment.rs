use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::os::unix::fs::{
    FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::Path;

pub(super) fn open_null() -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/null")?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_char_device()
        || libc::major(metadata.rdev()) != 1
        || libc::minor(metadata.rdev()) != 3
    {
        return Err(io::Error::other("expected the Linux null device"));
    }
    Ok(file)
}

/// Pin the kernel controlling-terminal device without opening its current
/// session. `O_PATH` works even when the launcher itself has no controlling tty.
pub(super) fn open_controlling_tty() -> io::Result<File> {
    let file = crate::platform::linux::fd::open_path(Path::new("/dev/tty"))?;
    validate_controlling_tty(&file)?;
    Ok(file)
}

fn validate_controlling_tty(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_char_device()
        || libc::major(metadata.rdev()) != 5
        || libc::minor(metadata.rdev()) != 0
    {
        return Err(io::Error::other(
            "expected the kernel controlling-terminal device",
        ));
    }
    Ok(())
}

pub(super) fn validate_uid(uid: u32) -> io::Result<()> {
    if uid == 0 {
        return Err(io::Error::other(
            "managed user services require a nonzero caller UID",
        ));
    }
    Ok(())
}

pub(super) fn validate_cwd(cwd: &Path) -> io::Result<()> {
    if !crate::execution::resources::valid_managed_working_directory(cwd) {
        return Err(io::Error::other(
            "working directory overlaps a managed runtime filesystem",
        ));
    }
    Ok(())
}

pub(super) fn validate_request(request: &super::WorkerRequest) -> io::Result<()> {
    validate_cwd(&request.cwd)?;
    let working = request
        .mounts
        .iter()
        .find(|mount| mount.kind == super::MountKind::Working)
        .ok_or_else(|| io::Error::other("managed request has no working descriptor"))?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&working.source)?;
    crate::execution::resources::validate_managed_working_descriptor(directory.as_fd())
}

pub(super) fn mount(root: &Path, null: BorrowedFd<'_>, tty: Option<&File>) -> io::Result<()> {
    let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    let temporary = root.join("tmp");
    std::fs::create_dir(&temporary)?;
    super::mount(
        Some(Path::new("tmpfs")),
        &temporary,
        Some(c"tmpfs"),
        flags,
    )?;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o700))?;
    let proc = root.join("proc");
    std::fs::create_dir(&proc)?;
    // Called by namespace PID 1: this proc instance cannot name host processes.
    super::mount(
        Some(Path::new("proc")),
        &proc,
        Some(c"proc"),
        flags | libc::MS_RDONLY,
    )?;
    let devices = root.join("dev");
    std::fs::create_dir(&devices)?;
    bind_device(
        &devices.join("null"),
        Path::new("/dev/null"),
        null,
    )?;
    if let Some(tty) = tty {
        validate_controlling_tty(tty)?;
        bind_device(
            &devices.join("tty"),
            Path::new("/dev/tty"),
            tty.as_fd(),
        )?;
    }
    for (name, number) in [
        ("stdin", 0),
        ("stdout", 1),
        ("stderr", 2),
    ] {
        std::os::unix::fs::symlink(
            format!("/proc/self/fd/{number}"),
            devices.join(name),
        )?;
    }
    Ok(())
}

fn reopen_pinned_device(path: &Path, descriptor: BorrowedFd<'_>) -> io::Result<File> {
    // The inherited f_path belongs to the monitor's previous mount namespace.
    // Reopen only the caller's known device path in this namespace, without
    // opening a terminal session or trusting a substituted node.
    let original = File::from(descriptor.try_clone_to_owned()?).metadata()?;
    let local = crate::platform::linux::fd::open_path(path)?;
    let actual = local.metadata()?;
    if !original.file_type().is_char_device()
        || !actual.file_type().is_char_device()
        || (original.dev(), original.ino(), original.rdev())
            != (actual.dev(), actual.ino(), actual.rdev())
    {
        return Err(io::Error::other(
            "runtime device identity or type changed",
        ));
    }
    Ok(local)
}

pub(super) fn bind_device(
    target: &Path,
    path: &Path,
    descriptor: BorrowedFd<'_>,
) -> io::Result<()> {
    let local = reopen_pinned_device(path, descriptor)?;
    File::create(target)?;
    let source = format!("/proc/self/fd/{}", local.as_raw_fd());
    super::mount(
        Some(Path::new(&source)),
        target,
        None,
        libc::MS_BIND,
    )?;
    // Add restrictions without clearing inherited (possibly locked) readonly,
    // nodev or atime attributes on the source mount.
    let target = super::text(target)?;
    let attributes = libc::mount_attr {
        attr_set: libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NOEXEC,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: target and attributes are live; modify only this private bind.
    super::checked(unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            target.as_ptr(),
            0_u32,
            &raw const attributes,
            size_of_val(&attributes),
        )
    })
    .map_err(|error| {
        io::Error::other(format!(
            "runtime device mount attributes: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_identity_and_filesystems_have_explicit_boundaries() {
        assert!(validate_uid(0).is_err());
        assert!(validate_uid(1000).is_ok());
        for path in [
            "/",
            "/tmp",
            "/proc",
            "/proc/self",
            "/dev",
            "/dev/shm/project",
            "/sys",
            "/sys/fs/cgroup",
        ] {
            assert!(validate_cwd(Path::new(path)).is_err());
        }
        for path in [
            "/tmp/project/work",
            "/home/user/project",
            "/device",
            "/process",
        ] {
            assert!(validate_cwd(Path::new(path)).is_ok());
        }
    }
    #[test]
    fn controlling_device_is_pinned_without_opening_ambient_terminal() {
        let tty = open_controlling_tty().unwrap();
        validate_controlling_tty(&tty).unwrap();
        assert_ne!(
            crate::platform::linux::fd::status_flags(tty.as_fd()).unwrap() & libc::O_PATH,
            0
        );
        assert!(validate_controlling_tty(&open_null().unwrap()).is_err());
        let temporary = tempfile::tempfile().unwrap();
        assert!(validate_controlling_tty(&temporary).is_err());
    }

    #[test]
    fn reopened_devices_keep_pinned_identity_and_do_not_open_terminal_sessions() {
        for (path, original) in [
            (Path::new("/dev/null"), open_null().unwrap()),
            (
                Path::new("/dev/tty"),
                open_controlling_tty().unwrap(),
            ),
        ] {
            let reopened = reopen_pinned_device(path, original.as_fd()).unwrap();
            let expected = original.metadata().unwrap();
            let actual = reopened.metadata().unwrap();
            assert_eq!(
                (expected.dev(), expected.ino(), expected.rdev()),
                (actual.dev(), actual.ino(), actual.rdev())
            );
            assert_ne!(
                crate::platform::linux::fd::status_flags(reopened.as_fd()).unwrap() & libc::O_PATH,
                0
            );
        }
    }

    #[test]
    fn device_reopen_refuses_substitution_regular_files_and_links() {
        let null = open_null().unwrap();
        assert!(reopen_pinned_device(Path::new("/dev/tty"), null.as_fd()).is_err());
        let directory = tempfile::tempdir().unwrap();
        let regular = directory.path().join("file");
        std::fs::write(&regular, b"not a device").unwrap();
        assert!(reopen_pinned_device(&regular, null.as_fd()).is_err());
        let link = directory.path().join("link");
        std::os::unix::fs::symlink("/dev/null", &link).unwrap();
        assert!(reopen_pinned_device(&link, null.as_fd()).is_err());
        assert!(
            reopen_pinned_device(
                Path::new("/dev/null"),
                File::open(&regular).unwrap().as_fd()
            )
            .is_err()
        );
    }
}

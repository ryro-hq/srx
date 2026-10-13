use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use crate::execution::configuration::MountKind;
use crate::execution::native::{bind_tree, mount};
use crate::platform::linux::fd::{self as linux_fd, FileIdentity};

pub(in crate::execution::native) struct CommandsMount {
    directory: OwnedFd,
    socket: OwnedFd,
    directory_identity: FileIdentity,
    socket_identity: FileIdentity,
}

impl CommandsMount {
    /// Inputs must come from the private authenticated monitor bootstrap, never
    /// from proxy request descriptors. `socket` is an `O_PATH` filesystem node,
    /// not the listening socket's anonymous descriptor.
    pub(in crate::execution::native) fn new(
        directory: OwnedFd,
        socket: OwnedFd,
    ) -> io::Result<Self> {
        validate_directory(&directory)?;
        validate_socket(&socket)?;
        Ok(Self {
            directory_identity: linux_fd::metadata(directory.as_fd())?.identity(),
            socket_identity: linux_fd::metadata(socket.as_fd())?.identity(),
            directory,
            socket,
        })
    }

    /// Call only in the new private mount namespace, before `pivot_root` and before
    /// any payload executes. The host inventory's placeholder remains untouched.
    pub(in crate::execution::native) fn attach(&self, root: &Path) -> io::Result<()> {
        self.revalidate()?;
        let destination = root.join("syrox/commands");
        fs::create_dir_all(destination.parent().ok_or_else(invalid)?)?;
        fs::create_dir(&destination)?;
        // Working selects the existing helper's nonrecursive, descriptor-pinned
        // open_tree path. Its mount flags are set explicitly below, not inherited
        // from the writable working-directory policy.
        bind_tree(
            &anchor(&self.directory),
            &destination,
            MountKind::Working,
            true,
        )?;
        let socket_target = destination.join("broker.sock");
        // Reopen the socket node in this mount namespace. A spelling is only a
        // locator: the reopened descriptor must match the admitted inode.
        let socket_path = fs::read_link(anchor(&self.socket))?;
        if !socket_path.is_absolute() {
            return Err(invalid());
        }
        let local_socket: OwnedFd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(socket_path)?
            .into();
        validate_socket(&local_socket)?;
        if linux_fd::metadata(local_socket.as_fd())?.identity() != self.socket_identity {
            return Err(invalid());
        }
        mount(
            Some(&anchor(&local_socket)),
            &socket_target,
            None,
            libc::MS_BIND,
        )?;
        let readonly =
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
        mount(
            None,
            &socket_target,
            None,
            readonly | libc::MS_NOEXEC,
        )?;
        // The worker and wrappers must remain executable; noexec applies only to
        // the separately mounted socket node, configuration and secret resources.
        mount(None, &destination, None, readonly)?;
        let mounted = linux_fd::open_top_directory(&destination).map_err(|_| invalid())?;
        if mounted.metadata().identity() != self.directory_identity {
            return Err(invalid());
        }
        let mounted_socket: OwnedFd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(socket_target)?
            .into();
        if linux_fd::metadata(mounted_socket.as_fd())?.identity() != self.socket_identity {
            return Err(invalid());
        }
        self.revalidate()
    }

    fn revalidate(&self) -> io::Result<()> {
        validate_directory(&self.directory)?;
        validate_socket(&self.socket)?;
        if linux_fd::metadata(self.directory.as_fd())?.identity() != self.directory_identity
            || linux_fd::metadata(self.socket.as_fd())?.identity() != self.socket_identity
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn validate_directory(directory: &OwnedFd) -> io::Result<()> {
    let metadata = linux_fd::metadata(directory.as_fd())?;
    if !metadata.is_trusted_directory() || metadata.mode() & 0o7777 != 0o500 {
        return Err(invalid());
    }
    let placeholder =
        linux_fd::open_beneath_no_mounts(directory.as_fd(), Path::new("broker.sock"), false)
            .map_err(|_| invalid())?;
    let metadata = placeholder.metadata();
    if !metadata.is_trusted_regular() || metadata.mode() & 0o7777 != 0o400 || metadata.size() != 0 {
        return Err(invalid());
    }
    Ok(())
}

fn validate_socket(socket: &OwnedFd) -> io::Result<()> {
    let metadata = File::from(socket.try_clone()?).metadata()?;
    // SAFETY: fcntl reads flags on a live owned descriptor; geteuid has no pointers.
    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_PATH == 0
        || metadata.mode() & libc::S_IFMT != libc::S_IFSOCK
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(invalid());
    }
    Ok(())
}

fn anchor(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}
fn invalid() -> io::Error {
    io::Error::other("invalid admitted command mount")
}

#[cfg(test)]
mod tests {
    //! Admission tests only. No test in this module performs mount or unshare.
    use super::{CommandsMount, validate_directory, validate_socket};
    use std::fs::{self, File, OpenOptions};
    use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};

    struct Fixture {
        root: tempfile::TempDir,
        directory: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let directory = root.path().join("commands");
            fs::create_dir(&directory).unwrap();
            fs::write(directory.join("broker.sock"), b"").unwrap();
            fs::set_permissions(
                directory.join("broker.sock"),
                fs::Permissions::from_mode(0o400),
            )
            .unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
            Self {
                root,
                directory,
            }
        }
        fn descriptor(&self) -> OwnedFd {
            File::open(&self.directory).unwrap().into()
        }
        fn socket(&self) -> (UnixListener, PathBuf, OwnedFd) {
            let path = self.root.path().join("listener.sock");
            let listener = UnixListener::bind(&path)
                .expect("real filesystem listener bind (IPC permission required)");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let descriptor = node(&path);
            (listener, path, descriptor)
        }
        fn writable(&self) {
            fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.writable();
        }
    }
    fn node(path: &Path) -> OwnedFd {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .unwrap()
            .into()
    }

    #[test]
    fn directory_requires_private_readonly_mode_and_empty_single_link_placeholder() {
        let fixture = Fixture::new();
        validate_directory(&fixture.descriptor()).unwrap();
        fixture.writable();
        assert!(validate_directory(&fixture.descriptor()).is_err());
        fs::set_permissions(
            &fixture.directory,
            fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        let placeholder = fixture.directory.join("broker.sock");
        fs::set_permissions(&placeholder, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_directory(&fixture.descriptor()).is_err());
        fs::write(&placeholder, b"not empty").unwrap();
        fs::set_permissions(&placeholder, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(validate_directory(&fixture.descriptor()).is_err());
        fs::set_permissions(&placeholder, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&placeholder, b"").unwrap();
        fs::set_permissions(&placeholder, fs::Permissions::from_mode(0o400)).unwrap();
        fs::hard_link(&placeholder, fixture.root.path().join("alias")).unwrap();
        assert!(validate_directory(&fixture.descriptor()).is_err());
    }

    #[test]
    fn missing_directory_or_symlink_placeholder_and_wrong_socket_fd_are_rejected() {
        let fixture = Fixture::new();
        let placeholder = fixture.directory.join("broker.sock");
        let regular: OwnedFd = File::open(&placeholder).unwrap().into();
        assert!(validate_directory(&regular).is_err());
        assert!(validate_socket(&regular).is_err());
        assert!(CommandsMount::new(fixture.descriptor(), node(&placeholder)).is_err());
        fixture.writable();
        fs::remove_file(&placeholder).unwrap();
        fs::set_permissions(
            &fixture.directory,
            fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        assert!(validate_directory(&fixture.descriptor()).is_err());
        fixture.writable();
        let other = fixture.root.path().join("other");
        fs::write(&other, b"").unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o400)).unwrap();
        symlink(&other, &placeholder).unwrap();
        fs::set_permissions(
            &fixture.directory,
            fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        assert!(validate_directory(&fixture.descriptor()).is_err());
    }

    #[test]
    fn accepts_pinned_filesystem_socket_but_not_the_listening_descriptor() {
        let fixture = Fixture::new();
        let (listener, _path, descriptor) = fixture.socket();
        assert!(
            CommandsMount::new(
                fixture.descriptor(),
                listener.as_fd().try_clone_to_owned().unwrap()
            )
            .is_err()
        );
        let directory = fixture.descriptor();
        let expected = [
            directory.as_raw_fd(),
            descriptor.as_raw_fd(),
        ];
        let mount = CommandsMount::new(directory, descriptor).unwrap();
        assert_eq!(
            [
                mount.directory.as_raw_fd(),
                mount.socket.as_raw_fd()
            ],
            expected
        );
        mount.revalidate().unwrap();
    }

    #[test]
    fn socket_mode_or_link_count_changes_refuse_revalidation() {
        let fixture = Fixture::new();
        let (_listener, path, descriptor) = fixture.socket();
        let mount = CommandsMount::new(fixture.descriptor(), descriptor).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        assert!(mount.revalidate().is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        mount.revalidate().unwrap();
        fs::hard_link(&path, fixture.root.path().join("socket-alias")).unwrap();
        assert!(mount.revalidate().is_err());
    }

    #[test]
    fn admitted_directory_tamper_is_rejected_without_mounting() {
        let fixture = Fixture::new();
        let (_listener, _path, descriptor) = fixture.socket();
        let mount = CommandsMount::new(fixture.descriptor(), descriptor).unwrap();
        let placeholder = fixture.directory.join("broker.sock");
        fs::set_permissions(&placeholder, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&placeholder, b"changed after admission").unwrap();
        fs::set_permissions(&placeholder, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(mount.revalidate().is_err());
    }
}

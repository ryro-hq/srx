use std::ffi::OsString;
use std::io::{self, Read as _};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use super::ProxyContext;
use super::context::MAX_CONTEXT_BYTES;
use super::request::{
    AdmittedProxyRequest, MAX_ARGUMENT_BYTES, MAX_ARGUMENT_TOTAL_BYTES, MAX_ARGUMENTS,
    ProxyRequest, alias_from_wrapper,
};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd};

/// The payload's actual termination kind, after namespace and terminal cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellCommandExit {
    Exited(u8),
    Signaled(i32),
}

/// Runs an authenticated public command wrapper without resolving host tools.
///
/// # Safety
/// Call only in a dedicated single-threaded worker which exits after return.
/// This operation forks and changes process signal and job-control state.
#[allow(unsafe_code)]
pub unsafe fn run_shell_command(
    args: &[OsString],
    cancel: &Cancellation,
) -> io::Result<ShellCommandExit> {
    let input = io::stdin();
    let output = io::stdout();
    let error = io::stderr();
    let prepared = PreparedProxyFrontend::prepare(
        args,
        [
            input.as_fd(),
            output.as_fd(),
            error.as_fd(),
        ],
        cancel,
    )?;
    // SAFETY: the caller provides the dedicated worker/fork boundary.
    let outcome = unsafe { super::guardian::process::run(prepared, cancel)? };
    Ok(match outcome {
        super::wire::CommandProxyExit::Exited(code) => ShellCommandExit::Exited(code),
        super::wire::CommandProxyExit::Signaled(signal) => ShellCommandExit::Signaled(signal),
    })
}

pub(crate) struct PreparedProxyFrontend {
    context: ProxyContext,
    request: AdmittedProxyRequest,
    authorized_cwd: linux_fd::OpenedPath,
}
impl PreparedProxyFrontend {
    /// `args[0]` is the kernel-supplied wrapper path; subsequent bytes are data.
    pub(crate) fn prepare(
        args: &[OsString],
        stdio: [BorrowedFd<'_>; 3],
        cancel: &Cancellation,
    ) -> io::Result<Self> {
        check(cancel)?;
        validate_arguments(args)?;
        let directory =
            linux_fd::open_top_directory(Path::new("/syrox/commands")).map_err(|_| invalid())?;
        let context = read_context(&directory, cancel)?;
        Self::prepare_in(
            context,
            args,
            stdio,
            &std::env::current_dir()?,
            cancel,
        )
    }

    fn prepare_in(
        context: ProxyContext,
        args: &[OsString],
        stdio: [BorrowedFd<'_>; 3],
        cwd: &Path,
        cancel: &Cancellation,
    ) -> io::Result<Self> {
        check(cancel)?;
        validate_arguments(args)?;
        let authorized_cwd =
            linux_fd::open_top_directory(context.working_directory()).map_err(|_| invalid())?;
        let actual_cwd = linux_fd::open_top_directory(cwd).map_err(|_| invalid())?;
        let visible_root = linux_fd::directory_path(&authorized_cwd)?;
        let visible_cwd = linux_fd::directory_path(&actual_cwd)?;
        if visible_root != context.working_directory() || visible_cwd != cwd {
            return Err(invalid());
        }
        let relative = relative_cwd(&visible_root, &visible_cwd)?;
        let request = ProxyRequest::new(
            alias_from_wrapper(&args[0])?,
            args[1..].to_vec(),
            relative,
        )?;
        let mut descriptors = vec![actual_cwd.fd().try_clone_to_owned()?];
        for fd in stdio {
            descriptors.push(fd.try_clone_to_owned()?);
        }
        let request =
            AdmittedProxyRequest::validate(request, descriptors, authorized_cwd.fd(), cancel)?;
        Ok(Self {
            context,
            request,
            authorized_cwd,
        })
    }

    pub(crate) fn revalidate(&self, cancel: &Cancellation) -> io::Result<()> {
        check(cancel)?;
        if linux_fd::directory_path(&self.authorized_cwd)? != self.context.working_directory() {
            return Err(invalid());
        }
        self.request
            .revalidate(self.authorized_cwd.fd(), cancel)
    }
    pub(crate) fn context(&self) -> &ProxyContext {
        &self.context
    }
    pub(crate) fn prepare_guardian_io(
        &self,
        cancel: &Cancellation,
    ) -> io::Result<super::guardian::GuardianIo> {
        self.revalidate(cancel)?;
        let prepared = super::guardian::GuardianIo::prepare(&self.request)?;
        check(cancel)?;
        Ok(prepared)
    }
    pub(crate) fn request(&self) -> &AdmittedProxyRequest {
        &self.request
    }
}

fn validate_arguments(args: &[OsString]) -> io::Result<()> {
    let Some((wrapper, arguments)) = args.split_first() else {
        return Err(invalid());
    };
    alias_from_wrapper(wrapper)?;
    if arguments.len() > MAX_ARGUMENTS {
        return Err(invalid());
    }
    let mut total = 0_usize;
    for argument in arguments {
        let bytes = argument.as_bytes();
        total = total
            .checked_add(bytes.len())
            .ok_or_else(invalid)?;
        if bytes.len() > MAX_ARGUMENT_BYTES
            || total > MAX_ARGUMENT_TOTAL_BYTES
            || bytes.contains(&0)
        {
            return Err(invalid());
        }
    }
    Ok(())
}
fn relative_cwd(root: &Path, current: &Path) -> io::Result<PathBuf> {
    let relative = current
        .strip_prefix(root)
        .map_err(|_| invalid())?;
    Ok(if relative.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        relative.to_path_buf()
    })
}
fn read_context(
    directory: &linux_fd::OpenedPath,
    cancel: &Cancellation,
) -> io::Result<ProxyContext> {
    check(cancel)?;
    let opened = linux_fd::open_beneath(directory.fd(), Path::new("context"), false)
        .map_err(|_| invalid())?;
    let before = linux_fd::metadata(opened.fd())?;
    if before.file_type() != linux_fd::FileType::Regular
        || before.mode() & 0o7777 != 0o400
        || before.size() > MAX_CONTEXT_BYTES as u64
    {
        return Err(invalid());
    }
    let mut file = opened.into_file();
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_CONTEXT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    check(cancel)?;
    let current = linux_fd::open_beneath(directory.fd(), Path::new("context"), false)
        .map_err(|_| invalid())?;
    if bytes.len() as u64 != before.size()
        || linux_fd::metadata(file.as_fd())? != before
        || current.metadata().identity() != before.identity()
    {
        return Err(invalid());
    }
    ProxyContext::decode(&bytes)
}
fn check(cancel: &Cancellation) -> io::Result<()> {
    cancel
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())
}
fn invalid() -> io::Error {
    io::Error::other("invalid public command frontend")
}

#[cfg(test)]
mod tests {
    use super::{PreparedProxyFrontend, read_context, relative_cwd, validate_arguments};
    use crate::execution::journal::SessionId;
    use crate::runtime::command_proxy::ProxyContext;
    use crate::{
        cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest,
    };
    use std::ffi::OsString;
    use std::fs::{self, OpenOptions};
    use std::os::fd::AsFd as _;
    use std::os::unix::{ffi::OsStringExt as _, fs::PermissionsExt as _};
    use std::path::Path;

    fn context(path: &Path) -> ProxyContext {
        ProxyContext::new(
            &SessionId::parse(&"1".repeat(32)).unwrap(),
            ContentDigest::sha256(b"index"),
            linux_fd::FileIdentity {
                device: 1,
                inode: 2,
            },
            path,
        )
        .unwrap()
    }
    #[test]
    fn wrapper_arguments_are_literal_bounded_and_never_modes() {
        assert!(validate_arguments(&[]).is_err());
        assert!(validate_arguments(&["tool".into()]).is_err());
        let mut args = vec![OsString::from(
            "/syrox/commands/bin/tool",
        )];
        args.extend([
            OsString::from("--worker"),
            OsString::from("$(host)"),
            OsString::from_vec(vec![255]),
        ]);
        validate_arguments(&args).unwrap();
        args.push("x".repeat(4097).into());
        assert!(validate_arguments(&args).is_err());
        let args = std::iter::once(OsString::from("/syrox/commands/bin/tool"))
            .chain(std::iter::repeat_n(OsString::new(), 257))
            .collect::<Vec<_>>();
        assert!(validate_arguments(&args).is_err());
    }
    #[test]
    fn relative_working_directory_never_adopts_private_or_external_roots() {
        let root = Path::new("/workspace/project");
        assert_eq!(relative_cwd(root, root).unwrap(), Path::new("."));
        assert_eq!(
            relative_cwd(root, &root.join("sub")).unwrap(),
            Path::new("sub")
        );
        for cwd in [
            "/workspace/project-other",
            "/tmp",
            "/syrox/secrets/service",
            "/",
        ] {
            assert!(relative_cwd(root, Path::new(cwd)).is_err());
        }
    }
    #[test]
    fn observed_cwd_and_io_are_pinned_without_connecting_or_mutating_terminal() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("sub");
        fs::create_dir(&child).unwrap();
        let null = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        let args = [
            "/syrox/commands/bin/tool".into(),
            "--literal".into(),
        ];
        let cancel = Cancellation::default();
        let prepared = PreparedProxyFrontend::prepare_in(
            context(root.path()),
            &args,
            [null.as_fd(); 3],
            &child,
            &cancel,
        )
        .unwrap();
        assert_eq!(
            prepared.request().request().cwd(),
            Path::new("sub")
        );
        assert_eq!(
            prepared.context().working_directory(),
            root.path()
        );
        prepared.revalidate(&cancel).unwrap();
        let (custody, relay) = prepared
            .prepare_guardian_io(&cancel)
            .unwrap()
            .into_parts();
        assert!(custody.is_none() && relay.is_none());
        fs::rename(&child, root.path().join("old")).unwrap();
        fs::create_dir(&child).unwrap();
        assert!(prepared.revalidate(&cancel).is_err());
        cancel.cancel();
        assert!(crate::cancellation::is_cancellation_io(
            &PreparedProxyFrontend::prepare(&args, [null.as_fd(); 3], &cancel)
                .err()
                .unwrap()
        ));
    }
    #[test]
    fn context_reader_requires_bounded_readonly_canonical_regular_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("context");
        let bytes = context(Path::new("/workspace/project"))
            .canonical_bytes()
            .unwrap();
        fs::write(&path, &bytes).unwrap();
        let directory = linux_fd::open_top_directory(root.path()).unwrap();
        let cancel = Cancellation::default();
        assert!(read_context(&directory, &cancel).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            read_context(&directory, &cancel)
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            bytes
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, vec![b' '; 8193]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_context(&directory, &cancel).is_err());
    }
}

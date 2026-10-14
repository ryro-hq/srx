use super::{OwnershipError, SessionId, record};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd};
use std::io::Read as _;
use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(super) struct Storage {
    path: PathBuf,
    directory: linux_fd::OpenedPath,
    authority: linux_fd::FileIdentity,
    uncertain: AtomicBool,
}
#[derive(Debug)]
pub(super) struct Authority(linux_fd::OpenedPath);

impl Storage {
    #[cfg(test)]
    pub(super) fn mark_uncertain_for_test(&self) {
        self.uncertain.store(true, Ordering::Release);
    }
    pub fn open(path: &Path) -> Result<Self, OwnershipError> {
        Self::open_mode(path, true)
    }
    pub fn open_existing(path: &Path) -> Result<Self, OwnershipError> {
        Self::open_mode(path, false)
    }
    fn open_mode(path: &Path, initialize: bool) -> Result<Self, OwnershipError> {
        let path = std::path::absolute(path)?;
        let directory = linux_fd::open_top_directory(&path).map_err(open_error)?;
        private_directory(&directory)?;
        let (authority, created) = if initialize {
            linux_fd::initialize_regular(directory.fd(), Path::new("authority.lock"))?
        } else {
            (
                linux_fd::open_existing_regular(directory.fd(), Path::new("authority.lock"))?,
                false,
            )
        };
        private_file(&authority)?;
        if created {
            linux_fd::sync_file(authority.fd())?;
            linux_fd::sync_directory(directory.fd())?;
        }
        Ok(Self {
            path,
            directory,
            authority: authority.metadata().identity(),
            uncertain: AtomicBool::new(false),
        })
    }
    pub fn lock(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Authority, OwnershipError> {
        if self.uncertain.load(Ordering::Acquire) {
            return Err(OwnershipError::Uncertain(
                "reopen and reconcile after ambiguous publication",
            ));
        }
        let lock =
            linux_fd::open_existing_regular(self.directory.fd(), Path::new("authority.lock"))?;
        private_file(&lock)?;
        if lock.metadata().identity() != self.authority {
            return Err(OwnershipError::Invalid(
                "installation authority inode changed",
            ));
        }
        loop {
            check(cancellation, deadline)?;
            if linux_fd::flock(
                lock.fd(),
                linux_fd::FlockMode::ExclusiveNonblocking,
            )? {
                break;
            }
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(10)),
            );
        }
        let authority = Authority(lock);
        let current =
            linux_fd::open_existing_regular(self.directory.fd(), Path::new("authority.lock"))?;
        let directory = linux_fd::open_top_directory(&self.path).map_err(open_error)?;
        private_directory(&directory)?;
        if current.metadata().identity() != self.authority
            || directory.metadata().identity() != self.directory.metadata().identity()
        {
            return Err(OwnershipError::Invalid(
                "installation authority changed while locking",
            ));
        }
        check(cancellation, deadline)?;
        if self.uncertain.load(Ordering::Acquire) {
            return Err(OwnershipError::Uncertain(
                "reopen and reconcile after ambiguous publication",
            ));
        }
        Ok(authority)
    }
    pub fn ids(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Vec<SessionId>, OwnershipError> {
        let mut count = 0;
        let names = linux_fd::read_directory(&self.directory, |name| {
            check(cancellation, deadline)?;
            if name == "authority.lock" {
                return Ok(());
            }
            count += 1;
            if count > super::MAX_SESSIONS {
                return Err(OwnershipError::Invalid(
                    "session registry capacity exceeded",
                ));
            }
            SessionId::parse(
                name.to_str()
                    .ok_or(OwnershipError::Invalid("non-UTF8 session entry"))?,
            )?;
            Ok(())
        })
        .map_err(|error| match error {
            linux_fd::ReadDirectoryError::Io(error) => OwnershipError::Io(error),
            linux_fd::ReadDirectoryError::Admission(error) => error,
        })?;
        names
            .into_iter()
            .filter(|name| name != "authority.lock")
            .map(|name| {
                SessionId::parse(
                    name.to_str()
                        .ok_or(OwnershipError::Invalid("non-UTF8 session entry"))?,
                )
            })
            .collect()
    }
    pub fn create_directory(
        &self,
        id: &SessionId,
    ) -> Result<Option<linux_fd::OpenedPath>, OwnershipError> {
        let (opened, created) = linux_fd::ensure_directory_beneath_with_status(
            self.directory.fd(),
            Path::new(id.as_str()),
        )
        .map_err(directory_error)?;
        private_directory(&opened)?;
        Ok(created.then_some(opened))
    }
    pub fn directory(&self, id: &SessionId) -> Result<linux_fd::OpenedPath, OwnershipError> {
        let opened = linux_fd::open_beneath(self.directory.fd(), Path::new(id.as_str()), true)
            .map_err(open_error)?;
        private_directory(&opened)?;
        Ok(opened)
    }
    pub fn read(dir: BorrowedFd<'_>, name: &str) -> Result<Vec<u8>, OwnershipError> {
        let limit = file_limit(name)?;
        let file = linux_fd::open_existing_regular(dir, Path::new(name))?;
        private_file(&file)?;
        if file.metadata().size() > limit as u64 {
            return Err(OwnershipError::Invalid("session file too large"));
        }
        let mut bytes = Vec::new();
        file.into_file()
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(OwnershipError::Invalid(
                "session file grew beyond bound",
            ));
        }
        Ok(bytes)
    }
    pub fn write(
        &self,
        dir: BorrowedFd<'_>,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), OwnershipError> {
        if bytes.len() > file_limit(name)? {
            return Err(OwnershipError::Invalid("session file too large"));
        }
        match linux_fd::write_atomic_beneath_with_prefix(
            dir,
            Path::new(name),
            bytes,
            ".syrox-session.tmp.",
        ) {
            Ok(()) => Ok(()),
            Err(linux_fd::WriteAtomicError::BeforeRename {
                source,
                cleanup,
            }) => {
                if cleanup.is_some() {
                    self.uncertain.store(true, Ordering::Release);
                    return Err(OwnershipError::Uncertain(
                        "temporary cleanup failed before publication",
                    ));
                }
                Err(OwnershipError::Io(source))
            }
            Err(linux_fd::WriteAtomicError::AfterRename {
                ..
            }) => {
                self.uncertain.store(true, Ordering::Release);
                Err(OwnershipError::Uncertain(
                    "publication happened but its durability is unknown",
                ))
            }
        }
    }
}
fn file_limit(name: &str) -> Result<usize, OwnershipError> {
    match name {
        "manifest" => Ok(super::MAX_SESSION_MANIFEST_BYTES),
        "state" => Ok(record::MAX_BYTES),
        _ => Err(OwnershipError::Invalid(
            "unknown session file role",
        )),
    }
}

impl Drop for Authority {
    fn drop(&mut self) {
        let _ = linux_fd::flock(self.0.fd(), linux_fd::FlockMode::Unlock);
    }
}
pub(super) fn check(cancellation: &Cancellation, deadline: Instant) -> Result<(), OwnershipError> {
    if cancellation.is_cancelled() {
        Err(OwnershipError::Cancelled)
    } else if Instant::now() >= deadline {
        Err(OwnershipError::Deadline)
    } else {
        Ok(())
    }
}
fn private_directory(opened: &linux_fd::OpenedPath) -> Result<(), OwnershipError> {
    if !opened.metadata().is_trusted_directory() || opened.metadata().mode() & 0o777 != 0o700 {
        Err(OwnershipError::Invalid(
            "session directory must be owned and mode 0700",
        ))
    } else {
        Ok(())
    }
}
fn private_file(opened: &linux_fd::OpenedPath) -> Result<(), OwnershipError> {
    if !opened.metadata().is_trusted_regular() || opened.metadata().mode() & 0o777 != 0o600 {
        Err(OwnershipError::Invalid(
            "session file must be owned, single-linked and mode 0600",
        ))
    } else {
        Ok(())
    }
}
fn open_error(error: linux_fd::OpenError) -> OwnershipError {
    match error {
        linux_fd::OpenError::Other(error) | linux_fd::OpenError::Unsupported(error) => {
            OwnershipError::Io(error)
        }
        linux_fd::OpenError::Symlink => {
            OwnershipError::Invalid("session path traverses a symbolic link")
        }
    }
}
fn directory_error(error: linux_fd::DirectoryError) -> OwnershipError {
    match error {
        linux_fd::DirectoryError::Io(error) => OwnershipError::Io(error),
        _ => OwnershipError::Invalid("session directory is untrusted"),
    }
}

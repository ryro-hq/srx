use super::{InstallationError, MAX_CANDIDATES, Result, check};
use crate::platform::linux::fd::{self as linux_fd, FileIdentity, FlockMode, OpenedPath};
use crate::{cancellation::Cancellation, store::ContentDigest};
use std::io::{self, Read as _};
use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const ID_HEADER: &str = "syrox-os-installation-v1\n";
#[cfg(test)]
thread_local! {
    static WAIT_SIGNAL: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn signal_lock_wait(sender: std::sync::mpsc::Sender<()>) {
    WAIT_SIGNAL.with(|signal| *signal.borrow_mut() = Some(sender));
}
#[cfg(test)]
thread_local! {
    static ABSENCE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn before_absence_readback(action: Box<dyn FnOnce()>) {
    ABSENCE_HOOK.with(|hook| *hook.borrow_mut() = Some(action));
}
#[derive(Debug)]
pub(in crate::deployment::os) struct Storage {
    path: PathBuf,
    root: OpenedPath,
    generations: OpenedPath,
    authority: FileIdentity,
    execution: OpenedPath,
    uncertain: AtomicBool,
}
#[derive(Debug)]
pub(in crate::deployment::os) struct Authority(OpenedPath);
impl Drop for Authority {
    fn drop(&mut self) {
        let _ = linux_fd::flock(self.0.fd(), FlockMode::Unlock);
    }
}
impl Storage {
    pub(super) fn validate_path(&self, path: &Path) -> Result<()> {
        let selected = linux_fd::open_top_directory(path).map_err(open_error)?;
        if selected.metadata().identity() != self.root.metadata().identity()
            || linux_fd::directory_path(&self.root)? != path
        {
            return Err(InstallationError::Invalid(
                "installation path differs from pinned authority",
            ));
        }
        Ok(())
    }
    pub(in crate::deployment::os) fn open(path: &Path, initialize: bool) -> Result<Self> {
        let path = std::path::absolute(path)?;
        let root = linux_fd::open_top_directory(&path).map_err(open_error)?;
        private_directory(&root)?;
        let create = initialize && read_optional(root.fd(), "installation", 128)?.is_none();
        let lock = if create {
            let (lock, created) =
                linux_fd::initialize_regular(root.fd(), Path::new("authority.lock"))?;
            if created {
                linux_fd::sync_file(lock.fd())?;
                linux_fd::sync_directory(root.fd())?;
            }
            lock
        } else {
            linux_fd::open_existing_regular(root.fd(), Path::new("authority.lock"))?
        };
        private_file(&lock)?;
        // Once the installation identity exists, a missing execution lock is
        // lost authority, never an invitation to create a different inode.
        let execution = if create {
            let (file, created) =
                linux_fd::initialize_regular(root.fd(), Path::new("execution.lock"))?;
            if created {
                linux_fd::sync_file(file.fd())?;
                linux_fd::sync_directory(root.fd())?;
            }
            file
        } else {
            linux_fd::open_existing_regular(root.fd(), Path::new("execution.lock"))?
        };
        private_file(&execution)?;
        let generations = if create {
            linux_fd::ensure_directory_beneath(root.fd(), Path::new("generations"))
                .map_err(|_| InstallationError::Invalid("cannot initialize generation directory"))?
        } else {
            linux_fd::open_beneath(root.fd(), Path::new("generations"), true).map_err(open_error)?
        };
        private_directory(&generations)?;
        if create {
            linux_fd::sync_directory(generations.fd())?;
            linux_fd::sync_directory(root.fd())?;
        }
        Ok(Self {
            path,
            root,
            generations,
            authority: lock.metadata().identity(),
            execution,
            uncertain: AtomicBool::new(false),
        })
    }
    pub(in crate::deployment::os) fn lock(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Authority> {
        self.lock_file(
            "authority.lock",
            self.authority,
            cancellation,
            deadline,
        )
    }
    pub(in crate::deployment::os) fn execution(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Authority> {
        self.lock_file(
            "execution.lock",
            self.execution.metadata().identity(),
            cancellation,
            deadline,
        )
    }
    fn lock_file(
        &self,
        name: &str,
        identity: FileIdentity,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Authority> {
        let file = linux_fd::open_existing_regular(self.root.fd(), Path::new(name))?;
        private_file(&file)?;
        if file.metadata().identity() != identity {
            return Err(InstallationError::Invalid(
                "installation lock changed",
            ));
        }
        loop {
            check(cancellation, deadline)?;
            if self.uncertain.load(Ordering::Acquire) {
                return Err(InstallationError::Uncertain(
                    "reopen after ambiguous publication",
                ));
            }
            if linux_fd::flock(file.fd(), FlockMode::ExclusiveNonblocking)? {
                break;
            }
            #[cfg(test)]
            WAIT_SIGNAL.with(|signal| {
                if let Some(sender) = signal.borrow_mut().take() {
                    let _ = sender.send(());
                }
            });
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(10)),
            );
        }
        let guard = Authority(file);
        let current = linux_fd::open_top_directory(&self.path).map_err(open_error)?;
        let lock = linux_fd::open_existing_regular(self.root.fd(), Path::new(name))?;
        let authority =
            linux_fd::open_existing_regular(self.root.fd(), Path::new("authority.lock"))?;
        let generations = linux_fd::open_beneath(self.root.fd(), Path::new("generations"), true)
            .map_err(open_error)?;
        if current.metadata().identity() != self.root.metadata().identity()
            || lock.metadata().identity() != identity
            || authority.metadata().identity() != self.authority
            || linux_fd::directory_path(&self.root)? != self.path
            || generations.metadata().identity() != self.generations.metadata().identity()
        {
            return Err(InstallationError::Invalid(
                "installation directory or lock was replaced",
            ));
        }
        private_directory(&current)?;
        private_directory(&generations)?;
        private_file(&lock)?;
        private_file(&authority)?;
        check(cancellation, deadline)?;
        if self.uncertain.load(Ordering::Acquire) {
            return Err(InstallationError::Uncertain(
                "reopen after ambiguous publication",
            ));
        }
        Ok(guard)
    }
    pub(in crate::deployment::os) fn installation_id(&self, initialize: bool) -> Result<String> {
        let bytes = match read_optional(self.root.fd(), "installation", 128)? {
            Some(bytes) => bytes,
            None if initialize => {
                if !self.ids()?.is_empty()
                    || self.read_activation()?.is_some()
                    || self.has_launch_evidence()?
                {
                    return Err(InstallationError::Invalid(
                        "installation identity missing while candidate evidence exists",
                    ));
                }
                let mut id = None;
                for _ in 0..64 {
                    let random = linux_fd::operation_name()?;
                    let text = random
                        .strip_prefix("op-")
                        .ok_or(InstallationError::Invalid(
                            "invalid random installation identity",
                        ))?;
                    if text.bytes().any(|byte| byte != b'0') {
                        id = Some(text.to_owned());
                        break;
                    }
                }
                let id = id.ok_or(InstallationError::Invalid(
                    "installation entropy retries exhausted",
                ))?;
                let bytes = format!("{ID_HEADER}{id}\n").into_bytes();
                self.write(self.root.fd(), "installation", &bytes)?;
                bytes
            }
            None => {
                return Err(InstallationError::Invalid(
                    "installation identity is absent",
                ));
            }
        };
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| InstallationError::Invalid("invalid installation identity encoding"))?;
        let id = text
            .strip_prefix(ID_HEADER)
            .and_then(|text| text.strip_suffix('\n'))
            .ok_or(InstallationError::Invalid(
                "unsupported installation identity",
            ))?;
        if id.len() != 32
            || id.bytes().all(|byte| byte == b'0')
            || id
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(InstallationError::Invalid(
                "invalid installation identity",
            ));
        }
        Ok(id.into())
    }
    pub(in crate::deployment::os) fn read_activation(&self) -> Result<Option<Vec<u8>>> {
        read_optional(
            self.root.fd(),
            "activation",
            crate::deployment::os::activation::MAX_STATE_BYTES,
        )
    }
    pub(in crate::deployment::os) fn write_activation(&self, bytes: &[u8]) -> Result<()> {
        self.write(self.root.fd(), "activation", bytes)
    }
    pub(super) fn mark_uncertain(&self) -> InstallationError {
        self.uncertain.store(true, Ordering::Release);
        InstallationError::Uncertain("installation publication durability is unknown")
    }
    pub(super) fn read_launch(&self, pin: ContentDigest) -> Result<Option<Vec<u8>>> {
        read_optional(
            self.root.fd(),
            &format!("launch-{pin}"),
            crate::deployment::os::launch_binding::MAX_LAUNCH_BINDING_BYTES,
        )
    }
    pub(super) fn observe_launch(
        &self,
        pin: ContentDigest,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>> {
        check(cancellation, deadline)?;
        let name = format!("launch-{pin}");
        let file = match linux_fd::open_existing_regular(self.root.fd(), Path::new(&name)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.confirm_launch_absence(&name, cancellation, deadline)?;
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let bytes = read_launch_file(&file)?;
        if ContentDigest::sha256(&bytes) != pin {
            return Err(InstallationError::Invalid(
                "launch binding content pin differs",
            ));
        }
        check(cancellation, deadline)?;
        linux_fd::sync_file(file.fd()).map_err(|_| self.mark_uncertain())?;
        linux_fd::sync_directory(self.root.fd()).map_err(|_| self.mark_uncertain())?;
        check(cancellation, deadline)?;
        let current = linux_fd::open_top_directory(&self.path).map_err(open_error)?;
        let observed = linux_fd::open_existing_regular(self.root.fd(), Path::new(&name))?;
        private_directory(&current)?;
        if current.metadata().identity() != self.root.metadata().identity()
            || linux_fd::directory_path(&self.root)? != self.path
            || observed.metadata().identity() != file.metadata().identity()
            || read_launch_file(&observed)? != bytes
        {
            return Err(InstallationError::Invalid(
                "launch binding changed during observation",
            ));
        }
        check(cancellation, deadline)?;
        Ok(Some(bytes))
    }
    fn confirm_launch_absence(
        &self,
        name: &str,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        check(cancellation, deadline)?;
        linux_fd::sync_directory(self.root.fd()).map_err(|_| self.mark_uncertain())?;
        #[cfg(test)]
        ABSENCE_HOOK.with(|hook| {
            if let Some(action) = hook.borrow_mut().take() {
                action();
            }
        });
        check(cancellation, deadline)?;
        self.validate_path(&self.path)?;
        let current = linux_fd::open_top_directory(&self.path).map_err(open_error)?;
        private_directory(&current)?;
        let authority =
            linux_fd::open_existing_regular(self.root.fd(), Path::new("authority.lock"))?;
        private_file(&authority)?;
        if authority.metadata().identity() != self.authority {
            return Err(InstallationError::Invalid(
                "installation authority changed during observation",
            ));
        }
        match linux_fd::open_existing_regular(self.root.fd(), Path::new(name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(InstallationError::Invalid(
                    "launch binding appeared during absence observation",
                ));
            }
        }
        self.validate_path(&self.path)?;
        check(cancellation, deadline)
    }
    fn has_launch_evidence(&self) -> Result<bool> {
        let mut count = 0;
        let names = linux_fd::read_directory(&self.root, |_| {
            count += 1;
            if count > 4096 {
                Err(InstallationError::Invalid(
                    "installation registry capacity exhausted",
                ))
            } else {
                Ok(())
            }
        })
        .map_err(|error| match error {
            linux_fd::ReadDirectoryError::Io(error) => InstallationError::Io(error),
            linux_fd::ReadDirectoryError::Admission(error) => error,
        })?;
        Ok(names
            .iter()
            .any(|name| name.as_encoded_bytes().starts_with(b"launch-")))
    }
    pub(super) fn publish_launch(
        &self,
        pin: ContentDigest,
        bytes: &[u8],
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        let name = format!("launch-{pin}");
        if let Some(existing) = self.read_launch(pin)? {
            if existing != bytes {
                return Err(InstallationError::Invalid(
                    "launch binding bytes differ",
                ));
            }
        } else {
            let mut count = 0;
            linux_fd::read_directory(&self.root, |_| {
                check(cancellation, deadline)?;
                count += 1;
                if count >= 4096 {
                    return Err(InstallationError::Invalid(
                        "installation registry capacity exhausted",
                    ));
                }
                Ok(())
            })
            .map_err(|error| match error {
                linux_fd::ReadDirectoryError::Io(error) => InstallationError::Io(error),
                linux_fd::ReadDirectoryError::Admission(error) => error,
            })?;
            self.write(self.root.fd(), &name, bytes)?;
        }
        // Reconcile an earlier rename whose directory sync was uncertain.
        // Returning a readable pin alone would not prove durable publication.
        let result = (|| {
            let file = linux_fd::open_existing_regular(self.root.fd(), Path::new(&name))?;
            private_file(&file)?;
            linux_fd::sync_file(file.fd())?;
            linux_fd::sync_directory(self.root.fd())?;
            Ok::<_, InstallationError>(())
        })();
        if result.is_err() {
            self.uncertain.store(true, Ordering::Release);
            return Err(InstallationError::Uncertain(
                "launch binding durability is unknown",
            ));
        }
        Ok(())
    }
    pub(super) fn ids(&self) -> Result<Vec<ContentDigest>> {
        let mut count = 0;
        let names = linux_fd::read_directory(&self.generations, |_| {
            count += 1;
            if count > MAX_CANDIDATES {
                Err(InstallationError::Invalid(
                    "candidate registry limit exceeded",
                ))
            } else {
                Ok(())
            }
        })
        .map_err(|error| match error {
            linux_fd::ReadDirectoryError::Io(error) => InstallationError::Io(error),
            linux_fd::ReadDirectoryError::Admission(error) => error,
        })?;
        names
            .into_iter()
            .map(|name| {
                let text = name.to_str().ok_or(InstallationError::Invalid(
                    "invalid candidate directory",
                ))?;
                let digest: ContentDigest = text
                    .parse()
                    .map_err(|_| InstallationError::Invalid("invalid candidate directory"))?;
                Ok(digest)
            })
            .collect()
    }
    pub(super) fn candidate(&self, pin: ContentDigest, create: bool) -> Result<OpenedPath> {
        let name = pin.to_string();
        let path = Path::new(&name);
        match linux_fd::open_beneath(self.generations.fd(), path, true) {
            Ok(directory) => {
                private_directory(&directory)?;
                Ok(directory)
            }
            Err(linux_fd::OpenError::Other(error))
                if create && error.kind() == io::ErrorKind::NotFound =>
            {
                if self.ids()?.len() >= MAX_CANDIDATES {
                    return Err(InstallationError::Invalid(
                        "candidate registry capacity exhausted",
                    ));
                }
                let directory = linux_fd::ensure_directory_beneath(self.generations.fd(), path)
                    .map_err(|_| InstallationError::Invalid("cannot create candidate directory"))?;
                private_directory(&directory)?;
                linux_fd::sync_directory(directory.fd())?;
                linux_fd::sync_directory(self.generations.fd())?;
                Ok(directory)
            }
            Err(error) => Err(open_error(error)),
        }
    }
    pub(super) fn confirm_durable(&self, pin: ContentDigest, directory: &OpenedPath) -> Result<()> {
        let result = (|| {
            let current = self.candidate(pin, false)?;
            if current.metadata().identity() != directory.metadata().identity() {
                return Err(InstallationError::Invalid(
                    "candidate directory was replaced",
                ));
            }
            for name in ["manifest", "state"] {
                let file = linux_fd::open_existing_regular(directory.fd(), Path::new(name))?;
                private_file(&file)?;
                linux_fd::sync_file(file.fd())?;
            }
            linux_fd::sync_directory(directory.fd())?;
            linux_fd::sync_directory(self.generations.fd())?;
            Ok(())
        })();
        if result.is_err() {
            self.uncertain.store(true, Ordering::Release);
            return Err(InstallationError::Uncertain(
                "candidate durability reconciliation failed",
            ));
        }
        result
    }
    pub(super) fn write(&self, directory: BorrowedFd<'_>, name: &str, bytes: &[u8]) -> Result<()> {
        let limit = match name {
            "installation" => 128,
            "state" => 1024,
            "activation" => crate::deployment::os::activation::MAX_STATE_BYTES,
            "manifest" => super::MAX_MANIFEST_BYTES,
            name if name
                .strip_prefix("launch-")
                .is_some_and(|text| text.parse::<ContentDigest>().is_ok()) =>
            {
                crate::deployment::os::launch_binding::MAX_LAUNCH_BINDING_BYTES
            }
            _ => {
                return Err(InstallationError::Invalid(
                    "unknown installation file",
                ));
            }
        };
        if bytes.len() > limit {
            return Err(InstallationError::Invalid(
                "installation file exceeds bound",
            ));
        }
        match linux_fd::write_atomic_beneath_with_prefix(
            directory,
            Path::new(name),
            bytes,
            ".syrox-generation.tmp.",
        ) {
            Ok(()) => Ok(()),
            Err(linux_fd::WriteAtomicError::BeforeRename {
                source,
                cleanup: None,
            }) => Err(source.into()),
            Err(_) => {
                self.uncertain.store(true, Ordering::Release);
                Err(InstallationError::Uncertain(
                    "publication or temporary cleanup durability is unknown",
                ))
            }
        }
    }
}
fn read_launch_file(file: &OpenedPath) -> Result<Vec<u8>> {
    private_file(file)?;
    let maximum = crate::deployment::os::launch_binding::MAX_LAUNCH_BINDING_BYTES;
    if file.metadata().size() > maximum as u64 {
        return Err(InstallationError::Invalid(
            "launch binding exceeds bound",
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(file.fd().try_clone_to_owned()?)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(InstallationError::Invalid(
            "launch binding grew beyond bound",
        ));
    }
    Ok(bytes)
}
pub(super) fn read(directory: BorrowedFd<'_>, name: &str, maximum: usize) -> Result<Vec<u8>> {
    read_optional(directory, name, maximum)?.ok_or(InstallationError::Invalid(
        "installation evidence is absent",
    ))
}
pub(super) fn read_optional(
    directory: BorrowedFd<'_>,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>> {
    let file = match linux_fd::open_existing_regular(directory, Path::new(name)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    private_file(&file)?;
    if file.metadata().size() > maximum as u64 {
        return Err(InstallationError::Invalid(
            "installation file exceeds bound",
        ));
    }
    let mut bytes = Vec::new();
    file.into_file()
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(InstallationError::Invalid(
            "installation file grew beyond bound",
        ));
    }
    Ok(Some(bytes))
}
fn private_directory(directory: &OpenedPath) -> Result<()> {
    if !directory.metadata().is_trusted_directory() || directory.metadata().mode() & 0o7777 != 0o700
    {
        return Err(InstallationError::Invalid(
            "installation directory must be owned and mode 0700",
        ));
    }
    Ok(())
}
fn private_file(file: &OpenedPath) -> Result<()> {
    if !file.metadata().is_trusted_regular() || file.metadata().mode() & 0o7777 != 0o600 {
        return Err(InstallationError::Invalid(
            "installation file must be owned, single linked and mode 0600",
        ));
    }
    Ok(())
}
pub(super) fn open_error(error: linux_fd::OpenError) -> InstallationError {
    match error {
        linux_fd::OpenError::Other(error) | linux_fd::OpenError::Unsupported(error) => error.into(),
        linux_fd::OpenError::Symlink => {
            InstallationError::Invalid("installation path traverses a symlink")
        }
    }
}

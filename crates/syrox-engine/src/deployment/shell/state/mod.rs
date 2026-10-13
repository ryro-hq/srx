use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::plan::PlanServiceState;
use crate::platform::linux::fd::{self as linux_fd, FileIdentity, OpenedPath};
use crate::{
    cancellation::Cancellation, plan::PlanConsumer, runtime::RuntimeConfiguration,
    runtime::RuntimeError,
};

mod cleanup;
#[cfg(test)]
mod tests;

const INVENTORY: &str = ".inventory";
const MAX_INVENTORY: u64 = 1024 * 1024;

pub(super) struct SessionState {
    parent: OpenedPath,
    root: OpenedPath,
    path: PathBuf,
    services: BTreeMap<String, OpenedPath>,
    inventory: Vec<u8>,
    inventory_identity: FileIdentity,
}

fn invalid() -> io::Error {
    io::Error::other("session state inventory or directory changed; data retained")
}
fn anchored(directory: &OpenedPath, name: &Path) -> PathBuf {
    PathBuf::from(format!(
        "/proc/self/fd/{}",
        directory.fd().as_raw_fd()
    ))
    .join(name)
}
fn checked(cancel: &Cancellation, deadline: Instant) -> io::Result<()> {
    cancel
        .check()
        .map_err(|_| crate::cancellation::cancellation_io())?;
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "session state deadline",
        ));
    }
    Ok(())
}

impl SessionState {
    pub(super) fn create(
        consumer: &PlanConsumer,
        parent: &Path,
        cancel: &Cancellation,
    ) -> io::Result<Option<Self>> {
        let names = consumer
            .services()
            .iter()
            .filter(|service| service.state() == PlanServiceState::Session)
            .map(|service| service.id().to_owned())
            .collect::<BTreeSet<_>>();
        if names.is_empty() {
            return Ok(None);
        }
        Self::create_names(names, parent, cancel).map(Some)
    }

    fn create_names(
        names: BTreeSet<String>,
        parent: &Path,
        cancel: &Cancellation,
    ) -> io::Result<Self> {
        cancel
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        let parent = linux_fd::open_top_directory(parent).map_err(|_| invalid())?;
        if !parent.metadata().is_trusted_directory() || parent.metadata().mode() & 0o7777 != 0o700 {
            return Err(invalid());
        }
        let parent_path = linux_fd::directory_path(&parent)?;
        let temporary = tempfile::Builder::new()
            .prefix("session-data-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(anchored(&parent, Path::new(".")))?;
        // Preserve even partial construction; no successful remote settlement is
        // inferred from an error. The parent is never exposed to the payload.
        let path = parent_path.join(temporary.path().file_name().ok_or_else(invalid)?);
        let owned_path = temporary.keep();
        let root = linux_fd::open_beneath(
            parent.fd(),
            Path::new(path.file_name().unwrap()),
            true,
        )
        .map_err(|_| invalid())?;
        linux_fd::sync_directory(parent.fd())?;
        let mut services = BTreeMap::new();
        for name in names {
            cancel
                .check()
                .map_err(|_| crate::cancellation::cancellation_io())?;
            // The projection supplies canonical service IDs; enforce the same
            // single-component property at the filesystem boundary as well.
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                || name == "."
                || name == ".."
            {
                return Err(invalid());
            }
            let target = anchored(&root, Path::new(&name));
            fs::create_dir(&target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
            let descriptor = linux_fd::open_beneath_no_mounts(root.fd(), Path::new(&name), true)
                .map_err(|_| invalid())?;
            linux_fd::sync_directory(descriptor.fd())?;
            services.insert(name, descriptor);
        }
        let identity = root.metadata().identity();
        let entries = services
            .iter()
            .map(|(name, directory)| {
                let id = directory.metadata().identity();
                (name.clone(), (id.device, id.inode))
            })
            .collect::<BTreeMap<_, _>>();
        let inventory = serde_json::to_vec(&(1_u32, (identity.device, identity.inode), entries))?;
        if inventory.len() as u64 > MAX_INVENTORY {
            return Err(invalid());
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(anchored(&root, Path::new(INVENTORY)))?;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        file.write_all(&inventory)?;
        file.sync_all()?;
        let inventory_identity = linux_fd::metadata(file.as_fd())?.identity();
        linux_fd::sync_directory(root.fd())?;
        linux_fd::sync_directory(parent.fd())?;
        drop(owned_path);
        let state = Self {
            parent,
            root,
            path,
            services,
            inventory,
            inventory_identity,
        };
        state.validate()?;
        cancel
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        Ok(state)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn configure(
        &self,
        service: &str,
        configuration: RuntimeConfiguration,
    ) -> Result<RuntimeConfiguration, RuntimeError> {
        self.validate()?;
        match self.services.get(service) {
            Some(directory) => configuration.with_session_state(service, directory.fd()),
            None => Ok(configuration),
        }
    }

    fn validate(&self) -> io::Result<()> {
        if linux_fd::directory_path(&self.parent)? != self.path.parent().ok_or_else(invalid)? {
            return Err(invalid());
        }
        let root = linux_fd::open_beneath_no_mounts(
            self.parent.fd(),
            Path::new(self.path.file_name().ok_or_else(invalid)?),
            true,
        )
        .map_err(|_| invalid())?;
        if root.metadata().identity() != self.root.metadata().identity()
            || !root.metadata().is_trusted_directory()
            || root.metadata().mode() & 0o7777 != 0o700
        {
            return Err(invalid());
        }
        let mut count = 0;
        let names = linux_fd::read_directory(&root, |_| {
            count += 1;
            if count > self.services.len() + 1 {
                Err(())
            } else {
                Ok(())
            }
        })
        .map_err(|_| invalid())?;
        let expected = self
            .services
            .keys()
            .map(std::ffi::OsString::from)
            .chain([INVENTORY.into()])
            .collect::<BTreeSet<_>>();
        if names.into_iter().collect::<BTreeSet<_>>() != expected {
            return Err(invalid());
        }
        let record = linux_fd::open_beneath_no_mounts(root.fd(), Path::new(INVENTORY), false)
            .map_err(|_| invalid())?;
        if record.metadata().identity() != self.inventory_identity
            || !record.metadata().is_trusted_regular()
            || record.metadata().mode() & 0o7777 != 0o400
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        record
            .into_file()
            .take(MAX_INVENTORY + 1)
            .read_to_end(&mut bytes)?;
        if bytes != self.inventory {
            return Err(invalid());
        }
        let after = linux_fd::open_beneath_no_mounts(root.fd(), Path::new(INVENTORY), false)
            .map_err(|_| invalid())?;
        if after.metadata().identity() != self.inventory_identity
            || !after.metadata().is_trusted_regular()
            || after.metadata().mode() & 0o7777 != 0o400
        {
            return Err(invalid());
        }
        for (name, directory) in &self.services {
            let current = linux_fd::open_beneath_no_mounts(root.fd(), Path::new(name), true)
                .map_err(|_| invalid())?;
            if current.metadata().identity() != directory.metadata().identity() {
                return Err(invalid());
            }
            crate::execution::configuration::validate_state_directory(current.fd())
                .map_err(|_| invalid())?;
        }
        Ok(())
    }

    /// Caller has already proved every session consumer settled. This method
    /// separately verifies the local inventory and refuses namespace changes.
    pub(super) fn close(self, cancel: &Cancellation, deadline: Instant) -> io::Result<()> {
        checked(cancel, deadline)?;
        self.validate()?;
        let entries = cleanup::scan(&self, cancel, deadline)?;
        self.validate()?;
        cleanup::remove(&self, entries, cancel, deadline)?;
        // Keep the inventory until all mutable contents have been removed.
        for (name, directory) in &self.services {
            let current = linux_fd::open_beneath_no_mounts(self.root.fd(), Path::new(name), true)
                .map_err(|_| invalid())?;
            if current.metadata().identity() != directory.metadata().identity() {
                return Err(invalid());
            }
            fs::remove_dir(anchored(&self.root, Path::new(name)))?;
        }
        let current = linux_fd::open_beneath_no_mounts(
            self.parent.fd(),
            Path::new(self.path.file_name().ok_or_else(invalid)?),
            true,
        )
        .map_err(|_| invalid())?;
        if current.metadata().identity() != self.root.metadata().identity()
            || linux_fd::directory_path(&self.parent)? != self.path.parent().ok_or_else(invalid)?
        {
            return Err(invalid());
        }
        let names = linux_fd::read_directory(&self.root, |name| {
            if name == INVENTORY {
                Ok(())
            } else {
                Err(())
            }
        })
        .map_err(|_| invalid())?;
        if names != [std::ffi::OsString::from(INVENTORY)] {
            return Err(invalid());
        }
        let inventory =
            linux_fd::open_beneath_no_mounts(self.root.fd(), Path::new(INVENTORY), false)
                .map_err(|_| invalid())?;
        if inventory.metadata().identity() != self.inventory_identity {
            return Err(invalid());
        }
        fs::remove_file(anchored(&self.root, Path::new(INVENTORY)))?;
        linux_fd::sync_directory(self.root.fd())?;
        fs::remove_dir(anchored(
            &self.parent,
            Path::new(self.path.file_name().ok_or_else(invalid)?),
        ))?;
        linux_fd::sync_directory(self.parent.fd())
    }
}

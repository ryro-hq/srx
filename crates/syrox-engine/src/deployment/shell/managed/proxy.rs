use std::ffi::OsString;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::ExitStatus;

use super::{ManagedShellSession, supervision};
use crate::deployment::shell::command_broker::preparation::{
    BrokerPreparation, PreparedCommandBroker,
};
use crate::execution::launcher::rendezvous::Listener;
use crate::runtime::command_proxy::launch::{self, Attachment};
use crate::{
    cancellation::Cancellation, deployment::shell::SessionError, platform::linux::fd as linux_fd,
};

impl ManagedShellSession {
    /// Called inside managed supervision, using its local cancellation token.
    /// Uses the session's pinned worker and dedicated command runtime entry.
    pub(super) fn run_proxy(
        &self,
        alias: &str,
        arguments: &[OsString],
        attachment: Attachment<'_>,
        operation: &Cancellation,
    ) -> Result<ExitStatus, SessionError> {
        operation
            .check()
            .map_err(|_| SessionError::Cancelled)?;
        if !self
            .shell
            .prepared
            .exposures()
            .contains_key(alias)
        {
            return Err(SessionError::MissingCommand(alias.into()));
        }
        let worker = self.owner.worker_snapshot();
        let parent_path = worker
            .parent()
            .ok_or_else(|| supervision("worker parent absent"))?;
        let parent = linux_fd::open_top_directory(parent_path)
            .map_err(|e| supervision(format!("worker parent: {e:?}")))?;
        if !parent.metadata().is_trusted_directory()
            || parent.metadata().mode() & 0o7777 != 0o700
            || linux_fd::directory_path(&parent)? != parent_path
        {
            return Err(supervision("worker directory authority changed"));
        }
        let worker_name = worker
            .file_name()
            .ok_or_else(|| supervision("worker name absent"))?;
        let bytes = linux_fd::read_bounded_beneath(
            parent.fd(),
            Path::new(worker_name),
            128 * 1024 * 1024,
        )
        .map_err(|e| supervision(format!("worker snapshot: {e:?}")))?
        .ok_or_else(|| supervision("worker snapshot disappeared"))?;
        if crate::store::ContentDigest::sha256(&bytes) != self.worker_digest {
            return Err(supervision(
                "worker snapshot differs from session candidate",
            ));
        }
        operation
            .check()
            .map_err(|_| SessionError::Cancelled)?;
        let anchored_parent = format!("/proc/self/fd/{}", parent.fd().as_raw_fd());
        let temporary = tempfile::Builder::new()
            .prefix("execution-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(anchored_parent)?;
        let name = temporary
            .path()
            .file_name()
            .expect("temporary execution name")
            .to_owned();
        let directory = linux_fd::open_beneath_no_mounts(parent.fd(), Path::new(&name), true)
            .map_err(|e| supervision(format!("execution directory: {e:?}")))?;
        linux_fd::sync_directory(parent.fd())?;
        let path = parent_path.join(&name);
        let mut listener = Listener::bind(&path, "broker.sock")?;
        let broker = PreparedCommandBroker::prepare(
            &self.shell,
            BrokerPreparation {
                parent: &path,
                session: self.owner.session.as_str(),
                socket_identity: listener.node_identity()?,
                worker: &bytes,
                worker_digest: self.worker_digest,
                cwd: &self.cwd,
            },
            operation,
        )?;
        // No child exists before this boundary; afterward even an uncertain
        // failure must preserve the private tree for reconciliation.
        let _retained_path = temporary.keep();
        listener.preserve_on_drop();
        let status = launch::run(
            &broker,
            &self.journal,
            &listener,
            alias,
            arguments,
            attachment,
            operation,
        )?;
        // launch's scope consumes its local operation token even on success.
        // Cleanup uses its own token only after final settlement was observed.
        let cleanup = Cancellation::default();
        broker.close(&cleanup)?;
        listener.close()?;
        linux_fd::remove_directory(
            parent.fd(),
            Path::new(&name),
            directory.metadata().identity(),
        )?;
        Ok(status)
    }
}

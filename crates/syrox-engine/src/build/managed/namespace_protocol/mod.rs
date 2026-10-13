use super::{
    BuildError, ManagedBuildResourcesSent, ManagedBuildWorkerInspection,
    ObservedManagedBuildBinding, ObservedManagedBuildRetention, PreparedManagedBuildNamespace,
    handshake::{expected_hello, same_binding},
    manager_error,
    namespace_identity::{VerifiedManagedBuildNamespace, verify_managed_build_namespace_identity},
    retention_protocol::{NAME as RETENTION_NAME, expected_entry},
    supervision::observe_managed_build_binding,
    worker::inspect_managed_build_worker,
};
use crate::build::managed::remaining_request as remaining;
use crate::systemd::fd_store::{FdStoreEntries, FdStoreEntry};
use crate::{
    cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest,
    systemd::SystemdManager, systemd::SystemdNotifier,
};
use serde::{Deserialize, Serialize};
use std::os::fd::AsFd as _;
use std::time::Instant;

mod execution;
pub use execution::{CapturedManagedBuildOutput, CommittedManagedBuild};
const DOMAIN: &[u8] = b"syrox-managed-build-namespace-processed-v2\n";
const NAME: &str = "syrox-build-namespace";
const RAW_O_LARGEFILE: u32 = 0x8000;
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NamespaceProcessed {
    hello: String,
    resources: String,
    name: String,
}
impl NamespaceProcessed {
    fn expected(hello: &[u8], manifest: &[u8]) -> Result<Self, BuildError> {
        Ok(Self {
            hello: std::str::from_utf8(hello)
                .map_err(|_| invalid())?
                .into(),
            resources: ContentDigest::sha256(manifest).to_string(),
            name: NAME.into(),
        })
    }
    fn encode(&self) -> Result<Vec<u8>, BuildError> {
        crate::build::managed::encode_json(DOMAIN, self, 2048)
    }
    fn verify(bytes: &[u8], expected: &Self) -> Result<(), BuildError> {
        if bytes != expected.encode()? {
            return Err(invalid());
        }
        Ok(())
    }
}
/// Holds the parked namespace after publishing its pidfd. A notification barrier
/// is not manager admission, journal persistence, or permission to execute.
#[derive(Debug)]
pub struct PublishedManagedBuildNamespace<'a> {
    namespace: PreparedManagedBuildNamespace<'a>,
    capture: crate::execution::native::build::BuildCapture,
}
impl PublishedManagedBuildNamespace<'_> {
    pub(in crate::build) fn inspection(&self) -> &ManagedBuildWorkerInspection {
        &self.namespace.published.received.inspection
    }
    pub(in crate::build) fn resources_digest(&self) -> ContentDigest {
        ContentDigest::sha256(
            self.namespace
                .published
                .received
                .resources
                .manifest(),
        )
    }
    pub(in crate::build) fn namespace_pidfd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.namespace.namespace_pidfd()
    }
    /// Refresh a legitimately advanced journal snapshot before taking its write
    /// guard. The original Bound record remains available for exact comparison.
    pub(in crate::build) fn revalidate_for_commit(
        &self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        let original = self.inspection();
        let current = inspect_managed_build_worker(
            original.operation_path(),
            original.action_digest(),
            original.nonce(),
            cancel,
            deadline,
        )?;
        if current.bound_process() != original.bound_process() {
            return Err(BuildError::InputChanged);
        }
        self.namespace
            .published
            .received
            .resources
            .revalidate(cancel, deadline)?;
        self.capture.revalidate()?;
        let identity = linux_fd::require_unique_pidfd(self.namespace_pidfd())?.identity();
        let namespace = current
            .namespace_snapshot()
            .ok_or(BuildError::InputChanged)?;
        if namespace.resources != self.resources_digest()
            || namespace.device != identity.device
            || namespace.inode != identity.inode
            || linux_fd::pidfd_exited(self.namespace_pidfd())?
        {
            return Err(BuildError::InputChanged);
        }
        current.revalidate(cancel, deadline)
    }
    pub fn action_digest(&self) -> ContentDigest {
        self.namespace.action_digest()
    }
}
impl<'a> PreparedManagedBuildNamespace<'a> {
    /// Failure may follow accepted notifications. Keep the attempt for explicit
    /// reconciliation; repeating this publication is not authorized by an error.
    pub fn publish_namespace(
        mut self,
        notifier: &SystemdNotifier,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<PublishedManagedBuildNamespace<'a>, BuildError> {
        self.published.revalidate(cancel, deadline)?;
        if linux_fd::pidfd_exited(self.namespace_pidfd())? {
            return Err(invalid());
        }
        notifier
            .store_fd(
                NAME,
                self.namespace_pidfd(),
                remaining(cancel, deadline)?,
                cancel,
            )
            .map_err(|error| manager_error(&error))?;
        notifier
            .barrier(remaining(cancel, deadline)?, cancel)
            .map_err(|error| manager_error(&error))?;
        self.published.revalidate(cancel, deadline)?;
        if linux_fd::pidfd_exited(self.namespace_pidfd())? {
            return Err(invalid());
        }
        let capture = self.take_capture()?;
        capture.revalidate()?;
        let received = &self.published.received;
        received.channel.send(
            &NamespaceProcessed::expected(&received.hello, received.resources.manifest())?
                .encode()?,
            &[
                self.namespace_pidfd(),
                capture.artifacts.as_fd(),
                capture.logs.as_fd(),
            ],
            deadline,
            cancel,
        )?;
        Ok(PublishedManagedBuildNamespace {
            namespace: self,
            capture,
        })
    }
}
/// Owns coordinator retention and the independently verified namespace pidfd.
/// The journal records preparation only; manager observations remain historical.
#[derive(Debug)]
pub struct ObservedManagedBuildNamespace<'a> {
    retention: ObservedManagedBuildRetention<'a>,
    namespace: VerifiedManagedBuildNamespace,
    inspection: ManagedBuildWorkerInspection,
    resources: ContentDigest,
    capture: crate::execution::native::build::BuildCapture,
}
impl ObservedManagedBuildNamespace<'_> {
    pub fn action_digest(&self) -> ContentDigest {
        self.retention.action_digest()
    }
    pub(in crate::build) fn binding(&self) -> &ObservedManagedBuildBinding {
        &self.retention.sent.binding
    }
    pub(in crate::build) fn resources_digest(&self) -> ContentDigest {
        self.resources
    }
    pub(in crate::build) fn namespace_identity(&self) -> &VerifiedManagedBuildNamespace {
        &self.namespace
    }
    pub(in crate::build) fn revalidate(
        &self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        self.inspection.revalidate(cancel, deadline)?;
        if let Some(snapshot) = self.inspection.namespace_snapshot() {
            let identity = self.namespace.file_identity();
            if snapshot.resources != self.resources
                || snapshot.pid != self.namespace.pid()
                || snapshot.device != identity.device
                || snapshot.inode != identity.inode
            {
                return Err(invalid());
            }
        }
        self.retention
            .sent
            .resources
            .revalidate(cancel, deadline)?;
        self.capture.revalidate()?;
        self.namespace.revalidate(cancel, deadline)?;
        self.inspection.revalidate(cancel, deadline)
    }
}
impl<'a> ObservedManagedBuildRetention<'a> {
    /// Independently verify the received pidfd and both FD store entries, then
    /// persist `NamespacePrepared`. No READY or COMMIT is sent to the worker.
    pub fn observe_namespace(
        self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<ObservedManagedBuildNamespace<'a>, BuildError> {
        self.sent.resources.revalidate(cancel, deadline)?;
        let inspection = inspect_sent(&self.sent, cancel, deadline)?;
        if inspection.namespace_snapshot().is_some() {
            return Err(invalid());
        }
        let first = observe_managed_build_binding(
            self.sent.prepared,
            &self.sent.specification,
            manager,
            cancel,
            deadline,
        )?;
        if !same_binding(&first, &self.sent.binding) {
            return Err(invalid());
        }
        let peer = self.sent.channel.peer_credentials()?;
        if peer.pid != first.main_pid()
            || peer.uid != first.context().uid
            || peer.gid != first.context().gid
        {
            return Err(invalid());
        }
        let hello = expected_hello(
            self.sent.prepared.operation_id(),
            &self.sent.specification,
            &first,
        )?
        .encode()?;
        let mut packet = self
            .sent
            .channel
            .receive(peer, 3, deadline, cancel)?;
        NamespaceProcessed::verify(
            &packet.bytes,
            &NamespaceProcessed::expected(&hello, self.sent.resources.manifest())?,
        )?;
        if packet.descriptors.len() != 3 {
            return Err(invalid());
        }
        let logs = packet.descriptors.pop().ok_or_else(invalid)?;
        let artifacts = packet.descriptors.pop().ok_or_else(invalid)?;
        let capture =
            crate::execution::native::build::BuildCapture::from_received(artifacts, logs)?;
        let namespace = verify_managed_build_namespace_identity(
            packet.descriptors.pop().ok_or_else(invalid)?,
            &first,
            cancel,
            deadline,
        )?;
        let unit = &first.context().unit;
        let before = manager
            .query_fd_store(unit, remaining(cancel, deadline)?, cancel)
            .map_err(|error| manager_error(&error))?
            .ok_or_else(invalid)?;
        let entries = manager
            .query_fd_store_entries(unit, remaining(cancel, deadline)?, cancel)
            .map_err(|error| manager_error(&error))?;
        verify_entries(
            &entries,
            &before,
            first.invocation(),
            &self.sent,
            &namespace,
        )?;
        let after = manager
            .query_fd_store(unit, remaining(cancel, deadline)?, cancel)
            .map_err(|error| manager_error(&error))?
            .ok_or_else(invalid)?;
        if after != before {
            return Err(invalid());
        }
        let second = observe_managed_build_binding(
            self.sent.prepared,
            &self.sent.specification,
            manager,
            cancel,
            deadline,
        )?;
        if !same_binding(&first, &second) {
            return Err(invalid());
        }
        let resources = ContentDigest::sha256(self.sent.resources.manifest());
        let mut observed = ObservedManagedBuildNamespace {
            retention: self,
            namespace,
            inspection,
            resources,
            capture,
        };
        observed.revalidate(cancel, deadline)?;
        observed
            .retention
            .sent
            .prepared
            .record_namespace_observation(&observed, cancel, deadline)?;
        // Refresh explicitly after the durable phase change; the previous Bound
        // snapshot must never silently become valid for the new journal bytes.
        observed.inspection = inspect_sent(&observed.retention.sent, cancel, deadline)?;
        if observed.inspection.namespace_snapshot().is_none() {
            return Err(invalid());
        }
        observed.revalidate(cancel, deadline)?;
        if linux_fd::pidfd_exited(observed.namespace.pidfd())? {
            return Err(invalid());
        }
        Ok(observed)
    }
}
fn inspect_sent(
    sent: &ManagedBuildResourcesSent<'_>,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<ManagedBuildWorkerInspection, BuildError> {
    let inspection = inspect_managed_build_worker(
        sent.prepared.operation_path(),
        sent.action_digest(),
        sent.binding.nonce(),
        cancel,
        deadline,
    )?;
    if inspection.bound_process()
        != Some((
            *sent.binding.invocation(),
            sent.binding.main_pid(),
        ))
    {
        return Err(invalid());
    }
    Ok(inspection)
}
fn verify_entries(
    entries: &FdStoreEntries,
    count: &crate::systemd::SystemdFdStoreObserved,
    invocation: &[u8; 16],
    sent: &ManagedBuildResourcesSent<'_>,
    namespace: &VerifiedManagedBuildNamespace,
) -> Result<(), BuildError> {
    if entries.invocation != invocation
        || count.invocation != invocation
        || count.count != 2
        || count.max != 2
        || count.notify_access != "main"
        || entries.entries.len() != 2
    {
        return Err(invalid());
    }
    let lease = expected_entry(sent.resources.retention_descriptor())?;
    let identity = namespace.file_identity();
    let ns = FdStoreEntry {
        name: NAME.into(),
        mode: namespace.mode(),
        device_major: libc::major(identity.device),
        device_minor: libc::minor(identity.device),
        inode: identity.inode,
        special_major: libc::major(namespace.rdev()),
        special_minor: libc::minor(namespace.rdev()),
        flags: namespace.flags() & !RAW_O_LARGEFILE,
    };
    verify_pair(&entries.entries, &lease, &ns)
}
fn verify_pair(
    entries: &[FdStoreEntry],
    lease: &FdStoreEntry,
    namespace: &FdStoreEntry,
) -> Result<(), BuildError> {
    if entries.len() != 2
        || lease.name != RETENTION_NAME
        || namespace.name != NAME
        || !entries.contains(lease)
        || !entries.contains(namespace)
    {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> BuildError {
    BuildError::InvalidRequest
}
#[cfg(test)]
mod tests;

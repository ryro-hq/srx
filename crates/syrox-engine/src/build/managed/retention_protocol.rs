use super::{
    BuildError,
    handshake::{
        ManagedBuildResourcesSent, ReceivedManagedBuildResources, expected_hello, same_binding,
    },
    manager_error,
    resources::ManagedBuildResources,
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
use std::os::fd::{AsFd as _, BorrowedFd};
use std::time::Instant;
const DOMAIN: &[u8] = b"syrox-managed-build-retention-processed-v1\n";
pub(in crate::build) const NAME: &str = "syrox-build-retention";
const OBSERVED_DOMAIN: &[u8] = b"syrox-managed-build-retention-observed-v1\n";
const RAW_O_LARGEFILE: u32 = 0x8000;
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Processed {
    hello: String,
    resources: String,
    name: String,
}
impl Processed {
    fn expected(hello: &[u8], resources: &ManagedBuildResources) -> Result<Self, BuildError> {
        Ok(Self {
            hello: std::str::from_utf8(hello)
                .map_err(|_| invalid())?
                .into(),
            resources: ContentDigest::sha256(resources.manifest()).to_string(),
            name: NAME.into(),
        })
    }
    fn encode(&self) -> Result<Vec<u8>, BuildError> {
        crate::build::managed::encode_json(DOMAIN, self, 2048)
    }
    fn verify(bytes: &[u8], expected: &Self) -> Result<(), BuildError> {
        let parsed: Self = crate::build::managed::decode_json(DOMAIN, bytes, 2048)?;
        if parsed != *expected || parsed.encode()? != bytes {
            return Err(invalid());
        }
        Ok(())
    }
}
/// Notifications were processed and the coordinator acknowledged its metadata
/// observation. This is not independent proof of OFD/flock ownership. This
/// worker handle retains the received descriptors and cannot authorize execution.
#[derive(Debug)]
pub struct ManagedBuildRetentionPublished {
    pub(in crate::build) received: ReceivedManagedBuildResources,
}
impl ManagedBuildRetentionPublished {
    pub(in crate::build) fn resources(&self) -> &ManagedBuildResources {
        &self.received.resources
    }
    pub(in crate::build) fn revalidate(
        &self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        validate_worker(&self.received, cancel, deadline)
    }
}
/// Historical manager observation of exactly the expected inode, flags and
/// name. Dump cannot identify an open file description or prove its flock lease;
/// both endpoints must retain their own resources until a later settlement.
/// This is not a namespace, readiness or payload authorization proof.
#[derive(Debug)]
pub struct ObservedManagedBuildRetention<'a> {
    pub(in crate::build) sent: ManagedBuildResourcesSent<'a>,
}
impl ObservedManagedBuildRetention<'_> {
    pub fn action_digest(&self) -> ContentDigest {
        self.sent.action_digest()
    }
}
impl ReceivedManagedBuildResources {
    /// Publish from the inspected `MainPID` only. A failure can follow accepted
    /// notifications and must not trigger an automatic resend or imply rollback.
    pub fn publish_retention(
        self,
        notifier: &SystemdNotifier,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<ManagedBuildRetentionPublished, BuildError> {
        validate_worker(&self, cancel, deadline)?;
        let fd = self.resources.retention_descriptor();
        notifier
            .store_fd(NAME, fd, remaining(cancel, deadline)?, cancel)
            .map_err(|error| manager_error(&error))?;
        notifier
            .barrier(remaining(cancel, deadline)?, cancel)
            .map_err(|error| manager_error(&error))?;
        validate_worker(&self, cancel, deadline)?;
        self.channel.send(
            &Processed::expected(&self.hello, &self.resources)?.encode()?,
            &[],
            deadline,
            cancel,
        )?;
        let acknowledgement = self
            .channel
            .receive(self.peer, 0, deadline, cancel)?;
        if acknowledgement.bytes
            != observed_ack(&Processed::expected(
                &self.hello,
                &self.resources,
            )?)?
        {
            return Err(invalid());
        }
        validate_worker(&self, cancel, deadline)?;
        Ok(ManagedBuildRetentionPublished {
            received: self,
        })
    }
}
impl<'a> ManagedBuildResourcesSent<'a> {
    pub fn observe_retention(
        self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<ObservedManagedBuildRetention<'a>, BuildError> {
        self.resources.revalidate(cancel, deadline)?;
        let inspection = inspect_managed_build_worker(
            self.prepared.operation_path(),
            self.action_digest(),
            self.binding.nonce(),
            cancel,
            deadline,
        )?;
        if inspection.bound_process()
            != Some((
                *self.binding.invocation(),
                self.binding.main_pid(),
            ))
        {
            return Err(invalid());
        }
        let first = observe_managed_build_binding(
            self.prepared,
            &self.specification,
            manager,
            cancel,
            deadline,
        )?;
        if !same_binding(&first, &self.binding) {
            return Err(invalid());
        }
        let pidfd = linux_fd::pidfd_open(first.main_pid())?;
        let peer = self.channel.peer_credentials()?;
        if peer.pid != first.main_pid()
            || peer.uid != first.context().uid
            || peer.gid != first.context().gid
        {
            return Err(invalid());
        }
        let hello = expected_hello(
            self.prepared.operation_id(),
            &self.specification,
            &first,
        )?
        .encode()?;
        let packet = self.channel.receive(peer, 0, deadline, cancel)?;
        Processed::verify(
            &packet.bytes,
            &Processed::expected(&hello, &self.resources)?,
        )?;
        let unit = &first.context().unit;
        let count = manager
            .query_fd_store(unit, remaining(cancel, deadline)?, cancel)
            .map_err(|error| manager_error(&error))?
            .ok_or_else(invalid)?;
        let entries = manager
            .query_fd_store_entries(unit, remaining(cancel, deadline)?, cancel)
            .map_err(|error| manager_error(&error))?;
        verify_entries(
            &entries,
            &count,
            first.invocation(),
            self.resources.retention_descriptor(),
        )?;
        let after_count = manager
            .query_fd_store(unit, remaining(cancel, deadline)?, cancel)
            .map_err(|error| manager_error(&error))?
            .ok_or_else(invalid)?;
        if after_count != count {
            return Err(invalid());
        }

        let second = observe_managed_build_binding(
            self.prepared,
            &self.specification,
            manager,
            cancel,
            deadline,
        )?;
        inspection.revalidate(cancel, deadline)?;
        if !same_binding(&first, &second) || linux_fd::pidfd_exited(pidfd.as_fd())? {
            return Err(invalid());
        }
        self.channel.send(
            &observed_ack(&Processed::expected(&hello, &self.resources)?)?,
            &[],
            deadline,
            cancel,
        )?;
        Ok(ObservedManagedBuildRetention {
            sent: self,
        })
    }
}
fn observed_ack(processed: &Processed) -> Result<Vec<u8>, BuildError> {
    super::encode_json(OBSERVED_DOMAIN, processed, 2048)
}
fn validate_worker(
    received: &ReceivedManagedBuildResources,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<(), BuildError> {
    remaining(cancel, deadline)?;
    received.inspection.revalidate(cancel, deadline)?;
    let Some((invocation, pid)) = received.inspection.bound_process() else {
        return Err(invalid());
    };
    if pid != std::process::id()
        || invocation.iter().all(|byte| *byte == 0)
        || received.channel.peer_credentials()? != received.peer
    {
        return Err(invalid());
    }
    received.resources.revalidate(cancel, deadline)?;
    received.inspection.revalidate(cancel, deadline)
}
fn verify_entries(
    entries: &FdStoreEntries,
    count: &crate::systemd::SystemdFdStoreObserved,
    invocation: &[u8; 16],
    fd: BorrowedFd<'_>,
) -> Result<(), BuildError> {
    if entries.invocation != invocation
        || count.invocation != invocation
        || count.count != 1
        || count.max != 2
        || count.notify_access != "main"
        || entries.entries.len() != 1
    {
        return Err(invalid());
    }
    let expected = expected_entry(fd)?;
    if entries.entries[0] != expected {
        return Err(invalid());
    }
    Ok(())
}
pub(in crate::build) fn expected_entry(fd: BorrowedFd<'_>) -> Result<FdStoreEntry, BuildError> {
    linux_fd::require_readonly(fd)?;
    let metadata = linux_fd::metadata(fd)?;
    if !metadata.is_trusted_regular() || metadata.mode() & 0o7777 != 0o400 {
        return Err(invalid());
    }
    let identity = metadata.identity();
    Ok(FdStoreEntry {
        name: NAME.into(),
        mode: metadata.mode(),
        device_major: libc::major(identity.device),
        device_minor: libc::minor(identity.device),
        inode: identity.inode,
        special_major: 0,
        special_minor: 0,
        flags: linux_fd::status_flags(fd)?.cast_unsigned() & !RAW_O_LARGEFILE,
    })
}

fn invalid() -> BuildError {
    BuildError::InvalidRequest
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;
    fn processed() -> Processed {
        Processed {
            hello: "exact-hello-including-invocation".into(),
            resources: ContentDigest::sha256(b"manifest").to_string(),
            name: NAME.into(),
        }
    }
    #[test]
    fn processing_claim_is_canonical_domain_and_context_bound() {
        let expected = processed();
        let bytes = expected.encode().unwrap();
        Processed::verify(&bytes, &expected).unwrap();
        for change in 0..3 {
            let mut changed = processed();
            match change {
                0 => changed.hello.push('x'),
                1 => changed.resources = ContentDigest::sha256(b"other").to_string(),
                _ => changed.name.push('x'),
            }
            assert!(Processed::verify(&changed.encode().unwrap(), &expected).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(b' ');
        assert!(Processed::verify(&extra, &expected).is_err());
        assert!(Processed::verify(&bytes[1..], &expected).is_err());
        assert!(Processed::verify(&bytes[..bytes.len() - 1], &expected).is_err());
        let mut unknown = bytes[..bytes.len() - 1].to_vec();
        unknown.extend_from_slice(b",\"ready\":true}");
        assert!(Processed::verify(&unknown, &expected).is_err());
        assert!(Processed::verify(&vec![b'x'; 2049], &expected).is_err());
    }
    fn retained() -> (tempfile::TempDir, File) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("interest");
        std::fs::write(&path, b"record").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let file = File::open(path).unwrap();
        (dir, file)
    }
    fn count() -> crate::systemd::SystemdFdStoreObserved {
        crate::systemd::SystemdFdStoreObserved {
            invocation: vec![1; 16],
            count: 1,
            max: 2,
            notify_access: "main".into(),
        }
    }
    #[test]
    fn independent_metadata_requires_exact_name_inode_flags_and_invocation() {
        let (_dir, file) = retained();
        let entries = FdStoreEntries {
            invocation: vec![1; 16],
            entries: vec![expected_entry(file.as_fd()).unwrap()],
        };
        verify_entries(&entries, &count(), &[1; 16], file.as_fd()).unwrap();
        for change in 0..8 {
            let mut entry = expected_entry(file.as_fd()).unwrap();
            match change {
                0 => entry.name.push('x'),
                1 => entry.inode += 1,
                2 => entry.device_major += 1,
                3 => entry.device_minor += 1,
                4 => entry.mode |= 0o200,
                5 => entry.flags |= libc::O_NONBLOCK.cast_unsigned(),
                6 => entry.special_major = 1,
                _ => entry.special_minor = 1,
            }
            let entries = FdStoreEntries {
                invocation: vec![1; 16],
                entries: vec![entry],
            };
            assert!(verify_entries(&entries, &count(), &[1; 16], file.as_fd()).is_err());
        }
        for change in 0..4 {
            let mut changed = count();
            match change {
                0 => changed.invocation = vec![2; 16],
                1 => changed.count = 2,
                2 => changed.max = 1,
                _ => changed.notify_access = "all".into(),
            }
            assert!(verify_entries(&entries, &changed, &[1; 16], file.as_fd()).is_err());
        }
        assert!(
            verify_entries(
                &FdStoreEntries {
                    invocation: vec![2; 16],
                    entries: vec![expected_entry(file.as_fd()).unwrap()]
                },
                &count(),
                &[1; 16],
                file.as_fd()
            )
            .is_err()
        );
        assert!(
            verify_entries(
                &FdStoreEntries {
                    invocation: vec![1; 16],
                    entries: vec![]
                },
                &count(),
                &[1; 16],
                file.as_fd()
            )
            .is_err()
        );
    }
    #[test]
    fn publisher_budget_cancel_and_deadline_do_not_imply_notification() {
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            remaining(&cancel, Instant::now() + Duration::from_secs(5)),
            Err(BuildError::Cancelled)
        ));
        assert!(remaining(&Cancellation::default(), Instant::now()).is_err());
    }
    #[test]
    fn processing_packet_requires_fixed_peer_and_zero_descriptors() {
        use crate::execution::transport::{PacketChannel, Peer};
        let (sender, receiver) = PacketChannel::pair().unwrap();
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        let bytes = processed().encode().unwrap();
        sender
            .send(&bytes, &[], deadline, &cancel)
            .unwrap();
        let packet = receiver
            .receive(Peer::current(), 0, deadline, &cancel)
            .unwrap();
        Processed::verify(&packet.bytes, &processed()).unwrap();
        let file = File::open("/dev/null").unwrap();
        sender
            .send(&bytes, &[file.as_fd()], deadline, &cancel)
            .unwrap();
        assert!(
            receiver
                .receive(Peer::current(), 0, deadline, &cancel)
                .is_err()
        );
    }

    #[test]
    fn observed_ack_is_distinct_from_processed_and_binds_the_same_context() {
        let expected = processed();
        let ack = observed_ack(&expected).unwrap();
        assert_ne!(ack, expected.encode().unwrap());
        assert!(ack.starts_with(OBSERVED_DOMAIN));
        let mut other = processed();
        other.resources = ContentDigest::sha256(b"another package").to_string();
        assert_ne!(ack, observed_ack(&other).unwrap());
    }
}

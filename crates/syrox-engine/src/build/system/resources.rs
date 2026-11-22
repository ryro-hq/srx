//! Complete, budgeted input descriptor sets for the separate System worker.
//!
//! A caller authenticates the expected manifest digest independently. Validation
//! retains objects and checks content/views, but grants no execution authority.

use super::{BuildError, SystemBuildAction, SystemBuildInputs};
use crate::{
    cancellation::Cancellation,
    platform::linux::fd,
    result::{MaterializedArtifact, OutputOrigin, artifact::IndexedArtifact},
    store::{ContentDigest, ObjectLease, chunked::ChunkedDescriptorReader},
};
use std::{
    collections::BTreeSet,
    os::{
        fd::{AsFd as _, BorrowedFd, OwnedFd},
        unix::fs::MetadataExt as _,
    },
};

mod reader;
mod wire;
use wire::{Input, Manifest};

/// The input portion of System worker resources: ordered view/artifact groups
/// and one independent, locked retention description. No global Store barrier
/// survives preparation or validation. Remaining non-input/executor descriptors
/// must be explicitly reserved by the caller before construction.
pub struct SystemBuildInputResources {
    action: SystemBuildAction,
    manifest: Vec<u8>,
    digest: ContentDigest,
    reserved: u32,
    descriptors: Vec<OwnedFd>,
    interest: Option<ObjectLease>,
}

impl std::fmt::Debug for SystemBuildInputResources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemBuildInputResources")
            .field("action", &self.action.digest())
            .field("manifest", &self.digest)
            .field("slots", &self.descriptors.len())
            .finish_non_exhaustive()
    }
}

impl SystemBuildInputs {
    pub fn prepare_input_resources(
        &self,
        reserved_descriptors: u32,
        cancellation: &Cancellation,
    ) -> Result<SystemBuildInputResources, BuildError> {
        cancellation.check()?;
        let mut inputs = Vec::with_capacity(self.inputs.len());
        let mut count = 1_u32; // Independent process-retention descriptor.
        for input in &self.inputs {
            let chunked = input
                .chunked()
                .map(crate::result::ChunkedOutput::decoded)
                .transpose()
                .map_err(|_| BuildError::InputChanged)?;
            let artifact_slots = chunked.as_ref().map_or(1, |manifest| {
                manifest
                    .chunks()
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    + 1
            });
            let artifact_slots =
                u32::try_from(artifact_slots).map_err(|_| BuildError::UnsupportedInputs)?;
            count = count
                .checked_add(1)
                .and_then(|n| n.checked_add(artifact_slots))
                .ok_or(BuildError::UnsupportedInputs)?;
            let limits = input.artifact_limits();
            let entry = Input {
                storage: if chunked.is_some() {
                    "chunked"
                } else {
                    "blob"
                }
                .into(),
                artifact_slots,
                maximum_bytes: limits.bytes,
                maximum_files: limits.files as u64,
            };
            entry.limits()?;
            inputs.push(entry);
        }
        // Reject aggregate over-budget inputs before opening any descriptor or
        // creating a new Store interest. Counts include duplicate selected roles.
        wire::check_slots(count, reserved_descriptors, &self.action)?;
        self.revalidate(cancellation)?;
        let mut leases = vec![&self.interest];
        leases.extend(
            self.inputs
                .iter()
                .map(MaterializedArtifact::object_lease),
        );
        let interest = ObjectLease::combine(&leases)?;
        let mut descriptors =
            Vec::with_capacity(usize::try_from(count).map_err(|_| BuildError::UnsupportedInputs)?);
        for (input, entry) in self.inputs.iter().zip(&inputs) {
            cancellation.check()?;
            descriptors.push(input.mount_fd().try_clone_to_owned()?);
            if entry.storage == "chunked" {
                let chunked =
                    super::input_descriptors::capture(input, entry.artifact_slots, cancellation)?;
                for descriptor in chunked.descriptors() {
                    descriptors.push(descriptor.try_clone()?);
                }
            } else {
                let operation = input.object_lease().operation()?;
                let artifact = operation
                    .open_verified_checked(input.artifact(), entry.maximum_bytes, || {
                        cancellation
                            .check()
                            .map_err(|_| crate::cancellation::cancellation_io())
                    })?
                    .ok_or(BuildError::InputChanged)?;
                descriptors.push(artifact.duplicate_readonly_descriptor()?);
            }
        }
        let retention = interest.process_retention()?;
        let metadata = retention.metadata()?;
        let mut bytes = Vec::new();
        // Hash with positional reads, not the descriptor's shared seek cursor.
        let retention_pin = hash_record(&retention, cancellation)?;
        descriptors.push(retention.into());
        let manifest = Manifest {
            action: self.action.digest().to_string(),
            reserved: reserved_descriptors,
            slots: count,
            inputs,
            retention: retention_pin.to_string(),
            retention_device: metadata.dev(),
            retention_inode: metadata.ino(),
        };
        bytes.extend(manifest.encode()?);
        let digest = ContentDigest::sha256(&bytes);
        let mut result = SystemBuildInputResources::from_received(
            &self.action,
            digest,
            &bytes,
            reserved_descriptors,
            descriptors,
            cancellation,
        )?;
        result.interest = Some(interest);
        self.revalidate(cancellation)?;
        Ok(result)
    }
}

impl SystemBuildInputResources {
    /// Strip sender-side Store handles after independently duplicating the
    /// exact input/retention roles. The receiver's flock keeps source, views
    /// and artifacts alive without carrying a Store path or writer authority.
    pub(super) fn into_namespace_receiver(
        self,
        cancellation: &Cancellation,
    ) -> Result<Self, BuildError> {
        let Self {
            action,
            digest,
            manifest,
            reserved,
            descriptors,
            interest: _sender_interest,
        } = self;
        Self::from_received(
            &action,
            digest,
            &manifest,
            reserved,
            descriptors,
            cancellation,
        )
    }
    pub const MAX_MANIFEST_BYTES: usize = wire::MAX_BYTES;

    pub const fn manifest_digest(&self) -> ContentDigest {
        self.digest
    }
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }
    pub fn descriptors(&self) -> &[OwnedFd] {
        &self.descriptors
    }
    pub fn action_digest(&self) -> ContentDigest {
        self.action.digest()
    }
    pub const fn reserved_descriptors(&self) -> u32 {
        self.reserved
    }

    /// Preflight untrusted offers before receiving any descriptor batches. The
    /// expected digest/reserve must come from authenticated coordinator evidence,
    /// not be copied from the offer whose trust is being established.
    pub fn expected_descriptor_count(
        action: &SystemBuildAction,
        expected: ContentDigest,
        bytes: &[u8],
        reserved: u32,
    ) -> Result<u32, BuildError> {
        Ok(Manifest::parse(bytes, expected, action, reserved)?.slots)
    }

    /// Acquire an independent shared interest lock and verify exact descriptor
    /// roles/content/views. This requires an independently authenticated manifest
    /// digest and action; parsing a received offer alone supplies neither.
    pub fn from_received(
        action: &SystemBuildAction,
        expected: ContentDigest,
        bytes: &[u8],
        reserved: u32,
        mut descriptors: Vec<OwnedFd>,
        cancellation: &Cancellation,
    ) -> Result<Self, BuildError> {
        cancellation.check()?;
        let manifest = Manifest::parse(bytes, expected, action, reserved)?;
        if descriptors.len()
            != usize::try_from(manifest.slots).map_err(|_| BuildError::InvalidRequest)?
        {
            return Err(BuildError::InputChanged);
        }
        // SCM_RIGHTS already supplies CLOEXEC, but direct callers may provide
        // inherited descriptors. Replace one owned role at a time with Rust's
        // CLOEXEC duplicate, keeping temporary FD use within the reserve.
        for descriptor in &mut descriptors {
            cancellation.check()?;
            *descriptor = descriptor.try_clone()?;
        }
        let retention = descriptors
            .last()
            .ok_or(BuildError::InvalidRequest)?;
        fd::require_readonly(retention.as_fd())?;
        let metadata = std::fs::File::from(retention.try_clone()?).metadata()?;
        if !metadata.is_file()
            || metadata.uid() != fd::effective_uid()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o400
            || (metadata.dev(), metadata.ino())
                != (
                    manifest.retention_device,
                    manifest.retention_inode,
                )
        {
            return Err(BuildError::InputChanged);
        }
        // A byte-identical replacement file is not the selected Store interest.
        // GC cannot unlink this interest after shared acquisition; metadata and
        // coverage are rechecked with the lock held before returning resources.
        if !fd::flock(retention.as_fd(), fd::FlockMode::Shared)? {
            return Err(BuildError::InputChanged);
        }
        let result = Self {
            action: action.clone(),
            manifest: bytes.to_vec(),
            digest: expected,
            reserved,
            descriptors,
            interest: None,
        };
        result.revalidate(cancellation)?;
        Ok(result)
    }

    pub fn revalidate(&self, cancellation: &Cancellation) -> Result<(), BuildError> {
        self.validate(cancellation, false)
    }

    pub(super) fn verify_namespace_inputs(
        &self,
        cancellation: &Cancellation,
    ) -> Result<(), BuildError> {
        self.validate(cancellation, true)
    }

    fn validate(&self, cancellation: &Cancellation, namespace: bool) -> Result<(), BuildError> {
        cancellation.check()?;
        if let Some(interest) = &self.interest
            && !namespace
        {
            drop(interest.operation()?);
        }
        let metadata = Manifest::parse(
            &self.manifest,
            self.digest,
            &self.action,
            self.reserved,
        )?;
        let retention = self
            .descriptors
            .last()
            .ok_or(BuildError::InvalidRequest)?;
        let stat = std::fs::File::from(retention.try_clone()?).metadata()?;
        if (stat.dev(), stat.ino())
            != (
                metadata.retention_device,
                metadata.retention_inode,
            )
            || !fd::flock(retention.as_fd(), fd::FlockMode::Shared)?
        {
            return Err(BuildError::InputChanged);
        }
        let retention_pin = metadata
            .retention
            .parse()
            .map_err(|_| BuildError::InvalidRequest)?;
        let record = reader::bytes(
            retention.try_clone()?,
            ObjectLease::MAX_HANDOFF_RECORD_BYTES,
            retention_pin,
            Some(0o400),
            cancellation,
        )?;
        let mut references = vec![self.action.source_digest()];
        let mut views = Vec::new();
        let mut slot = 0;
        for (entry, selected) in metadata
            .inputs
            .iter()
            .zip(self.action.selected_inputs())
        {
            cancellation.check()?;
            let limits = entry.limits()?;
            let mounted;
            let directory = if namespace {
                mounted = fd::open_top_directory(std::path::Path::new(&format!(
                    "/syrox/store/{}/{}",
                    selected.action, selected.output
                )))
                .map_err(|_| BuildError::InputChanged)?;
                mounted.fd()
            } else {
                self.descriptors[slot].as_fd()
            };
            let directory_metadata = fd::metadata(directory)?;
            fd::require_readonly(directory)?;
            if !directory_metadata.is_trusted_directory()
                || directory_metadata.mode() & 0o7777 != 0o700
            {
                return Err(BuildError::InputChanged);
            }
            slot += 1;
            let count =
                usize::try_from(entry.artifact_slots).map_err(|_| BuildError::InvalidRequest)?;
            let group = self.descriptors[slot..slot + count]
                .iter()
                .map(OwnedFd::try_clone)
                .collect::<std::io::Result<Vec<_>>>()?;
            slot += count;
            let input = if entry.storage == "chunked" {
                let reader = ChunkedDescriptorReader::from_received(
                    selected.artifact,
                    group,
                    limits.bytes,
                    entry.artifact_slots,
                    cancellation,
                )
                .map_err(|_| invalidated(cancellation))?;
                references.extend_from_slice(reader.manifest().chunks());
                InputReader::Chunked(reader)
            } else {
                InputReader::Blob(reader::Reader::verified(
                    group
                        .into_iter()
                        .next()
                        .ok_or(BuildError::InvalidRequest)?,
                    limits.bytes,
                    selected.artifact,
                    None,
                    cancellation,
                )?)
            };
            let mut indexed = IndexedArtifact::open_with_limits(input, "", limits, cancellation)
                .map_err(|_| invalidated(cancellation))?;
            let maximum_entries = if entry.storage == "chunked" {
                limits.files
            } else {
                65_536
            };
            crate::result::materialize::verify_descriptor_view_with_limit(
                directory,
                &mut indexed,
                maximum_entries,
                cancellation,
            )
            .map_err(|_| invalidated(cancellation))?;
            references.push(selected.artifact);
            views.push(selected.artifact);
            match selected.origin {
                OutputOrigin::Built {
                    receipt,
                } => references.extend([selected.action, receipt]),
                OutputOrigin::Imported {
                    manifest,
                } => references.push(manifest),
            }
        }
        ObjectLease::validate_handoff_record(&record, &references, &views)?;
        cancellation.check()?;
        Ok(())
    }

    /// A freshly verified directory role only; this does not authorize mounting
    /// or opening an execution gate. Keep these resources/retention alive.
    pub fn view_descriptor(
        &self,
        index: usize,
        cancellation: &Cancellation,
    ) -> Result<BorrowedFd<'_>, BuildError> {
        self.revalidate(cancellation)?;
        self.mount_descriptor(index)
    }

    /// Internal mount slot lookup after the namespace preparer revalidates the
    /// complete input record. Content is checked again through the mounted view.
    pub(super) fn mount_descriptor(&self, index: usize) -> Result<BorrowedFd<'_>, BuildError> {
        let manifest = Manifest::parse(
            &self.manifest,
            self.digest,
            &self.action,
            self.reserved,
        )?;
        if index >= manifest.inputs.len() {
            return Err(BuildError::UnsupportedInputs);
        }
        let slot = manifest.inputs[..index]
            .iter()
            .map(|input| 1 + input.artifact_slots as usize)
            .sum::<usize>();
        Ok(self.descriptors[slot].as_fd())
    }

    /// Retention alone, for a future authenticated `SCM_RIGHTS`/`FDSTORE` protocol.
    pub fn retention_descriptor(
        &self,
        cancellation: &Cancellation,
    ) -> Result<BorrowedFd<'_>, BuildError> {
        self.revalidate(cancellation)?;
        Ok(self
            .descriptors
            .last()
            .ok_or(BuildError::InvalidRequest)?
            .as_fd())
    }
}

fn invalidated(cancellation: &Cancellation) -> BuildError {
    if cancellation.is_cancelled() {
        BuildError::Cancelled
    } else {
        BuildError::InputChanged
    }
}

fn hash_record(
    file: &std::fs::File,
    cancellation: &Cancellation,
) -> Result<ContentDigest, BuildError> {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::FileExt as _;
    let length = file.metadata()?.len();
    if length > ObjectLease::MAX_HANDOFF_RECORD_BYTES {
        return Err(BuildError::InvalidRequest);
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    let mut position = 0;
    loop {
        cancellation.check()?;
        let count = match file.read_at(&mut buffer, position) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        position += count as u64;
        if position > length {
            return Err(BuildError::InputChanged);
        }
        digest.update(&buffer[..count]);
    }
    if position != length {
        return Err(BuildError::InputChanged);
    }
    Ok(ContentDigest::from_sha256_hash(
        digest.finalize().into(),
    ))
}

#[derive(Debug)]
enum InputReader {
    Blob(reader::Reader),
    Chunked(ChunkedDescriptorReader),
}
impl std::io::Read for InputReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Blob(reader) => reader.read(bytes),
            Self::Chunked(reader) => reader.read(bytes),
        }
    }
}
impl std::io::Seek for InputReader {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        match self {
            Self::Blob(reader) => reader.seek(position),
            Self::Chunked(reader) => reader.seek(position),
        }
    }
}

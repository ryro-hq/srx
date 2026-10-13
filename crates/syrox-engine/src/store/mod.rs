//! Objects addressed by digest and interests that keep them alive.
//!
//! # Access and retention have different lifetimes
//!
//! [`Store::operation`] opens access for reading and publication. Maintenance uses
//! a separate lease to sweep collectible objects. This global lock need not last
//! while a process uses an output: [`ObjectLease`] keeps a narrower interest in the
//! required objects and views. See [`retention`](../../src/syrox_engine/store/retention/mod.rs.html) for the locks behind each interest.
//!
//! A digest verifies content; an open descriptor identifies the directory or file
//! being used. Publication and collection require both pieces of information.

use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

#[cfg(test)]
thread_local! {
    static VERIFIED_READ_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn take_verified_read_bytes() -> u64 {
    VERIFIED_READ_BYTES.with(|count| count.replace(0))
}

#[cfg(target_os = "linux")]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::io::Seek as _;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd as _;

#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const MAX_STORE_BLOB_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_ROOT_NAME_BYTES: usize = 128;
pub const MAX_ROOT_REFERENCES: u64 = 65_536;
pub const MAX_ROOT_BYTES: u64 = 4_718_740;
pub const MAX_GC_ROOTS: u64 = 65_536;
pub const MAX_GC_ROOT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_GC_REFERENCES: u64 = 1_000_000;
pub const MAX_GC_OBJECTS: u64 = 1_000_000;
pub const MAX_GC_OBJECT_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
pub const MAX_GC_CANDIDATES: u64 = 1_000_000;
pub const MAX_GC_WORK: u64 = 4_000_000;
pub const MAX_RECOVERY_ENTRIES: u64 = 1_000_000;
pub const MAX_RECOVERY_CANDIDATES: u64 = 1_000_000;
pub const MAX_RECOVERY_WORK: u64 = 2_000_000;

#[cfg(target_os = "linux")]
const ROOT_HEADER: &str = "syrox-root\n";
#[cfg(target_os = "linux")]
const OBJECT_TEMP_PREFIX: &str = ".syrox-store.tmp.";
#[cfg(target_os = "linux")]
const ROOT_TEMP_PREFIX: &str = ".syrox-root.tmp.";

mod identity;
mod maintenance;
mod objects;
pub(crate) use objects::StoreAdmission;
mod retention;
pub use identity::{ContentDigest, DigestParseError, RootName, RootNameError};
pub use retention::ObjectLease;
pub(crate) use retention::durable::DurableInterest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreObjectState {
    Published,
    Existing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreObject {
    digest: ContentDigest,
    size: u64,
    state: StoreObjectState,
}

impl StoreObject {
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn state(&self) -> StoreObjectState {
        self.state
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBytes {
    digest: ContentDigest,
    bytes: Vec<u8>,
}

impl VerifiedBytes {
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    pub fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug)]
pub struct VerifiedReader {
    digest: ContentDigest,
    size: u64,
    #[cfg(target_os = "linux")]
    file: std::fs::File,
    _lease: OperationLease,
}

impl VerifiedReader {
    /// Duplicate the already verified inode. The caller supplies independent
    /// granular retention if it needs the Store namespace to survive GC.
    pub(crate) fn duplicate_readonly_descriptor(&self) -> io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::AsFd as _;
        self.file.as_fd().try_clone_to_owned()
    }
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn read_range_checked(
        &self,
        offset: u64,
        length: usize,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        use std::os::fd::AsFd as _;
        if offset
            .checked_add(length as u64)
            .is_none_or(|end| end > self.size)
        {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        crate::platform::linux::fd::read_exact_at(self.file.as_fd(), offset, length, check)
    }
}

impl Read for VerifiedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            self.file.read(buffer)
        }
    }
}

impl io::Seek for VerifiedReader {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        #[cfg(target_os = "linux")]
        {
            self.file.seek(position)
        }
    }
}

#[derive(Debug)]
struct StoreInner {
    #[cfg(target_os = "linux")]
    objects_parent: crate::platform::linux::fd::OpenedPath,
    #[cfg(target_os = "linux")]
    objects: crate::platform::linux::fd::OpenedPath,
    #[cfg(target_os = "linux")]
    roots_parent: crate::platform::linux::fd::OpenedPath,
    #[cfg(target_os = "linux")]
    roots: crate::platform::linux::fd::OpenedPath,
    #[cfg(target_os = "linux")]
    private_parent: crate::platform::linux::fd::OpenedPath,
    #[cfg(target_os = "linux")]
    coordination: crate::platform::linux::fd::OpenedPath,
    interests: crate::platform::linux::fd::OpenedPath,
    #[cfg(target_os = "linux")]
    lease_identity: crate::platform::linux::fd::FileIdentity,
    #[cfg(target_os = "linux")]
    _lease_anchor: crate::platform::linux::fd::OpenedPath,
}

#[derive(Debug)]
pub struct Store {
    inner: Arc<StoreInner>,
}

#[derive(Debug)]
pub struct OperationLease {
    inner: Arc<StoreInner>,
    #[cfg(target_os = "linux")]
    lock: Arc<LeaseLock>,
}

/// Release ownership explicitly: an unrelated concurrent fork can temporarily
/// inherit a CLOEXEC descriptor until exec. Closing only our descriptor would
/// let that child extend the flock beyond the last actual Store consumer.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LeaseLock(crate::platform::linux::fd::OpenedPath);

#[cfg(target_os = "linux")]
impl Drop for LeaseLock {
    fn drop(&mut self) {
        let _ = crate::platform::linux::fd::flock(
            self.0.fd(),
            crate::platform::linux::fd::FlockMode::Unlock,
        );
    }
}

impl Clone for OperationLease {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            #[cfg(target_os = "linux")]
            lock: Arc::clone(&self.lock),
        }
    }
}

#[derive(Debug)]
pub struct MaintenanceLease {
    inner: Arc<StoreInner>,
    #[cfg(target_os = "linux")]
    _lock: LeaseLock,
}

impl Store {
    pub(crate) fn validate_directory(&self, path: &Path) -> Result<(), StoreError> {
        let root = crate::platform::linux::fd::open_top_directory(path).map_err(map_open_error)?;
        require_directory(&root)?;
        for (name, expected) in [
            ("objects", &self.inner.objects_parent),
            ("roots", &self.inner.roots_parent),
            (".syrox-store", &self.inner.private_parent),
        ] {
            let current =
                crate::platform::linux::fd::open_beneath(root.fd(), Path::new(name), true)
                    .map_err(map_open_error)?;
            if current.metadata().identity() != expected.metadata().identity() {
                return Err(StoreError::LeaseCorrupt);
            }
        }
        Ok(())
    }
    /// Initialize a configured absolute location beneath an existing trusted
    /// user directory. Creation is descriptor-relative and safe to repeat.
    pub fn initialize(root: &Path) -> Result<Self, StoreError> {
        #[cfg(target_os = "linux")]
        {
            use std::path::Component;
            if !root.is_absolute()
                || root.components().count() > 64
                || root.as_os_str().len() > 4096
                || root
                    .components()
                    .any(|part| matches!(part, Component::ParentDir))
            {
                return Err(StoreError::InvalidLocation);
            }
            let mut ancestor = root;
            let mut missing = Vec::new();
            let mut opened = loop {
                match crate::platform::linux::fd::open_top_directory(ancestor) {
                    Ok(opened) => break opened,
                    Err(crate::platform::linux::fd::OpenError::Other(error))
                        if error.kind() == io::ErrorKind::NotFound =>
                    {
                        missing.push(
                            ancestor
                                .file_name()
                                .ok_or(StoreError::InvalidLocation)?,
                        );
                        ancestor = ancestor
                            .parent()
                            .ok_or(StoreError::InvalidLocation)?;
                    }
                    Err(error) => return Err(map_open_error(error)),
                }
            };
            require_directory(&opened)?;
            for name in missing.into_iter().rev() {
                opened = crate::platform::linux::fd::ensure_directory_beneath(
                    opened.fd(),
                    Path::new(name),
                )
                .map_err(map_directory_error)?;
            }
            Self::from_directory(&opened)
        }
    }

    pub fn open(root: &Path) -> Result<Self, StoreError> {
        #[cfg(target_os = "linux")]
        {
            let root =
                crate::platform::linux::fd::open_top_directory(root).map_err(map_open_error)?;
            Self::from_directory(&root)
        }
    }

    /// Open an already initialized Store without creating or repairing metadata.
    /// This retains the existing permanent lease inode; operations remain subject
    /// to the same coordination and identity checks as an initialized handle.
    pub fn open_existing(root: &Path) -> Result<Self, StoreError> {
        let root = crate::platform::linux::fd::open_top_directory(root).map_err(map_open_error)?;
        require_directory(&root)?;
        reject_unsupported_layout(&root)?;
        let objects_parent = open_named_directory(root.fd(), "objects")?;
        let objects = open_named_directory(objects_parent.fd(), "sha256")?;
        for shard in 0_u16..=255 {
            open_named_directory(objects.fd(), &format!("{shard:02x}"))?;
        }
        let roots_parent = open_named_directory(root.fd(), "roots")?;
        let roots = open_named_directory(roots_parent.fd(), "retained")?;
        let private_parent = open_named_directory(root.fd(), ".syrox-store")?;
        let coordination = open_named_directory(private_parent.fd(), "state")?;
        let lease = crate::platform::linux::fd::open_existing_regular(
            coordination.fd(),
            Path::new("lease"),
        )
        .map_err(|_| StoreError::LeaseCorrupt)?;
        let interests = open_named_directory(private_parent.fd(), "interests")?;
        let lease_identity = lease.metadata().identity();
        Ok(Self {
            inner: Arc::new(StoreInner {
                objects_parent,
                objects,
                roots_parent,
                roots,
                private_parent,
                coordination,
                interests,
                lease_identity,
                _lease_anchor: lease,
            }),
        })
    }

    #[cfg(target_os = "linux")]
    fn from_directory(root: &crate::platform::linux::fd::OpenedPath) -> Result<Self, StoreError> {
        require_directory(root)?;
        reject_unsupported_layout(root)?;
        let objects_parent = ensure(root.fd(), "objects")?;
        let objects = ensure(objects_parent.fd(), "sha256")?;
        for shard in 0_u16..=255 {
            ensure(objects.fd(), &format!("{shard:02x}"))?;
        }
        let roots_parent = ensure(root.fd(), "roots")?;
        let roots = ensure(roots_parent.fd(), "retained")?;
        let private_parent = ensure(root.fd(), ".syrox-store")?;
        let initialization =
            crate::platform::linux::fd::open_beneath(private_parent.fd(), Path::new("."), true)
                .map_err(map_open_error)?;
        crate::platform::linux::fd::flock(
            initialization.fd(),
            crate::platform::linux::fd::FlockMode::Exclusive,
        )?;
        let (coordination, coordination_created) =
            crate::platform::linux::fd::ensure_directory_beneath_with_status(
                private_parent.fd(),
                Path::new("state"),
            )
            .map_err(map_directory_error)?;
        let lease = if coordination_created {
            let (lease, _created) = crate::platform::linux::fd::initialize_regular(
                coordination.fd(),
                Path::new("lease"),
            )?;
            lease
        } else {
            crate::platform::linux::fd::open_existing_regular(coordination.fd(), Path::new("lease"))
                .map_err(|_| StoreError::LeaseCorrupt)?
        };
        crate::platform::linux::fd::sync_file(lease.fd())?;
        crate::platform::linux::fd::sync_directory(coordination.fd())?;
        let interests = ensure(private_parent.fd(), "interests")?;
        drop(initialization);
        let lease_identity = lease.metadata().identity();
        Ok(Self {
            inner: Arc::new(StoreInner {
                objects_parent,
                objects,
                roots_parent,
                roots,
                private_parent,
                coordination,
                interests,
                lease_identity,
                _lease_anchor: lease,
            }),
        })
    }

    pub fn operation(&self) -> Result<OperationLease, StoreError> {
        #[cfg(target_os = "linux")]
        {
            let lock = open_lease(&self.inner)?;
            if !crate::platform::linux::fd::flock(
                lock.fd(),
                crate::platform::linux::fd::FlockMode::Shared,
            )? {
                return Err(StoreError::Busy);
            }
            Ok(OperationLease {
                inner: Arc::clone(&self.inner),
                lock: Arc::new(LeaseLock(lock)),
            })
        }
    }

    pub fn maintenance(&self) -> Result<MaintenanceLease, StoreError> {
        #[cfg(target_os = "linux")]
        {
            let lock = open_lease(&self.inner)?;
            if !crate::platform::linux::fd::flock(
                lock.fd(),
                crate::platform::linux::fd::FlockMode::ExclusiveNonblocking,
            )? {
                return Err(StoreError::Busy);
            }
            Ok(MaintenanceLease {
                inner: Arc::clone(&self.inner),
                _lock: LeaseLock(lock),
            })
        }
    }
}

#[derive(Debug)]
pub struct StoreStaging {
    expected: ContentDigest,
    maximum_bytes: u64,
    size: u64,
    #[cfg(target_os = "linux")]
    lease: OperationLease,
    #[cfg(target_os = "linux")]
    hasher: Sha256,
    #[cfg(target_os = "linux")]
    failed: bool,
    #[cfg(target_os = "linux")]
    temporary: crate::platform::linux::fd::AtomicFile,
}

impl OperationLease {
    #[cfg(target_os = "linux")]
    pub(crate) fn verify_checked(
        &self,
        expected: ContentDigest,
        maximum_bytes: u64,
        check: impl FnMut() -> io::Result<()>,
    ) -> Result<Option<StoreObject>, StoreError> {
        Ok(self
            .open_verified_checked(expected, maximum_bytes, check)?
            .map(|reader| StoreObject {
                digest: expected,
                size: reader.size(),
                state: StoreObjectState::Existing,
            }))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn open_verified_checked(
        &self,
        expected: ContentDigest,
        maximum_bytes: u64,
        check: impl FnMut() -> io::Result<()>,
    ) -> Result<Option<VerifiedReader>, StoreError> {
        validate_blob_limit(maximum_bytes)?;
        Ok(open_verified_from_directory_checked(
            open_shard(&self.inner, expected)?.fd(),
            expected,
            maximum_bytes,
            check,
        )?
        .map(|opened| VerifiedReader {
            digest: expected,
            size: opened.size,
            file: opened.file,
            _lease: self.clone(),
        }))
    }

    /// Executor-owned operational state, separate from CAS/retention roots.
    /// Its caller keeps this shared Store lease while using the returned handle.
    #[cfg(target_os = "linux")]
    pub(crate) fn build_directory(
        &self,
    ) -> Result<crate::platform::linux::fd::OpenedPath, StoreError> {
        ensure(self.inner.private_parent.fd(), "builds")
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn action_directory(
        &self,
    ) -> Result<crate::platform::linux::fd::OpenedPath, StoreError> {
        ensure(self.inner.private_parent.fd(), "actions")
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn view_directory(
        &self,
    ) -> Result<crate::platform::linux::fd::OpenedPath, StoreError> {
        ensure(self.inner.private_parent.fd(), "views")
    }

    /// Read a retained build closure using the same limits as root publication.
    #[cfg(target_os = "linux")]
    pub(crate) fn build_references(
        &self,
        name: &RootName,
    ) -> Result<Option<Vec<ContentDigest>>, StoreError> {
        read_root(
            &self.inner.roots,
            name,
            MAX_ROOT_BYTES,
            MAX_ROOT_REFERENCES,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn managed_build_roots(&self) -> Result<Vec<RootName>, StoreError> {
        let mut count = 0_u64;
        let names = crate::platform::linux::fd::read_directory(&self.inner.roots, |_| {
            count += 1;
            if count > MAX_GC_ROOTS {
                Err(())
            } else {
                Ok(())
            }
        })
        .map_err(|error| {
            StoreError::Io(io::Error::other(format!(
                "build root inventory refused: {error:?}"
            )))
        })?;
        Ok(names
            .into_iter()
            .filter_map(|name| {
                let name = name.to_str()?;
                name.strip_prefix("build_")?
                    .parse::<ContentDigest>()
                    .ok()?;
                RootName::new(name).ok()
            })
            .collect())
    }

    pub fn begin_staging(
        &self,
        expected: ContentDigest,
        maximum_bytes: u64,
    ) -> Result<StoreStaging, StoreError> {
        #[cfg(target_os = "linux")]
        {
            validate_blob_limit(maximum_bytes)?;
            let shard = open_shard(&self.inner, expected)?;
            let temporary = crate::platform::linux::fd::create_atomic_beneath(shard.fd())
                .map_err(map_create_atomic_error)?;
            Ok(StoreStaging {
                expected,
                maximum_bytes,
                size: 0,
                lease: self.clone(),
                hasher: Sha256::new(),
                failed: false,
                temporary,
            })
        }
    }

    /// Build outputs have no expected digest until their stream is validated.
    /// Stage in an existing shard so normal recovery can reclaim interrupted
    /// admissions; publication moves that same inode to its final digest shard.
    #[cfg(target_os = "linux")]
    pub(crate) fn begin_admission(&self, maximum_bytes: u64) -> Result<StoreAdmission, StoreError> {
        self.begin_staging(
            ContentDigest::from_sha256_hash([0; 32]),
            maximum_bytes,
        )
        .map(|staging| StoreAdmission {
            staging,
        })
    }

    pub fn ingest(
        &self,
        mut source: impl Read,
        expected: ContentDigest,
        maximum_bytes: u64,
    ) -> Result<StoreObject, StoreError> {
        #[cfg(target_os = "linux")]
        {
            let mut staging = self.begin_staging(expected, maximum_bytes)?;
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let requested = usize::try_from(maximum_bytes.saturating_sub(staging.size) + 1)
                    .unwrap_or(usize::MAX)
                    .min(buffer.len());
                let read = match source.read(&mut buffer[..requested]) {
                    Ok(read) => read,
                    Err(source) => return staging.fail_with_cleanup(StoreError::Io(source)),
                };
                if read == 0 {
                    break;
                }
                if let Err(primary) = staging.append(&buffer[..read]) {
                    return staging.fail_with_cleanup(primary);
                }
            }
            staging.finish()
        }
    }

    pub fn verify(&self, expected: ContentDigest) -> Result<Option<StoreObject>, StoreError> {
        #[cfg(target_os = "linux")]
        {
            verify_from_directory(
                open_shard(&self.inner, expected)?.fd(),
                expected,
                MAX_STORE_BLOB_BYTES,
            )
        }
    }

    pub fn read_verified(
        &self,
        expected: ContentDigest,
        maximum_bytes: u64,
    ) -> Result<Option<VerifiedBytes>, StoreError> {
        #[cfg(target_os = "linux")]
        {
            validate_blob_limit(maximum_bytes)?;
            read_verified_from_directory(
                open_shard(&self.inner, expected)?.fd(),
                expected,
                maximum_bytes,
            )
        }
    }

    pub fn open_verified(
        &self,
        expected: ContentDigest,
        maximum_bytes: u64,
    ) -> Result<Option<VerifiedReader>, StoreError> {
        #[cfg(target_os = "linux")]
        {
            validate_blob_limit(maximum_bytes)?;
            Ok(open_verified_from_directory(
                open_shard(&self.inner, expected)?.fd(),
                expected,
                maximum_bytes,
            )?
            .map(|opened| VerifiedReader {
                digest: expected,
                size: opened.size,
                file: opened.file,
                _lease: self.clone(),
            }))
        }
    }

    pub fn publish_root(
        &self,
        name: &RootName,
        digests: &[ContentDigest],
    ) -> Result<RootPublicationState, StoreError> {
        self.publish_root_checked(name, digests, || Ok(()))
    }

    /// Observe cancellation during verification, then finish the atomic durable
    /// publication without hiding a committed or uncertain result behind it.
    pub(crate) fn publish_root_checked(
        &self,
        name: &RootName,
        digests: &[ContentDigest],
        mut check: impl FnMut() -> io::Result<()>,
    ) -> Result<RootPublicationState, StoreError> {
        #[cfg(target_os = "linux")]
        {
            check()?;
            if digests.len() as u64 > MAX_ROOT_REFERENCES
                || digests.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(StoreError::NonCanonicalRoot {
                    name: name.clone(),
                });
            }
            let bytes = encode_root(name, digests)?;
            let mut synced_shards = BTreeSet::new();
            for digest in digests {
                let shard = open_shard(&self.inner, *digest)?;
                let opened = open_verified_from_directory_checked(
                    shard.fd(),
                    *digest,
                    MAX_STORE_BLOB_BYTES,
                    &mut check,
                )?
                .ok_or(StoreError::MissingRootObject {
                    root: name.clone(),
                    digest: *digest,
                })?;
                crate::platform::linux::fd::sync_file(opened.file.as_fd())?;
                synced_shards.insert(digest.to_string()[..2].to_owned());
            }
            for shard_name in synced_shards {
                check()?;
                let shard = open_named_directory(self.inner.objects.fd(), &shard_name)?;
                crate::platform::linux::fd::sync_directory(shard.fd())?;
            }
            crate::platform::linux::fd::sync_directory(self.inner.objects.fd())?;
            check()?;
            let mut temporary = crate::platform::linux::fd::create_atomic_beneath_with_prefix(
                self.inner.roots.fd(),
                ROOT_TEMP_PREFIX,
            )
            .map_err(map_create_atomic_error)?;
            if let Err(source) = temporary.write_all(&bytes) {
                return Err(fail_atomic_publication(
                    &mut temporary,
                    StoreError::Io(source),
                ));
            }
            match temporary.publish_noreplace(Path::new(name.as_str())) {
                Ok(crate::platform::linux::fd::PublishStatus::Published) => {
                    Ok(RootPublicationState::Published)
                }
                Ok(crate::platform::linux::fd::PublishStatus::AlreadyExists) => {
                    temporary
                        .discard()
                        .map_err(map_cleanup_uncertain)?;
                    let existing = read_root(
                        &self.inner.roots,
                        name,
                        MAX_ROOT_BYTES,
                        MAX_ROOT_REFERENCES,
                    )?
                    .ok_or_else(|| StoreError::RootDisappeared {
                        name: name.clone(),
                    })?;
                    if existing == digests {
                        // An earlier publication may have become visible before a
                        // failed directory sync. Existing bytes alone do not prove
                        // durable retention for a new consumer or cache hit.
                        let file = crate::platform::linux::fd::open_existing_regular(
                            self.inner.roots.fd(),
                            Path::new(name.as_str()),
                        )?;
                        crate::platform::linux::fd::sync_file(file.fd())
                            .and_then(|()| {
                                crate::platform::linux::fd::sync_directory(self.inner.roots.fd())
                            })
                            .and_then(|()| {
                                crate::platform::linux::fd::sync_directory(
                                    self.inner.roots_parent.fd(),
                                )
                            })
                            .map_err(|source| StoreError::PublicationUncertain {
                                source,
                            })?;
                        Ok(RootPublicationState::Existing)
                    } else {
                        Err(StoreError::RootConflict {
                            name: name.clone(),
                        })
                    }
                }
                Err(error) if error.committed => Err(StoreError::PublicationUncertain {
                    source: error.source,
                }),
                Err(error) => Err(fail_atomic_publication(
                    &mut temporary,
                    StoreError::Io(error.source),
                )),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootPublicationState {
    Published,
    Existing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcLimits {
    pub roots: u64,
    pub root_bytes: u64,
    pub references: u64,
    pub objects: u64,
    pub object_bytes: u64,
    pub candidates: u64,
    pub work: u64,
}

impl Default for GcLimits {
    fn default() -> Self {
        Self {
            roots: MAX_GC_ROOTS,
            root_bytes: MAX_GC_ROOT_BYTES,
            references: MAX_GC_REFERENCES,
            objects: MAX_GC_OBJECTS,
            object_bytes: MAX_GC_OBJECT_BYTES,
            candidates: MAX_GC_CANDIDATES,
            work: MAX_GC_WORK,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcRequest {
    pub collect: bool,
    pub remove_roots: Vec<RootName>,
    pub limits: GcLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryLimits {
    pub entries: u64,
    pub candidates: u64,
    pub work: u64,
}

impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            entries: MAX_RECOVERY_ENTRIES,
            candidates: MAX_RECOVERY_CANDIDATES,
            work: MAX_RECOVERY_WORK,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcCandidate {
    pub digest: ContentDigest,
    pub bytes: u64,
}

#[derive(Debug)]
pub struct MaintenanceFailure {
    pub path: String,
    pub operation: MaintenanceFailureOperation,
    pub source: io::Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintenanceFailureOperation {
    Unlink,
    Synchronize,
}

#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub removed: Vec<String>,
    pub failures: Vec<MaintenanceFailure>,
    pub uncertain: bool,
}

#[derive(Debug, Default)]
pub struct GcReport {
    pub removed_interests: usize,
    pub candidates: Vec<GcCandidate>,
    pub candidate_bytes: u64,
    pub removed_roots: Vec<RootName>,
    pub removed_objects: Vec<ContentDigest>,
    pub failures: Vec<MaintenanceFailure>,
    pub uncertain: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct RemovalCandidate {
    directory: Arc<crate::platform::linux::fd::OpenedPath>,
    directory_name: String,
    name: String,
    identity: crate::platform::linux::fd::FileIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct GcRootRecord {
    digests: Vec<ContentDigest>,
    identity: crate::platform::linux::fd::FileIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct GcObjectRecord {
    identity: crate::platform::linux::fd::FileIdentity,
    size: u64,
    shard_name: String,
    directory: Arc<crate::platform::linux::fd::OpenedPath>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct GcInventory {
    interests: retention::InterestInventory,
    roots: BTreeMap<RootName, GcRootRecord>,
    objects: BTreeMap<ContentDigest, GcObjectRecord>,
    roots_directory: Arc<crate::platform::linux::fd::OpenedPath>,
}

#[cfg(target_os = "linux")]
struct WorkBudget {
    used: u64,
    limit: u64,
    resource: &'static str,
}

#[cfg(target_os = "linux")]
impl WorkBudget {
    const fn new(limit: u64, resource: &'static str) -> Self {
        Self {
            used: 0,
            limit,
            resource,
        }
    }

    fn charge(&mut self, amount: u64) -> Result<(), StoreError> {
        self.used = self
            .used
            .checked_add(amount)
            .ok_or(StoreError::LimitExceeded {
                resource: self.resource,
            })?;
        charge(self.used, self.limit, self.resource)
    }

    const fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("the live object interest is invalid, missing, or replaced")]
    InterestCorrupt,
    #[error("object interests belong to different Stores")]
    InterestStoreMismatch,
    #[error("Store initialization requires a bounded absolute location without '..'")]
    InvalidLocation,
    #[error("the Store uses an incompatible prelaunch layout; select a fresh Store")]
    UnsupportedLayout,
    #[error("the store is busy with an incompatible lease")]
    Busy,
    #[error("the permanent store lease inode is missing, replaced, or unsafe")]
    LeaseCorrupt,
    #[error("the Linux kernel does not provide the required secure traversal: {source}")]
    UnsupportedKernel {
        #[source]
        source: io::Error,
    },
    #[error("the store contains a symbolic link in a protected path")]
    SymbolicLink,
    #[error("store entries have an unsafe type, owner, mode, or link count")]
    UntrustedEntry,
    #[error("store directories must belong to the effective user and deny group/other writes")]
    UntrustedDirectory,
    #[error(
        "configured blob limit {configured} exceeds the hard {MAX_STORE_BLOB_BYTES}-byte limit"
    )]
    InvalidLimit {
        configured: u64,
    },
    #[error("configured maintenance limit for {resource} exceeds its hard maximum")]
    InvalidMaintenanceLimit {
        resource: &'static str,
    },
    #[error("the bounded {resource} limit was exceeded")]
    LimitExceeded {
        resource: &'static str,
    },
    #[error("blob exceeds the configured {limit}-byte limit")]
    BlobTooLarge {
        limit: u64,
    },
    #[error("staging cannot be finished after an append failure")]
    StagingFailed,
    #[error("blob digest mismatch: expected {expected}, calculated {actual}")]
    DigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("stored object {expected} is corrupt; calculated {actual}")]
    CorruptObject {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("stored object {digest} exceeds the configured {limit}-byte limit")]
    CorruptObjectTooLarge {
        digest: ContentDigest,
        limit: u64,
    },
    #[error("stored object {digest} is not one trusted regular file")]
    UnsafeObject {
        digest: ContentDigest,
    },
    #[error("stored object {digest} disappeared during concurrent publication")]
    ObjectDisappeared {
        digest: ContentDigest,
    },
    #[error("root {name} is not canonical")]
    NonCanonicalRoot {
        name: RootName,
    },
    #[error("root {name} is malformed or corrupt")]
    CorruptRoot {
        name: RootName,
    },
    #[error("root {name} conflicts with an existing immutable root")]
    RootConflict {
        name: RootName,
    },
    #[error("root {name} disappeared during publication")]
    RootDisappeared {
        name: RootName,
    },
    #[error("root {root} references missing object {digest}")]
    MissingRootObject {
        root: RootName,
        digest: ContentDigest,
    },
    #[error("requested root {name} does not exist")]
    MissingRoot {
        name: RootName,
    },
    #[error("a root removal was requested more than once")]
    DuplicateRootRemoval,
    #[error("recognized temporary entries remain; run recovery first")]
    RecoveryRequired,
    #[error("unexpected protected store entry {path}")]
    UnexpectedEntry {
        path: String,
    },
    #[error("recognized temporary entry {path} is malformed or unsafe")]
    UnsafeTemporary {
        path: String,
    },
    #[error("publication may be visible but durability could not be confirmed: {source}")]
    PublicationUncertain {
        #[source]
        source: io::Error,
    },
    #[error("explicit staging cleanup could not be confirmed: {cleanup}")]
    CleanupUncertain {
        #[source]
        cleanup: StoreCleanupError,
    },
    #[error("operation failed ({primary}) and explicit cleanup also failed: {cleanup}")]
    CleanupFailed {
        primary: Box<StoreError>,
        cleanup: StoreCleanupError,
    },
    #[error("store I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Error)]
pub enum StoreCleanupError {
    #[error("temporary removal failed: {source}")]
    Removal {
        #[source]
        source: io::Error,
    },
    #[error("cleanup directory synchronization failed: {source}")]
    Synchronization {
        #[source]
        source: io::Error,
    },
    #[error(
        "temporary removal failed ({removal}) and cleanup directory synchronization failed ({synchronization})"
    )]
    RemovalAndSynchronization {
        removal: io::Error,
        synchronization: io::Error,
    },
}

#[cfg(target_os = "linux")]
fn validate_blob_limit(maximum_bytes: u64) -> Result<(), StoreError> {
    if maximum_bytes > MAX_STORE_BLOB_BYTES {
        Err(StoreError::InvalidLimit {
            configured: maximum_bytes,
        })
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn validate_gc_limits(limits: GcLimits) -> Result<(), StoreError> {
    for (value, maximum, resource) in [
        (limits.roots, MAX_GC_ROOTS, "GC roots"),
        (
            limits.root_bytes,
            MAX_GC_ROOT_BYTES,
            "GC root bytes",
        ),
        (
            limits.references,
            MAX_GC_REFERENCES,
            "GC references",
        ),
        (limits.objects, MAX_GC_OBJECTS, "GC objects"),
        (
            limits.object_bytes,
            MAX_GC_OBJECT_BYTES,
            "GC object bytes",
        ),
        (
            limits.candidates,
            MAX_GC_CANDIDATES,
            "GC candidates",
        ),
        (limits.work, MAX_GC_WORK, "GC work"),
    ] {
        if value > maximum {
            return Err(StoreError::InvalidMaintenanceLimit {
                resource,
            });
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_recovery_limits(limits: RecoveryLimits) -> Result<(), StoreError> {
    for (value, maximum, resource) in [
        (
            limits.entries,
            MAX_RECOVERY_ENTRIES,
            "recovery entries",
        ),
        (
            limits.candidates,
            MAX_RECOVERY_CANDIDATES,
            "recovery candidates",
        ),
        (limits.work, MAX_RECOVERY_WORK, "recovery work"),
    ] {
        if value > maximum {
            return Err(StoreError::InvalidMaintenanceLimit {
                resource,
            });
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn charge(value: u64, limit: u64, resource: &'static str) -> Result<(), StoreError> {
    if value > limit {
        Err(StoreError::LimitExceeded {
            resource,
        })
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn encode_root(name: &RootName, digests: &[ContentDigest]) -> Result<Vec<u8>, StoreError> {
    let expected = ROOT_HEADER.len() + 5 + name.as_str().len() + 1 + digests.len() * 72;
    if expected as u64 > MAX_ROOT_BYTES {
        return Err(StoreError::LimitExceeded {
            resource: "root bytes",
        });
    }
    let mut bytes = Vec::with_capacity(expected);
    bytes.extend_from_slice(ROOT_HEADER.as_bytes());
    bytes.extend_from_slice(b"name=");
    bytes.extend_from_slice(name.as_str().as_bytes());
    bytes.push(b'\n');
    for digest in digests {
        bytes.extend_from_slice(b"sha256=");
        bytes.extend_from_slice(digest.to_string().as_bytes());
        bytes.push(b'\n');
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn parse_root(
    filename: &RootName,
    bytes: &[u8],
    reference_limit: u64,
) -> Result<Vec<ContentDigest>, StoreError> {
    if !bytes.is_ascii() || !bytes.ends_with(b"\n") {
        return Err(StoreError::CorruptRoot {
            name: filename.clone(),
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| StoreError::CorruptRoot {
        name: filename.clone(),
    })?;
    let mut lines = text.lines();
    if lines.next() != Some(ROOT_HEADER.trim_end())
        || lines.next() != Some(&format!("name={filename}"))
    {
        return Err(StoreError::CorruptRoot {
            name: filename.clone(),
        });
    }
    let mut digests = Vec::new();
    for line in lines {
        charge(
            digests.len() as u64 + 1,
            reference_limit,
            "root references",
        )?;
        let digest = line
            .strip_prefix("sha256=")
            .ok_or_else(|| StoreError::CorruptRoot {
                name: filename.clone(),
            })?
            .parse()
            .map_err(|_| StoreError::CorruptRoot {
                name: filename.clone(),
            })?;
        if digests
            .last()
            .is_some_and(|previous| *previous >= digest)
        {
            return Err(StoreError::CorruptRoot {
                name: filename.clone(),
            });
        }
        digests.push(digest);
    }
    if encode_root(filename, &digests)? != bytes {
        return Err(StoreError::CorruptRoot {
            name: filename.clone(),
        });
    }
    Ok(digests)
}

#[cfg(target_os = "linux")]
fn ensure(
    directory: std::os::fd::BorrowedFd<'_>,
    name: &str,
) -> Result<crate::platform::linux::fd::OpenedPath, StoreError> {
    crate::platform::linux::fd::ensure_directory_beneath(directory, Path::new(name))
        .map_err(map_directory_error)
}

#[cfg(target_os = "linux")]
fn reject_unsupported_layout(
    root: &crate::platform::linux::fd::OpenedPath,
) -> Result<(), StoreError> {
    // Reject experimental layouts before creating even a shard or lease.
    for path in [
        "roots/v1",
        ".syrox-store/v1",
        ".syrox-store/builds-v1",
        ".syrox-store/actions-v1",
        ".syrox-store/views-v1",
    ] {
        match crate::platform::linux::fd::open_beneath(root.fd(), Path::new(path), true) {
            Ok(_) => return Err(StoreError::UnsupportedLayout),
            Err(crate::platform::linux::fd::OpenError::Other(error))
                if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_open_error(error)),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_directory(path: &crate::platform::linux::fd::OpenedPath) -> Result<(), StoreError> {
    if path.metadata().is_trusted_directory() {
        Ok(())
    } else {
        Err(StoreError::UntrustedDirectory)
    }
}

#[cfg(target_os = "linux")]
fn open_named_directory(
    parent: std::os::fd::BorrowedFd<'_>,
    name: &str,
) -> Result<crate::platform::linux::fd::OpenedPath, StoreError> {
    let opened = crate::platform::linux::fd::open_beneath(parent, Path::new(name), true)
        .map_err(map_open_error)?;
    require_directory(&opened)?;
    Ok(opened)
}

#[cfg(target_os = "linux")]
fn open_shard(
    inner: &StoreInner,
    digest: ContentDigest,
) -> Result<crate::platform::linux::fd::OpenedPath, StoreError> {
    open_named_directory(inner.objects.fd(), &digest.to_string()[..2])
}

#[cfg(target_os = "linux")]
fn open_lease(inner: &StoreInner) -> Result<crate::platform::linux::fd::OpenedPath, StoreError> {
    drop(retention::open_interest_directory(inner)?);
    let opened = crate::platform::linux::fd::open_existing_regular(
        inner.coordination.fd(),
        Path::new("lease"),
    )
    .map_err(|_| StoreError::LeaseCorrupt)?;
    if opened.metadata().identity() != inner.lease_identity {
        return Err(StoreError::LeaseCorrupt);
    }
    Ok(opened)
}

#[cfg(target_os = "linux")]
fn open_regular(
    directory: &crate::platform::linux::fd::OpenedPath,
    name: &str,
) -> Result<crate::platform::linux::fd::OpenedPath, StoreError> {
    let opened = crate::platform::linux::fd::open_beneath(directory.fd(), Path::new(name), false)
        .map_err(map_open_error)?;
    if !opened.metadata().is_trusted_regular() {
        return Err(StoreError::UntrustedEntry);
    }
    Ok(opened)
}

#[cfg(target_os = "linux")]
fn read_root(
    directory: &crate::platform::linux::fd::OpenedPath,
    name: &RootName,
    byte_limit: u64,
    reference_limit: u64,
) -> Result<Option<Vec<ContentDigest>>, StoreError> {
    use crate::platform::linux::fd::OpenError;
    let opened = match crate::platform::linux::fd::open_beneath(
        directory.fd(),
        Path::new(name.as_str()),
        false,
    ) {
        Ok(opened) => opened,
        Err(OpenError::Other(source)) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(source) => return Err(map_open_error(source)),
    };
    if !opened.metadata().is_trusted_regular() {
        return Err(StoreError::CorruptRoot {
            name: name.clone(),
        });
    }
    read_root_opened(opened, name, byte_limit, reference_limit).map(Some)
}

#[cfg(target_os = "linux")]
fn read_root_opened(
    opened: crate::platform::linux::fd::OpenedPath,
    name: &RootName,
    byte_limit: u64,
    reference_limit: u64,
) -> Result<Vec<ContentDigest>, StoreError> {
    let size = opened.metadata().size();
    if size > MAX_ROOT_BYTES || size > byte_limit {
        return Err(StoreError::LimitExceeded {
            resource: "root bytes",
        });
    }
    let capacity = usize::try_from(size).map_err(|_| StoreError::LimitExceeded {
        resource: "root bytes",
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    opened
        .into_file()
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != size {
        return Err(StoreError::CorruptRoot {
            name: name.clone(),
        });
    }
    parse_root(name, &bytes, reference_limit)
}

#[cfg(target_os = "linux")]
fn verify_opened(
    object: crate::platform::linux::fd::OpenedPath,
    expected: ContentDigest,
    maximum_bytes: u64,
    check: impl FnMut() -> io::Result<()>,
) -> Result<OpenedVerified, StoreError> {
    verify_opened_collect(object, expected, maximum_bytes, None, check)
}

#[cfg(target_os = "linux")]
fn verify_opened_collect(
    object: crate::platform::linux::fd::OpenedPath,
    expected: ContentDigest,
    maximum_bytes: u64,
    mut collected: Option<&mut Vec<u8>>,
    mut check: impl FnMut() -> io::Result<()>,
) -> Result<OpenedVerified, StoreError> {
    if !object.metadata().is_trusted_regular() {
        return Err(StoreError::UnsafeObject {
            digest: expected,
        });
    }
    if object.metadata().size() > maximum_bytes {
        return Err(StoreError::CorruptObjectTooLarge {
            digest: expected,
            limit: maximum_bytes,
        });
    }
    let mut file = object.into_file();
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        check()?;
        let requested = usize::try_from(maximum_bytes.saturating_sub(size) + 1)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = file.read(&mut buffer[..requested])?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(StoreError::CorruptObjectTooLarge {
                digest: expected,
                limit: maximum_bytes,
            })?;
        if size > maximum_bytes {
            return Err(StoreError::CorruptObjectTooLarge {
                digest: expected,
                limit: maximum_bytes,
            });
        }
        #[cfg(test)]
        VERIFIED_READ_BYTES.with(|count| count.set(count.get().saturating_add(read as u64)));
        hasher.update(&buffer[..read]);
        if let Some(bytes) = collected.as_mut() {
            bytes.extend_from_slice(&buffer[..read]);
        }
    }
    let actual = ContentDigest::from_sha256_hash(hasher.finalize().into());
    if actual != expected {
        return Err(StoreError::CorruptObject {
            expected,
            actual,
        });
    }
    if collected.is_none() {
        file.rewind()?;
    }
    Ok(OpenedVerified {
        size,
        file,
    })
}

#[cfg(target_os = "linux")]
struct OpenedVerified {
    size: u64,
    file: std::fs::File,
}

#[cfg(target_os = "linux")]
fn open_verified_from_directory(
    directory: std::os::fd::BorrowedFd<'_>,
    expected: ContentDigest,
    maximum_bytes: u64,
) -> Result<Option<OpenedVerified>, StoreError> {
    open_verified_from_directory_checked(directory, expected, maximum_bytes, || Ok(()))
}

#[cfg(target_os = "linux")]
fn open_verified_from_directory_checked(
    directory: std::os::fd::BorrowedFd<'_>,
    expected: ContentDigest,
    maximum_bytes: u64,
    check: impl FnMut() -> io::Result<()>,
) -> Result<Option<OpenedVerified>, StoreError> {
    use crate::platform::linux::fd::OpenError;
    let object = match crate::platform::linux::fd::open_beneath(
        directory,
        Path::new(&expected.to_string()),
        false,
    ) {
        Ok(object) => object,
        Err(OpenError::Other(source)) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(source) => return Err(map_open_error(source)),
    };
    verify_opened(object, expected, maximum_bytes, check).map(Some)
}

#[cfg(target_os = "linux")]
fn verify_from_directory(
    directory: std::os::fd::BorrowedFd<'_>,
    expected: ContentDigest,
    maximum_bytes: u64,
) -> Result<Option<StoreObject>, StoreError> {
    Ok(
        open_verified_from_directory(directory, expected, maximum_bytes)?.map(|opened| {
            StoreObject {
                digest: expected,
                size: opened.size,
                state: StoreObjectState::Existing,
            }
        }),
    )
}

#[cfg(target_os = "linux")]
fn read_verified_from_directory(
    directory: std::os::fd::BorrowedFd<'_>,
    expected: ContentDigest,
    maximum_bytes: u64,
) -> Result<Option<VerifiedBytes>, StoreError> {
    use crate::platform::linux::fd::OpenError;
    let object = match crate::platform::linux::fd::open_beneath(
        directory,
        Path::new(&expected.to_string()),
        false,
    ) {
        Ok(object) => object,
        Err(OpenError::Other(source)) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(source) => return Err(map_open_error(source)),
    };
    let mut bytes = Vec::with_capacity(
        usize::try_from(object.metadata().size())
            .unwrap_or(64 * 1024)
            .min(64 * 1024),
    );
    verify_opened_collect(
        object,
        expected,
        maximum_bytes,
        Some(&mut bytes),
        || Ok(()),
    )?;
    Ok(Some(VerifiedBytes {
        digest: expected,
        bytes,
    }))
}

#[cfg(target_os = "linux")]
fn exact_temporary(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

#[cfg(target_os = "linux")]
fn directory_names_bounded(
    directory: &crate::platform::linux::fd::OpenedPath,
    limit: u64,
    resource: &'static str,
    work: &mut WorkBudget,
) -> Result<Vec<String>, StoreError> {
    let mut count = 0_u64;
    crate::platform::linux::fd::read_directory(directory, |_| {
        work.charge(1)?;
        count = count
            .checked_add(1)
            .ok_or(StoreError::LimitExceeded {
                resource,
            })?;
        charge(count, limit, resource)
    })
    .map_err(|error| match error {
        crate::platform::linux::fd::ReadDirectoryError::Io(source) => StoreError::Io(source),
        crate::platform::linux::fd::ReadDirectoryError::Admission(source) => source,
    })?
    .into_iter()
    .map(|name| {
        name.into_string()
            .map_err(|_| StoreError::UnexpectedEntry {
                path: "non-UTF-8 entry".into(),
            })
    })
    .collect()
}

#[cfg(target_os = "linux")]
fn inventory_recovery(
    inner: &StoreInner,
    limits: RecoveryLimits,
    work: &mut WorkBudget,
) -> Result<Vec<RemovalCandidate>, StoreError> {
    let mut candidates = Vec::new();
    let mut entries = 0_u64;
    validate_protected_layout(inner, work)?;
    let shards: Vec<_> = (0_u16..=255)
        .map(|value| format!("{value:02x}"))
        .collect();
    for shard_name in shards {
        let shard = Arc::new(open_named_directory(
            inner.objects.fd(),
            &shard_name,
        )?);
        for name in directory_names_bounded(
            &shard,
            limits.entries.saturating_sub(entries),
            "recovery entries",
            work,
        )? {
            entries = entries
                .checked_add(1)
                .ok_or(StoreError::LimitExceeded {
                    resource: "recovery entries",
                })?;
            charge(entries, limits.entries, "recovery entries")?;
            work.charge(1)?;
            if exact_temporary(&name, OBJECT_TEMP_PREFIX) {
                charge(
                    candidates.len() as u64 + 1,
                    limits.candidates,
                    "recovery candidates",
                )?;
                work.charge(1)?;
                let opened =
                    open_regular(&shard, &name).map_err(|_| StoreError::UnsafeTemporary {
                        path: format!("objects/sha256/{shard_name}/{name}"),
                    })?;
                candidates.push(RemovalCandidate {
                    directory: Arc::clone(&shard),
                    directory_name: format!("objects/sha256/{shard_name}"),
                    name,
                    identity: opened.metadata().identity(),
                });
            } else {
                let digest: ContentDigest =
                    name.parse()
                        .map_err(|_| StoreError::UnexpectedEntry {
                            path: format!("objects/sha256/{shard_name}/{name}"),
                        })?;
                if digest.to_string()[..2] != shard_name {
                    return Err(StoreError::UnexpectedEntry {
                        path: format!("objects/sha256/{shard_name}/{name}"),
                    });
                }
                drop(
                    open_regular(&shard, &name).map_err(|_| StoreError::UnsafeObject {
                        digest,
                    })?,
                );
            }
        }
    }
    let roots = Arc::new(
        crate::platform::linux::fd::open_beneath(inner.roots.fd(), Path::new("."), true)
            .map_err(map_open_error)?,
    );
    for name in directory_names_bounded(
        &roots,
        limits.entries.saturating_sub(entries),
        "recovery entries",
        work,
    )? {
        entries = entries
            .checked_add(1)
            .ok_or(StoreError::LimitExceeded {
                resource: "recovery entries",
            })?;
        charge(entries, limits.entries, "recovery entries")?;
        work.charge(1)?;
        if exact_temporary(&name, ROOT_TEMP_PREFIX) {
            charge(
                candidates.len() as u64 + 1,
                limits.candidates,
                "recovery candidates",
            )?;
            work.charge(1)?;
            let opened = open_regular(&roots, &name).map_err(|_| StoreError::UnsafeTemporary {
                path: format!("roots/retained/{name}"),
            })?;
            candidates.push(RemovalCandidate {
                directory: Arc::clone(&roots),
                directory_name: "roots/retained".into(),
                name,
                identity: opened.metadata().identity(),
            });
        } else {
            let root = RootName::new(name.clone()).map_err(|_| StoreError::UnexpectedEntry {
                path: format!("roots/retained/{name}"),
            })?;
            let opened = open_regular(&roots, &name).map_err(|_| StoreError::CorruptRoot {
                name: root.clone(),
            })?;
            let digests = read_root_opened(
                opened,
                &root,
                MAX_ROOT_BYTES,
                MAX_ROOT_REFERENCES.min(work.remaining()),
            )?;
            work.charge(digests.len() as u64)?;
        }
    }
    Ok(candidates)
}

#[cfg(target_os = "linux")]
fn validate_protected_layout(inner: &StoreInner, work: &mut WorkBudget) -> Result<(), StoreError> {
    for (directory, expected, path) in [
        (&inner.objects_parent, "sha256", "objects"),
        (&inner.roots_parent, "retained", "roots"),
    ] {
        if directory_names_bounded(directory, 1, "layout entries", work)? != [expected] {
            return Err(StoreError::UnexpectedEntry {
                path: path.into(),
            });
        }
    }
    // Operational namespaces have their own cleanup contracts and are not GC
    // roots. Admit only known trusted directories, without traversing their data.
    let private = directory_names_bounded(
        &inner.private_parent,
        5,
        "private layout entries",
        work,
    )?;
    if !private.iter().any(|name| name == "state")
        || private.iter().any(|name| {
            !matches!(
                name.as_str(),
                "state" | "builds" | "actions" | "views" | "interests"
            )
        })
    {
        return Err(StoreError::UnexpectedEntry {
            path: ".syrox-store".into(),
        });
    }
    for name in private {
        drop(open_named_directory(
            inner.private_parent.fd(),
            &name,
        )?);
    }
    if directory_names_bounded(
        &inner.coordination,
        1,
        "coordination entries",
        work,
    )? != ["lease"]
    {
        return Err(StoreError::UnexpectedEntry {
            path: ".syrox-store/state".into(),
        });
    }
    drop(open_lease(inner)?);
    let shards = directory_names_bounded(&inner.objects, 256, "object shards", work)?;
    let expected: Vec<_> = (0_u16..=255)
        .map(|value| format!("{value:02x}"))
        .collect();
    if shards != expected {
        return Err(StoreError::UnexpectedEntry {
            path: "objects/sha256 shard set".into(),
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn inventory_gc(
    inner: &StoreInner,
    limits: GcLimits,
    work: &mut WorkBudget,
) -> Result<GcInventory, StoreError> {
    validate_protected_layout(inner, work)?;
    let mut roots = BTreeMap::new();
    let mut root_bytes = 0_u64;
    let mut references = 0_u64;
    let roots_directory = Arc::new(
        crate::platform::linux::fd::open_beneath(inner.roots.fd(), Path::new("."), true)
            .map_err(map_open_error)?,
    );
    for filename in directory_names_bounded(&roots_directory, limits.roots, "GC roots", work)? {
        if exact_temporary(&filename, ROOT_TEMP_PREFIX) {
            return Err(StoreError::RecoveryRequired);
        }
        charge(roots.len() as u64 + 1, limits.roots, "GC roots")?;
        work.charge(1)?;
        let name = RootName::new(filename.clone()).map_err(|_| StoreError::UnexpectedEntry {
            path: format!("roots/retained/{filename}"),
        })?;
        let opened =
            open_regular(&roots_directory, &filename).map_err(|_| StoreError::CorruptRoot {
                name: name.clone(),
            })?;
        let identity = opened.metadata().identity();
        let size = opened.metadata().size();
        let remaining_bytes = limits.root_bytes.saturating_sub(root_bytes);
        let remaining_references = limits.references.saturating_sub(references);
        let digests = read_root_opened(
            opened,
            &name,
            MAX_ROOT_BYTES.min(remaining_bytes),
            MAX_ROOT_REFERENCES
                .min(remaining_references)
                .min(work.remaining()),
        )?;
        root_bytes = root_bytes
            .checked_add(size)
            .ok_or(StoreError::LimitExceeded {
                resource: "GC root bytes",
            })?;
        charge(root_bytes, limits.root_bytes, "GC root bytes")?;
        references = references
            .checked_add(digests.len() as u64)
            .ok_or(StoreError::LimitExceeded {
                resource: "GC references",
            })?;
        charge(references, limits.references, "GC references")?;
        work.charge(digests.len() as u64)?;
        roots.insert(
            name,
            GcRootRecord {
                digests,
                identity,
            },
        );
    }
    let interests = retention::inventory(
        inner,
        GcLimits {
            roots: limits.roots.saturating_sub(roots.len() as u64),
            root_bytes: limits.root_bytes.saturating_sub(root_bytes),
            references: limits.references.saturating_sub(references),
            ..limits
        },
        work,
    )?;
    let mut objects = BTreeMap::new();
    let mut object_bytes = 0_u64;
    for shard_value in 0_u16..=255 {
        let shard_name = format!("{shard_value:02x}");
        let shard = Arc::new(open_named_directory(
            inner.objects.fd(),
            &shard_name,
        )?);
        for filename in directory_names_bounded(
            &shard,
            limits
                .objects
                .saturating_sub(objects.len() as u64),
            "GC objects",
            work,
        )? {
            if exact_temporary(&filename, OBJECT_TEMP_PREFIX) {
                return Err(StoreError::RecoveryRequired);
            }
            charge(
                objects.len() as u64 + 1,
                limits.objects,
                "GC objects",
            )?;
            work.charge(1)?;
            let digest: ContentDigest =
                filename
                    .parse()
                    .map_err(|_| StoreError::UnexpectedEntry {
                        path: format!("objects/sha256/{shard_name}/{filename}"),
                    })?;
            if digest.to_string()[..2] != shard_name {
                return Err(StoreError::UnexpectedEntry {
                    path: format!("objects/sha256/{shard_name}/{filename}"),
                });
            }
            let opened = open_regular(&shard, &filename)?;
            let identity = opened.metadata().identity();
            let verified = verify_opened(opened, digest, MAX_STORE_BLOB_BYTES, || Ok(()))?;
            object_bytes =
                object_bytes
                    .checked_add(verified.size)
                    .ok_or(StoreError::LimitExceeded {
                        resource: "GC object bytes",
                    })?;
            charge(
                object_bytes,
                limits.object_bytes,
                "GC object bytes",
            )?;
            objects.insert(
                digest,
                GcObjectRecord {
                    identity,
                    size: verified.size,
                    shard_name: shard_name.clone(),
                    directory: Arc::clone(&shard),
                },
            );
        }
    }
    for (root, record) in &roots {
        for digest in &record.digests {
            work.charge(1)?;
            if !objects.contains_key(digest) {
                return Err(StoreError::MissingRootObject {
                    root: root.clone(),
                    digest: *digest,
                });
            }
        }
    }
    for digest in &interests.references {
        work.charge(1)?;
        if !objects.contains_key(digest) {
            return Err(StoreError::InterestCorrupt);
        }
    }
    Ok(GcInventory {
        interests,
        roots,
        objects,
        roots_directory,
    })
}

#[cfg(target_os = "linux")]
fn map_open_error(source: crate::platform::linux::fd::OpenError) -> StoreError {
    match source {
        crate::platform::linux::fd::OpenError::Unsupported(source) => {
            StoreError::UnsupportedKernel {
                source,
            }
        }
        crate::platform::linux::fd::OpenError::Symlink => StoreError::SymbolicLink,
        crate::platform::linux::fd::OpenError::Other(source) => StoreError::Io(source),
    }
}

#[cfg(target_os = "linux")]
fn map_directory_error(source: crate::platform::linux::fd::DirectoryError) -> StoreError {
    match source {
        crate::platform::linux::fd::DirectoryError::Symlink => StoreError::SymbolicLink,
        crate::platform::linux::fd::DirectoryError::Untrusted => StoreError::UntrustedDirectory,
        crate::platform::linux::fd::DirectoryError::Io(source) => StoreError::Io(source),
    }
}

#[cfg(target_os = "linux")]
fn map_cleanup_error(source: crate::platform::linux::fd::CleanupError) -> StoreCleanupError {
    match source {
        crate::platform::linux::fd::CleanupError::Removal(source) => StoreCleanupError::Removal {
            source,
        },
        crate::platform::linux::fd::CleanupError::Synchronization(source) => {
            StoreCleanupError::Synchronization {
                source,
            }
        }
        crate::platform::linux::fd::CleanupError::RemovalAndSynchronization {
            removal,
            synchronization,
        } => StoreCleanupError::RemovalAndSynchronization {
            removal,
            synchronization,
        },
    }
}

#[cfg(target_os = "linux")]
fn map_cleanup_uncertain(source: crate::platform::linux::fd::CleanupError) -> StoreError {
    StoreError::CleanupUncertain {
        cleanup: map_cleanup_error(source),
    }
}

#[cfg(target_os = "linux")]
fn map_create_atomic_error(source: crate::platform::linux::fd::CreateAtomicError) -> StoreError {
    let primary = StoreError::Io(source.source);
    match source.cleanup {
        None => primary,
        Some(cleanup) => StoreError::CleanupFailed {
            primary: Box::new(primary),
            cleanup: map_cleanup_error(cleanup),
        },
    }
}

#[cfg(target_os = "linux")]
fn fail_atomic_publication(
    temporary: &mut crate::platform::linux::fd::AtomicFile,
    primary: StoreError,
) -> StoreError {
    match temporary.discard() {
        Ok(()) => primary,
        Err(cleanup) => StoreError::CleanupFailed {
            primary: Box::new(primary),
            cleanup: map_cleanup_error(cleanup),
        },
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(std::path::PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "syrox-store-d-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn ingest(lease: &OperationLease, bytes: &[u8]) -> ContentDigest {
        let digest = ContentDigest::sha256(bytes);
        lease
            .ingest(Cursor::new(bytes), digest, bytes.len() as u64)
            .unwrap();
        digest
    }

    #[test]
    fn open_existing_never_initializes_or_repairs_metadata() {
        let temp = TempDirectory::new();
        assert!(Store::open_existing(&temp.0).is_err());
        assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0);
        assert!(Store::open_existing(&temp.0.join("absent")).is_err());
        assert!(!temp.0.join("absent").exists());
        let store = Store::initialize(&temp.0).unwrap();
        drop(store);
        for name in [
            "objects/sha256/00",
            ".syrox-store/interests",
        ] {
            let path = temp.0.join(name);
            fs::remove_dir(&path).unwrap();
            assert!(Store::open_existing(&temp.0).is_err());
            assert!(!path.exists());
            fs::create_dir(&path).unwrap();
        }
        let lease = temp.0.join(".syrox-store/state/lease");
        fs::remove_file(&lease).unwrap();
        assert!(matches!(
            Store::open_existing(&temp.0),
            Err(StoreError::LeaseCorrupt)
        ));
        assert!(!lease.exists());
    }

    #[test]
    fn open_existing_preserves_permanent_lease_and_operation_exclusion() {
        let temp = TempDirectory::new();
        let initialized = Store::initialize(&temp.0).unwrap();
        let operation = initialized.operation().unwrap();
        let digest = ingest(&operation, b"existing Store object");
        let opened = Store::open_existing(&temp.0).unwrap();
        assert_eq!(
            opened.inner.lease_identity,
            initialized.inner.lease_identity
        );
        assert!(matches!(
            opened.maintenance(),
            Err(StoreError::Busy)
        ));
        assert!(
            opened
                .operation()
                .unwrap()
                .verify(digest)
                .unwrap()
                .is_some()
        );
        drop(operation);
        assert!(opened.maintenance().is_ok());
        let lease = temp.0.join(".syrox-store/state/lease");
        fs::rename(&lease, lease.with_extension("previous")).unwrap();
        fs::write(&lease, b"").unwrap();
        assert!(matches!(
            opened.operation(),
            Err(StoreError::LeaseCorrupt)
        ));
    }

    #[test]
    fn open_existing_rejects_symlinks_and_untrusted_metadata() {
        let temp = TempDirectory::new();
        let store = Store::initialize(&temp.0).unwrap();
        drop(store);
        let shard = temp.0.join("objects/sha256/00");
        fs::set_permissions(&shard, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            Store::open_existing(&temp.0),
            Err(StoreError::UntrustedDirectory)
        ));
        fs::set_permissions(&shard, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir(&shard).unwrap();
        symlink("01", &shard).unwrap();
        assert!(Store::open_existing(&temp.0).is_err());
        assert!(
            fs::symlink_metadata(&shard)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn published_build_roots_round_trip_beyond_legacy_reader_limits() {
        let temp = TempDirectory::new();
        let store = Store::initialize(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let mut digests = (0_u64..60)
            .map(|number| ingest(&lease, &number.to_le_bytes()))
            .collect::<Vec<_>>();
        digests.sort_unstable();
        for count in [45, 46, 60] {
            let name = RootName::new(format!("build_closure_{count}")).unwrap();
            let references = &digests[..count];
            lease.publish_root(&name, references).unwrap();
            assert_eq!(
                lease.build_references(&name).unwrap().unwrap(),
                references
            );
            assert_eq!(
                lease.publish_root(&name, references).unwrap(),
                RootPublicationState::Existing
            );
        }
    }

    #[test]
    fn maximum_root_reference_count_round_trips_at_maximum_name_length() {
        let name = RootName::new("a".repeat(MAX_ROOT_NAME_BYTES)).unwrap();
        let mut digests = (0..MAX_ROOT_REFERENCES)
            .map(|number| ContentDigest::sha256(&number.to_le_bytes()))
            .collect::<Vec<_>>();
        digests.sort_unstable();
        let bytes = encode_root(&name, &digests).unwrap();
        assert!(bytes.len() as u64 <= MAX_ROOT_BYTES);
        assert_eq!(
            parse_root(&name, &bytes, MAX_ROOT_REFERENCES).unwrap(),
            digests
        );
        assert!(matches!(
            parse_root(&name, &bytes, MAX_ROOT_REFERENCES - 1),
            Err(StoreError::LimitExceeded {
                resource: "root references"
            })
        ));
    }

    #[test]
    fn admission_cross_shard_publication_preserves_uncertainty_and_deduplication() {
        use crate::platform::linux::fd::{AtomicFault, fail_next_atomic};
        for fault in [
            AtomicFault::Rename,
            AtomicFault::DirectorySync,
            AtomicFault::SourceDirectorySync,
        ] {
            let temp = TempDirectory::new();
            let store = Store::initialize(&temp.0).unwrap();
            let lease = store.operation().unwrap();
            let bytes = b"newly admitted output";
            let digest = ContentDigest::sha256(bytes);
            assert!(!digest.to_string().starts_with("00"));
            let mut admission = lease.begin_admission(bytes.len() as u64).unwrap();
            admission.append(bytes).unwrap();
            assert!(lease.verify(digest).unwrap().is_none());
            fail_next_atomic(fault);
            let result = admission.finish();
            if fault == AtomicFault::Rename {
                assert!(matches!(result, Err(StoreError::Io(_))));
                assert!(lease.verify(digest).unwrap().is_none());
            } else {
                assert!(matches!(
                    result,
                    Err(StoreError::PublicationUncertain { .. })
                ));
                assert!(lease.verify(digest).unwrap().is_some());
            }
            let mut retry = lease.begin_admission(bytes.len() as u64).unwrap();
            retry.append(bytes).unwrap();
            assert_eq!(retry.finish().unwrap().digest(), digest);
            assert_eq!(
                lease
                    .read_verified(digest, bytes.len() as u64)
                    .unwrap()
                    .unwrap()
                    .as_bytes(),
                bytes
            );
        }
    }

    #[test]
    fn incompatible_layout_is_rejected_before_creating_shards_or_leases() {
        for old in [
            "roots/v1",
            ".syrox-store/v1",
            ".syrox-store/actions-v1",
        ] {
            let temp = TempDirectory::new();
            fs::create_dir_all(temp.0.join(old)).unwrap();
            assert!(matches!(
                Store::initialize(&temp.0),
                Err(StoreError::UnsupportedLayout)
            ));
            assert!(!temp.0.join("objects").exists());
            assert!(!temp.0.join("roots/retained").exists());
            assert!(!temp.0.join(".syrox-store/state").exists());
        }
    }

    #[test]
    fn concurrent_initialization_preserves_one_store_and_its_permanent_lease() {
        let temp = TempDirectory::new();
        let path = temp.0.join("data with spaces/syrox/store");
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || Store::initialize(&path).unwrap())
            })
            .collect();
        let stores: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        let identity = stores[0].inner.lease_identity;
        assert!(
            stores
                .iter()
                .all(|store| store.inner.lease_identity == identity)
        );
        let lease = stores[0].operation().unwrap();
        let digest = ingest(&lease, b"retained through reinitialization");
        lease
            .publish_root(&RootName::new("retained").unwrap(), &[digest])
            .unwrap();
        let reopened = Store::initialize(&path).unwrap();
        assert_eq!(reopened.inner.lease_identity, identity);
        assert!(
            reopened
                .operation()
                .unwrap()
                .verify(digest)
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            reopened.maintenance(),
            Err(StoreError::Busy)
        ));
    }

    #[test]
    fn shared_leases_coexist_and_exclusive_is_nonblocking() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let first = store.operation().unwrap();
        let second = store.operation().unwrap();
        assert!(matches!(
            store.maintenance(),
            Err(StoreError::Busy)
        ));
        drop(first);
        assert!(matches!(
            store.maintenance(),
            Err(StoreError::Busy)
        ));
        drop(second);
        let maintenance = store.maintenance().unwrap();
        assert!(matches!(store.operation(), Err(StoreError::Busy)));
        drop(maintenance);
        assert!(store.operation().is_ok());
    }

    #[test]
    #[allow(clippy::used_underscore_binding)] // Inspect the RAII-only maintenance guard.
    fn inherited_descriptor_cannot_extend_a_released_store_lease() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let lease = store.operation().unwrap();
        let consumer = lease.clone();
        // dup and fork share the same open file description. Retain a duplicate
        // to deterministically model a child paused between fork and exec.
        let inherited = lease.lock.0.fd().try_clone_to_owned().unwrap();
        drop(lease);
        assert!(matches!(
            store.maintenance(),
            Err(StoreError::Busy)
        ));
        drop(consumer);
        let maintenance = store.maintenance().unwrap();
        let inherited_exclusive = maintenance
            ._lock
            .0
            .fd()
            .try_clone_to_owned()
            .unwrap();
        assert!(matches!(store.operation(), Err(StoreError::Busy)));
        drop(maintenance);
        assert!(store.operation().is_ok());
        drop((inherited, inherited_exclusive));
    }

    #[test]
    fn lease_inode_is_permanent_and_staging_and_reader_retain_it() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lock = temp.0.join(".syrox-store/state/lease");
        let inode = fs::metadata(&lock).unwrap().ino();
        let lease = store.operation().unwrap();
        let digest = ingest(&lease, b"retained");
        let staging = lease
            .begin_staging(ContentDigest::sha256(b"staging"), 7)
            .unwrap();
        let reader = lease.open_verified(digest, 8).unwrap().unwrap();
        drop(lease);
        assert!(matches!(
            store.maintenance(),
            Err(StoreError::Busy)
        ));
        staging.abort().unwrap();
        assert!(matches!(
            store.maintenance(),
            Err(StoreError::Busy)
        ));
        drop(reader);
        assert!(store.maintenance().is_ok());
        assert_eq!(fs::metadata(lock).unwrap().ino(), inode);
    }

    #[test]
    fn roots_are_canonical_immutable_and_require_verified_objects() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let first = ingest(&lease, b"first");
        let second = ingest(&lease, b"second");
        let mut sorted = vec![first, second];
        sorted.sort();
        let name = RootName::new("release_1").unwrap();
        assert_eq!(
            lease.publish_root(&name, &sorted).unwrap(),
            RootPublicationState::Published
        );
        assert_eq!(
            lease.publish_root(&name, &sorted).unwrap(),
            RootPublicationState::Existing
        );
        assert!(matches!(
            lease.publish_root(&name, &sorted[..1]),
            Err(StoreError::RootConflict { .. })
        ));
        assert!(matches!(
            lease.publish_root(
                &RootName::new("missing").unwrap(),
                &[ContentDigest::sha256(b"absent")]
            ),
            Err(StoreError::MissingRootObject { .. })
        ));
        assert!(RootName::new("bad order").is_err());

        let corrupt = ingest(&lease, b"will corrupt");
        fs::write(
            temp.0
                .join("objects/sha256")
                .join(&corrupt.to_string()[..2])
                .join(corrupt.to_string()),
            b"changed",
        )
        .unwrap();
        assert!(matches!(
            lease.publish_root(&RootName::new("corrupt").unwrap(), &[corrupt]),
            Err(StoreError::CorruptObject { .. })
        ));

        fs::write(
            temp.0.join("roots/retained/release_1"),
            b"malformed\n",
        )
        .unwrap();
        assert!(matches!(
            lease.publish_root(&name, &sorted),
            Err(StoreError::CorruptRoot { .. })
        ));
    }

    #[test]
    fn cancellation_during_root_verification_prevents_any_publication() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let digest = ingest(&lease, &vec![b'x'; 256 * 1024]);
        let root = RootName::new("cancelled_generation").unwrap();
        let mut checks = 0;
        let result = lease.publish_root_checked(&root, &[digest], || {
            checks += 1;
            if checks == 3 {
                Err(crate::cancellation::cancellation_io())
            } else {
                Ok(())
            }
        });
        assert!(
            matches!(result, Err(StoreError::Io(ref error)) if crate::cancellation::is_cancellation_io(error))
        );
        assert!(lease.build_references(&root).unwrap().is_none());
        assert_eq!(
            fs::read_dir(temp.0.join("roots/retained"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            lease.publish_root(&root, &[digest]).unwrap(),
            RootPublicationState::Published
        );
    }

    #[test]
    fn empty_roots_and_owned_bytes_are_valid() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let name = RootName::new("empty").unwrap();
        lease.publish_root(&name, &[]).unwrap();
        let digest = ingest(&lease, b"owned");
        let bytes = lease.read_verified(digest, 5).unwrap().unwrap();
        drop(lease);
        assert_eq!(bytes.into_bytes(), b"owned");
    }

    #[test]
    fn gc_dry_run_retains_everything_and_collect_obeys_roots() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let live = ingest(&lease, b"live");
        let dead = ingest(&lease, b"dead");
        let root = RootName::new("keep").unwrap();
        lease.publish_root(&root, &[live]).unwrap();
        drop(lease);
        let mut maintenance = store.maintenance().unwrap();
        let dry = maintenance
            .garbage_collect(&GcRequest::default())
            .unwrap();
        assert_eq!(
            dry.candidates,
            vec![GcCandidate {
                digest: dead,
                bytes: 4
            }]
        );
        drop(maintenance);
        assert!(
            store
                .operation()
                .unwrap()
                .verify(dead)
                .unwrap()
                .is_some()
        );
        let mut maintenance = store.maintenance().unwrap();
        let report = maintenance
            .garbage_collect(&GcRequest {
                collect: true,
                ..GcRequest::default()
            })
            .unwrap();
        assert_eq!(report.removed_objects, [dead]);
        drop(maintenance);
        let lease = store.operation().unwrap();
        assert!(lease.verify(live).unwrap().is_some());
        assert!(lease.verify(dead).unwrap().is_none());
    }

    #[test]
    fn collect_removes_requested_root_before_sweeping() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let digest = ingest(&lease, b"only root");
        let root = RootName::new("remove_me").unwrap();
        lease.publish_root(&root, &[digest]).unwrap();
        drop(lease);
        let mut maintenance = store.maintenance().unwrap();
        let report = maintenance
            .garbage_collect(&GcRequest {
                collect: true,
                remove_roots: vec![root.clone()],
                ..GcRequest::default()
            })
            .unwrap();
        assert_eq!(report.removed_roots, [root]);
        assert_eq!(report.removed_objects, [digest]);
    }

    #[test]
    fn malformed_inventory_causes_zero_deletes() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let dead = ingest(&lease, b"dead");
        drop(lease);
        fs::write(
            temp.0.join("objects/sha256/00/not-an-object"),
            b"bad",
        )
        .unwrap();
        let mut maintenance = store.maintenance().unwrap();
        assert!(matches!(
            maintenance.garbage_collect(&GcRequest {
                collect: true,
                ..GcRequest::default()
            }),
            Err(StoreError::UnexpectedEntry { .. })
        ));
        drop(maintenance);
        assert!(
            store
                .operation()
                .unwrap()
                .verify(dead)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn recovery_only_accepts_exact_temporary_names() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let exact = format!("{OBJECT_TEMP_PREFIX}{}", "a".repeat(32));
        fs::write(
            temp.0.join("objects/sha256/00").join(&exact),
            b"temporary",
        )
        .unwrap();
        let root_exact = format!("{ROOT_TEMP_PREFIX}{}", "b".repeat(32));
        fs::write(
            temp.0.join("roots/retained").join(root_exact),
            b"temporary",
        )
        .unwrap();
        let mut maintenance = store.maintenance().unwrap();
        let report = maintenance
            .recover(RecoveryLimits::default())
            .unwrap();
        assert_eq!(report.removed.len(), 2);
        drop(maintenance);
        fs::write(
            temp.0
                .join("objects/sha256/00/.syrox-store.tmp.lookalike"),
            b"bad",
        )
        .unwrap();
        let mut maintenance = store.maintenance().unwrap();
        assert!(matches!(
            maintenance.recover(RecoveryLimits::default()),
            Err(StoreError::UnexpectedEntry { .. })
        ));
    }

    #[test]
    fn maintenance_limits_are_hard_and_charged_before_growth() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let digest = ingest(&lease, b"one");
        drop(lease);
        let mut maintenance = store.maintenance().unwrap();
        let limits = GcLimits {
            objects: 0,
            ..GcLimits::default()
        };
        assert!(matches!(
            maintenance.garbage_collect(&GcRequest {
                limits,
                ..GcRequest::default()
            }),
            Err(StoreError::LimitExceeded {
                resource: "GC objects"
            })
        ));
        let limits = GcLimits {
            objects: MAX_GC_OBJECTS + 1,
            ..GcLimits::default()
        };
        assert!(matches!(
            maintenance.garbage_collect(&GcRequest {
                limits,
                ..GcRequest::default()
            }),
            Err(StoreError::InvalidMaintenanceLimit {
                resource: "GC objects"
            })
        ));
        assert!(matches!(
            maintenance.recover(RecoveryLimits {
                entries: MAX_RECOVERY_ENTRIES + 1,
                ..RecoveryLimits::default()
            }),
            Err(StoreError::InvalidMaintenanceLimit {
                resource: "recovery entries"
            })
        ));
        let limits = GcLimits {
            work: 263,
            ..GcLimits::default()
        };
        assert!(matches!(
            maintenance.garbage_collect(&GcRequest {
                collect: true,
                limits,
                ..GcRequest::default()
            }),
            Err(StoreError::LimitExceeded {
                resource: "GC work"
            })
        ));
        drop(maintenance);
        assert!(
            store
                .operation()
                .unwrap()
                .verify(digest)
                .unwrap()
                .is_some()
        );

        let recovery_temp = TempDirectory::new();
        let recovery_store = Store::open(&recovery_temp.0).unwrap();
        let temporary = recovery_temp
            .0
            .join("objects/sha256/00")
            .join(format!("{OBJECT_TEMP_PREFIX}{}", "d".repeat(32)));
        fs::write(&temporary, b"temporary").unwrap();
        let mut maintenance = recovery_store.maintenance().unwrap();
        assert!(matches!(
            maintenance.recover(RecoveryLimits {
                work: 263,
                ..RecoveryLimits::default()
            }),
            Err(StoreError::LimitExceeded {
                resource: "recovery work"
            })
        ));
        assert!(temporary.exists());
    }

    #[test]
    fn corrupt_root_and_object_are_rejected_before_gc_mutation() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let digest = ingest(&lease, b"data");
        let root = RootName::new("root").unwrap();
        lease.publish_root(&root, &[digest]).unwrap();
        drop(lease);
        fs::write(
            temp.0.join("roots/retained/root"),
            b"not canonical\n",
        )
        .unwrap();
        let mut maintenance = store.maintenance().unwrap();
        assert!(matches!(
            maintenance.garbage_collect(&GcRequest::default()),
            Err(StoreError::CorruptRoot { .. })
        ));
        drop(maintenance);
        fs::set_permissions(
            temp.0.join("roots/retained/root"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    #[test]
    fn digest_text_is_strict_lowercase_sha256() {
        let digest = ContentDigest::sha256(b"abc");
        let text = digest.to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<ContentDigest>().unwrap(), digest);
        assert!(
            text.to_uppercase()
                .parse::<ContentDigest>()
                .is_err()
        );
        assert!(text[..63].parse::<ContentDigest>().is_err());
    }

    #[test]
    fn staging_is_private_bounded_and_failed_state_is_terminal() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let bytes = b"two chunks";
        let digest = ContentDigest::sha256(bytes);
        let mut staging = lease
            .begin_staging(digest, bytes.len() as u64)
            .unwrap();
        staging.append(b"two ").unwrap();
        staging.append(b"chunks").unwrap();
        assert_eq!(lease.verify(digest).unwrap(), None);
        assert_eq!(
            staging.finish().unwrap().state(),
            StoreObjectState::Published
        );

        let empty = ContentDigest::sha256(b"");
        assert_eq!(
            lease
                .begin_staging(empty, 0)
                .unwrap()
                .finish()
                .unwrap()
                .size(),
            0
        );
        let over = ContentDigest::sha256(b"five!");
        let mut staging = lease.begin_staging(over, 4).unwrap();
        assert!(matches!(
            staging.append(b"five!"),
            Err(StoreError::BlobTooLarge {
                limit: 4
            })
        ));
        assert!(matches!(
            staging.append(b"x"),
            Err(StoreError::StagingFailed)
        ));
        assert!(matches!(
            staging.finish(),
            Err(StoreError::StagingFailed)
        ));

        let aborted = ContentDigest::sha256(b"abort");
        let mut staging = lease.begin_staging(aborted, 5).unwrap();
        staging.append(b"abort").unwrap();
        staging.abort().unwrap();
        assert_eq!(lease.verify(aborted).unwrap(), None);
    }

    #[test]
    fn mismatch_and_transport_failure_clean_up_or_preserve_both_errors() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("transport failed"))
            }
        }

        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let expected = ContentDigest::sha256(b"expected");
        assert!(matches!(
            lease.ingest(Cursor::new(b"different"), expected, 32),
            Err(StoreError::DigestMismatch { .. })
        ));
        assert_eq!(lease.verify(expected).unwrap(), None);

        crate::platform::linux::fd::fail_next_atomic(
            crate::platform::linux::fd::AtomicFault::CleanupUnlink,
        );
        let error = lease
            .ingest(FailingReader, expected, 32)
            .unwrap_err();
        assert!(matches!(
            error,
            StoreError::CleanupFailed {
                primary,
                cleanup: StoreCleanupError::Removal { .. }
            } if matches!(*primary, StoreError::Io(_))
        ));
    }

    #[test]
    fn verified_reads_reject_corrupt_oversized_and_unsafe_objects() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let digest = ingest(&lease, b"limit");
        assert!(matches!(
            lease.read_verified(digest, 4),
            Err(StoreError::CorruptObjectTooLarge { .. })
        ));
        let object = temp
            .0
            .join("objects/sha256")
            .join(&digest.to_string()[..2])
            .join(digest.to_string());
        fs::write(&object, b"wrong").unwrap();
        assert!(matches!(
            lease.verify(digest),
            Err(StoreError::CorruptObject { .. })
        ));

        let hard_temp = TempDirectory::new();
        let hard_store = Store::open(&hard_temp.0).unwrap();
        let hard_lease = hard_store.operation().unwrap();
        let hard = ingest(&hard_lease, b"hard");
        let hard_path = hard_temp
            .0
            .join("objects/sha256")
            .join(&hard.to_string()[..2])
            .join(hard.to_string());
        fs::hard_link(&hard_path, hard_temp.0.join("extra")).unwrap();
        assert!(matches!(
            hard_lease.verify(hard),
            Err(StoreError::UnsafeObject { .. })
        ));

        let mode_temp = TempDirectory::new();
        let mode_store = Store::open(&mode_temp.0).unwrap();
        let mode_lease = mode_store.operation().unwrap();
        let mode = ingest(&mode_lease, b"mode");
        let mode_path = mode_temp
            .0
            .join("objects/sha256")
            .join(&mode.to_string()[..2])
            .join(mode.to_string());
        fs::set_permissions(&mode_path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            mode_lease.verify(mode),
            Err(StoreError::UnsafeObject { .. })
        ));

        let link_temp = TempDirectory::new();
        let link_store = Store::open(&link_temp.0).unwrap();
        let link_lease = link_store.operation().unwrap();
        let link = ingest(&link_lease, b"link");
        let link_path = link_temp
            .0
            .join("objects/sha256")
            .join(&link.to_string()[..2])
            .join(link.to_string());
        fs::remove_file(&link_path).unwrap();
        symlink("elsewhere", link_path).unwrap();
        assert!(matches!(
            link_lease.verify(link),
            Err(StoreError::SymbolicLink)
        ));
    }

    #[test]
    fn concurrent_identical_writers_converge() {
        let temp = TempDirectory::new();
        let store = Arc::new(Store::open(&temp.0).unwrap());
        let bytes = b"one immutable object";
        let digest = ContentDigest::sha256(bytes);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    store
                        .operation()
                        .unwrap()
                        .ingest(Cursor::new(bytes), digest, 1024)
                        .unwrap()
                })
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap().digest(), digest);
        }
        let shard = temp
            .0
            .join("objects/sha256")
            .join(&digest.to_string()[..2]);
        assert_eq!(fs::read_dir(shard).unwrap().count(), 1);
    }

    #[test]
    fn verified_reader_retains_the_rehashed_inode_after_path_replacement() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let bytes = b"retained inode";
        let digest = ingest(&lease, bytes);
        let mut reader = lease.open_verified(digest, 64).unwrap().unwrap();
        let object = temp
            .0
            .join("objects/sha256")
            .join(&digest.to_string()[..2])
            .join(digest.to_string());
        fs::remove_file(&object).unwrap();
        fs::write(object, b"replacement").unwrap();
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
    }

    #[test]
    fn separately_opened_verified_readers_have_independent_cursors() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let bytes = b"independent verified cursors";
        let digest = ingest(&lease, bytes);
        let mut first = lease.open_verified(digest, 64).unwrap().unwrap();
        let mut second = lease.open_verified(digest, 64).unwrap().unwrap();
        let mut prefix = [0_u8; 12];
        first.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, &bytes[..12]);
        second.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, &bytes[..12]);
        let mut remaining = Vec::new();
        first.read_to_end(&mut remaining).unwrap();
        assert_eq!(remaining, &bytes[12..]);
    }

    #[test]
    #[ignore = "explicit bounded Store read profiling; reads 32 MiB three times"]
    fn read_verified_profile_one_pass() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let bytes = (0_usize..32 * 1024 * 1024)
            .map(|index| u8::try_from(index % 251).expect("remainder is a byte"))
            .collect::<Vec<_>>();
        let digest = ContentDigest::sha256(&bytes);
        lease
            .ingest(bytes.as_slice(), digest, bytes.len() as u64)
            .unwrap();
        let before = fs::read_to_string("/proc/self/io").unwrap();
        let start = std::time::Instant::now();
        for _ in 0..3 {
            let result = lease
                .read_verified(digest, bytes.len() as u64)
                .unwrap()
                .unwrap();
            assert_eq!(result.as_bytes(), bytes);
        }
        let elapsed = start.elapsed();
        let after = fs::read_to_string("/proc/self/io").unwrap();
        let counter = |input: &str, key: &str| -> u64 {
            input
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        };
        eprintln!(
            "store_read_3x_elapsed={elapsed:?} rchar={} syscr={} read_bytes={}",
            counter(&after, "rchar:") - counter(&before, "rchar:"),
            counter(&after, "syscr:") - counter(&before, "syscr:"),
            counter(&after, "read_bytes:") - counter(&before, "read_bytes:")
        );
    }

    #[test]
    fn atomic_faults_preserve_commit_and_cleanup_boundaries() {
        use crate::platform::linux::fd::AtomicFault;

        let bytes = b"fault boundary";
        let digest = ContentDigest::sha256(bytes);
        for fault in [
            AtomicFault::FileSync,
            AtomicFault::TemporaryReopen,
            AtomicFault::Rename,
        ] {
            let temp = TempDirectory::new();
            let store = Store::open(&temp.0).unwrap();
            let lease = store.operation().unwrap();
            let mut staging = lease
                .begin_staging(digest, bytes.len() as u64)
                .unwrap();
            staging.append(bytes).unwrap();
            crate::platform::linux::fd::fail_next_atomic(fault);
            assert!(matches!(staging.finish(), Err(StoreError::Io(_))));
            assert_eq!(lease.verify(digest).unwrap(), None);
        }
        for fault in [
            AtomicFault::PublishedReopen,
            AtomicFault::DirectorySync,
        ] {
            let temp = TempDirectory::new();
            let store = Store::open(&temp.0).unwrap();
            let lease = store.operation().unwrap();
            let mut staging = lease
                .begin_staging(digest, bytes.len() as u64)
                .unwrap();
            staging.append(bytes).unwrap();
            crate::platform::linux::fd::fail_next_atomic(fault);
            assert!(matches!(
                staging.finish(),
                Err(StoreError::PublicationUncertain { .. })
            ));
            assert!(lease.verify(digest).unwrap().is_some());
        }
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let mut staging = lease
            .begin_staging(digest, bytes.len() as u64)
            .unwrap();
        crate::platform::linux::fd::fail_next_atomic(AtomicFault::Write);
        assert!(matches!(
            staging.append(bytes),
            Err(StoreError::Io(_))
        ));
        assert!(matches!(
            staging.finish(),
            Err(StoreError::StagingFailed)
        ));

        let staging = lease
            .begin_staging(digest, bytes.len() as u64)
            .unwrap();
        crate::platform::linux::fd::fail_next_atomic(AtomicFault::CleanupUnlink);
        crate::platform::linux::fd::fail_next_atomic(AtomicFault::CleanupSync);
        assert!(matches!(
            staging.abort(),
            Err(StoreError::CleanupUncertain {
                cleanup: StoreCleanupError::RemovalAndSynchronization { .. }
            })
        ));
    }

    #[test]
    fn missing_or_replaced_lease_inode_is_corruption_and_never_recreated() {
        let missing_temp = TempDirectory::new();
        let missing_store = Store::open(&missing_temp.0).unwrap();
        let missing = missing_temp.0.join(".syrox-store/state/lease");
        let original = fs::metadata(&missing).unwrap().ino();
        fs::remove_file(&missing).unwrap();
        assert!(matches!(
            missing_store.operation(),
            Err(StoreError::LeaseCorrupt)
        ));
        assert!(!missing.exists());
        assert!(matches!(
            Store::open(&missing_temp.0),
            Err(StoreError::LeaseCorrupt)
        ));
        assert!(!missing.exists());

        let replaced_temp = TempDirectory::new();
        let replaced_store = Store::open(&replaced_temp.0).unwrap();
        let replaced = replaced_temp.0.join(".syrox-store/state/lease");
        let replaced_original = fs::metadata(&replaced).unwrap().ino();
        fs::remove_file(&replaced).unwrap();
        fs::write(&replaced, b"replacement").unwrap();
        assert_ne!(
            fs::metadata(&replaced).unwrap().ino(),
            replaced_original
        );
        assert!(matches!(
            replaced_store.maintenance(),
            Err(StoreError::LeaseCorrupt)
        ));
        assert_eq!(fs::metadata(&replaced).unwrap().len(), 11);
        assert_ne!(original, 0);
    }

    #[test]
    fn simultaneous_first_open_converges_on_one_lease_inode() {
        let temp = Arc::new(TempDirectory::new());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let temp = Arc::clone(&temp);
                std::thread::spawn(move || Store::open(&temp.0).unwrap())
            })
            .collect();
        let stores: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        let inode = fs::metadata(temp.0.join(".syrox-store/state/lease"))
            .unwrap()
            .ino();
        assert!(stores.iter().all(|store| {
            store.inner.lease_identity.inode == inode && store.operation().is_ok()
        }));
    }

    #[test]
    fn recovery_validates_unsafe_later_object_before_any_delete() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let temporary = format!("{OBJECT_TEMP_PREFIX}{}", "a".repeat(32));
        let temporary_path = temp.0.join("objects/sha256/00").join(&temporary);
        fs::write(&temporary_path, b"temporary").unwrap();
        let digest = (0_u64..10_000)
            .map(|value| ContentDigest::sha256(value.to_string().as_bytes()))
            .find(|digest| digest.to_string().starts_with("ff"))
            .unwrap();
        let unsafe_path = temp
            .0
            .join("objects/sha256/ff")
            .join(digest.to_string());
        fs::write(&unsafe_path, b"unsafe").unwrap();
        fs::hard_link(&unsafe_path, temp.0.join("extra-link")).unwrap();
        let mut maintenance = store.maintenance().unwrap();
        assert!(matches!(
            maintenance.recover(RecoveryLimits::default()),
            Err(StoreError::UnsafeObject { .. })
        ));
        assert!(temporary_path.exists());
    }

    #[test]
    fn maintenance_reports_partial_unlink_and_sync_failures() {
        let unlink_temp = TempDirectory::new();
        let unlink_store = Store::open(&unlink_temp.0).unwrap();
        for suffix in ["a", "b"] {
            fs::write(
                unlink_temp
                    .0
                    .join("objects/sha256/00")
                    .join(format!(
                        "{OBJECT_TEMP_PREFIX}{}",
                        suffix.repeat(32)
                    )),
                b"temporary",
            )
            .unwrap();
        }
        let mut maintenance = unlink_store.maintenance().unwrap();
        crate::platform::linux::fd::fail_next_maintenance_unlink();
        let report = maintenance
            .recover(RecoveryLimits::default())
            .unwrap();
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.failures.len(), 1);
        assert!(report.uncertain);

        let sync_temp = TempDirectory::new();
        let sync_store = Store::open(&sync_temp.0).unwrap();
        fs::write(
            sync_temp
                .0
                .join("roots/retained")
                .join(format!("{ROOT_TEMP_PREFIX}{}", "c".repeat(32))),
            b"temporary",
        )
        .unwrap();
        let mut maintenance = sync_store.maintenance().unwrap();
        crate::platform::linux::fd::fail_next_maintenance_sync();
        let report = maintenance
            .recover(RecoveryLimits::default())
            .unwrap();
        assert_eq!(report.removed.len(), 1);
        assert!(matches!(
            report.failures.as_slice(),
            [MaintenanceFailure {
                operation: MaintenanceFailureOperation::Synchronize,
                ..
            }]
        ));
        assert!(report.uncertain);
    }

    #[test]
    fn gc_sync_failure_preserves_removed_objects_in_partial_report() {
        let temp = TempDirectory::new();
        let store = Store::open(&temp.0).unwrap();
        let lease = store.operation().unwrap();
        let digest = ingest(&lease, b"unrooted");
        drop(lease);
        let mut maintenance = store.maintenance().unwrap();
        crate::platform::linux::fd::fail_next_maintenance_sync();
        let report = maintenance
            .garbage_collect(&GcRequest {
                collect: true,
                ..GcRequest::default()
            })
            .unwrap();
        assert_eq!(report.removed_objects, [digest]);
        assert!(matches!(
            report.failures.as_slice(),
            [MaintenanceFailure {
                operation: MaintenanceFailureOperation::Synchronize,
                ..
            }]
        ));
        assert!(report.uncertain);
    }
}

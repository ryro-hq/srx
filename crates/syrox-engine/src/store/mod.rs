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
mod tests;

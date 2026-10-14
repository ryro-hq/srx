//! Opening a file view of an already admitted output.
//!
//! The view can be reconstructed from the artifact. Build and import adapters check
//! who authorized the output before entering this module. The handle retains
//! objects and the directory while the consumer uses their files.

use crate::cancellation::OperationControl;
#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read as _;
use std::ops::Deref;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

use super::artifact::{self, IndexedArtifact};
use crate::cancellation::Cancellation;
use crate::platform::linux::fd::{self as fd, FileType, FlockMode, OpenedPath};
use crate::store::RootName;
use crate::{
    store::ContentDigest, store::MaintenanceLease, store::OperationLease, store::Store,
    store::StoreError,
};

const MAX_VIEW_ENTRIES: usize = 65_536;
const MAX_VIEWS: usize = 1024;

mod retention;
pub use retention::{OutputIdentity, OutputOrigin, RetainedOutput};

struct ViewGuard {
    directory: OpenedPath,
    acquired: Instant,
    wait: Duration,
}

impl Deref for ViewGuard {
    type Target = OpenedPath;

    fn deref(&self) -> &OpenedPath {
        &self.directory
    }
}

impl Drop for ViewGuard {
    fn drop(&mut self) {
        if std::env::var_os("SYROX_PROFILE_LOCKS").is_some() {
            eprintln!(
                "syrox-lock views wait_us={} held_us={}",
                self.wait.as_micros(),
                self.acquired.elapsed().as_micros()
            );
        }
    }
}

#[derive(Debug, Error)]
pub enum MaterializationError {
    #[error("materialization cancelled")]
    Cancelled,
    #[error("the result has no retained, complete authorization")]
    MissingResult,
    #[error("the retained result or its materialization is invalid: {0}")]
    Invalid(String),
    #[error("materialization may be visible but durability is unconfirmed: {0}")]
    Uncertain(std::io::Error),
    #[error("materialization failed ({primary}); private staging cleanup also failed: {cleanup}")]
    FailureAndCleanup {
        primary: Box<Self>,
        cleanup: String,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Holds a granular Store interest while a verified view is consumed. Physical paths are
/// local, reconstructible views, valid only while a consumer holds this value.
/// Persist `RetainedOutput` in a generation and reopen it for later consumption.
#[derive(Debug)]
pub struct MaterializedArtifact {
    lease: crate::store::ObjectLease,
    directory: Arc<OpenedPath>,
    identity: OutputIdentity,
    references: Arc<[ContentDigest]>,
    files: usize,
    reused: bool,
}

impl MaterializedArtifact {
    pub(crate) fn retained_references(&self) -> &[ContentDigest] {
        &self.references
    }
    pub(crate) const fn object_lease(&self) -> &crate::store::ObjectLease {
        &self.lease
    }

    pub(crate) fn same_store(&self, store: &Store) -> Result<bool, StoreError> {
        self.lease.same_store(store)
    }

    /// The closure retains this already-opened directory until launcher exit.
    pub(crate) fn mount_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.directory.fd()
    }
    /// Revalidate the held view against its authenticated Artifact without
    /// requiring the original durable root to remain published.
    pub(crate) fn verify_view(
        &self,
        cancellation: &Cancellation,
    ) -> Result<(), MaterializationError> {
        check(cancellation)?;
        let operation = self.lease.operation()?;
        let parent = operation.view_directory()?;
        let _guard = lock_views(&parent, cancellation)?;
        let name = format!("tree_{}", self.identity.artifact);
        let published = fd::open_beneath(parent.fd(), Path::new(&name), true).map_err(problem)?;
        if published.metadata().identity() != self.directory.metadata().identity() {
            return Err(invalid("held view publication changed"));
        }
        let mut indexed = IndexedArtifact::open_checked(
            self.open_artifact(cancellation)?,
            "",
            cancellation,
        )
        .map_err(|error| {
            if cancellation.is_cancelled() {
                MaterializationError::Cancelled
            } else {
                problem(error)
            }
        })?;
        if indexed.files().len() != self.files {
            return Err(invalid("held view file count changed"));
        }
        let expected = expected_names(indexed.files())?;
        verify_tree(
            &self.directory,
            &mut indexed,
            &expected,
            cancellation,
        )?;
        fd::directory_path(&self.directory)?;
        check(cancellation)
    }

    #[cfg(test)]
    pub(crate) fn shares_directory(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.directory, &other.directory)
    }
    /// Share one already-authorized view within an operation. Both roles retain
    /// the same granular interest and verified directory descriptor.
    pub(crate) fn share(&self) -> Self {
        Self {
            lease: self.lease.clone(),
            directory: Arc::clone(&self.directory),
            identity: self.identity.clone(),
            references: Arc::clone(&self.references),
            files: self.files,
            reused: self.reused,
        }
    }
    pub const fn action(&self) -> ContentDigest {
        self.identity.action
    }
    /// Stable mount location within a private Syrox runtime namespace. The
    /// action digest precedes the build output; no final-content hash is baked
    /// into the build inputs.
    pub fn logical_prefix(&self) -> String {
        format!(
            "/syrox/store/{}/{}",
            self.identity.action, self.identity.output
        )
    }
    pub const fn artifact(&self) -> ContentDigest {
        self.identity.artifact
    }
    pub const fn files(&self) -> usize {
        self.files
    }
    pub const fn reused(&self) -> bool {
        self.reused
    }
    /// Revalidates that the descriptor is still published at this exact path.
    pub fn directory(&self) -> Result<PathBuf, MaterializationError> {
        fd::directory_path(&self.directory).map_err(Into::into)
    }
}

/// Construct only after a receipt or pinned result manifest authorizes the output.
pub(crate) struct AuthorizedOutput {
    pub identity: OutputIdentity,
    pub references: Vec<ContentDigest>,
    pub files: usize,
    pub maximum_bytes: u64,
}

// Consume the operation barrier: returned views retain only granular interests.
#[allow(clippy::needless_pass_by_value)] // Retain the admitted object while validating and publishing its descriptor-relative view.
pub(crate) fn materialize_verified(
    lease: OperationLease,
    output: AuthorizedOutput,
    cancellation: &(impl OperationControl + ?Sized),
) -> Result<MaterializedArtifact, MaterializationError> {
    check(cancellation)?;
    let input = lease
        .open_verified_checked(
            output.identity.artifact,
            output.maximum_bytes,
            || cancellation_io(cancellation),
        )
        .map_err(|error| cancellation_store_error(error, cancellation))?
        .ok_or(MaterializationError::MissingResult)?;
    let mut indexed = IndexedArtifact::open_checked(input, "", cancellation).map_err(|error| {
        if cancellation.is_cancelled() {
            MaterializationError::Cancelled
        } else {
            problem(error)
        }
    })?;
    if indexed.files().len() != output.files {
        return Err(invalid(
            "artifact file count disagrees with authorization",
        ));
    }
    let expected = expected_names(indexed.files())?;
    let identity = output.identity;
    let references: Arc<[ContentDigest]> = Arc::from(output.references);
    let parent = lease.view_directory()?;
    let _guard = lock_views(&parent, cancellation)?;
    let name = format!("tree_{}", identity.artifact);
    if let Some(directory) = open_optional(&parent, &name)? {
        verify_tree(&directory, &mut indexed, &expected, cancellation)?;
        fd::sync_directory(parent.fd())?;
        let interest = lease.retain_objects(&references, &[identity.artifact])?;
        return Ok(MaterializedArtifact {
            lease: interest,
            directory: Arc::new(directory),
            identity,
            references,
            files: indexed.files().len(),
            reused: true,
        });
    }
    if entries(&parent, MAX_VIEWS)?.len() >= MAX_VIEWS {
        return Err(invalid("view cache limit reached"));
    }
    let initializing = format!("init-{}", &fd::operation_name()?[3..]);
    let (directory, created) =
        fd::ensure_directory_beneath_with_status(parent.fd(), Path::new(&initializing))
            .map_err(problem)?;
    if !created {
        return Err(invalid("view initialization name collision"));
    }
    let outcome = (|| {
        write_tree(&directory, &mut indexed, cancellation)?;
        verify_tree(&directory, &mut indexed, &expected, cancellation)?;
        // A failed rename sync can leave a visible tree. Callers must receive an
        // uncertain outcome, then a later verified lookup confirms durability.
        fd::rename_directory(
            parent.fd(),
            Path::new(&initializing),
            Path::new(&name),
            directory.metadata().identity(),
        )
        .map_err(MaterializationError::Uncertain)?;
        Ok(())
    })();
    if let Err(primary) = outcome {
        if open_optional(&parent, &initializing)?.is_some() {
            return match remove_tree(&parent, &initializing, &directory) {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(MaterializationError::FailureAndCleanup {
                    primary: Box::new(primary),
                    cleanup: cleanup.to_string(),
                }),
            };
        }
        return Err(primary);
    }
    let interest = lease.retain_objects(&references, &[identity.artifact])?;
    Ok(MaterializedArtifact {
        lease: interest,
        directory: Arc::new(directory),
        identity,
        references,
        files: indexed.files().len(),
        reused: false,
    })
}

/// Remove abandoned private init-* trees only after acquiring the namespace lock.
/// Published trees are never deleted here; consumers can hold them under a lease.
#[cfg(test)]
fn recover_materializations(store: &Store) -> Result<usize, MaterializationError> {
    let lease = store.operation()?;
    let parent = lease.view_directory()?;
    let _guard = lock_views(&parent, &Cancellation::default())?;
    let mut removed = 0;
    for name in entries(&parent, MAX_VIEWS)? {
        if name.starts_with("tree_") && name[5..].parse::<ContentDigest>().is_ok() {
            continue;
        }
        if !name.strip_prefix("init-").is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(invalid("unexpected view cache entry"));
        }
        let directory = fd::open_beneath(parent.fd(), Path::new(&name), true).map_err(problem)?;
        if !directory.metadata().is_trusted_directory() {
            return Err(invalid("untrusted view staging directory"));
        }
        remove_tree(&parent, &name, &directory)?;
        removed += 1;
    }
    Ok(removed)
}

/// Reclaim reconstructible views while holding exclusive Store maintenance.
/// Published receipts remain retained; a subsequent consumer recreates and
/// revalidates its physical tree from the Artifact. Trees protected by live
/// local or supervised-process interests are excluded from reclamation.
pub fn clear_materializations(
    maintenance: &mut MaintenanceLease,
) -> Result<usize, MaterializationError> {
    let protected = maintenance.protected_views()?;
    let parent = maintenance.view_directory()?;
    let _guard = lock_views(&parent, &Cancellation::default())?;
    let mut removed = 0;
    for name in entries(&parent, MAX_VIEWS)? {
        if name
            .strip_prefix("tree_")
            .and_then(|digest| digest.parse::<ContentDigest>().ok())
            .is_some_and(|digest| protected.contains(&digest))
        {
            continue;
        }
        let published = name
            .strip_prefix("tree_")
            .is_some_and(|digest| digest.parse::<ContentDigest>().is_ok());
        let initializing = name.strip_prefix("init-").is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
        if !published && !initializing {
            return Err(invalid("unexpected view cache entry"));
        }
        let directory = fd::open_beneath(parent.fd(), Path::new(&name), true).map_err(problem)?;
        if !directory.metadata().is_trusted_directory() {
            return Err(invalid("untrusted view directory"));
        }
        remove_tree(&parent, &name, &directory)?;
        removed += 1;
    }
    Ok(removed)
}

fn expected_names(
    files: &artifact::ArtifactIndex,
) -> Result<BTreeSet<String>, MaterializationError> {
    let mut names = BTreeSet::new();
    for file in files.iter() {
        names.insert(file.path.to_owned());
        let mut part = file.path;
        while let Some((parent, _)) = part.rsplit_once('/') {
            names.insert(parent.to_owned());
            part = parent;
        }
        if names.len() > MAX_VIEW_ENTRIES {
            return Err(invalid("materialization entry limit reached"));
        }
    }
    Ok(names)
}

fn write_tree(
    root: &OpenedPath,
    indexed: &mut IndexedArtifact<crate::store::VerifiedReader>,
    cancellation: &(impl OperationControl + ?Sized),
) -> Result<(), MaterializationError> {
    let (files, input) = indexed.parts();
    for file in files.iter() {
        check(cancellation)?;
        let mut directory = fd::open_beneath(root.fd(), Path::new("."), true).map_err(problem)?;
        let mut components = file.path.split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                let (opened, created) =
                    fd::initialize_regular(directory.fd(), Path::new(component))?;
                if !created {
                    return Err(invalid("view file already exists"));
                }
                let mut output = opened.into_file();
                let copied = copy_with_cancellation(
                    IndexedArtifact::<crate::store::VerifiedReader>::reader_from(input, &file)?,
                    &mut output,
                    cancellation,
                )?;
                if copied != file.size {
                    return Err(invalid("artifact file is truncated"));
                }
                output.set_permissions(fs::Permissions::from_mode(if file.executable {
                    0o500
                } else {
                    0o400
                }))?;
                output.sync_all()?;
                fd::sync_directory(directory.fd())?;
            } else {
                let child = fd::ensure_directory_beneath(directory.fd(), Path::new(component))
                    .map_err(problem)?;
                directory = child;
            }
        }
    }
    // Child directories were synced as entries were created. Their content was
    // synced after each file, including empty ancestor chains.
    fd::sync_directory(root.fd())?;
    Ok(())
}

/// Compare a retained directory descriptor against an authenticated Artifact.
/// No Store lookup, extraction, or pathname-based admission is performed.
pub(crate) fn verify_descriptor_view<R: std::io::Read + std::io::Seek>(
    directory: std::os::fd::BorrowedFd<'_>,
    indexed: &mut IndexedArtifact<R>,
    cancellation: &(impl OperationControl + ?Sized),
) -> Result<(), MaterializationError> {
    let opened = fd::open_beneath(directory, Path::new("."), true).map_err(problem)?;
    let expected = expected_names(indexed.files())?;
    verify_tree(&opened, indexed, &expected, cancellation)
}

fn verify_tree<R: std::io::Read + std::io::Seek>(
    root: &OpenedPath,
    indexed: &mut IndexedArtifact<R>,
    expected: &BTreeSet<String>,
    cancellation: &(impl OperationControl + ?Sized),
) -> Result<(), MaterializationError> {
    let (files, input) = indexed.parts();
    // Queue bounded paths, not open directories: wide Artifacts must not
    // consume one descriptor per pending sibling under managed nofile limits.
    let mut pending = vec![String::new()];
    let mut seen = BTreeSet::new();
    let mut actual = [0_u8; 16 * 1024];
    let mut expected_chunk = [0_u8; 16 * 1024];
    while let Some(prefix) = pending.pop() {
        let relative = if prefix.is_empty() {
            "."
        } else {
            prefix.as_str()
        };
        let directory = fd::open_beneath(root.fd(), Path::new(relative), true).map_err(problem)?;
        check(cancellation)?;
        if !directory.metadata().is_trusted_directory()
            || directory.metadata().mode() & 0o777 != 0o700
        {
            return Err(invalid("view directory mode or owner changed"));
        }
        for name in entries(&directory, MAX_VIEW_ENTRIES)? {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if !expected.contains(&path) || !seen.insert(path.clone()) {
                return Err(invalid("unexpected or repeated view entry"));
            }
            if let Some(file) = files.find(path.as_str()) {
                let opened = fd::open_existing_regular(directory.fd(), Path::new(&name))?;
                let expected_identity = opened.metadata().identity();
                let mut actual_file = opened.into_file();
                let metadata = actual_file.metadata()?;
                if metadata.len() != file.size
                    || metadata.permissions().mode() & 0o777
                        != if file.executable {
                            0o500
                        } else {
                            0o400
                        }
                {
                    return Err(invalid("view file mode or size changed"));
                }
                let mut expected_bytes = IndexedArtifact::<R>::reader_from(input, &file)?;
                loop {
                    check(cancellation)?;
                    let size = expected_bytes.read(&mut expected_chunk)?;
                    if size == 0 {
                        break;
                    }
                    actual_file.read_exact(&mut actual[..size])?;
                    if actual[..size] != expected_chunk[..size] {
                        return Err(invalid("view file bytes changed"));
                    }
                }
                let after = actual_file.metadata()?;
                let mut extra = [0u8; 1];
                let reopened = fd::open_existing_regular(directory.fd(), Path::new(&name))?;
                if actual_file.read(&mut extra)? != 0
                    || after.len() != file.size
                    || after.permissions().mode() & 0o7777
                        != if file.executable {
                            0o500
                        } else {
                            0o400
                        }
                    || reopened.metadata().identity() != expected_identity
                {
                    return Err(invalid("view file changed during verification"));
                }
                actual_file.sync_all()?;
            } else {
                pending.push(path);
            }
        }
        fd::sync_directory(directory.fd())?;
    }
    if seen != *expected {
        return Err(invalid("view is incomplete"));
    }
    Ok(())
}

fn remove_tree(
    parent: &OpenedPath,
    name: &str,
    root: &OpenedPath,
) -> Result<(), MaterializationError> {
    // Postorder, bounded and descriptor-relative. Unknown entry types are never
    // followed or removed; an interrupted cleanup is safe to retry explicitly.
    let mut pending = vec![(
        fd::open_beneath(root.fd(), Path::new("."), true).map_err(problem)?,
        String::new(),
        false,
    )];
    let mut visited = 0;
    while let Some((directory, path, explored)) = pending.pop() {
        if !directory.metadata().is_trusted_directory() {
            return Err(invalid("unsafe view directory"));
        }
        if !explored {
            pending.push((
                fd::open_beneath(
                    root.fd(),
                    if path.is_empty() {
                        Path::new(".")
                    } else {
                        Path::new(&path)
                    },
                    true,
                )
                .map_err(problem)?,
                path.clone(),
                true,
            ));
            for entry in entries(&directory, MAX_VIEW_ENTRIES)? {
                visited += 1;
                if visited > MAX_VIEW_ENTRIES {
                    return Err(invalid("oversized view staging tree"));
                }
                let opened =
                    fd::open_beneath(directory.fd(), Path::new(&entry), false).map_err(problem)?;
                match opened.metadata().file_type() {
                    FileType::Regular if opened.metadata().is_trusted_regular() => {
                        fd::unlink_opened(
                            directory.fd(),
                            Path::new(&entry),
                            opened.metadata().identity(),
                        )?;
                        fd::sync_directory(directory.fd())?;
                    }
                    FileType::Directory if opened.metadata().is_trusted_directory() => {
                        let child_path = if path.is_empty() {
                            entry
                        } else {
                            format!("{path}/{entry}")
                        };
                        pending.push((opened, child_path, false));
                    }
                    _ => return Err(invalid("unsafe entry in view staging")),
                }
            }
        } else if !path.is_empty() {
            let (parent_path, leaf) = path
                .rsplit_once('/')
                .unwrap_or(("", path.as_str()));
            let holder = fd::open_beneath(
                root.fd(),
                if parent_path.is_empty() {
                    Path::new(".")
                } else {
                    Path::new(parent_path)
                },
                true,
            )
            .map_err(problem)?;
            fd::remove_directory(
                holder.fd(),
                Path::new(leaf),
                directory.metadata().identity(),
            )?;
        }
    }
    fd::remove_directory(
        parent.fd(),
        Path::new(name),
        root.metadata().identity(),
    )?;
    Ok(())
}

fn entries(directory: &OpenedPath, max: usize) -> Result<Vec<String>, MaterializationError> {
    let mut count = 0;
    fd::read_directory(directory, |_| {
        count += 1;
        if count > max {
            Err(())
        } else {
            Ok(())
        }
    })
    .map_err(problem)?
    .into_iter()
    .map(|name| {
        name.into_string()
            .map_err(|_| invalid("non-UTF-8 view entry"))
    })
    .collect()
}

fn open_optional(
    parent: &OpenedPath,
    name: &str,
) -> Result<Option<OpenedPath>, MaterializationError> {
    match fd::open_beneath(parent.fd(), Path::new(name), true) {
        Ok(directory) if directory.metadata().is_trusted_directory() => Ok(Some(directory)),
        Err(fd::OpenError::Other(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        other => Err(problem(other)),
    }
}

fn lock_views(
    parent: &OpenedPath,
    cancellation: &(impl OperationControl + ?Sized),
) -> Result<ViewGuard, MaterializationError> {
    let started = Instant::now();
    let guard = fd::open_beneath(parent.fd(), Path::new("."), true).map_err(problem)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fd::flock(guard.fd(), FlockMode::ExclusiveNonblocking)? {
        check(cancellation)?;
        if Instant::now() >= deadline {
            return Err(invalid("view namespace busy"));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Ok(ViewGuard {
        directory: guard,
        acquired: Instant::now(),
        wait: started.elapsed(),
    })
}

pub(crate) fn check(
    cancellation: &(impl OperationControl + ?Sized),
) -> Result<(), MaterializationError> {
    if cancellation.is_cancelled() {
        Err(MaterializationError::Cancelled)
    } else {
        Ok(())
    }
}

pub(crate) fn cancellation_io(
    cancellation: &(impl OperationControl + ?Sized),
) -> std::io::Result<()> {
    if cancellation.is_cancelled() {
        Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "materialization cancelled",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn cancellation_store_error(
    error: StoreError,
    cancellation: &(impl OperationControl + ?Sized),
) -> MaterializationError {
    if cancellation.is_cancelled()
        && matches!(error, StoreError::Io(ref source) if source.kind() == std::io::ErrorKind::Interrupted)
    {
        MaterializationError::Cancelled
    } else {
        error.into()
    }
}

fn copy_with_cancellation(
    mut input: impl std::io::Read,
    output: &mut impl std::io::Write,
    cancellation: &(impl OperationControl + ?Sized),
) -> Result<u64, MaterializationError> {
    let mut buffer = [0_u8; 8 * 1024];
    let mut copied = 0_u64;
    loop {
        check(cancellation)?;
        let count = match input.read(&mut buffer) {
            Ok(0) => return Ok(copied),
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        check(cancellation)?;
        output.write_all(&buffer[..count])?;
        copied += count as u64;
    }
}

pub(crate) fn invalid(reason: &str) -> MaterializationError {
    MaterializationError::Invalid(reason.to_owned())
}
pub(crate) fn problem(error: impl std::fmt::Debug) -> MaterializationError {
    invalid(&format!("{error:?}"))
}

#[cfg(test)]
mod tests;

use crate::build::records::{Action, MAX_RECORD_BYTES, Receipt};

/// Materialize a retained Artifact in the Store's private cache. This function
/// does not execute the entry or claim its runtime closure is available.
pub fn materialize_artifact(
    store: &Store,
    root: &RootName,
    receipt_digest: ContentDigest,
) -> Result<MaterializedArtifact, MaterializationError> {
    materialize_named_artifact(store, root, receipt_digest, "out")
}

/// Materialize one output from a verified, retained multi-output receipt.
/// The other outputs remain part of the same root and action identity.
pub fn materialize_named_artifact(
    store: &Store,
    root: &RootName,
    receipt_digest: ContentDigest,
    output_name: &str,
) -> Result<MaterializedArtifact, MaterializationError> {
    materialize_authorized(
        store,
        root,
        receipt_digest,
        output_name,
        None,
        &Cancellation::default(),
    )
}

pub(crate) fn materialize_named_with_cancellation(
    store: &Store,
    root: &RootName,
    receipt_digest: ContentDigest,
    output_name: &str,
    cancellation: &(impl OperationControl + ?Sized),
) -> Result<MaterializedArtifact, MaterializationError> {
    materialize_authorized(
        store,
        root,
        receipt_digest,
        output_name,
        None,
        cancellation,
    )
}

/// Authorize a provider through the retained application result rather than
/// requiring its independent root to survive garbage collection.
pub(crate) fn materialize_provider_with_cancellation(
    store: &Store,
    application_root: &RootName,
    application_receipt: ContentDigest,
    provider_receipt: ContentDigest,
    output_name: &str,
    cancellation: &(impl OperationControl + ?Sized),
) -> Result<MaterializedArtifact, MaterializationError> {
    materialize_authorized(
        store,
        application_root,
        provider_receipt,
        output_name,
        Some(application_receipt),
        cancellation,
    )
}

#[cfg(test)]
pub(crate) fn materialize_provider(
    store: &Store,
    application_root: &RootName,
    application_receipt: ContentDigest,
    provider_receipt: ContentDigest,
) -> Result<MaterializedArtifact, MaterializationError> {
    materialize_provider_with_cancellation(
        store,
        application_root,
        application_receipt,
        provider_receipt,
        "out",
        &Cancellation::default(),
    )
}

fn materialize_authorized(
    store: &Store,
    root: &RootName,
    receipt_digest: ContentDigest,
    output_name: &str,
    owner_digest: Option<ContentDigest>,
    cancellation: &(impl OperationControl + ?Sized),
) -> Result<MaterializedArtifact, MaterializationError> {
    check(cancellation)?;
    let lease = store.operation()?;
    let references = lease
        .build_references(root)?
        .ok_or(MaterializationError::MissingResult)?;
    let bytes = lease
        .read_verified(receipt_digest, MAX_RECORD_BYTES)?
        .ok_or(MaterializationError::MissingResult)?;
    let receipt = Receipt::parse(bytes.as_bytes()).map_err(problem)?;
    if receipt.digest() != receipt_digest {
        return Err(invalid("root references disagree with receipt"));
    }
    if let Some(owner_digest) = owner_digest {
        let bytes = lease
            .read_verified(owner_digest, MAX_RECORD_BYTES)?
            .ok_or(MaterializationError::MissingResult)?;
        let owner = Receipt::parse(bytes.as_bytes()).map_err(problem)?;
        let bytes = lease
            .read_verified(owner.action, MAX_RECORD_BYTES)?
            .ok_or(MaterializationError::MissingResult)?;
        let owner_action = Action::parse(bytes.as_bytes()).map_err(problem)?;
        if owner.digest() != owner_digest
            || owner.references() != references
            || !owner.matches_action(&owner_action)
            || !owner_action.inputs.iter().any(|input| {
                input.origin
                    == (OutputOrigin::Built {
                        receipt: receipt_digest,
                    })
            })
            || !receipt
                .references()
                .iter()
                .all(|digest| owner.inputs.contains(digest))
        {
            return Err(invalid("provider is not retained by application"));
        }
        owner
            .verify_inputs(&lease, &owner_action, cancellation)
            .map_err(|error| {
                if cancellation.is_cancelled() {
                    MaterializationError::Cancelled
                } else {
                    problem(error)
                }
            })?;
        owner
            .verify_retained_inputs(&lease, &owner_action, || {
                if cancellation.is_cancelled() {
                    Err(crate::build::records::invalid("cancelled"))
                } else {
                    Ok(())
                }
            })
            .map_err(|error| {
                if cancellation.is_cancelled() {
                    MaterializationError::Cancelled
                } else {
                    problem(error)
                }
            })?;
        for output in owner.outputs.values() {
            check(cancellation)?;
            let input = lease
                .open_verified_checked(
                    output.artifact,
                    owner_action.program.resources.output_limit(),
                    || cancellation_io(cancellation),
                )
                .map_err(|error| cancellation_store_error(error, cancellation))?
                .ok_or(MaterializationError::MissingResult)?;
            if artifact::validate_stream_checked(input, "", cancellation).map_err(|error| {
                if cancellation.is_cancelled() {
                    MaterializationError::Cancelled
                } else {
                    problem(error)
                }
            })? != output.files
            {
                return Err(invalid(
                    "application output disagrees with receipt",
                ));
            }
        }
    } else if receipt.references() != references {
        return Err(invalid("root references disagree with receipt"));
    }
    let bytes = lease
        .read_verified(receipt.action, MAX_RECORD_BYTES)?
        .ok_or(MaterializationError::MissingResult)?;
    let action = Action::parse(bytes.as_bytes()).map_err(problem)?;
    if !receipt.matches_action(&action) {
        return Err(invalid("action and receipt disagree"));
    }
    receipt
        .verify_inputs(&lease, &action, cancellation)
        .map_err(|error| {
            if cancellation.is_cancelled() {
                MaterializationError::Cancelled
            } else {
                problem(error)
            }
        })?;
    receipt
        .verify_retained_inputs(&lease, &action, || {
            if cancellation.is_cancelled() {
                Err(crate::build::records::invalid("cancelled"))
            } else {
                Ok(())
            }
        })
        .map_err(|error| {
            if cancellation.is_cancelled() {
                MaterializationError::Cancelled
            } else {
                problem(error)
            }
        })?;
    let output = receipt
        .output(output_name)
        .ok_or_else(|| invalid("output is not declared by the receipt"))?;
    let artifact_limit = action.program.resources.output_limit();
    verify_other_outputs(
        &lease,
        &receipt,
        output_name,
        artifact_limit,
        cancellation,
    )?;
    materialize_verified(
        lease,
        AuthorizedOutput {
            identity: OutputIdentity {
                action: receipt.action,
                origin: OutputOrigin::Built {
                    receipt: receipt_digest,
                },
                artifact: output.artifact,
                output: output_name.to_owned(),
            },
            references: receipt.references(),
            files: output.files,
            maximum_bytes: artifact_limit,
        },
        cancellation,
    )
}

fn verify_other_outputs(
    lease: &OperationLease,
    receipt: &Receipt,
    selected: &str,
    artifact_limit: u64,
    cancellation: &(impl OperationControl + ?Sized),
) -> Result<(), MaterializationError> {
    // A named receipt denotes one indivisible result; no partial views.
    for (name, other) in &receipt.outputs {
        check(cancellation)?;
        if name == selected {
            continue;
        }
        let input = lease
            .open_verified_checked(other.artifact, artifact_limit, || {
                cancellation_io(cancellation)
            })
            .map_err(|error| cancellation_store_error(error, cancellation))?
            .ok_or(MaterializationError::MissingResult)?;
        if artifact::validate_stream_checked(input, "", cancellation).map_err(|error| {
            if cancellation.is_cancelled() {
                MaterializationError::Cancelled
            } else {
                problem(error)
            }
        })? != other.files
        {
            return Err(invalid(
                "named output file count disagrees with receipt",
            ));
        }
    }
    Ok(())
}

// Public retained-output reopening is a format-dispatch adapter. The generic
// materializer and its portable identity types do not depend on build records.
impl RetainedOutput {
    /// Open files for a build input with the producer's live cancellation policy.
    /// This does not select or authorize a runtime command from an import.
    pub(crate) fn open_for_build(
        &self,
        store: &Store,
        cancellation: &(impl OperationControl + ?Sized),
    ) -> Result<MaterializedArtifact, MaterializationError> {
        let view = match self.identity.origin {
            OutputOrigin::Built {
                receipt,
            } => materialize_named_with_cancellation(
                store,
                &self.root,
                receipt,
                &self.identity.output,
                cancellation,
            )?,
            OutputOrigin::Imported {
                manifest,
            } => crate::result::materialize_imported_control(
                store,
                &self.root,
                manifest,
                &self.identity,
                cancellation,
            )?,
        };
        if view.identity() != &self.identity {
            return Err(invalid(
                "build input identity disagrees with verified result",
            ));
        }
        Ok(view)
    }

    /// Recheck the root and its evidence: build receipt/inputs or pinned import
    /// manifest/artifacts. Reconstruct views as needed; never trust an old path.
    pub fn open(
        &self,
        store: &Store,
        cancellation: &Cancellation,
    ) -> Result<MaterializedArtifact, MaterializationError> {
        let view = match self.identity.origin {
            OutputOrigin::Built {
                receipt,
            } => materialize_named_with_cancellation(
                store,
                &self.root,
                receipt,
                &self.identity.output,
                cancellation,
            )?,
            OutputOrigin::Imported {
                manifest,
            } => crate::result::materialize_imported(
                store,
                &self.root,
                manifest,
                &self.identity,
                cancellation,
            )?,
        };
        if view.identity() != &self.identity {
            return Err(invalid(
                "retained output identity disagrees with verified result",
            ));
        }
        Ok(view)
    }
}

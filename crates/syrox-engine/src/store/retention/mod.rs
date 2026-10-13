//! Interesses nos objetos e views usados por uma operação ou processo.
//!
//! Cada interesse usa seu próprio inode de lock. Assim, manter um output vivo
//! não bloqueia toda a manutenção da Store. O manager pode guardar um descritor
//! independente do interesse; ele precisa continuar retido até o processo encerrar.

use super::*;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;

const HEADER: &str = "syrox-interest-v1\n";
const MAX_INTEREST_BYTES: u64 = MAX_ROOT_BYTES * 2;
const MAX_INTERESTS: u64 = MAX_GC_ROOTS;

pub(crate) mod durable;

#[derive(Debug)]
struct InterestLock(File);
impl Drop for InterestLock {
    fn drop(&mut self) {
        let _ = crate::platform::linux::fd::flock(
            self.0.as_fd(),
            crate::platform::linux::fd::FlockMode::Unlock,
        );
    }
}

/// Live interest in a bounded set of objects and materialized views. Unlike an
/// operation lease, this does not exclude Store maintenance. It is not a durable
/// root: the last local/process descriptor closing ends the interest.
#[derive(Clone, Debug)]
pub struct ObjectLease {
    inner: Arc<StoreInner>,
    directory: Arc<crate::platform::linux::fd::OpenedPath>,
    name: String,
    identity: crate::platform::linux::fd::FileIdentity,
    _lock: Arc<InterestLock>,
    references: Arc<[ContentDigest]>,
    views: Arc<[ContentDigest]>,
}

impl ObjectLease {
    pub(crate) const MAX_HANDOFF_RECORD_BYTES: u64 = MAX_INTEREST_BYTES;
    /// Validate canonical interest bytes and required coverage, not Store
    /// provenance, lock ownership, manager admission or execution authority.
    pub(crate) fn validate_handoff_record(
        bytes: &[u8],
        references: &[ContentDigest],
        views: &[ContentDigest],
    ) -> Result<(), StoreError> {
        if bytes.len() as u64 > MAX_INTEREST_BYTES {
            return Err(StoreError::InterestCorrupt);
        }
        let (actual_references, actual_views) = decode(bytes)?;
        if references
            .iter()
            .any(|digest| actual_references.binary_search(digest).is_err())
            || views
                .iter()
                .any(|digest| actual_views.binary_search(digest).is_err())
        {
            return Err(StoreError::InterestCorrupt);
        }
        Ok(())
    }
    pub(crate) fn operation(&self) -> Result<OperationLease, StoreError> {
        Store {
            inner: Arc::clone(&self.inner),
        }
        .operation()
    }

    pub(crate) fn same_store(&self, store: &Store) -> Result<bool, StoreError> {
        // Revalidate both permanent anchors, including independently opened Stores.
        drop(open_lease(&self.inner)?);
        drop(open_lease(&store.inner)?);
        Ok(self.inner.lease_identity == store.inner.lease_identity)
    }

    pub(crate) fn combine(leases: &[&Self]) -> Result<Self, StoreError> {
        let first = leases
            .first()
            .ok_or(StoreError::InterestCorrupt)?;
        let mut references = BTreeSet::new();
        let mut views = BTreeSet::new();
        for lease in leases {
            if lease.inner.lease_identity != first.inner.lease_identity {
                return Err(StoreError::InterestStoreMismatch);
            }
            references.extend(lease.references.iter().copied());
            views.extend(lease.views.iter().copied());
            charge(
                references.len() as u64,
                MAX_ROOT_REFERENCES,
                "interest references",
            )?;
            charge(
                views.len() as u64,
                MAX_ROOT_REFERENCES,
                "interest views",
            )?;
        }
        first.operation()?.retain_objects(
            &references.into_iter().collect::<Vec<_>>(),
            &views.into_iter().collect::<Vec<_>>(),
        )
    }

    /// A distinct OFD is essential: dropping a local lease explicitly unlocks
    /// its own description, and must not unlock a manager's `SCM_RIGHTS` copy.
    pub(crate) fn process_retention(&self) -> Result<File, StoreError> {
        let _barrier = self.operation()?;
        let opened = open_regular(&self.directory, &self.name)?;
        if opened.metadata().identity() != self.identity {
            return Err(StoreError::InterestCorrupt);
        }
        if !crate::platform::linux::fd::flock(
            opened.fd(),
            crate::platform::linux::fd::FlockMode::Shared,
        )? {
            return Err(StoreError::Busy);
        }
        Ok(opened.into_file())
    }

    pub(crate) fn open_verified_checked(
        &self,
        expected: ContentDigest,
        maximum_bytes: u64,
        check: impl FnMut() -> io::Result<()>,
    ) -> Result<Option<VerifiedReader>, StoreError> {
        if self.references.binary_search(&expected).is_err() {
            return Err(StoreError::InterestCorrupt);
        }
        self.operation()?
            .open_verified_checked(expected, maximum_bytes, check)
    }

    pub(crate) fn publish_root_checked(
        &self,
        name: &RootName,
        references: &[ContentDigest],
        check: impl FnMut() -> io::Result<()>,
    ) -> Result<RootPublicationState, StoreError> {
        if references
            .iter()
            .any(|digest| self.references.binary_search(digest).is_err())
        {
            return Err(StoreError::InterestCorrupt);
        }
        self.operation()?
            .publish_root_checked(name, references, check)
    }
}

impl OperationLease {
    /// Transfer already verified references to a runtime interest while the
    /// operation barrier still excludes GC. Views must be referenced artifacts.
    pub(crate) fn retain_objects(
        &self,
        references: &[ContentDigest],
        views: &[ContentDigest],
    ) -> Result<ObjectLease, StoreError> {
        validate_sets(references, views)?;
        for digest in references {
            // Admission already authenticated these bytes. Confirm each regular
            // object still exists under the same publication/sweep barrier.
            let shard = open_shard(&self.inner, *digest)?;
            drop(open_regular(&shard, &digest.to_string())?);
        }
        let directory = Arc::new(open_interest_directory(&self.inner)?);
        let mut budget = WorkBudget::new(MAX_GC_WORK, "interest publication work");
        if directory_names_bounded(
            &directory,
            MAX_INTERESTS,
            "interests",
            &mut budget,
        )?
        .len() as u64
            >= MAX_INTERESTS
        {
            return Err(StoreError::LimitExceeded {
                resource: "interests",
            });
        }
        let name = crate::platform::linux::fd::operation_name()?;
        let (opened, created) =
            crate::platform::linux::fd::initialize_regular(directory.fd(), Path::new(&name))?;
        if !created {
            return Err(StoreError::InterestCorrupt);
        }
        let identity = opened.metadata().identity();
        if !crate::platform::linux::fd::flock(
            opened.fd(),
            crate::platform::linux::fd::FlockMode::Shared,
        )? {
            return Err(StoreError::Busy);
        }
        let mut file = opened.into_file();
        let bytes = encode(references, views);
        charge(
            bytes.len() as u64,
            MAX_INTEREST_BYTES,
            "interest bytes",
        )?;
        file.write_all(&bytes)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
        crate::platform::linux::fd::sync_directory(directory.fd())?;
        crate::platform::linux::fd::sync_directory(self.inner.private_parent.fd())?;
        // A crash during writing leaves an unlocked abandoned record. No reader
        // can scan it before this operation releases the global shared barrier.
        Ok(ObjectLease {
            inner: Arc::clone(&self.inner),
            directory,
            name,
            identity,
            _lock: Arc::new(InterestLock(file)),
            references: Arc::from(references),
            views: Arc::from(views),
        })
    }
}

pub(super) fn open_interest_directory(
    inner: &StoreInner,
) -> Result<crate::platform::linux::fd::OpenedPath, StoreError> {
    let directory = open_named_directory(inner.private_parent.fd(), "interests")?;
    if directory.metadata().identity() != inner.interests.metadata().identity() {
        return Err(StoreError::InterestCorrupt);
    }
    Ok(directory)
}

fn validate_sets(references: &[ContentDigest], views: &[ContentDigest]) -> Result<(), StoreError> {
    for values in [references, views] {
        charge(
            values.len() as u64,
            MAX_ROOT_REFERENCES,
            "interest references",
        )?;
        if values.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(StoreError::InterestCorrupt);
        }
    }
    if views
        .iter()
        .any(|digest| references.binary_search(digest).is_err())
    {
        return Err(StoreError::InterestCorrupt);
    }
    Ok(())
}

fn encode(references: &[ContentDigest], views: &[ContentDigest]) -> Vec<u8> {
    let mut text = HEADER.to_owned();
    for digest in references {
        writeln!(text, "object={digest}").expect("writing to a String cannot fail");
    }
    for digest in views {
        writeln!(text, "view={digest}").expect("writing to a String cannot fail");
    }
    text.into_bytes()
}

fn decode(bytes: &[u8]) -> Result<(Vec<ContentDigest>, Vec<ContentDigest>), StoreError> {
    let text = std::str::from_utf8(bytes).map_err(|_| StoreError::InterestCorrupt)?;
    let text = text
        .strip_prefix(HEADER)
        .ok_or(StoreError::InterestCorrupt)?;
    let mut references = Vec::new();
    let mut views = Vec::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("object=") {
            if !views.is_empty() {
                return Err(StoreError::InterestCorrupt);
            }
            references.push(
                value
                    .parse()
                    .map_err(|_| StoreError::InterestCorrupt)?,
            );
        } else if let Some(value) = line.strip_prefix("view=") {
            views.push(
                value
                    .parse()
                    .map_err(|_| StoreError::InterestCorrupt)?,
            );
        } else {
            return Err(StoreError::InterestCorrupt);
        }
    }
    validate_sets(&references, &views)?;
    if encode(&references, &views) != bytes {
        return Err(StoreError::InterestCorrupt);
    }
    Ok((references, views))
}

#[derive(Debug, Default)]
pub(super) struct InterestInventory {
    pub references: BTreeSet<ContentDigest>,
    pub views: BTreeSet<ContentDigest>,
    directory: Option<crate::platform::linux::fd::OpenedPath>,
    abandoned: Vec<(String, crate::platform::linux::fd::OpenedPath)>,
}

pub(super) fn inventory(
    inner: &StoreInner,
    limits: GcLimits,
    work: &mut WorkBudget,
) -> Result<InterestInventory, StoreError> {
    let directory = open_interest_directory(inner)?;
    let mut inventory = InterestInventory::default();
    let mut bytes = 0_u64;
    let mut references_count = 0_u64;
    for name in directory_names_bounded(
        &directory,
        limits.roots.min(MAX_INTERESTS),
        "interests",
        work,
    )? {
        let persistent = exact_temporary(&name, "hold-");
        if !persistent && !exact_temporary(&name, "op-") {
            return Err(StoreError::InterestCorrupt);
        }
        let opened = open_regular(&directory, &name)?;
        if !persistent
            && crate::platform::linux::fd::flock(
                opened.fd(),
                crate::platform::linux::fd::FlockMode::ExclusiveNonblocking,
            )?
        {
            inventory.abandoned.push((name, opened));
            continue;
        }
        let mode = if persistent {
            0o600
        } else {
            0o400
        };
        if opened.metadata().mode() & 0o7777 != mode {
            return Err(StoreError::InterestCorrupt);
        }
        charge(
            opened.metadata().size(),
            MAX_INTEREST_BYTES,
            "interest bytes",
        )?;
        bytes = bytes
            .checked_add(opened.metadata().size())
            .ok_or(StoreError::InterestCorrupt)?;
        charge(bytes, limits.root_bytes, "GC interest bytes")?;
        let identity = opened.metadata().identity();
        let mut contents = Vec::new();
        opened
            .into_file()
            .take(MAX_INTEREST_BYTES + 1)
            .read_to_end(&mut contents)?;
        charge(
            contents.len() as u64,
            MAX_INTEREST_BYTES,
            "interest bytes",
        )?;
        let reopened = open_regular(&directory, &name)?;
        if reopened.metadata().identity() != identity || reopened.metadata().mode() & 0o7777 != mode
        {
            return Err(StoreError::InterestCorrupt);
        }
        let (references, views) = if persistent {
            durable::decode(&contents)?
        } else {
            decode(&contents)?
        };
        references_count += (references.len() + views.len()) as u64;
        charge(
            references_count,
            limits.references,
            "GC interest references",
        )?;
        work.charge((references.len() + views.len()) as u64)?;
        inventory.references.extend(references);
        inventory.views.extend(views);
    }
    inventory.directory = Some(directory);
    Ok(inventory)
}

impl InterestInventory {
    pub(super) fn cleanup_work(&self) -> u64 {
        self.abandoned.len() as u64 + u64::from(!self.abandoned.is_empty())
    }
    pub(super) fn cleanup(&self, report: &mut GcReport) {
        let Some(directory) = &self.directory else {
            return;
        };
        for (name, file) in &self.abandoned {
            match crate::platform::linux::fd::unlink_opened(
                directory.fd(),
                Path::new(name),
                file.metadata().identity(),
            ) {
                Ok(()) => report.removed_interests += 1,
                Err(source) => report.failures.push(MaintenanceFailure {
                    path: format!(".syrox-store/interests/{name}"),
                    operation: MaintenanceFailureOperation::Unlink,
                    source,
                }),
            }
        }
        if !self.abandoned.is_empty()
            && let Err(source) = crate::platform::linux::fd::sync_directory(directory.fd())
        {
            report.failures.push(MaintenanceFailure {
                path: ".syrox-store/interests".into(),
                operation: MaintenanceFailureOperation::Synchronize,
                source,
            });
        }
    }
}

impl MaintenanceLease {
    pub(crate) fn protected_views(&self) -> Result<BTreeSet<ContentDigest>, StoreError> {
        Ok(inventory(
            &self.inner,
            GcLimits::default(),
            &mut WorkBudget::new(MAX_GC_WORK, "view interest work"),
        )?
        .views)
    }
}

#[cfg(test)]
mod tests;

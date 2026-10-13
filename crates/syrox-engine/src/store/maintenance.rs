//! Inventory, collection and recovery under the exclusive maintenance lease.
//!
//! Inventory validates the protected layout and retains each candidate's open
//! directory and inode identity. Mutation starts only after bounded enumeration
//! succeeds; unlink and synchronization failures remain visible in the report.
//! Shared interests and traversal budgets stay with the Store boundary.

use super::*;

impl MaintenanceLease {
    /// Private rebuildable view cache. Maintenance excludes materialization, while
    /// live object interests identify runtime trees that must not be reclaimed.
    #[cfg(target_os = "linux")]
    pub(crate) fn view_directory(
        &self,
    ) -> Result<crate::platform::linux::fd::OpenedPath, StoreError> {
        ensure(self.inner.private_parent.fd(), "views")
    }

    pub fn recover(&mut self, limits: RecoveryLimits) -> Result<RecoveryReport, StoreError> {
        #[cfg(target_os = "linux")]
        {
            validate_recovery_limits(limits)?;
            let mut work = WorkBudget::new(limits.work, "recovery work");
            let candidates = inventory_recovery(&self.inner, limits, &mut work)?;
            let mut sync_directories = BTreeMap::new();
            for candidate in &candidates {
                sync_directories.insert(
                    candidate.directory_name.clone(),
                    Arc::clone(&candidate.directory),
                );
            }
            work.charge(candidates.len() as u64 + sync_directories.len() as u64)?;

            let mut report = RecoveryReport::default();
            let mut changed = BTreeSet::new();
            for candidate in candidates {
                match crate::platform::linux::fd::unlink_opened(
                    candidate.directory.fd(),
                    Path::new(&candidate.name),
                    candidate.identity,
                ) {
                    Ok(()) => {
                        report.removed.push(format!(
                            "{}/{}",
                            candidate.directory_name, candidate.name
                        ));
                        changed.insert(candidate.directory_name);
                    }
                    Err(source) => report.failures.push(MaintenanceFailure {
                        path: format!("{}/{}", candidate.directory_name, candidate.name),
                        operation: MaintenanceFailureOperation::Unlink,
                        source,
                    }),
                }
            }
            for directory_name in changed {
                let directory = sync_directories
                    .get(&directory_name)
                    .expect("recovery plan retains every candidate directory");
                if let Err(source) = crate::platform::linux::fd::sync_directory(directory.fd()) {
                    report.failures.push(MaintenanceFailure {
                        path: directory_name,
                        operation: MaintenanceFailureOperation::Synchronize,
                        source,
                    });
                }
            }
            report.uncertain = !report.failures.is_empty();
            Ok(report)
        }
    }

    pub fn garbage_collect(&mut self, request: &GcRequest) -> Result<GcReport, StoreError> {
        #[cfg(target_os = "linux")]
        {
            validate_gc_limits(request.limits)?;
            charge(
                request.remove_roots.len() as u64,
                request.limits.roots,
                "GC root removals",
            )?;
            let mut work = WorkBudget::new(request.limits.work, "GC work");
            work.charge(request.remove_roots.len() as u64)?;
            let removed_set: BTreeSet<_> = request.remove_roots.iter().cloned().collect();
            if removed_set.len() != request.remove_roots.len() {
                return Err(StoreError::DuplicateRootRemoval);
            }

            let inventory = inventory_gc(&self.inner, request.limits, &mut work)?;
            for name in &request.remove_roots {
                if !inventory.roots.contains_key(name) {
                    return Err(StoreError::MissingRoot {
                        name: name.clone(),
                    });
                }
            }
            let mut live = inventory.interests.references.clone();
            for (name, root) in &inventory.roots {
                if removed_set.contains(name) {
                    continue;
                }
                for digest in &root.digests {
                    work.charge(1)?;
                    live.insert(*digest);
                }
            }
            let mut report = GcReport::default();
            let mut candidate_directories = BTreeMap::new();
            for (digest, object) in &inventory.objects {
                work.charge(1)?;
                if !live.contains(digest) {
                    charge(
                        report.candidates.len() as u64 + 1,
                        request.limits.candidates,
                        "GC candidates",
                    )?;
                    report.candidate_bytes = report
                        .candidate_bytes
                        .checked_add(object.size)
                        .ok_or(StoreError::LimitExceeded {
                            resource: "GC candidate bytes",
                        })?;
                    report.candidates.push(GcCandidate {
                        digest: *digest,
                        bytes: object.size,
                    });
                    candidate_directories.insert(
                        object.shard_name.clone(),
                        Arc::clone(&object.directory),
                    );
                }
            }
            if !request.collect {
                return Ok(report);
            }

            work.charge(
                request.remove_roots.len() as u64
                    + u64::from(!request.remove_roots.is_empty())
                    + report.candidates.len() as u64
                    + candidate_directories.len() as u64
                    + inventory.interests.cleanup_work(),
            )?;

            for name in &request.remove_roots {
                let root = inventory
                    .roots
                    .get(name)
                    .expect("requested roots were admitted before mutation");
                match crate::platform::linux::fd::unlink_opened(
                    inventory.roots_directory.fd(),
                    Path::new(name.as_str()),
                    root.identity,
                ) {
                    Ok(()) => report.removed_roots.push(name.clone()),
                    Err(source) => report.failures.push(MaintenanceFailure {
                        path: format!("roots/retained/{name}"),
                        operation: MaintenanceFailureOperation::Unlink,
                        source,
                    }),
                }
            }
            if !request.remove_roots.is_empty()
                && let Err(source) =
                    crate::platform::linux::fd::sync_directory(inventory.roots_directory.fd())
            {
                report.failures.push(MaintenanceFailure {
                    path: "roots/retained".into(),
                    operation: MaintenanceFailureOperation::Synchronize,
                    source,
                });
            }
            if !report.failures.is_empty() {
                report.uncertain = true;
                return Ok(report);
            }

            let mut changed = BTreeSet::new();
            for candidate in &report.candidates {
                let object = inventory
                    .objects
                    .get(&candidate.digest)
                    .expect("candidate came from the validated object inventory");
                match crate::platform::linux::fd::unlink_opened(
                    object.directory.fd(),
                    Path::new(&candidate.digest.to_string()),
                    object.identity,
                ) {
                    Ok(()) => {
                        report.removed_objects.push(candidate.digest);
                        changed.insert(object.shard_name.clone());
                    }
                    Err(source) => report.failures.push(MaintenanceFailure {
                        path: format!(
                            "objects/sha256/{}/{}",
                            object.shard_name, candidate.digest
                        ),
                        operation: MaintenanceFailureOperation::Unlink,
                        source,
                    }),
                }
            }
            for shard_name in changed {
                let shard = candidate_directories
                    .get(&shard_name)
                    .expect("GC plan retains every candidate shard");
                if let Err(source) = crate::platform::linux::fd::sync_directory(shard.fd()) {
                    report.failures.push(MaintenanceFailure {
                        path: format!("objects/sha256/{shard_name}"),
                        operation: MaintenanceFailureOperation::Synchronize,
                        source,
                    });
                }
            }
            inventory.interests.cleanup(&mut report);
            report.uncertain = !report.failures.is_empty();
            Ok(report)
        }
    }
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

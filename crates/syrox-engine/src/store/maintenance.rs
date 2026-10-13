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

use super::{
    BuildError, BuildProfile, BuildResources,
    journal::managed::{ManagedNamespaceSnapshot, inspect_worker_attempt},
    records::Action,
};
use crate::{cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest};
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

struct PinnedStageFile {
    name: &'static str,
    file: linux_fd::OpenedPath,
    digest: ContentDigest,
    size: u64,
    mode: u32,
}
/// Pinned, historically validated staging. No manager liveness or execution
/// authority is implied. A journal transition requires a fresh inspection.
pub struct ManagedBuildWorkerInspection {
    path: PathBuf,
    action: ContentDigest,
    nonce: String,
    record: Vec<u8>,
    bound_process: Option<([u8; 16], u32)>,
    namespace: Option<ManagedNamespaceSnapshot>,
    gate_identity: linux_fd::FileIdentity,
    directory: linux_fd::OpenedPath,
    stage: linux_fd::OpenedPath,
    files: Vec<PinnedStageFile>,
}
impl std::fmt::Debug for ManagedBuildWorkerInspection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedBuildWorkerInspection")
            .field("action", &self.action)
            .field(
                "namespace_prepared",
                &self.namespace_snapshot().is_some(),
            )
            .finish_non_exhaustive()
    }
}
impl ManagedBuildWorkerInspection {
    pub(in crate::build) fn record_bytes(&self) -> &[u8] {
        &self.record
    }
    /// A recorded binding, to be checked against live peer/manager evidence.
    pub(in crate::build) fn bound_process(&self) -> Option<([u8; 16], u32)> {
        self.bound_process
    }
    /// Historical journal evidence only. This never authorizes reopening a PID.
    pub(in crate::build) fn namespace_snapshot(&self) -> Option<ManagedNamespaceSnapshot> {
        self.namespace
    }
    pub(in crate::build) fn operation_path(&self) -> &Path {
        &self.path
    }
    pub(in crate::build) fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn action_digest(&self) -> ContentDigest {
        self.action
    }
    pub(in crate::build) fn worker_digest(&self) -> ContentDigest {
        self.files
            .iter()
            .find(|file| file.name == "worker")
            .expect("validated worker role")
            .digest
    }
    /// Recheck the original journal snapshot and pinned file bytes. No flock is
    /// retained between calls; this is not a gate release or a lifetime seal.
    pub fn revalidate(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        let attempt = inspect_worker_attempt(
            &self.path,
            self.action,
            &self.nonce,
            cancellation,
            deadline,
        )?;
        if attempt.gate_identity() != self.gate_identity
            || attempt.record != self.record
            || attempt.directory.metadata().identity() != self.directory.metadata().identity()
            || attempt.stage.metadata().identity() != self.stage.metadata().identity()
        {
            return Err(BuildError::InputChanged);
        }
        for pinned in &self.files {
            check(cancellation, deadline)?;
            let reopened =
                linux_fd::open_existing_regular(attempt.stage.fd(), Path::new(pinned.name))?;
            if reopened.metadata().identity() != pinned.file.metadata().identity() {
                return Err(BuildError::InputChanged);
            }
            let (_, digest) = read_file(
                &pinned.file,
                pinned.size,
                pinned.mode,
                false,
                cancellation,
                deadline,
            )?;
            if digest != pinned.digest {
                return Err(BuildError::InputChanged);
            }
            let after =
                linux_fd::open_existing_regular(attempt.stage.fd(), Path::new(pinned.name))?;
            if after.metadata().identity() != pinned.file.metadata().identity() {
                return Err(BuildError::InputChanged);
            }
        }
        attempt.revalidate()?;
        check(cancellation, deadline)
    }
}
pub fn inspect_managed_build_worker(
    operation: &Path,
    action: ContentDigest,
    nonce: &str,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<ManagedBuildWorkerInspection, BuildError> {
    let attempt = inspect_worker_attempt(operation, action, nonce, cancellation, deadline)?;
    let mut files = Vec::new();
    let action_bytes = pin_file(
        &attempt.stage,
        "build-action",
        super::records::MAX_RECORD_BYTES,
        0o400,
        &mut files,
        cancellation,
        deadline,
    )?;
    let description = Action::parse(&action_bytes)?;
    if description.digest() != action
        || description.program.profile != BuildProfile::Managed
        || description.toolchain.is_some()
        || description.worker != attempt.context.worker
    {
        return Err(BuildError::InputChanged);
    }
    let program = pin_file(
        &attempt.stage,
        "build-program",
        super::MAX_BUILD_PROGRAM_BYTES as u64,
        0o400,
        &mut files,
        cancellation,
        deadline,
    )?;
    if program != description.program.encode() {
        return Err(BuildError::InputChanged);
    }
    // Acquisition.maximum_bytes was checked against the Plan before staging.
    // Here the authenticated source pin preserves those bytes, and the Action
    // resource profile supplies the independently checkable envelope.
    let source_limit = if description.program.resources == BuildResources::Large {
        super::MAX_LARGE_SOURCE_BYTES
    } else {
        super::MAX_SOURCE_BYTES
    };
    let source = pin_file(
        &attempt.stage,
        "source",
        source_limit,
        0o400,
        &mut files,
        cancellation,
        deadline,
    )?;
    if ContentDigest::sha256(&source) != description.source {
        return Err(BuildError::InputChanged);
    }
    let worker = pin_file(
        &attempt.stage,
        "worker",
        128 * 1024 * 1024,
        0o500,
        &mut files,
        cancellation,
        deadline,
    )?;
    if ContentDigest::sha256(&worker) != description.worker {
        return Err(BuildError::InputChanged);
    }
    crate::runtime::validate_static_worker_image(&worker)
        .map_err(|_| BuildError::InvalidRequest)?;
    attempt.revalidate()?;
    let result = ManagedBuildWorkerInspection {
        path: operation.to_path_buf(),
        action,
        nonce: nonce.into(),
        record: attempt.record.clone(),
        bound_process: attempt.bound_process()?,
        namespace: attempt.namespace_snapshot()?,
        gate_identity: attempt.gate_identity(),
        directory: linux_fd::open_beneath(attempt.directory.fd(), Path::new("."), true)
            .map_err(|_| BuildError::InputChanged)?,
        stage: linux_fd::open_beneath(attempt.stage.fd(), Path::new("."), true)
            .map_err(|_| BuildError::InputChanged)?,
        files,
    };
    drop(attempt);
    result.revalidate(cancellation, deadline)?;
    Ok(result)
}
fn pin_file(
    stage: &linux_fd::OpenedPath,
    name: &'static str,
    maximum: u64,
    mode: u32,
    files: &mut Vec<PinnedStageFile>,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<Vec<u8>, BuildError> {
    let file = linux_fd::open_existing_regular(stage.fd(), Path::new(name))?;
    let size = file.metadata().size();
    if size > maximum {
        return Err(BuildError::InvalidRequest);
    }
    let (bytes, digest) = read_file(&file, size, mode, true, cancellation, deadline)?;
    let reopened = linux_fd::open_existing_regular(stage.fd(), Path::new(name))?;
    if reopened.metadata().identity() != file.metadata().identity() {
        return Err(BuildError::InputChanged);
    }
    files.push(PinnedStageFile {
        name,
        file,
        digest,
        size,
        mode,
    });
    Ok(bytes)
}
fn read_file(
    pinned: &linux_fd::OpenedPath,
    size: u64,
    mode: u32,
    collect: bool,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(Vec<u8>, ContentDigest), BuildError> {
    let file = File::from(pinned.fd().try_clone_to_owned()?);
    let before = file.metadata()?;
    if before.len() != size
        || before.mode() & 0o7777 != mode
        || before.nlink() != 1
        || before.uid() != linux_fd::effective_uid()
    {
        return Err(BuildError::InputChanged);
    }
    let mut hash = Sha256::new();
    let mut bytes = Vec::new();
    let mut offset = 0;
    let mut chunk = [0u8; 16 * 1024];
    while offset < size {
        check(cancellation, deadline)?;
        let count = file.read_at(&mut chunk, offset)?;
        if count == 0 || offset + count as u64 > size {
            return Err(BuildError::InputChanged);
        }
        hash.update(&chunk[..count]);
        if collect {
            bytes.extend_from_slice(&chunk[..count]);
        }
        offset += count as u64;
    }
    let after = file.metadata()?;
    if file.read_at(&mut chunk[..1], size)? != 0
        || after.len() != size
        || after.mode() & 0o7777 != mode
        || after.nlink() != 1
        || after.uid() != linux_fd::effective_uid()
    {
        return Err(BuildError::InputChanged);
    }
    check(cancellation, deadline)?;
    Ok((
        bytes,
        ContentDigest::from_sha256_hash(hash.finalize().into()),
    ))
}
fn check(cancellation: &Cancellation, deadline: Instant) -> Result<(), BuildError> {
    cancellation.check()?;
    if Instant::now() >= deadline {
        return Err(BuildError::InvalidRequest);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::{
        BuildPath, BuildProgram, BuildSourceFormat, BuildStep,
        journal::{Operation, managed::ManagedAttemptContext},
    };
    use crate::{store::Store, systemd::SystemdUnitName};
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    fn fixture(profile: BuildProfile) -> (tempfile::TempDir, Operation, Action, String) {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::initialize(&temporary.path().join("store")).unwrap();
        let operation = Operation::create(&store.operation().unwrap()).unwrap();
        let mut worker = crate::runtime::tests::elf(2, None, &[], None, None);
        worker[24..32].copy_from_slice(&0x0040_0100_u64.to_le_bytes());
        worker[68..72].copy_from_slice(&5_u32.to_le_bytes());
        let action = Action {
            program: BuildProgram {
                profile,
                resources: BuildResources::Standard,
                source_format: BuildSourceFormat::Raw,
                outputs: vec!["out".into()],
                steps: vec![BuildStep::Directory(BuildPath::Work(
                    "data".into(),
                ))],
            },
            source: ContentDigest::sha256(b"source"),
            toolchain: if profile == BuildProfile::Managed {
                None
            } else {
                Some(ContentDigest::sha256(b"toolchain"))
            },
            worker: ContentDigest::sha256(&worker),
            directory: "source-1".into(),
            inputs: Vec::new(),
        };
        for (name, bytes, executable) in [
            ("source", b"source".to_vec(), false),
            ("worker", worker, true),
            ("build-action", action.encode(), false),
            ("build-program", action.program.encode(), false),
        ] {
            operation
                .write_stage(name, &bytes, executable)
                .unwrap();
        }
        let context = ManagedAttemptContext {
            action: action.digest(),
            worker: action.worker,
            boot: crate::platform::linux::boot::BootId::current(
                &Cancellation::default(),
                deadline(),
            )
            .unwrap()
            .as_str()
            .into(),
            manager: ContentDigest::sha256(b"manager"),
            scope: "user:/run/user/1000/bus".into(),
            unit: SystemdUnitName::new(operation.unit()).unwrap(),
            uid: linux_fd::real_uid(),
            gid: linux_fd::real_gid(),
        };
        let nonce = operation
            .prepare_managed(&context, &Cancellation::default(), deadline())
            .unwrap();
        operation
            .authorize_managed_start(
                &context,
                &nonce,
                &Cancellation::default(),
                deadline(),
            )
            .unwrap();
        (temporary, operation, action, nonce)
    }
    #[test]
    fn inspection_pins_stage_and_rechecks_without_retaining_gate() {
        let (_temporary, operation, action, nonce) = fixture(BuildProfile::Managed);
        let cancel = Cancellation::default();
        let inspected = inspect_managed_build_worker(
            &operation.path,
            action.digest(),
            &nonce,
            &cancel,
            deadline(),
        )
        .unwrap();
        assert_eq!(inspected.action_digest(), action.digest());
        inspected.revalidate(&cancel, deadline()).unwrap();
        assert!(
            super::super::journal::lock_existing(&operation.directory, "gate")
                .unwrap()
                .is_some()
        );
        operation
            .revoke_managed(&cancel, deadline())
            .unwrap();
        assert!(inspected.revalidate(&cancel, deadline()).is_err());
        assert!(
            inspect_managed_build_worker(
                &operation.path,
                action.digest(),
                &nonce,
                &cancel,
                deadline()
            )
            .is_err()
        );
    }
    #[test]
    fn arguments_profile_modes_and_corruption_are_rejected() {
        let (_temporary, operation, action, nonce) = fixture(BuildProfile::Managed);
        let cancel = Cancellation::default();
        assert!(
            inspect_managed_build_worker(
                &operation.path,
                action.digest(),
                &"0".repeat(32),
                &cancel,
                deadline()
            )
            .is_err()
        );
        assert!(
            inspect_managed_build_worker(
                &operation.path,
                ContentDigest::sha256(b"other"),
                &nonce,
                &cancel,
                deadline()
            )
            .is_err()
        );
        let source = operation.stage_path().join("source");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            inspect_managed_build_worker(
                &operation.path,
                action.digest(),
                &nonce,
                &cancel,
                deadline()
            )
            .is_err()
        );
        std::fs::write(&source, b"tamper").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(
            inspect_managed_build_worker(
                &operation.path,
                action.digest(),
                &nonce,
                &cancel,
                deadline()
            )
            .is_err()
        );
        let (_temporary, operation, action, nonce) = fixture(BuildProfile::HostBootstrap);
        assert!(
            inspect_managed_build_worker(
                &operation.path,
                action.digest(),
                &nonce,
                &cancel,
                deadline()
            )
            .is_err()
        );
    }
    #[test]
    fn pinned_file_or_operation_replacement_fails_revalidation() {
        let (_temporary, operation, action, nonce) = fixture(BuildProfile::Managed);
        let cancel = Cancellation::default();
        let inspected = inspect_managed_build_worker(
            &operation.path,
            action.digest(),
            &nonce,
            &cancel,
            deadline(),
        )
        .unwrap();
        operation
            .write_stage("source", b"source", false)
            .unwrap();
        assert!(inspected.revalidate(&cancel, deadline()).is_err());
        let inspected = inspect_managed_build_worker(
            &operation.path,
            action.digest(),
            &nonce,
            &cancel,
            deadline(),
        )
        .unwrap();
        let moved = operation.path.with_extension("moved");
        std::fs::rename(&operation.path, &moved).unwrap();
        std::fs::create_dir(&operation.path).unwrap();
        assert!(inspected.revalidate(&cancel, deadline()).is_err());
    }
    #[test]
    fn cancellation_deadline_and_symlink_do_not_change_journal() {
        let (_temporary, operation, action, nonce) = fixture(BuildProfile::Managed);
        let before = std::fs::read(operation.path.join("managed-attempt")).unwrap();
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(
            inspect_managed_build_worker(
                &operation.path,
                action.digest(),
                &nonce,
                &cancel,
                deadline()
            )
            .is_err()
        );
        let cancel = Cancellation::default();
        assert!(
            inspect_managed_build_worker(
                &operation.path,
                action.digest(),
                &nonce,
                &cancel,
                Instant::now()
            )
            .is_err()
        );
        let source = operation.stage_path().join("source");
        std::fs::remove_file(&source).unwrap();
        std::os::unix::fs::symlink("worker", &source).unwrap();
        assert!(
            inspect_managed_build_worker(
                &operation.path,
                action.digest(),
                &nonce,
                &cancel,
                deadline()
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(operation.path.join("managed-attempt")).unwrap(),
            before
        );
    }

    #[test]
    fn replacing_an_unlocked_gate_invalidates_previous_inspection() {
        let (_temporary, operation, action, nonce) = fixture(BuildProfile::Managed);
        let cancellation = Cancellation::default();
        let inspection = inspect_managed_build_worker(
            &operation.path,
            action.digest(),
            &nonce,
            &cancellation,
            deadline(),
        )
        .unwrap();
        let gate = operation.path.join("gate");
        let original = operation.path.join("old-gate");
        std::fs::rename(&gate, &original).unwrap();
        std::fs::write(&gate, b"").unwrap();
        std::fs::set_permissions(&gate, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(original).unwrap();
        assert!(
            inspection
                .revalidate(&cancellation, deadline())
                .is_err()
        );
    }

    #[test]
    fn all_staged_roles_are_authenticated_before_inspection_returns() {
        for role in [
            "build-action",
            "build-program",
            "source",
            "worker",
        ] {
            let (_temporary, operation, action, nonce) = fixture(BuildProfile::Managed);
            operation
                .write_stage(role, b"corrupt", role == "worker")
                .unwrap();
            assert!(
                inspect_managed_build_worker(
                    &operation.path,
                    action.digest(),
                    &nonce,
                    &Cancellation::default(),
                    deadline()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn transition_to_bound_requires_new_inspection_without_granting_authority() {
        let (_temporary, operation, action, nonce) = fixture(BuildProfile::Managed);
        let cancellation = Cancellation::default();
        let before = inspect_managed_build_worker(
            &operation.path,
            action.digest(),
            &nonce,
            &cancellation,
            deadline(),
        )
        .unwrap();
        let attempt = inspect_worker_attempt(
            &operation.path,
            action.digest(),
            &nonce,
            &cancellation,
            deadline(),
        )
        .unwrap();
        let observed = crate::build::managed::supervision::ObservedManagedBuildBinding::for_test(
            attempt.context.clone(),
            nonce.clone(),
            [1; 16],
            100,
            ContentDigest::sha256(b"contract"),
        );
        drop(attempt);
        operation
            .bind_managed(&observed, &cancellation, deadline())
            .unwrap();
        assert!(
            before
                .revalidate(&cancellation, deadline())
                .is_err()
        );
        let bound = inspect_managed_build_worker(
            &operation.path,
            action.digest(),
            &nonce,
            &cancellation,
            deadline(),
        )
        .unwrap();
        assert_eq!(before.bound_process(), None);
        assert_eq!(bound.bound_process(), Some(([1; 16], 100)));
        bound
            .revalidate(&cancellation, deadline())
            .unwrap();
        assert!(!operation.path.join("authorized").exists());
    }

    #[test]
    fn namespace_journal_transition_requires_fresh_inspection_and_is_not_gate_authority() {
        let (_temporary, operation, action, nonce) = fixture(BuildProfile::Managed);
        let cancellation = Cancellation::default();
        let attempt = inspect_worker_attempt(
            &operation.path,
            action.digest(),
            &nonce,
            &cancellation,
            deadline(),
        )
        .unwrap();
        let observed = crate::build::managed::supervision::ObservedManagedBuildBinding::for_test(
            attempt.context.clone(),
            nonce.clone(),
            [1; 16],
            100,
            ContentDigest::sha256(b"contract"),
        );
        drop(attempt);
        operation
            .bind_managed(&observed, &cancellation, deadline())
            .unwrap();
        let bound = inspect_managed_build_worker(
            &operation.path,
            action.digest(),
            &nonce,
            &cancellation,
            deadline(),
        )
        .unwrap();
        assert!(bound.namespace_snapshot().is_none());
        // Only a persisted-format fixture, not a fabricated kernel observation or
        // production admission. The journal's production method needs an opaque proof.
        let path = operation.path.join("managed-attempt");
        let resources = ContentDigest::sha256(b"resource manifest");
        let before = std::fs::read_to_string(&path).unwrap();
        let after=before.replace("\"state\":\"bound\"","\"state\":\"namespace_prepared\"").replace("\"namespace\":null",&format!("\"namespace\":{{\"resources\":\"{resources}\",\"pid\":200,\"device\":1,\"inode\":300}}"));
        assert_ne!(before, after);
        std::fs::write(&path, after).unwrap();
        assert!(
            bound
                .revalidate(&cancellation, deadline())
                .is_err()
        );
        let prepared = inspect_managed_build_worker(
            &operation.path,
            action.digest(),
            &nonce,
            &cancellation,
            deadline(),
        )
        .unwrap();
        assert_eq!(prepared.bound_process(), Some(([1; 16], 100)));
        let snapshot = prepared.namespace_snapshot().unwrap();
        assert_eq!(snapshot.resources, resources);
        assert_eq!(
            (snapshot.pid, snapshot.device, snapshot.inode),
            (200, 1, 300)
        );
        prepared
            .revalidate(&cancellation, deadline())
            .unwrap();
        assert!(!operation.path.join("authorized").exists());
        operation
            .revoke_managed(&cancellation, deadline())
            .unwrap();
        assert!(
            prepared
                .revalidate(&cancellation, deadline())
                .is_err()
        );
    }
}

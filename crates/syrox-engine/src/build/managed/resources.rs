use super::{
    BuildError, BuildProfile, BuildResources, cancellation::BuildControl, records::Action,
    worker::ManagedBuildWorkerInspection,
};
use crate::result::artifact::IndexedArtifact;
use crate::{
    cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest,
    store::ObjectLease,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::time::Instant;

const FIXED_SLOTS: usize = 5;
const EXECUTOR_RESERVE: usize = 32;
pub(in crate::build) const MAX_MANAGED_RESOURCE_SLOTS: usize =
    BuildResources::Large.envelope().nofile as usize - EXECUTOR_RESERVE;
const MAX_MANIFEST: usize = 1024;
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    action: String,
    slots: u16,
    retention: String,
}
impl Manifest {
    fn parse(bytes: &[u8]) -> Result<Self, BuildError> {
        if bytes.len() > MAX_MANIFEST {
            return Err(BuildError::InvalidRequest);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| BuildError::InvalidRequest)?;
        if value.version != 1
            || value.encode()? != bytes
            || usize::from(value.slots) > MAX_MANAGED_RESOURCE_SLOTS
            || value.slots < 5
        {
            return Err(BuildError::InvalidRequest);
        }
        pin(&value.action)?;
        pin(&value.retention)?;
        Ok(value)
    }
    fn encode(&self) -> Result<Vec<u8>, BuildError> {
        serde_json::to_vec(self).map_err(|_| BuildError::InvalidRequest)
    }
}
/// Owns read-only source/action/program/worker, input view+Artifact pairs, and
/// an independent retention description. No Store reader/global GC lease is held.
pub struct ManagedBuildResources {
    manifest: Vec<u8>,
    descriptors: Vec<OwnedFd>,
    action: ContentDigest,
}
impl std::fmt::Debug for ManagedBuildResources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedBuildResources")
            .field("action", &self.action)
            .field("slots", &self.descriptors.len())
            .finish_non_exhaustive()
    }
}
impl ManagedBuildResources {
    pub fn action_digest(&self) -> ContentDigest {
        self.action
    }
    pub(in crate::build) fn manifest(&self) -> &[u8] {
        &self.manifest
    }
    pub(in crate::build) fn retention_descriptor(&self) -> BorrowedFd<'_> {
        self.descriptors
            .last()
            .expect("validated retention slot")
            .as_fd()
    }
    pub(crate) fn descriptors(&self) -> &[OwnedFd] {
        &self.descriptors
    }
    pub(in crate::build) fn namespace_action(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Action, BuildError> {
        self.revalidate(cancellation, deadline)?;
        read_action(
            self.descriptors[0].as_fd(),
            self.action,
            &Budget {
                cancellation,
                deadline,
            },
        )
    }
    /// Compare the namespace-visible nonrecursive binds, not the original host
    /// views, before the native init closes its authenticated Artifact handles.
    pub(crate) fn verify_namespace_inputs(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        let budget = Budget {
            cancellation,
            deadline,
        };
        let action = read_action(self.descriptors[0].as_fd(), self.action, &budget)?;
        for (index, input) in action.inputs.iter().enumerate() {
            budget.check()?;
            let path = format!("/syrox/store/{}/{}", input.action, input.output);
            let directory = linux_fd::open_top_directory(std::path::Path::new(&path))
                .map_err(|_| BuildError::InputChanged)?;
            verify_input_view(
                directory.fd(),
                self.descriptors[5 + 2 * index].as_fd(),
                input.artifact,
                &budget,
            )?;
        }
        budget.check()
    }
    pub(in crate::build) fn from_prepared(
        action: &Action,
        descriptors: Vec<OwnedFd>,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Self, BuildError> {
        let budget = Budget {
            cancellation,
            deadline,
        };
        budget.check()?;
        let slots = resource_slots(action)?;
        if descriptors.len() != slots {
            return Err(BuildError::UnsupportedInputs);
        }
        let (_, retention) = read_regular(
            descriptors[slots - 1].as_fd(),
            ObjectLease::MAX_HANDOFF_RECORD_BYTES,
            0o400,
            false,
            &budget,
        )?;
        let manifest = Manifest {
            version: 1,
            action: action.digest().to_string(),
            slots: u16::try_from(slots).map_err(|_| BuildError::UnsupportedInputs)?,
            retention: retention.to_string(),
        }
        .encode()?;
        validate_all(action.digest(), &manifest, &descriptors, &budget)?;
        Ok(Self {
            manifest,
            descriptors,
            action: action.digest(),
        })
    }
    /// Recheck current bytes against the pinned manifest. This does not freeze
    /// mutable host files or establish peer identity, FDSTORE acceptance or exec.
    pub fn revalidate(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        validate_all(
            self.action,
            &self.manifest,
            &self.descriptors,
            &Budget {
                cancellation,
                deadline,
            },
        )
    }
}
pub fn validate_managed_build_resources(
    inspection: &ManagedBuildWorkerInspection,
    manifest: &[u8],
    descriptors: Vec<OwnedFd>,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<ManagedBuildResources, BuildError> {
    inspection.revalidate(cancellation, deadline)?;
    validate_all(
        inspection.action_digest(),
        manifest,
        &descriptors,
        &Budget {
            cancellation,
            deadline,
        },
    )?;
    inspection.revalidate(cancellation, deadline)?;
    Ok(ManagedBuildResources {
        action: inspection.action_digest(),
        manifest: manifest.to_vec(),
        descriptors,
    })
}
/// Validate batch zero's Action before accepting subsequent descriptor batches.
/// The count respects 32 descriptors reserved by the profile for the executor.
pub(in crate::build) fn validate_managed_resource_budget(
    inspection: &ManagedBuildWorkerInspection,
    manifest: &[u8],
    action: BorrowedFd<'_>,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<usize, BuildError> {
    inspection.revalidate(cancellation, deadline)?;
    let metadata = Manifest::parse(manifest)?;
    let action = read_action(
        action,
        inspection.action_digest(),
        &Budget {
            cancellation,
            deadline,
        },
    )?;
    validate_manifest(&metadata, &action)
}
pub(in crate::build) fn resource_slots(action: &Action) -> Result<usize, BuildError> {
    let slots = action
        .inputs
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_add(FIXED_SLOTS))
        .ok_or(BuildError::UnsupportedInputs)?;
    let limit = usize::try_from(action.program.resources.envelope().nofile)
        .map_err(|_| BuildError::UnsupportedInputs)?
        .checked_sub(EXECUTOR_RESERVE)
        .ok_or(BuildError::UnsupportedInputs)?;
    if slots > limit {
        return Err(BuildError::UnsupportedInputs);
    }
    Ok(slots)
}
fn pin(text: &str) -> Result<ContentDigest, BuildError> {
    let digest: ContentDigest = text
        .parse()
        .map_err(|_| BuildError::InvalidRequest)?;
    Ok(digest)
}
fn validate_manifest(manifest: &Manifest, action: &Action) -> Result<usize, BuildError> {
    let slots = resource_slots(action)?;
    if pin(&manifest.action)? != action.digest() || usize::from(manifest.slots) != slots {
        return Err(BuildError::InputChanged);
    }
    Ok(slots)
}
fn read_action(
    fd: BorrowedFd<'_>,
    expected: ContentDigest,
    budget: &Budget<'_>,
) -> Result<Action, BuildError> {
    let (bytes, digest) = read_regular(
        fd,
        super::records::MAX_RECORD_BYTES,
        0o400,
        true,
        budget,
    )?;
    if digest != expected {
        return Err(BuildError::InputChanged);
    }
    let action = Action::parse(&bytes)?;
    if action.program.profile != BuildProfile::Managed || action.toolchain.is_some() {
        return Err(BuildError::InvalidRequest);
    }
    Ok(action)
}
fn validate_all(
    expected: ContentDigest,
    bytes: &[u8],
    descriptors: &[OwnedFd],
    budget: &Budget<'_>,
) -> Result<(), BuildError> {
    budget.check()?;
    let manifest = Manifest::parse(bytes)?;
    if descriptors.len() != usize::from(manifest.slots) {
        return Err(BuildError::InvalidRequest);
    }
    let action = read_action(descriptors[0].as_fd(), expected, budget)?;
    let slots = validate_manifest(&manifest, &action)?;
    let mut fixed = std::collections::BTreeSet::new();
    for slot in [0, 1, 2, 3, slots - 1] {
        let id = linux_fd::metadata(descriptors[slot].as_fd())?.identity();
        if !fixed.insert((id.device, id.inode)) {
            return Err(BuildError::InputChanged);
        }
    }
    let (program, _) = read_regular(
        descriptors[1].as_fd(),
        super::MAX_BUILD_PROGRAM_BYTES as u64,
        0o400,
        true,
        budget,
    )?;
    if program != action.program.encode() {
        return Err(BuildError::InputChanged);
    }
    let source_limit = action.program.maximum_source_bytes();
    let (_, source) = read_regular(
        descriptors[2].as_fd(),
        source_limit,
        0o400,
        false,
        budget,
    )?;
    let (worker, worker_pin) = read_regular(
        descriptors[3].as_fd(),
        128 * 1024 * 1024,
        0o500,
        true,
        budget,
    )?;
    if source != action.source || worker_pin != action.worker {
        return Err(BuildError::InputChanged);
    }
    crate::runtime::validate_static_worker_image(&worker)
        .map_err(|_| BuildError::InvalidRequest)?;
    let mut required = vec![action.source];
    let mut views = Vec::new();
    for (index, input) in action.inputs.iter().enumerate() {
        budget.check()?;
        let view = descriptors[4 + 2 * index].as_fd();
        let artifact = descriptors[5 + 2 * index].as_fd();
        verify_input_view(view, artifact, input.artifact, budget)?;
        required.push(input.artifact);
        match input.origin {
            crate::result::OutputOrigin::Built {
                receipt,
            } => {
                required.extend([receipt, input.action]);
            }
            crate::result::OutputOrigin::Imported {
                manifest,
            } => required.push(manifest),
        }
        views.push(input.artifact);
    }
    let (retention, pin) = read_regular(
        descriptors[slots - 1].as_fd(),
        ObjectLease::MAX_HANDOFF_RECORD_BYTES,
        0o400,
        true,
        budget,
    )?;
    if pin != self::pin(&manifest.retention)? {
        return Err(BuildError::InputChanged);
    }
    ObjectLease::validate_handoff_record(&retention, &required, &views)?;
    budget.check()
}
fn verify_input_view(
    view: BorrowedFd<'_>,
    artifact: BorrowedFd<'_>,
    expected: ContentDigest,
    budget: &Budget<'_>,
) -> Result<(), BuildError> {
    linux_fd::require_readonly(view)?;
    let metadata = linux_fd::metadata(view)?;
    if !metadata.is_trusted_directory() || metadata.mode() & 0o7777 != 0o700 {
        return Err(BuildError::InputChanged);
    }
    let (_, pin) = read_regular(
        artifact,
        super::MAX_OUTPUT_BYTES,
        0o600,
        false,
        budget,
    )?;
    if pin != expected {
        return Err(BuildError::InputChanged);
    }
    let length = linux_fd::metadata(artifact)?.size();
    if length > super::MAX_OUTPUT_BYTES {
        return Err(BuildError::InvalidRequest);
    }
    let reader = DescriptorReader::new(artifact, length)?;
    let mut indexed = IndexedArtifact::open_checked(reader, "", budget)?;
    crate::result::materialize::verify_descriptor_view(view, &mut indexed, budget).map_err(
        |_| {
            if budget.cancellation.is_cancelled() {
                BuildError::Cancelled
            } else {
                BuildError::InputChanged
            }
        },
    )?;
    let (_, after) = read_regular(
        artifact,
        super::MAX_OUTPUT_BYTES,
        0o600,
        false,
        budget,
    )?;
    if after != expected {
        return Err(BuildError::InputChanged);
    }
    budget.check()
}
#[derive(Debug)]
struct Budget<'a> {
    cancellation: &'a Cancellation,
    deadline: Instant,
}
impl BuildControl for Budget<'_> {
    fn check(&self) -> Result<(), BuildError> {
        self.cancellation.check()?;
        if Instant::now() >= self.deadline {
            return Err(BuildError::InvalidRequest);
        }
        Ok(())
    }
}
fn read_regular(
    fd: BorrowedFd<'_>,
    maximum: u64,
    mode: u32,
    collect: bool,
    budget: &Budget<'_>,
) -> Result<(Vec<u8>, ContentDigest), BuildError> {
    budget.check()?;
    linux_fd::require_readonly(fd)?;
    let before = linux_fd::metadata(fd)?;
    // Store CAS objects use 0600 today, while their transferred FD is O_RDONLY.
    // The other roles retain exact staging/interest modes.
    let actual_mode = before.mode() & 0o7777;
    let mode_matches = actual_mode == mode || (mode == 0o600 && actual_mode == 0o400);
    if !before.is_trusted_regular() || !mode_matches || before.size() > maximum {
        return Err(BuildError::InputChanged);
    }
    let mut reader = DescriptorReader::new(fd, before.size())?;
    let mut bytes = Vec::new();
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 16384];
    loop {
        budget.check()?;
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        hash.update(&chunk[..count]);
        if collect {
            bytes.extend_from_slice(&chunk[..count]);
        }
    }
    let after = linux_fd::metadata(fd)?;
    let mut extra = [0u8; 1];
    if before != after || reader.file.read_at(&mut extra, before.size())? != 0 {
        return Err(BuildError::InputChanged);
    }
    Ok((
        bytes,
        ContentDigest::from_sha256_hash(hash.finalize().into()),
    ))
}
/// Positional reads keep each parser cursor private even across `SCM_RIGHTS`/`dup`.
struct DescriptorReader {
    file: File,
    position: u64,
    length: u64,
}
impl DescriptorReader {
    fn new(fd: BorrowedFd<'_>, length: u64) -> io::Result<Self> {
        let file = File::from(fd.try_clone_to_owned()?);
        Ok(Self {
            file,
            position: 0,
            length,
        })
    }
}
impl Read for DescriptorReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let remaining = self.length.saturating_sub(self.position);
        let count = output
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if count == 0 {
            return Ok(0);
        }
        let read = self
            .file
            .read_at(&mut output[..count], self.position)?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.position += read as u64;
        Ok(read)
    }
}
impl Seek for DescriptorReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.length) + i128::from(value),
        };
        self.position =
            u64::try_from(position).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(self.position)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::{
        journal::managed::ManagedAttemptContext,
        managed::preparation::{ManagedBuildRetention, PreparedManagedBuild},
    };
    use crate::{store::Store, systemd::SystemdUnitName};
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;
    struct Fixture {
        temporary: tempfile::TempDir,
        store: Store,
        prepared: PreparedManagedBuild,
        retention: ManagedBuildRetention,
        resources: ManagedBuildResources,
        inspection: ManagedBuildWorkerInspection,
        provider: crate::build::BuildResult,
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }
    fn fixture() -> Fixture {
        let mut worker = crate::runtime::tests::elf(2, None, &[], None, None);
        worker[24..32].copy_from_slice(&0x0040_0100_u64.to_le_bytes());
        worker[68..72].copy_from_slice(&5_u32.to_le_bytes());
        let (temporary, store, prepared, provider) =
            crate::build::managed::preparation::tests::handoff_fixture_with_worker(&worker);
        let cancellation = Cancellation::default();
        let context = ManagedAttemptContext {
            action: prepared.action_digest(),
            worker: prepared.worker_digest(),
            boot: crate::platform::linux::boot::BootId::current(&cancellation, deadline())
                .unwrap()
                .as_str()
                .into(),
            manager: ContentDigest::sha256(b"manager"),
            scope: "user:/run/user/1000/bus".into(),
            unit: SystemdUnitName::new(format!(
                "syrox-build-{}.service",
                &prepared.operation_id()[3..]
            ))
            .unwrap(),
            uid: linux_fd::real_uid(),
            gid: linux_fd::real_gid(),
        };
        let nonce = prepared
            .prepare_attempt(&context, &cancellation, deadline())
            .unwrap();
        prepared
            .authorize_test_start(&context, &nonce, &cancellation, deadline())
            .unwrap();
        let inspection = crate::build::managed::worker::inspect_managed_build_worker(
            prepared.operation_path(),
            prepared.action_digest(),
            &nonce,
            &cancellation,
            deadline(),
        )
        .unwrap();
        let retention = prepared
            .retain_for_handoff(&cancellation, deadline())
            .unwrap();
        let resources = prepared
            .prepare_resources(&retention, &cancellation, deadline())
            .unwrap();
        Fixture {
            temporary,
            store,
            prepared,
            retention,
            resources,
            inspection,
            provider,
        }
    }
    fn copies(resources: &ManagedBuildResources) -> Vec<OwnedFd> {
        resources
            .descriptors
            .iter()
            .map(|fd| fd.try_clone().unwrap())
            .collect()
    }
    fn receiver(
        fixture: &Fixture,
        descriptors: Vec<OwnedFd>,
    ) -> Result<ManagedBuildResources, BuildError> {
        validate_managed_build_resources(
            &fixture.inspection,
            &fixture.resources.manifest,
            descriptors,
            &Cancellation::default(),
            deadline(),
        )
    }
    #[test]
    fn verified_descriptor_package_survives_sender_drop_and_gc() {
        // The transferred OFD can also be inherited by unrelated harness forks.
        // Isolate the last-close assertion without changing the GC contract.
        if linux_fd::retention_fork_tests::isolate_test(
            "build::managed::resources::tests::verified_descriptor_package_survives_sender_drop_and_gc",
            "SYROX_MANAGED_RESOURCES_GC_ISOLATED",
        ) {
            return;
        }
        let fixture = fixture();
        assert_eq!(fixture.resources.descriptors.len(), 7);
        assert_eq!(
            validate_managed_resource_budget(
                &fixture.inspection,
                &fixture.resources.manifest,
                fixture.resources.descriptors[0].as_fd(),
                &Cancellation::default(),
                deadline()
            )
            .unwrap(),
            7
        );
        let received = receiver(&fixture, copies(&fixture.resources)).unwrap();
        let Fixture {
            temporary: _temporary,
            store,
            prepared,
            retention,
            resources,
            inspection: _inspection,
            provider,
        } = fixture;
        let provider_root = provider.root.clone();
        let provider_artifact = provider.artifact;
        drop((prepared, retention, resources, provider));
        let garbage = ContentDigest::sha256(b"garbage");
        store
            .operation()
            .unwrap()
            .ingest(&b"garbage"[..], garbage, 100)
            .unwrap();
        let report = store
            .maintenance()
            .unwrap()
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                remove_roots: vec![provider_root],
                ..crate::store::GcRequest::default()
            })
            .unwrap();
        assert!(report.removed_objects.contains(&garbage));
        assert!(
            !report
                .removed_objects
                .contains(&provider_artifact)
        );
        received
            .revalidate(&Cancellation::default(), deadline())
            .unwrap();
        drop(received);
        assert!(
            store
                .maintenance()
                .unwrap()
                .garbage_collect(&crate::store::GcRequest {
                    collect: true,
                    ..crate::store::GcRequest::default()
                })
                .unwrap()
                .removed_objects
                .contains(&provider_artifact)
        );
    }
    #[test]
    fn rejects_writable_descriptors_swapped_slots_and_artifact_substitution() {
        let fixture = fixture();
        let mut changed = copies(&fixture.resources);
        changed.swap(1, 2);
        assert!(receiver(&fixture, changed).is_err());
        let mut changed = copies(&fixture.resources);
        changed[5] = changed[2].try_clone().unwrap();
        assert!(receiver(&fixture, changed).is_err());
        let source = fixture
            .prepared
            .operation_path()
            .join("stage/source");
        let path_only = crate::platform::linux::fd::open_path(&source).unwrap();
        let mut changed = copies(&fixture.resources);
        changed[2] = path_only.into();
        assert!(receiver(&fixture, changed).is_err());
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        let writable = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o400)).unwrap();
        let mut changed = copies(&fixture.resources);
        changed[2] = writable.into();
        assert!(receiver(&fixture, changed).is_err());
        let link = fixture.temporary.path().join("source-alias");
        std::fs::hard_link(&source, link).unwrap();
        assert!(receiver(&fixture, copies(&fixture.resources)).is_err());
    }
    #[test]
    fn authenticated_artifact_does_not_authorize_corrupt_extra_or_missing_view_files() {
        for mutation in ["bytes", "extra", "missing"] {
            let fixture = fixture();
            let path = linux_fd::directory_path(
                &linux_fd::open_beneath(
                    fixture.resources.descriptors[4].as_fd(),
                    std::path::Path::new("."),
                    true,
                )
                .unwrap(),
            )
            .unwrap();
            let file = path.join("bin/hello");
            match mutation {
                "bytes" => {
                    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                    std::fs::write(&file, b"bad").unwrap();
                    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o500)).unwrap();
                }
                "extra" => {
                    std::fs::write(path.join("extra"), b"unknown").unwrap();
                }
                _ => {
                    std::fs::remove_file(file).unwrap();
                }
            }
            assert!(receiver(&fixture, copies(&fixture.resources)).is_err());
        }
    }
    #[test]
    fn retention_record_requires_selected_references_and_views_even_with_matching_pin() {
        let fixture = fixture();
        let empty = fixture
            .store
            .operation()
            .unwrap()
            .retain_objects(&[], &[])
            .unwrap();
        let empty_fd = empty.process_retention().unwrap();
        let (_, digest) = read_regular(
            empty_fd.as_fd(),
            ObjectLease::MAX_HANDOFF_RECORD_BYTES,
            0o400,
            false,
            &Budget {
                cancellation: &Cancellation::default(),
                deadline: deadline(),
            },
        )
        .unwrap();
        let mut metadata = Manifest::parse(&fixture.resources.manifest).unwrap();
        metadata.retention = digest.to_string();
        let mut descriptors = copies(&fixture.resources);
        *descriptors.last_mut().unwrap() = empty_fd.into();
        assert!(
            validate_managed_build_resources(
                &fixture.inspection,
                &metadata.encode().unwrap(),
                descriptors,
                &Cancellation::default(),
                deadline()
            )
            .is_err()
        );
    }
    #[test]
    fn profile_budget_uses_declared_nofile_and_preserves_executor_reserve() {
        let fixture = fixture();
        let cancellation = Cancellation::default();
        let mut action = read_action(
            fixture.resources.descriptors[0].as_fd(),
            fixture.resources.action,
            &Budget {
                cancellation: &cancellation,
                deadline: deadline(),
            },
        )
        .unwrap();
        for resources in [
            BuildResources::Standard,
            BuildResources::Large,
        ] {
            action.program.resources = resources;
            let input = action.inputs[0].clone();
            let limit = usize::try_from(resources.envelope().nofile).unwrap() - EXECUTOR_RESERVE;
            let allowed = (limit - FIXED_SLOTS) / 2;
            action.inputs = vec![input.clone(); allowed];
            assert_eq!(
                resource_slots(&action).unwrap(),
                FIXED_SLOTS + 2 * allowed
            );
            action.inputs.push(input);
            assert!(resource_slots(&action).is_err());
        }
        cancellation.cancel();
        assert!(
            fixture
                .resources
                .revalidate(&cancellation, deadline())
                .is_err()
        );
        assert!(
            fixture
                .resources
                .revalidate(&Cancellation::default(), Instant::now())
                .is_err()
        );
    }
    #[test]
    fn descriptor_cursors_are_private_across_dup_and_seek() {
        let fixture = fixture();
        let fd = fixture.resources.descriptors[5].as_fd();
        let size = linux_fd::metadata(fd).unwrap().size();
        let mut first = DescriptorReader::new(fd, size).unwrap();
        let mut second = DescriptorReader::new(fd, size).unwrap();
        first.seek(SeekFrom::End(-1)).unwrap();
        let mut prefix = [0u8; 14];
        second.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"syrox-artifact");
        let mut duplicate = File::from(fd.try_clone_to_owned().unwrap());
        duplicate.seek(SeekFrom::End(0)).unwrap();
        first.seek(SeekFrom::Start(0)).unwrap();
        first.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"syrox-artifact");
    }

    #[test]
    fn artifact_accepts_owner_only_store_modes_but_not_public_or_executable_mode() {
        let fixture = fixture();
        let artifact = File::from(
            fixture.resources.descriptors[5]
                .try_clone()
                .unwrap(),
        );
        for mode in [0o400, 0o600] {
            artifact
                .set_permissions(std::fs::Permissions::from_mode(mode))
                .unwrap();
            receiver(&fixture, copies(&fixture.resources)).unwrap();
        }
        artifact
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(receiver(&fixture, copies(&fixture.resources)).is_err());
    }
    #[test]
    fn wide_artifact_views_are_validated_without_a_pending_descriptor_per_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let tree = temporary.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o700)).unwrap();
        for index in 0..96 {
            let directory = tree.join(format!("dir-{index:03}"));
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let file = directory.join("data");
            std::fs::write(&file, b"contents").unwrap();
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let mut bytes = Vec::new();
        crate::result::artifact::pack(&tree, &mut bytes).unwrap();
        let cancellation = Cancellation::default();
        let budget = Budget {
            cancellation: &cancellation,
            deadline: deadline(),
        };
        let mut artifact =
            IndexedArtifact::open_checked(io::Cursor::new(bytes), "", &budget).unwrap();
        let view = linux_fd::open_top_directory(&tree).unwrap();
        crate::result::materialize::verify_descriptor_view(view.fd(), &mut artifact, &budget)
            .unwrap();
    }
    #[test]
    fn foreign_store_retention_cannot_cover_an_identical_action_package() {
        let first = fixture();
        let second = fixture();
        assert_eq!(
            first.prepared.action_digest(),
            second.prepared.action_digest()
        );
        assert!(
            first
                .prepared
                .prepare_resources(
                    &second.retention,
                    &Cancellation::default(),
                    deadline()
                )
                .is_err()
        );
    }

    #[test]
    fn namespace_visible_tree_must_match_artifact_even_when_original_view_is_valid() {
        let fixture = fixture();
        let cancellation = Cancellation::default();
        fixture
            .resources
            .revalidate(&cancellation, deadline())
            .unwrap();
        let alternate = fixture.temporary.path().join("namespace-tree");
        std::fs::create_dir(&alternate).unwrap();
        std::fs::set_permissions(&alternate, std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = linux_fd::open_top_directory(&alternate).unwrap();
        let budget = Budget {
            cancellation: &cancellation,
            deadline: deadline(),
        };
        let action = fixture
            .resources
            .namespace_action(&cancellation, deadline())
            .unwrap();
        assert!(
            verify_input_view(
                directory.fd(),
                fixture.resources.descriptors[5].as_fd(),
                action.inputs[0].artifact,
                &budget
            )
            .is_err()
        );
        // No mutation of the original pinned view is necessary for this rejection.
        fixture
            .resources
            .revalidate(&cancellation, deadline())
            .unwrap();
    }
}

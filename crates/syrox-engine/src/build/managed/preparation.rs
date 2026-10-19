use super::{
    BuildError, BuildProfile, BuildSpecification,
    journal::Operation,
    records::{Action, BuildDescription, InputIdentity},
};
use crate::build::materialization_error;
use crate::{
    cancellation::Cancellation, plan::Plan, platform::linux::fd as linux_fd,
    result::MaterializedArtifact, store::ContentDigest, store::ObjectLease, store::Store,
};
use sha2::{Digest as _, Sha256};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// Diagnostic paths, never authorization to reopen a mutable host pathname.
#[derive(Debug)]
pub struct ManagedBuildLayout {
    pub staging: PathBuf,
    pub working: PathBuf,
    pub outputs: PathBuf,
    pub inputs: Vec<PathBuf>,
}
struct PinnedFile {
    name: &'static str,
    file: linux_fd::OpenedPath,
    digest: ContentDigest,
    size: u64,
}
/// Owns staging descriptors and granular input retention. Dropping this value
/// preserves the unauthorised journal operation for explicit Store recovery.
pub struct PreparedManagedBuild {
    action: Action,
    operation: std::sync::Arc<Operation>,
    stage: linux_fd::OpenedPath,
    files: Vec<PinnedFile>,
    inputs: Vec<MaterializedArtifact>,
    source_interest: ObjectLease,
    timeout_seconds: u32,
}
/// Authenticated input bytes and granular retention, without a staging operation.
/// This can survive producer admission without holding the global Store barrier.
pub struct ManagedBuildInputs {
    pub(super) action: Action,
    pub(super) source: Vec<u8>,
    pub(super) worker: Vec<u8>,
    pub(super) inputs: Vec<MaterializedArtifact>,
    pub(super) source_interest: ObjectLease,
    pub(super) timeout_seconds: u32,
}
impl std::fmt::Debug for ManagedBuildInputs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedBuildInputs")
            .field("action", &self.action.digest())
            .finish_non_exhaustive()
    }
}
impl ManagedBuildInputs {
    pub fn action_digest(&self) -> ContentDigest {
        self.action.digest()
    }

    /// Create one staging operation only after the caller has selected this producer.
    /// This standalone method does not itself perform shared producer admission.
    pub fn stage(self, cancellation: &Cancellation) -> Result<PreparedManagedBuild, BuildError> {
        cancellation.check()?;
        for input in &self.inputs {
            input
                .verify_view(cancellation)
                .map_err(|error| materialization_error(&error))?;
        }
        let lease = self.source_interest.operation()?;
        let operation = std::sync::Arc::new(Operation::create(&lease)?);
        drop(lease);
        self.write_stage(operation, cancellation)
    }

    pub(in crate::build) fn stage_in(
        self,
        operation: std::sync::Arc<Operation>,
        cancellation: &Cancellation,
    ) -> Result<PreparedManagedBuild, BuildError> {
        cancellation.check()?;
        let attempt =
            super::journal::Attempt::read(&operation.directory)?.ok_or(BuildError::InputChanged)?;
        if attempt.action != self.action.digest() || attempt.timeout_seconds != self.timeout_seconds
        {
            return Err(BuildError::InputChanged);
        }
        self.write_stage(operation, cancellation)
    }

    fn write_stage(
        self,
        operation: std::sync::Arc<Operation>,
        cancellation: &Cancellation,
    ) -> Result<PreparedManagedBuild, BuildError> {
        cancellation.check()?;
        for input in &self.inputs {
            input
                .verify_view(cancellation)
                .map_err(|error| materialization_error(&error))?;
        }
        let lease = self.source_interest.operation()?;
        let parent = lease.build_directory()?;
        let current = linux_fd::open_beneath(parent.fd(), Path::new(&operation.name), true)
            .map_err(|_| BuildError::InputChanged)?;
        if current.metadata().identity() != operation.directory.metadata().identity() {
            return Err(BuildError::InputChanged);
        }
        let stage = linux_fd::open_beneath(operation.directory.fd(), Path::new("stage"), true)
            .map_err(|error| BuildError::Cache(format!("staging directory: {error:?}")))?;
        let mut files = Vec::new();
        for (name, bytes, executable) in [
            ("source", self.source.as_slice(), false),
            ("worker", self.worker.as_slice(), true),
            (
                "build-action",
                self.action.encode().as_slice(),
                false,
            ),
            (
                "build-program",
                self.action.program.encode().as_slice(),
                false,
            ),
        ] {
            cancellation.check()?;
            operation.write_stage(name, bytes, executable)?;
            let file = linux_fd::open_existing_regular(stage.fd(), Path::new(name))?;
            files.push(PinnedFile {
                name,
                file,
                digest: ContentDigest::sha256(bytes),
                size: bytes.len() as u64,
            });
        }
        let prepared = PreparedManagedBuild {
            action: self.action,
            operation,
            stage,
            files,
            inputs: self.inputs,
            source_interest: self.source_interest,
            timeout_seconds: self.timeout_seconds,
        };
        prepared.verify_preparation(cancellation)?;
        Ok(prepared)
    }
}
/// Granular Store retention and verified descriptors for a future handoff.
/// This protects source objects and input closures/views, not the operation
/// pathname, manager identity, payload authorization, or process settlement.
pub(in crate::build) struct ManagedBuildRetention {
    action: ContentDigest,
    interest: ObjectLease,
    source: std::fs::File,
    source_digest: ContentDigest,
    source_size: u64,
    inputs: Vec<MaterializedArtifact>,
    selected: Vec<InputIdentity>,
}
impl std::fmt::Debug for ManagedBuildRetention {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedBuildRetention")
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}
impl ManagedBuildRetention {
    #[cfg(test)]
    pub fn action_digest(&self) -> ContentDigest {
        self.action
    }
    /// Validate held source bytes and materialized inputs, without reopening
    /// the coordinator's staging pathname or retaining a global Store barrier.
    pub fn revalidate(
        &self,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
    ) -> Result<(), BuildError> {
        retention_check(cancellation, deadline)?;
        // Revalidate permanent Store anchors without holding the GC barrier
        // during source hashing or view verification.
        drop(self.interest.operation()?);
        verify_file_contents(
            &self.source,
            (self.source_digest, self.source_size, 0o400),
            cancellation,
            Some(deadline),
        )?;
        if self.inputs.len() != self.selected.len() {
            return Err(BuildError::InputChanged);
        }
        for (input, selected) in self.inputs.iter().zip(&self.selected) {
            retention_check(cancellation, deadline)?;
            input
                .verify_view(cancellation)
                .map_err(|error| materialization_error(&error))?;
            if input.identity().artifact != selected.artifact
                || input.identity().origin != selected.origin
                || input.identity().action != selected.action
                || input.identity().output != selected.output
            {
                return Err(BuildError::InputChanged);
            }
        }
        retention_check(cancellation, deadline)
    }
    /// Independent read-only open-file description for `SCM_RIGHTS`/manager
    /// `FDSTORE`. Closing local interests does not unlock this description.
    /// The receiver must still authenticate identity and its handoff protocol;
    /// this descriptor grants retention only, never execution authority.
    #[cfg(test)]
    pub fn process_retention(
        &self,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
    ) -> Result<std::fs::File, BuildError> {
        self.revalidate(cancellation, deadline)?;
        let retained = self.interest.process_retention()?;
        retention_check(cancellation, deadline)?;
        Ok(retained)
    }
}
fn retention_check(
    cancellation: &Cancellation,
    deadline: std::time::Instant,
) -> Result<(), BuildError> {
    cancellation.check()?;
    if std::time::Instant::now() >= deadline {
        return Err(BuildError::InvalidRequest);
    }
    Ok(())
}
impl std::fmt::Debug for PreparedManagedBuild {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedManagedBuild")
            .field("action", &self.action.digest())
            .finish_non_exhaustive()
    }
}
impl PreparedManagedBuild {
    pub(in crate::build) fn record_settlement(
        &self,
        proof: &super::execution::ManagedBuildSettlement,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
    ) -> Result<(), BuildError> {
        self.operation
            .record_managed_settlement(proof, cancellation, deadline)
    }
    pub(in crate::build) fn publish_captured(
        &self,
        captured: super::CapturedManagedBuildOutput,
        cancellation: &Cancellation,
        publication: &dyn super::cancellation::BuildControl,
    ) -> Result<super::BuildResult, BuildError> {
        publication.check()?;
        if captured.action_digest() != self.action.digest() {
            return Err(BuildError::InputChanged);
        }
        self.verify_preparation(cancellation)?;
        let references = self
            .inputs
            .iter()
            .flat_map(MaterializedArtifact::retained_references)
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let lease = self.source_interest.operation()?;
        let mut file = captured.into_file();
        super::publication::publish_outputs(
            &lease,
            self.operation_id(),
            &self.action,
            None,
            &mut file,
            &references,
            publication,
        )
    }
    /// Retain the authenticated source and every selected input closure for a
    /// future descriptor handoff. Does not create a durable root or launch a unit.
    pub(in crate::build) fn retain_for_handoff(
        &self,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
    ) -> Result<ManagedBuildRetention, BuildError> {
        retention_check(cancellation, deadline)?;
        self.verify_preparation(cancellation)?;
        let source = self
            .files
            .iter()
            .find(|file| file.name == "source")
            .ok_or(BuildError::InputChanged)?;
        if source.digest != self.action.source {
            return Err(BuildError::InputChanged);
        }
        let mut leases = vec![&self.source_interest];
        leases.extend(
            self.inputs
                .iter()
                .map(MaterializedArtifact::object_lease),
        );
        let retained = ManagedBuildRetention {
            action: self.action.digest(),
            interest: ObjectLease::combine(&leases)?,
            source: std::fs::File::from(source.file.fd().try_clone_to_owned()?),
            source_digest: source.digest,
            source_size: source.size,
            inputs: self
                .inputs
                .iter()
                .map(MaterializedArtifact::share)
                .collect(),
            selected: self.action.inputs.clone(),
        };
        retained.revalidate(cancellation, deadline)?;
        Ok(retained)
    }
    /// Assemble verified read-only descriptors without launching or mounting.
    /// Fixed slots are Action, Program, Source, Worker; then view/Artifact pairs
    /// in selected-input order, followed by one independent retention descriptor.
    pub(in crate::build) fn prepare_resources(
        &self,
        retention: &ManagedBuildRetention,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
    ) -> Result<super::resources::ManagedBuildResources, BuildError> {
        retention_check(cancellation, deadline)?;
        super::resources::resource_slots(&self.action)?;
        if retention.action != self.action.digest() {
            return Err(BuildError::InputChanged);
        }
        self.verify_preparation(cancellation)?;
        retention.revalidate(cancellation, deadline)?;
        // A matching action pin alone does not identify the Store. Combining
        // interests refuses a same-content handle borrowed from another Store.
        let interest = ObjectLease::combine(&[
            &self.source_interest,
            &retention.interest,
        ])?;
        let mut descriptors = Vec::new();
        for name in [
            "build-action",
            "build-program",
            "source",
            "worker",
        ] {
            let pinned = self
                .files
                .iter()
                .find(|file| file.name == name)
                .ok_or(BuildError::InputChanged)?;
            linux_fd::require_readonly(pinned.file.fd())?;
            descriptors.push(pinned.file.fd().try_clone_to_owned()?);
        }
        for input in &self.inputs {
            retention_check(cancellation, deadline)?;
            descriptors.push(input.mount_fd().try_clone_to_owned()?);
            let artifact = input
                .open_artifact(cancellation)
                .map_err(|error| materialization_error(&error))?;
            descriptors.push(artifact.duplicate_readonly_descriptor()?);
            // Release its global operation barrier immediately. The combined
            // interest below keeps both Artifact inode and view retained.
            drop(artifact);
        }
        descriptors.push(interest.process_retention()?.into());
        let resources = super::resources::ManagedBuildResources::from_prepared(
            &self.action,
            descriptors,
            cancellation,
            deadline,
        )?;
        retention_check(cancellation, deadline)?;
        Ok(resources)
    }
    pub(in crate::build) fn operation_id(&self) -> &str {
        &self.operation.name
    }
    pub(in crate::build) fn operation_path(&self) -> &Path {
        &self.operation.path
    }
    pub(in crate::build) fn worker_path(&self) -> PathBuf {
        self.operation.stage_path().join("worker")
    }
    pub(in crate::build) fn worker_digest(&self) -> ContentDigest {
        self.action.worker
    }
    pub(in crate::build) fn resources(&self) -> super::BuildResources {
        self.action.program.resources
    }
    pub(in crate::build) fn timeout_seconds(&self) -> u32 {
        self.timeout_seconds
    }
    pub(in crate::build) fn with_managed_preparation_cleanup<T>(
        &self,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
        build: impl FnOnce(
            &mut super::journal::managed::LocalManagedPreparation<'_>,
        ) -> Result<T, BuildError>,
        discard: impl FnOnce(T) -> std::io::Result<()>,
    ) -> Result<T, BuildError> {
        self.operation
            .with_managed_preparation_cleanup(cancellation, deadline, build, discard)
    }
    #[cfg(test)]
    pub(in crate::build) fn prepare_attempt(
        &self,
        context: &super::journal::managed::ManagedAttemptContext,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
    ) -> Result<String, BuildError> {
        self.verify_preparation(cancellation)?;
        if context.action != self.action.digest() || context.worker != self.action.worker {
            return Err(BuildError::InputChanged);
        }
        self.operation
            .prepare_managed(context, cancellation, deadline)
    }
    #[cfg(test)]
    pub(in crate::build) fn authorize_test_start(
        &self,
        context: &super::journal::managed::ManagedAttemptContext,
        nonce: &str,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
    ) -> Result<(), BuildError> {
        self.operation
            .authorize_managed_start(context, nonce, cancellation, deadline)
    }
    pub(in crate::build) fn authorize_manager_start(
        &self,
        specification: &super::supervision::ManagedBuildServiceSpecification,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
    ) -> Result<(), BuildError> {
        self.operation.authorize_managed_start(
            specification.context(),
            specification.nonce(),
            cancellation,
            deadline,
        )
    }
    /// Record an independently observed manager binding. This never authorizes execution.
    pub(in crate::build) fn bind_manager_observation(
        &self,
        observation: &super::supervision::ObservedManagedBuildBinding,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
    ) -> Result<(), BuildError> {
        self.verify_preparation(cancellation)?;
        self.operation
            .bind_managed(observation, cancellation, deadline)
    }
    pub(in crate::build) fn record_namespace_observation(
        &self,
        observation: &super::ObservedManagedBuildNamespace<'_>,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
    ) -> Result<(), BuildError> {
        self.verify_preparation(cancellation)?;
        self.operation
            .record_managed_namespace(observation, cancellation, deadline)
    }
    pub(in crate::build) fn authorize_execution<T>(
        &self,
        observation: &super::ObservedManagedBuildNamespace<'_>,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
        send: impl FnOnce() -> Result<T, BuildError>,
    ) -> Result<T, BuildError> {
        self.verify_preparation(cancellation)?;
        self.operation
            .authorize_managed_commit(observation, cancellation, deadline, send)
    }
    /// Revoke this attempt without stopping a unit or claiming kernel settlement.
    pub(in crate::build) fn revoke_manager_attempt(
        &self,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
    ) -> Result<(), BuildError> {
        self.operation
            .revoke_managed(cancellation, deadline)
    }
    pub(in crate::build) fn verify_service_worker(
        &self,
        cancellation: &Cancellation,
    ) -> Result<(), BuildError> {
        self.verify_preparation(cancellation)?;
        let worker = self
            .files
            .iter()
            .find(|file| file.name == "worker")
            .ok_or(BuildError::InputChanged)?;
        let mut bytes =
            vec![0; usize::try_from(worker.size).map_err(|_| BuildError::InputChanged)?];
        let file = std::fs::File::from(worker.file.fd().try_clone_to_owned()?);
        for (index, chunk) in bytes.chunks_mut(16 * 1024).enumerate() {
            cancellation.check()?;
            file.read_exact_at(
                chunk,
                u64::try_from(index * 16 * 1024).expect("bounded worker"),
            )?;
        }
        if ContentDigest::sha256(&bytes) != self.action.worker {
            return Err(BuildError::InputChanged);
        }
        crate::runtime::validate_static_worker_image(&bytes).map_err(|_| BuildError::InvalidRequest)
    }
    pub fn action_digest(&self) -> ContentDigest {
        self.action.digest()
    }
    pub fn layout(&self) -> ManagedBuildLayout {
        ManagedBuildLayout {
            staging: self.operation.stage_path(),
            working: "/work".into(),
            outputs: format!("/out/syrox/store/{}", self.action.digest()).into(),
            inputs: self
                .action
                .inputs
                .iter()
                .map(|input| format!("/syrox/store/{}/{}", input.action, input.output).into())
                .collect(),
        }
    }
    /// Revalidate pinned files and their namespace before any future handoff.
    /// This does not authorize mounting or executing the worker.
    /// Validate the pinned worker and its descriptor package without exposing
    /// handoff proofs or authorizing payload execution.
    pub fn validate_worker_resources(
        &self,
        cancellation: &Cancellation,
        deadline: std::time::Instant,
    ) -> Result<(), BuildError> {
        let retention = self.retain_for_handoff(cancellation, deadline)?;
        let resources = self.prepare_resources(&retention, cancellation, deadline)?;
        resources.revalidate(cancellation, deadline)
    }

    pub fn verify_preparation(&self, cancellation: &Cancellation) -> Result<(), BuildError> {
        cancellation.check()?;
        if linux_fd::directory_path(&self.stage)? != self.operation.stage_path() {
            return Err(BuildError::InputChanged);
        }
        // Reacquire the source interest's barrier, so its namespace identity is checked.
        let _barrier = self.source_interest.operation()?;
        for pinned in &self.files {
            cancellation.check()?;
            let current = linux_fd::open_existing_regular(self.stage.fd(), Path::new(pinned.name))?;
            if current.metadata().identity() != pinned.file.metadata().identity() {
                return Err(BuildError::InputChanged);
            }
            verify_file(pinned, cancellation)?;
            let after = linux_fd::open_existing_regular(self.stage.fd(), Path::new(pinned.name))?;
            if after.metadata().identity() != pinned.file.metadata().identity() {
                return Err(BuildError::InputChanged);
            }
        }
        for (input, expected) in self.inputs.iter().zip(&self.action.inputs) {
            cancellation.check()?;
            input
                .verify_view(cancellation)
                .map_err(|error| materialization_error(&error))?;
            if input.identity().artifact != expected.artifact
                || input.identity().origin != expected.origin
                || input.identity().action != expected.action
                || input.identity().output != expected.output
            {
                return Err(BuildError::UnsupportedInputs);
            }
        }
        Ok(())
    }
}

/// Prepare authenticated Managed inputs without invoking a host executor.
/// Source and selected retained results must already exist in the supplied Store.
/// All invalid request/source/input checks precede creation of the operation.
pub fn prepare_managed_build_inputs(
    plan: &Plan,
    request: &BuildSpecification,
    store: &Store,
    worker_bytes: &[u8],
    cancellation: &Cancellation,
) -> Result<ManagedBuildInputs, BuildError> {
    cancellation.check()?;
    request.validate()?;
    if request.program.profile != BuildProfile::Managed
        || worker_bytes.is_empty()
        || worker_bytes.len() > 128 * 1024 * 1024
    {
        return Err(BuildError::InvalidRequest);
    }
    let declared = plan
        .builds()
        .find(|build| build.package() == &request.package)
        .ok_or(BuildError::UnsupportedInputs)?;
    if declared.program() != &request.program
        || declared.source_directory() != request.source_directory
        || declared.timeout_seconds() != request.timeout_seconds
        || declared.inputs().len() != request.inputs.len()
    {
        return Err(BuildError::UnsupportedInputs);
    }
    let description = BuildDescription::from_plan(plan, &request.package)?;
    let lease = store.operation()?;
    let limit = source_limit(plan, request)?;
    let mut reader = lease
        .open_verified_checked(description.source, limit, || {
            if cancellation.is_cancelled() {
                Err(crate::cancellation::cancellation_io())
            } else {
                Ok(())
            }
        })
        .map_err(|error| {
            if cancellation.is_cancelled() {
                BuildError::Cancelled
            } else {
                error.into()
            }
        })?
        .ok_or(BuildError::InvalidRequest)?;
    let source = read_source(
        &mut reader,
        description.source,
        limit,
        cancellation,
    )?;
    cancellation.check()?;
    let mut action = Action::new(
        request,
        description.source,
        None,
        ContentDigest::sha256(worker_bytes),
    );
    let inputs = prepare_inputs(
        plan,
        request,
        store,
        &lease,
        &mut action,
        cancellation,
    )?;
    // Reparse the authenticated encoding before writing a staging operation.
    if Action::parse(&action.encode())? != action {
        return Err(BuildError::InvalidRequest);
    }
    let source_interest = lease.retain_objects(&[description.source], &[])?;
    cancellation.check()?;
    drop(reader);
    Ok(ManagedBuildInputs {
        action,
        source,
        worker: worker_bytes.to_vec(),
        inputs,
        source_interest,
        timeout_seconds: request.timeout_seconds,
    })
}

/// Prepare inputs and create a standalone staging operation. Shared execution
/// must admit a producer before selecting an operation for staging.
pub fn prepare_managed_build(
    plan: &Plan,
    request: &BuildSpecification,
    store: &Store,
    worker_bytes: &[u8],
    cancellation: &Cancellation,
) -> Result<PreparedManagedBuild, BuildError> {
    prepare_managed_build_inputs(plan, request, store, worker_bytes, cancellation)?
        .stage(cancellation)
}

fn source_limit(plan: &Plan, request: &BuildSpecification) -> Result<u64, BuildError> {
    let limit = request.program.maximum_source_bytes();
    let declared_limit = plan
        .acquisitions()
        .find(|entry| entry.package() == &request.package)
        .and_then(|entry| entry.sources().next())
        .ok_or(BuildError::UnsupportedInputs)?
        .maximum_bytes();
    Ok(limit.min(declared_limit))
}

fn prepare_inputs(
    plan: &Plan,
    request: &BuildSpecification,
    store: &Store,
    lease: &crate::store::OperationLease,
    action: &mut Action,
    cancellation: &Cancellation,
) -> Result<Vec<MaterializedArtifact>, BuildError> {
    let mut inputs = Vec::new();
    let mut references = std::collections::BTreeSet::new();
    let mut visited = 0;
    for (binding, selected) in request.inputs.iter().zip(
        plan.builds()
            .find(|build| build.package() == &request.package)
            .expect("validated build")
            .inputs(),
    ) {
        let input = binding
            .output
            .open_for_build(store, cancellation)
            .map_err(|error| materialization_error(&error))?;
        super::linux::verify_selected_output(
            plan,
            selected,
            input.identity(),
            lease,
            cancellation,
            &mut visited,
        )?;
        references.extend(input.retained_references().iter().copied());
        if references.len() > 4096 {
            return Err(BuildError::UnsupportedInputs);
        }
        action
            .inputs
            .push(InputIdentity::from(input.identity()));
        inputs.push(input);
    }
    Ok(inputs)
}
fn read_source(
    reader: &mut impl std::io::Read,
    expected: ContentDigest,
    limit: u64,
    cancellation: &Cancellation,
) -> Result<Vec<u8>, BuildError> {
    let mut source = Vec::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        cancellation.check()?;
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if source.len() as u64 + count as u64 > limit {
            return Err(BuildError::InvalidRequest);
        }
        source.extend_from_slice(&chunk[..count]);
    }
    cancellation.check()?;
    if ContentDigest::sha256(&source) != expected {
        return Err(BuildError::InputChanged);
    }
    Ok(source)
}

fn verify_file(pinned: &PinnedFile, cancellation: &Cancellation) -> Result<(), BuildError> {
    let file = std::fs::File::from(pinned.file.fd().try_clone_to_owned()?);
    let mode = if pinned.name == "worker" {
        0o500
    } else {
        0o400
    };
    verify_file_contents(
        &file,
        (pinned.digest, pinned.size, mode),
        cancellation,
        None,
    )
}
fn verify_file_contents(
    file: &std::fs::File,
    (expected, size, mode): (ContentDigest, u64, u32),
    cancellation: &Cancellation,
    deadline: Option<std::time::Instant>,
) -> Result<(), BuildError> {
    let metadata = file.metadata()?;
    if metadata.len() != size
        || metadata.permissions().mode() & 0o7777 != mode
        || metadata.uid() != linux_fd::effective_uid()
    {
        return Err(BuildError::InputChanged);
    }
    let mut hash = Sha256::new();
    let mut remaining = size;
    let mut buffer = [0u8; 16 * 1024];
    while remaining > 0 {
        cancellation.check()?;
        if let Some(deadline) = deadline {
            retention_check(cancellation, deadline)?;
        }
        let chunk_size = usize::try_from(remaining.min(buffer.len() as u64)).expect("bounded read");
        let count = file.read_at(&mut buffer[..chunk_size], size - remaining)?;
        if count == 0 {
            return Err(BuildError::InputChanged);
        }
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut extra = [0u8; 1];
    if file.read_at(&mut extra, size)? != 0
        || file.metadata()?.len() != size
        || file.metadata()?.permissions().mode() & 0o7777 != mode
        || file.metadata()?.uid() != linux_fd::effective_uid()
    {
        return Err(BuildError::InputChanged);
    }
    let digest = ContentDigest::from_sha256_hash(hash.finalize().into());
    if digest != expected {
        return Err(BuildError::InputChanged);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/preparation_imported_tests.rs"]
mod imported_tests;
#[cfg(test)]
#[path = "tests/preparation.rs"]
pub(in crate::build) mod tests;

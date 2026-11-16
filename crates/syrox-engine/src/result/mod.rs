//! Outputs that can be stored and consumed after a build.
//!
//! An imported result is admitted through its manifest and pins without inventing
//! a build record. Materialization retains referenced objects and opens a verified
//! view. The manifest also binds commands to the outputs providing their
//! application, loader and libraries.
//!
//! See [`materialize`](../../src/syrox_engine/result/materialize/mod.rs.html) for view reconstruction and handle lifetime, then
//! [`crate::runtime`] for checking a command's executable closure.

pub(crate) mod artifact;
pub(crate) mod materialize;
mod staging;
pub use staging::{PreparedSystemOutput, ingest_system_output, stage_system_output};
mod producer;
pub use producer::SystemOutputStream;
mod worker_output;
pub use worker_output::{receive_system_outputs, write_system_outputs};
mod transport;
use std::collections::{BTreeMap, BTreeSet};
pub(crate) use transport::ArtifactReader;
pub use transport::ChunkedOutput;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::result::materialize::{AuthorizedOutput, materialize_verified};
use crate::{
    cancellation::Cancellation, runtime::RetainedRuntime, store::ContentDigest,
    store::OperationLease, store::RootName, store::Store, store::StoreError,
};

/// Largest admitted manifest; legacy v2 remains capped at 1 MiB.
pub const MAX_RESULT_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LEGACY_MANIFEST_BYTES: u64 = 1024 * 1024;
const SYSTEM_HEADER: &[u8] = b"syrox-result-v3\n";
pub const MAX_RESULT_OUTPUTS: usize = 128;
pub const MAX_RESULT_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_COMMANDS: usize = 128;
const MAX_COMMAND_ROLES: usize = 1024;
const HEADER: &[u8] = b"syrox-result-v2\n";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultOutput {
    #[serde(with = "digest_text")]
    pub action: ContentDigest,
    pub output: String,
    #[serde(with = "digest_text")]
    pub artifact: ContentDigest,
    pub files: usize,
    /// Absent in legacy outputs; `artifact` pins this embedded manifest when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunked: Option<ChunkedOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultCommand {
    pub application: String,
    pub application_path: String,
    pub loader: Option<String>,
    pub loader_path: Option<String>,
    pub libraries: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultManifest {
    outputs: BTreeMap<String, ResultOutput>,
    commands: BTreeMap<String, ResultCommand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    system: Option<SystemResultLimits>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemResultLimits {
    bytes: u64,
    files: u64,
}

#[derive(Debug, Error)]
pub enum ResultError {
    #[error("invalid consumable result: {0}")]
    Invalid(String),
    #[error("consumable result does not match the explicitly authorized manifest digest")]
    PinMismatch,
    #[error("consumable result operation cancelled")]
    Cancelled,
    #[error(transparent)]
    Store(StoreError),
    #[error(transparent)]
    Materialization(MaterializationError),
    #[error(transparent)]
    Runtime(crate::runtime::RuntimeError),
}

impl From<StoreError> for ResultError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Io(ref source) if crate::cancellation::is_cancellation_io(source) => {
                Self::Cancelled
            }
            other => Self::Store(other),
        }
    }
}

impl From<MaterializationError> for ResultError {
    fn from(error: MaterializationError) -> Self {
        match error {
            MaterializationError::Cancelled => Self::Cancelled,
            other => Self::Materialization(other),
        }
    }
}

impl From<crate::runtime::RuntimeError> for ResultError {
    fn from(error: crate::runtime::RuntimeError) -> Self {
        match error {
            crate::runtime::RuntimeError::Cancelled => Self::Cancelled,
            other => Self::Runtime(other),
        }
    }
}

fn invalid(message: impl Into<String>) -> ResultError {
    ResultError::Invalid(message.into())
}

fn check(cancellation: &Cancellation) -> Result<(), ResultError> {
    cancellation
        .check()
        .map_err(|_| ResultError::Cancelled)
}

impl ResultManifest {
    /// Derive portable metadata from verified live views, excluding build receipts,
    /// sources and toolchains. Commands select output keys, not host paths.
    pub fn from_views(
        outputs: BTreeMap<String, &MaterializedArtifact>,
        commands: BTreeMap<String, ResultCommand>,
    ) -> Result<Self, ResultError> {
        let manifest = Self {
            outputs: outputs
                .into_iter()
                .map(|(key, view)| {
                    (
                        key,
                        ResultOutput {
                            action: view.action(),
                            output: view.identity().output.clone(),
                            artifact: view.artifact(),
                            files: view.files(),
                            chunked: view.chunked().cloned(),
                        },
                    )
                })
                .collect(),
            commands,
            system: None,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Construct an explicitly budgeted system result. This is pure metadata;
    /// admission still checks every chunk, artifact record and runtime closure.
    pub fn for_system(
        outputs: BTreeMap<String, ResultOutput>,
        commands: BTreeMap<String, ResultCommand>,
        budget: &crate::system::budget::AdmittedBudget,
    ) -> Result<Self, ResultError> {
        let manifest = Self {
            outputs,
            commands,
            system: Some(SystemResultLimits {
                bytes: budget.request().output_bytes,
                files: budget.request().files,
            }),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub(crate) fn check_system_budget(
        &self,
        budget: &crate::system::budget::AdmittedBudget,
    ) -> Result<(), ResultError> {
        self.validate()?;
        let limits = self
            .system
            .ok_or_else(|| invalid("expected system result version 3"))?;
        if limits.bytes > budget.request().output_bytes || limits.files > budget.request().files {
            return Err(invalid(
                "system result exceeds administrator-admitted budget",
            ));
        }
        Ok(())
    }

    pub fn is_system(&self) -> bool {
        self.system.is_some()
    }

    fn limits(&self, output: &ResultOutput) -> artifact::ArtifactLimits {
        if output.chunked.is_some() {
            let system = self.system.expect("validated system descriptor");
            artifact::ArtifactLimits {
                bytes: system.bytes,
                expanded_bytes: system.bytes,
                files: usize::try_from(system.files).expect("bounded system files"),
            }
        } else {
            artifact::ArtifactLimits::LEGACY
        }
    }

    fn manifest_limit(&self) -> u64 {
        if self.is_system() {
            MAX_RESULT_MANIFEST_BYTES
        } else {
            MAX_LEGACY_MANIFEST_BYTES
        }
    }

    pub fn outputs(&self) -> &BTreeMap<String, ResultOutput> {
        &self.outputs
    }
    pub fn commands(&self) -> &BTreeMap<String, ResultCommand> {
        &self.commands
    }

    pub fn encode(&self) -> Result<Vec<u8>, ResultError> {
        self.validate()?;
        let mut bytes = if self.is_system() {
            SYSTEM_HEADER
        } else {
            HEADER
        }
        .to_vec();
        serde_json::to_writer(&mut bytes, self).map_err(|error| invalid(error.to_string()))?;
        bytes.push(b'\n');
        if bytes.len() as u64 > self.manifest_limit() {
            return Err(invalid("manifest byte limit exceeded"));
        }
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ResultError> {
        if bytes.len() as u64 > MAX_RESULT_MANIFEST_BYTES {
            return Err(invalid("manifest byte limit exceeded"));
        }
        if bytes.starts_with(HEADER) && bytes.len() as u64 > MAX_LEGACY_MANIFEST_BYTES {
            return Err(invalid("manifest byte limit exceeded"));
        }
        let json = bytes
            .strip_prefix(HEADER)
            .or_else(|| bytes.strip_prefix(SYSTEM_HEADER))
            .ok_or_else(|| invalid("unsupported manifest version"))?;
        let manifest: Self =
            serde_json::from_slice(json).map_err(|error| invalid(error.to_string()))?;
        if manifest.encode()? != bytes {
            return Err(invalid("manifest is not canonical"));
        }
        Ok(manifest)
    }

    pub fn digest(&self) -> Result<ContentDigest, ResultError> {
        Ok(ContentDigest::sha256(&self.encode()?))
    }

    /// Complete portable CAS closure, including this manifest itself.
    pub fn references(&self) -> Result<Vec<ContentDigest>, ResultError> {
        let mut references = BTreeSet::from([self.digest()?]);
        for output in self.outputs.values() {
            references.insert(output.artifact);
            if let Some(chunked) = &output.chunked {
                references.extend(chunked.references(output.artifact)?);
            }
        }
        if references.len() as u64 > crate::store::MAX_ROOT_REFERENCES {
            return Err(invalid(
                "result object closure exceeds root reference limit",
            ));
        }
        Ok(references.into_iter().collect())
    }

    fn validate(&self) -> Result<(), ResultError> {
        if self.outputs.is_empty()
            || self.outputs.len() > MAX_RESULT_OUTPUTS
            || self.commands.len() > MAX_COMMANDS
        {
            return Err(invalid("output or command count exceeds bounds"));
        }
        if let Some(system) = self.system
            && (system.bytes == 0
                || system.bytes > crate::store::chunked::MAX_ARTIFACT_BYTES
                || system.files == 0
                || system.files > 1_000_000)
        {
            return Err(invalid("invalid system result budget"));
        }
        let mut logical = BTreeMap::new();
        for (key, output) in &self.outputs {
            if output.chunked.is_some() && self.system.is_none() {
                return Err(invalid(
                    "chunked outputs require a version 3 system result",
                ));
            }
            if !valid_name(key)
                || !valid_name(&output.output)
                || output.files == 0
                || output.files > self.limits(output).files
            {
                return Err(invalid("invalid output metadata"));
            }
            if let Some(previous) = logical.insert((output.action, &output.output), output)
                && previous != output
            {
                return Err(invalid("conflicting logical output identities"));
            }
        }
        // Validate embedded manifests before any Store or output-view effect.
        let mut closure = BTreeSet::new();
        let mut declared = BTreeSet::new();
        let mut declared_bytes = 0_u64;
        let mut declared_files = 0_u64;
        for output in self.outputs.values() {
            if let Some(system) = self.system
                && declared.insert(output.artifact)
            {
                declared_files = declared_files
                    .checked_add(output.files as u64)
                    .filter(|count| *count <= system.files)
                    .ok_or_else(|| invalid("aggregate declared artifact file limit exceeded"))?;
                if let Some(chunked) = &output.chunked {
                    declared_bytes = declared_bytes
                        .checked_add(chunked.decoded()?.size())
                        .filter(|bytes| *bytes <= system.bytes)
                        .ok_or_else(|| {
                            invalid("aggregate declared artifact byte limit exceeded")
                        })?;
                }
            }
            if let Some(chunked) = &output.chunked {
                closure.extend(chunked.references(output.artifact)?);
                if chunked.decoded()?.size() > self.limits(output).bytes {
                    return Err(invalid(
                        "system artifact exceeds declared result budget",
                    ));
                }
            } else {
                closure.insert(output.artifact);
            }
        }
        // Reserve one reference for the result manifest itself.
        if closure.len() as u64 >= crate::store::MAX_ROOT_REFERENCES {
            return Err(invalid(
                "result object closure exceeds root reference limit",
            ));
        }
        let mut roles = 0;
        for (name, command) in &self.commands {
            roles += 1 + usize::from(command.loader.is_some()) + command.libraries.len();
            if !valid_name(name)
                || command.libraries.len() > crate::runtime::MAX_RUNTIME_LIBRARIES
                || roles > MAX_COMMAND_ROLES
            {
                return Err(invalid("invalid command name or role count"));
            }
            for key in std::iter::once(&command.application)
                .chain(command.loader.iter())
                .chain(&command.libraries)
            {
                if !self.outputs.contains_key(key) {
                    return Err(invalid("command references an absent output"));
                }
            }
            if !valid_path(&command.application_path)
                || command.loader.is_some() != command.loader_path.is_some()
                || command
                    .loader_path
                    .as_ref()
                    .is_some_and(|path| !valid_path(path))
            {
                return Err(invalid(
                    "command requires valid executable paths for its application and loader",
                ));
            }
        }
        Ok(())
    }
}

fn valid_path(path: &str) -> bool {
    path.len() <= 4096 && artifact::relative_path(path)
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && name != "."
        && name != ".."
}

/// Retains verified portable result objects while consumers select outputs.
#[derive(Debug)]
pub struct AdmittedResult {
    lease: crate::store::ObjectLease,
    root: RootName,
    digest: ContentDigest,
    manifest: ResultManifest,
}

impl AdmittedResult {
    pub fn open(
        store: &Store,
        root: &RootName,
        digest: ContentDigest,
        cancellation: &Cancellation,
    ) -> Result<Self, ResultError> {
        check(cancellation)?;
        let lease = store.operation()?;
        let bytes = lease
            .read_verified(digest, MAX_RESULT_MANIFEST_BYTES)?
            .ok_or_else(|| invalid("manifest is absent"))?;
        let manifest = ResultManifest::parse(bytes.as_bytes())?;
        let references = lease
            .build_references(root)?
            .ok_or_else(|| invalid("result root is absent"))?;
        if manifest.digest()? != digest || references != manifest.references()? {
            return Err(invalid("result root disagrees with manifest"));
        }
        verify(&lease, &manifest, digest, cancellation)?;
        let interest = lease.retain_objects(&manifest.references()?, &[])?;
        Ok(Self {
            lease: interest,
            root: root.clone(),
            digest,
            manifest,
        })
    }
    pub(crate) fn materialize_output(
        &self,
        requested: &OutputIdentity,
        cancellation: &Cancellation,
    ) -> Result<MaterializedArtifact, ResultError> {
        check(cancellation)?;
        let output = self
            .manifest
            .outputs
            .values()
            .find(|output| identity(output, self.digest) == *requested)
            .ok_or_else(|| invalid("output identity is absent from manifest"))?;
        Ok(materialize_verified(
            self.lease.operation()?,
            authorized(&self.manifest, self.digest, output)?,
            cancellation,
        )?)
    }

    pub fn manifest(&self) -> &ResultManifest {
        &self.manifest
    }
    pub fn output(&self, key: &str) -> Option<RetainedOutput> {
        self.manifest
            .outputs
            .get(key)
            .map(|output| RetainedOutput {
                root: self.root.clone(),
                identity: identity(output, self.digest),
            })
    }
    pub fn command(&self, name: &str) -> Option<RetainedRuntime> {
        let command = self.manifest.commands.get(name)?;
        Some(RetainedRuntime {
            application: crate::runtime::RuntimeFile {
                output: self.output(&command.application)?,
                path: command.application_path.clone(),
            },
            loader: match (&command.loader, &command.loader_path) {
                (Some(key), Some(path)) => Some(crate::runtime::RuntimeFile {
                    output: self.output(key)?,
                    path: path.clone(),
                }),
                (None, None) => None,
                _ => return None,
            },
            libraries: command
                .libraries
                .iter()
                .map(|key| self.output(key))
                .collect::<Option<_>>()?,
        })
    }
}

/// Admit only the exact pinned manifest after every output and runtime command
/// validates under one shared Store lease. Unretained uploaded objects are inert.
pub fn admit_result(
    store: &Store,
    root: &RootName,
    manifest: &ResultManifest,
    expected_digest: ContentDigest,
    cancellation: &Cancellation,
) -> Result<AdmittedResult, ResultError> {
    if manifest.is_system() {
        return Err(invalid(
            "system results require explicit budgeted admission",
        ));
    }
    admit_checked(
        store,
        root,
        manifest,
        expected_digest,
        cancellation,
    )
}

/// Admit a v3 result only within the administrator-admitted output/inode budget.
/// This authorizes consumption of pinned bytes, not execution or installation.
pub fn admit_system_result(
    store: &Store,
    root: &RootName,
    manifest: &ResultManifest,
    expected_digest: ContentDigest,
    budget: &crate::system::budget::AdmittedBudget,
    cancellation: &Cancellation,
) -> Result<AdmittedResult, ResultError> {
    manifest.check_system_budget(budget)?;
    admit_checked(
        store,
        root,
        manifest,
        expected_digest,
        cancellation,
    )
}

fn admit_checked(
    store: &Store,
    root: &RootName,
    manifest: &ResultManifest,
    expected_digest: ContentDigest,
    cancellation: &Cancellation,
) -> Result<AdmittedResult, ResultError> {
    check(cancellation)?;
    let bytes = manifest.encode()?;
    let digest = ContentDigest::sha256(&bytes);
    if digest != expected_digest {
        return Err(ResultError::PinMismatch);
    }
    let lease = store.operation()?;
    // The pinned bytes remain inert until root publication. Materialized
    // verification now retains every reference, including this manifest.
    lease.ingest(
        bytes.as_slice(),
        digest,
        MAX_RESULT_MANIFEST_BYTES,
    )?;
    verify(&lease, manifest, digest, cancellation)?;
    let interest = lease.retain_objects(&manifest.references()?, &[])?;
    check(cancellation)?;
    lease
        .publish_root_checked(root, &manifest.references()?, || {
            cancellation
                .check()
                .map_err(|_| crate::cancellation::cancellation_io())
        })
        .map_err(|error| match error {
            StoreError::Io(ref source) if crate::cancellation::is_cancellation_io(source) => {
                ResultError::Cancelled
            }
            other => other.into(),
        })?;
    Ok(AdmittedResult {
        lease: interest,
        root: root.clone(),
        digest,
        manifest: manifest.clone(),
    })
}

fn identity(output: &ResultOutput, manifest: ContentDigest) -> OutputIdentity {
    OutputIdentity {
        action: output.action,
        origin: OutputOrigin::Imported {
            manifest,
        },
        artifact: output.artifact,
        output: output.output.clone(),
    }
}

fn authorized(
    manifest: &ResultManifest,
    digest: ContentDigest,
    output: &ResultOutput,
) -> Result<AuthorizedOutput, ResultError> {
    Ok(AuthorizedOutput {
        identity: identity(output, digest),
        references: manifest.references()?,
        files: output.files,
        maximum_bytes: manifest.limits(output).bytes,
        limits: manifest.limits(output),
        chunked: output.chunked.clone(),
    })
}

#[derive(Default)]
struct ArtifactBudget {
    seen: BTreeSet<ContentDigest>,
    bytes: u64,
    files: u64,
}

impl ArtifactBudget {
    fn charge(
        &mut self,
        digest: ContentDigest,
        bytes: u64,
        files: usize,
        limits: Option<SystemResultLimits>,
    ) -> Result<(), ResultError> {
        if self.seen.contains(&digest) {
            return Ok(());
        }
        let maximum = limits.map_or(MAX_RESULT_ARTIFACT_BYTES, |limits| limits.bytes);
        let total = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| invalid("aggregate artifact byte limit exceeded"))?;
        self.files = self
            .files
            .checked_add(files as u64)
            .filter(|total| limits.is_none_or(|limits| *total <= limits.files))
            .ok_or_else(|| invalid("aggregate artifact file limit exceeded"))?;
        self.seen.insert(digest);
        self.bytes = total;
        Ok(())
    }
}

fn verify(
    lease: &OperationLease,
    manifest: &ResultManifest,
    digest: ContentDigest,
    cancellation: &Cancellation,
) -> Result<(), ResultError> {
    manifest.validate()?;
    let mut budget = ArtifactBudget::default();
    for output in manifest.outputs.values() {
        check(cancellation)?;
        let limits = manifest.limits(output);
        let input = ArtifactReader::open(
            lease,
            output.artifact,
            output.chunked.as_ref(),
            limits,
            cancellation,
        )?;
        let encoded_bytes = input.size();
        let indexed = artifact::IndexedArtifact::open_with_limits(input, "", limits, cancellation)
            .map_err(|error| {
                if cancellation.is_cancelled() {
                    ResultError::Cancelled
                } else {
                    invalid(error.to_string())
                }
            })?;
        let bytes = if manifest.is_system() {
            encoded_bytes.max(indexed.files().expanded_bytes())
        } else {
            encoded_bytes
        };
        let files = if let Some(system) = manifest.system {
            indexed
                .files()
                .view_entries(usize::try_from(system.files).expect("bounded files"))
                .map_err(|error| invalid(error.to_string()))?
        } else {
            output.files
        };
        budget.charge(output.artifact, bytes, files, manifest.system)?;
        if indexed.files().len() != output.files {
            return Err(invalid(
                "artifact file count disagrees with manifest",
            ));
        }
    }
    let mut views = BTreeMap::new();
    for command in manifest.commands.values() {
        for key in std::iter::once(&command.application)
            .chain(command.loader.iter())
            .chain(&command.libraries)
        {
            if !views.contains_key(key) {
                views.insert(
                    key.clone(),
                    materialize_verified(
                        lease.clone(),
                        authorized(manifest, digest, &manifest.outputs[key])?,
                        cancellation,
                    )?,
                );
            }
        }
        crate::runtime::verify_materialized_runtime(
            crate::runtime::RuntimeFile {
                output: views[&command.application].share(),
                path: command.application_path.clone(),
            },
            command
                .loader
                .as_ref()
                .map(|key| crate::runtime::RuntimeFile {
                    output: views[key].share(),
                    path: command
                        .loader_path
                        .clone()
                        .expect("validated loader path"),
                }),
            command
                .libraries
                .iter()
                .map(|key| views[key].share())
                .collect(),
            cancellation,
        )?;
    }
    check(cancellation)
}

pub(crate) fn materialize_imported(
    store: &Store,
    root: &RootName,
    digest: ContentDigest,
    requested: &OutputIdentity,
    cancellation: &Cancellation,
) -> Result<MaterializedArtifact, MaterializationError> {
    let open = || -> Result<MaterializedArtifact, ResultError> {
        let admitted = AdmittedResult::open(store, root, digest, cancellation)?;
        admitted.materialize_output(requested, cancellation)
    };
    open().map_err(|error| {
        if cancellation.is_cancelled() {
            MaterializationError::Cancelled
        } else {
            MaterializationError::Invalid(error.to_string())
        }
    })
}

/// Verify the complete portable file closure for a build input. This does not
/// select or authorize execution of the manifest's runtime commands.
pub(crate) fn verify_build_input_manifest(
    lease: &OperationLease,
    digest: ContentDigest,
    cancellation: &(impl crate::cancellation::OperationControl + ?Sized),
) -> Result<ResultManifest, crate::build::BuildError> {
    use crate::build::BuildError;
    use std::io::Read as _;
    cancellation.check_cancelled()?;
    let fail = || BuildError::Cache("invalid imported build input".into());
    let mut reader = lease
        .open_verified_checked(digest, MAX_RESULT_MANIFEST_BYTES, || {
            cancellation
                .check_cancelled()
                .map_err(|_| crate::cancellation::cancellation_io())
        })
        .map_err(|error| {
            if cancellation.is_cancelled() {
                BuildError::Cancelled
            } else {
                error.into()
            }
        })?
        .ok_or_else(fail)?;
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_RESULT_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    cancellation.check_cancelled()?;
    if bytes.len() as u64 > MAX_RESULT_MANIFEST_BYTES || ContentDigest::sha256(&bytes) != digest {
        return Err(fail());
    }
    let manifest = ResultManifest::parse(&bytes).map_err(|_| fail())?;
    if manifest.is_system() {
        return Err(fail());
    }
    let mut budget = ArtifactBudget::default();
    for output in manifest.outputs.values() {
        cancellation.check_cancelled()?;
        let artifact = lease
            .open_verified_checked(
                output.artifact,
                artifact::MAX_OUTPUT_BYTES,
                || {
                    cancellation
                        .check_cancelled()
                        .map_err(|_| crate::cancellation::cancellation_io())
                },
            )
            .map_err(|error| {
                if cancellation.is_cancelled() {
                    BuildError::Cancelled
                } else {
                    error.into()
                }
            })?
            .ok_or_else(fail)?;
        budget
            .charge(
                output.artifact,
                artifact.size(),
                output.files,
                None,
            )
            .map_err(|_| fail())?;
        if artifact::IndexedArtifact::open_checked(artifact, "", cancellation)?
            .files()
            .len()
            != output.files
        {
            return Err(fail());
        }
    }
    cancellation.check_cancelled()?;
    Ok(manifest)
}

/// Internal file-only reopening for build inputs, with shared build cancellation.
pub(crate) fn materialize_imported_control(
    store: &Store,
    root: &RootName,
    digest: ContentDigest,
    requested: &OutputIdentity,
    cancellation: &(impl crate::cancellation::OperationControl + ?Sized),
) -> Result<MaterializedArtifact, MaterializationError> {
    cancellation
        .check_cancelled()
        .map_err(|_| MaterializationError::Cancelled)?;
    let lease = store.operation()?;
    let manifest = verify_build_input_manifest(&lease, digest, cancellation).map_err(|error| {
        if cancellation.is_cancelled() {
            MaterializationError::Cancelled
        } else {
            MaterializationError::Invalid(error.to_string())
        }
    })?;
    let references = lease
        .build_references(root)?
        .ok_or(MaterializationError::MissingResult)?;
    if references
        != manifest
            .references()
            .map_err(|error| MaterializationError::Invalid(error.to_string()))?
    {
        return Err(MaterializationError::Invalid(
            "result root disagrees with manifest".into(),
        ));
    }
    let output = manifest
        .outputs
        .values()
        .find(|output| identity(output, digest) == *requested)
        .ok_or_else(|| {
            MaterializationError::Invalid("output identity is absent from manifest".into())
        })?;
    let authorized = authorized(&manifest, digest, output)
        .map_err(|error| MaterializationError::Invalid(error.to_string()))?;
    materialize_verified(lease, authorized, cancellation)
}

mod digest_text {
    use super::ContentDigest;
    use serde::{Deserialize, Deserializer, Serializer};
    pub(super) fn serialize<S: Serializer>(
        value: &ContentDigest,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ContentDigest, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests;

pub use materialize::{
    MaterializationError, MaterializedArtifact, OutputIdentity, OutputOrigin, RetainedOutput,
    clear_materializations,
};
pub use materialize::{materialize_artifact, materialize_named_artifact};

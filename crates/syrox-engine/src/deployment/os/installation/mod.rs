//! Guarda uma geração e permite reabri-la sem o projeto original.
//!
//! `Preparing` e `Prepared` dizem quais objetos precisam continuar retidos. A
//! seleção de uma geração desejada e a autorização para agir no manager ficam
//! no apply e no journal de ativação.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::Path;
use std::time::Instant;

use super::{GenerationManifest, PreparedGeneration};
use crate::{
    cancellation::Cancellation, result::MaterializedArtifact, result::OutputIdentity,
    result::OutputOrigin, result::RetainedOutput, runtime::RuntimeClosure, runtime::RuntimeFile,
    store::ContentDigest, store::ObjectLease, store::RootName, store::Store,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod configuration;
mod launch;
mod launcher;
pub(crate) use configuration::GenerationConfiguration;
pub(crate) use launcher::GenerationLauncher;
pub(super) mod storage;
#[cfg(test)]
mod tests;

const MAX_CANDIDATES: usize = 1024;
const MAX_MANIFEST_BYTES: usize = super::manifest::MAX_BYTES;
const MAX_LAUNCHER_BYTES: u64 = 128 * 1024 * 1024;
const RECORD_HEADER: &[u8] = b"syrox-os-candidate-v1\n";

#[derive(Debug, Error)]
pub(crate) enum InstallationError {
    #[error("invalid Os installation: {0}")]
    Invalid(&'static str),
    #[error("Os candidate publication is uncertain: {0}")]
    Uncertain(&'static str),
    #[error("Os preparation cancelled")]
    Cancelled,
    #[error("Os preparation deadline expired")]
    Deadline,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error(transparent)]
    Materialization(#[from] crate::result::MaterializationError),
    #[error(transparent)]
    Runtime(#[from] crate::runtime::RuntimeError),
    #[error(transparent)]
    Generation(#[from] super::GenerationError),
    #[error(transparent)]
    Encoding(#[from] serde_json::Error),
}
type Result<T> = std::result::Result<T, InstallationError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CandidatePhase {
    Preparing,
    Prepared,
}
#[derive(Debug)]
pub(crate) struct CandidateEntry {
    pub pin: ContentDigest,
    pub phase: std::result::Result<CandidatePhase, String>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    installation: String,
    generation: String,
    phase: CandidatePhase,
}
impl Record {
    fn bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = RECORD_HEADER.to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        Ok(bytes)
    }
    fn parse(bytes: &[u8], installation: &str, pin: ContentDigest) -> Result<Self> {
        let json = bytes
            .strip_prefix(RECORD_HEADER)
            .ok_or(InstallationError::Invalid(
                "unsupported candidate record",
            ))?;
        let record: Self = serde_json::from_slice(json)?;
        if record.version != 1
            || record.installation != installation
            || record.generation != pin.to_string()
            || record.bytes()? != bytes
        {
            return Err(InstallationError::Invalid(
                "candidate record identity or encoding differs",
            ));
        }
        Ok(record)
    }
}

#[derive(Debug)]
pub(crate) struct GenerationInstallation {
    storage: storage::Storage,
    id: String,
}
/// Serializes apply/recovery while permitting independent worker journal updates.
#[derive(Debug)]
pub(crate) struct ExecutionGuard {
    _authority: storage::Authority,
}
impl GenerationInstallation {
    pub(crate) fn execution(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<ExecutionGuard> {
        let execution = self.storage.execution(cancellation, deadline)?;
        let _journal = self.storage.lock(cancellation, deadline)?;
        if self.storage.installation_id(false)? != self.id {
            return Err(InstallationError::Invalid(
                "installation identity changed",
            ));
        }
        Ok(ExecutionGuard {
            _authority: execution,
        })
    }
    pub(crate) fn validate_path(
        &self,
        path: &Path,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        let _guard = self.storage.lock(cancellation, deadline)?;
        if self.storage.installation_id(false)? != self.id {
            return Err(InstallationError::Invalid(
                "installation identity changed",
            ));
        }
        self.storage.validate_path(path)
    }
    /// The caller supplies an existing private directory. Initialization creates
    /// only installation metadata, never host configuration or systemd units.
    pub(crate) fn initialize(
        path: &Path,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        check(cancellation, deadline)?;
        let storage = storage::Storage::open(path, true)?;
        let _lock = storage.lock(cancellation, deadline)?;
        let id = storage.installation_id(true)?;
        Ok(Self {
            storage,
            id,
        })
    }
    pub(crate) fn open_existing(
        path: &Path,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        check(cancellation, deadline)?;
        let storage = storage::Storage::open(path, false)?;
        let _lock = storage.lock(cancellation, deadline)?;
        let id = storage.installation_id(false)?;
        Ok(Self {
            storage,
            id,
        })
    }
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn list(
        &self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Vec<CandidateEntry>> {
        let _lock = self.storage.lock(cancellation, deadline)?;
        if self.storage.installation_id(false)? != self.id {
            return Err(InstallationError::Invalid(
                "installation identity changed",
            ));
        }
        let mut result = Vec::new();
        for pin in self.storage.ids()? {
            check(cancellation, deadline)?;
            let phase = (|| {
                let directory = self.storage.candidate(pin, false)?;
                let bytes = storage::read(directory.fd(), "state", 1024)?;
                Ok(Record::parse(&bytes, &self.id, pin)?.phase)
            })()
            .map_err(|error: InstallationError| error.to_string());
            result.push(CandidateEntry {
                pin,
                phase,
            });
        }
        Ok(result)
    }
    pub(crate) fn prepare(
        &self,
        generation: &PreparedGeneration,
        store: &Store,
        launcher: &Path,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<RetainedGeneration> {
        check(cancellation, deadline)?;
        let pin = generation.digest();
        let manifest = GenerationManifest::decode_bounded(generation.canonical_bytes(), pin)?;
        let mut views = BTreeMap::new();
        for view in generation.consumer().outputs().values() {
            if !view.same_store(store)? {
                return Err(InstallationError::Invalid(
                    "output belongs to another Store",
                ));
            }
            views.insert(
                super::manifest::Output::from_identity(view.identity()).key()?,
                view,
            );
        }
        if views.len() != manifest.outputs.len() || views.keys().ne(manifest.outputs.keys()) {
            return Err(InstallationError::Invalid(
                "prepared output identities differ from manifest",
            ));
        }
        let launcher_file =
            crate::platform::linux::fd::open_top(launcher).map_err(storage::open_error)?;
        if launcher_file.metadata().file_type() != crate::platform::linux::fd::FileType::Regular
            || launcher_file.metadata().size() > MAX_LAUNCHER_BYTES
        {
            return Err(InstallationError::Invalid(
                "launcher is not a bounded regular file",
            ));
        }
        let launcher_digest = launcher_digest(&manifest)?;
        let _lock = self.storage.lock(cancellation, deadline)?;
        if self.storage.installation_id(false)? != self.id {
            return Err(InstallationError::Invalid(
                "installation identity changed",
            ));
        }
        let (directory, mut record) = self.begin_candidate(pin, generation.canonical_bytes())?;
        let operation = store.operation()?;
        operation.ingest(
            CheckedReader {
                inner: launcher_file.into_file(),
                cancellation,
                deadline,
            },
            launcher_digest,
            MAX_LAUNCHER_BYTES,
        )?;
        operation.ingest(
            generation.canonical_bytes(),
            pin,
            MAX_MANIFEST_BYTES as u64,
        )?;
        for (key, view) in views {
            check(cancellation, deadline)?;
            view.retain(&output_root(&self.id, pin, &key)?, cancellation)?;
        }
        let references = metadata_references(pin, launcher_digest);
        operation.publish_root_checked(
            &metadata_root(&self.id, pin)?,
            &references,
            || check_io(cancellation, deadline),
        )?;
        drop(operation);
        check(cancellation, deadline)?;
        record.phase = CandidatePhase::Prepared;
        self.storage
            .write(directory.fd(), "state", &record.bytes()?)?;
        self.open_locked(store, pin, cancellation, deadline)
    }
    pub(crate) fn open(
        &self,
        store: &Store,
        pin: ContentDigest,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<RetainedGeneration> {
        let _lock = self.storage.lock(cancellation, deadline)?;
        if self.storage.installation_id(false)? != self.id {
            return Err(InstallationError::Invalid(
                "installation identity changed",
            ));
        }
        self.open_locked(store, pin, cancellation, deadline)
    }
    fn begin_candidate(
        &self,
        pin: ContentDigest,
        bytes: &[u8],
    ) -> Result<(crate::platform::linux::fd::OpenedPath, Record)> {
        let directory = self.storage.candidate(pin, true)?;
        let mut record = Record {
            version: 1,
            installation: self.id.clone(),
            generation: pin.to_string(),
            phase: CandidatePhase::Preparing,
        };
        if let Some(bytes) = storage::read_optional(directory.fd(), "state", 1024)? {
            record = Record::parse(&bytes, &self.id, pin)?;
        } else {
            // The manifest fixes every expected root name before any Store
            // publication. Incomplete directories remain recovery evidence.
            if let Some(previous) =
                storage::read_optional(directory.fd(), "manifest", MAX_MANIFEST_BYTES)?
            {
                if previous != bytes {
                    return Err(InstallationError::Invalid(
                        "incomplete candidate manifest differs; evidence retained",
                    ));
                }
            } else {
                self.storage
                    .write(directory.fd(), "manifest", bytes)?;
            }
            self.storage
                .write(directory.fd(), "state", &record.bytes()?)?;
        }
        let saved = storage::read(directory.fd(), "manifest", MAX_MANIFEST_BYTES)?;
        if saved != bytes {
            return Err(InstallationError::Invalid(
                "candidate manifest differs",
            ));
        }
        Ok((directory, record))
    }
    fn open_locked(
        &self,
        store: &Store,
        pin: ContentDigest,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<RetainedGeneration> {
        check(cancellation, deadline)?;
        let directory = self.storage.candidate(pin, false)?;
        let record = Record::parse(
            &storage::read(directory.fd(), "state", 1024)?,
            &self.id,
            pin,
        )?;
        if record.phase != CandidatePhase::Prepared {
            return Err(InstallationError::Invalid(
                "candidate is not prepared; evidence retained",
            ));
        }
        let bytes = storage::read(directory.fd(), "manifest", MAX_MANIFEST_BYTES)?;
        let manifest = GenerationManifest::decode_bounded(&bytes, pin)?;
        let launcher = launcher_digest(&manifest)?;
        let operation = store.operation()?;
        let references = metadata_references(pin, launcher);
        if operation.build_references(&metadata_root(&self.id, pin)?)? != Some(references.clone()) {
            return Err(InstallationError::Invalid(
                "candidate metadata root is absent or differs",
            ));
        }
        let stored = operation
            .read_verified(pin, MAX_MANIFEST_BYTES as u64)?
            .ok_or(InstallationError::Invalid(
                "retained manifest is absent",
            ))?;
        if stored.as_bytes() != bytes {
            return Err(InstallationError::Invalid(
                "retained manifest differs",
            ));
        }
        let worker = operation
            .open_verified_checked(launcher, MAX_LAUNCHER_BYTES, || {
                check_io(cancellation, deadline)
            })?
            .ok_or(InstallationError::Invalid(
                "retained launcher is absent",
            ))?;
        drop(worker);
        let metadata_interest = operation.retain_objects(&references, &[])?;
        drop(operation);
        let mut outputs = BTreeMap::new();
        let mut retained = BTreeMap::new();
        for (key, output) in &manifest.outputs {
            check(cancellation, deadline)?;
            let output = RetainedOutput {
                root: output_root(&self.id, pin, key)?,
                identity: output_identity(output)?,
            };
            outputs.insert(key.clone(), output.open(store, cancellation)?);
            retained.insert(key.clone(), output);
        }
        let mut commands = BTreeMap::new();
        for (key, invocation) in &manifest.commands {
            check(cancellation, deadline)?;
            let application = RuntimeFile {
                output: outputs[&invocation.application.output].share(),
                path: invocation.application.path.clone(),
            };
            let loader = invocation
                .loader
                .as_ref()
                .map(|role| RuntimeFile {
                    output: outputs[&role.output].share(),
                    path: role.path.clone(),
                });
            let libraries = invocation
                .libraries
                .iter()
                .map(|key| outputs[key].share())
                .collect();
            commands.insert(
                key.clone(),
                crate::runtime::verify_materialized_runtime(
                    application,
                    loader,
                    libraries,
                    cancellation,
                )?,
            );
        }
        check(cancellation, deadline)?;
        self.storage.confirm_durable(pin, &directory)?;
        Ok(RetainedGeneration {
            installation: self.id.clone(),
            manifest,
            bytes,
            pin,
            #[cfg(test)]
            retained,
            outputs,
            commands,
            metadata_interest,
        })
    }
}

#[derive(Debug)]
pub(crate) struct RetainedGeneration {
    installation: String,
    manifest: GenerationManifest,
    bytes: Vec<u8>,
    pin: ContentDigest,
    #[cfg(test)]
    retained: BTreeMap<String, RetainedOutput>,
    outputs: BTreeMap<String, MaterializedArtifact>,
    commands: BTreeMap<String, RuntimeClosure>,
    metadata_interest: ObjectLease,
}
impl RetainedGeneration {
    pub(crate) fn process_retention(&self) -> Result<std::fs::File> {
        let mut leases = vec![&self.metadata_interest];
        leases.extend(
            self.outputs
                .values()
                .map(MaterializedArtifact::object_lease),
        );
        Ok(ObjectLease::combine(&leases)?.process_retention()?)
    }
    pub(super) fn installation_id(&self) -> &str {
        &self.installation
    }
    pub(crate) const fn manifest(&self) -> &GenerationManifest {
        &self.manifest
    }
    pub(crate) const fn digest(&self) -> ContentDigest {
        self.pin
    }
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) const fn outputs(&self) -> &BTreeMap<String, MaterializedArtifact> {
        &self.outputs
    }
    #[cfg(test)]
    pub(crate) const fn retained_outputs(&self) -> &BTreeMap<String, RetainedOutput> {
        &self.retained
    }
    pub(crate) const fn commands(&self) -> &BTreeMap<String, RuntimeClosure> {
        &self.commands
    }
}
fn launcher_digest(manifest: &GenerationManifest) -> Result<ContentDigest> {
    manifest
        .launcher
        .digest
        .parse()
        .map_err(|_| InstallationError::Invalid("invalid launcher digest"))
}
fn output_identity(output: &super::manifest::Output) -> Result<OutputIdentity> {
    let parse = |text: &str| {
        text.parse()
            .map_err(|_| InstallationError::Invalid("invalid output identity"))
    };
    Ok(OutputIdentity {
        action: parse(&output.action)?,
        origin: match &output.origin {
            super::manifest::Origin::Built {
                receipt,
            } => OutputOrigin::Built {
                receipt: parse(receipt)?,
            },
            super::manifest::Origin::Imported {
                manifest,
            } => OutputOrigin::Imported {
                manifest: parse(manifest)?,
            },
        },
        artifact: parse(&output.artifact)?,
        output: output.name.clone(),
    })
}
fn metadata_references(pin: ContentDigest, launcher: ContentDigest) -> Vec<ContentDigest> {
    let mut references = vec![pin, launcher];
    references.sort_unstable();
    references.dedup();
    references
}
fn output_root(id: &str, pin: ContentDigest, output: &str) -> Result<RootName> {
    root(id, pin, &format!("output:{output}"))
}
fn metadata_root(id: &str, pin: ContentDigest) -> Result<RootName> {
    root(id, pin, "metadata")
}
fn root(id: &str, pin: ContentDigest, role: &str) -> Result<RootName> {
    let digest = ContentDigest::sha256(
        format!("syrox-generation-root-v1\n{id}\n{pin}\n{role}\n").as_bytes(),
    );
    RootName::new(format!("os_{id}_{digest}"))
        .map_err(|_| InstallationError::Invalid("invalid generation root"))
}
fn check(cancellation: &Cancellation, deadline: Instant) -> Result<()> {
    cancellation
        .check()
        .map_err(|_| InstallationError::Cancelled)?;
    if Instant::now() >= deadline {
        return Err(InstallationError::Deadline);
    }
    Ok(())
}
fn check_io(cancellation: &Cancellation, deadline: Instant) -> io::Result<()> {
    check(cancellation, deadline).map_err(io::Error::other)
}
struct CheckedReader<'a, R> {
    inner: R,
    cancellation: &'a Cancellation,
    deadline: Instant,
}
impl<R: Read> Read for CheckedReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        check_io(self.cancellation, self.deadline)?;
        self.inner.read(bytes)
    }
}

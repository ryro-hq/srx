//! Preparing a plan consumer's outputs and commands.
//!
//! The result keeps invocations and the views they need. Installing configuration
//! or starting processes are later steps chosen by the Shell or Os path.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use thiserror::Error;

use crate::{
    cancellation::Cancellation, config::UserConfiguration, plan::PlanCommand,
    plan::PlanCommandArgument, plan::PlanCommandEnvironment, plan::PlanCommandRef,
    plan::PlanConsumer, plan::PlanOutputRef, plan::PlanPackageId, plan::PlanServiceCommand,
    project::PreparedPlan, realize::BuildProgress, result::MaterializedArtifact,
    runtime::RuntimeClosure, runtime::RuntimeFile,
};

pub(crate) mod commands;

#[cfg(test)]
pub(crate) mod tests;

#[derive(Debug, Error)]
pub enum DeploymentError {
    #[error("native configuration validator `{command}` rejected service `{service}`")]
    ConfigurationValidation {
        service: String,
        command: String,
    },
    #[error("configuration validation I/O failed: {0}")]
    ValidationIo(#[from] std::io::Error),
    #[error("invalid public command namespace: {0}")]
    CommandNamespace(&'static str),
    #[error("consumer `{0}` is absent or ambiguous in the prepared plan")]
    Consumer(String),
    #[error("command `{name}` conflicts in namespace {service:?}")]
    CommandConflict {
        service: Option<String>,
        name: String,
    },
    #[error(transparent)]
    Realize(#[from] crate::realize::RealizeError),
    #[error(transparent)]
    Command(Box<crate::realize::CommandError>),
    #[error(transparent)]
    Runtime(#[from] crate::runtime::RuntimeError),
    #[error(transparent)]
    Materialization(#[from] crate::result::MaterializationError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
}

impl From<crate::realize::CommandError> for DeploymentError {
    fn from(error: crate::realize::CommandError) -> Self {
        Self::Command(Box::new(error))
    }
}

/// A root command has no service ID; service commands belong to private namespaces.
pub type ConsumerCommandKey = (Option<String>, String);

#[derive(Debug)]
pub struct ConsumerSelection {
    consumer: PlanConsumer,
    outputs: BTreeSet<PlanOutputRef>,
    commands: BTreeMap<ConsumerCommandKey, PlanCommand>,
    configured: BTreeMap<ConsumerCommandKey, PlanServiceCommand>,
    exposures: BTreeMap<String, ConsumerCommandKey>,
}

impl ConsumerSelection {
    pub const fn consumer(&self) -> &PlanConsumer {
        &self.consumer
    }
    pub fn outputs(&self) -> impl Iterator<Item = &PlanOutputRef> {
        self.outputs.iter()
    }
    pub fn exposures(&self) -> &BTreeMap<String, ConsumerCommandKey> {
        &self.exposures
    }
    pub fn commands(&self) -> impl Iterator<Item = (&ConsumerCommandKey, &PlanCommand)> {
        self.commands.iter()
    }
}

/// Resolve every output and public command before any Store or worker effect.
pub fn select_consumer(
    prepared: &PreparedPlan,
    name: &str,
) -> Result<ConsumerSelection, DeploymentError> {
    let mut matching = prepared
        .plan()
        .consumers()
        .filter(|consumer| consumer.name() == name);
    let consumer = matching
        .next()
        .ok_or_else(|| DeploymentError::Consumer(name.into()))?
        .clone();
    if matching.next().is_some() {
        return Err(DeploymentError::Consumer(name.into()));
    }
    let mut outputs = BTreeSet::new();
    let mut commands = BTreeMap::<ConsumerCommandKey, PlanCommand>::new();
    for (service, selections) in std::iter::once((None, consumer.pkgs())).chain(
        consumer
            .services()
            .iter()
            .map(|service| (Some(service.id()), service.pkgs())),
    ) {
        for selection in selections {
            crate::realize::resolve_plan_output(prepared, selection.output())?;
            outputs.insert(selection.output().clone());
            for name in selection.commands() {
                let reference = PlanCommandRef {
                    package: selection.package().clone(),
                    name: name.clone(),
                };
                let resolved = crate::realize::resolve_plan_command(prepared, &reference)?;
                let command = resolved.description();
                let key = (service.map(str::to_owned), name.clone());
                if let Some(previous) = commands.get(&key) {
                    if previous.package() != command.package() {
                        return Err(DeploymentError::CommandConflict {
                            service: key.0,
                            name: key.1,
                        });
                    }
                    continue;
                }
                for output in command
                    .loader()
                    .map(|file| &file.output)
                    .into_iter()
                    .chain(command.libraries())
                {
                    crate::realize::resolve_plan_output(prepared, output)?;
                    outputs.insert(output.clone());
                }
                commands.insert(key, command.clone());
            }
        }
    }
    let exposures = commands
        .keys()
        .filter(|key| key.0.is_none())
        .map(|key| (key.1.clone(), key.clone()))
        .collect();
    let mut selection = ConsumerSelection {
        consumer,
        outputs,
        commands,
        configured: BTreeMap::new(),
        exposures,
    };
    add_configured(prepared, &mut selection)?;
    if selection.consumer.kind() == PlanConsumerKind::Shell {
        commands::PreparedCommandIndex::new(&selection.exposures)?;
    }
    Ok(selection)
}

fn add_configured(
    prepared: &PreparedPlan,
    selection: &mut ConsumerSelection,
) -> Result<(), DeploymentError> {
    for service in selection.consumer.services() {
        for invocation in service.commands() {
            let key = (
                Some(service.id().to_owned()),
                invocation.name().to_owned(),
            );
            let resolved = crate::realize::resolve_plan_command(prepared, invocation.command())?;
            let command = resolved.description();
            let application = PlanOutputRef {
                package: command.package().clone(),
                output: command.output().into(),
            };
            for output in std::iter::once(&application)
                .chain(command.loader().map(|file| &file.output))
                .chain(command.libraries())
            {
                crate::realize::resolve_plan_output(prepared, output)?;
                selection.outputs.insert(output.clone());
            }
            if selection
                .commands
                .insert(key.clone(), command.clone())
                .is_some()
            {
                return Err(DeploymentError::CommandConflict {
                    service: key.0,
                    name: key.1,
                });
            }
            if let Some(expose) = invocation.expose()
                && selection
                    .exposures
                    .insert(expose.into(), key.clone())
                    .is_some()
            {
                return Err(DeploymentError::CommandConflict {
                    service: None,
                    name: expose.into(),
                });
            }
            selection
                .configured
                .insert(key, invocation.clone());
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct PreparedInvocation {
    closure: RuntimeClosure,
    arguments: Vec<PlanCommandArgument>,
    environment: Vec<PlanCommandEnvironment>,
}
impl PreparedInvocation {
    pub const fn closure(&self) -> &RuntimeClosure {
        &self.closure
    }
    pub fn arguments(&self) -> &[PlanCommandArgument] {
        &self.arguments
    }
    pub fn environment(&self) -> &[PlanCommandEnvironment] {
        &self.environment
    }
}

/// Live preparation owns source snapshots and verified leases for all selected outputs.
/// Configuration remains descriptive content in `consumer().services()`.
#[derive(Debug)]
pub struct PreparedConsumer {
    /// Source snapshots remain live until the entire consumer preparation drops.
    _prepared: PreparedPlan,
    selection: ConsumerSelection,
    outputs: BTreeMap<PlanOutputRef, MaterializedArtifact>,
    commands: BTreeMap<ConsumerCommandKey, PreparedInvocation>,
}

impl PreparedConsumer {
    pub const fn consumer(&self) -> &PlanConsumer {
        &self.selection.consumer
    }
    pub fn outputs(&self) -> &BTreeMap<PlanOutputRef, MaterializedArtifact> {
        &self.outputs
    }
    pub fn exposures(&self) -> &BTreeMap<String, ConsumerCommandKey> {
        &self.selection.exposures
    }
    pub fn invocations(&self) -> &BTreeMap<ConsumerCommandKey, PreparedInvocation> {
        &self.commands
    }
}

pub fn prepare_consumer(
    prepared: PreparedPlan,
    name: &str,
    user: &UserConfiguration,
    worker: &Path,
    offline: bool,
    cancellation: &Cancellation,
    mut progress: impl FnMut(&PlanPackageId, BuildProgress),
) -> Result<PreparedConsumer, DeploymentError> {
    let selection = select_consumer(&prepared, name)?;
    cancellation
        .check()
        .map_err(crate::realize::RealizeError::from)?;
    // Empty/configuration-only consumers require no Store, toolchain or worker.
    if selection.outputs.is_empty() {
        return finish(prepared, selection, BTreeMap::new(), cancellation);
    }
    let context = crate::realize::RealizeContext::new(crate::realize::RealizeOptions {
        configuration: user,
        worker,
        offline,
    });
    let store = context.store()?;
    let mut results = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    for reference in &selection.outputs {
        if let std::collections::btree_map::Entry::Vacant(entry) =
            results.entry(reference.package.clone())
        {
            let resolved = crate::realize::resolve_plan_output(&prepared, reference)?;
            entry.insert(crate::realize::outputs::realize_package(
                &resolved,
                &context,
                cancellation,
                |stage| progress(&reference.package, stage),
            )?);
        }
        let (view, _) =
            results[&reference.package].materialize(store, &reference.output, cancellation)?;
        outputs.insert(reference.clone(), view);
    }
    finish(prepared, selection, outputs, cancellation)
}

fn finish(
    prepared: PreparedPlan,
    selection: ConsumerSelection,
    outputs: BTreeMap<PlanOutputRef, MaterializedArtifact>,
    cancellation: &Cancellation,
) -> Result<PreparedConsumer, DeploymentError> {
    let mut commands = BTreeMap::new();
    for (key, command) in &selection.commands {
        let application = PlanOutputRef {
            package: command.package().clone(),
            output: command.output().into(),
        };
        let closure = crate::runtime::verify_materialized_runtime(
            RuntimeFile {
                output: outputs[&application].share(),
                path: command.path().into(),
            },
            command.loader().map(|file| RuntimeFile {
                output: outputs[&file.output].share(),
                path: file.path.clone(),
            }),
            command
                .libraries()
                .map(|output| outputs[output].share())
                .collect(),
            cancellation,
        )?;
        let configured = selection.configured.get(key);
        commands.insert(
            key.clone(),
            PreparedInvocation {
                closure,
                arguments: configured.map_or_else(Vec::new, |value| value.arguments().to_vec()),
                environment: configured.map_or_else(Vec::new, |value| value.environment().to_vec()),
            },
        );
    }
    let consumer = PreparedConsumer {
        _prepared: prepared,
        selection,
        outputs,
        commands,
    };
    validation::validate(&consumer, cancellation)?;
    Ok(consumer)
}

use crate::{plan::PlanConsumerKind, store::ContentDigest};
pub(crate) mod encoding;
mod validate_manifest;
mod validation;
use encoding::{Argument, Config, Invocation, Output, Provenance, Role, Selection};
pub(crate) use encoding::{GenerationManifest, LauncherIdentity};

#[derive(Debug, Error)]
pub(crate) enum GenerationError {
    #[error("generation preparation requires an Os consumer")]
    NotOs,
    #[error("session snapshot requires a Shell consumer")]
    NotShell,
    #[error("invalid generation: {0}")]
    Invalid(&'static str),
    #[error("generation encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
}
type ManifestResult<T> = Result<T, GenerationError>;

#[derive(Debug)]
pub(crate) struct PreparedGeneration {
    consumer: PreparedConsumer,
    #[cfg(test)]
    manifest: GenerationManifest,
    bytes: Vec<u8>,
    digest: ContentDigest,
}
impl PreparedGeneration {
    /// Freeze verified outputs while preserving every preparation lease. This
    /// does not publish durable roots or select a generation for execution.
    pub(crate) fn freeze(
        consumer: PreparedConsumer,
        launcher: LauncherIdentity,
    ) -> ManifestResult<Self> {
        if consumer.consumer().kind() != PlanConsumerKind::Os {
            return Err(GenerationError::NotOs);
        }
        let manifest = operational_manifest(&consumer, launcher)?;
        let bytes = manifest.canonical_bytes()?;
        let digest = ContentDigest::sha256(&bytes);
        Ok(Self {
            consumer,
            #[cfg(test)]
            manifest,
            bytes,
            digest,
        })
    }
    #[cfg(test)]
    pub(crate) const fn manifest(&self) -> &GenerationManifest {
        &self.manifest
    }
    pub(crate) const fn digest(&self) -> ContentDigest {
        self.digest
    }
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) const fn consumer(&self) -> &PreparedConsumer {
        &self.consumer
    }
}
/// Serialize a Shell's verified preparation without moving its leases. The
/// snapshot carries no manager authority or physical configuration paths.
pub(crate) fn shell_snapshot(
    consumer: &PreparedConsumer,
    launcher: LauncherIdentity,
) -> ManifestResult<(Vec<u8>, ContentDigest)> {
    if consumer.consumer().kind() != PlanConsumerKind::Shell {
        return Err(GenerationError::NotShell);
    }
    let manifest = encoding::ShellSessionManifest::new(operational_manifest(consumer, launcher)?);
    let bytes = manifest.canonical_bytes()?;
    let digest = ContentDigest::sha256(&bytes);
    Ok((bytes, digest))
}

fn operational_manifest(
    consumer: &PreparedConsumer,
    launcher: LauncherIdentity,
) -> ManifestResult<GenerationManifest> {
    let mut manifest = GenerationManifest::empty(launcher);
    let mut outputs = BTreeMap::new();
    for (reference, view) in consumer.outputs() {
        let output = Output::from_identity(view.identity());
        let key = output.key()?;
        manifest.outputs.insert(key.clone(), output);
        manifest
            .provenance
            .entry(key.clone())
            .or_default()
            .insert(Provenance {
                label: reference.package.as_str().into(),
                path: reference.package.path().to_vec(),
            });
        outputs.insert(reference.clone(), key);
    }
    for (service, selections) in std::iter::once((None, consumer.consumer().pkgs())).chain(
        consumer
            .consumer()
            .services()
            .iter()
            .map(|service| (Some(service.id().to_owned()), service.pkgs())),
    ) {
        for selection in selections {
            manifest.selections.insert(Selection {
                service: service.clone(),
                output: outputs[selection.output()].clone(),
            });
        }
    }
    record_services(&mut manifest, consumer.consumer().services());
    for (key, invocation) in consumer.invocations() {
        let closure = invocation.closure();
        manifest.commands.insert(
            encoding::command_key(key.0.as_deref(), &key.1),
            Invocation {
                service: key.0.clone(),
                name: key.1.clone(),
                application: role(
                    &closure.application().output,
                    &closure.application().path,
                )?,
                loader: closure
                    .loader()
                    .map(|file| role(&file.output, &file.path))
                    .transpose()?,
                libraries: closure
                    .libraries()
                    .iter()
                    .map(|view| Output::from_identity(view.identity()).key())
                    .collect::<ManifestResult<BTreeSet<_>>>()?,
                arguments: invocation
                    .arguments()
                    .iter()
                    .map(argument)
                    .collect(),
                environment: invocation
                    .environment()
                    .iter()
                    .map(|entry| (entry.name.clone(), argument(&entry.value)))
                    .collect(),
            },
        );
    }
    manifest.exposures = consumer
        .exposures()
        .iter()
        .map(|(name, key)| {
            (
                name.clone(),
                encoding::command_key(key.0.as_deref(), &key.1),
            )
        })
        .collect();
    validate_manifest::manifest(&manifest)?;
    Ok(manifest)
}

fn record_services(manifest: &mut GenerationManifest, services: &[crate::plan::PlanService]) {
    for service in services {
        for validator in service.validators() {
            manifest.validators.insert(encoding::command_key(
                Some(service.id()),
                validator,
            ));
        }
        manifest.services.insert(service.id().into());
        if !service.secrets().is_empty() {
            manifest.secrets.insert(
                service.id().into(),
                service.secrets().iter().cloned().collect(),
            );
        }
        if service.state() == crate::plan::PlanServiceState::Session {
            manifest
                .session_states
                .insert(service.id().into());
        }
        for file in service.files() {
            manifest.configs.insert(
                format!("{}/{}", service.id(), file.path()),
                Config {
                    service: service.id().into(),
                    path: file.path().into(),
                    text: file.text().into(),
                    digest: ContentDigest::sha256(file.text().as_bytes()).to_string(),
                    mode: 0o400,
                },
            );
        }
        for process in service.processes() {
            manifest.processes.insert(
                format!("{}/{}", service.id(), process.id),
                encoding::Process {
                    command: encoding::command_key(Some(service.id()), &process.command),
                    restart: process.restart(),
                },
            );
        }
    }
}

fn role(output: &MaterializedArtifact, path: &str) -> ManifestResult<Role> {
    Ok(Role {
        output: Output::from_identity(output.identity()).key()?,
        path: path.into(),
    })
}
fn argument(value: &PlanCommandArgument) -> Argument {
    match value {
        PlanCommandArgument::StateDirectory => Argument::StateDirectory,
        PlanCommandArgument::SecretFile(name) => Argument::SecretFile(name.clone()),
        PlanCommandArgument::Literal(value) => Argument::Literal(value.clone()),
        PlanCommandArgument::File(path) => Argument::File(path.clone()),
    }
}

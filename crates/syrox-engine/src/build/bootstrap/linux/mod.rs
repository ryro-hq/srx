use crate::build::cancellation::BuildControl;
use crate::build::materialization_error;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::time::Duration;

use sha2::{Digest as _, Sha256};

mod inventory;
use super::{
    BuildError, BuildResult, BuildSpecification, Cancellation, cache, group,
    journal::Operation,
    records::{Action, BuildDescription},
    sandbox, shared,
};
#[cfg(test)]
use crate::build::{BuildExecution, records::Receipt};
use crate::{plan::Plan, store::ContentDigest, store::RootName, store::Store};
use inventory::toolchain_inventory;

const MAX_TOOLCHAIN_FILES: usize = 262_144;
const MAX_TOOLCHAIN_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_INVENTORY_BYTES: usize = 32 * 1024 * 1024;
const INVENTORY_BATCH: usize = 1024;
const INVENTORY_WORKERS: usize = 1;
const INVENTORY_TASKS_PER_WORKER: usize = 8;

static INVENTORY_CAPACITY: OnceLock<(Mutex<usize>, Condvar)> = OnceLock::new();

struct InventoryPermits {
    capacity: &'static (Mutex<usize>, Condvar),
    count: usize,
}

impl InventoryPermits {
    fn acquire(requested: usize, cancellation: &dyn BuildControl) -> Result<Self, BuildError> {
        let capacity =
            INVENTORY_CAPACITY.get_or_init(|| (Mutex::new(INVENTORY_WORKERS), Condvar::new()));
        let mut available = capacity
            .0
            .lock()
            .expect("inventory capacity poisoned");
        while *available == 0 {
            cancellation.check()?;
            available = capacity
                .1
                .wait_timeout(available, Duration::from_millis(50))
                .expect("inventory capacity poisoned")
                .0;
        }
        cancellation.check()?;
        let count = (*available).min(requested);
        *available -= count;
        Ok(Self {
            capacity,
            count,
        })
    }
}

impl Drop for InventoryPermits {
    fn drop(&mut self) {
        let mut available = self
            .capacity
            .0
            .lock()
            .expect("inventory capacity poisoned");
        *available += self.count;
        self.capacity.1.notify_all();
    }
}

pub(crate) fn retained_build_with_inputs(
    plan: &Plan,
    build: &crate::plan::PlanBuild,
    provider: &crate::plan::PlanPackageId,
    store: &Store,
    toolchain: &Path,
    worker: &Path,
    cancellation: &dyn BuildControl,
) -> Result<Option<(BuildResult, ContentDigest)>, BuildError> {
    if build.program().profile == super::BuildProfile::Managed {
        return Err(BuildError::UnsupportedProfile);
    }
    let mut phases = super::profile::PhaseProfiler::new();
    let application = BuildDescription::from_plan(plan, build.package())?;
    let provider_description = BuildDescription::from_plan(plan, provider)?;
    let provider_build = plan
        .builds()
        .find(|candidate| candidate.package() == provider)
        .ok_or(BuildError::UnsupportedInputs)?;
    if !provider_build.inputs().is_empty()
        || build
            .inputs()
            .iter()
            .any(|input| &input.package != provider)
    {
        return Ok(None);
    }
    let lease = store.operation()?;
    if !cache::has_retained_build_with_inputs(&lease, &application, cancellation)? {
        phases.mark("application-retention-miss");
        return Ok(None);
    }
    phases.mark("application-retention-scan");
    let (inventory, _) = toolchain_inventory(toolchain, cancellation)?;
    phases.mark("application-toolchain-inventory");
    let worker = read_worker(worker, cancellation)?;
    phases.mark("application-worker-identity");
    let query = cache::RetainedQuery {
        application,
        provider: provider_description,
        worker: ContentDigest::sha256(&worker),
        toolchain: Some(ContentDigest::sha256(&inventory)),
        input_outputs: build
            .inputs()
            .iter()
            .map(|input| input.output.as_str())
            .collect(),
    };
    let result = cache::retained_build_with_inputs(&lease, &query, cancellation);
    phases.mark("application-lookup");
    result
}

/// Owned identity survives source acquisition; the worker bytes and toolchain
/// inventory used to compute this Action are the same inputs used on a miss.
pub(crate) struct PreparedBuild {
    description: Action,
    timeout_seconds: u32,
    origin: String,
    inventory: Vec<u8>,
    blocked: Vec<PathBuf>,
    worker_bytes: Vec<u8>,
    inputs: Vec<(super::BuildInput, String)>,
    retained_inputs: Vec<ContentDigest>,
    source: ContentDigest,
    maximum_source: u64,
}

impl PreparedBuild {
    /// An HTTPS/local acquisition can outlive a mutation of the host `/usr`.
    /// Do not accept a result for the old Action or launch with stale mounts.
    pub(crate) fn revalidate_after_acquisition(
        &self,
        toolchain: &Path,
        cancellation: &dyn BuildControl,
    ) -> Result<(), BuildError> {
        let (inventory, blocked) = toolchain_inventory(toolchain, cancellation)?;
        if inventory != self.inventory || blocked != self.blocked {
            return Err(BuildError::InputChanged);
        }
        Ok(())
    }
}

pub(crate) enum PreparedLookup {
    Hit(Box<BuildResult>),
    Miss(Box<PreparedBuild>),
}

/// Pure with respect to source acquisition: validate the Plan and current
/// build identities, then ask the admitted action index before reading source
/// bytes. A miss retains the exact inputs for the subsequent producer.
pub(crate) fn prepare_managed(
    plan: &Plan,
    request: &BuildSpecification,
    store: &Store,
    toolchain: &Path,
    worker: &Path,
    cancellation: &dyn BuildControl,
) -> Result<PreparedLookup, BuildError> {
    request.validate()?;
    prepare_action(
        plan,
        request,
        store,
        None,
        toolchain,
        worker,
        cancellation,
    )
}

pub(in crate::build) fn build(
    plan: &Plan,
    request: &BuildSpecification,
    store: &Store,
    root: Option<&RootName>,
    toolchain: &Path,
    worker: &Path,
    cancellation: &Cancellation,
) -> Result<BuildResult, BuildError> {
    match prepare_action(
        plan,
        request,
        store,
        root,
        toolchain,
        worker,
        cancellation,
    )? {
        PreparedLookup::Hit(result) => Ok(*result),
        PreparedLookup::Miss(prepared) => {
            build_prepared_with_root(*prepared, store, root, toolchain, cancellation)
        }
    }
}

fn prepare_action(
    plan: &Plan,
    request: &BuildSpecification,
    store: &Store,
    root: Option<&RootName>,
    toolchain: &Path,
    worker: &Path,
    cancellation: &dyn BuildControl,
) -> Result<PreparedLookup, BuildError> {
    let mut phases = super::profile::PhaseProfiler::new();
    cancellation.check()?;
    if request.program.profile == super::BuildProfile::Managed {
        return Err(BuildError::UnsupportedProfile);
    }
    if (toolchain != Path::new("/usr") && !cfg!(test)) || cfg!(not(target_arch = "x86_64")) {
        return Err(BuildError::Toolchain);
    }
    let declared = plan
        .builds()
        .find(|build| build.package() == &request.package)
        .ok_or(BuildError::UnsupportedInputs)?;
    if declared.source_directory() != request.source_directory
        || declared.timeout_seconds() != request.timeout_seconds
        || declared.program() != &request.program
        || declared.inputs().len() != request.inputs.len()
    {
        return Err(BuildError::UnsupportedInputs);
    }
    let acquisition = plan
        .acquisitions()
        .find(|a| a.package() == &request.package)
        .ok_or(BuildError::UnsupportedInputs)?;
    if acquisition.sources().len() != 1 {
        return Err(BuildError::UnsupportedInputs);
    }
    let source = acquisition.sources().next().unwrap();
    let source_digest = source.digest();
    let lease = store.operation()?;
    let maximum_source = request.program.maximum_source_bytes();
    // The Action is determined by the locked source digest, not by opening
    // source bytes. A retained hit validates the source through its receipt;
    // only a miss has to read the source for inspection and the payload.
    let (inventory, blocked) = toolchain_inventory(toolchain, cancellation)?;
    phases.mark("toolchain-inventory");
    let toolchain_digest = ContentDigest::sha256(&inventory);
    let worker_bytes = read_worker(worker, cancellation)?;
    let worker_digest = ContentDigest::sha256(&worker_bytes);
    phases.mark("worker-identity");
    let mut visited = 0;
    let mut retained_inputs = Vec::new();
    let mut description = Action::new(
        request,
        source_digest,
        Some(toolchain_digest),
        worker_digest,
    );
    let mut inputs = Vec::new();
    for (binding, selected) in request.inputs.iter().zip(declared.inputs()) {
        cancellation.check()?;
        let input = binding
            .output
            .open_for_build(store, cancellation)
            .map_err(|error| materialization_error(&error))?;
        verify_selected_output(
            plan,
            selected,
            input.identity(),
            &lease,
            cancellation,
            &mut visited,
        )?;
        description
            .inputs
            .push(super::records::InputIdentity::from(
                input.identity(),
            ));
        retained_inputs.extend_from_slice(input.retained_references());
        retained_inputs.sort_unstable();
        retained_inputs.dedup();
        if retained_inputs.len() > 4096 {
            return Err(BuildError::UnsupportedInputs);
        }
        inputs.push((binding.clone(), selected.output.clone()));
    }
    let hit = cache::lookup(&lease, &description, root, cancellation)?;
    phases.mark("action-lookup");
    if let Some(result) = hit {
        return Ok(PreparedLookup::Hit(Box::new(result)));
    }
    Ok(PreparedLookup::Miss(Box::new(PreparedBuild {
        description,
        timeout_seconds: request.timeout_seconds,
        origin: format!(
            "syrox-build-origin\nlock {}\npackage {}\ndomain {}\npath {:?}\n",
            ContentDigest::from_sha256_hash(*plan.lock_digest()),
            request.package,
            request.package.domain(),
            request.package.path()
        ),
        inventory,
        blocked,
        worker_bytes,
        inputs,
        retained_inputs,
        source: source_digest,
        maximum_source: source.maximum_bytes().min(maximum_source),
    })))
}

pub(crate) fn build_prepared(
    prepared: PreparedBuild,
    store: &Store,
    toolchain: &Path,
    cancellation: &Cancellation,
) -> Result<BuildResult, BuildError> {
    build_prepared_with_root(prepared, store, None, toolchain, cancellation)
}

fn build_prepared_with_root(
    prepared: PreparedBuild,
    store: &Store,
    root: Option<&RootName>,
    toolchain: &Path,
    cancellation: &Cancellation,
) -> Result<BuildResult, BuildError> {
    let PreparedBuild {
        description,
        timeout_seconds,
        origin,
        inventory,
        blocked,
        worker_bytes,
        inputs,
        retained_inputs,
        source,
        maximum_source,
    } = prepared;
    let mut phases = super::profile::PhaseProfiler::new();
    cancellation.check()?;
    let lease = store.operation()?;
    // A concurrent caller may have published this Action while the source was
    // acquired. Check the index again before any source read or build preflight.
    if let Some(result) = cache::lookup(&lease, &description, root, cancellation)? {
        phases.mark("post-acquisition-lookup-hit");
        return Ok(result);
    }
    phases.mark("post-acquisition-lookup-miss");
    let source_bytes = lease
        .read_verified(source, maximum_source)?
        .ok_or(BuildError::MissingSource)?;
    phases.mark("source-open");
    // A retained, fully verified result already attests to source inspection.
    // Only a miss needs to expand the pinned archive again.
    if description.program.source_format == super::BuildSourceFormat::Xz {
        crate::acquire::archive::inspect_archive_with_cancellation(
            store,
            source,
            crate::acquire::archive::ArchiveFormat::XzTar,
            crate::acquire::archive::ArchiveLimits::large_xz(),
            cancellation,
        )
        .map_err(|error| match error {
            crate::acquire::archive::ArchiveError::Cancelled => BuildError::Cancelled,
            error => BuildError::Archive(error),
        })?;
    } else if description.program.source_format == super::BuildSourceFormat::Gzip {
        crate::acquire::archive::inspect_gzip_tar_with_cancellation(
            source_bytes.as_bytes(),
            cancellation,
        )
        .map_err(|error| match error {
            crate::acquire::archive::ArchiveError::Cancelled => BuildError::Cancelled,
            error => BuildError::Archive(error),
        })?;
    }
    phases.mark("source-inspection");
    let result = shared::realize(
        &lease,
        &description,
        timeout_seconds,
        root,
        cancellation,
        |operation, cancellation| {
            let execution = (|| {
                super::check_build_host(toolchain)?;
                cancellation.check()?;
                let mut views = Vec::new();
                for ((input, output), identity) in inputs.iter().zip(&description.inputs) {
                    let view = input
                        .output
                        .open_for_build(store, cancellation)
                        .map_err(|error| materialization_error(&error))?;
                    if &view.identity().output != output
                        || super::records::InputIdentity::from(view.identity()) != *identity
                    {
                        return Err(BuildError::UnsupportedInputs);
                    }
                    views.push(view);
                }
                prepare(
                    operation,
                    &worker_bytes,
                    source_bytes.as_bytes(),
                    cancellation,
                )?;
                operation.record_origin(&origin)?;
                operation.authorize_program(&description, timeout_seconds)?;
                sandbox::execute(
                    operation,
                    &description,
                    timeout_seconds,
                    &blocked,
                    cancellation,
                )
            })();
            let mut output = finish_stage(operation, execution)?;
            cancellation.check()?;
            let (after_inventory, after_blocked) = toolchain_inventory(toolchain, cancellation)?;
            if after_inventory != inventory || after_blocked != blocked {
                return Err(BuildError::InputChanged);
            }
            super::publication::publish_outputs(
                &lease,
                &operation.name,
                &description,
                Some(&inventory),
                &mut output.file,
                &retained_inputs,
                cancellation,
            )
        },
    );
    phases.mark("build-and-publication");
    result
}

fn prepare(
    operation: &Operation,
    worker: &[u8],
    source: &[u8],
    cancellation: &dyn BuildControl,
) -> Result<(), BuildError> {
    cancellation.check()?;
    operation.write_stage("source", source, false)?;
    cancellation.check()?;
    operation.write_stage("worker", worker, true)
}

pub(in crate::build) fn verify_selected_input(
    plan: &Plan,
    package: &crate::plan::PlanPackageId,
    action: &Action,
    lease: &crate::store::OperationLease,
    cancellation: &dyn BuildControl,
    visited: &mut usize,
) -> Result<(), BuildError> {
    cancellation.check()?;
    *visited += 1;
    if *visited > 4096 {
        return Err(BuildError::UnsupportedInputs);
    }
    let build = plan
        .builds()
        .find(|build| build.package() == package)
        .ok_or(BuildError::UnsupportedInputs)?;
    let description = BuildDescription::from_plan(plan, package)?;
    if !description.matches(action) || build.inputs().len() != action.inputs.len() {
        return Err(BuildError::UnsupportedInputs);
    }
    for (selected, input) in build.inputs().iter().zip(&action.inputs) {
        if selected.output != input.output {
            return Err(BuildError::UnsupportedInputs);
        }
        let identity = crate::result::OutputIdentity {
            origin: input.origin.clone(),
            action: input.action,
            artifact: input.artifact,
            output: input.output.clone(),
        };
        verify_selected_output(
            plan,
            selected,
            &identity,
            lease,
            cancellation,
            visited,
        )?;
    }
    Ok(())
}

pub(in crate::build) fn verify_selected_output(
    plan: &Plan,
    selected: &crate::plan::PlanOutputRef,
    identity: &crate::result::OutputIdentity,
    lease: &crate::store::OperationLease,
    cancellation: &dyn BuildControl,
    visited: &mut usize,
) -> Result<(), BuildError> {
    cancellation.check()?;
    if selected.output != identity.output {
        return Err(BuildError::UnsupportedInputs);
    }
    match identity.origin {
        crate::result::OutputOrigin::Built {
            receipt,
        } => {
            if plan
                .imports()
                .any(|import| import.package() == &selected.package)
            {
                return Err(BuildError::UnsupportedInputs);
            }
            let (action, receipt) = cache::read_result(lease, receipt, cancellation)?;
            if receipt.action != identity.action
                || receipt
                    .output(&identity.output)
                    .is_none_or(|output| output.artifact != identity.artifact)
            {
                return Err(BuildError::UnsupportedInputs);
            }
            receipt.verify_retained_inputs(lease, &action, || cancellation.check())?;
            verify_selected_input(
                plan,
                &selected.package,
                &action,
                lease,
                cancellation,
                visited,
            )
        }
        crate::result::OutputOrigin::Imported {
            manifest,
        } => {
            let declared = plan
                .imports()
                .find(|import| import.package() == &selected.package)
                .filter(|import| import.manifest() == manifest)
                .ok_or(BuildError::UnsupportedInputs)?;
            let key = declared
                .outputs()
                .get(&selected.output)
                .ok_or(BuildError::UnsupportedInputs)?;
            let bytes = lease
                .read_verified(manifest, crate::result::MAX_RESULT_MANIFEST_BYTES)?
                .ok_or(BuildError::UnsupportedInputs)?;
            let manifest = crate::result::ResultManifest::parse(bytes.as_bytes())
                .map_err(|error| BuildError::Cache(error.to_string()))?;
            let output = manifest
                .outputs()
                .get(key)
                .ok_or(BuildError::UnsupportedInputs)?;
            if output.action != identity.action
                || output.artifact != identity.artifact
                || output.output != identity.output
            {
                return Err(BuildError::UnsupportedInputs);
            }
            Ok(())
        }
    }
}

fn read_worker(worker: &Path, cancellation: &dyn BuildControl) -> Result<Vec<u8>, BuildError> {
    // Capture exactly the trusted bytes whose digest participates in the action;
    // a miss stages these same owned bytes, not a later path reopen.
    cancellation.check()?;
    let mut bytes = Vec::new();
    fs::File::open(worker)?
        .take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 128 * 1024 * 1024 {
        return Err(BuildError::InvalidRequest);
    }
    cancellation.check()?;
    Ok(bytes)
}

fn finish_stage<T>(operation: &Operation, outcome: Result<T, BuildError>) -> Result<T, BuildError> {
    if let Err(BuildError::Settlement {
        reason,
        primary,
        ..
    }) = outcome
    {
        return Err(BuildError::Settlement {
            stage: operation.stage_path(),
            reason,
            primary,
        });
    }
    // No processes can retain staging at this point. Even failures must perform
    // explicit cleanup; never turn a cleanup error into a successful build.
    if let Err(cleanup) = operation.clean_stage() {
        let cleanup = std::io::Error::other(format!("{}: {cleanup}", operation.path.display()));
        return Err(match outcome {
            Err(primary) => BuildError::FailureAndCleanup {
                primary: Box::new(primary),
                cleanup,
            },
            Ok(_) => BuildError::Cleanup(cleanup),
        });
    }
    outcome
}

pub(in crate::build) fn publish_result(
    lease: &crate::store::OperationLease,
    root: &RootName,
    references: &[ContentDigest],
    objects: &[(&[u8], ContentDigest)],
    artifacts: Vec<group::GroupOutput>,
    cancellation: &dyn BuildControl,
) -> Result<(), BuildError> {
    // Store objects may be orphaned on an intermediate publication failure;
    // only the final durable root denotes a complete retained result.
    for (bytes, digest) in objects {
        cancellation.check()?;
        lease.ingest(*bytes, *digest, bytes.len() as u64)?;
    }
    for output in artifacts {
        cancellation.check()?;
        output.admission.finish()?;
    }
    cancellation.check_publication()?;
    // Commit boundary: report the Store's actual publication outcome even if a
    // cancellation arrives while the durable root publication is in progress.
    lease.publish_root(root, references)?;
    Ok(())
}

/// Host-admin controlled /usr is observed before and after execution. This is
/// not an immutable snapshot or a bit-for-bit reproducibility claim. Every file,
/// link target and mode is recorded, not only the top-level compiler binary.
#[cfg(test)]
#[path = "selected_input_tests.rs"]
mod selected_input_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::artifact;

    #[test]
    fn prepared_action_hits_before_source_acquisition_and_detects_toolchain_changes() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let toolchain = dir.path().join("toolchain");
        let project = dir.path().join("project");
        fs::create_dir(&toolchain).unwrap();
        fs::create_dir(&project).unwrap();
        fs::write(toolchain.join("compiler"), b"one").unwrap();
        let worker = dir.path().join("worker");
        fs::write(&worker, b"worker bytes").unwrap();
        let source = b"retained bytes need not be an archive on a hit";
        let digest = ContentDigest::sha256(source);
        fs::write(project.join("main.srx"), format!(r#"mod factories::hello {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "hello"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{ sources = [std::SourceRequest {{ url = "https://example.invalid/archive"; sha256 = "{digest}"; maximum_bytes = 1024; }}]; }});
            build = std::Option::Some(std::autotools(std::BuildOptions {{ source_directory = "hello-1"; timeout_seconds = 120; }})); }} }} }}
            mod factories::other {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "hello"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{ sources = [std::SourceRequest {{ url = "https://example.invalid/other"; sha256 = "{digest}"; maximum_bytes = 1024; }}]; }});
            build = std::Option::Some(std::autotools(std::BuildOptions {{ source_directory = "other-1"; timeout_seconds = 120; }})); }} }} }}
        pub publish(factories, recipe): std::Recipe;"#)).unwrap();
        let checks = crate::project::CheckConfiguration {
            standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
            ..crate::project::CheckConfiguration::default()
        };
        crate::project::lock_project_with(&project, &checks).unwrap();
        let locked = crate::project::open_locked_project_with(&project, &checks).unwrap();
        let mut evaluation = locked.evaluation().unwrap();
        evaluation.select_package("hello").unwrap();
        evaluation.select_package("other").unwrap();
        let plan = evaluation.into_selected_plan().unwrap();
        let request = plan
            .builds()
            .find(|build| build.source_directory() == "hello-1")
            .unwrap()
            .request();
        let other = plan
            .builds()
            .find(|build| build.source_directory() == "other-1")
            .unwrap()
            .request();
        assert_eq!(request.package.as_str(), other.package.as_str());
        assert_ne!(request.package, other.package);
        let store = Store::initialize(&dir.path().join("store")).unwrap();
        let lease = store.operation().unwrap();
        let cancellation = Cancellation::default();
        let (inventory, _) = toolchain_inventory(&toolchain, &cancellation).unwrap();
        let action = Action::new(
            &request,
            digest,
            Some(ContentDigest::sha256(&inventory)),
            ContentDigest::sha256(b"worker bytes"),
        );
        let output = dir.path().join("output");
        fs::create_dir_all(output.join("usr/bin")).unwrap();
        let entry = output.join("usr/bin/hello");
        fs::write(&entry, b"executable").unwrap();
        fs::set_permissions(entry, fs::Permissions::from_mode(0o755)).unwrap();
        let mut artifact = Vec::new();
        artifact::pack(&output, &mut artifact).unwrap();
        let receipt = Receipt::new(&action, ContentDigest::sha256(&artifact), 1);
        for bytes in [
            &source[..],
            &inventory,
            &action.encode(),
            &artifact,
            &receipt.encode(),
        ] {
            lease
                .ingest(
                    bytes,
                    ContentDigest::sha256(bytes),
                    bytes.len() as u64,
                )
                .unwrap();
        }
        let root = receipt.root();
        lease
            .publish_root(&root, &receipt.references())
            .unwrap();
        cache::record(
            &lease,
            &action,
            &BuildResult {
                retention: lease
                    .retain_objects(&receipt.references(), &[])
                    .unwrap(),
                execution: BuildExecution::Cached,
                action: action.digest(),
                artifact: ContentDigest::sha256(&artifact),
                receipt: receipt.digest(),
                toolchain: action.toolchain,
                files: 1,
                root,
            },
        )
        .unwrap();
        assert!(
            matches!(prepare_managed(&plan, &request, &store, &toolchain, &worker, &cancellation).unwrap(),
            PreparedLookup::Hit(result) if result.receipt == receipt.digest())
        );
        let PreparedLookup::Miss(other_action) = prepare_managed(
            &plan,
            &other,
            &store,
            &toolchain,
            &worker,
            &cancellation,
        )
        .unwrap() else {
            panic!("homonymous build must not reuse a different Action");
        };
        assert_eq!(other_action.description.directory, "other-1");
        assert_ne!(other_action.description.digest(), action.digest());
        let mut mismatched = other;
        mismatched.package = request.package.clone();
        assert!(matches!(
            prepare_managed(
                &plan,
                &mismatched,
                &store,
                &toolchain,
                &worker,
                &cancellation
            ),
            Err(BuildError::UnsupportedInputs)
        ));
        fs::write(toolchain.join("compiler"), b"two").unwrap();
        let PreparedLookup::Miss(prepared) = prepare_managed(
            &plan,
            &request,
            &store,
            &toolchain,
            &worker,
            &cancellation,
        )
        .unwrap() else {
            panic!("changed toolchain must miss");
        };
        fs::write(toolchain.join("compiler"), b"three").unwrap();
        assert!(matches!(
            prepared.revalidate_after_acquisition(&toolchain, &cancellation),
            Err(BuildError::InputChanged)
        ));
    }

    #[test]
    fn single_worker_inventory_keeps_canonical_order_across_batches() {
        let root = tempfile::tempdir().unwrap();
        for index in 0..=INVENTORY_BATCH {
            fs::write(
                root.path().join(format!("file-{index:04}")),
                index.to_le_bytes(),
            )
            .unwrap();
        }
        std::os::unix::fs::symlink("file-0000", root.path().join("alias")).unwrap();
        let mut expected = b"syrox-host-toolchain\n".to_vec();
        for name in std::iter::once("alias".to_owned())
            .chain((0..=INVENTORY_BATCH).map(|index| format!("file-{index:04}")))
        {
            let path = root.path().join(&name);
            let metadata = fs::symlink_metadata(&path).unwrap();
            let content = if metadata.is_symlink() {
                expected.push(b'l');
                b"file-0000".to_vec()
            } else {
                expected.push(b'f');
                Sha256::digest(fs::read(path).unwrap()).to_vec()
            };
            for field in [
                name.as_bytes(),
                &metadata.mode().to_le_bytes(),
                &metadata.len().to_le_bytes(),
                &content,
            ] {
                expected.extend_from_slice(&(field.len() as u64).to_le_bytes());
                expected.extend_from_slice(field);
            }
        }
        let (actual, blocked) = toolchain_inventory(root.path(), &Cancellation::default()).unwrap();
        assert!(blocked.is_empty());
        assert_eq!(actual, expected);
    }

    #[test]
    fn inventory_byte_budget_is_checked_before_hashing_a_sparse_file() {
        let root = tempfile::tempdir().unwrap();
        fs::File::create(root.path().join("oversized"))
            .unwrap()
            .set_len(MAX_TOOLCHAIN_BYTES + 1)
            .unwrap();
        assert!(matches!(
            toolchain_inventory(root.path(), &Cancellation::default()),
            Err(BuildError::Toolchain)
        ));
    }

    #[test]
    #[ignore = "explicit /usr inventory profiling; reads the complete mutable host toolchain"]
    fn inventory_profile_usr() {
        let (inventory, blocked) =
            toolchain_inventory(Path::new("/usr"), &Cancellation::default()).unwrap();
        eprintln!(
            "inventory_sha256={} inventory_bytes={} blocked={}",
            ContentDigest::sha256(&inventory),
            inventory.len(),
            blocked.len()
        );
    }

    #[test]
    #[ignore = "set SYROX_BENCH_STORE, SYROX_BENCH_RECEIPT and SYROX_BENCH_SRX for a retained application"]
    fn retained_build_with_inputs_costs_are_measured_separately() {
        let store = Store::open(Path::new(
            &std::env::var("SYROX_BENCH_STORE").unwrap(),
        ))
        .unwrap();
        let receipt: ContentDigest = std::env::var("SYROX_BENCH_RECEIPT")
            .unwrap()
            .parse()
            .unwrap();
        let worker = std::env::var("SYROX_BENCH_SRX").unwrap();
        let cancellation = Cancellation::default();
        let lease = store.operation().unwrap();
        let record = lease
            .read_verified(receipt, 4096)
            .unwrap()
            .unwrap();
        let receipt = Receipt::parse(record.as_bytes()).unwrap();
        let record = lease
            .read_verified(receipt.action, 4096)
            .unwrap()
            .unwrap();
        let action = Action::parse(record.as_bytes()).unwrap();
        let start = std::time::Instant::now();
        lease
            .read_verified(
                action.source,
                action.program.maximum_source_bytes(),
            )
            .unwrap()
            .unwrap();
        let source_time = start.elapsed();
        let start = std::time::Instant::now();
        let (inventory, _) = toolchain_inventory(Path::new("/usr"), &cancellation).unwrap();
        let inventory_time = start.elapsed();
        let start = std::time::Instant::now();
        let worker = read_worker(Path::new(&worker), &cancellation).unwrap();
        let worker_time = start.elapsed();
        assert_eq!(
            Some(ContentDigest::sha256(&inventory)),
            action.toolchain
        );
        assert_eq!(ContentDigest::sha256(&worker), action.worker);
        let start = std::time::Instant::now();
        let hit = cache::lookup(&lease, &action, None, &cancellation)
            .unwrap()
            .unwrap();
        let lookup_time = start.elapsed();
        let start = std::time::Instant::now();
        let view = crate::result::materialize_artifact(&store, &hit.root, hit.receipt).unwrap();
        let view_time = start.elapsed();
        eprintln!(
            "source={source_time:?} inventory={inventory_time:?} worker={worker_time:?} verified_lookup={lookup_time:?} view={view_time:?} reused_view={}",
            view.reused()
        );
    }

    #[test]
    fn publication_failure_and_root_conflict_never_report_a_completed_build() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let lease = store.operation().unwrap();
        let source = ContentDigest::sha256(b"source");
        lease.ingest(&b"source"[..], source, 6).unwrap();
        let root = RootName::new("result").unwrap();
        let object = (
            &b"artifact"[..],
            ContentDigest::sha256(b"artifact"),
        );
        let mut references = vec![source, object.1];
        references.sort_unstable();
        crate::platform::linux::fd::fail_next_atomic(
            crate::platform::linux::fd::AtomicFault::Write,
        );
        let cancellation = Cancellation::default();
        assert!(
            publish_result(
                &lease,
                &root,
                &references,
                &[object],
                Vec::new(),
                &cancellation
            )
            .is_err()
        );
        assert!(
            !directory
                .path()
                .join("roots/retained/result")
                .exists()
        );
        publish_result(
            &lease,
            &root,
            &references,
            &[object],
            Vec::new(),
            &cancellation,
        )
        .unwrap();
        let before = fs::read(directory.path().join("roots/retained/result")).unwrap();
        let other = (&b"other"[..], ContentDigest::sha256(b"other"));
        let mut other_references = vec![source, other.1];
        other_references.sort_unstable();
        assert!(matches!(
            publish_result(
                &lease,
                &root,
                &other_references,
                &[other],
                Vec::new(),
                &cancellation,
            ),
            Err(BuildError::Store(
                crate::store::StoreError::RootConflict { .. }
            ))
        ));
        assert_eq!(
            fs::read(directory.path().join("roots/retained/result")).unwrap(),
            before
        );
        cancellation.cancel();
        let cancelled = RootName::new("cancelled").unwrap();
        assert!(matches!(
            publish_result(
                &lease,
                &cancelled,
                &references,
                &[object],
                Vec::new(),
                &cancellation
            ),
            Err(BuildError::Cancelled)
        ));
        assert!(
            !directory
                .path()
                .join("roots/retained/cancelled")
                .exists()
        );
    }

    #[test]
    fn cancelled_stage_is_cleaned_but_uncertain_settlement_retains_evidence() {
        let parent = tempfile::tempdir().unwrap();
        let store = Store::open(parent.path()).unwrap();
        let lease = store.operation().unwrap();
        let operation = Operation::create(&lease).unwrap();
        let path = operation.stage_path();
        operation
            .write_stage("source", b"input", false)
            .unwrap();
        assert!(matches!(
            finish_stage::<()>(&operation, Err(BuildError::Cancelled)),
            Err(BuildError::Cancelled)
        ));
        assert!(!path.exists());

        let operation = Operation::create(&lease).unwrap();
        let path = operation.stage_path();
        operation
            .write_stage("source", b"input", false)
            .unwrap();
        let error = BuildError::Settlement {
            stage: path.clone(),
            reason: "query failed",
            primary: Some(Box::new(BuildError::Cancelled)),
        };
        let error = finish_stage::<()>(&operation, Err(error)).unwrap_err();
        assert!(
            matches!(error, BuildError::Settlement { primary: Some(ref error), .. } if matches!(error.as_ref(), BuildError::Cancelled))
        );
        assert_eq!(fs::read(path.join("source")).unwrap(), b"input");
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn cleanup_failure_cannot_report_success_or_hide_cancellation() {
        for outcome in [Ok(()), Err(BuildError::Cancelled)] {
            let cancelled = outcome.is_err();
            let parent = tempfile::tempdir().unwrap();
            let store = Store::open(parent.path()).unwrap();
            let operation = Operation::create(&store.operation().unwrap()).unwrap();
            let path = operation.stage_path();
            // Make recursive directory removal fail without relying on uid or
            // permissions. The outer guard owns both paths even on assertion failure.
            fs::rename(&path, parent.path().join("retained")).unwrap();
            fs::write(&path, b"replacement").unwrap();
            let error = finish_stage(&operation, outcome).unwrap_err();
            if cancelled {
                assert!(
                    matches!(error, BuildError::FailureAndCleanup { primary, .. }
                    if matches!(*primary, BuildError::Cancelled))
                );
            } else {
                assert!(matches!(error, BuildError::Cleanup(_)));
            }
            assert_eq!(fs::read(path).unwrap(), b"replacement");
        }
    }
}

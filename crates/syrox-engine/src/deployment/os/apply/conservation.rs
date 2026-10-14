use super::preparation::{
    PreparationError, PreparedResource, ResourcePreparation, check, context_for_unit,
};
use crate::deployment::os::{
    activation::ActivationSnapshot,
    diff::{ChangeKind, ResourceKind, diff_generations},
    installation::{GenerationConfiguration, GenerationLauncher, RetainedGeneration},
    launch_binding::OsLaunchBinding,
    runtime::prepare_bound_os_runtime,
};
use crate::systemd::persistent::{OsUnitContract, OsUnitInput};
use crate::{cancellation::Cancellation, store::ContentDigest};
use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::sync::Arc;
use std::time::Instant;

type Result<T> = std::result::Result<T, PreparationError>;
const MAX_RESOURCES: usize = 1024;
// Aggregate canonical input admitted to the cache, not a per-generation limit.
const MAX_CACHE_BYTES: usize = crate::deployment::os::manifest::MAX_BYTES;
// diff_generations also scans the current candidate once per unique prior generation.
const MAX_DIFF_BYTES: usize = 2 * MAX_CACHE_BYTES;

struct CacheBudget {
    admitted: usize,
    maximum: usize,
}
impl CacheBudget {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        let admitted = self
            .admitted
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum)
            .ok_or_else(|| invalid("generation conservation exceeds aggregate byte budget"))?;
        self.admitted = admitted;
        Ok(())
    }
}

pub(crate) struct PreservedResource {
    pub binding: OsLaunchBinding,
    pub contract: OsUnitContract,
    // Retains the previous generation's output leases until this resource settles.
    #[allow(dead_code)] // Its Drop controls the previous generation's lease lifetime.
    retained_generation: Arc<RetainedGeneration>,
}
pub(super) struct ExistingSnapshots {
    launcher: GenerationLauncher,
    configuration: GenerationConfiguration,
}
struct PreviousGeneration {
    retained: Arc<RetainedGeneration>,
    unchanged: BTreeSet<String>,
    snapshots: Option<ExistingSnapshots>,
}

pub(crate) fn prepare_conservation(
    input: &ResourcePreparation<'_>,
    resources: &BTreeMap<String, PreparedResource>,
    snapshot: &ActivationSnapshot,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<BTreeMap<String, PreservedResource>> {
    input.revalidate(cancellation, deadline)?;
    if snapshot.installation != input.installation.id()
        || input.generation.installation_id() != input.installation.id()
        || resources.len() > MAX_RESOURCES
        || snapshot.bindings.len() > MAX_RESOURCES
    {
        return Err(invalid(
            "conservation authority or resource bound differs",
        ));
    }
    let mut cache = BTreeMap::<ContentDigest, PreviousGeneration>::new();
    let mut budget = CacheBudget {
        admitted: 0,
        maximum: MAX_CACHE_BYTES,
    };
    let mut diff_budget = CacheBudget {
        admitted: 0,
        maximum: MAX_DIFF_BYTES,
    };
    let mut preserved = BTreeMap::new();
    for (key, next) in resources {
        check(cancellation, deadline)?;
        let Some(previous) = snapshot
            .bindings
            .get(key)
            .filter(|binding| binding.authorized && &binding.epoch == input.epoch)
        else {
            continue;
        };
        let pin = previous
            .pin
            .parse()
            .map_err(|_| invalid("invalid prior binding pin"))?;
        let binding = input
            .installation
            .read_launch_binding(pin, cancellation, deadline)?;
        if binding.process_key() != *key
            || binding.unit().as_str() != previous.unit
            || binding.epoch() != &previous.epoch
            || binding.generation().to_string() != previous.generation
        {
            return Err(invalid(
                "prior binding differs from activation evidence",
            ));
        }
        let prior = match cache.entry(binding.generation()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let retained = input.installation.open(
                    input.store,
                    binding.generation(),
                    cancellation,
                    deadline,
                )?;
                // Charge each distinct generation once, before diffing or caching
                // its decoded runtime descriptions. Reused entries are free.
                budget.charge(retained.canonical_bytes().len())?;
                charge_diff(
                    &mut diff_budget,
                    retained.canonical_bytes().len(),
                    input.generation.canonical_bytes().len(),
                )?;
                let unchanged = diff_generations(retained.manifest(), input.generation.manifest())
                    .changes()
                    .iter()
                    .filter(|change| {
                        change.resource == ResourceKind::Process
                            && change.kind == ChangeKind::Unchanged
                    })
                    .map(|change| change.key.clone())
                    .collect();
                check(cancellation, deadline)?;
                entry.insert(PreviousGeneration {
                    retained: Arc::new(retained),
                    unchanged,
                    snapshots: None,
                })
            }
        };
        if !prior.unchanged.contains(key) || !compatible(input, key, &binding, next)? {
            continue;
        }
        let contract = verify_existing(input, prior, &binding, cancellation, deadline)?;
        preserved.insert(
            key.clone(),
            PreservedResource {
                binding,
                contract,
                retained_generation: Arc::clone(&prior.retained),
            },
        );
    }
    input.paths.revalidate(cancellation, deadline)?;
    check(cancellation, deadline)?;
    Ok(preserved)
}

fn charge_diff(budget: &mut CacheBudget, previous: usize, candidate: usize) -> Result<()> {
    let bytes = previous
        .checked_add(candidate)
        .ok_or_else(|| invalid("generation diff input byte count overflow"))?;
    budget.charge(bytes)
}

fn compatible(
    input: &ResourcePreparation<'_>,
    key: &str,
    old: &OsLaunchBinding,
    next: &PreparedResource,
) -> Result<bool> {
    let fresh = &next.binding;
    if fresh.generation() != input.generation.digest()
        || fresh.installation_id() != input.installation.id()
        || fresh.process_key() != key
        || fresh.epoch() != input.epoch
        || next.contract.binding() != fresh.digest()?
    {
        return Err(invalid(
            "candidate resource differs from preparation",
        ));
    }
    let expected = context_for_unit(input, &fresh.unit())?;
    let expected = expected.with_restart(input.generation.manifest().processes[key].restart)?;
    if fresh.context() != &expected || fresh.cwd() != input.paths.cwd() {
        return Err(invalid("candidate operational context differs"));
    }
    Ok(old.context() == fresh.context()
        && old.cwd() == fresh.cwd()
        && old.unit() == fresh.unit()
        && old.command_key() == fresh.command_key()
        && old.launcher() == fresh.launcher()
        && old.spec() == fresh.spec())
}

fn verify_existing(
    input: &ResourcePreparation<'_>,
    prior: &mut PreviousGeneration,
    binding: &OsLaunchBinding,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsUnitContract> {
    if prior.snapshots.is_none() {
        prior.snapshots = Some(ExistingSnapshots::open(
            input.installation,
            &prior.retained,
            cancellation,
            deadline,
        )?);
    }
    snapshot_contract(
        input.paths,
        &prior.retained,
        binding,
        prior
            .snapshots
            .as_ref()
            .expect("opened existing snapshots"),
        cancellation,
        deadline,
    )
}
impl ExistingSnapshots {
    pub(super) fn open(
        installation: &crate::deployment::os::installation::GenerationInstallation,
        retained: &RetainedGeneration,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        Ok(Self {
            launcher: installation.open_launcher(retained, cancel, deadline)?,
            configuration: installation.open_configuration(retained, cancel, deadline)?,
        })
    }
}
pub(super) fn snapshot_contract(
    paths: &crate::deployment::os::paths::OsExecutionPaths,
    retained: &RetainedGeneration,
    binding: &OsLaunchBinding,
    snapshots: &ExistingSnapshots,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<OsUnitContract> {
    let (configuration, path) = snapshots
        .configuration
        .service(binding.service())?;
    if path != binding.configuration() {
        return Err(invalid("prior configuration path differs"));
    }
    // This checks exact configuration bytes, executable paths and runtime closure,
    // then compares the resulting specification with the original binding pin.
    prepare_bound_os_runtime(retained, binding, configuration, cancellation)?;
    snapshots
        .launcher
        .verify_path(cancellation, deadline)?;
    let context = binding.context();
    let contract = OsUnitContract::new(OsUnitInput {
        restart: binding.context().restart(),
        unit: binding.unit(),
        scope: context.scope(),
        worker: snapshots.launcher.path().into(),
        installation: paths.installation().into(),
        store: context.store().into(),
        binding: binding.digest()?,
        fragment: context.fragment().into(),
        uid: context.uid(),
        gid: context.gid(),
        start_timeout: context.start_timeout(),
        stop_timeout: context.stop_timeout(),
    })?;
    check(cancellation, deadline)?;
    Ok(contract)
}

fn invalid(message: &'static str) -> PreparationError {
    PreparationError::Invalid(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::os::activation::{ActivationJournal, EffectKind, ExecutionEpoch};
    use crate::deployment::os::apply::preparation::prepare_resources;
    use crate::deployment::os::installation::GenerationInstallation;
    use crate::deployment::os::launch_binding::OsLaunchContext;
    use crate::deployment::os::paths::OsExecutionPaths;
    use crate::deployment::os::{LauncherIdentity, PreparedGeneration};
    use crate::{store::Store, systemd::SystemdScope};
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(20)
    }
    fn private() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    fn unrelated_config(text: &str) -> String {
        text.replace(
            "services = [std::Service {",
            r#"services = [std::Service {
            id = "unrelated"; files = [std::ConfigFile { path = "extra"; text = "independent"; }];
        }, std::Service {"#,
        )
    }
    struct Fixture {
        _directories: Vec<tempfile::TempDir>,
        installation: GenerationInstallation,
        store: Store,
        paths: OsExecutionPaths,
        units: PathBuf,
        old_binding: OsLaunchBinding,
        old_contract: OsUnitContract,
        candidate: RetainedGeneration,
        resources: BTreeMap<String, PreparedResource>,
        snapshot: ActivationSnapshot,
        epoch: ExecutionEpoch,
    }
    impl Fixture {
        fn new(transform: impl FnOnce(String) -> String) -> Self {
            let (first, consumer) =
                crate::deployment::manifest::tests::prepared_service_payload_fixture_kind(
                    &crate::runtime::tests::elf(2, None, &[], None, None),
                    "",
                    "Os",
                );
            let store_path = first.path().join("store");
            let store = Store::open_existing(&store_path).unwrap();
            let install = private();
            let cwd = private();
            let units = private();
            let cancellation = Cancellation::default();
            let installation =
                GenerationInstallation::initialize(install.path(), &cancellation, deadline())
                    .unwrap();
            let paths = OsExecutionPaths::open(
                install.path(),
                &store_path,
                cwd.path(),
                &cancellation,
                deadline(),
            )
            .unwrap();
            let old = retain(&installation, &store, first.path(), consumer);
            let context = OsLaunchContext::new(
                SystemdScope::System,
                store_path.clone(),
                units.path().join("placeholder.service"),
                1000,
                1000,
                Duration::from_secs(30),
                Duration::from_secs(10),
            )
            .unwrap();
            let epoch = ExecutionEpoch {
                boot: crate::platform::linux::boot::BootId::parse(
                    "11111111-1111-4111-8111-111111111111",
                )
                .unwrap(),
                manager: "conservation-manager".into(),
                scope: context.scope_key(),
            };
            let old_resources = prepare_resources(
                &input(
                    &installation,
                    &store,
                    &paths,
                    units.path(),
                    &old,
                    &epoch,
                ),
                &cancellation,
                deadline(),
            )
            .unwrap();
            let old_resource = old_resources.into_values().next().unwrap();
            let snapshot = authorize(
                &installation,
                &old,
                &old_resource.binding,
                install.path(),
                &epoch,
            );
            let (second, consumer) =
                crate::deployment::manifest::tests::prepared_service_payload_fixture_with_source(
                    &crate::runtime::tests::elf(2, None, &[], None, None),
                    "",
                    "Os",
                    Some(&store_path),
                    transform,
                );
            let candidate = retain(&installation, &store, second.path(), consumer);
            let resources = prepare_resources(
                &input(
                    &installation,
                    &store,
                    &paths,
                    units.path(),
                    &candidate,
                    &epoch,
                ),
                &cancellation,
                deadline(),
            )
            .unwrap();
            Self {
                installation,
                store,
                paths,
                units: units.path().into(),
                old_binding: old_resource.binding,
                old_contract: old_resource.contract,
                candidate,
                resources,
                snapshot,
                epoch,
                _directories: vec![first, second, install, cwd, units],
            }
        }
        fn input(&self) -> ResourcePreparation<'_> {
            input(
                &self.installation,
                &self.store,
                &self.paths,
                &self.units,
                &self.candidate,
                &self.epoch,
            )
        }
        fn preserve(&self) -> Result<BTreeMap<String, PreservedResource>> {
            prepare_conservation(
                &self.input(),
                &self.resources,
                &self.snapshot,
                &Cancellation::default(),
                deadline(),
            )
        }
    }
    fn input<'a>(
        installation: &'a GenerationInstallation,
        store: &'a Store,
        paths: &'a OsExecutionPaths,
        units: &'a Path,
        generation: &'a RetainedGeneration,
        epoch: &'a ExecutionEpoch,
    ) -> ResourcePreparation<'a> {
        ResourcePreparation {
            installation,
            generation,
            store,
            paths,
            units,
            epoch,
            scope: SystemdScope::System,
            uid: 1000,
            gid: 1000,
            start_timeout: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(10),
        }
    }
    fn retain(
        installation: &GenerationInstallation,
        store: &Store,
        project: &Path,
        consumer: crate::deployment::manifest::PreparedConsumer,
    ) -> RetainedGeneration {
        let worker = project.join("candidate-worker");
        fs::write(&worker, b"retained conservation worker").unwrap();
        let prepared = PreparedGeneration::freeze(
            consumer,
            LauncherIdentity::new(
                ContentDigest::sha256(b"retained conservation worker"),
                1,
            )
            .unwrap(),
        )
        .unwrap();
        let retained = installation
            .prepare(
                &prepared,
                store,
                &worker,
                &Cancellation::default(),
                deadline(),
            )
            .unwrap();
        fs::remove_file(worker).unwrap();
        fs::remove_file(project.join("main.srx")).unwrap();
        retained
    }
    fn authorize(
        installation: &GenerationInstallation,
        generation: &RetainedGeneration,
        binding: &OsLaunchBinding,
        path: &Path,
        epoch: &ExecutionEpoch,
    ) -> ActivationSnapshot {
        let cancel = Cancellation::default();
        let journal = ActivationJournal::open_existing(path, &cancel, deadline()).unwrap();
        let operation = journal
            .begin(
                generation,
                None,
                epoch.clone(),
                &cancel,
                deadline(),
            )
            .unwrap();
        let pin = installation
            .publish_launch_binding(generation, binding, &cancel, deadline())
            .unwrap();
        let effect = journal
            .plan_effect(
                &operation,
                &binding.process_key(),
                EffectKind::Publish,
                None,
                pin,
                &cancel,
                deadline(),
            )
            .unwrap();
        journal
            .record_observed(
                &operation,
                &effect,
                pin,
                None,
                &cancel,
                deadline(),
            )
            .unwrap();
        journal
            .authorize_binding(&operation, &effect, binding, &cancel, deadline())
            .unwrap();
        journal.snapshot(&cancel, deadline()).unwrap()
    }

    #[test]
    fn unrelated_candidate_change_preserves_verified_old_execution_without_publication() {
        let fixture = Fixture::new(|text| unrelated_config(&text));
        assert_ne!(
            fixture.old_binding.generation(),
            fixture.candidate.digest()
        );
        let preserved = fixture.preserve().unwrap();
        assert_eq!(preserved.len(), 1);
        let old = &preserved[&fixture.old_binding.process_key()];
        assert_eq!(old.binding, fixture.old_binding);
        assert_eq!(
            old.contract.render(),
            fixture.old_contract.render()
        );
        assert_eq!(
            old.retained_generation.digest(),
            fixture.old_binding.generation()
        );
        let fresh = &fixture.resources[&old.binding.process_key()].binding;
        assert_ne!(
            old.binding.digest().unwrap(),
            fresh.digest().unwrap()
        );
        assert!(
            fixture
                .installation
                .read_launch_binding(
                    fresh.digest().unwrap(),
                    &Cancellation::default(),
                    deadline()
                )
                .is_err()
        );
        assert!(!old.binding.context().fragment().exists());
        fixture
            .store
            .maintenance()
            .unwrap()
            .garbage_collect(&crate::store::GcRequest {
                collect: true,
                ..crate::store::GcRequest::default()
            })
            .unwrap();
        assert_eq!(old.retained_generation.commands().len(), 1);
    }

    #[test]
    fn changed_process_or_revoked_or_other_epoch_is_not_conserved() {
        let fixture = Fixture::new(|text| text.replace("controlled", "changed configuration"));
        assert!(fixture.preserve().unwrap().is_empty());
        let mut fixture = Fixture::new(|text| unrelated_config(&text));
        fixture
            .snapshot
            .bindings
            .values_mut()
            .next()
            .unwrap()
            .authorized = false;
        assert!(fixture.preserve().unwrap().is_empty());
        let previous = fixture
            .snapshot
            .bindings
            .values_mut()
            .next()
            .unwrap();
        previous.authorized = true;
        previous.epoch.manager = "different manager".into();
        assert!(fixture.preserve().unwrap().is_empty());
    }

    #[test]
    fn command_alias_change_is_not_adopted_even_with_equal_runtime_bytes() {
        let fixture = Fixture::new(|text| {
            text.replace(r#"name = "serve";"#, r#"name = "other";"#)
                .replace(r#"command = "serve";"#, r#"command = "other";"#)
        });
        let fresh = &fixture.resources[&fixture.old_binding.process_key()].binding;
        assert_eq!(fresh.spec(), fixture.old_binding.spec());
        assert_ne!(
            fresh.command_key(),
            fixture.old_binding.command_key()
        );
        assert!(fixture.preserve().unwrap().is_empty());
    }

    #[test]
    fn changed_cwd_or_timeouts_require_fresh_execution() {
        let fixture = Fixture::new(|text| unrelated_config(&text));
        let cwd = private();
        let paths = OsExecutionPaths::open(
            fixture.paths.installation(),
            fixture.paths.store(),
            cwd.path(),
            &Cancellation::default(),
            deadline(),
        )
        .unwrap();
        let mut changed = fixture.input();
        changed.paths = &paths;
        let resources = prepare_resources(&changed, &Cancellation::default(), deadline()).unwrap();
        assert!(
            prepare_conservation(
                &changed,
                &resources,
                &fixture.snapshot,
                &Cancellation::default(),
                deadline()
            )
            .unwrap()
            .is_empty()
        );
        let mut changed = fixture.input();
        changed.stop_timeout = Duration::from_secs(20);
        let resources = prepare_resources(&changed, &Cancellation::default(), deadline()).unwrap();
        assert!(
            prepare_conservation(
                &changed,
                &resources,
                &fixture.snapshot,
                &Cancellation::default(),
                deadline()
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn missing_or_corrupt_old_configuration_is_not_repaired_or_promoted() {
        let fixture = Fixture::new(|text| unrelated_config(&text));
        let config = fixture
            .old_binding
            .configuration()
            .join("nested/config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&config, b"corrupted").unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(fixture.preserve().is_err());
        assert_eq!(fs::read(&config).unwrap(), b"corrupted");
        let parent = config.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(&config).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(fixture.preserve().is_err());
        assert!(!config.exists());
    }

    #[test]
    fn mismatched_prior_binding_and_cancellation_fail_before_conservation() {
        let mut fixture = Fixture::new(|text| unrelated_config(&text));
        fixture
            .snapshot
            .bindings
            .values_mut()
            .next()
            .unwrap()
            .generation = ContentDigest::sha256(b"wrong").to_string();
        assert!(fixture.preserve().is_err());
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            prepare_conservation(
                &fixture.input(),
                &fixture.resources,
                &fixture.snapshot,
                &cancel,
                deadline()
            ),
            Err(PreparationError::Cancelled)
        ));
    }

    #[test]
    fn aggregate_cache_budget_rejects_sum_and_overflow_without_admitting_failure() {
        let mut budget = CacheBudget {
            admitted: 0,
            maximum: 128,
        };
        budget.charge(70).unwrap();
        assert!(
            budget.charge(70).is_err(),
            "individually bounded manifests can exceed the aggregate"
        );
        assert_eq!(budget.admitted, 70);
        budget.charge(58).unwrap();
        assert_eq!(budget.admitted, 128);
        assert!(budget.charge(1).is_err());
        assert!(budget.charge(usize::MAX).is_err());
        assert_eq!(budget.admitted, 128);
    }

    #[test]
    fn diff_work_charges_the_candidate_again_for_each_distinct_previous_generation() {
        let mut memory = CacheBudget {
            admitted: 0,
            maximum: 64,
        };
        let mut work = CacheBudget {
            admitted: 0,
            maximum: 128,
        };
        memory.charge(4).unwrap();
        charge_diff(&mut work, 4, 60).unwrap();
        memory.charge(4).unwrap();
        charge_diff(&mut work, 4, 60).unwrap();
        assert_eq!(memory.admitted, 8);
        assert_eq!(work.admitted, 128);
        memory.charge(4).unwrap();
        assert!(charge_diff(&mut work, 4, 60).is_err());
        assert!(charge_diff(&mut work, usize::MAX, 1).is_err());
        assert_eq!(work.admitted, 128);
    }

    #[test]
    fn historical_contract_reopens_old_generation_independently_of_changed_candidate() {
        let fixture = Fixture::new(|text| text.replace("controlled", "changed configuration"));
        assert!(fixture.preserve().unwrap().is_empty());
        let cancel = Cancellation::default();
        let old = fixture
            .installation
            .open(
                &fixture.store,
                fixture.old_binding.generation(),
                &cancel,
                deadline(),
            )
            .unwrap();
        assert_ne!(old.digest(), fixture.candidate.digest());
        let snapshots =
            ExistingSnapshots::open(&fixture.installation, &old, &cancel, deadline()).unwrap();
        let recovered = snapshot_contract(
            &fixture.paths,
            &old,
            &fixture.old_binding,
            &snapshots,
            &cancel,
            deadline(),
        )
        .unwrap();
        assert_eq!(recovered.render(), fixture.old_contract.render());
        assert_eq!(
            recovered.binding(),
            fixture.old_binding.digest().unwrap()
        );
        assert!(
            !fixture.old_binding.context().fragment().exists(),
            "reopening must not publish a unit"
        );
        assert!(
            snapshot_contract(
                &fixture.paths,
                &fixture.candidate,
                &fixture.old_binding,
                &snapshots,
                &cancel,
                deadline()
            )
            .is_err()
        );
    }
}

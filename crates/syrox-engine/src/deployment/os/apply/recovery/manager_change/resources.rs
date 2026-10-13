use super::{OpenedRecovery, Result};
use crate::deployment::os::{
    activation::{ActivationSnapshot, manager_change::ManagerChange},
    apply::conservation::{ExistingSnapshots, snapshot_contract},
    installation::RetainedGeneration,
    launch_binding::OsLaunchBinding,
};
use crate::systemd::persistent::OsUnitContract;
use crate::{cancellation::Cancellation, store::ContentDigest};
use std::collections::{BTreeMap, btree_map::Entry};
use std::time::Instant;

struct Generation {
    retained: RetainedGeneration,
    snapshots: ExistingSnapshots,
}
pub(super) struct HistoricalResources {
    generations: BTreeMap<ContentDigest, Generation>,
    pub contracts: BTreeMap<String, OsUnitContract>,
}
impl HistoricalResources {
    pub(super) fn open(
        opened: &OpenedRecovery,
        snapshot: &ActivationSnapshot,
        change: &str,
        units: &std::path::Path,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        let transition = &snapshot.manager_changes[change];
        let mut this = Self {
            generations: BTreeMap::new(),
            contracts: BTreeMap::new(),
        };
        let mut bytes = 0usize;
        for (name, resource) in &transition.resources {
            let binding = Self::binding(
                opened,
                transition,
                name,
                &resource.binding.pin,
                cancel,
                deadline,
            )?;
            if binding.context().fragment().parent() != Some(units) {
                return Err("historical unit directory differs from explicit recovery path");
            }
            if binding.generation().to_string() != resource.binding.generation {
                return Err("historical generation differs from journal");
            }
            this.admit(opened, &binding, &mut bytes, cancel, deadline)?;
            let generation = &this.generations[&binding.generation()];
            let contract = snapshot_contract(
                &opened.paths,
                &generation.retained,
                &binding,
                &generation.snapshots,
                cancel,
                deadline,
            )
            .map_err(|_| "revalidate retained historical runtime")?;
            this.contracts.insert(name.clone(), contract);
        }
        for (name, pin) in snapshot
            .manager_history(change)
            .map_err(|_| "read historical startup inventory")?
        {
            let binding = Self::binding(opened, transition, &name, &pin, cancel, deadline)?;
            this.admit(opened, &binding, &mut bytes, cancel, deadline)?;
            let generation = &this.generations[&binding.generation()];
            snapshot_contract(
                &opened.paths,
                &generation.retained,
                &binding,
                &generation.snapshots,
                cancel,
                deadline,
            )
            .map_err(|_| "revalidate previous invocation runtime")?;
        }
        Ok(this)
    }
    fn binding(
        opened: &OpenedRecovery,
        transition: &ManagerChange,
        name: &str,
        pin: &str,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<OsLaunchBinding> {
        let binding = opened
            .installation
            .read_launch_binding(
                pin.parse()
                    .map_err(|_| "invalid historical pin")?,
                cancel,
                deadline,
            )
            .map_err(|_| "open historical binding")?;
        let resource = transition
            .resources
            .get(name)
            .ok_or("historical resource not inventoried")?;
        if binding.installation_id() != opened.installation.id()
            || binding.process_key() != name
            || binding.epoch() != &transition.previous
            || binding.unit().as_str() != resource.binding.unit
            || binding.context().store() != opened.paths.store()
            || binding.cwd() != opened.paths.cwd()
        {
            return Err("historical binding authority or execution paths differ");
        }
        Ok(binding)
    }
    fn admit(
        &mut self,
        opened: &OpenedRecovery,
        binding: &OsLaunchBinding,
        bytes: &mut usize,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        if let Entry::Vacant(entry) = self.generations.entry(binding.generation()) {
            let retained = opened
                .installation
                .open(
                    &opened.store,
                    binding.generation(),
                    cancel,
                    deadline,
                )
                .map_err(|_| "open retained historical generation")?;
            *bytes = bytes
                .checked_add(retained.canonical_bytes().len())
                .filter(|size| *size <= crate::deployment::os::manifest::MAX_BYTES)
                .ok_or("historical generation aggregate limit exceeded")?;
            let snapshots =
                ExistingSnapshots::open(&opened.installation, &retained, cancel, deadline)
                    .map_err(|_| "open historical execution snapshots")?;
            entry.insert(Generation {
                retained,
                snapshots,
            });
        }
        Ok(())
    }
}

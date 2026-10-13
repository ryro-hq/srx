use super::{ObservedInvocation, PinnedResource, Reconciler, Result};
use crate::systemd::persistent::OsUnitContract;

impl Reconciler<'_> {
    pub(super) fn epoch(&mut self) -> Result<()> {
        let identity = self
            .manager
            .observe_identity(self.remaining()?, self.cancel)
            .map_err(|_| "observe current manager")?;
        let boot = crate::platform::linux::boot::BootId::current(self.cancel, self.deadline)
            .map_err(|_| "observe current boot")?;
        if identity.fingerprint().to_string() != self.current.manager || boot != self.current.boot {
            return Err("manager recovery epoch changed");
        }
        Ok(())
    }
    pub(super) fn loaded(&mut self, contract: &OsUnitContract) -> Result<()> {
        self.epoch()?;
        let loaded = self
            .manager
            .observe_os_unit(contract, self.remaining()?, self.cancel)
            .map_err(|_| "observe historical loaded contract")?;
        if loaded.unit() != contract.unit()
            || loaded.manager().fingerprint().to_string() != self.current.manager
        {
            return Err("loaded contract manager differs");
        }
        self.epoch()
    }
    pub(super) fn invocation(
        &mut self,
        unit: &crate::systemd::SystemdUnitName,
        expected: ObservedInvocation,
    ) -> Result<()> {
        let current = self
            .manager
            .query(unit, self.remaining()?, self.cancel)
            .map_err(|_| "query prior invocation")?
            .ok_or("prior unit is absent")?;
        if current.unit != *unit {
            return Err("prior invocation changed");
        }
        expected.verify(&current.invocation)?;
        self.epoch()
    }
    pub(super) fn check(
        &mut self,
        pinned: &PinnedResource,
        contract: &OsUnitContract,
    ) -> Result<()> {
        self.manager
            .verify_unit_reference(&pinned.reference, self.remaining()?, self.cancel)
            .map_err(|_| "unit reference changed")?;
        self.loaded(contract)?;
        self.invocation(&pinned.unit, pinned.observation)
    }
    pub(super) fn stop(
        &mut self,
        name: &str,
        contract: &OsUnitContract,
        pinned: &PinnedResource,
    ) -> Result<()> {
        self.check(pinned, contract)?;
        // A newly loaded unit has no authority to receive Stop for the extinct
        // historical invocation. Its empty identifier only selects observation.
        let ObservedInvocation::Historical(invocation) = pinned.observation else {
            return Ok(());
        };
        let invocation = super::invocation::encode(&invocation);
        if self
            .manager
            .unit_idle_without_job(&pinned.unit, self.remaining()?, self.cancel)
            .map_err(|_| "observe idle unit before stop")?
        {
            return Ok(());
        }
        if !self
            .opened
            .journal
            .intent_changed_stop(
                self.change,
                name,
                &invocation,
                self.cancel,
                self.deadline,
            )
            .map_err(|_| "persist single-use recovery stop intent")?
        {
            // Intent, Accepted and Unknown all enter observation-only recovery.
            return Ok(());
        }
        self.check(pinned, contract)?;
        let response = self
            .manager
            .stop(&pinned.unit, self.remaining()?, self.cancel);
        self.opened
            .journal
            .changed_stop_reply(
                self.change,
                name,
                &invocation,
                response
                    .as_ref()
                    .ok()
                    .map(crate::systemd::SystemdJob::path),
                self.cancel,
                self.deadline,
            )
            .map_err(|_| "persist recovery stop reply")?;
        let job = response.map_err(|_| "recovery stop outcome uncertain")?;
        self.manager
            .wait_job(&job, self.remaining()?, self.cancel)
            .map_err(|_| "recovery stop job unresolved")?;
        self.check(pinned, contract)
    }
}

impl Reconciler<'_> {
    /// Observation only: callers separately prove `NeverStarted` or a complete
    /// exited process inventory. Empty `ControlGroup` never proves process exit.
    pub(super) fn idle_without_cgroup(
        &mut self,
        reference: &crate::systemd::SystemdUnitReference,
        contract: &OsUnitContract,
    ) -> Result<()> {
        self.manager
            .verify_unit_reference(reference, self.remaining()?, self.cancel)
            .map_err(|_| "inventory unit reference changed")?;
        self.loaded(contract)?;
        let before = self
            .manager
            .query(contract.unit(), self.remaining()?, self.cancel)
            .map_err(|_| "query inventory unit")?
            .ok_or("inventory unit unavailable")?;
        if before.unit != *contract.unit()
            || before.main_pid != 0
            || !before.control_group.is_empty()
            || !matches!(
                before.active_state.as_str(),
                "inactive" | "failed"
            )
        {
            return Err("inventory unit is not idle");
        }
        if !self
            .manager
            .unit_idle_without_job(contract.unit(), self.remaining()?, self.cancel)
            .map_err(|_| "observe inventory unit job")?
        {
            return Err("inventory unit has pending job");
        }
        let store = self
            .manager
            .query_fd_store(contract.unit(), self.remaining()?, self.cancel)
            .map_err(|_| "observe inventory fdstore")?
            .ok_or("inventory fdstore unavailable")?;
        if store.count != 0 || store.invocation != before.invocation {
            return Err("inventory fdstore differs");
        }
        let after = self
            .manager
            .query(contract.unit(), self.remaining()?, self.cancel)
            .map_err(|_| "revalidate inventory unit")?
            .ok_or("inventory unit disappeared")?;
        if after.unit != before.unit
            || after.invocation != before.invocation
            || after.main_pid != 0
            || !after.control_group.is_empty()
            || !matches!(after.active_state.as_str(), "inactive" | "failed")
        {
            return Err("inventory unit changed");
        }
        self.epoch()
    }
}

impl Reconciler<'_> {
    /// This observation is usable only alongside `ClosedProcessInventory`. Empty
    /// `ControlGroup` is checked for consistency, never used as a death proof.
    pub(super) fn closed_inventory_idle(
        &mut self,
        pinned: &PinnedResource,
        contract: &OsUnitContract,
    ) -> Result<()> {
        self.check(pinned, contract)?;
        self.idle_without_cgroup(&pinned.reference, contract)?;
        self.check(pinned, contract)
    }
}

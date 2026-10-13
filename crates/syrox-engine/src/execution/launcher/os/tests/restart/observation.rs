use super::*;
use crate::deployment::os::installation::GenerationInstallation;
use crate::platform::linux::fd::persisted_namespace::{LauncherRecord, NamespaceRecord};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
pub(super) struct Attempt {
    invocation: String,
    gate_used: bool,
    namespace: Option<NamespaceRecord>,
    launcher: Option<LauncherRecord>,
}
impl Fixture {
    pub(super) fn attempts(&self) -> Result<BTreeMap<String, Attempt>> {
        let snapshot = self.journal.snapshot(&self.cancel, deadline())?;
        let json = serde_json::to_value(snapshot)?;
        let attempts = json["attempts"]
            .as_object()
            .ok_or_else(|| invalid("missing attempt inventory"))?;
        attempts
            .iter()
            .map(|(id, value)| {
                check(
                    value["resource"] == "probe/worker",
                    "foreign resource in private gate journal",
                )?;
                Ok((id.clone(), serde_json::from_value(value.clone())?))
            })
            .collect()
    }
    fn binding(&self) -> Result<Option<OsLaunchBinding>> {
        let json = serde_json::to_value(self.journal.snapshot(&self.cancel, deadline())?)?;
        let Some(binding) = json["bindings"].get("probe/worker") else {
            return Ok(None);
        };
        let pin: ContentDigest = binding["pin"]
            .as_str()
            .ok_or_else(|| invalid("invalid binding pin"))?
            .parse()?;
        let installation = GenerationInstallation::open_existing(
            &self.request.installation,
            &self.cancel,
            deadline(),
        )?;
        Ok(Some(installation.read_launch_binding(
            pin,
            &self.cancel,
            deadline(),
        )?))
    }
    fn observe(&mut self) -> Result<SystemdUnitStatus> {
        let binding = self
            .binding()?
            .ok_or_else(|| invalid("gate binding not published"))?;
        let unit = binding.unit();
        let epoch = self
            .manager
            .observe_identity(Duration::from_secs(2), &self.cancel)?;
        check(
            epoch.fingerprint().to_string() == binding.epoch().manager
                && crate::platform::linux::boot::BootId::current(&self.cancel, deadline())?
                    == binding.epoch().boot,
            "gate manager epoch changed",
        )?;
        if self.reference.is_none() {
            self.reference = Some(self.manager.reference_unit(
                &unit,
                Duration::from_secs(2),
                &self.cancel,
            )?);
        }
        self.manager.verify_unit_reference(
            self.reference.as_ref().unwrap(),
            Duration::from_secs(2),
            &self.cancel,
        )?;
        let installation = GenerationInstallation::open_existing(
            &self.request.installation,
            &self.cancel,
            deadline(),
        )?;
        let store = Store::open_existing(&self.request.store)?;
        let generation = installation.open(
            &store,
            binding.generation(),
            &self.cancel,
            deadline(),
        )?;
        let launcher = installation.open_launcher(&generation, &self.cancel, deadline())?;
        let context = binding.context();
        let contract = OsUnitContract::new(OsUnitInput {
            unit: unit.clone(),
            scope: context.scope(),
            worker: launcher.path().into(),
            installation: self.request.installation.clone(),
            store: self.request.store.clone(),
            binding: binding.digest()?,
            fragment: context.fragment().into(),
            uid: context.uid(),
            gid: context.gid(),
            start_timeout: context.start_timeout(),
            stop_timeout: context.stop_timeout(),
            restart: context.restart(),
        })?;
        self.manager
            .observe_os_unit(&contract, Duration::from_secs(2), &self.cancel)?;
        self.manager
            .query(&unit, Duration::from_secs(2), &self.cancel)?
            .ok_or_else(|| invalid("owned unit disappeared; no settlement inferred"))
    }
    pub(super) fn wait_payload(&mut self, number: u32) -> Result<Vec<u8>> {
        let until = deadline();
        loop {
            let status = self.observe()?;
            let marker = self.cwd.join(format!("witness.{number}"));
            if marker.exists() {
                check(
                    fs::read(marker)? == format!("SYROX_RESTART_V1 {number}\n").as_bytes(),
                    "payload witness differs",
                )?;
                let attempts = self.attempts()?;
                let invocation = context::hex(
                    &status
                        .invocation
                        .clone()
                        .try_into()
                        .map_err(|_| invalid("invalid current invocation"))?,
                );
                check(
                    attempts.len() == number as usize
                        && attempts.values().any(|attempt| {
                            attempt.invocation == invocation
                                && attempt.gate_used
                                && attempt.namespace.is_some()
                                && attempt.launcher.is_some()
                        }),
                    "payload lacks authenticated admitted attempt",
                )?;
                check(
                    status.active_state == "active" && status.main_pid != 0,
                    "payload is not active",
                )?;
                let store = self
                    .manager
                    .query_fd_store(&status.unit, Duration::from_secs(2), &self.cancel)?
                    .ok_or_else(|| invalid("missing FD store"))?;
                check(
                    store.invocation == status.invocation
                        && store.count == 1
                        && store.max == 1
                        && store.notify_access == "main",
                    "per-attempt retention handoff did not reach one descriptor",
                )?;
                return Ok(status.invocation);
            }
            check(Instant::now() < until, "payload witness deadline")?;
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    pub(super) fn wait_failed(&mut self, code: i32, result: &str) -> Result<Vec<u8>> {
        self.wait_terminal(code, Some(result))
    }
    pub(super) fn wait_start_limited(&mut self) -> Result<()> {
        // The manager may retain exit-code after the limit, as in the Shell
        // gate. Prove refusal through StartUnit, not only a result string.
        self.wait_terminal(1, None)?;
        let unit = self
            .binding()?
            .ok_or_else(|| invalid("missing limited unit binding"))?
            .unit();
        match self
            .manager
            .start_unit(&unit, Duration::from_secs(5), &self.cancel)
        {
            Ok(job) => check(
                matches!(
                    self.manager
                        .wait_job(&job, Duration::from_secs(5), &self.cancel)?,
                    crate::systemd::SystemdJobCompletion::Observed {
                        result: crate::systemd::SystemdJobResult::Failed
                    }
                ),
                "start-limit refusal was not observed",
            )?,
            Err(crate::systemd::SystemdError::Remote {
                name,
                ..
            }) => check(
                name == "org.freedesktop.systemd1.StartLimitHit",
                "unexpected StartUnit refusal",
            )?,
            Err(error) => return Err(error.into()),
        }
        check(
            self.observe()?.main_pid == 0,
            "limited unit started a process",
        )
    }
    fn wait_terminal(&mut self, code: i32, result: Option<&str>) -> Result<Vec<u8>> {
        let until = deadline();
        loop {
            let status = self.observe()?;
            if status.active_state == "failed"
                && status.main_pid == 0
                && self.manager.unit_idle_without_job(
                    &status.unit,
                    Duration::from_secs(2),
                    &self.cancel,
                )?
            {
                check(
                    result.map_or_else(
                        || {
                            matches!(
                                status.result.as_str(),
                                "start-limit-hit" | "exit-code"
                            )
                        },
                        |expected| status.result == expected,
                    ) && status.exec_main_code == libc::CLD_EXITED
                        && status.exec_main_status == code,
                    "unexpected launcher envelope or manager rate-limit result",
                )?;
                let store = self
                    .manager
                    .query_fd_store(&status.unit, Duration::from_secs(2), &self.cancel)?
                    .ok_or_else(|| invalid("missing terminal FD store"))?;
                check(
                    store.invocation == status.invocation && store.count == 0,
                    "terminal FD store was not released",
                )?;
                return Ok(status.invocation);
            }
            check(
                Instant::now() < until,
                "terminal invocation deadline",
            )?;
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    pub(super) fn revoke(&self) -> Result<()> {
        if let Some(binding) = self.binding()? {
            self.journal.revoke_binding(
                &binding.process_key(),
                binding.digest()?,
                &self.cancel,
                deadline(),
            )?;
        }
        Ok(())
    }
    pub(super) fn cleanup(&mut self) -> Result<()> {
        self.revoke()?;
        if self.binding()?.is_none() {
            return Ok(());
        }
        let status = self.observe()?;
        if status.main_pid != 0 {
            let invocation = context::hex(
                &status
                    .invocation
                    .clone()
                    .try_into()
                    .map_err(|_| invalid("cleanup invocation malformed"))?,
            );
            check(
                self.attempts()?
                    .values()
                    .any(|attempt| attempt.invocation == invocation),
                "cleanup refuses unadmitted or foreign live invocation",
            )?;
            let job = self
                .manager
                .stop(&status.unit, Duration::from_secs(5), &self.cancel)?;
            self.manager
                .wait_job(&job, Duration::from_secs(10), &self.cancel)?;
        }
        let until = deadline();
        loop {
            let attempts = self.attempts()?;
            let mut complete = true;
            for attempt in attempts.values() {
                let namespace = attempt
                    .namespace
                    .as_ref()
                    .ok_or_else(|| invalid("incomplete namespace inventory; evidence retained"))?;
                let launcher = attempt
                    .launcher
                    .as_ref()
                    .ok_or_else(|| invalid("incomplete launcher inventory; evidence retained"))?;
                complete &= namespace
                    .observe_exit(&self.cancel, until)?
                    .is_some()
                    && launcher
                        .observe_exit(&self.cancel, until)?
                        .is_some();
            }
            if complete {
                break;
            }
            check(
                Instant::now() < until,
                "cleanup lacks kernel settlement",
            )?;
            std::thread::sleep(Duration::from_millis(20));
        }
        if let Some(mut reference) = self.reference.take() {
            self.manager.unreference_unit(
                &mut reference,
                Duration::from_secs(2),
                &self.cancel,
            )?;
        }
        // No roots, snapshots, unit ownership records or evidence are deleted.
        fs::write(
            self.root.join("kernel-settled"),
            b"all recorded launcher and namespace identities exited\n",
        )?;
        Ok(())
    }
}

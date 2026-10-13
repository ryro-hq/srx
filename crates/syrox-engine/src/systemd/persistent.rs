use super::{SystemdError, SystemdScope, SystemdUnitName, absolute};
use crate::store::ContentDigest;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub(crate) struct OsUnitInput {
    pub unit: SystemdUnitName,
    pub scope: SystemdScope,
    /// Publisher must pin immutable executable bytes and retain them independently.
    pub worker: PathBuf,
    pub installation: PathBuf,
    pub store: PathBuf,
    pub binding: ContentDigest,
    pub fragment: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub start_timeout: Duration,
    pub stop_timeout: Duration,
    pub restart: crate::execution::restart::ProcessRestart,
}
#[derive(Clone, Debug)]
pub(crate) struct OsUnitContract {
    pub(super) input: OsUnitInput,
    pub(super) argv: Vec<String>,
}
impl OsUnitContract {
    pub(crate) fn new(input: OsUnitInput) -> Result<Self, SystemdError> {
        for path in [
            &input.worker,
            &input.installation,
            &input.store,
            &input.fragment,
        ] {
            let value = absolute(path)?;
            if path.components().collect::<PathBuf>().to_str() != Some(value)
                || value == "/"
                || value.chars().any(char::is_control)
            {
                return Err(SystemdError::Invalid(
                    "noncanonical launcher path",
                ));
            }
        }
        if input.uid == 0 || input.gid == 0 || input.uid == u32::MAX || input.gid == u32::MAX {
            return Err(SystemdError::Invalid(
                "Os launcher requires explicit nonzero uid/gid",
            ));
        }
        if matches!(input.scope, SystemdScope::User { .. }) {
            let ids = super::bus::caller_ids();
            if ids != (input.uid, input.uid, input.gid, input.gid) {
                return Err(SystemdError::Invalid(
                    "user manager identity differs from launcher",
                ));
            }
        }
        input.scope.address()?;
        if input
            .fragment
            .file_name()
            .and_then(|value| value.to_str())
            != Some(input.unit.as_str())
        {
            return Err(SystemdError::Invalid(
                "fragment basename differs from unit",
            ));
        }
        duration(input.start_timeout, 300)?;
        duration(input.stop_timeout, 60)?;
        let argv = vec![
            absolute(&input.worker)?.into(),
            "__os-service".into(),
            absolute(&input.installation)?.into(),
            absolute(&input.store)?.into(),
            input.binding.to_string(),
        ];
        Ok(Self {
            input,
            argv,
        })
    }
    pub(crate) fn unit(&self) -> &SystemdUnitName {
        &self.input.unit
    }
    pub(crate) fn scope(&self) -> &SystemdScope {
        &self.input.scope
    }
    pub(crate) fn binding(&self) -> ContentDigest {
        self.input.binding
    }
    pub(crate) fn file_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.render())
    }
    pub(crate) fn render(&self) -> Vec<u8> {
        let mut result = String::from(
            "# syrox-os-unit-v1\n[Unit]\nDefaultDependencies=yes\nCollectMode=inactive\nStopWhenUnneeded=no\n\n[Service]\nType=notify\nExitType=cgroup\nKillMode=mixed\nNotifyAccess=main\nFileDescriptorStoreMax=1\nFileDescriptorStorePreserve=no\nSendSIGKILL=yes\nKillSignal=SIGTERM\nFinalKillSignal=SIGKILL\nNoNewPrivileges=yes\nUMask=0077\nRemainAfterExit=no\nDelegate=no\nDynamicUser=no\nWorkingDirectory=/\nRootDirectory=\nRootImage=\nEnvironment=\nEnvironmentFile=\nPassEnvironment=\nUnsetEnvironment=\nStandardInput=null\nStandardOutput=journal\nStandardError=journal\n",
        );
        let (restart, delay, window, burst) = self.restart_properties();
        writeln!(result, "Restart={restart}\nRestartSec={delay}us\nRestartPreventExitStatus=78\nRestartForceExitStatus=\nSuccessExitStatus=").expect("String write");
        writeln!(result, "[Unit]\nStartLimitIntervalSec={window}us\nStartLimitBurst={burst}\nStartLimitAction=none\n[Service]").expect("String write");
        writeln!(
            result,
            "Slice={}\nUser={}\nGroup={}\nTimeoutStartSec={}us\nTimeoutStopSec={}us",
            self.slice(),
            self.input.uid,
            self.input.gid,
            self.input.start_timeout.as_micros(),
            self.input.stop_timeout.as_micros()
        )
        .expect("String write");
        result.push_str("ExecStart=:");
        for (index, value) in self.argv.iter().enumerate() {
            if index != 0 {
                result.push(' ');
            }
            result.push_str(&quote(value));
        }
        result.push('\n');
        result.into_bytes()
    }
    pub(super) fn restart_properties(&self) -> (&'static str, u64, u64, u32) {
        match self.input.restart {
            crate::execution::restart::ProcessRestart::Never => ("no", 1_000_000, 10_000_000, 5),
            crate::execution::restart::ProcessRestart::OnFailure(limits) => (
                "on-failure",
                u64::from(limits.delay_seconds()) * 1_000_000,
                u64::from(limits.window_seconds()) * 1_000_000,
                limits.burst(),
            ),
        }
    }
    pub(super) fn slice(&self) -> &'static str {
        match self.scope() {
            SystemdScope::User {
                ..
            } => "app.slice",
            SystemdScope::System => "system.slice",
        }
    }
}
fn duration(value: Duration, maximum: u64) -> Result<(), SystemdError> {
    if value.is_zero()
        || value > Duration::from_secs(maximum)
        || !value.subsec_nanos().is_multiple_of(1000)
    {
        return Err(SystemdError::Invalid(
            "launcher timeout must be finite whole microseconds",
        ));
    }
    Ok(())
}
fn quote(value: &str) -> String {
    let mut output = String::from("\"");
    for c in value.chars() {
        match c {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '%' => output.push_str("%%"),
            _ => output.push(c),
        }
    }
    output.push('"');
    output
}
#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(crate) fn input() -> OsUnitInput {
        OsUnitInput {
            restart: crate::execution::restart::ProcessRestart::Never,
            unit: SystemdUnitName::new("syrox-os-test.service").unwrap(),
            scope: SystemdScope::System,
            worker: "/private/worker".into(),
            installation: "/private/installation".into(),
            store: "/private/store".into(),
            binding: ContentDigest::sha256(b"binding"),
            fragment: "/etc/systemd/system/syrox-os-test.service".into(),
            uid: 1000,
            gid: 1000,
            start_timeout: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(2),
        }
    }
    #[test]
    fn renderer_has_fixed_authority_policy_and_literal_arguments() {
        let mut request = input();
        request.installation = "/private/space % $ \" \\".into();
        let contract = OsUnitContract::new(request).unwrap();
        let rendered = String::from_utf8(contract.render()).unwrap();
        for line in [
            "DefaultDependencies=yes",
            "Type=notify",
            "KillMode=mixed",
            "Restart=no",
            "FileDescriptorStorePreserve=no",
            "FileDescriptorStoreMax=1",
            "User=1000",
            "Group=1000",
            "TimeoutStartSec=30000000us",
        ] {
            assert!(rendered.lines().any(|v| v == line));
        }
        assert!(rendered.contains("ExecStart=:\"/private/worker\" \"__os-service\""));
        assert!(rendered.contains("space %% $ \\\" \\\\\""));
        assert_eq!(
            contract.file_digest(),
            ContentDigest::sha256(&contract.render())
        );
    }
    #[test]
    fn constructor_rejects_injection_invalid_paths_and_user_identity_before_effects() {
        for path in [
            "relative",
            "/private/../other",
            "/private//other",
            "/private/./other",
            "/private/worker\nExecStart=/bin/sh",
        ] {
            let mut request = input();
            request.worker = path.into();
            assert!(OsUnitContract::new(request).is_err());
        }
        for (uid, gid) in [(0, 1000), (1000, 0), (u32::MAX, 1000)] {
            let mut request = input();
            request.uid = uid;
            request.gid = gid;
            assert!(OsUnitContract::new(request).is_err());
        }
        let mut request = input();
        request.scope = SystemdScope::User {
            bus_socket: "/run/user/1000/bus".into(),
        };
        request.uid = super::super::bus::caller_ids().0.wrapping_add(1);
        assert!(OsUnitContract::new(request).is_err());
        let mut request = input();
        request.scope = SystemdScope::User {
            bus_socket: "/run/user/1000/bus".into(),
        };
        request.uid = super::super::bus::caller_ids().0;
        request.gid = super::super::bus::caller_ids().2.wrapping_add(1);
        assert!(OsUnitContract::new(request).is_err());
    }

    #[test]
    fn explicit_restart_changes_unit_pin_and_preserves_reserved_envelope() {
        let never = OsUnitContract::new(input()).unwrap();
        let mut value = input();
        value.restart = crate::execution::restart::ProcessRestart::OnFailure(
            crate::execution::restart::RestartLimits::new(2, 30, 4).unwrap(),
        );
        let retry = OsUnitContract::new(value).unwrap();
        assert_ne!(never.file_digest(), retry.file_digest());
        let text = String::from_utf8(retry.render()).unwrap();
        for line in [
            "Restart=on-failure",
            "RestartSec=2000000us",
            "StartLimitIntervalSec=30000000us",
            "StartLimitBurst=4",
            "StartLimitAction=none",
            "RestartPreventExitStatus=78",
            "RestartForceExitStatus=",
            "SuccessExitStatus=",
        ] {
            assert!(text.lines().any(|found| found == line), "{line}");
        }
    }
}

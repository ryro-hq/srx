use super::persistent::OsUnitContract;
use super::{
    Budget, Cancellation, SERVICE_INTERFACE, SystemdError, SystemdManager, SystemdManagerIdentity,
    SystemdScope, SystemdUnitName, UNIT_INTERFACE,
};
use crate::store::ContentDigest;
use serde::Serialize;
use std::time::Duration;

const MAX_OBSERVATION: usize = 64 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct ExecSpec {
    pub(super) path: String,
    pub(super) argv: Vec<String>,
    pub(super) flags: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) enum Value {
    Text(String),
    Strings(Vec<String>),
    Bool(bool),
    U32(u32),
    I32(i32),
    U64(u64),
    Exec(Vec<ExecSpec>),
    ExitStatuses {
        codes: Vec<i32>,
        signals: Vec<i32>,
    },
    Empty(String),
}
impl Value {
    pub(super) fn signature(&self) -> &str {
        match self {
            Self::Text(_) => "s",
            Self::Strings(_) => "as",
            Self::Bool(_) => "b",
            Self::U32(_) => "u",
            Self::I32(_) => "i",
            Self::U64(_) => "t",
            Self::Exec(_) => "a(sasasttttuii)",
            Self::ExitStatuses {
                ..
            } => "(aiai)",
            Self::Empty(signature) => signature,
        }
    }
}
pub(super) struct Property {
    pub(super) interface: &'static str,
    pub(super) name: &'static str,
    pub(super) expected: Value,
    pub(super) extra: Vec<String>,
}
#[derive(Debug)]
pub(crate) struct LoadedOsUnitObserved {
    manager: SystemdManagerIdentity,
    unit: SystemdUnitName,
    fingerprint: ContentDigest,
}
impl LoadedOsUnitObserved {
    pub(crate) fn manager(&self) -> &SystemdManagerIdentity {
        &self.manager
    }
    pub(crate) fn unit(&self) -> &SystemdUnitName {
        &self.unit
    }
    /// Versioned digest of the checked properties, not of the published file.
    pub(crate) fn fingerprint(&self) -> ContentDigest {
        self.fingerprint
    }
}
impl SystemdManager {
    pub(crate) fn observe_os_unit(
        &mut self,
        contract: &OsUnitContract,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<LoadedOsUnitObserved, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        if &self.scope != contract.scope() {
            return Err(SystemdError::Invalid(
                "Os unit scope differs from manager",
            ));
        }
        let mut reference = self.load_unit_reference(contract.unit(), &budget)?;
        let manager = reference.manager_identity().clone();
        let path = reference.object_path().to_owned();
        let outcome = (|| {
            self.bus.watch_loaded(&path, &budget)?;
            loop {
                let revision = self.bus.configuration_revision();
                let properties = properties(contract);
                let first = observe(self, &path, &properties, &budget)?;
                let second = observe(self, &path, &properties, &budget)?;
                let final_reload = read(
                    self,
                    &path,
                    &Property {
                        interface: UNIT_INTERFACE,
                        name: "NeedDaemonReload",
                        expected: Value::Bool(false),
                        extra: vec![],
                    },
                    &budget,
                )?;
                if first != second
                    || final_reload != Value::Bool(false)
                    || self.observe_identity_with(&budget)? != manager
                {
                    return Err(invalid(
                        "loaded Os unit changed during observation",
                    ));
                }
                if self.bus.configuration_revision() != revision {
                    // Discard the whole observation. Load/reload may still deliver
                    // queued signals; approval needs a fresh, unchanged bracket.
                    budget.check()?;
                    continue;
                }
                budget.check()?;
                let mut bytes = b"syrox-loaded-os-unit-v1\n".to_vec();
                bytes.extend(
                    serde_json::to_vec(&(
                        manager.fingerprint().to_string(),
                        contract.unit().as_str(),
                        first,
                    ))
                    .map_err(|_| invalid("cannot encode loaded unit observation"))?,
                );
                if bytes.len() > MAX_OBSERVATION {
                    return Err(invalid("loaded unit observation exceeds limit"));
                }
                return Ok(LoadedOsUnitObserved {
                    manager,
                    unit: contract.unit().clone(),
                    fingerprint: ContentDigest::sha256(&bytes),
                });
            }
        })();
        // Metadata retention is connection-scoped and grants no start authority.
        // Release also after cancellation/failure, with a separate cleanup budget.
        let cleanup = self.unreference_unit(
            &mut reference,
            Duration::from_secs(1),
            &Cancellation::default(),
        );
        match (outcome, cleanup) {
            (Ok(observed), Ok(())) => Ok(observed),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
}
fn invalid(message: &'static str) -> SystemdError {
    SystemdError::Protocol(message)
}
pub(super) fn observe(
    manager: &mut SystemdManager,
    path: &str,
    properties: &[Property],
    budget: &Budget<'_>,
) -> Result<Vec<(String, Value)>, SystemdError> {
    let mut output = Vec::new();
    let mut bytes = 0usize;
    for property in properties {
        budget.check()?;
        let value = read(manager, path, property, budget)?;
        validate(property, &value)?;
        bytes = bytes
            .checked_add(
                serde_json::to_vec(&value)
                    .map_err(|_| invalid("cannot encode property"))?
                    .len(),
            )
            .filter(|total| *total <= MAX_OBSERVATION)
            .ok_or_else(|| invalid("loaded properties exceed limit"))?;
        output.push((
            format!("{}.{}", property.interface, property.name),
            value,
        ));
    }
    Ok(output)
}
pub(super) fn validate(property: &Property, value: &Value) -> Result<(), SystemdError> {
    if property.extra.is_empty() {
        if &property.expected == value {
            return Ok(());
        }
    } else if let (Value::Strings(required), Value::Strings(actual)) = (&property.expected, value)
        && required.iter().all(|v| actual.contains(v))
        && actual
            .iter()
            .all(|v| required.contains(v) || property.extra.contains(v))
    {
        return Ok(());
    }
    Err(SystemdError::Remote {
        name: "syrox.UnsupportedLoadedUnit".into(),
        message: format!("loaded Os property differs: {}", property.name),
    })
}
fn read(
    manager: &mut SystemdManager,
    path: &str,
    p: &Property,
    budget: &Budget<'_>,
) -> Result<Value, SystemdError> {
    let reply = manager
        .bus
        .get(path, p.interface, p.name, budget)?;
    decode(&reply.0, &p.expected)
}
fn decode(frame: &super::wire::Frame, expected: &Value) -> Result<Value, SystemdError> {
    if frame.signature != "v" || frame.body.len() > MAX_OBSERVATION {
        return Err(invalid("invalid loaded property envelope"));
    }
    let mut r = frame.reader();
    let signature = r.sig()?;
    if signature != expected.signature() {
        return Err(invalid("unexpected loaded property signature"));
    }
    let value = match expected {
        Value::Text(_) => Value::Text(r.string()?.into()),
        Value::Strings(_) => {
            let mut list = strings(&mut r)?;
            list.sort();
            if list.windows(2).any(|v| v[0] == v[1]) {
                return Err(invalid("duplicate property entry"));
            }
            Value::Strings(list)
        }
        Value::Bool(_) => Value::Bool(match r.u32()? {
            0 => false,
            1 => true,
            _ => return Err(invalid("invalid boolean")),
        }),
        Value::U32(_) => Value::U32(r.u32()?),
        Value::I32(_) => Value::I32(i32::from_ne_bytes(r.u32()?.to_ne_bytes())),
        Value::U64(_) => Value::U64(r.u64()?),
        Value::ExitStatuses {
            ..
        } => {
            r.align(8)?;
            Value::ExitStatuses {
                codes: exit_statuses(&mut r, 255)?,
                signals: exit_statuses(&mut r, 64)?,
            }
        }
        Value::Empty(sig) => {
            let end = r.array_end(if sig == "as" {
                4
            } else {
                8
            })?;
            if r.pos != end {
                return Err(invalid("unexpected nonempty property"));
            }
            Value::Empty(sig.clone())
        }
        Value::Exec(_) => {
            let end = r.array_end(8)?;
            let mut list = Vec::new();
            while r.pos < end {
                if !list.is_empty() {
                    return Err(invalid("multiple launcher commands"));
                }
                r.align(8)?;
                let path = r.string()?.into();
                let argv = strings(&mut r)?;
                let flags = strings(&mut r)?;
                for _ in 0..4 {
                    r.u64()?;
                }
                for _ in 0..3 {
                    r.u32()?;
                }
                list.push(ExecSpec {
                    path,
                    argv,
                    flags,
                });
            }
            if r.pos != end {
                return Err(invalid("command array boundary"));
            }
            Value::Exec(list)
        }
    };
    r.end()?;
    Ok(value)
}
fn strings(r: &mut super::wire::Reader<'_>) -> Result<Vec<String>, SystemdError> {
    let end = r.array_end(4)?;
    let mut list = Vec::new();
    while r.pos < end {
        if list.len() >= 32 {
            return Err(invalid("property string count exceeded"));
        }
        list.push(r.string()?.into());
    }
    if r.pos != end {
        return Err(invalid("string array boundary"));
    }
    Ok(list)
}
fn exit_statuses(r: &mut super::wire::Reader<'_>, maximum: i32) -> Result<Vec<i32>, SystemdError> {
    let end = r.array_end(4)?;
    let mut values = Vec::new();
    while r.pos < end {
        let value = i32::from_ne_bytes(r.u32()?.to_ne_bytes());
        if !(0..=maximum).contains(&value) || values.len() >= 256 {
            return Err(invalid("invalid exit status list"));
        }
        values.push(value);
    }
    if r.pos != end {
        return Err(invalid("invalid exit status array boundary"));
    }
    values.sort_unstable();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("duplicate exit status"));
    }
    Ok(values)
}
pub(super) fn properties(c: &OsUnitContract) -> Vec<Property> {
    let mut p = Vec::new();
    unit_properties(c, &mut p);
    service_properties(c, &mut p);
    restart_properties(c, &mut p);
    dependency_properties(c, &mut p);
    p
}
fn restart_properties(c: &OsUnitContract, p: &mut Vec<Property>) {
    let (mode, delay, window, burst) = c.restart_properties();
    for (interface, name, expected) in [
        (
            SERVICE_INTERFACE,
            "Restart",
            Value::Text(mode.into()),
        ),
        (
            SERVICE_INTERFACE,
            "RestartUSec",
            Value::U64(delay),
        ),
        (
            UNIT_INTERFACE,
            "StartLimitIntervalUSec",
            Value::U64(window),
        ),
        (
            UNIT_INTERFACE,
            "StartLimitBurst",
            Value::U32(burst),
        ),
        (
            UNIT_INTERFACE,
            "StartLimitAction",
            Value::Text("none".into()),
        ),
        (
            SERVICE_INTERFACE,
            "RestartPreventExitStatus",
            Value::ExitStatuses {
                codes: vec![78],
                signals: vec![],
            },
        ),
        (
            SERVICE_INTERFACE,
            "RestartForceExitStatus",
            Value::ExitStatuses {
                codes: vec![],
                signals: vec![],
            },
        ),
        (
            SERVICE_INTERFACE,
            "SuccessExitStatus",
            Value::ExitStatuses {
                codes: vec![],
                signals: vec![],
            },
        ),
    ] {
        p.push(Property {
            interface,
            name,
            expected,
            extra: vec![],
        });
    }
}
fn unit_properties(c: &OsUnitContract, p: &mut Vec<Property>) {
    let mut add = |interface, name, expected| {
        p.push(Property {
            interface,
            name,
            expected,
            extra: vec![],
        });
    };
    for (name, value) in [
        ("Id", c.unit().as_str()),
        ("LoadState", "loaded"),
        (
            "FragmentPath",
            c.input.fragment.to_str().expect("validated"),
        ),
        ("SourcePath", ""),
        ("CollectMode", "inactive"),
    ] {
        add(UNIT_INTERFACE, name, Value::Text(value.into()));
    }
    for (name, value) in [
        ("Transient", false),
        ("NeedDaemonReload", false),
        ("DefaultDependencies", true),
        ("StopWhenUnneeded", false),
    ] {
        add(UNIT_INTERFACE, name, Value::Bool(value));
    }
    for name in [
        "DropInPaths",
        "OnFailure",
        "OnSuccess",
        "BindsTo",
        "PartOf",
        "Requisite",
    ] {
        add(UNIT_INTERFACE, name, Value::Strings(vec![]));
    }
    for name in ["Conditions", "Asserts"] {
        add(
            UNIT_INTERFACE,
            name,
            Value::Empty("a(sbbsi)".into()),
        );
    }
}
fn service_properties(c: &OsUnitContract, p: &mut Vec<Property>) {
    // No condition/pre/post/stop/reload executor is allowed outside the single
    // authenticated MainPID inventory. A live manager control process refuses it.
    p.push(Property {
        interface: SERVICE_INTERFACE,
        name: "ControlPID",
        expected: Value::U32(0),
        extra: vec![],
    });
    let mut add = |interface, name, expected| {
        p.push(Property {
            interface,
            name,
            expected,
            extra: vec![],
        });
    };
    for (name, value) in [
        ("Type", "notify"),
        ("ExitType", "cgroup"),
        ("KillMode", "mixed"),
        ("NotifyAccess", "main"),
        ("FileDescriptorStorePreserve", "no"),
        ("WorkingDirectory", "/"),
        ("RootDirectory", ""),
        ("RootImage", ""),
        ("Slice", c.slice()),
        ("StandardInput", "null"),
        ("StandardOutput", "journal"),
        ("StandardError", "journal"),
    ] {
        add(SERVICE_INTERFACE, name, Value::Text(value.into()));
    }
    add(
        SERVICE_INTERFACE,
        "User",
        Value::Text(c.input.uid.to_string()),
    );
    add(
        SERVICE_INTERFACE,
        "Group",
        Value::Text(c.input.gid.to_string()),
    );
    for (name, value) in [
        ("SendSIGKILL", true),
        ("NoNewPrivileges", true),
        ("RemainAfterExit", false),
        ("Delegate", false),
        ("DynamicUser", false),
    ] {
        add(SERVICE_INTERFACE, name, Value::Bool(value));
    }
    for (name, value) in [
        ("FileDescriptorStoreMax", 1),
        ("UMask", 0o77),
    ] {
        add(SERVICE_INTERFACE, name, Value::U32(value));
    }
    for (name, value) in [
        ("KillSignal", libc::SIGTERM),
        ("FinalKillSignal", libc::SIGKILL),
    ] {
        add(SERVICE_INTERFACE, name, Value::I32(value));
    }
    for (name, value) in [
        ("TimeoutStartUSec", c.input.start_timeout),
        ("TimeoutStopUSec", c.input.stop_timeout),
    ] {
        add(
            SERVICE_INTERFACE,
            name,
            Value::U64(u64::try_from(value.as_micros()).expect("bounded")),
        );
    }
    for name in [
        "Environment",
        "PassEnvironment",
        "UnsetEnvironment",
    ] {
        add(SERVICE_INTERFACE, name, Value::Strings(vec![]));
    }
    add(
        SERVICE_INTERFACE,
        "EnvironmentFiles",
        Value::Empty("a(sb)".into()),
    );
    add(
        SERVICE_INTERFACE,
        "ExecStartEx",
        Value::Exec(vec![ExecSpec {
            path: c.argv[0].clone(),
            argv: c.argv.clone(),
            flags: vec!["no-env-expand".into()],
        }]),
    );
    for name in [
        "ExecConditionEx",
        "ExecStartPreEx",
        "ExecStartPostEx",
        "ExecReloadEx",
        "ExecStopEx",
        "ExecStopPostEx",
    ] {
        add(
            SERVICE_INTERFACE,
            name,
            Value::Empty("a(sasasttttuii)".into()),
        );
    }
}
fn dependency_properties(c: &OsUnitContract, p: &mut Vec<Property>) {
    let system = matches!(c.scope(), SystemdScope::System);
    for (name, required, extra) in [
        (
            "Requires",
            vec![
                if system {
                    "sysinit.target"
                } else {
                    "basic.target"
                },
                c.slice(),
            ],
            vec!["-.mount", "systemd-journald.socket"],
        ),
        (
            "After",
            if system {
                vec![
                    "sysinit.target",
                    "basic.target",
                    c.slice(),
                ]
            } else {
                vec!["basic.target", c.slice()]
            },
            vec!["-.mount", "systemd-journald.socket"],
        ),
        (
            "Before",
            vec!["shutdown.target"],
            vec![if system {
                "multi-user.target"
            } else {
                "default.target"
            }],
        ),
        ("Conflicts", vec!["shutdown.target"], vec![]),
        ("Wants", vec![], vec!["systemd-journald.socket"]),
    ] {
        let mut required: Vec<String> = required.into_iter().map(str::to_owned).collect();
        required.sort();
        p.push(Property {
            interface: UNIT_INTERFACE,
            name,
            expected: Value::Strings(required),
            extra: extra.into_iter().map(str::to_owned).collect(),
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd::wire::{Frame, Writer};
    fn contract() -> OsUnitContract {
        OsUnitContract::new(super::super::persistent::tests::input()).unwrap()
    }
    fn frame(signature: &str, body: Vec<u8>) -> Frame {
        Frame {
            kind: 2,
            reply: 1,
            sender: ":1.2".into(),
            path: String::new(),
            interface: String::new(),
            member: String::new(),
            error: String::new(),
            signature: signature.into(),
            body,
            little: true,
        }
    }
    #[test]
    fn same_fragment_does_not_authorize_changed_effective_commands_or_policy() {
        let properties = properties(&contract());
        for name in [
            "ExecStartEx",
            "Restart",
            "NotifyAccess",
            "FileDescriptorStorePreserve",
            "FileDescriptorStoreMax",
            "NeedDaemonReload",
            "DropInPaths",
        ] {
            let p = properties
                .iter()
                .find(|p| p.name == name)
                .unwrap();
            let changed = match &p.expected {
                Value::Text(_) => Value::Text("changed".into()),
                Value::U32(_) => Value::U32(2),
                Value::Bool(_) => Value::Bool(true),
                Value::Strings(_) => Value::Strings(vec!["/evil.conf".into()]),
                Value::Exec(v) => {
                    let mut v = v.clone();
                    v[0].argv.push("extra".into());
                    Value::Exec(v)
                }
                _ => panic!("unexpected"),
            };
            assert!(validate(p, &changed).is_err());
            assert!(validate(p, &p.expected).is_ok());
        }
    }
    #[test]
    fn defaults_are_bounded_and_unknown_dependencies_are_rejected() {
        let properties = properties(&contract());
        let p = properties
            .iter()
            .find(|p| p.name == "Requires")
            .unwrap();
        let Value::Strings(mut values) = p.expected.clone() else {
            panic!()
        };
        values.push("-.mount".into());
        assert!(validate(p, &Value::Strings(values.clone())).is_ok());
        values.push("unrelated.service".into());
        assert!(validate(p, &Value::Strings(values)).is_err());
    }
    #[test]
    fn strict_property_decoder_rejects_bad_booleans_signatures_and_array_boundaries() {
        let mut w = Writer::default();
        w.sig("b").unwrap();
        w.u32(2);
        assert!(decode(&frame("v", w.0), &Value::Bool(false)).is_err());
        let mut w = Writer::default();
        w.sig("as").unwrap();
        w.u32(u32::MAX);
        assert!(decode(&frame("v", w.0), &Value::Strings(vec![])).is_err());
        let mut w = Writer::default();
        w.sig("s").unwrap();
        w.string("loaded").unwrap();
        assert!(decode(&frame("v", w.0), &Value::Bool(false)).is_err());
        let mut w = Writer::default();
        w.sig("b").unwrap();
        w.u32(1);
        assert_eq!(
            decode(&frame("v", w.0), &Value::Bool(false)).unwrap(),
            Value::Bool(true)
        );
    }

    fn exec_frame(executable: &ExecSpec, timestamp: u64) -> Frame {
        let mut w = Writer::default();
        w.sig("a(sasasttttuii)").unwrap();
        w.array(8, |w| {
            w.align(8);
            w.string(&executable.path)?;
            w.strings(&executable.argv)?;
            w.strings(&executable.flags)?;
            for _ in 0..4 {
                w.align(8);
                w.0.extend(timestamp.to_le_bytes());
            }
            for _ in 0..3 {
                w.u32(42);
            }
            Ok(())
        })
        .unwrap();
        frame("v", w.0)
    }
    #[test]
    fn exec_ex_preserves_flags_and_arguments_but_excludes_last_run_status() {
        let contract = contract();
        let properties = properties(&contract);
        let p = properties
            .iter()
            .find(|p| p.name == "ExecStartEx")
            .unwrap();
        let Value::Exec(executable) = &p.expected else {
            panic!()
        };
        for timestamp in [0, 987_654_321] {
            assert_eq!(
                decode(
                    &exec_frame(&executable[0], timestamp),
                    &p.expected
                )
                .unwrap(),
                p.expected
            );
        }
        let mut changed = executable[0].clone();
        changed.flags.push("ignore-failure".into());
        let decoded = decode(&exec_frame(&changed, 0), &p.expected).unwrap();
        assert!(validate(p, &decoded).is_err());
        let mut malformed = exec_frame(&executable[0], 0);
        malformed.body.pop();
        assert!(decode(&malformed, &p.expected).is_err());
    }
    #[test]
    fn u64_properties_support_both_endians_and_reject_trailing_bytes() {
        let mut w = Writer::default();
        w.sig("t").unwrap();
        w.align(8);
        w.0.extend(987_654_321u64.to_le_bytes());
        let mut reply = frame("v", w.0);
        assert_eq!(
            decode(&reply, &Value::U64(0)).unwrap(),
            Value::U64(987_654_321)
        );
        reply.little = false;
        reply.body[8..16].copy_from_slice(&987_654_321u64.to_be_bytes());
        assert_eq!(
            decode(&reply, &Value::U64(0)).unwrap(),
            Value::U64(987_654_321)
        );
        reply.body.push(0);
        assert!(decode(&reply, &Value::U64(0)).is_err());
    }
    #[test]
    #[ignore = "requires real user manager and a separately provisioned exact Os unit; never starts it"]
    fn real_loaded_os_unit_observation_gate() {
        use std::path::PathBuf;
        let env =
            |name| PathBuf::from(std::env::var_os(name).expect("explicit fixture field required"));
        let (uid, _, gid, _) = super::super::bus::caller_ids();
        let mut input = super::super::persistent::tests::input();
        input.scope = SystemdScope::User {
            bus_socket: env("SYROX_SYSTEMD_USER_BUS"),
        };
        input.unit =
            SystemdUnitName::new(std::env::var("SYROX_OS_UNIT_NAME").expect("unit")).unwrap();
        input.fragment = env("SYROX_OS_UNIT_FRAGMENT");
        input.worker = env("SYROX_OS_UNIT_WORKER");
        input.installation = env("SYROX_OS_UNIT_INSTALLATION");
        input.store = env("SYROX_OS_UNIT_STORE");
        input.binding = std::env::var("SYROX_OS_UNIT_BINDING")
            .expect("binding")
            .parse()
            .unwrap();
        input.uid = uid;
        input.gid = gid;
        let expected = OsUnitContract::new(input).unwrap();
        let cancellation = Cancellation::default();
        let timeout = Duration::from_secs(30);
        let mut manager =
            SystemdManager::connect(expected.scope().clone(), timeout, &cancellation).unwrap();
        let observation = manager
            .observe_os_unit(&expected, timeout, &cancellation)
            .unwrap();
        assert_eq!(observation.unit(), expected.unit());
        assert_eq!(observation.manager().scope(), expected.scope());
        assert_ne!(observation.fingerprint(), expected.file_digest());
    }

    #[test]
    fn restart_properties_and_status_sets_are_exact() {
        let mut input = super::super::persistent::tests::input();
        input.restart = crate::execution::restart::ProcessRestart::OnFailure(
            crate::execution::restart::RestartLimits::new(2, 30, 4).unwrap(),
        );
        let p = properties(&OsUnitContract::new(input).unwrap());
        for name in [
            "Restart",
            "RestartUSec",
            "StartLimitIntervalUSec",
            "StartLimitBurst",
            "StartLimitAction",
            "RestartPreventExitStatus",
            "RestartForceExitStatus",
            "SuccessExitStatus",
        ] {
            let property = p.iter().find(|p| p.name == name).unwrap();
            assert!(validate(property, &property.expected).is_ok());
            let changed = match &property.expected {
                Value::Text(_) => Value::Text("changed".into()),
                Value::U32(v) => Value::U32(v + 1),
                Value::U64(v) => Value::U64(v + 1),
                Value::ExitStatuses {
                    ..
                } => Value::ExitStatuses {
                    codes: vec![1],
                    signals: vec![],
                },
                _ => panic!("unexpected restart property"),
            };
            assert!(validate(property, &changed).is_err());
        }
    }
    #[test]
    fn exit_status_codec_rejects_signal_substitution_duplicates_and_truncation() {
        fn encoded(codes: &[u32], signals: &[u32]) -> Vec<u8> {
            let mut w = Writer::default();
            w.sig("(aiai)").unwrap();
            w.align(8);
            for values in [codes, signals] {
                w.array(4, |w| {
                    for value in values {
                        w.u32(*value);
                    }
                    Ok(())
                })
                .unwrap();
            }
            w.0
        }
        let expected = Value::ExitStatuses {
            codes: vec![78],
            signals: vec![],
        };
        assert_eq!(
            decode(&frame("v", encoded(&[78], &[])), &expected).unwrap(),
            expected
        );
        assert_ne!(
            decode(&frame("v", encoded(&[], &[15])), &expected).unwrap(),
            expected
        );
        for mut bytes in [
            encoded(&[78, 78], &[]),
            encoded(&[256], &[]),
            encoded(&[], &[65]),
        ] {
            assert!(decode(&frame("v", bytes.clone()), &expected).is_err());
            bytes.pop();
            assert!(decode(&frame("v", bytes), &expected).is_err());
        }
    }
}

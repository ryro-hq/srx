use super::loaded::{ExecSpec, Property as LoadedProperty, Value as LoadedValue};
use super::{
    SERVICE_INTERFACE, SystemdError, SystemdService, SystemdServiceProfile, UNIT_INTERFACE,
    absolute, text,
};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Value {
    String(String),
    Bool(bool),
    U64(u64),
    U32(u32),
    Strings(Vec<String>),
    ExitStatuses {
        codes: Vec<i32>,
        signals: Vec<i32>,
    },
    Exec {
        executable: String,
        argv: Vec<String>,
    },
}
impl Value {
    pub(super) fn signature(&self) -> &'static str {
        match self {
            Self::String(_) => "s",
            Self::Bool(_) => "b",
            Self::U64(_) => "t",
            Self::U32(_) => "u",
            Self::Strings(_) => "as",
            Self::ExitStatuses {
                ..
            } => "(aiai)",
            Self::Exec {
                ..
            } => "a(sasas)",
        }
    }
}
pub(super) type Property = (&'static str, Value);

pub(super) fn service(service: &SystemdService) -> Result<Vec<Property>, SystemdError> {
    let executable = absolute(&service.executable)?.to_owned();
    if service.arguments.len() > 256 || service.environment.len() > 128 {
        return Err(SystemdError::Invalid(
            "argument or environment count exceeded",
        ));
    }
    if service.stop_timeout.is_zero() || service.stop_timeout > std::time::Duration::from_secs(60) {
        return Err(SystemdError::Invalid(
            "stop timeout must be in (0, 60s]",
        ));
    }
    let mut bytes = executable.len();
    let mut argv = vec![executable.clone()];
    for value in &service.arguments {
        text(value)?;
        bytes += value.len();
        argv.push(value.clone());
    }
    let mut environment = Vec::new();
    for (key, value) in &service.environment {
        if key.is_empty()
            || !key.bytes().enumerate().all(|(i, b)| {
                b == b'_' || b.is_ascii_alphabetic() || (i != 0 && b.is_ascii_digit())
            })
        {
            return Err(SystemdError::Invalid("invalid environment name"));
        }
        text(key)?;
        text(value)?;
        bytes += key.len() + value.len() + 1;
        environment.push(format!("{key}={value}"));
    }
    if bytes > 64 * 1024 {
        return Err(SystemdError::Invalid(
            "argv/environment byte limit exceeded",
        ));
    }
    let (kind, kill_mode) = profile(&service.profile)?;
    let mut result = vec![
        ("Type", Value::String(kind.into())),
        ("ExitType", Value::String("cgroup".into())),
        ("KillMode", Value::String(kill_mode.into())),
        ("SendSIGKILL", Value::Bool(true)),
        ("NoNewPrivileges", Value::Bool(true)),
        ("CollectMode", Value::String("inactive".into())),
        (
            "TimeoutStopUSec",
            Value::U64(micros(service.stop_timeout)?),
        ),
        ("UMask", Value::U32(0o077)),
        (
            "ExecStartEx",
            Value::Exec {
                executable,
                argv,
            },
        ),
        ("Environment", Value::Strings(environment)),
    ];
    result.extend(restart(service)?);
    if let SystemdServiceProfile::Notify {
        fd_store_max,
        start_timeout,
    } = &service.profile
    {
        result.push(("NotifyAccess", Value::String("main".into())));
        result.push((
            "FileDescriptorStoreMax",
            Value::U32(*fd_store_max),
        ));
        result.push((
            "TimeoutStartUSec",
            Value::U64(micros(*start_timeout)?),
        ));
    }
    if let Some(owner) = &service.bound_to {
        if owner == &service.unit {
            return Err(SystemdError::Invalid(
                "unit cannot bind to itself",
            ));
        }
        result.push((
            "BindsTo",
            Value::Strings(vec![owner.as_str().into()]),
        ));
        result.push((
            "After",
            Value::Strings(vec![owner.as_str().into()]),
        ));
    }
    if let Some(directory) = &service.working_directory {
        result.push((
            "WorkingDirectory",
            Value::String(absolute(directory)?.into()),
        ));
    }
    if let Some(limit) = service.runtime_max {
        if limit.is_zero() || limit > std::time::Duration::from_hours(8760) {
            return Err(SystemdError::Invalid(
                "runtime limit must be in (0, 365 days]",
            ));
        }
        result.push(("RuntimeMaxUSec", Value::U64(micros(limit)?)));
    }
    for (name, limit) in [
        ("MemoryMax", service.memory_max),
        ("TasksMax", service.tasks_max),
    ] {
        if let Some(limit) = limit {
            if limit == 0 || limit == u64::MAX {
                return Err(SystemdError::Invalid(
                    "resource limit must be finite and positive",
                ));
            }
            result.push((name, Value::U64(limit)));
        }
    }
    if let Some(credentials) = service.credentials {
        result.extend(credential_properties(credentials)?);
    }
    if let Some(limits) = service.build_limits {
        result.extend(build_limits(limits)?);
        result.extend(build_retention_policy(&service.profile));
    }
    Ok(result)
}

fn build_retention_policy(profile: &SystemdServiceProfile) -> Option<Property> {
    // v254 supports this explicit policy; do not depend on default restart.
    matches!(profile, SystemdServiceProfile::Notify { .. }).then(|| {
        (
            "FileDescriptorStorePreserve",
            Value::String("no".into()),
        )
    })
}

fn restart(service: &SystemdService) -> Result<Vec<Property>, SystemdError> {
    let crate::execution::restart::ProcessRestart::OnFailure(limits) = service.restart else {
        return Ok(vec![("Restart", Value::String("no".into()))]);
    };
    if !matches!(
        service.profile,
        SystemdServiceProfile::Notify {
            fd_store_max: 1,
            ..
        }
    ) || service.bound_to.is_none()
        || service.build_limits.is_some()
    {
        return Err(SystemdError::Invalid(
            "restart requires an owner-bound notify service with one retention descriptor",
        ));
    }
    Ok(vec![
        ("Restart", Value::String("on-failure".into())),
        (
            "FileDescriptorStorePreserve",
            Value::String("no".into()),
        ),
        (
            "RestartUSec",
            Value::U64(u64::from(limits.delay_seconds()) * 1_000_000),
        ),
        (
            "StartLimitIntervalUSec",
            Value::U64(u64::from(limits.window_seconds()) * 1_000_000),
        ),
        ("StartLimitBurst", Value::U32(limits.burst())),
        ("StartLimitAction", Value::String("none".into())),
        (
            "RestartPreventExitStatus",
            Value::ExitStatuses {
                codes: vec![78],
                signals: vec![],
            },
        ),
        (
            "RestartForceExitStatus",
            Value::ExitStatuses {
                codes: vec![],
                signals: vec![],
            },
        ),
        (
            "SuccessExitStatus",
            Value::ExitStatuses {
                codes: vec![],
                signals: vec![],
            },
        ),
    ])
}

fn credential_properties(
    credentials: super::SystemdCredentials,
) -> Result<[Property; 2], SystemdError> {
    if matches!(credentials.uid, 0 | u32::MAX) || matches!(credentials.gid, 0 | u32::MAX) {
        return Err(SystemdError::Invalid(
            "service credentials must be nonroot concrete IDs",
        ));
    }
    Ok([
        ("User", Value::String(credentials.uid.to_string())),
        (
            "Group",
            Value::String(credentials.gid.to_string()),
        ),
    ])
}

fn build_limits(limits: super::SystemdBuildLimits) -> Result<Vec<Property>, SystemdError> {
    if limits.cpu_percent == 0
        || [limits.nofile, limits.file_size]
            .iter()
            .any(|value| *value == 0 || *value == u64::MAX)
    {
        return Err(SystemdError::Invalid(
            "build limits must be finite and positive",
        ));
    }
    // Native systemd properties use microseconds per second, not a percentage
    // string. Explicit Soft properties avoid inheriting the manager's soft limits.
    Ok(vec![
        (
            "CPUQuotaPerSecUSec",
            Value::U64(u64::from(limits.cpu_percent) * 10_000),
        ),
        ("LimitNOFILE", Value::U64(limits.nofile)),
        ("LimitNOFILESoft", Value::U64(limits.nofile)),
        ("LimitFSIZE", Value::U64(limits.file_size)),
        ("LimitFSIZESoft", Value::U64(limits.file_size)),
        ("MemorySwapMax", Value::U64(0)),
        ("LimitCORE", Value::U64(0)),
        ("LimitCORESoft", Value::U64(0)),
    ])
}
fn micros(duration: std::time::Duration) -> Result<u64, SystemdError> {
    u64::try_from(duration.as_micros())
        .ok()
        .filter(|value| *value > 0)
        .ok_or(SystemdError::Invalid(
            "microsecond duration is out of bounds",
        ))
}

fn profile(profile: &SystemdServiceProfile) -> Result<(&'static str, &'static str), SystemdError> {
    match profile {
        SystemdServiceProfile::Exec => Ok(("exec", "control-group")),
        SystemdServiceProfile::Notify {
            fd_store_max,
            start_timeout,
        } => {
            if *fd_store_max > 64
                || start_timeout.is_zero()
                || *start_timeout > super::MAX_OPERATION
            {
                return Err(SystemdError::Invalid(
                    "notify capacity/deadline exceeded",
                ));
            }
            Ok(("notify", "mixed"))
        }
    }
}

fn property_interface(name: &str) -> &'static str {
    if matches!(
        name,
        "CollectMode"
            | "BindsTo"
            | "After"
            | "StartLimitIntervalUSec"
            | "StartLimitBurst"
            | "StartLimitAction"
    ) {
        UNIT_INTERFACE
    } else {
        SERVICE_INTERFACE
    }
}
/// Expected properties used to independently observe a requested transient service.
pub(super) fn observed_transient(
    service: &SystemdService,
) -> Result<Vec<LoadedProperty>, SystemdError> {
    let mut result = Vec::new();
    for (name, value) in self::service(service)? {
        let interface = property_interface(name);
        let expected = match value {
            Value::String(value) => LoadedValue::Text(value),
            Value::Bool(value) => LoadedValue::Bool(value),
            Value::U64(value) => LoadedValue::U64(value),
            Value::U32(value) => LoadedValue::U32(value),
            Value::ExitStatuses {
                codes,
                signals,
            } => LoadedValue::ExitStatuses {
                codes,
                signals,
            },
            Value::Strings(mut values) => {
                values.sort();
                LoadedValue::Strings(values)
            }
            Value::Exec {
                executable,
                argv,
            } => LoadedValue::Exec(vec![ExecSpec {
                path: executable,
                argv,
                flags: vec!["no-env-expand".into()],
            }]),
        };
        result.push(LoadedProperty {
            interface,
            name,
            expected,
            extra: vec![],
        });
    }
    append_transient_defaults(&mut result, service);
    Ok(result)
}

/// Observe implicit manager defaults separately from explicitly requested properties.
/// Extra execution hooks, inherited environment and alternate roots stay forbidden.
fn append_transient_defaults(result: &mut Vec<LoadedProperty>, service: &SystemdService) {
    for (interface, name, expected) in [
        (
            UNIT_INTERFACE,
            "Transient",
            LoadedValue::Bool(true),
        ),
        (
            UNIT_INTERFACE,
            "NeedDaemonReload",
            LoadedValue::Bool(false),
        ),
        (
            SERVICE_INTERFACE,
            "RemainAfterExit",
            LoadedValue::Bool(false),
        ),
        (
            SERVICE_INTERFACE,
            "Delegate",
            LoadedValue::Bool(false),
        ),
        (
            SERVICE_INTERFACE,
            "DynamicUser",
            LoadedValue::Bool(false),
        ),
        (
            SERVICE_INTERFACE,
            "EnvironmentFiles",
            LoadedValue::Empty("a(sb)".into()),
        ),
        (
            SERVICE_INTERFACE,
            "PassEnvironment",
            LoadedValue::Strings(vec![]),
        ),
        (
            SERVICE_INTERFACE,
            "UnsetEnvironment",
            LoadedValue::Strings(vec![]),
        ),
        (
            SERVICE_INTERFACE,
            "RootDirectory",
            LoadedValue::Text(String::new()),
        ),
        (
            SERVICE_INTERFACE,
            "RootImage",
            LoadedValue::Text(String::new()),
        ),
        (
            SERVICE_INTERFACE,
            "KillSignal",
            LoadedValue::I32(libc::SIGTERM),
        ),
        (
            SERVICE_INTERFACE,
            "FinalKillSignal",
            LoadedValue::I32(libc::SIGKILL),
        ),
    ] {
        result.push(LoadedProperty {
            interface,
            name,
            expected,
            extra: vec![],
        });
    }
    if service.credentials.is_none() {
        for name in ["User", "Group"] {
            result.push(LoadedProperty {
                interface: SERVICE_INTERFACE,
                name,
                expected: LoadedValue::Text(String::new()),
                extra: vec![],
            });
        }
    }
    for name in [
        "ExecConditionEx",
        "ExecStartPreEx",
        "ExecStartPostEx",
        "ExecReloadEx",
        "ExecStopEx",
        "ExecStopPostEx",
    ] {
        result.push(LoadedProperty {
            interface: SERVICE_INTERFACE,
            name,
            expected: LoadedValue::Empty("a(sasasttttuii)".into()),
            extra: vec![],
        });
    }
}

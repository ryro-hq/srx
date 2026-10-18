//! Export the same wire interfaces used by requests and native observations.
use super::loaded::Property;
use super::persistent::{OsUnitContract, OsUnitInput};
use super::{
    MANAGER_INTERFACE, SERVICE_INTERFACE, SystemdBuildLimits, SystemdCredentials, SystemdError,
    SystemdScope, SystemdService, SystemdServiceProfile, SystemdUnitName, UNIT_INTERFACE, loaded,
    properties, service,
};
use crate::execution::restart::{ProcessRestart, RestartLimits};
use crate::store::ContentDigest;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::OnceLock;
use std::time::Duration;

const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
type Members = BTreeMap<String, BTreeMap<String, String>>;

/// Versioned host interfaces, derived from the engine's request and observation specifications.
#[derive(Clone, Debug, Serialize)]
pub struct SystemdInterfaceContract {
    schema: u32,
    id: &'static str,
    provider: &'static str,
    profiles: BTreeMap<&'static str, Profile>,
}

#[derive(Clone, Debug, Serialize)]
struct Profile {
    upstream_baseline: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    extends: Option<&'static str>,
    #[serde(flatten)]
    members: Members,
}

pub(super) struct Method {
    interface: &'static str,
    name: &'static str,
    pub(super) input: &'static str,
    pub(super) output: &'static str,
    managed: bool,
}

macro_rules! methods {
    ($(($interface:ident, $name:literal, $input:literal, $output:literal, $managed:literal)),* $(,)?) => {
        const METHODS: &[Method] = &[$(Method {
            interface: $interface, name: $name, input: $input, output: $output,
            managed: $managed,
        }),*];
    };
}
methods! {
    (MANAGER_INTERFACE, "GetUnit", "s", "o", false),
    (MANAGER_INTERFACE, "GetJob", "u", "o", false),
    (MANAGER_INTERFACE, "StartUnit", "ss", "o", false),
    (MANAGER_INTERFACE, "StopUnit", "ss", "o", false),
    (MANAGER_INTERFACE, "Reload", "", "", false),
    (MANAGER_INTERFACE, "StartTransientUnit", "ssa(sv)a(sa(sv))", "o", false),
    (MANAGER_INTERFACE, "Subscribe", "", "", false),
    (MANAGER_INTERFACE, "LoadUnit", "s", "o", true),
    (UNIT_INTERFACE, "Ref", "", "", true),
    (UNIT_INTERFACE, "Unref", "", "", true),
    (SERVICE_INTERFACE, "DumpFileDescriptorStore", "", "a(suuutuusu)", true),
    (PROPERTIES_INTERFACE, "Get", "ss", "v", false),
}

pub(super) fn method(interface: &str, name: &str) -> Result<Option<&'static Method>, SystemdError> {
    let known_interface = matches!(
        interface,
        MANAGER_INTERFACE | UNIT_INTERFACE | SERVICE_INTERFACE | PROPERTIES_INTERFACE
    );
    if !known_interface {
        // Bus authentication and ownership calls belong to org.freedesktop.DBus.
        return Ok(None);
    }
    METHODS
        .iter()
        .find(|method| method.interface == interface && method.name == name)
        .map(Some)
        .ok_or(SystemdError::Invalid(
            "method is absent from the host interface contract",
        ))
}

pub(super) struct Signal {
    pub(super) interface: &'static str,
    pub(super) name: &'static str,
    pub(super) signature: &'static str,
}
impl Signal {
    pub(super) fn rule(&self, path: Option<&str>) -> String {
        let mut rule = format!(
            "type='signal',sender='org.freedesktop.systemd1',interface='{}',member='{}'",
            self.interface, self.name
        );
        if let Some(path) = path {
            write!(rule, ",path='{path}'").expect("String write");
        }
        rule
    }
}
pub(super) const JOB_REMOVED: Signal = Signal {
    interface: MANAGER_INTERFACE,
    name: "JobRemoved",
    signature: "uoss",
};
pub(super) const UNIT_REMOVED: Signal = Signal {
    interface: MANAGER_INTERFACE,
    name: "UnitRemoved",
    signature: "so",
};
pub(super) const RELOADING: Signal = Signal {
    interface: MANAGER_INTERFACE,
    name: "Reloading",
    signature: "b",
};
pub(super) const PROPERTIES_CHANGED: Signal = Signal {
    interface: PROPERTIES_INTERFACE,
    name: "PropertiesChanged",
    signature: "sa{sv}as",
};

fn group(interface: &str, kind: &str) -> Result<String, SystemdError> {
    let name = match interface {
        MANAGER_INTERFACE => "manager",
        UNIT_INTERFACE => "unit",
        SERVICE_INTERFACE => "service",
        PROPERTIES_INTERFACE => "properties",
        _ => {
            return Err(SystemdError::Invalid(
                "unknown host contract interface",
            ));
        }
    };
    Ok(format!("{name}_{kind}"))
}

fn insert(
    members: &mut Members,
    interface: &str,
    kind: &str,
    name: &str,
    signature: &str,
) -> Result<(), SystemdError> {
    let previous = members
        .entry(group(interface, kind)?)
        .or_default()
        .insert(name.into(), signature.into());
    if previous
        .as_deref()
        .is_some_and(|previous| previous != signature)
    {
        return Err(SystemdError::Invalid(
            "conflicting host interface signatures",
        ));
    }
    Ok(())
}

fn observed(members: &mut Members, properties: Vec<Property>) -> Result<(), SystemdError> {
    for property in properties {
        insert(
            members,
            property.interface,
            "properties",
            property.name,
            property.expected.signature(),
        )?;
    }
    Ok(())
}

/// Build the host contract without a bus, executing services or observing the host.
/// Property signatures come from the actual transient, persistent and Shell observers.
pub fn interface_contract() -> Result<SystemdInterfaceContract, SystemdError> {
    let mut supervision = Members::new();
    let mut managed = Members::new();
    for method in METHODS {
        insert(
            if method.managed {
                &mut managed
            } else {
                &mut supervision
            },
            method.interface,
            "methods",
            method.name,
            &format!("{}->{}", method.input, method.output),
        )?;
    }
    for signal in [
        JOB_REMOVED,
        UNIT_REMOVED,
        RELOADING,
        PROPERTIES_CHANGED,
    ] {
        insert(
            &mut supervision,
            signal.interface,
            "signals",
            signal.name,
            signal.signature,
        )?;
    }
    // These status values are read directly by Bus rather than by loaded::observe.
    // Bus::get checks this same specification before accepting a variant reply.
    for (interface, name, signature) in [
        (UNIT_INTERFACE, "Id", "s"),
        (UNIT_INTERFACE, "InvocationID", "ay"),
        (UNIT_INTERFACE, "ActiveState", "s"),
        (UNIT_INTERFACE, "SubState", "s"),
        (UNIT_INTERFACE, "Job", "(uo)"),
        (SERVICE_INTERFACE, "ControlGroup", "s"),
        (SERVICE_INTERFACE, "Result", "s"),
        (SERVICE_INTERFACE, "MainPID", "u"),
        (SERVICE_INTERFACE, "ExecMainCode", "i"),
        (SERVICE_INTERFACE, "ExecMainStatus", "i"),
    ] {
        insert(
            &mut supervision,
            interface,
            "properties",
            name,
            signature,
        )?;
    }
    insert(
        &mut managed,
        SERVICE_INTERFACE,
        "properties",
        "NFileDescriptorStore",
        "u",
    )?;
    let mut request = SystemdService::new(
        SystemdUnitName::new("syrox-contract.service")?,
        "/contract/worker".into(),
    );
    request.working_directory = Some("/contract/work".into());
    request.runtime_max = Some(Duration::from_secs(60));
    request.memory_max = Some(1024 * 1024);
    request.tasks_max = Some(32);
    observed(
        &mut supervision,
        properties::observed_transient(&request)?,
    )?;
    request.credentials = Some(SystemdCredentials {
        uid: 1000,
        gid: 1000,
    });
    request.bound_to = Some(SystemdUnitName::new(
        "syrox-contract-owner.service",
    )?);
    request.profile = SystemdServiceProfile::Notify {
        fd_store_max: 1,
        start_timeout: Duration::from_secs(30),
    };
    observed(
        &mut managed,
        properties::observed_transient(&request)?,
    )?;
    for scope in [
        SystemdScope::System,
        SystemdScope::User {
            bus_socket: "/run/user/1000/bus".into(),
        },
    ] {
        observed(
            &mut managed,
            service::properties(&request, &scope)?,
        )?;
    }
    request.restart = ProcessRestart::OnFailure(
        RestartLimits::new(1, 10, 3)
            .map_err(|_| SystemdError::Invalid("invalid contract restart fixture"))?,
    );
    observed(
        &mut managed,
        properties::observed_transient(&request)?,
    )?;
    request.restart = ProcessRestart::Never;
    request.build_limits = Some(SystemdBuildLimits {
        cpu_percent: 100,
        nofile: 1024,
        file_size: 1024,
    });
    observed(
        &mut managed,
        properties::observed_transient(&request)?,
    )?;
    let mut persistent = OsUnitContract::new(OsUnitInput {
        unit: request.unit.clone(),
        scope: SystemdScope::System,
        worker: "/contract/worker".into(),
        installation: "/contract/installation".into(),
        store: "/contract/store".into(),
        binding: ContentDigest::sha256(b"contract interface fixture"),
        fragment: "/contract/syrox-contract.service".into(),
        uid: 1000,
        gid: 1000,
        start_timeout: Duration::from_secs(30),
        stop_timeout: Duration::from_secs(2),
        restart: ProcessRestart::Never,
    })?;
    observed(&mut managed, loaded::properties(&persistent))?;
    // Only extract property types for the user profile, without claiming a live UID.
    persistent.input.scope = SystemdScope::User {
        bus_socket: "/run/user/1000/bus".into(),
    };
    observed(&mut managed, loaded::properties(&persistent))?;
    for (group, members) in &mut managed {
        members.retain(|name, signature| {
            supervision
                .get(group)
                .and_then(|members| members.get(name))
                != Some(signature)
        });
    }
    managed.retain(|_, members| !members.is_empty());
    Ok(SystemdInterfaceContract {
        schema: 1,
        id: "syrox-systemd-v1",
        provider: "host",
        profiles: BTreeMap::from([
            (
                "supervision",
                Profile {
                    upstream_baseline: 250,
                    extends: None,
                    members: supervision,
                },
            ),
            (
                "managed",
                Profile {
                    upstream_baseline: 254,
                    extends: Some("supervision"),
                    members: managed,
                },
            ),
        ]),
    })
}

pub(super) fn property_signature(
    interface: &str,
    name: &str,
) -> Result<&'static str, SystemdError> {
    static CONTRACT: OnceLock<SystemdInterfaceContract> = OnceLock::new();
    let contract = CONTRACT
        .get_or_init(|| interface_contract().expect("valid internal host contract profiles"));
    let group = group(interface, "properties")?;
    for profile in contract.profiles.values() {
        if let Some(signature) = profile
            .members
            .get(&group)
            .and_then(|members| members.get(name))
        {
            return Ok(signature);
        }
    }
    Err(SystemdError::Invalid(
        "property is absent from the host interface contract",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_uses_native_observer_types_and_rejects_unregistered_requests() {
        let contract = interface_contract().unwrap();
        assert_eq!(
            contract.profiles["supervision"].members["service_properties"]["ExecStartEx"],
            "a(sasasttttuii)"
        );
        assert_eq!(
            contract.profiles["managed"].members["service_properties"]["CPUQuotaPerSecUSec"],
            "t"
        );
        assert_eq!(
            property_signature(UNIT_INTERFACE, "Job").unwrap(),
            "(uo)"
        );
        assert!(property_signature(SERVICE_INTERFACE, "UnknownProperty").is_err());
        assert!(method(MANAGER_INTERFACE, "UnknownMethod").is_err());
        assert!(
            method("org.freedesktop.DBus", "Hello")
                .unwrap()
                .is_none()
        );
    }
}

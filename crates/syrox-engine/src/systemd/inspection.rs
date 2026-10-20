//! Read-only comparison with the engine's canonical systemd wire contract.
use super::{
    Budget, Cancellation, MANAGER_PATH, SystemdError, SystemdManager, SystemdUnitName,
    contract::{self, Members},
};
use serde::Serialize;
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone, Debug, Serialize)]
pub struct MissingInterface {
    pub interface: String,
    pub member: String,
    pub expected: String,
    pub observed: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SystemdInterfaceInspection {
    pub profile: String,
    pub unit: String,
    pub manager_identity: String,
    pub missing: Vec<MissingInterface>,
    /// Observed signatures do not qualify execution permissions or lifecycle behavior.
    pub qualification: bool,
}

fn invalid(message: &'static str) -> SystemdError {
    SystemdError::Protocol(message)
}

fn observe(xml: &str, manager: bool, observed: &mut Members) -> Result<(), SystemdError> {
    if xml.len() > 1024 * 1024 || xml.contains("<!ENTITY") {
        return Err(invalid(
            "oversized or entity-bearing introspection",
        ));
    }
    // No resolver and no network I/O. D-Bus introspection may include its public
    // DOCTYPE. Entity declarations are rejected above and tree size is bounded.
    let document = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            nodes_limit: 50_000,
            entity_resolver: None,
        },
    )
    .map_err(|_| invalid("invalid systemd introspection XML"))?;
    if !document.root_element().has_tag_name("node") {
        return Err(invalid("introspection requires a node"));
    }
    for interface in document
        .root_element()
        .children()
        .filter(|node| node.has_tag_name("interface"))
    {
        let owner = match interface.attribute("name") {
            Some("org.freedesktop.systemd1.Manager") if manager => "manager",
            Some("org.freedesktop.systemd1.Unit") if !manager => "unit",
            Some("org.freedesktop.systemd1.Service") if !manager => "service",
            Some("org.freedesktop.DBus.Properties") if !manager => "properties",
            _ => continue,
        };
        for member in interface
            .children()
            .filter(roxmltree::Node::is_element)
        {
            let Some(name) = member.attribute("name") else {
                return Err(invalid("introspection member lacks a name"));
            };
            let (kind, signature) = match member.tag_name().name() {
                "method" => {
                    let mut input = String::new();
                    let mut output = String::new();
                    for arg in member
                        .children()
                        .filter(|node| node.has_tag_name("arg"))
                    {
                        let signature = arg
                            .attribute("type")
                            .ok_or_else(|| invalid("introspection arg lacks type"))?;
                        match arg.attribute("direction").unwrap_or("in") {
                            "in" => input.push_str(signature),
                            "out" => output.push_str(signature),
                            _ => return Err(invalid("invalid introspection direction")),
                        }
                    }
                    ("methods", format!("{input}->{output}"))
                }
                "signal" => {
                    let mut signature = String::new();
                    for arg in member
                        .children()
                        .filter(|node| node.has_tag_name("arg"))
                    {
                        signature.push_str(
                            arg.attribute("type")
                                .ok_or_else(|| invalid("introspection arg lacks type"))?,
                        );
                    }
                    ("signals", signature)
                }
                "property"
                    if matches!(
                        member.attribute("access"),
                        Some("read" | "readwrite")
                    ) =>
                {
                    (
                        "properties",
                        member
                            .attribute("type")
                            .ok_or_else(|| invalid("introspection property lacks type"))?
                            .into(),
                    )
                }
                _ => continue,
            };
            if observed
                .entry(format!("{owner}_{kind}"))
                .or_default()
                .insert(name.into(), signature)
                .is_some()
            {
                return Err(invalid("duplicate introspection member"));
            }
        }
    }
    Ok(())
}

impl SystemdManager {
    /// Observe existing objects only; `GetUnit` never loads or starts the selected unit.
    pub fn inspect_interfaces(
        &mut self,
        profile: &str,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<SystemdInterfaceInspection, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        let identity = self.observe_identity_with(&budget)?;
        let mut get = self.bus.manager_method("GetUnit")?;
        get.string(unit.as_str())?;
        let object = self.bus.call(get, &budget)?.single_object()?;
        let mut observed = BTreeMap::new();
        for (path, manager) in [
            (MANAGER_PATH, true),
            (object.as_str(), false),
        ] {
            let call = self.bus.method(
                "org.freedesktop.systemd1",
                path,
                "org.freedesktop.DBus.Introspectable",
                "Introspect",
            )?;
            let xml = self.bus.call(call, &budget)?.single_string()?;
            observe(&xml, manager, &mut observed)?;
        }
        if self.observe_identity_with(&budget)? != identity {
            return Err(invalid(
                "systemd manager changed during inspection",
            ));
        }
        Ok(SystemdInterfaceInspection {
            profile: profile.into(),
            unit: unit.as_str().into(),
            manager_identity: identity.fingerprint().to_string(),
            missing: missing(profile, &observed)?,
            qualification: false,
        })
    }
}

fn missing(profile: &str, observed: &Members) -> Result<Vec<MissingInterface>, SystemdError> {
    let contract = contract::interface_contract()?;
    let mut required = Members::new();
    let profiles: &[&str] = match profile {
        "supervision" => &["supervision"],
        "managed" => &["supervision", "managed"],
        _ => return Err(invalid("unknown systemd profile")),
    };
    for name in profiles {
        for (group, members) in &contract.profiles[name].members {
            required
                .entry(group.clone())
                .or_default()
                .extend(members.clone());
        }
    }
    let mut missing = Vec::new();
    for (group, members) in required {
        for (name, signature) in members {
            let actual = observed
                .get(&group)
                .and_then(|members| members.get(&name));
            if actual != Some(&signature) {
                missing.push(MissingInterface {
                    interface: group.clone(),
                    member: name,
                    expected: signature,
                    observed: actual.cloned(),
                });
            }
        }
    }
    Ok(missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_are_bound_to_interface_object_direction_and_access() {
        let xml = r#"<node><interface name="org.freedesktop.systemd1.Service"><property name="ExitType" type="s" access="read"/><method name="DumpFileDescriptorStore"><arg type="a(suuutuusu)" direction="out"/></method></interface></node>"#;
        let mut observed = Members::new();
        observe(xml, false, &mut observed).unwrap();
        assert_eq!(observed["service_properties"]["ExitType"], "s");
        assert_eq!(
            observed["service_methods"]["DumpFileDescriptorStore"],
            "->a(suuutuusu)"
        );
        for xml in [
            xml.replace("Service", "service"),
            xml.replace("access=\"read\"", "access=\"write\""),
        ] {
            let mut observed = Members::new();
            observe(&xml, false, &mut observed).unwrap();
            assert!(
                missing("managed", &observed)
                    .unwrap()
                    .iter()
                    .any(|item| item.member == "ExitType")
            );
        }
        let mut observed = Members::new();
        observe(xml, true, &mut observed).unwrap();
        assert!(observed.is_empty());
        let contract = contract::interface_contract().unwrap();
        let mut observed = contract.profiles["supervision"].members.clone();
        assert!(
            missing("supervision", &observed)
                .unwrap()
                .is_empty()
        );
        assert!(!missing("managed", &observed).unwrap().is_empty());
        for (group, members) in &contract.profiles["managed"].members {
            observed
                .entry(group.clone())
                .or_default()
                .extend(members.clone());
        }
        assert!(missing("managed", &observed).unwrap().is_empty());
        observed
            .get_mut("service_methods")
            .unwrap()
            .insert("DumpFileDescriptorStore".into(), "->u".into());
        assert_eq!(
            missing("managed", &observed).unwrap()[0]
                .observed
                .as_deref(),
            Some("->u")
        );
        assert!(
            observe(
                "<!DOCTYPE node [<!ENTITY e 'x'>]><node/>",
                false,
                &mut Members::new()
            )
            .is_err()
        );
    }
}

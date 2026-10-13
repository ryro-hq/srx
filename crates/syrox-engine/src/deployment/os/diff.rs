use super::manifest::{GenerationManifest, Invocation};
use crate::store::ContentDigest;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChangeKind {
    Added,
    Removed,
    Changed,
    Unchanged,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ResourceKind {
    Output,
    PackageSelection,
    Service,
    Command,
    Exposure,
    Configuration,
    Process,
    Launcher,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Effect {
    None,
    Availability,
    Configuration,
    StartRequired,
    StopRequired,
    RestartRequired,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GenerationChange {
    pub resource: ResourceKind,
    pub key: String,
    pub kind: ChangeKind,
    pub effect: Effect,
    pub reasons: Vec<&'static str>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GenerationDiff {
    changes: Vec<GenerationChange>,
}
impl GenerationDiff {
    pub(crate) fn changes(&self) -> &[GenerationChange] {
        &self.changes
    }
    pub(crate) fn has_operational_changes(&self) -> bool {
        self.changes
            .iter()
            .any(|change| change.kind != ChangeKind::Unchanged)
    }
    /// Bounded by manifest resource counts; does not print configuration content,
    /// arguments, environment values or incidental paths from the local machine.
    pub(crate) fn render(&self) -> String {
        let mut text = String::from("Prepared Os difference (no changes applied)\n");
        for change in &self.changes {
            if change.kind == ChangeKind::Unchanged {
                continue;
            }
            writeln!(
                text,
                "{:?} {:?} {}: {:?}{}",
                change.kind,
                change.resource,
                change.key,
                change.effect,
                if change.reasons.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", change.reasons.join(", "))
                }
            )
            .expect("String writes cannot fail");
        }
        if !self.has_operational_changes() {
            text.push_str("No operational changes.\n");
        }
        text
    }
}
pub(crate) fn diff_generations(
    previous: &GenerationManifest,
    candidate: &GenerationManifest,
) -> GenerationDiff {
    let mut changes = Vec::new();
    let changed_configs = changed_configurations(previous, candidate);
    map_diff(
        &mut changes,
        ResourceKind::Output,
        &previous.outputs,
        &candidate.outputs,
        Effect::Availability,
    );
    let selections = |value: &GenerationManifest| {
        value
            .selections
            .iter()
            .map(|selection| {
                format!(
                    "{}/{}",
                    selection.service.as_deref().unwrap_or("<root>"),
                    selection.output
                )
            })
            .collect::<BTreeSet<_>>()
    };
    set_diff(
        &mut changes,
        ResourceKind::PackageSelection,
        &selections(previous),
        &selections(candidate),
    );
    set_diff(
        &mut changes,
        ResourceKind::Service,
        &previous.services,
        &candidate.services,
    );
    map_diff(
        &mut changes,
        ResourceKind::Command,
        &previous.commands,
        &candidate.commands,
        Effect::Availability,
    );
    map_diff(
        &mut changes,
        ResourceKind::Exposure,
        &previous.exposures,
        &candidate.exposures,
        Effect::Availability,
    );
    map_diff(
        &mut changes,
        ResourceKind::Configuration,
        &previous.configs,
        &candidate.configs,
        Effect::Configuration,
    );
    changes.push(GenerationChange {
        resource: ResourceKind::Launcher,
        key: "launcher".into(),
        kind: if previous.launcher == candidate.launcher {
            ChangeKind::Unchanged
        } else {
            ChangeKind::Changed
        },
        effect: if previous.launcher == candidate.launcher {
            Effect::None
        } else {
            Effect::Availability
        },
        reasons: Vec::new(),
    });
    process_diff(
        &mut changes,
        previous,
        candidate,
        &changed_configs,
    );
    changes.sort_by(|left, right| (&left.resource, &left.key).cmp(&(&right.resource, &right.key)));
    GenerationDiff {
        changes,
    }
}
fn map_diff<T: PartialEq>(
    changes: &mut Vec<GenerationChange>,
    resource: ResourceKind,
    old: &BTreeMap<String, T>,
    new: &BTreeMap<String, T>,
    effect: Effect,
) {
    for key in old
        .keys()
        .chain(new.keys())
        .collect::<BTreeSet<_>>()
    {
        let kind = match (old.get(key), new.get(key)) {
            (None, Some(_)) => ChangeKind::Added,
            (Some(_), None) => ChangeKind::Removed,
            (Some(a), Some(b)) if a == b => ChangeKind::Unchanged,
            _ => ChangeKind::Changed,
        };
        changes.push(GenerationChange {
            resource,
            key: key.clone(),
            kind,
            effect: if kind == ChangeKind::Unchanged {
                Effect::None
            } else {
                effect
            },
            reasons: Vec::new(),
        });
    }
}
#[derive(Clone, Copy)]
struct RuntimeFingerprint {
    application: ContentDigest,
    closure: ContentDigest,
    arguments: ContentDigest,
    environment: ContentDigest,
}
impl RuntimeFingerprint {
    fn new(invocation: &Invocation) -> Self {
        fn digest(value: &impl serde::Serialize) -> ContentDigest {
            ContentDigest::sha256(
                &serde_json::to_vec(value).expect("validated string-keyed runtime descriptor"),
            )
        }
        Self {
            application: digest(&invocation.application),
            closure: digest(&(&invocation.loader, &invocation.libraries)),
            arguments: digest(&invocation.arguments),
            environment: digest(&invocation.environment),
        }
    }
}
fn runtime_reasons(old: &RuntimeFingerprint, new: &RuntimeFingerprint) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if old.application != new.application {
        reasons.push("executable");
    }
    if old.closure != new.closure {
        reasons.push("runtime closure");
    }
    if old.arguments != new.arguments {
        reasons.push("arguments");
    }
    if old.environment != new.environment {
        reasons.push("environment");
    }
    reasons
}
fn changed_configurations<'a>(
    previous: &'a GenerationManifest,
    candidate: &'a GenerationManifest,
) -> BTreeSet<&'a str> {
    fn trees(manifest: &GenerationManifest) -> BTreeMap<&str, BTreeMap<&str, (&str, u32)>> {
        let mut trees = BTreeMap::<&str, BTreeMap<&str, (&str, u32)>>::new();
        for config in manifest.configs.values() {
            trees
                .entry(&config.service)
                .or_default()
                .insert(&config.path, (&config.digest, config.mode));
        }
        trees
    }
    let old = trees(previous);
    let new = trees(candidate);
    old.keys()
        .chain(new.keys())
        .copied()
        .filter(|service| old.get(service) != new.get(service))
        .collect()
}

fn process_diff(
    changes: &mut Vec<GenerationChange>,
    previous: &GenerationManifest,
    candidate: &GenerationManifest,
    changed_configs: &BTreeSet<&str>,
) {
    let old_fingerprints: BTreeMap<_, _> = previous
        .commands
        .iter()
        .map(|(key, invocation)| (key, RuntimeFingerprint::new(invocation)))
        .collect();
    let new_fingerprints: BTreeMap<_, _> = candidate
        .commands
        .iter()
        .map(|(key, invocation)| (key, RuntimeFingerprint::new(invocation)))
        .collect();
    for key in previous
        .processes
        .keys()
        .chain(candidate.processes.keys())
        .collect::<BTreeSet<_>>()
    {
        let old = previous
            .processes
            .get(key)
            .map(|process| &previous.commands[&process.command]);
        let new = candidate
            .processes
            .get(key)
            .map(|process| &candidate.commands[&process.command]);
        let (kind, effect, reasons) = match (old, new) {
            (None, Some(_)) => (
                ChangeKind::Added,
                Effect::StartRequired,
                Vec::new(),
            ),
            (Some(_), None) => (
                ChangeKind::Removed,
                Effect::StopRequired,
                Vec::new(),
            ),
            (Some(old), Some(new)) => {
                let mut reasons = runtime_reasons(
                    &old_fingerprints[&previous.processes[key].command],
                    &new_fingerprints[&candidate.processes[key].command],
                );
                if previous.processes[key].restart != candidate.processes[key].restart {
                    reasons.push("restart policy");
                }
                if previous.launcher != candidate.launcher {
                    reasons.push("launcher");
                }
                if old.service != new.service
                    || new
                        .service
                        .as_ref()
                        .is_some_and(|service| changed_configs.contains(service.as_str()))
                {
                    reasons.push("service configuration");
                }
                if reasons.is_empty() {
                    (ChangeKind::Unchanged, Effect::None, reasons)
                } else {
                    (
                        ChangeKind::Changed,
                        Effect::RestartRequired,
                        reasons,
                    )
                }
            }
            (None, None) => unreachable!("union of process keys"),
        };
        changes.push(GenerationChange {
            resource: ResourceKind::Process,
            key: key.clone(),
            kind,
            effect,
            reasons,
        });
    }
}
fn set_diff(
    changes: &mut Vec<GenerationChange>,
    resource: ResourceKind,
    old: &BTreeSet<String>,
    new: &BTreeSet<String>,
) {
    for key in old.union(new) {
        let kind = match (old.contains(key), new.contains(key)) {
            (true, true) => ChangeKind::Unchanged,
            (true, false) => ChangeKind::Removed,
            (false, true) => ChangeKind::Added,
            (false, false) => unreachable!("set union"),
        };
        changes.push(GenerationChange {
            resource,
            key: key.clone(),
            kind,
            effect: if kind == ChangeKind::Unchanged {
                Effect::None
            } else {
                Effect::Availability
            },
            reasons: Vec::new(),
        });
    }
}

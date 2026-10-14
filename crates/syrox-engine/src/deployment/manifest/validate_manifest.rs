use super::encoding::{
    Argument, GenerationManifest, Invocation, MAX_BYTES, MAX_ITEMS, Origin, Role, command_key,
};
use super::{GenerationError, ManifestResult as Result};
use crate::config::secrets::valid_name as service_name;
use crate::execution::configuration::{
    MAX_CONFIGURATION_BYTES, MAX_CONFIGURATION_DEPTH, MAX_CONFIGURATION_ENTRIES,
    MAX_RUNTIME_ENVIRONMENT_BYTES, MAX_RUNTIME_ENVIRONMENT_ENTRIES, MAX_RUNTIME_ENVIRONMENT_VALUE,
};
use crate::result::valid_name as name;
use crate::store::ContentDigest;
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::deployment) fn manifest(value: &GenerationManifest) -> Result<()> {
    digest(&value.launcher.digest)?;
    require(
        value.launcher.protocol == 1,
        "unsupported launcher protocol",
    )?;
    let counts = [
        value.outputs.len(),
        value.provenance.len(),
        value.services.len(),
        value.session_states.len(),
        value.secrets.len(),
        value.secrets.values().map(BTreeSet::len).sum(),
        value.selections.len(),
        value.commands.len(),
        value.exposures.len(),
        value.configs.len(),
        value.processes.len(),
        value.validators.len(),
    ];
    require(
        counts
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .is_some_and(|n| n <= MAX_ITEMS),
        "generation item bound exceeded",
    )?;
    for service in &value.services {
        require(service_name(service), "invalid service namespace")?;
    }
    require(
        value.session_states.is_subset(&value.services),
        "state references undeclared service",
    )?;
    secret_declarations(value)?;
    let mut used = BTreeSet::new();
    outputs(value)?;
    let root_outputs: BTreeSet<_> = value
        .selections
        .iter()
        .filter(|selection| selection.service.is_none())
        .map(|selection| selection.output.as_str())
        .collect();
    for selection in &value.selections {
        namespace(value, selection.service.as_deref())?;
        output_ref(value, &selection.output, &mut used)?;
    }
    configs(value)?;
    for (key, command) in &value.commands {
        namespace(value, command.service.as_deref())?;
        require(
            name(&command.name) && key == &command_key(command.service.as_deref(), &command.name),
            "invalid command key",
        )?;
        if command.service.is_none() {
            require(
                root_outputs.contains(command.application.output.as_str())
                    && value.exposures.get(&command.name) == Some(key),
                "root command must belong to a selected output and its public exposure",
            )?;
        }
        role(value, &command.application, &mut used)?;
        if let Some(loader) = &command.loader {
            role(value, loader, &mut used)?;
        }
        require(
            command.libraries.len() <= crate::runtime::MAX_RUNTIME_LIBRARIES,
            "too many runtime libraries",
        )?;
        for library in &command.libraries {
            output_ref(value, library, &mut used)?;
        }
        invocation(value, command)?;
    }
    for validator in &value.validators {
        require(
            value
                .commands
                .get(validator)
                .is_some_and(|command| {
                    command.service.is_some()
                        && command
                            .arguments
                            .iter()
                            .chain(command.environment.values())
                            .all(|argument| {
                                matches!(argument, Argument::Literal(_) | Argument::File(_))
                            })
                }),
            "validator references absent command or mutable resources",
        )?;
    }
    for (exposure, command) in &value.exposures {
        require(
            name(exposure) && value.commands.contains_key(command),
            "invalid exposed command",
        )?;
    }
    for (key, process) in &value.processes {
        let (service, id) = key
            .split_once('/')
            .ok_or(GenerationError::Invalid("invalid process key"))?;
        require(
            name(id) && value.services.contains(service),
            "invalid process namespace",
        )?;
        require(
            value
                .commands
                .get(&process.command)
                .is_some_and(|command| command.service.as_deref() == Some(service)),
            "process references absent or foreign command",
        )?;
    }
    require(
        used.len() == value.outputs.len(),
        "generation contains unreferenced outputs",
    )
}
fn output_ref<'a>(
    value: &'a GenerationManifest,
    key: &'a str,
    used: &mut BTreeSet<&'a str>,
) -> Result<()> {
    require(
        value.outputs.contains_key(key),
        "missing output reference",
    )?;
    used.insert(key);
    Ok(())
}
fn role<'a>(
    value: &'a GenerationManifest,
    role: &'a Role,
    used: &mut BTreeSet<&'a str>,
) -> Result<()> {
    require(
        role.path.len() <= 4096 && crate::build::relative_path(&role.path),
        "invalid runtime entry path",
    )?;
    output_ref(value, &role.output, used)
}
fn namespace(value: &GenerationManifest, service: Option<&str>) -> Result<()> {
    require(
        service.is_none_or(|service| value.services.contains(service)),
        "unknown service namespace",
    )
}
fn configs(value: &GenerationManifest) -> Result<()> {
    let mut trees = BTreeMap::<&str, BTreeSet<String>>::new();
    let mut bytes = BTreeMap::<&str, u64>::new();
    let mut total = 0usize;
    for (key, file) in &value.configs {
        require(
            value.services.contains(&file.service)
                && config_path(&file.path)
                && key == &format!("{}/{}", file.service, file.path)
                && file.mode == 0o400,
            "invalid configuration descriptor",
        )?;
        digest(&file.digest)?;
        require(
            ContentDigest::sha256(file.text.as_bytes()).to_string() == file.digest,
            "configuration content digest mismatch",
        )?;
        total = total
            .checked_add(file.text.len())
            .ok_or(GenerationError::Invalid("configuration overflow"))?;
        require(
            total <= MAX_BYTES,
            "configuration total bound exceeded",
        )?;
        let service_bytes = bytes.entry(&file.service).or_default();
        *service_bytes += u64::try_from(file.text.len()).expect("bounded config size");
        require(
            *service_bytes <= MAX_CONFIGURATION_BYTES,
            "service configuration byte bound exceeded",
        )?;
        let nodes = trees.entry(&file.service).or_default();
        nodes.insert(file.path.clone());
        let mut prefix = String::new();
        let parts: Vec<_> = file.path.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            require(
                !value
                    .configs
                    .contains_key(&format!("{}/{prefix}", file.service)),
                "configuration file shadows a directory",
            )?;
            nodes.insert(prefix.clone());
        }
        require(
            nodes.len() <= MAX_CONFIGURATION_ENTRIES,
            "service configuration entry bound exceeded",
        )?;
    }
    Ok(())
}
fn invocation(value: &GenerationManifest, command: &Invocation) -> Result<()> {
    require(
        command.arguments.len() <= 256
            && command.environment.len() <= MAX_RUNTIME_ENVIRONMENT_ENTRIES,
        "invocation item bound exceeded",
    )?;
    for argument in &command.arguments {
        argument_length(value, command, argument)?;
    }
    let mut total = 0usize;
    for (name, argument) in &command.environment {
        require(
            crate::runtime::valid_runtime_environment_name(name),
            "invalid or reserved environment name",
        )?;
        let length = argument_length(value, command, argument)?;
        require(
            length <= MAX_RUNTIME_ENVIRONMENT_VALUE,
            "rendered environment value too large",
        )?;
        total += name.len() + length + 2;
        require(
            total <= MAX_RUNTIME_ENVIRONMENT_BYTES,
            "environment aggregate bound exceeded",
        )?;
    }
    Ok(())
}
fn secret_declarations(value: &GenerationManifest) -> Result<()> {
    let mut total_secrets = 0usize;
    for (service, names) in &value.secrets {
        require(
            value.services.contains(service)
                && !names.is_empty()
                && names.len() <= crate::config::secrets::MAX_SERVICE_SECRETS,
            "invalid service secret declarations",
        )?;
        for name in names {
            require(
                crate::config::secrets::valid_name(name),
                "invalid secret name",
            )?;
        }
        total_secrets = total_secrets.saturating_add(names.len());
    }
    require(
        total_secrets <= crate::config::secrets::MAX_CONSUMER_SECRETS,
        "too many declared secrets",
    )?;
    Ok(())
}

fn argument_length(
    value: &GenerationManifest,
    command: &Invocation,
    argument: &Argument,
) -> Result<usize> {
    match argument {
        Argument::SecretFile(name) => {
            let service = command
                .service
                .as_deref()
                .ok_or(GenerationError::Invalid(
                    "root invocation cannot reference secret",
                ))?;
            require(
                value
                    .secrets
                    .get(service)
                    .is_some_and(|names| names.contains(name)),
                "argument references undeclared secret",
            )?;
            Ok("/syrox/secrets/".len() + service.len() + 1 + name.len())
        }
        Argument::StateDirectory => {
            let service = command
                .service
                .as_deref()
                .ok_or(GenerationError::Invalid(
                    "root invocation cannot reference state",
                ))?;
            require(
                value.session_states.contains(service),
                "argument references undeclared session state",
            )?;
            Ok("/syrox/state/".len() + service.len())
        }
        Argument::Literal(text) => {
            require(
                text.len() <= MAX_RUNTIME_ENVIRONMENT_VALUE && !text.contains('\0'),
                "invalid command literal",
            )?;
            Ok(text.len())
        }
        Argument::File(path) => {
            let service = command
                .service
                .as_deref()
                .ok_or(GenerationError::Invalid(
                    "root invocation cannot reference service configuration",
                ))?;
            require(
                value
                    .configs
                    .contains_key(&format!("{service}/{path}")),
                "argument references undeclared configuration",
            )?;
            Ok("/syrox/config/".len() + service.len() + 1 + path.len())
        }
    }
}
fn config_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && path.split('/').count() <= MAX_CONFIGURATION_DEPTH
        && !path
            .chars()
            .any(|ch| ch == '\\' || ch.is_control())
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && part.len() <= 255)
}
fn text(text: &str, maximum: usize) -> bool {
    !text.is_empty() && text.len() <= maximum && !text.chars().any(char::is_control)
}
fn digest(text: &str) -> Result<()> {
    require(
        text.parse::<ContentDigest>().is_ok(),
        "invalid content digest",
    )
}
fn require(condition: bool, reason: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(GenerationError::Invalid(reason))
    }
}

fn outputs(value: &GenerationManifest) -> Result<()> {
    for (key, output) in &value.outputs {
        digest(&output.action)?;
        digest(&output.artifact)?;
        match &output.origin {
            Origin::Built {
                receipt,
            } => digest(receipt)?,
            Origin::Imported {
                manifest,
            } => digest(manifest)?,
        }
        require(
            name(&output.name) && key == &output.key()?,
            "output identity or key is invalid",
        )?;
    }
    require(
        value.outputs.keys().eq(value.provenance.keys()),
        "output provenance does not match output set",
    )?;
    let mut provenance_items = 0usize;
    for origins in value.provenance.values() {
        require(!origins.is_empty(), "missing output provenance")?;
        for origin in origins {
            provenance_items = provenance_items
                .checked_add(1 + origin.path.len())
                .ok_or(GenerationError::Invalid("provenance overflow"))?;
            require(
                provenance_items <= MAX_ITEMS
                    && text(&origin.label, 255)
                    && origin.path.iter().all(|part| text(part, 4096)),
                "provenance bound exceeded",
            )?;
        }
    }
    Ok(())
}

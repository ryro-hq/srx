use super::{
    AuthenticatedStandardLibrary, BTreeMap, CanonicalItemIdentity, CanonicalType, MemoId,
    PlanBuild, PlanCommand, PlanError, PlanOutputRef, PlanPackageId, PrimitiveValue,
    ProjectionBudget, Value, decode_output_ref, exact_nominal, plan_path,
};
use crate::config::secrets::valid_name as valid_service_id;

mod commands;
pub use commands::{
    PlanCommandArgument, PlanCommandEnvironment, PlanServiceCommand, PlanServiceProcess,
};

const OS_PATH: &[&str] = &["std", "deployment", "Os"];
const SHELL_PATH: &[&str] = &["std", "deployment", "Shell"];
const SELECTION_PATH: &[&str] = &["std", "deployment", "PackageSelection"];
const COMMAND_NAME_PATH: &[&str] = &["std", "pkg", "CommandName"];
const SERVICE_PATH: &[&str] = &["std", "deployment", "Service"];
const SERVICE_ID_PATH: &[&str] = &["std", "deployment", "ServiceId"];
const FILE_PATH: &[&str] = &["std", "deployment", "ConfigFile"];
const CONFIG_PATH: &[&str] = &["std", "deployment", "ConfigPath"];
const TEXT_PATH: &[&str] = &["std", "deployment", "ConfigText"];
const MAX_CONFIG_PATH_BYTES: usize = 4096;
const MAX_CONFIG_COMPONENT_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanConsumerKind {
    Os,
    Shell,
}

/// One structural output and the commands explicitly exposed by its consumer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlanPackageSelection {
    output: PlanOutputRef,
    commands: Vec<String>,
}

impl PlanPackageSelection {
    pub const fn output(&self) -> &PlanOutputRef {
        &self.output
    }
    pub const fn package(&self) -> &PlanPackageId {
        &self.output.package
    }
    pub fn commands(&self) -> &[String] {
        &self.commands
    }
}

struct SelectionIndex<'a> {
    references: &'a BTreeMap<&'a MemoId, PlanPackageId>,
    builds: &'a [PlanBuild],
    imports: &'a [super::PlanImportedResult],
    commands: &'a [PlanCommand],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanConsumer {
    name: String,
    domain: u32,
    path: Vec<String>,
    kind: PlanConsumerKind,
    pkgs: Vec<PlanPackageSelection>,
    services: Vec<PlanService>,
}

impl PlanConsumer {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn domain(&self) -> u32 {
        self.domain
    }

    pub fn path(&self) -> &[String] {
        &self.path
    }

    pub const fn kind(&self) -> PlanConsumerKind {
        self.kind
    }

    pub fn pkgs(&self) -> &[PlanPackageSelection] {
        &self.pkgs
    }

    pub fn services(&self) -> &[PlanService] {
        &self.services
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanServiceState {
    None,
    Session,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanService {
    state: PlanServiceState,
    secrets: Vec<String>,
    id: String,
    pkgs: Vec<PlanPackageSelection>,
    files: Vec<PlanConfigFile>,
    commands: Vec<PlanServiceCommand>,
    processes: Vec<PlanServiceProcess>,
    validators: Vec<String>,
}

impl PlanService {
    pub fn validators(&self) -> &[String] {
        &self.validators
    }
    pub fn secrets(&self) -> &[String] {
        &self.secrets
    }
    pub const fn state(&self) -> PlanServiceState {
        self.state
    }
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn pkgs(&self) -> &[PlanPackageSelection] {
        &self.pkgs
    }

    pub fn commands(&self) -> &[PlanServiceCommand] {
        &self.commands
    }
    pub fn processes(&self) -> &[PlanServiceProcess] {
        &self.processes
    }

    pub fn files(&self) -> &[PlanConfigFile] {
        &self.files
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanConfigFile {
    path: String,
    text: String,
}

impl PlanConfigFile {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

#[derive(Clone, Copy)]
struct ErrorContext<'a> {
    root: &'a str,
    service: Option<&'a str>,
    path: Option<&'a str>,
}

impl<'a> ErrorContext<'a> {
    const fn service(self, id: &'a str) -> Self {
        Self {
            service: Some(id),
            ..self
        }
    }

    const fn file(self, path: &'a str) -> Self {
        Self {
            path: Some(path),
            ..self
        }
    }

    fn invalid<T>(
        self,
        reason: &'static str,
        budget: &mut ProjectionBudget,
    ) -> Result<T, PlanError> {
        let root = budget.string(self.root)?;
        Err(match (self.service, self.path) {
            (Some(service), Some(path)) => PlanError::InvalidConfigFile {
                root,
                service: budget.string(service)?,
                path: budget.string(path)?,
                reason,
            },
            (Some(service), None) => PlanError::InvalidService {
                root,
                service: budget.string(service)?,
                reason,
            },
            _ => PlanError::InvalidConsumer {
                root,
                reason,
            },
        })
    }
}

fn kind(ty: &CanonicalType) -> Option<PlanConsumerKind> {
    if exact_nominal(ty, OS_PATH) {
        Some(PlanConsumerKind::Os)
    } else if exact_nominal(ty, SHELL_PATH) {
        Some(PlanConsumerKind::Shell)
    } else {
        None
    }
}

pub(super) fn extract(
    components: &[super::recipes::Component<'_>],
    references: &BTreeMap<&MemoId, PlanPackageId>,
    builds: &[PlanBuild],
    imports: &[super::PlanImportedResult],
    commands: &[PlanCommand],
    standard_library: Option<&AuthenticatedStandardLibrary>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanConsumer>, PlanError> {
    if standard_library.is_none() {
        return Ok(Vec::new());
    }
    let index = SelectionIndex {
        references,
        builds,
        imports,
        commands,
    };
    let mut count = 0;
    for component in components {
        budget.charge_work()?;
        count += usize::from(consumer_kind(component).is_some());
    }
    let mut result = budget.collection::<PlanConsumer>(count)?;
    for component in components {
        budget.charge_work()?;
        let Some(kind) = consumer_kind(component) else {
            continue;
        };
        result.push(consumer(
            component.name(),
            component.identity(),
            kind,
            component.value(),
            &index,
            budget,
        )?);
    }
    let key_bytes = result
        .iter()
        .map(|consumer| {
            size_of::<u32>()
                + consumer
                    .path
                    .iter()
                    .map(|part| part.len() + 1)
                    .sum::<usize>()
        })
        .max()
        .unwrap_or(0);
    charge_sort(result.len(), key_bytes, budget)?;
    result.sort_unstable_by(|left, right| {
        (&left.domain, &left.path).cmp(&(&right.domain, &right.path))
    });
    Ok(result)
}

fn consumer_kind(component: &super::recipes::Component<'_>) -> Option<PlanConsumerKind> {
    // Forced references also have a project identity; reference presence, not
    // export status, distinguishes these auxiliary roots from explicit outputs.
    if component.reference().is_some()
        || component.identity().domain() != syrox_lang::source::SourceDomainId::project()
    {
        return None;
    }
    kind(component.ty())
}

fn consumer(
    name: &str,
    identity: &CanonicalItemIdentity,
    kind: PlanConsumerKind,
    value: &Value,
    index: &SelectionIndex<'_>,
    budget: &mut ProjectionBudget,
) -> Result<PlanConsumer, PlanError> {
    budget.node::<PlanConsumer>()?;
    let context = ErrorContext {
        root: name,
        service: None,
        path: None,
    };
    let path = match kind {
        PlanConsumerKind::Os => OS_PATH,
        PlanConsumerKind::Shell => SHELL_PATH,
    };
    let fields = fields(
        value,
        path,
        &["pkgs", "services"],
        context,
        budget,
    )?;
    let pkgs = packages(&fields[0].1, index, context, budget)?;
    let services = services(&fields[1].1, index, context, budget)?;
    if kind == PlanConsumerKind::Shell
        && services
            .iter()
            .flat_map(PlanService::processes)
            .any(|process| process.restart() != crate::execution::restart::ProcessRestart::Never)
    {
        return context.invalid("process restart is supported only by Os", budget);
    }
    if kind == PlanConsumerKind::Os
        && services.iter().any(|service| {
            service.state == PlanServiceState::Session || !service.secrets.is_empty()
        })
    {
        return context.invalid(
            "session state and secrets are supported only by managed Shell",
            budget,
        );
    }
    if services
        .iter()
        .map(|service| service.secrets.len())
        .sum::<usize>()
        > crate::config::secrets::MAX_CONSUMER_SECRETS
    {
        return context.invalid("too many declared secrets", budget);
    }
    commands::validate_exposures(&pkgs, &services, context, budget)?;
    Ok(PlanConsumer {
        name: budget.string(name)?,
        domain: identity.domain().as_u32(),
        path: plan_path(identity.path(), budget)?,
        kind,
        pkgs,
        services,
    })
}

fn fields<'a>(
    value: &'a Value,
    path: &[&str],
    names: &[&str],
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<&'a [(String, Value)], PlanError> {
    budget.charge_work()?;
    let Value::Struct {
        ty,
        fields,
        ..
    } = value
    else {
        return context.invalid("expected an exact deployment struct", budget);
    };
    if !exact_nominal(ty, path)
        || fields.len() != names.len()
        || !fields
            .iter()
            .zip(names)
            .all(|((name, _), expected)| name == expected)
    {
        return context.invalid("unexpected deployment type or fields", budget);
    }
    Ok(fields)
}

fn list<'a>(
    value: &'a Value,
    valid_item: impl FnOnce(&CanonicalType) -> bool,
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<&'a [Value], PlanError> {
    budget.charge_work()?;
    let Value::List {
        ty,
        items,
    } = value
    else {
        return context.invalid("expected a typed list", budget);
    };
    let CanonicalType::List(item) = ty.as_ref() else {
        return context.invalid("expected a typed list", budget);
    };
    if !valid_item(item) {
        return context.invalid("unexpected list item type", budget);
    }
    Ok(items)
}

fn packages(
    value: &Value,
    index: &SelectionIndex<'_>,
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanPackageSelection>, PlanError> {
    let items = list(
        value,
        |ty| exact_nominal(ty, SELECTION_PATH),
        context,
        budget,
    )?;
    let mut selected = budget.collection::<PlanPackageSelection>(items.len())?;
    for item in items {
        let values = fields(
            item,
            SELECTION_PATH,
            &["output", "commands"],
            context,
            budget,
        )?;
        let Some((reference, output)) = decode_output_ref(&values[0].1) else {
            return context.invalid(
                "selection requires an authenticated recipe output",
                budget,
            );
        };
        let Some(package) = index.references.get(reference) else {
            return context.invalid(
                "selected output has no typed recipe reference",
                budget,
            );
        };
        budget.charge_work_units(index.builds.len() + index.imports.len())?;
        let built = index
            .builds
            .iter()
            .find(|build| build.package() == package);
        if let Some(build) = built {
            budget.charge_work_units(build.program().outputs.len())?;
        }
        let declared = built.is_some_and(|build| {
            build
                .program()
                .outputs
                .iter()
                .any(|name| name == output)
        }) || index
            .imports
            .iter()
            .any(|entry| entry.package() == package && entry.outputs().contains_key(output));
        if !declared {
            return context.invalid(
                "selected output is not declared by its recipe",
                budget,
            );
        }
        let names = list(
            &values[1].1,
            |ty| exact_nominal(ty, COMMAND_NAME_PATH),
            context,
            budget,
        )?;
        let mut commands = budget.collection::<String>(names.len())?;
        for name in names {
            let Some(name) = nominal_string(name, COMMAND_NAME_PATH) else {
                return context.invalid("selection command is not CommandName", budget);
            };
            budget.charge_work_units(index.commands.len())?;
            if !index.commands.iter().any(|command| {
                command.package() == package && command.name() == name && command.output() == output
            }) {
                return context.invalid(
                    "selected command is absent from the selected output",
                    budget,
                );
            }
            commands.push(budget.string(name)?);
        }
        selected.push(PlanPackageSelection {
            output: PlanOutputRef {
                package: package.copy(budget)?,
                output: budget.string(output)?,
            },
            commands,
        });
    }
    normalize_selections(selected, budget)
}

fn normalize_selections(
    mut selected: Vec<PlanPackageSelection>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanPackageSelection>, PlanError> {
    let key_bytes = selected
        .iter()
        .map(|selection| {
            selection.output.output.len()
                + selection.package().as_str().len()
                + size_of::<u32>()
                + selection
                    .package()
                    .path()
                    .iter()
                    .map(|part| part.len() + 1)
                    .sum::<usize>()
        })
        .max()
        .unwrap_or(0);
    charge_sort(selected.len(), key_bytes, budget)?;
    selected.sort_unstable_by(|left, right| left.output.cmp(&right.output));
    charge_comparisons(selected.len(), key_bytes, budget)?;
    let mut result = budget.collection::<PlanPackageSelection>(selected.len())?;
    for selection in selected {
        if let Some(last) = result
            .last_mut()
            .filter(|last| last.output == selection.output)
        {
            last.commands.extend(selection.commands);
        } else {
            result.push(selection);
        }
    }
    for selection in &mut result {
        let key_bytes = selection
            .commands
            .iter()
            .map(String::len)
            .max()
            .unwrap_or(0);
        charge_sort(selection.commands.len(), key_bytes, budget)?;
        selection.commands.sort_unstable();
        charge_comparisons(selection.commands.len(), key_bytes, budget)?;
        selection.commands.dedup();
    }
    Ok(result)
}

fn nominal_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    match value {
        Value::Nominal {
            ty,
            value: PrimitiveValue::Str(text),
            resource: false,
        } if exact_nominal(ty, path) => Some(text),
        _ => None,
    }
}

fn secret_names(
    value: &Value,
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<String>, PlanError> {
    let names = list(
        value,
        |ty| exact_nominal(ty, &["std", "deployment", "SecretName"]),
        context,
        budget,
    )?;
    if names.len() > crate::config::secrets::MAX_SERVICE_SECRETS {
        return context.invalid("too many service secrets", budget);
    }
    let mut secrets = budget.collection::<String>(names.len())?;
    for name in names {
        let Some(name) = nominal_string(name, &["std", "deployment", "SecretName"]) else {
            return context.invalid("expected SecretName", budget);
        };
        budget.charge_work_units(secrets.len())?;
        if !crate::config::secrets::valid_name(name) || secrets.iter().any(|prior| prior == name) {
            return context.invalid("invalid or duplicate secret name", budget);
        }
        secrets.push(budget.string(name)?);
    }
    secrets.sort();
    Ok(secrets)
}

fn services(
    value: &Value,
    index: &SelectionIndex<'_>,
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanService>, PlanError> {
    let items = list(
        value,
        |ty| exact_nominal(ty, SERVICE_PATH),
        context,
        budget,
    )?;
    let mut result = budget.collection::<PlanService>(items.len())?;
    for item in items {
        budget.node::<PlanService>()?;
        let fields = fields(
            item,
            SERVICE_PATH,
            &[
                "id",
                "pkgs",
                "files",
                "commands",
                "processes",
                "state",
                "secrets",
                "validators",
            ],
            context.service("<invalid>"),
            budget,
        )?;
        let Some(id) = nominal_string(&fields[0].1, SERVICE_ID_PATH) else {
            return context
                .service("<invalid>")
                .invalid("expected a ServiceId", budget);
        };
        let context = context.service(id);
        if !valid_service_id(id) {
            return context.invalid(
                "service ID must match ASCII [a-z0-9][a-z0-9._-]{0,127}",
                budget,
            );
        }
        let state = match &fields[5].1 {
            Value::Variant {
                ty,
                index,
                payload,
            } if exact_nominal(ty, &["std", "deployment", "ServiceState"])
                && payload.is_empty() =>
            {
                match index {
                    0 => PlanServiceState::None,
                    1 => PlanServiceState::Session,
                    _ => return context.invalid("invalid ServiceState", budget),
                }
            }
            _ => return context.invalid("expected authenticated ServiceState", budget),
        };
        let secrets = secret_names(&fields[6].1, context, budget)?;
        let pkgs = packages(&fields[1].1, index, context, budget)?;
        let files = files(&fields[2].1, context, budget)?;
        let commands = commands::commands(
            &fields[3].1,
            index,
            &pkgs,
            commands::Resources {
                files: &files,
                state,
                secrets: &secrets,
            },
            context,
            budget,
        )?;
        let processes = commands::processes(&fields[4].1, &commands, context, budget)?;
        let validator_values = list(
            &fields[7].1,
            |ty| exact_nominal(ty, COMMAND_NAME_PATH),
            context,
            budget,
        )?;
        let mut validators = budget.collection::<String>(validator_values.len())?;
        for value in validator_values {
            let Some(name) = nominal_string(value, COMMAND_NAME_PATH) else {
                return context.invalid("validator must name a service command", budget);
            };
            let Some(command) = commands
                .iter()
                .find(|command| command.name() == name)
            else {
                return context.invalid("validator command is absent", budget);
            };
            if command
                .arguments()
                .iter()
                .chain(
                    command
                        .environment()
                        .iter()
                        .map(|entry| &entry.value),
                )
                .any(|argument| {
                    matches!(
                        argument,
                        PlanCommandArgument::StateDirectory | PlanCommandArgument::SecretFile(_)
                    )
                })
            {
                return context.invalid(
                    "configuration validators require literal arguments and configuration files",
                    budget,
                );
            }
            if validators.iter().any(|previous| previous == name) {
                return context.invalid("duplicate configuration validator", budget);
            }
            validators.push(budget.string(name)?);
        }
        result.push(PlanService {
            state,
            secrets,
            id: budget.string(id)?,
            pkgs,
            files,
            commands,
            processes,
            validators,
        });
    }
    let key_bytes = result
        .iter()
        .map(|service| service.id.len())
        .max()
        .unwrap_or(0);
    charge_sort(result.len(), key_bytes, budget)?;
    result.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    for pair in result.windows(2) {
        budget.charge_work_units(pair[0].id.len().min(pair[1].id.len()) + 1)?;
        if pair[0].id == pair[1].id {
            return context
                .service(&pair[1].id)
                .invalid("duplicate service ID", budget);
        }
    }
    Ok(result)
}

fn files(
    value: &Value,
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanConfigFile>, PlanError> {
    let items = list(
        value,
        |ty| exact_nominal(ty, FILE_PATH),
        context,
        budget,
    )?;
    let mut result = budget.collection::<PlanConfigFile>(items.len())?;
    for item in items {
        budget.node::<PlanConfigFile>()?;
        let fields = fields(
            item,
            FILE_PATH,
            &["path", "text"],
            context.file("<invalid>"),
            budget,
        )?;
        let Some(path) = nominal_string(&fields[0].1, CONFIG_PATH) else {
            return context
                .file("<invalid>")
                .invalid("expected a ConfigPath", budget);
        };
        let context = context.file(path);
        if !valid_config_path(path) {
            return context.invalid("configuration path must be a bounded, relative path without empty, dot, control or backslash components", budget);
        }
        let Some(text) = nominal_string(&fields[1].1, TEXT_PATH) else {
            return context.invalid("expected ConfigText", budget);
        };
        result.push(PlanConfigFile {
            path: budget.string(path)?,
            text: budget.string(text)?,
        });
    }
    let key_bytes = result
        .iter()
        .map(|file| file.path.len())
        .max()
        .unwrap_or(0);
    charge_sort(result.len(), key_bytes, budget)?;
    result.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    validate_paths(&result, context, budget)?;
    validate_config_limits(&result, context, budget)?;
    Ok(result)
}

fn validate_config_limits(
    files: &[PlanConfigFile],
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<(), PlanError> {
    let mut entries = std::collections::BTreeSet::new();
    let mut bytes = 0;
    for file in files {
        bytes += file.text.len();
        let mut depth = 1;
        for (index, _) in file.path.match_indices('/') {
            budget.charge_work_units(index + 1)?;
            entries.insert(&file.path[..index]);
            depth += 1;
        }
        entries.insert(file.path.as_str());
        if entries.len() > crate::execution::configuration::MAX_CONFIGURATION_ENTRIES
            || bytes as u64 > crate::execution::configuration::MAX_CONFIGURATION_BYTES
            || depth > crate::execution::configuration::MAX_CONFIGURATION_DEPTH
        {
            return context.invalid(
                "configuration exceeds entry, byte or depth bounds",
                budget,
            );
        }
    }
    Ok(())
}

fn validate_paths(
    files: &[PlanConfigFile],
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<(), PlanError> {
    for (index, file) in files.iter().enumerate() {
        budget.charge_work_units(file.path.len() + 1)?;
        if index > 0 && files[index - 1].path == file.path {
            return context
                .file(&file.path)
                .invalid("duplicate configuration path", budget);
        }
        // Adjacent comparison misses a, a-b, a/c. Search once for the first
        // possible descendant, independent of this path's component depth.
        let prefix_bytes = file.path.len() + 1;
        budget.node::<String>()?;
        budget.bytes(prefix_bytes)?;
        let mut prefix = String::with_capacity(prefix_bytes);
        prefix.push_str(&file.path);
        prefix.push('/');
        let comparisons = (usize::BITS - files.len().leading_zeros()) as usize + 1;
        charge_comparisons(comparisons, prefix_bytes, budget)?;
        let next = files.partition_point(|entry| entry.path < prefix);
        if let Some(descendant) = files.get(next)
            && descendant.path.starts_with(&prefix)
        {
            return context.file(&descendant.path).invalid(
                "configuration path has a file as an ancestor",
                budget,
            );
        }
    }
    Ok(())
}

fn charge_comparisons(
    comparisons: usize,
    key_bytes: usize,
    budget: &mut ProjectionBudget,
) -> Result<(), PlanError> {
    let units =
        comparisons
            .checked_mul(key_bytes.max(1))
            .ok_or(PlanError::ProjectionWorkLimit {
                limit: budget.work_limit,
            })?;
    budget.charge_work_units(units)
}

fn charge_sort(
    len: usize,
    key_bytes: usize,
    budget: &mut ProjectionBudget,
) -> Result<(), PlanError> {
    // Conservatively account for traversal and n log n comparisons before the
    // sort, including long shared key prefixes rather than only counting nodes.
    budget.charge_work_units(len)?;
    if len > 1 {
        let levels = (usize::BITS - (len - 1).leading_zeros()) as usize;
        let comparisons = len
            .checked_mul(levels)
            .and_then(|units| units.checked_mul(2))
            .ok_or(PlanError::ProjectionWorkLimit {
                limit: budget.work_limit,
            })?;
        charge_comparisons(comparisons, key_bytes, budget)?;
    }
    Ok(())
}

fn valid_config_path(path: &str) -> bool {
    if path.split('/').count() > crate::execution::configuration::MAX_CONFIGURATION_DEPTH {
        return false;
    }
    !path.is_empty()
        && path.len() <= MAX_CONFIG_PATH_BYTES
        && !path
            .chars()
            .any(|character| character == '\\' || character.is_control())
        && path.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component.len() <= MAX_CONFIG_COMPONENT_BYTES
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn nominal(path: &[&str]) -> CanonicalType {
        CanonicalType::Nominal(Arc::new(
            CanonicalItemIdentity::new(
                syrox_lang::source::SourceDomainId::standard_library(),
                path.iter().copied(),
            )
            .unwrap(),
        ))
    }

    fn selection_type() -> CanonicalType {
        nominal(SELECTION_PATH)
    }

    fn typed_list(item: CanonicalType, items: Vec<Value>) -> Value {
        Value::List {
            ty: Arc::new(CanonicalType::List(Arc::new(item))),
            items,
        }
    }

    fn string(path: &[&str], text: &str) -> Value {
        Value::Nominal {
            ty: Arc::new(nominal(path)),
            value: PrimitiveValue::Str(text.to_owned()),
            resource: false,
        }
    }

    fn structure(path: &[&str], fields: Vec<(&str, Value)>) -> Value {
        Value::Struct {
            owner: None,
            ty: Arc::new(nominal(path)),
            fields: fields
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect(),
        }
    }

    fn service(id: &str, files: &[(&str, &str)]) -> Value {
        structure(
            SERVICE_PATH,
            vec![
                ("id", string(SERVICE_ID_PATH, id)),
                ("pkgs", typed_list(selection_type(), vec![])),
                (
                    "files",
                    typed_list(
                        nominal(FILE_PATH),
                        files
                            .iter()
                            .map(|(path, text)| {
                                structure(
                                    FILE_PATH,
                                    vec![
                                        ("path", string(CONFIG_PATH, path)),
                                        ("text", string(TEXT_PATH, text)),
                                    ],
                                )
                            })
                            .collect(),
                    ),
                ),
                (
                    "commands",
                    typed_list(
                        nominal(&["std", "deployment", "ServiceCommand"]),
                        vec![],
                    ),
                ),
                (
                    "processes",
                    typed_list(
                        nominal(&["std", "deployment", "ServiceProcess"]),
                        vec![],
                    ),
                ),
                (
                    "state",
                    Value::Variant {
                        ty: Arc::new(nominal(&["std", "deployment", "ServiceState"])),
                        index: 0,
                        payload: vec![],
                    },
                ),
                (
                    "secrets",
                    typed_list(
                        nominal(&["std", "deployment", "SecretName"]),
                        vec![],
                    ),
                ),
                (
                    "validators",
                    typed_list(nominal(COMMAND_NAME_PATH), vec![]),
                ),
            ],
        )
    }

    fn deployment(services: Vec<Value>) -> Value {
        structure(
            OS_PATH,
            vec![
                ("pkgs", typed_list(selection_type(), vec![])),
                (
                    "services",
                    typed_list(nominal(SERVICE_PATH), services),
                ),
            ],
        )
    }

    fn project(value: &Value, budget: &mut ProjectionBudget) -> Result<PlanConsumer, PlanError> {
        consumer(
            "os",
            &CanonicalItemIdentity::new(
                syrox_lang::source::SourceDomainId::project(),
                ["os"],
            )
            .unwrap(),
            PlanConsumerKind::Os,
            value,
            &SelectionIndex {
                references: &BTreeMap::new(),
                builds: &[],
                imports: &[],
                commands: &[],
            },
            budget,
        )
    }

    fn unlimited() -> ProjectionBudget {
        ProjectionBudget::new(usize::MAX, usize::MAX)
    }

    #[test]
    fn configuration_limits_count_implicit_directories_and_all_file_bytes() {
        let context = ErrorContext {
            root: "shell",
            service: Some("config"),
            path: None,
        };
        let mut files: Vec<_> = (0..1023)
            .map(|index| PlanConfigFile {
                path: format!("directory/{index}"),
                text: String::new(),
            })
            .collect();
        let mut budget = ProjectionBudget::new(usize::MAX, usize::MAX);
        validate_config_limits(&files, context, &mut budget).unwrap();
        files.push(PlanConfigFile {
            path: "directory/extra".into(),
            text: String::new(),
        });
        assert!(validate_config_limits(&files, context, &mut budget).is_err());
        let mut files = vec![PlanConfigFile {
            path: "file".into(),
            text: "a".repeat(16 * 1024 * 1024),
        }];
        validate_config_limits(&files, context, &mut budget).unwrap();
        files[0].text.push('a');
        assert!(validate_config_limits(&files, context, &mut budget).is_err());
        assert!(valid_config_path(&vec!["a"; 32].join("/")));
        assert!(!valid_config_path(&vec!["a"; 33].join("/")));
    }

    #[test]
    fn service_id_and_path_boundaries_are_exact() {
        for id in [
            "0",
            "git-config",
            "a._-09",
            &"a".repeat(128),
        ] {
            assert!(valid_service_id(id), "{id}");
        }
        for id in [
            "",
            "A",
            "-a",
            "a+b",
            "a/b",
            "é",
            &"a".repeat(129),
        ] {
            assert!(!valid_service_id(id), "{id}");
        }
        for path in [
            "config",
            "nested/config",
            "café",
            &"a".repeat(255),
        ] {
            assert!(valid_config_path(path), "{path}");
        }
        for path in [
            "",
            "/a",
            "a/",
            "a//b",
            ".",
            "..",
            "a/./b",
            "a/../b",
            "a\\b",
            "a\0b",
            "a\nb",
            "a\u{85}b",
            &"a".repeat(256),
        ] {
            assert!(!valid_config_path(path), "{path:?}");
        }
        let mut components = vec!["a".repeat(255); 15];
        components.push("a".repeat(254));
        components.push("a".to_owned());
        let exact = components.join("/");
        assert_eq!(exact.len(), MAX_CONFIG_PATH_BYTES);
        assert!(valid_config_path(&exact));
        assert!(!valid_config_path(&(exact + "a")));
    }

    #[test]
    fn files_are_private_to_each_instance_and_sorted() {
        let value = deployment(vec![
            service("z", &[("same", "z")]),
            service("a", &[("z", "last"), ("same", "a")]),
        ]);
        let consumer = project(&value, &mut unlimited()).unwrap();
        assert!(consumer.pkgs().is_empty());
        assert_eq!(consumer.services()[0].id(), "a");
        assert!(consumer.services()[0].pkgs().is_empty());
        assert_eq!(consumer.services()[0].files()[0].path(), "same");
        assert_eq!(consumer.services()[0].files()[0].text(), "a");
        assert_eq!(consumer.services()[1].files()[0].path(), "same");
    }

    #[test]
    fn malformed_nominals_and_duplicate_instances_have_context() {
        let duplicate = deployment(vec![
            service("same", &[]),
            service("same", &[]),
        ]);
        assert!(matches!(project(&duplicate, &mut unlimited()),
            Err(PlanError::InvalidService { root, service, reason: "duplicate service ID" })
                if root == "os" && service == "same"));
        let mut file_service = service("config", &[("file", "text")]);
        let Value::Struct {
            fields,
            ..
        } = &mut file_service
        else {
            unreachable!()
        };
        fields[0].1 = Value::Str("config".into());
        assert!(matches!(
            project(&deployment(vec![file_service]), &mut unlimited()),
            Err(PlanError::InvalidService {
                reason: "expected a ServiceId",
                ..
            })
        ));
        let foreign = CanonicalType::Nominal(Arc::new(
            CanonicalItemIdentity::new(
                syrox_lang::source::SourceDomainId::project(),
                OS_PATH.iter().copied(),
            )
            .unwrap(),
        ));
        assert_eq!(kind(&foreign), None);
        assert!(
            extract(
                &[],
                &BTreeMap::new(),
                &[],
                &[],
                &[],
                None,
                &mut unlimited()
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn file_conflicts_include_nonadjacent_ancestors() {
        for paths in [
            vec!["a", "a"],
            vec!["a/c", "a-b", "a"],
            vec!["a/b/c", "a/b-c", "a/b"],
        ] {
            let files: Vec<_> = paths.iter().map(|path| (*path, "text")).collect();
            let value = deployment(vec![service("config", &files)]);
            assert!(matches!(project(&value, &mut unlimited()),
                Err(PlanError::InvalidConfigFile { root, service, .. })
                    if root == "os" && service == "config"));
        }
    }

    #[test]
    fn consumer_projection_accounts_work_and_retained_text_before_copy() {
        let value = deployment(vec![service(
            "config",
            &[("dir/file", &"x".repeat(1024))],
        )]);
        let mut measured = unlimited();
        let expected = project(&value, &mut measured).unwrap();
        assert_eq!(
            project(
                &value,
                &mut ProjectionBudget::new(measured.work, measured.retained_bytes)
            ),
            Ok(expected)
        );
        assert!(matches!(
            project(
                &value,
                &mut ProjectionBudget::new(measured.work - 1, usize::MAX)
            ),
            Err(PlanError::ProjectionWorkLimit { .. })
        ));
        assert!(matches!(
            project(
                &value,
                &mut ProjectionBudget::new(usize::MAX, measured.retained_bytes - 1)
            ),
            Err(PlanError::ProjectionRetainedBytesLimit { .. })
        ));
    }

    #[test]
    fn deep_path_search_charges_bytes_without_searching_each_ancestor() {
        let files = vec![PlanConfigFile {
            path: vec!["a"; 1024].join("/"),
            text: String::new(),
        }];
        let context = ErrorContext {
            root: "os",
            service: Some("config"),
            path: None,
        };
        assert!(matches!(
            validate_paths(
                &files,
                context,
                &mut ProjectionBudget::new(4096, usize::MAX)
            ),
            Err(PlanError::ProjectionWorkLimit { .. })
        ));
        assert!(
            validate_paths(
                &files,
                context,
                &mut ProjectionBudget::new(8192, usize::MAX)
            )
            .is_ok()
        );
    }

    #[test]
    fn rejected_paths_and_ids_cannot_inject_terminal_controls() {
        for value in [
            deployment(vec![service("bad\n\u{1b}[31m", &[])]),
            deployment(vec![service(
                "config",
                &[("bad\n\u{1b}[31m", "text")],
            )]),
        ] {
            let error = project(&value, &mut unlimited())
                .unwrap_err()
                .to_string();
            assert!(!error.contains('\n'));
            assert!(!error.contains('\u{1b}'));
            assert!(error.contains("\\n"));
        }
    }

    #[test]
    fn display_marks_configuration_planned_escapes_text_and_obeys_byte_limit() {
        let consumer = project(
            &deployment(vec![service(
                "config",
                &[("dir/file", "line\n\"quoted\"\t")],
            )]),
            &mut unlimited(),
        )
        .unwrap();
        let mut plan = super::super::Plan {
            lock_digest: [0; 32],
            policy_identity: "test".into(),
            standard_library: None,
            packages: vec![],
            acquisitions: vec![],
            builds: vec![],
            imports: vec![],
            commands: vec![],
            consumers: vec![consumer],
            package_edges: 0,
            roots: vec![],
            canonical_display_bytes: 0,
        };
        let bytes = super::super::canonical_display_bytes(&plan, usize::MAX).unwrap();
        assert_eq!(
            super::super::canonical_display_bytes(&plan, bytes),
            Ok(bytes)
        );
        assert_eq!(
            super::super::canonical_display_bytes(&plan, bytes - 1),
            Err(PlanError::DisplayBytesLimit {
                limit: bytes - 1
            })
        );
        plan.canonical_display_bytes = bytes;
        let text = plan.to_string();
        assert_eq!(text.len(), bytes);
        assert!(text.contains("consumers 1 planned configuration"));
        assert!(text.contains("planned file \"dir/file\" text \"line\\n\\\"quoted\\\"\\t\""));
        plan.consumers.clear();
        plan.canonical_display_bytes =
            super::super::canonical_display_bytes(&plan, usize::MAX).unwrap();
        assert!(!plan.to_string().contains("consumers"));
    }
}

use super::{
    COMMAND_NAME_PATH, CONFIG_PATH, CanonicalType, ErrorContext, PlanConfigFile, PlanError,
    PlanPackageSelection, PlanService, ProjectionBudget, SERVICE_ID_PATH, SelectionIndex, Value,
    exact_nominal, fields, list, nominal_string, valid_service_id,
};
use crate::execution::configuration::{
    MAX_RUNTIME_ENVIRONMENT_BYTES, MAX_RUNTIME_ENVIRONMENT_ENTRIES, MAX_RUNTIME_ENVIRONMENT_VALUE,
};
use crate::plan::PlanCommandRef;
use crate::result::valid_name;
use std::collections::BTreeSet;
mod restart;

const COMMAND_PATH: &[&str] = &["std", "deployment", "ServiceCommand"];
const PROCESS_PATH: &[&str] = &["std", "deployment", "ServiceProcess"];
const ARGUMENT_PATH: &[&str] = &["std", "deployment", "CommandArgument"];
const LITERAL_PATH: &[&str] = &["std", "deployment", "CommandLiteral"];
const ENVIRONMENT_NAME_PATH: &[&str] = &[
    "std",
    "deployment",
    "CommandEnvironmentName",
];
const ENVIRONMENT_PATH: &[&str] = &[
    "std",
    "deployment",
    "CommandEnvironment",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanCommandArgument {
    StateDirectory,
    SecretFile(String),
    Literal(String),
    File(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanCommandEnvironment {
    pub name: String,
    pub value: PlanCommandArgument,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanServiceCommand {
    name: String,
    command: PlanCommandRef,
    arguments: Vec<PlanCommandArgument>,
    environment: Vec<PlanCommandEnvironment>,
    expose: Option<String>,
}
impl PlanServiceCommand {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub const fn command(&self) -> &PlanCommandRef {
        &self.command
    }
    pub fn arguments(&self) -> &[PlanCommandArgument] {
        &self.arguments
    }
    pub fn environment(&self) -> &[PlanCommandEnvironment] {
        &self.environment
    }
    pub fn expose(&self) -> Option<&str> {
        self.expose.as_deref()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanServiceProcess {
    pub id: String,
    pub command: String,
    restart: crate::execution::restart::ProcessRestart,
}
impl PlanServiceProcess {
    pub const fn restart(&self) -> crate::execution::restart::ProcessRestart {
        self.restart
    }
}

#[derive(Clone, Copy)]
pub(super) struct Resources<'a> {
    pub files: &'a [PlanConfigFile],
    pub state: super::PlanServiceState,
    pub secrets: &'a [String],
}

fn argument(
    value: &Value,
    resources: Resources<'_>,
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<PlanCommandArgument, PlanError> {
    budget.charge_work()?;
    let Value::Variant {
        ty,
        index,
        payload,
    } = value
    else {
        return context.invalid("expected CommandArgument", budget);
    };
    if !exact_nominal(ty, ARGUMENT_PATH) {
        return context.invalid("expected authenticated CommandArgument", budget);
    }
    match (*index, payload.as_slice()) {
        (0, [value]) => {
            let Some(text) = nominal_string(value, LITERAL_PATH) else {
                return context.invalid("expected CommandLiteral", budget);
            };
            if text.len() > MAX_RUNTIME_ENVIRONMENT_VALUE || text.contains('\0') {
                return context.invalid(
                    "command literal exceeds bound or contains NUL",
                    budget,
                );
            }
            Ok(PlanCommandArgument::Literal(budget.string(text)?))
        }
        (1, [value]) => {
            let Some(path) = nominal_string(value, CONFIG_PATH) else {
                return context.invalid("expected ConfigPath argument", budget);
            };
            budget.charge_work_units(resources.files.len())?;
            if !resources
                .files
                .iter()
                .any(|file| file.path() == path)
            {
                return context.invalid(
                    "command references undeclared configuration file",
                    budget,
                );
            }
            Ok(PlanCommandArgument::File(budget.string(path)?))
        }
        (2, []) if resources.state == super::PlanServiceState::Session => {
            Ok(PlanCommandArgument::StateDirectory)
        }
        (2, []) => context.invalid(
            "command references undeclared session state",
            budget,
        ),
        (3, [value]) => {
            let Some(name) = nominal_string(value, &["std", "deployment", "SecretName"]) else {
                return context.invalid("expected SecretName argument", budget);
            };
            budget.charge_work_units(resources.secrets.len())?;
            if !resources
                .secrets
                .iter()
                .any(|declared| declared == name)
            {
                return context.invalid("command references undeclared secret", budget);
            }
            Ok(PlanCommandArgument::SecretFile(
                budget.string(name)?,
            ))
        }
        _ => context.invalid(
            "invalid command argument or literal exceeds 4096 bytes",
            budget,
        ),
    }
}

fn expose(
    value: &Value,
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<Option<String>, PlanError> {
    let Value::Variant {
        ty,
        index,
        payload,
    } = value
    else {
        return context.invalid("expected optional exposure", budget);
    };
    if !matches!(ty.as_ref(), CanonicalType::Specialization {template,arguments} if template.domain() == syrox_lang::source::SourceDomainId::standard_library() && template.path() == ["std","option","Option"] && matches!(arguments.as_slice(),[item] if exact_nominal(item,COMMAND_NAME_PATH)))
    {
        return context.invalid("expected Option<CommandName>", budget);
    }
    match (*index, payload.as_slice()) {
        (0, []) => Ok(None),
        (1, [name]) => match nominal_string(name, COMMAND_NAME_PATH) {
            Some(name) if valid_name(name) => Ok(Some(budget.string(name)?)),
            _ => context.invalid("invalid exposed command name", budget),
        },
        _ => context.invalid("invalid optional exposure", budget),
    }
}

fn environment(
    value: &Value,
    resources: Resources<'_>,
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanCommandEnvironment>, PlanError> {
    let items = list(
        value,
        |ty| exact_nominal(ty, ENVIRONMENT_PATH),
        context,
        budget,
    )?;
    if items.len() > MAX_RUNTIME_ENVIRONMENT_ENTRIES {
        return context.invalid("too many command environment entries", budget);
    }
    let mut result = budget.collection::<PlanCommandEnvironment>(items.len())?;
    let mut names = BTreeSet::<&str>::new();
    let mut bytes = 0;
    for item in items {
        let values = fields(
            item,
            ENVIRONMENT_PATH,
            &["name", "argument"],
            context,
            budget,
        )?;
        let Some(name) = nominal_string(&values[0].1, ENVIRONMENT_NAME_PATH) else {
            return context.invalid("expected environment name", budget);
        };
        if !crate::runtime::valid_runtime_environment_name(name) || !names.insert(name) {
            return context.invalid(
                "invalid, reserved or duplicate environment name",
                budget,
            );
        }
        let value = argument(&values[1].1, resources, context, budget)?;
        let length = match &value {
            PlanCommandArgument::SecretFile(name) => {
                "/syrox/secrets/".len() + context.service.unwrap_or_default().len() + 1 + name.len()
            }
            PlanCommandArgument::StateDirectory => {
                "/syrox/state/".len() + context.service.unwrap_or_default().len()
            }
            PlanCommandArgument::Literal(value) => value.len(),
            PlanCommandArgument::File(path) => {
                "/syrox/config/".len() + context.service.unwrap_or_default().len() + 1 + path.len()
            }
        };
        bytes += name.len() + length + 2;
        if length > MAX_RUNTIME_ENVIRONMENT_VALUE || bytes > MAX_RUNTIME_ENVIRONMENT_BYTES {
            return context.invalid("command environment exceeds byte bounds", budget);
        }
        result.push(PlanCommandEnvironment {
            name: budget.string(name)?,
            value,
        });
    }
    Ok(result)
}

pub(super) fn commands(
    value: &Value,
    index: &SelectionIndex<'_>,
    pkgs: &[PlanPackageSelection],
    resources: Resources<'_>,
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanServiceCommand>, PlanError> {
    let items = list(
        value,
        |ty| exact_nominal(ty, COMMAND_PATH),
        context,
        budget,
    )?;
    if items.len() > 128 {
        return context.invalid("too many configured commands", budget);
    }
    let mut result = budget.collection::<PlanServiceCommand>(items.len())?;
    let mut names = BTreeSet::<&str>::new();
    for package in pkgs {
        for name in package.commands() {
            budget.charge_work()?;
            names.insert(name);
        }
    }
    for item in items {
        let values = fields(
            item,
            COMMAND_PATH,
            &[
                "name",
                "command",
                "arguments",
                "environment",
                "expose",
            ],
            context,
            budget,
        )?;
        let Some(name) = nominal_string(&values[0].1, COMMAND_NAME_PATH) else {
            return context.invalid("expected command name", budget);
        };
        if !valid_name(name) || !names.insert(name) {
            return context.invalid(
                "invalid or conflicting configured command name",
                budget,
            );
        }
        let Some((reference, entry)) = crate::plan::apps::decode_ref(&values[1].1) else {
            return context.invalid("expected authenticated CommandRef", budget);
        };
        let Some(package) = index.references.get(reference) else {
            return context.invalid("configured command recipe absent", budget);
        };
        budget.charge_work_units(index.commands.len())?;
        if !index
            .commands
            .iter()
            .any(|command| command.package() == package && command.name() == entry)
        {
            return context.invalid("configured command is not declared", budget);
        }
        let items = list(
            &values[2].1,
            |ty| exact_nominal(ty, ARGUMENT_PATH),
            context,
            budget,
        )?;
        if items.len() > 256 {
            return context.invalid("too many configured arguments", budget);
        }
        let mut arguments = budget.collection::<PlanCommandArgument>(items.len())?;
        for value in items {
            arguments.push(argument(value, resources, context, budget)?);
        }
        result.push(PlanServiceCommand {
            name: budget.string(name)?,
            command: PlanCommandRef {
                package: package.copy(budget)?,
                name: budget.string(entry)?,
            },
            arguments,
            environment: environment(&values[3].1, resources, context, budget)?,
            expose: expose(&values[4].1, context, budget)?,
        });
    }
    Ok(result)
}

pub(super) fn processes(
    value: &Value,
    commands: &[PlanServiceCommand],
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanServiceProcess>, PlanError> {
    let items = list(
        value,
        |ty| exact_nominal(ty, PROCESS_PATH),
        context,
        budget,
    )?;
    if items.len() > 128 {
        return context.invalid("too many service processes", budget);
    }
    let mut result = budget.collection::<PlanServiceProcess>(items.len())?;
    let mut ids = BTreeSet::new();
    let mut selected = BTreeSet::new();
    for item in items {
        let values = fields(
            item,
            PROCESS_PATH,
            &["id", "command", "restart"],
            context,
            budget,
        )?;
        let Some(id) = nominal_string(&values[0].1, SERVICE_ID_PATH) else {
            return context.invalid("expected process ID", budget);
        };
        let Some(command) = nominal_string(&values[1].1, COMMAND_NAME_PATH) else {
            return context.invalid("expected process command", budget);
        };
        budget.charge_work_units(commands.len())?;
        if !valid_service_id(id)
            || !ids.insert(id)
            || !selected.insert(command)
            || !commands
                .iter()
                .any(|candidate| candidate.name() == command)
        {
            return context.invalid(
                "invalid process ID, repeated process command or absent configured command",
                budget,
            );
        }
        result.push(PlanServiceProcess {
            id: budget.string(id)?,
            command: budget.string(command)?,
            restart: restart::decode(&values[2].1, context, budget)?,
        });
    }
    Ok(result)
}

pub(super) fn validate_exposures(
    pkgs: &[PlanPackageSelection],
    services: &[PlanService],
    context: ErrorContext<'_>,
    budget: &mut ProjectionBudget,
) -> Result<(), PlanError> {
    let mut names = BTreeSet::<&str>::new();
    for package in pkgs {
        for name in package.commands() {
            budget.charge_work()?;
            names.insert(name);
        }
    }
    for service in services {
        for command in service.commands() {
            budget.charge_work()?;
            if let Some(name) = command.expose()
                && !names.insert(name)
            {
                return context
                    .service(service.id())
                    .invalid("conflicting exposed command name", budget);
            }
        }
    }
    Ok(())
}

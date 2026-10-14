use super::{
    AuthenticatedStandardLibrary, BTreeMap, BTreeSet, CanonicalType, MemoId, PackageIndex,
    PlanBuild, PlanError, PlanOutputRef, PlanPackageId, ProjectionBudget, Value,
    decode_nominal_string, decode_output_ref, decode_recipe_ref, exact_nominal,
};
use crate::result::valid_name as valid_command_name;

const RECIPE_PATH: &[&str] = &["std", "pkg", "Recipe"];
const COMMAND_PATH: &[&str] = &["std", "pkg", "Command"];
const FILE_PATH: &[&str] = &["std", "pkg", "RuntimeFile"];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlanCommandRef {
    pub package: PlanPackageId,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanRuntimeFile {
    pub output: PlanOutputRef,
    pub path: String,
}

/// A recipe entry has its own selected output, executable path and closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanCommand {
    package: PlanPackageId,
    name: String,
    output: String,
    path: String,
    loader: Option<PlanRuntimeFile>,
    libraries: Vec<PlanOutputRef>,
}

impl PlanCommand {
    pub const fn package(&self) -> &PlanPackageId {
        &self.package
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn output(&self) -> &str {
        &self.output
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub const fn loader(&self) -> Option<&PlanRuntimeFile> {
        self.loader.as_ref()
    }
    pub fn libraries(&self) -> impl ExactSizeIterator<Item = &PlanOutputRef> {
        self.libraries.iter()
    }
}

pub(super) fn extract(
    components: &[super::recipes::Component<'_>],
    packages: &PackageIndex<'_>,
    builds: &[PlanBuild],
    imports: &[super::PlanImportedResult],
    references: &BTreeMap<&MemoId, PlanPackageId>,
    standard_library: Option<&AuthenticatedStandardLibrary>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanCommand>, PlanError> {
    if standard_library.is_none() {
        return Ok(Vec::new());
    }
    let mut commands = Vec::new();
    let mut build_by_id = BTreeMap::new();
    for build in builds {
        budget.node::<(&PlanPackageId, &PlanBuild)>()?;
        build_by_id.insert(
            build.package(),
            build
                .program()
                .outputs
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
        );
    }
    for imported in imports {
        budget.node::<(&PlanPackageId, BTreeSet<&str>)>()?;
        budget.charge_work_units(imported.outputs().len())?;
        build_by_id.insert(
            imported.package(),
            imported
                .outputs()
                .keys()
                .map(String::as_str)
                .collect(),
        );
    }
    for root in components
        .iter()
        .filter(|root| exact_nominal(root.ty(), RECIPE_PATH))
    {
        budget.node::<PlanCommand>()?;
        let name = budget.string(root.name())?;
        let invalid = |reason| PlanError::InvalidCommand {
            root: name.clone(),
            reason,
        };
        let Value::Struct {
            fields,
            ..
        } = root.value()
        else {
            return Err(invalid("expected exact command owner"));
        };
        let package = packages.component(root)?.id();
        let value = fields
            .iter()
            .find(|(name, _)| name == "commands")
            .map(|(_, value)| value)
            .ok_or_else(|| invalid("recipe has no commands field"))?;
        let Value::List {
            ty,
            items,
        } = value
        else {
            return Err(invalid("commands must be a list"));
        };
        if !matches!(ty.as_ref(), CanonicalType::List(item) if exact_nominal(item, COMMAND_PATH))
            || items.len() > 128
        {
            return Err(invalid("invalid command list type or count"));
        }
        let mut distinct = BTreeSet::new();
        for value in items {
            budget.node::<PlanCommand>()?;
            let fields = exact_fields(
                value,
                COMMAND_PATH,
                &[
                    "name",
                    "output",
                    "path",
                    "loader",
                    "libraries",
                ],
            )
            .ok_or_else(|| invalid("invalid command fields"))?;
            let command_name = decode_nominal_string(&fields[0].1, &["std", "pkg", "CommandName"])
                .filter(|name| valid_command_name(name))
                .ok_or_else(|| invalid("invalid command name"))?;
            if !distinct.insert(command_name) {
                return Err(invalid("duplicate command name"));
            }
            let output = decode_nominal_string(&fields[1].1, &["std", "pkg", "OutputName"])
                .ok_or_else(|| invalid("invalid command output"))?;
            if !build_by_id
                .get(package)
                .is_some_and(|outputs| outputs.contains(output))
            {
                return Err(invalid(
                    "command output is not produced by recipe",
                ));
            }
            let path = decode_path(&fields[2].1)
                .ok_or_else(|| invalid("command path must be nonempty and relative"))?;
            let Value::List {
                ty,
                items: loaders,
            } = &fields[3].1
            else {
                return Err(invalid("loader must be a list"));
            };
            if !matches!(ty.as_ref(), CanonicalType::List(item) if exact_nominal(item, FILE_PATH))
                || loaders.len() > 1
            {
                return Err(invalid("invalid loader list type or count"));
            }
            let loader = loaders
                .first()
                .map(|value| {
                    let fields = exact_fields(value, FILE_PATH, &["output", "path"])
                        .ok_or_else(|| invalid("invalid runtime file"))?;
                    let output = resolve_output(
                        &fields[0].1,
                        references,
                        &build_by_id,
                        budget,
                        &invalid,
                    )?;
                    let path =
                        decode_path(&fields[1].1).ok_or_else(|| invalid("invalid loader path"))?;
                    Ok::<_, PlanError>(PlanRuntimeFile {
                        output,
                        path: budget.string(path)?,
                    })
                })
                .transpose()?;
            let Value::List {
                ty,
                items: libraries,
            } = &fields[4].1
            else {
                return Err(invalid("libraries must be a list"));
            };
            if libraries.len() > crate::runtime::MAX_RUNTIME_LIBRARIES
                || !matches!(ty.as_ref(), CanonicalType::List(item)
                if matches!(item.as_ref(), CanonicalType::Specialization { template, arguments }
                    if template.domain() == syrox_lang::source::SourceDomainId::standard_library()
                        && template.path() == ["std", "recipe", "OutputRef"]
                        && matches!(arguments.as_slice(), [recipe] if exact_nominal(recipe, RECIPE_PATH))))
            {
                return Err(invalid(
                    "invalid runtime library list type or count",
                ));
            }
            let mut selected = budget.collection::<PlanOutputRef>(libraries.len())?;
            for library in libraries {
                let output = resolve_output(
                    library,
                    references,
                    &build_by_id,
                    budget,
                    &invalid,
                )?;
                if selected.contains(&output) {
                    return Err(invalid("duplicate runtime output"));
                }
                selected.push(output);
            }
            commands.push(PlanCommand {
                package: package.copy(budget)?,
                name: budget.string(command_name)?,
                output: budget.string(output)?,
                path: budget.string(path)?,
                loader,
                libraries: selected,
            });
            if commands.len() > super::MAX_PLAN_PACKAGE_NODES {
                return Err(PlanError::NodeLimit);
            }
        }
    }
    commands.sort_by(|a, b| (&a.package, &a.name).cmp(&(&b.package, &b.name)));
    Ok(commands)
}

fn exact_fields<'a>(
    value: &'a Value,
    path: &[&str],
    names: &[&str],
) -> Option<&'a [(String, Value)]> {
    let Value::Struct {
        ty,
        fields,
        ..
    } = value
    else {
        return None;
    };
    (exact_nominal(ty, path)
        && fields.len() == names.len()
        && fields
            .iter()
            .zip(names)
            .all(|((name, _), expected)| name == expected))
    .then_some(fields)
}

pub(super) fn decode_ref(value: &Value) -> Option<(&MemoId, &str)> {
    let Value::Struct {
        ty,
        fields,
        ..
    } = value
    else {
        return None;
    };
    if !matches!(ty.as_ref(), CanonicalType::Specialization { template, arguments }
        if template.domain() == syrox_lang::source::SourceDomainId::standard_library()
            && template.path() == ["std", "recipe", "CommandRef"]
            && matches!(arguments.as_slice(), [recipe] if exact_nominal(recipe, RECIPE_PATH)))
    {
        return None;
    }
    match fields.as_slice() {
        [(recipe, value), (name, command)] if recipe == "recipe" && name == "name" => Some((
            decode_recipe_ref(value)?,
            decode_nominal_string(command, &["std", "pkg", "CommandName"])?,
        )),
        _ => None,
    }
}

fn decode_path(value: &Value) -> Option<&str> {
    decode_nominal_string(value, &["std", "pkg", "InstalledEntry"])
        .filter(|path| !path.is_empty() && path.len() <= 4096 && crate::build::relative_path(path))
}

fn resolve_output(
    value: &Value,
    references: &BTreeMap<&MemoId, PlanPackageId>,
    builds: &BTreeMap<&PlanPackageId, BTreeSet<&str>>,
    budget: &mut ProjectionBudget,
    invalid: &impl Fn(&'static str) -> PlanError,
) -> Result<PlanOutputRef, PlanError> {
    let (reference, name) =
        decode_output_ref(value).ok_or_else(|| invalid("invalid runtime output reference"))?;
    let package = references
        .get(reference)
        .ok_or_else(|| invalid("runtime output has no selected recipe"))?;
    if !builds
        .get(package)
        .is_some_and(|outputs| outputs.contains(name))
    {
        return Err(invalid(
            "runtime output is not produced by recipe",
        ));
    }
    Ok(PlanOutputRef {
        package: package.copy(budget)?,
        output: budget.string(name)?,
    })
}

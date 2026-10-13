use super::{
    AuthenticatedStandardLibrary, BTreeMap, MemoId, PackageIndex, PlanAcquisition, PlanError,
    PlanOutputRef, PlanPackageId, PrimitiveValue, ProjectionBudget, Value, decode_nominal_string,
    decode_output_ref, exact_nominal,
};

mod program;
const BUILD_PATH: &[&str] = &["std", "pkg", "Build"];

/// A recipe-owned instruction program with structurally selected output inputs.
/// No filesystem or toolchain authority is carried by this pure description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanBuild {
    package: PlanPackageId,
    source_directory: String,
    timeout_seconds: u32,
    program: crate::build::BuildProgram,
    inputs: Vec<PlanOutputRef>,
}

impl PlanBuild {
    pub const fn program(&self) -> &crate::build::BuildProgram {
        &self.program
    }
    pub const fn package(&self) -> &PlanPackageId {
        &self.package
    }
    pub const fn protocol(&self) -> &'static str {
        "program-v2"
    }
    pub fn source_directory(&self) -> &str {
        &self.source_directory
    }
    pub const fn timeout_seconds(&self) -> u32 {
        self.timeout_seconds
    }
    pub fn inputs(&self) -> &[PlanOutputRef] {
        &self.inputs
    }

    pub(crate) fn request(&self) -> crate::build::BuildSpecification {
        crate::build::BuildSpecification {
            package: self.package.clone(),
            source_directory: self.source_directory.clone(),
            timeout_seconds: self.timeout_seconds,
            program: self.program.clone(),
            inputs: Vec::new(),
        }
    }
}

pub(super) fn extract(
    components: &[super::recipes::Component<'_>],
    packages: &PackageIndex<'_>,
    acquisitions: &[PlanAcquisition],
    imports: &[super::PlanImportedResult],
    references: &BTreeMap<&MemoId, PlanPackageId>,
    standard_library: Option<&AuthenticatedStandardLibrary>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanBuild>, PlanError> {
    if standard_library.is_none() {
        return Ok(Vec::new());
    }
    let mut roots: Vec<_> = components
        .iter()
        .filter(|root| root.belongs_to_plan() && exact_nominal(root.ty(), BUILD_PATH))
        .collect();
    roots.sort_by(|left, right| left.identity().cmp(right.identity()));
    if roots.len() > super::MAX_PLAN_PACKAGE_NODES {
        return Err(PlanError::NodeLimit);
    }
    let mut sources = BTreeMap::new();
    for acquisition in acquisitions {
        budget.node::<&PlanAcquisition>()?;
        sources.insert(acquisition.package(), acquisition.sources().len());
    }
    let mut builds = budget.collection::<PlanBuild>(roots.len())?;
    for root in roots {
        budget.node::<PlanBuild>()?;
        let name = budget.string(root.name())?;
        let invalid = |reason| PlanError::InvalidBuild {
            root: name.clone(),
            reason,
        };
        let Value::Struct {
            fields,
            ..
        } = root.value()
        else {
            return Err(invalid("expected an exact std build struct"));
        };
        let names = [
            "source_directory",
            "timeout_seconds",
            "resources",
            "source_format",
            "produces",
            "steps",
            "profile",
        ];
        if fields.len() != names.len()
            || !fields
                .iter()
                .zip(&names)
                .all(|((name, _), expected)| name == expected)
        {
            return Err(invalid("unexpected build fields"));
        }
        let id = packages.component(root)?.id();
        if sources.get(id) != Some(&1) {
            return Err(invalid("build requires exactly one source"));
        }
        let directory = decode_nominal_string(&fields[0].1, &["std", "pkg", "SourceDirectory"])
            .ok_or_else(|| invalid("source_directory is not SourceDirectory"))?;
        let timeout = match &fields[1].1 {
            Value::Nominal {
                ty,
                value: PrimitiveValue::Int(value),
                resource: false,
            } if exact_nominal(ty, &["std", "pkg", "BuildTimeout"]) => u32::try_from(*value).ok(),
            _ => None,
        }
        .filter(|value| (1..=1800).contains(value))
        .ok_or_else(|| invalid("timeout_seconds exceeds the protocol deadline"))?;
        if !crate::build::relative_path(directory) || directory.contains('/') {
            return Err(invalid(
                "invalid build request: expected canonical relative directory",
            ));
        }
        builds.push(PlanBuild {
            package: id.copy(budget)?,
            source_directory: budget.string(directory)?,
            timeout_seconds: timeout,
            program: program::decode(fields, budget, &invalid)?,
            inputs: Vec::new(),
        });
    }
    builds.sort_by(|left, right| left.package.cmp(&right.package));
    extract_build_inputs(
        components,
        packages,
        references,
        &mut builds,
        imports,
        budget,
    )?;
    for build in &builds {
        if build
            .program
            .input_indices()
            .iter()
            .any(|index| *index as usize >= build.inputs.len())
        {
            return Err(PlanError::InvalidBuild {
                root: build.package.to_string(),
                reason: "build path refers to an undeclared input",
            });
        }
    }
    Ok(builds)
}

const INPUTS_PATH: &[&str] = &["std", "pkg", "BuildInputs"];

fn extract_build_inputs(
    components: &[super::recipes::Component<'_>],
    packages: &PackageIndex<'_>,
    references: &BTreeMap<&MemoId, PlanPackageId>,
    builds: &mut [PlanBuild],
    imports: &[super::PlanImportedResult],
    budget: &mut ProjectionBudget,
) -> Result<(), PlanError> {
    use super::CanonicalType;
    for root in components
        .iter()
        .filter(|root| root.belongs_to_plan() && exact_nominal(root.ty(), INPUTS_PATH))
    {
        budget.node::<PlanBuild>()?;
        let name = budget.string(root.name())?;
        let invalid = |reason| PlanError::InvalidBuild {
            root: name.clone(),
            reason,
        };
        let Value::Struct {
            ty,
            fields,
            ..
        } = root.value()
        else {
            return Err(invalid("expected exact std build inputs"));
        };
        if !exact_nominal(ty, INPUTS_PATH) || fields.len() != 1 || fields[0].0 != "selected" {
            return Err(invalid("invalid build input fields"));
        }
        let owner = packages.component(root)?.id();
        let index = builds
            .binary_search_by(|build| build.package.cmp(owner))
            .map_err(|_| invalid("build inputs require an existing build"))?;
        let Value::List {
            ty,
            items,
        } = &fields[0].1
        else {
            return Err(invalid("outputs must be a list"));
        };
        if !matches!(ty.as_ref(), CanonicalType::List(item) if matches!(item.as_ref(), CanonicalType::Specialization { template, arguments }
            if template.domain() == syrox_lang::source::SourceDomainId::standard_library()
                && template.path() == ["std", "recipe", "OutputRef"]
                && matches!(arguments.as_slice(), [recipe] if exact_nominal(recipe, &["std", "pkg", "Recipe"]))))
            || items.len() > 64
        {
            return Err(invalid(
                "build inputs must be a bounded list of output references",
            ));
        }
        let mut inputs = budget.collection::<PlanOutputRef>(items.len())?;
        for item in items {
            let (reference, output) =
                decode_output_ref(item).ok_or_else(|| invalid("invalid build output reference"))?;
            let provider = references
                .get(reference)
                .ok_or_else(|| invalid("build output has no selected provider"))?;
            budget.charge_work_units(imports.len())?;
            let imported = imports
                .iter()
                .any(|entry| entry.package() == provider && entry.outputs().contains_key(output));
            let built = builds
                .binary_search_by(|build| build.package.cmp(provider))
                .is_ok_and(|index| {
                    builds[index]
                        .program
                        .outputs
                        .iter()
                        .any(|name| name == output)
                });
            if provider == owner || !(built || imported) {
                return Err(invalid(
                    "build input requires another recipe's declared output",
                ));
            }
            inputs.push(PlanOutputRef {
                package: provider.copy(budget)?,
                output: budget.string(output)?,
            });
        }
        builds[index].inputs = inputs;
    }
    Ok(())
}

pub(super) fn validate_execution_graph(
    builds: &[PlanBuild],
    budget: &mut ProjectionBudget,
) -> Result<(), PlanError> {
    let mut complete = BTreeMap::new();
    for build in builds {
        visit_inputs(
            build,
            builds,
            &mut complete,
            &mut std::collections::BTreeSet::new(),
            budget,
        )?;
    }
    Ok(())
}

fn visit_inputs<'a>(
    build: &'a PlanBuild,
    builds: &'a [PlanBuild],
    complete: &mut BTreeMap<&'a PlanPackageId, usize>,
    active: &mut std::collections::BTreeSet<&'a PlanPackageId>,
    budget: &mut ProjectionBudget,
) -> Result<usize, PlanError> {
    budget.charge_work()?;
    let invalid = || PlanError::InvalidBuild {
        root: build.package.to_string(),
        reason: "cyclic or too deep build inputs",
    };
    if let Some(&height) = complete.get(&build.package) {
        if active.len() + height > 128 {
            return Err(invalid());
        }
        return Ok(height);
    }
    if active.len() >= 128 || active.contains(&build.package) {
        return Err(invalid());
    }
    budget.node::<&PlanPackageId>()?;
    budget
        .bytes(2 * (size_of::<&PlanPackageId>() + 6 * size_of::<usize>()) + size_of::<usize>())?;
    active.insert(&build.package);
    let mut height = 1;
    for input in build.inputs.iter().map(|input| &input.package) {
        let Ok(next) = builds.binary_search_by(|build| build.package.cmp(input)) else {
            // Validated imported providers are graph leaves, not build nodes.
            continue;
        };
        height = height.max(1 + visit_inputs(&builds[next], builds, complete, active, budget)?);
    }
    active.remove(&build.package);
    complete.insert(&build.package, height);
    Ok(height)
}

use syrox_lang::evaluator::RealizedRoot;

use super::{
    AuthenticatedStandardLibrary, CanonicalItemIdentity, CanonicalType, PlanError,
    ProjectionBudget, RealizedProgram, Value, exact_nominal,
};

/// A borrowed contract value from a root or one of its recipe fields. All
/// components share the already evaluated recipe's identity and provenance.
pub(super) struct Component<'a> {
    root: &'a RealizedRoot,
    ty: &'a CanonicalType,
    value: &'a Value,
}

impl Component<'_> {
    pub(super) fn recipe_owner(&self) -> Option<syrox_lang::source::SourceDomainId> {
        self.root.recipe_owner()
    }
    pub(super) fn name(&self) -> &str {
        self.root.name()
    }
    pub(super) fn identity(&self) -> &CanonicalItemIdentity {
        self.root.identity()
    }
    pub(super) fn is_selected(&self) -> bool {
        self.root.is_selected()
    }
    /// Explicit selection retains the member's original library domain. Merely
    /// importing a library does not admit its unselected value roots.
    pub(super) fn belongs_to_plan(&self) -> bool {
        self.is_selected()
            || self.identity().domain() == syrox_lang::source::SourceDomainId::project()
    }
    pub(super) fn reference(&self) -> Option<&syrox_lang::evaluator::MemoId> {
        self.root.selected_reference()
    }
    pub(super) fn aliases(&self) -> impl ExactSizeIterator<Item = &str> {
        self.root.aliases()
    }
    pub(super) const fn ty(&self) -> &CanonicalType {
        self.ty
    }
    pub(super) const fn value(&self) -> &Value {
        self.value
    }
}

pub(super) fn components<'a>(
    realized: &'a RealizedProgram,
    standard_library: Option<&AuthenticatedStandardLibrary>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<Component<'a>>, PlanError> {
    let mut result = Vec::new();
    for root in realized.roots() {
        let (Some(ty), Some(value)) = (root.ty(), root.value()) else {
            return Err(PlanError::UnrealizedRoot {
                root: budget.string(root.name())?,
            });
        };
        if standard_library.is_some() && is_recipe(ty) {
            recipe_components(root, value, &mut result, budget)?;
        } else {
            push(
                &mut result,
                Component {
                    root,
                    ty,
                    value,
                },
                budget,
            )?;
        }
    }
    Ok(result)
}

fn is_recipe(ty: &CanonicalType) -> bool {
    matches!(ty, CanonicalType::Nominal(identity)
        if identity.domain() == syrox_lang::source::SourceDomainId::standard_library()
            && identity.path() == ["std", "pkg", "Recipe"])
}

fn recipe_components<'a>(
    root: &'a RealizedRoot,
    value: &'a Value,
    result: &mut Vec<Component<'a>>,
    budget: &mut ProjectionBudget,
) -> Result<(), PlanError> {
    let name = budget.string(root.name())?;
    let invalid = |reason| PlanError::InvalidRecipe {
        root: name.clone(),
        reason,
    };
    let Value::Struct {
        fields,
        ..
    } = value
    else {
        return Err(invalid("expected a recipe struct"));
    };
    let names: &[&str] = &[
        "package",
        "acquisition",
        "build",
        "build_inputs",
        "commands",
        "imported",
    ];
    if fields.len() != names.len()
        || !fields
            .iter()
            .zip(names)
            .all(|((name, _), expected)| name == expected)
    {
        return Err(invalid("unexpected recipe fields"));
    }
    if matches!(
        unwrap_optional(&fields[5].1, "ImportedResult"),
        OptionalComponent::Present(_)
    ) && fields[1..4]
        .iter()
        .zip(["Acquisition", "Build", "BuildInputs"])
        .any(|((_, value), contract)| {
            !matches!(
                unwrap_optional(value, contract),
                OptionalComponent::Absent
            )
        })
    {
        return Err(invalid(
            "imported result cannot declare acquisition, build or build inputs",
        ));
    }
    // Preserve the complete recipe as the owner of its named command list.
    let Value::Struct {
        ty,
        ..
    } = value
    else {
        unreachable!()
    };
    push(
        result,
        Component {
            root,
            ty,
            value,
        },
        budget,
    )?;
    for (index, (_, value)) in fields
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 4)
    {
        budget.charge_work()?;
        let value = if index > 0 {
            let contract = match index {
                1 => "Acquisition",
                2 => "Build",
                3 => "BuildInputs",
                5 => "ImportedResult",
                _ => unreachable!(),
            };
            match unwrap_optional(value, contract) {
                OptionalComponent::Present(value) => value,
                OptionalComponent::Absent => continue,
                OptionalComponent::Invalid => {
                    return Err(invalid("invalid optional recipe component"));
                }
            }
        } else {
            value
        };
        let Value::Struct {
            ty,
            ..
        } = value
        else {
            return Err(invalid(
                "recipe component must be a contract struct",
            ));
        };
        let contract = match index {
            0 => "Package",
            1 => "Acquisition",
            2 => "Build",
            3 => "BuildInputs",
            5 => "ImportedResult",
            _ => {
                return Err(invalid(
                    "recipe build has no supported build contract",
                ));
            }
        };
        if !exact_nominal(ty, &["std", "pkg", contract]) {
            return Err(invalid(
                "recipe component has the wrong nominal contract",
            ));
        }
        push(
            result,
            Component {
                root,
                ty,
                value,
            },
            budget,
        )?;
    }
    Ok(())
}

enum OptionalComponent<'a> {
    Invalid,
    Absent,
    Present(&'a Value),
}

fn unwrap_optional<'a>(value: &'a Value, contract: &str) -> OptionalComponent<'a> {
    let Value::Variant {
        ty,
        index,
        payload,
    } = value
    else {
        return OptionalComponent::Invalid;
    };
    let CanonicalType::Specialization {
        template,
        arguments,
    } = ty.as_ref()
    else {
        return OptionalComponent::Invalid;
    };
    if template.domain() != syrox_lang::source::SourceDomainId::standard_library()
        || template.path() != ["std", "option", "Option"]
        || arguments.len() != 1
        || !exact_nominal(&arguments[0], &["std", "pkg", contract])
    {
        return OptionalComponent::Invalid;
    }
    match (*index, payload.as_slice()) {
        (0, []) => OptionalComponent::Absent,
        (1, [value]) => OptionalComponent::Present(value),
        _ => OptionalComponent::Invalid,
    }
}

fn push<'a>(
    result: &mut Vec<Component<'a>>,
    component: Component<'a>,
    budget: &mut ProjectionBudget,
) -> Result<(), PlanError> {
    budget.node::<Component<'a>>()?;
    // Account for geometric Vec growth as well as the live borrowed component.
    budget.bytes(size_of::<Component<'a>>())?;
    result.push(component);
    Ok(())
}

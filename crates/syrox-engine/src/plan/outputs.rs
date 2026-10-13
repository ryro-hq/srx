use super::{Plan, PlanPackageId, PlanType, PlanValue};

/// A named output of a structural node in one Plan. This is not an Action or
/// Artifact identity; it is resolved before realization from a typed `OutputRef`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlanOutputRef {
    pub package: PlanPackageId,
    pub output: String,
}

impl Plan {
    /// Resolve a projected typed recipe reference by structural identity.
    pub fn recipe_reference(&self, value: &PlanValue) -> Option<&PlanPackageId> {
        self.standard_library()?;
        let PlanValue::Struct {
            ty,
            fields,
        } = value
        else {
            return None;
        };
        if !reference_type(ty, "RecipeRef") {
            return None;
        }
        let [
            (
                factory,
                PlanValue::Reference {
                    domain,
                    path,
                },
            ),
        ] = fields.as_slice()
        else {
            return None;
        };
        if factory != "factory" {
            return None;
        }
        self.packages()
            .find(|package| package.id().domain() == *domain && package.id().path() == path)
            .map(super::PlanPackage::id)
    }

    /// Decode a projected `std::OutputRef<std::Recipe>` within this Plan. Types,
    /// node identity and the declared output are all checked; package labels and
    /// public aliases are never used as dependency identities.
    pub fn output_reference(&self, value: &PlanValue) -> Option<PlanOutputRef> {
        self.standard_library()?;
        let PlanValue::Struct {
            ty,
            fields,
        } = value
        else {
            return None;
        };
        if !reference_type(ty, "OutputRef") {
            return None;
        }
        let [
            (recipe, reference),
            (
                output,
                PlanValue::Nominal {
                    ty: name_ty,
                    value,
                    resource: false,
                },
            ),
        ] = fields.as_slice()
        else {
            return None;
        };
        if recipe != "recipe"
            || output != "output"
            || !nominal(name_ty, &["std", "pkg", "OutputName"])
        {
            return None;
        }
        let PlanValue::Str(output) = value.as_ref() else {
            return None;
        };
        let package = self.recipe_reference(reference)?;
        self.named_output(package, output)
    }

    pub fn named_output(&self, package: &PlanPackageId, output: &str) -> Option<PlanOutputRef> {
        let declared = self.builds().any(|build| {
            build.package() == package
                && build
                    .program()
                    .outputs
                    .iter()
                    .any(|name| name == output)
        }) || self
            .imports()
            .any(|entry| entry.package() == package && entry.outputs().contains_key(output));
        declared.then(|| PlanOutputRef {
            package: package.clone(),
            output: output.to_owned(),
        })
    }
}

fn reference_type(ty: &PlanType, name: &str) -> bool {
    matches!(ty, PlanType::Specialization { domain, path, arguments }
        if *domain == syrox_lang::source::SourceDomainId::standard_library().as_u32()
            && path == &["std", "recipe", name]
            && matches!(arguments.as_slice(), [recipe] if nominal(recipe, &["std", "pkg", "Recipe"])))
}

fn nominal(ty: &PlanType, expected: &[&str]) -> bool {
    matches!(ty, PlanType::Nominal { domain, path }
        if *domain == syrox_lang::source::SourceDomainId::standard_library().as_u32() && path == expected)
}

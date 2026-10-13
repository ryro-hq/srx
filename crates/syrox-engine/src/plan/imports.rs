use super::{
    BTreeMap, ContentDigest, PackageIndex, PlanError, PlanPackageId, ProjectionBudget, Value,
    decode_nominal_string, exact_nominal,
};
use crate::result::valid_name;
use crate::store::RootName;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanImportedResult {
    package: PlanPackageId,
    root: RootName,
    manifest: ContentDigest,
    outputs: BTreeMap<String, String>,
}
impl PlanImportedResult {
    pub const fn package(&self) -> &PlanPackageId {
        &self.package
    }
    pub const fn root(&self) -> &RootName {
        &self.root
    }
    pub const fn manifest(&self) -> ContentDigest {
        self.manifest
    }
    /// Output name to manifest key. This selects an entry, never renames it:
    /// admission must verify that the manifest entry has this same output name.
    pub const fn outputs(&self) -> &BTreeMap<String, String> {
        &self.outputs
    }
}

pub(super) fn extract(
    components: &[super::recipes::Component<'_>],
    packages: &PackageIndex<'_>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanImportedResult>, PlanError> {
    let mut imports = Vec::new();
    for component in components
        .iter()
        .filter(|component| exact_nominal(component.ty(), &["std", "pkg", "ImportedResult"]))
    {
        budget.node::<PlanImportedResult>()?;
        let invalid = |reason| PlanError::InvalidRecipe {
            root: component.name().into(),
            reason,
        };
        let Value::Struct {
            fields,
            ..
        } = component.value()
        else {
            return Err(invalid("invalid imported result"));
        };
        if fields.len() != 3
            || fields
                .iter()
                .map(|(name, _)| name.as_str())
                .ne(["root", "manifest", "entries"])
        {
            return Err(invalid("invalid imported result fields"));
        }
        let root = decode_nominal_string(&fields[0].1, &["std", "pkg", "ResultRoot"])
            .ok_or_else(|| invalid("invalid result root type"))?;
        let root =
            RootName::new(budget.string(root)?).map_err(|_| invalid("invalid result root"))?;
        let pin = decode_nominal_string(&fields[1].1, &["std", "pkg", "ResultDigest"])
            .ok_or_else(|| invalid("invalid result manifest type"))?;
        let manifest = pin
            .parse::<ContentDigest>()
            .map_err(|_| invalid("invalid result manifest digest"))?;
        let Value::List {
            items,
            ..
        } = &fields[2].1
        else {
            return Err(invalid("invalid imported outputs"));
        };
        if items.is_empty() || items.len() > 128 {
            return Err(invalid("imported output count exceeded"));
        }
        let mut outputs = BTreeMap::new();
        let mut keys = std::collections::BTreeSet::new();
        for item in items {
            budget.node::<(String, String)>()?;
            let Value::Struct {
                ty,
                fields,
                ..
            } = item
            else {
                return Err(invalid("invalid imported output"));
            };
            if !exact_nominal(ty, &["std", "pkg", "ImportedOutput"])
                || fields.len() != 2
                || fields[0].0 != "output"
                || fields[1].0 != "key"
            {
                return Err(invalid("invalid imported output fields"));
            }
            let output = decode_nominal_string(&fields[0].1, &["std", "pkg", "OutputName"])
                .filter(|name| valid_name(name))
                .ok_or_else(|| invalid("invalid imported output name"))?;
            let key = decode_nominal_string(&fields[1].1, &["std", "pkg", "ResultOutputKey"])
                .filter(|name| valid_name(name))
                .ok_or_else(|| invalid("invalid imported output key"))?;
            if outputs
                .insert(budget.string(output)?, budget.string(key)?)
                .is_some()
                || !keys.insert(key)
            {
                return Err(invalid("duplicate imported output name or key"));
            }
        }
        imports.push(PlanImportedResult {
            package: packages.component(component)?.id().copy(budget)?,
            root,
            manifest,
            outputs,
        });
    }
    imports.sort_by(|left, right| left.package.cmp(&right.package));
    if imports
        .windows(2)
        .any(|pair| pair[0].package == pair[1].package)
    {
        return Err(PlanError::InvalidRecipe {
            root: "imported".into(),
            reason: "duplicate imported result",
        });
    }
    Ok(imports)
}

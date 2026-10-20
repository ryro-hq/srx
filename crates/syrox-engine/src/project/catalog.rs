//! Instantiate every required selector using the loader's authenticated domains.
use super::{CheckConfiguration, loader};
use crate::{
    catalog::{Catalog, CatalogError},
    store::ContentDigest,
};
use std::{fmt::Write as _, path::Path};
use syrox_lang::{
    checker::check,
    evaluator::{PrimitiveValue, Value, evaluate_with_limits},
    resolver::resolve,
    syntax::parse_sources,
};

pub fn check_catalog_with(
    root: &Path,
    catalog: &Catalog,
    configuration: &CheckConfiguration,
) -> Result<(), CatalogError> {
    catalog.validate()?;
    catalog.generate_releases(root, true)?;
    let invalid = |message: String| CatalogError::Invalid(message);
    let loaded = loader::load_project_linux(root, configuration).map_err(|error| {
        invalid(format!(
            "catalog project admission failed: {error}"
        ))
    })?;
    let parsed = parse_sources(&loaded.sources)
        .map_err(|errors| invalid(format!("catalog syntax: {errors:?}")))?;
    let namespace = |file: &str| -> Result<(String, syrox_lang::source::SourceId), CatalogError> {
        for input in loaded.inputs() {
            let Some(directory) = input.locator().strip_prefix("modules:") else {
                continue;
            };
            for source in input.files() {
                if Path::new(directory).join(source.relative_path()) == Path::new(file) {
                    let module = parsed
                        .iter()
                        .find(|candidate| candidate.source_id() == source.source_id())
                        .expect("loaded source")
                        .module();
                    return Ok((
                        std::iter::once(input.name())
                            .chain(module.iter().map(String::as_str))
                            .collect::<Vec<_>>()
                            .join("::"),
                        source.source_id(),
                    ));
                }
            }
        }
        Err(invalid(format!(
            "catalog file is absent from declared module inputs: {file}"
        )))
    };
    let mut outputs = String::from("outputs {\n");
    let mut contract_pins = Vec::new();
    for (index, package) in catalog.packages.iter().enumerate() {
        namespace(&package.recipe)?;
        let (contract, contract_source) = namespace(&package.contract)?;
        contract_pins.push(
            ContentDigest::sha256(
                loaded
                    .sources
                    .get(contract_source)
                    .expect("contract source")
                    .text()
                    .as_bytes(),
            )
            .to_string(),
        );
        let request = format!(
            "{}({{ version = {:?}; variant = {:?}; system = {:?}; }})",
            package.factory, package.version, package.variant, package.system
        );
        writeln!(
            outputs,
            "catalog_combination_{index}: std::PackageRef<{contract}::{}> = {request};",
            package.contract_type
        )
        .expect("String write");
        writeln!(outputs, "catalog_recipe_{index}: std::Recipe = std::recipe_value(std::package_recipe({request}));").expect("String write");
    }
    outputs.push_str("}\n");
    let mut sources = loaded.sources.clone();
    sources
        .add("<catalog-combinations>", outputs)
        .map_err(|error| invalid(error.to_string()))?;
    let parsed =
        parse_sources(&sources).map_err(|errors| invalid(format!("catalog syntax: {errors:?}")))?;
    let resolved =
        resolve(parsed).map_err(|errors| invalid(format!("catalog resolution: {errors:?}")))?;
    let checked = check(resolved, &configuration.policy)
        .map_err(|errors| invalid(format!("catalog contracts: {errors:?}")))?;
    let realized = evaluate_with_limits(
        &checked,
        &configuration.policy,
        &configuration.environment,
        configuration.evaluation_limits,
    )
    .map_err(|error| invalid(error.to_string()))?;
    if !realized.is_success() {
        return Err(invalid(format!(
            "catalog selectors failed: {:?}",
            realized.diagnostics().collect::<Vec<_>>()
        )));
    }
    for (index, package) in catalog.packages.iter().enumerate() {
        let reference = realized
            .roots()
            .find(|root| root.name() == format!("catalog_combination_{index}"))
            .and_then(|root| root.value())
            .ok_or_else(|| invalid("missing selected package".into()))?;
        let pin = &contract_pins[index];
        for (field, expected) in [
            ("version", &package.version),
            ("variant", &package.variant),
            ("system", &package.system),
            ("contract", pin),
        ] {
            if string(field_value(reference, field)) != Some(expected.as_str()) {
                return Err(invalid(format!(
                    "selected package metadata differs: {} {} {field}",
                    package.name, package.version
                )));
            }
        }
        let recipe = realized
            .roots()
            .find(|root| root.name() == format!("catalog_recipe_{index}"))
            .and_then(|root| root.value())
            .ok_or_else(|| invalid("missing selected recipe".into()))?;
        let expected_id = format!(
            "{}-{}-{}-{}-{pin}",
            package.name, package.version, package.variant, package.system
        );
        if string(field_value(recipe, "package").and_then(|value| field_value(value, "id")))
            != Some(expected_id.as_str())
        {
            return Err(invalid(
                "selected recipe identity differs from its package".into(),
            ));
        }
        let Some(Value::Variant {
            payload,
            ..
        }) = field_value(recipe, "acquisition")
        else {
            return Err(invalid(
                "selected recipe has no acquisition".into(),
            ));
        };
        let Some(Value::List {
            items,
            ..
        }) = payload
            .first()
            .and_then(|value| field_value(value, "sources"))
        else {
            return Err(invalid(
                "selected recipe has no source inventory".into(),
            ));
        };
        let [source] = items.as_slice() else {
            return Err(invalid(
                "selected recipe must have one pinned upstream source".into(),
            ));
        };
        if string(field_value(source, "url")) != Some(package.source_url.as_str())
            || string(field_value(source, "sha256")) != Some(package.source_sha256.as_str())
            || !matches!(field_value(source, "maximum_bytes"), Some(Value::Nominal { value: PrimitiveValue::Int(limit), .. }) if u64::try_from(*limit).ok() == Some(package.source_maximum_bytes))
        {
            return Err(invalid(
                "selected recipe source differs from release provenance".into(),
            ));
        }
    }
    Ok(())
}

fn field_value<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    if let Value::Struct {
        fields,
        ..
    } = value
    {
        fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value)
    } else {
        None
    }
}
fn string(value: Option<&Value>) -> Option<&str> {
    match value? {
        Value::Str(value)
        | Value::Nominal {
            value: PrimitiveValue::Str(value),
            ..
        } => Some(value),
        _ => None,
    }
}

use std::path::Path;

use syrox_lang::{
    checker::check, evaluator::RealizedRootOutcome, evaluator::evaluate_with_limits,
    resolver::resolve, source::SourceSet, syntax::parse_sources,
};

use super::{CheckConfiguration, CheckFailure, CheckReport, LoadedProject, ValidatedProject};

pub(super) fn validate_loaded(
    loaded: LoadedProject,
    configuration: &CheckConfiguration,
) -> Result<ValidatedProject, CheckFailure> {
    let checked = check_loaded(&loaded, configuration)?;
    let declarations = checked.resolved().parsed().declaration_count();
    let environment = asset_environment(&loaded, &configuration.environment);
    let realized = evaluate_with_limits(
        &checked,
        &configuration.policy,
        &environment,
        configuration.evaluation_limits,
    )
    .map_err(|source| CheckFailure::EvaluationSetup {
        source,
    })?;
    require_success(&loaded, &realized)?;
    Ok(ValidatedProject {
        loaded,
        declarations,
        realized,
    })
}

pub(super) fn check_loaded(
    loaded: &LoadedProject,
    configuration: &CheckConfiguration,
) -> Result<syrox_lang::checker::CheckedProgram, CheckFailure> {
    let input = &loaded.sources;
    let parsed = parse_sources(input).map_err(|errors| CheckFailure::Diagnostics {
        input: input.clone(),
        errors,
    })?;
    let resolved = resolve(parsed).map_err(|errors| CheckFailure::Diagnostics {
        input: input.clone(),
        errors,
    })?;
    check(resolved, &configuration.policy).map_err(|errors| CheckFailure::Diagnostics {
        input: input.clone(),
        errors,
    })
}

pub(super) fn require_success(
    loaded: &LoadedProject,
    realized: &syrox_lang::evaluator::RealizedProgram,
) -> Result<(), CheckFailure> {
    if !realized.is_success() {
        let errors = realized.diagnostics().cloned().collect();
        let failed_roots = realized
            .roots()
            .filter(|root| matches!(root.outcome(), RealizedRootOutcome::Failed(_)))
            .map(|root| root.name().to_owned())
            .collect();
        return Err(CheckFailure::Evaluation {
            input: loaded.sources.clone(),
            errors,
            failed_roots,
        });
    }
    Ok(())
}

pub(super) fn check_sources(
    path: &Path,
    input: SourceSet,
    configuration: &CheckConfiguration,
) -> Result<CheckReport, CheckFailure> {
    let parsed = parse_sources(&input).map_err(|errors| CheckFailure::Diagnostics {
        input: input.clone(),
        errors,
    })?;
    let declarations = parsed.declaration_count();
    let resolved = resolve(parsed).map_err(|errors| CheckFailure::Diagnostics {
        input: input.clone(),
        errors,
    })?;
    let checked =
        check(resolved, &configuration.policy).map_err(|errors| CheckFailure::Diagnostics {
            input: input.clone(),
            errors,
        })?;
    let realized = evaluate_with_limits(
        &checked,
        &configuration.policy,
        &configuration.environment,
        configuration.evaluation_limits,
    )
    .map_err(|source| CheckFailure::EvaluationSetup {
        source,
    })?;
    let realized_roots = realized.roots().len();
    if !realized.is_success() {
        let errors = realized.diagnostics().cloned().collect();
        let failed_roots = realized
            .roots()
            .filter(|root| matches!(root.outcome(), RealizedRootOutcome::Failed(_)))
            .map(|root| root.name().to_owned())
            .collect();
        return Err(CheckFailure::Evaluation {
            input,
            errors,
            failed_roots,
        });
    }
    Ok(CheckReport {
        path: path.to_path_buf(),
        declarations,
        realized_roots,
    })
}

/// Bind retained asset bytes to the domains assigned by this loaded graph.
pub(super) fn asset_environment(
    loaded: &LoadedProject,
    base: &syrox_lang::evaluator::EvaluationEnvironment,
) -> syrox_lang::evaluator::EvaluationEnvironment {
    let mut roots = std::collections::BTreeMap::new();
    super::collect_project_roots(
        loaded,
        loaded,
        syrox_lang::source::SourceDomainId::project(),
        &mut roots,
    );
    let mut environment = base.clone();
    for (domain, project) in roots {
        for asset in project.assets() {
            environment = environment.with_authenticated_asset(
                domain,
                asset.relative_path.to_string_lossy().into_owned(),
                asset.content.clone(),
            );
        }
    }
    environment
}

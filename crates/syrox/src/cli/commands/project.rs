use crate::cli::{
    arguments::ProjectCommand,
    presentation::{render_check_error, render_message, render_operation_error, usage_error},
    reference,
};
use crate::signals;
use std::path::Path;
use std::process::ExitCode;
use syrox_engine::{
    acquire::{
        archive::{ArchiveFormat, ArchiveLimits, inspect_archive, inspect_source_archive},
        https::{HttpsSourceRequest, HttpsTransportPolicy, acquire_https},
    },
    plan::{Plan, PlanPackageId, PlanSourceRequest},
    project::{
        CheckConfiguration, CheckFailure, ProjectOperationError, check_path_with,
        check_project_lock_with, fetch_project_inputs_with, lock::LockStatus, lock_project_with,
        plan_project_consumer_with, plan_project_package_with, plan_project_with,
    },
    store::{RootName, Store},
};

pub(crate) fn run(command: ProjectCommand, checks: &CheckConfiguration) -> ExitCode {
    match command {
        ProjectCommand::Check {
            path,
            file,
        } => match reference::project(file.as_deref(), path.as_deref()) {
            Ok(path) => check(&path, checks),
            Err(error) => usage_error(&error),
        },
        ProjectCommand::Lock {
            path,
            file,
            check: only,
            fetch,
        } => match reference::project(file.as_deref(), path.as_deref()) {
            Ok(path) => lock(&path, only, fetch, checks),
            Err(error) => usage_error(&error),
        },
        ProjectCommand::Plan {
            path,
            file,
            output,
        } => match reference::project(file.as_deref(), path.as_deref()) {
            Ok(path) => plan(&path, output.as_deref(), checks),
            Err(error) => usage_error(&error),
        },
        ProjectCommand::Fetch {
            path,
            package,
            source_index,
            store,
            root,
            allow_https,
        } => render_message(acquire_source(
            &path,
            &package,
            source_index,
            &store,
            &root,
            &allow_https,
            checks,
        )),
        ProjectCommand::InspectSource {
            path,
            package,
            source_index,
            store,
        } => render_message(inspect(
            &path,
            &package,
            source_index,
            &store,
            checks,
        )),
    }
}

fn lock(
    path: &Path,
    check_only: bool,
    fetch: bool,
    configuration: &CheckConfiguration,
) -> ExitCode {
    let signals = match signals::OperationSignals::install() {
        Ok(signals) => signals,
        Err(error) => return usage_error(&error.to_string()),
    };
    let mut configuration = configuration.clone();
    configuration.github.cancellation = signals.cancellation.clone();
    let result = if check_only {
        check_project_lock_with(path, &configuration)
    } else if fetch {
        fetch_project_inputs_with(path, &configuration)
    } else {
        lock_project_with(path, &configuration)
    };
    match result {
        Ok(report) => {
            let state = if check_only || fetch {
                "current"
            } else {
                match report.status() {
                    LockStatus::Created => "created",
                    LockStatus::Updated => "updated",
                    LockStatus::Unchanged => "unchanged",
                }
            };
            println!("lock {state}: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            let cancelled = matches!(
                &error,
                ProjectOperationError::Check(CheckFailure::Github(
                    syrox_engine::acquire::github::GithubError::Cancelled
                ))
            );
            let exit = render_operation_error(error);
            if cancelled {
                ExitCode::from(signals.cancelled_exit_code())
            } else {
                exit
            }
        }
    }
}

fn plan(path: &Path, output: Option<&str>, configuration: &CheckConfiguration) -> ExitCode {
    let result = match output {
        Some(name) => plan_project_consumer_with(path, configuration, name),
        None => plan_project_with(path, configuration),
    };
    match result {
        Ok(plan) => {
            print!("{plan}");
            ExitCode::SUCCESS
        }
        Err(error) => render_operation_error(error),
    }
}

fn check(path: &Path, configuration: &CheckConfiguration) -> ExitCode {
    match check_path_with(path, configuration) {
        Ok(report) => {
            println!(
                "checked {}: {} top-level declaration(s)",
                report.path.display(),
                report.declarations
            );
            ExitCode::SUCCESS
        }
        Err(error) => render_check_error(error),
    }
}

/// The exact URL grant is independent of the project lock and digest. Disallow
/// redirects: each new destination would require a new grant from the caller.
fn acquire_source(
    project: &Path,
    package: &str,
    source_index: usize,
    store_path: &Path,
    root: &str,
    allow_https: &str,
    configuration: &CheckConfiguration,
) -> Result<String, String> {
    let plan = plan_project_package_with(project, configuration, package)
        .map_err(|error| crate::cli::presentation::project_error(&error))?;
    let (_, request) = select_source(&plan, package, source_index)?;
    if request.url() != allow_https {
        return Err("the exact planned source URL must match --allow-https".to_owned());
    }
    let request = HttpsSourceRequest::new(
        request.url(),
        request.digest(),
        request.maximum_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let root = RootName::new(root).map_err(|error| error.to_string())?;
    let store = Store::open(store_path).map_err(|error| error.to_string())?;
    let acquired = acquire_https(
        &store,
        &request,
        &root,
        HttpsTransportPolicy {
            maximum_redirects: 0,
            ..HttpsTransportPolicy::default()
        },
    )
    .map_err(|error| error.to_string())?;
    Ok(format!(
        "fetched {} source {} sha256 {} ({} bytes, cache_hit={}, root={:?})",
        package,
        source_index,
        acquired.object().digest(),
        acquired.object().size(),
        acquired.cache_hit(),
        acquired.root_state()
    ))
}

fn inspect(
    project: &Path,
    package: &str,
    source_index: usize,
    store_path: &Path,
    configuration: &CheckConfiguration,
) -> Result<String, String> {
    let plan = plan_project_package_with(project, configuration, package)
        .map_err(|error| crate::cli::presentation::project_error(&error))?;
    let (package_id, source) = select_source(&plan, package, source_index)?;
    let store = Store::open(store_path).map_err(|error| error.to_string())?;
    let inventory = if plan.builds().any(|build| {
        build.package() == package_id
            && build.program().source_format == syrox_engine::build::BuildSourceFormat::Xz
    }) {
        let mut limits = ArchiveLimits::large_xz();
        limits.compressed_bytes = limits
            .compressed_bytes
            .min(source.maximum_bytes());
        inspect_archive(
            &store,
            source.digest(),
            ArchiveFormat::XzTar,
            limits,
        )
    } else {
        inspect_source_archive(&store, source.digest(), source.maximum_bytes())
    }
    .map_err(|error| error.to_string())?;
    Ok(format!(
        "source {}:{} sha256 {}: {} entries, {} regular files, {} expanded file bytes",
        package,
        source_index,
        source.digest(),
        inventory.entries(),
        inventory.files(),
        inventory.expanded_bytes()
    ))
}

fn select_source<'a>(
    plan: &'a Plan,
    package: &str,
    source_index: usize,
) -> Result<(&'a PlanPackageId, &'a PlanSourceRequest), String> {
    let package_id = plan
        .packages()
        .find(|entry| entry.has_export(package))
        .ok_or_else(|| "selected package has no Plan node".to_owned())?
        .id();
    let source = plan
        .acquisitions()
        .find(|acquisition| acquisition.package() == package_id)
        .and_then(|acquisition| acquisition.sources().nth(source_index))
        .ok_or_else(|| "package has no acquisition source at that index".to_owned())?;
    Ok((package_id, source))
}

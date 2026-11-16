use std::{path::PathBuf, process::ExitCode};
use syrox_engine::{
    acquire::local::import_source_stream,
    project::{CheckConfiguration, plan_project_package_with},
    store::{RootName, Store},
    system::descriptor::open_resolved,
};

#[derive(Debug, clap::Args)]
pub(crate) struct ImportSourceArguments {
    path: PathBuf,
    package: String,
    source_index: usize,
    /// Existing regular file. Symlinks in any path component are refused.
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    root: String,
}

pub(super) fn run(arguments: &ImportSourceArguments, checks: &CheckConfiguration) -> ExitCode {
    let signals = match crate::signals::OperationSignals::install() {
        Ok(signals) => signals,
        Err(error) => return super::usage_error(&error.to_string()),
    };
    let result = execute(arguments, checks, &signals.cancellation);
    let failed = result.is_err();
    let exit = super::render_message(result);
    if failed && signals.cancellation.is_cancelled() {
        ExitCode::from(signals.cancelled_exit_code())
    } else {
        exit
    }
}

fn execute(
    arguments: &ImportSourceArguments,
    checks: &CheckConfiguration,
    cancellation: &syrox_engine::cancellation::Cancellation,
) -> Result<String, String> {
    let plan = plan_project_package_with(&arguments.path, checks, &arguments.package)
        .map_err(|error| crate::cli::presentation::project_error(&error))?;
    let (_, request) = super::select_source(&plan, &arguments.package, arguments.source_index)?;
    let root = RootName::new(&arguments.root).map_err(|error| error.to_string())?;
    let file = open_resolved(
        None,
        &arguments.file,
        false,
        libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    )
    .map_err(|error| format!("cannot open source file: {error}"))?;
    if !file
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("source import requires a regular file".to_owned());
    }
    let store_path = std::path::absolute(&arguments.store).map_err(|error| error.to_string())?;
    let store = Store::initialize(&store_path).map_err(|error| error.to_string())?;
    let imported = import_source_stream(
        &store,
        file,
        request.digest(),
        request.maximum_bytes(),
        &root,
        cancellation,
    )
    .map_err(|error| error.to_string())?;
    Ok(format!(
        "imported {} source {} sha256 {} ({} bytes, root={:?})",
        arguments.package,
        arguments.source_index,
        imported.object().digest(),
        imported.object().size(),
        imported.root_state()
    ))
}

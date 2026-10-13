use crate::cli::arguments::StoreCommand;
use std::path::PathBuf;
use std::process::ExitCode;
use syrox_engine::{
    build::{BuildRecoveryState, check_build_host, rebuild_build_index, recover_builds},
    config::UserConfiguration,
    result::clear_materializations,
    store::{GcRequest, Store, StoreError},
};

#[cfg(target_os = "linux")]
#[derive(Debug, clap::Args)]
pub(crate) struct StoreOptions {
    /// Explicit operational configuration instead of the global default.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override the selected Store.
    #[arg(long)]
    store: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub(crate) struct GcArguments {
    #[command(flatten)]
    options: StoreOptions,
    /// Collect unretained objects after the dry-run report.
    #[arg(long)]
    apply: bool,
}

fn user(options: &StoreOptions) -> Result<UserConfiguration, String> {
    UserConfiguration::load_with_store(
        options.config.as_deref(),
        options.store.as_deref(),
    )
    .map_err(|e| e.to_string())
}

fn render(result: Result<bool, String>) -> ExitCode {
    match result {
        Ok(complete) => ExitCode::from(u8::from(!complete)),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

pub(crate) fn gc(args: &GcArguments) -> ExitCode {
    render((|| {
        let user = user(&args.options)?;
        let store = Store::open(user.store()).map_err(|e| e.to_string())?;
        let mut maintenance = store.maintenance().map_err(|e| e.to_string())?;
        let report = maintenance
            .garbage_collect(&GcRequest {
                collect: args.apply,
                ..GcRequest::default()
            })
            .map_err(|e| e.to_string())?;
        println!(
            "{} unretained object(s), {} bytes {}",
            report.candidates.len(),
            report.candidate_bytes,
            if args.apply {
                "collected"
            } else {
                "collectable (use --apply to collect)"
            }
        );
        if report.uncertain || !report.failures.is_empty() {
            return Err(format!(
                "garbage collection left {} failure(s); inspect Store before retry",
                report.failures.len()
            ));
        }
        #[cfg(target_os = "linux")]
        if args.apply {
            let views = clear_materializations(&mut maintenance).map_err(|e| e.to_string())?;
            if views != 0 {
                println!("{views} reconstructible view(s) reclaimed");
            }
        }
        Ok(true)
    })())
}

pub(crate) fn doctor(options: &StoreOptions) -> ExitCode {
    render((|| {
        let user = user(options)?;
        println!("store {}", user.store().display());
        match Store::open(user.store()) {
            Ok(_) => println!("store: available"),
            Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                println!("store: not initialized (first build will create it)");
            }
            Err(error) => return Err(format!("store: {error}")),
        }
        let toolchain = user
            .host_toolchain()
            .ok_or_else(|| "build.host-toolchain is not configured".to_owned())?;
        check_build_host(toolchain).map_err(|e| e.to_string())?;
        println!("build host: ready ({})", toolchain.display());
        Ok(true)
    })())
}

pub(crate) fn recover(arguments: &StoreOptions) -> ExitCode {
    render(execute_recover(arguments))
}

fn execute_recover(arguments: &StoreOptions) -> Result<bool, String> {
    let user = user(arguments)?;
    let store = Store::open(user.store()).map_err(|e| e.to_string())?;
    let report = recover_builds(&store).map_err(|e| e.to_string())?;
    let mut complete = true;
    for entry in &report.entries {
        match &entry.state {
            BuildRecoveryState::Active => println!("active {}", entry.operation),
            BuildRecoveryState::Recovered => println!("recovered {}", entry.operation),
            BuildRecoveryState::Retained(reason) => {
                eprintln!("retained {}: {reason}", entry.operation);
                complete = false;
            }
        }
    }
    if report.entries.is_empty() {
        println!("no build operations to recover");
    }
    Ok(complete)
}

pub(crate) fn reindex(arguments: &StoreOptions) -> ExitCode {
    render(execute_reindex(arguments))
}

fn execute_reindex(arguments: &StoreOptions) -> Result<bool, String> {
    let user = user(arguments)?;
    let store = Store::open(user.store()).map_err(|e| e.to_string())?;
    let report = rebuild_build_index(&store).map_err(|e| e.to_string())?;
    println!(
        "indexed {} retained build actions; skipped {} unsupported receipts; removed {} stale entries",
        report.indexed, report.skipped, report.removed_stale
    );
    for action in &report.conflicts {
        eprintln!("divergent retained results for action {action}");
    }
    Ok(report.conflicts.is_empty())
}

pub(crate) fn run(command: &StoreCommand) -> ExitCode {
    match command {
        StoreCommand::Doctor(args) => doctor(args),
        StoreCommand::Gc(args) => gc(args),
        StoreCommand::Recover(args) => recover(args),
        StoreCommand::Reindex(args) => reindex(args),
    }
}

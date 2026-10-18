use std::path::PathBuf;
use std::process::ExitCode;

use crate::cli::presentation::{realize_error, render_message};

use syrox_engine::{
    build::BuildError, build::BuildExecution, cancellation::Cancellation,
    config::UserConfiguration, project::CheckConfiguration, realize::BuildProgress,
    realize::RealizeError, realize::ResolvedBuild, realize::realize_build, realize::realize_builds,
    realize::resolve_build, realize::resolve_builds, realize::search_build_exports,
    realize::search_project_build_exports,
};

#[derive(Debug, clap::Args)]
pub(crate) struct ReferenceArguments {
    /// Explicit public member: catalog member, .#member, or ./project#member.
    reference: Option<String>,
    /// Select a project's main.srx; use .#export to select one of its exports.
    #[arg(short = 'f', long)]
    file: Option<PathBuf>,
    /// Explicit user configuration instead of `$XDG_CONFIG_HOME/syrox/config.toml`.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Find matching packages in the pinned catalog or a selected local project (info only).
    #[arg(long)]
    search: Option<String>,
}

#[derive(Debug, clap::Args)]
pub(crate) struct Arguments {
    #[command(flatten)]
    selection: ReferenceArguments,
    /// Override the configured Store (default: `$XDG_DATA_HOME/syrox/store`).
    #[arg(long)]
    store: Option<PathBuf>,
    /// Require all sources to be present and verified locally.
    #[arg(short = 'o', long)]
    offline: bool,
    /// Resolve and display the selected build without acquiring or building.
    #[arg(short = 'n', long)]
    dry_run: bool,
    /// Show operational progress and complete result identities.
    #[arg(short = 'v', long, action = clap::ArgAction::Count, conflicts_with = "quiet")]
    verbose: u8,
    /// Only print the build result (or a failure).
    #[arg(short = 'q', long, action = clap::ArgAction::Count, conflicts_with = "verbose")]
    quiet: u8,
    /// Build every public export from this project.
    #[arg(short = 'A', long)]
    all: bool,
    /// Maximum concurrent builds with -A (1..=8).
    #[arg(short = 'j', long, requires = "all", value_parser = clap::value_parser!(u8).range(1..=8))]
    jobs: Option<u8>,
}

pub(crate) fn run(args: &Arguments, configuration: &CheckConfiguration) -> ExitCode {
    let signals = match crate::signals::OperationSignals::install() {
        Ok(signals) => signals,
        Err(error) => {
            return render_message(Err(format!(
                "cannot install build signal handlers: {error}"
            )));
        }
    };
    match execute(args, configuration, &signals.cancellation) {
        Ok(message) => render_message(Ok(message)),
        Err(failure) => {
            eprintln!("error: {}", failure.message);
            ExitCode::from(if failure.cancelled {
                signals.cancelled_exit_code()
            } else {
                1
            })
        }
    }
}

struct Failure {
    message: String,
    cancelled: bool,
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            cancelled: false,
        }
    }
}

fn execute(
    args: &Arguments,
    configuration: &CheckConfiguration,
    cancellation: &Cancellation,
) -> Result<String, Failure> {
    if args.selection.search.is_some() {
        return Err("--search is available on srx info"
            .to_owned()
            .into());
    }
    let user = UserConfiguration::load_with_store(
        args.selection.config.as_deref(),
        args.store.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    let reference = crate::cli::reference::select(
        args.selection.reference.as_deref(),
        args.selection.file.as_deref(),
    )?;
    if args.all {
        if !matches!(
            syrox_engine::project::reference::parse_project_reference(&reference),
            Ok(
                syrox_engine::project::reference::ProjectReference::Project {
                    export: None,
                    ..
                }
            )
        ) {
            return Err("-A/--all requires a project path or -f main.srx"
                .to_owned()
                .into());
        }
        return execute_all(
            &reference,
            &user,
            args.offline,
            args.dry_run,
            usize::from(args.jobs.unwrap_or(1)),
            configuration,
            cancellation,
        );
    }
    let resolved =
        resolve_build(&reference, &user, configuration).map_err(|e| realize_error(&e))?;
    if args.dry_run {
        return Ok(format!(
            "would build {}\n{}",
            resolved.description().package(),
            summary(&resolved)
        ));
    }
    let worker = crate::cli::worker_path::build_candidate()?;
    if args.verbose > 0 {
        eprintln!(
            "resolved {}#{} ({})",
            resolved.project().display(),
            resolved.export(),
            resolved.backend()
        );
    }
    let result = realize_build(
        &resolved,
        syrox_engine::realize::RealizeOptions {
            configuration: &user,
            worker: &worker,
            offline: args.offline,
        },
        cancellation,
        |stage| {
            if args.verbose > 0 {
                eprintln!(
                    "{}",
                    match stage {
                        BuildProgress::PreparingStore => "preparing Store",
                        BuildProgress::CheckingBackend => "checking build host",
                        BuildProgress::SourceCacheHit => "source: verified local cache hit",
                        BuildProgress::AcquiringSource => "source: acquiring pinned bytes",
                        BuildProgress::Building =>
                            "realizing (toolchain inventory, action cache, build if needed)",
                    }
                );
            }
        },
    )
    .map_err(|error| Failure {
        cancelled: matches!(
            error,
            RealizeError::Cancelled | RealizeError::Build(BuildError::Cancelled)
        ),
        message: realize_error(&error),
    })?;
    let (verb, execution) = match result.execution {
        BuildExecution::Built {
            operation,
        } => ("built", format!("operation {operation}")),
        BuildExecution::Cached => (
            "reused",
            "cache verified local action hit".to_owned(),
        ),
        BuildExecution::Shared {
            operation,
        } => ("shared", format!("operation {operation}")),
    };
    if args.quiet > 0 {
        return Ok(format!(
            "{verb} {}",
            resolved.description().package()
        ));
    }
    Ok(format!(
        "{verb} {}\n{}\nstore {}\n{execution}\naction {}\nartifact {}\nreceipt {}\ntoolchain {}\nfiles {}\nroot {}",
        resolved.description().package(),
        summary(&resolved),
        user.store().display(),
        result.action,
        result.artifact,
        result.receipt,
        result
            .toolchain
            .map_or_else(|| "none".into(), |pin| pin.to_string()),
        result.files,
        result.root
    ))
}

fn execute_all(
    reference: &str,
    user: &UserConfiguration,
    offline: bool,
    dry_run: bool,
    jobs: usize,
    configuration: &CheckConfiguration,
    cancellation: &Cancellation,
) -> Result<String, Failure> {
    let builds = resolve_builds(reference, user, configuration).map_err(|e| realize_error(&e))?;
    if builds.is_empty() {
        return Err("project has no public buildable exports"
            .to_owned()
            .into());
    }
    if builds.len() > 64 {
        return Err(
            "-A/--all is limited to 64 buildable exports per invocation"
                .to_owned()
                .into(),
        );
    }
    if dry_run {
        return Ok(format!(
            "would build {} export(s): {}",
            builds.len(),
            builds
                .iter()
                .map(ResolvedBuild::export)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let worker = crate::cli::worker_path::build_candidate()?;
    let results = realize_builds(
        &builds,
        syrox_engine::realize::RealizeOptions {
            configuration: user,
            worker: &worker,
            offline,
        },
        jobs,
        cancellation,
    )
    .map_err(|error| Failure {
        cancelled: matches!(
            error,
            RealizeError::Cancelled | RealizeError::Build(BuildError::Cancelled)
        ),
        message: realize_error(&error),
    })?;
    Ok(builds
        .iter()
        .zip(results)
        .map(|(resolved, result)| {
            format!(
                "{} {}\nroot {}",
                match result.execution {
                    BuildExecution::Built {
                        ..
                    } => "built",
                    BuildExecution::Cached => "reused",
                    BuildExecution::Shared {
                        ..
                    } => "shared",
                },
                resolved.description().package(),
                result.root
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

pub(crate) fn info(args: &ReferenceArguments, checks: &CheckConfiguration) -> ExitCode {
    render_message((|| {
        let user = UserConfiguration::load(args.config.as_deref()).map_err(|e| e.to_string())?;
        if let Some(query) = &args.search {
            let names = if args.reference.is_some() || args.file.is_some() {
                let reference =
                    crate::cli::reference::select(args.reference.as_deref(), args.file.as_deref())?;
                if !matches!(
                    syrox_engine::project::reference::parse_project_reference(&reference),
                    Ok(
                        syrox_engine::project::reference::ProjectReference::Project {
                            export: None,
                            ..
                        }
                    )
                ) {
                    return Err("--search requires a project path or -f main.srx".to_owned());
                }
                search_project_build_exports(query, std::path::Path::new(&reference), checks)
            } else {
                search_build_exports(query, &user, checks)
            }
            .map_err(|e| realize_error(&e))?;
            return Ok(if names.is_empty() {
                "no matching packages".into()
            } else {
                names.join("\n")
            });
        }
        let reference =
            crate::cli::reference::select(args.reference.as_deref(), args.file.as_deref())?;
        let resolved = resolve_build(&reference, &user, checks).map_err(|e| realize_error(&e))?;
        Ok(format!(
            "{}\nsource-directory {}\ntimeout-seconds {}\nstore {}\nhost-toolchain {}",
            summary(&resolved),
            resolved.description().source_directory(),
            resolved.description().timeout_seconds(),
            user.store().display(),
            user.host_toolchain().map_or_else(
                || "not configured".to_owned(),
                |path| path.display().to_string()
            )
        ))
    })())
}

fn summary(resolved: &ResolvedBuild) -> String {
    let text = format!(
        "project {}\nexport {}\npackage {}\nlock sha256 {}\nprotocol {}\nbackend {}",
        resolved.project().display(),
        resolved.export(),
        resolved.description().package(),
        resolved.lock_digest(),
        resolved.description().protocol(),
        resolved.backend()
    );

    text
}

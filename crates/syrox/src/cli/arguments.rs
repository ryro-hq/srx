use super::commands::{build, bundle, format, host, install_self, os, run, session, shell, store};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "srx",
    version,
    about = "Syrox package manager",
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    /// Select the authenticated standard library.
    #[arg(long = "std", value_enum, default_value_t = StandardLibrarySelection::Bundled, global = true)]
    pub(crate) standard_library: StandardLibrarySelection,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum StandardLibrarySelection {
    Bundled,
    None,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Maintain versioned sources, configuration contracts and build matrices.
    #[cfg(target_os = "linux")]
    Catalog {
        #[command(subcommand)]
        command: super::commands::catalog::Command,
    },
    /// Format one source to stdout, without loading or evaluating a project.
    Fmt(format::Arguments),
    /// Serve editor diagnostics and navigation over LSP stdio.
    #[cfg(target_os = "linux")]
    Lsp {
        path: Option<PathBuf>,
    },
    /// Install this release and its embedded worker without host utilities.
    #[cfg(target_os = "linux")]
    InstallSelf(install_self::Arguments),
    /// Inspect native Linux capabilities and candidate cgroup delegation.
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
    /// Build a declared package with automatic source acquisition and retention.
    Build(build::Arguments),
    /// Run a declared application with its verified runtime closure.
    Run(run::Arguments),
    /// Run an exposed managed command with temporary Shell configuration.
    Shell(shell::Arguments),
    /// Prepare, inspect and apply retained Os generations.
    Os {
        #[command(subcommand)]
        command: os::Command,
    },
    /// Inspect or recover recorded managed Shell sessions.
    Session {
        #[command(subcommand)]
        command: session::Command,
    },
    /// Transfer and consume pinned runtime bundles without build inputs.
    Bundle {
        #[command(subcommand)]
        command: bundle::Command,
    },
    /// Inspect a locked build reference and its origin without realizing it.
    Info(build::ReferenceArguments),
    /// Project checking, locking, planning and explicit source inspection.
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// Store build-operation maintenance.
    Store {
        #[command(subcommand)]
        command: StoreCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ProjectCommand {
    /// Check the selected project without effects.
    Check {
        path: Option<PathBuf>,
        #[arg(short = 'f', long)]
        file: Option<PathBuf>,
    },
    /// Create or verify its Syrox.lock.
    Lock {
        path: Option<PathBuf>,
        #[arg(short = 'f', long)]
        file: Option<PathBuf>,
        #[arg(long)]
        check: bool,
        /// Acquire missing GitHub snapshots at the locked commit without updating refs.
        #[arg(long, conflicts_with = "check")]
        fetch: bool,
    },
    /// Print the pure, locked project plan.
    Plan {
        path: Option<PathBuf>,
        #[arg(short = 'f', long)]
        file: Option<PathBuf>,
        /// Select one Os or Shell output and its referenced packages.
        #[arg(long)]
        output: Option<String>,
    },
    /// Explicitly acquire a pinned source (normally handled by build).
    Fetch {
        path: PathBuf,
        package: String,
        source_index: usize,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        root: String,
        #[arg(long)]
        allow_https: String,
    },
    /// Inspect a verified source archive without extracting it.
    InspectSource {
        path: PathBuf,
        package: String,
        source_index: usize,
        #[arg(long)]
        store: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum StoreCommand {
    /// Inspect configured Store and build-host capabilities without building.
    Doctor(store::StoreOptions),
    /// Preview or collect unretained Store objects.
    Gc(store::GcArguments),
    /// Recover orphaned build operations after confirmed settlement.
    Recover(store::StoreOptions),
    /// Rebuild the action index from retained results.
    Reindex(store::StoreOptions),
}

#[derive(Debug, Subcommand)]
pub(crate) enum HostCommand {
    /// Inspect kernel and cgroup v2 capabilities; active probes are opt-in.
    Inspect(host::Arguments),
    /// Internal, gated process used exclusively for the cgroup migration probe.
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    ProbeChild,
}

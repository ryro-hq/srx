//! Parsing `srx` arguments and dispatching the selected operation.
//!
//! [`arguments`] defines command inputs. Handlers in [`commands`] own the engine
//! operation for each domain. This module selects configuration and the bundled
//! standard library, then translates the result into CLI status. [`crate::lsp`]
//! serves editor requests; the internal worker enters through another binary.

use crate::lsp;
use arguments::{Cli, Command, HostCommand, StandardLibrarySelection};
use clap::Parser as _;
use commands::{
    build, bundle, format, host, install_self, os, project, run, session, shell, store,
};
use std::process::ExitCode;
use syrox_engine::project::{AuthenticatedStandardLibrary, CheckConfiguration};

mod arguments;
mod commands;
pub(crate) mod presentation;
pub(crate) mod reference;
pub(crate) mod worker_path;

pub(crate) fn main() -> ExitCode {
    run(Cli::parse())
}

pub(crate) fn configuration(enabled: bool) -> CheckConfiguration {
    let mut configuration = CheckConfiguration::default();
    if enabled {
        configuration.standard_library = Some(AuthenticatedStandardLibrary::bundled());
    }
    configuration
}

/// Dispatch parsed commands and project operations.
pub(crate) fn run(cli: Cli) -> ExitCode {
    let configuration = configuration(matches!(
        cli.standard_library,
        StandardLibrarySelection::Bundled
    ));
    match cli.command {
        #[cfg(target_os = "linux")]
        Command::Catalog {
            command,
        } => commands::catalog::run(command, &configuration),
        Command::Fmt(arguments) => format::run(&arguments),
        #[cfg(target_os = "linux")]
        Command::Lsp {
            path,
        } => lsp::run(path, configuration),
        #[cfg(target_os = "linux")]
        Command::InstallSelf(arguments) => install_self::run(&arguments),
        Command::Host {
            command,
        } => match command {
            HostCommand::Inspect(arguments) => host::inspect(&arguments),
            #[cfg(target_os = "linux")]
            HostCommand::ProbeChild => host::probe_child(),
        },
        Command::Build(arguments) => build::run(&arguments, &configuration),
        Command::Run(arguments) => run::run(&arguments, &configuration),
        Command::Shell(arguments) => shell::run(&arguments, &configuration),
        Command::Os {
            command,
        } => os::run(&command, &configuration),
        Command::Session {
            command,
        } => session::run(&command),
        Command::Bundle {
            command,
        } => bundle::run(&command),
        Command::Info(arguments) => build::info(&arguments, &configuration),
        Command::Project {
            command,
        } => project::run(command, &configuration),
        Command::Store {
            command,
        } => store::run(&command),
    }
}

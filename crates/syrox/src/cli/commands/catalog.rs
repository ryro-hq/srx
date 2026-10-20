//! Native maintenance of the version inventory and its required build matrix.

use clap::Subcommand;
use std::{path::PathBuf, process::ExitCode};
use syrox_engine::project::CheckConfiguration;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Verify local qualified bundles and write a descriptor for explicit trust.
    AuthorizeArtifacts {
        path: PathBuf,
        #[arg(long)]
        release: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
        /// Descriptor must be written beside the bundles it authorizes.
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate only release data, retaining shared selectors and construction.
    Generate {
        path: PathBuf,
        #[arg(long)]
        check: bool,
    },
    /// Require every matrix row and verify bundle pins before publishing a manifest.
    ReleaseManifest {
        path: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Build and run an exact combination, test nginx HTTP and verify offline transport.
    Qualify {
        path: PathBuf,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Append a signed release and generate locks without promoting its default.
    Add {
        path: PathBuf,
        name: String,
        version: String,
    },
    /// Query fixed official channels for new stable releases.
    Updates {
        path: PathBuf,
    },
    /// Verify official archives and signatures with previously pinned keys.
    VerifySources {
        path: PathBuf,
    },
    /// Validate version entries, source declarations and typed contracts.
    Check {
        path: PathBuf,
    },
    /// Generate or verify pins for every registered version, variant and ABI.
    Lock {
        path: PathBuf,
        #[arg(long)]
        check: bool,
        #[arg(long, conflicts_with = "check")]
        accept_key_change: bool,
    },
    /// Emit the complete mandatory GitHub Actions build matrix as JSON.
    Matrix {
        path: PathBuf,
    },
    /// Reject loss of previously retained version identities.
    Preserve {
        path: PathBuf,
        previous: PathBuf,
    },
}

pub(crate) fn run(command: Command, checks: &CheckConfiguration) -> ExitCode {
    match super::catalog_query::execute(command, checks) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

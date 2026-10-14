//! Native maintenance of the version inventory and its required build matrix.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;
use syrox_engine::{
    catalog::{Catalog, CatalogError, CatalogLock, LOCK_FILE},
    project::{
        CheckConfiguration, check_path_with, check_project_lock_with, lock_project_with,
        plan_project_package_with,
    },
};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
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
    match execute(command, checks) {
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

fn execute(
    command: Command,
    checks: &CheckConfiguration,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Command::ReleaseManifest {
        path,
        evidence,
        output,
    } = command
    {
        return super::catalog_qualification::release_manifest(&path, &evidence, &output, checks);
    }
    if let Command::Qualify {
        path,
        identity,
        config,
        store,
        output,
    } = command
    {
        super::catalog_qualification::qualify(&path, &identity, &config, &store, &output, checks)?;
        return Ok(format!(
            "qualified {identity}: native execution and offline import passed"
        ));
    }
    let path = match &command {
        Command::Qualify {
            ..
        }
        | Command::ReleaseManifest {
            ..
        } => unreachable!("handled above"),
        Command::Add {
            path,
            ..
        }
        | Command::Updates {
            path,
        }
        | Command::VerifySources {
            path,
        }
        | Command::Check {
            path,
        }
        | Command::Lock {
            path,
            ..
        }
        | Command::Matrix {
            path,
        }
        | Command::Preserve {
            path,
            ..
        } => path,
    };
    let mut catalog = Catalog::load(path)?;
    if let Command::Add {
        name,
        version,
        ..
    } = &command
    {
        let previous = fs::read(path.join(LOCK_FILE))
            .ok()
            .map(|bytes| serde_json::from_slice::<CatalogLock>(&bytes))
            .transpose()?;
        catalog.add_version(path, name, version)?;
        lock_project_with(path, checks)?;
        let mut next = catalog.lock(path)?;
        if let Some(previous) = previous {
            next.retain_previous(&previous, false)?;
        }
        fs::write(path.join(LOCK_FILE), next.encode()?)?;
        let changes = path.join("changes");
        fs::create_dir_all(&changes)?;
        let record = serde_json::json!({
            "schema": 1, "name": name, "version": version,
            "default": catalog.defaults.get(name),
            "signing_authority": catalog.channels.iter().find(|channel| &channel.name == name),
            "combinations": next.versions.iter().filter(|entry| &entry.package.name == name && &entry.package.version == version).collect::<Vec<_>>(),
            "qualification": "required before publication",
        });
        let mut change = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(changes.join(format!("{name}-{version}.json")))?;
        change.write_all(serde_json::to_string_pretty(&record)?.as_bytes())?;
        change.sync_all()?;
        return Ok(format!(
            "added {name} {version}; default unchanged; native qualification required"
        ));
    }
    if matches!(command, Command::Updates { .. }) {
        return Ok(serde_json::to_string_pretty(&catalog.updates()?)?);
    }
    if matches!(command, Command::VerifySources { .. }) {
        return Ok(catalog.verify_sources(path)?.join("\n"));
    }
    check_path_with(path, checks)?;
    let mut lock = catalog.lock(path)?;
    if let Ok(previous) = fs::read(path.join(LOCK_FILE)) {
        let previous: CatalogLock = serde_json::from_slice(&previous)?;
        lock.retain_previous(
            &previous,
            matches!(
                command,
                Command::Lock {
                    accept_key_change: true,
                    ..
                }
            ),
        )?;
    }
    match command {
        Command::Qualify {
            ..
        }
        | Command::ReleaseManifest {
            ..
        } => unreachable!("handled above"),
        Command::Add {
            ..
        } => unreachable!("handled before lock projection"),
        Command::Updates {
            ..
        }
        | Command::VerifySources {
            ..
        } => unreachable!("handled before pure admission"),
        Command::Check {
            ..
        } => Ok(format!(
            "checked {} version/variant/system combinations",
            lock.versions.len()
        )),
        Command::Lock {
            path,
            check,
            ..
        } => {
            let bytes = lock.encode()?;
            if check {
                if fs::read(path.join(LOCK_FILE))? != bytes {
                    return Err(CatalogError::Invalid("Catalog.lock is stale".to_owned()).into());
                }
                check_project_lock_with(&path, checks)?;
                Ok("catalog and project locks match".to_owned())
            } else {
                lock_project_with(&path, checks)?;
                let temporary = path.join(".Catalog.lock.new");
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temporary)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                fs::rename(temporary, path.join(LOCK_FILE))?;
                Ok(format!(
                    "locked {} combinations",
                    lock.versions.len()
                ))
            }
        }
        Command::Matrix {
            path,
        } => {
            if fs::read(path.join(LOCK_FILE))? != lock.encode()? {
                return Err(CatalogError::Invalid("Catalog.lock is stale".to_owned()).into());
            }
            check_project_lock_with(&path, checks)?;
            for entry in &catalog.packages {
                let plan = plan_project_package_with(&path, checks, &entry.export)?;
                let pin = plan
                    .acquisitions()
                    .flat_map(syrox_engine::plan::PlanAcquisition::sources)
                    .any(|source| {
                        source.url() == entry.source_url
                            && source.digest().to_string() == entry.source_sha256
                            && source.maximum_bytes() == entry.source_maximum_bytes
                    });
                if !pin {
                    return Err(CatalogError::Invalid(format!(
                        "{} does not consume its declared source",
                        entry.export
                    ))
                    .into());
                }
            }
            Ok(serde_json::to_string(&lock.matrix())?)
        }
        Command::Preserve {
            previous,
            ..
        } => {
            let old: CatalogLock = serde_json::from_slice(&fs::read(previous)?)?;
            lock.preserves(&old)?;
            Ok("all previous version identities remain pinned".to_owned())
        }
    }
}

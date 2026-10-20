//! Query, admission and maintenance of the release inventory.
use std::fs;
use std::io::Write as _;

use syrox_engine::{
    catalog::{Catalog, CatalogError, CatalogLock, LOCK_FILE},
    project::{
        CheckConfiguration, check_path_with, check_project_lock_with, lock_project_with,
        plan_project_package_with,
    },
};

use super::catalog::Command;

pub(super) fn execute(
    command: Command,
    checks: &CheckConfiguration,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Command::New(arguments) = command {
        return super::catalog_authoring::generate(&arguments, checks);
    }
    if let Command::AuthorizeArtifacts {
        path,
        release,
        evidence,
        output,
    } = command
    {
        let output = std::path::absolute(output)?;
        if output
            .parent()
            .ok_or("descriptor requires a parent directory")?
            .canonicalize()?
            != evidence.canonicalize()?
        {
            return Err("write the descriptor beside its bundles in --evidence".into());
        }
        let descriptor = syrox_engine::catalog::artifacts::authorize_artifacts(
            &path,
            &release,
            &evidence,
            checks,
            &syrox_engine::cancellation::Cancellation::default(),
        )?;
        let bytes = descriptor.encode()?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        return Ok(format!(
            "authorized local artifact descriptor {}\nsha256 {}\nReview and pin this descriptor in [artifacts] before use.",
            output.display(),
            syrox_engine::store::ContentDigest::sha256(&bytes)
        ));
    }
    if let Command::Generate {
        path,
        check,
    } = command
    {
        Catalog::load(&path)?.generate_releases(&path, check)?;
        return Ok(if check {
            "release data matches"
        } else {
            "generated release data"
        }
        .into());
    }
    if let Command::ReleaseManifest {
        path,
        evidence,
        output,
    } = command
    {
        return super::catalog_publication::release_manifest(&path, &evidence, &output, checks);
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
        Command::New(..)
        | Command::AuthorizeArtifacts {
            ..
        }
        | Command::Qualify {
            ..
        }
        | Command::Generate {
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
    if catalog.schema == 2 {
        syrox_engine::project::check_catalog_with(path, &catalog, checks)?;
    }
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
        Command::Generate {
            ..
        } => unreachable!("handled before admission"),
        Command::New(..)
        | Command::AuthorizeArtifacts {
            ..
        }
        | Command::Qualify {
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
            for entry in catalog
                .packages
                .iter()
                .filter(|_| catalog.schema == 1)
            {
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

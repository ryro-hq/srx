use super::*;
use crate::{
    catalog::{Catalog, CatalogLock},
    project::{CheckConfiguration, open_locked_project_with},
    store::{RootName, Store},
};

/// Authorize existing, qualified local bundles against an exact catalog checkout.
/// This performs no acquisition or execution. The resulting descriptor must be
/// reviewed and pinned separately by the consumer's configuration.
pub fn authorize_artifacts(
    catalog_path: &Path,
    release_path: &Path,
    evidence: &Path,
    checks: &CheckConfiguration,
    cancellation: &Cancellation,
) -> Result<ArtifactDescriptor, ArtifactError> {
    check(cancellation)?;
    let catalog = Catalog::load(catalog_path)?;
    let lock_bytes = read_file(
        &catalog_path.join(super::super::LOCK_FILE),
        super::super::model::MAX_BYTES,
    )?;
    let lock: CatalogLock =
        serde_json::from_slice(&lock_bytes).map_err(|e| invalid(e.to_string()))?;
    let release_bytes = read_file(release_path, MAX_DESCRIPTOR)?;
    let release: serde_json::Value =
        serde_json::from_slice(&release_bytes).map_err(|e| invalid(e.to_string()))?;
    let project_bytes = read_file(&catalog_path.join("Syrox.lock"), MAX_DESCRIPTOR)?;
    let project_pin = ContentDigest::sha256(&project_bytes).to_string();
    let catalog_pin = ContentDigest::sha256(&lock_bytes).to_string();
    if release["schema"] != 1
        || release["catalog_lock_sha256"] != catalog_pin
        || release["project_lock_sha256"] != project_pin
    {
        return Err(invalid(
            "release does not authorize these exact catalog and project locks",
        ));
    }
    let reports = release["packages"]
        .as_array()
        .ok_or_else(|| invalid("release packages are absent"))?;
    if lock.schema != 1
        || lock.versions.len() != catalog.packages.len()
        || reports.len() != lock.versions.len()
        || lock.index_sha256
            != ContentDigest::sha256(&super::super::files::bounded_file(
                catalog_path,
                super::super::INDEX_FILE,
            )?)
            .to_string()
    {
        return Err(invalid(
            "release inventory differs from the catalog",
        ));
    }
    let standard = checks
        .standard_library
        .as_ref()
        .ok_or_else(|| invalid("catalog authorization requires authenticated std"))?;
    let expected = catalog.lock_with_standard(catalog_path, standard)?;
    if expected.versions != lock.versions || expected.index_sha256 != lock.index_sha256 {
        return Err(invalid(
            "catalog lock no longer matches its recipe, std, contract or toolchain inputs",
        ));
    }
    let locked_project = open_locked_project_with(catalog_path, checks)?;
    let temporary = tempfile::tempdir()?;
    let snapshot = temporary.path().join("pkgs");
    copy_catalog(locked_project.loaded(), &snapshot, checks)?;
    let consumer = temporary.path().join("consumer");
    std::fs::create_dir(&consumer)?;
    let receiver = Store::initialize(&temporary.path().join("store"))?;
    let mut entries = Vec::new();
    for locked in lock.versions {
        check(cancellation)?;
        if !catalog.packages.contains(&locked.package) {
            return Err(invalid("locked package is not registered"));
        }
        let matches = reports
            .iter()
            .filter(|report| report["identity"] == locked.identity)
            .collect::<Vec<_>>();
        let [report] = matches.as_slice() else {
            return Err(invalid(
                "release identity must appear exactly once",
            ));
        };
        if report["schema"] != 1
            || report["name"] != locked.package.name
            || report["version"] != locked.package.version
            || report["variant"] != locked.package.variant
            || report["system"] != locked.package.system
            || report["native_execution"] != true
            || report["offline_import_and_execution"] != true
            || (locked.package.name == "nginx" && report["service_preparation"] != true)
        {
            return Err(invalid(
                "package lacks successful qualification for this exact target",
            ));
        }
        let text = |key: &str| {
            report[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid(format!("qualification lacks {key}")))
        };
        let bundle_sha256 = text("bundle_sha256")?;
        let manifest_sha256 = text("manifest")?;
        let toolchain = text("toolchain")?;
        pin(&toolchain)?;
        let bundle = format!("{}.bundle", locked.identity);
        let mut file = verify_bundle(
            &evidence.join(&bundle),
            pin(&bundle_sha256)?,
            cancellation,
        )?;
        let root = RootName::new(format!("authorize_{}", locked.identity))
            .map_err(|e| invalid(e.to_string()))?;
        let admitted = crate::bundle::import_bundle(
            &receiver,
            &root,
            pin(&manifest_sha256)?,
            &mut file,
            cancellation,
        )?;
        let manifest = admitted.manifest().clone();
        // Inventory exports include historical aliases. Qualification selects
        // the exact factory arguments; reproduce that selection, not an alias.
        let package = &locked.package;
        std::fs::write(
            consumer.join("main.srx"),
            format!(
                "inputs {{ pkgs = \"path:../pkgs\"; }}\npub let selected = package_recipe(pkgs.{}({{ version = {:?}; variant = {:?}; system = {:?}; }}));\n",
                package.factory, package.version, package.variant, package.system
            ),
        )?;
        crate::project::lock_project_with(&consumer, checks)?;
        let selected_project = open_locked_project_with(&consumer, checks)?;
        let mut evaluation = selected_project.evaluation()?;
        if !evaluation.select_package("selected")? {
            return Err(invalid(
                "catalog factory is not a lazy package reference",
            ));
        }
        let prepared = evaluation.into_selected_prepared_plan()?;
        let package = prepared
            .plan()
            .packages()
            .find(|package| package.has_export("selected"))
            .ok_or_else(|| invalid("catalog selection has no recipe"))?;
        if prepared
            .recipe_source_pin(package)
            .map(|pin| pin.to_string())
            .as_deref()
            != Some(project_pin.as_str())
        {
            return Err(invalid(
                "catalog recipe is not owned by the authorized source snapshot",
            ));
        }
        let fingerprints = fingerprints(&prepared)?;
        let recipe_sha256 = fingerprints[package.id()].clone();
        let command = prepared
            .plan()
            .commands()
            .find(|command| {
                command.package() == package.id() && command.name() == locked.package.name
            })
            .ok_or_else(|| invalid("qualified command is absent in recipe"))?;
        let result = manifest
            .commands()
            .get(&locked.package.name)
            .ok_or_else(|| invalid("qualified command is absent in bundle"))?;
        if manifest.commands().len() != 1
            || result.application_path != command.path()
            || result.loader_path.as_deref() != command.loader().map(|file| file.path.as_str())
            || result.libraries.len() != command.libraries().len()
        {
            return Err(invalid(format!(
                "bundle command differs from recipe {}: application {:?}/{:?}, loader {:?}/{:?}, libraries {}/{}",
                locked.package.export,
                result.application_path,
                command.path(),
                result.loader_path,
                command.loader().map(|file| &file.path),
                result.libraries.len(),
                command.libraries().len()
            )));
        }
        let mut outputs = Vec::new();
        let mut add = |reference: &PlanOutputRef, key: &str| -> Result<(), ArtifactError> {
            let value = manifest
                .outputs()
                .get(key)
                .ok_or_else(|| invalid("missing closure output"))?;
            if value.output != reference.output {
                return Err(invalid("closure output name changed"));
            }
            outputs.push(ArtifactOutput {
                recipe_sha256: fingerprints[&reference.package].clone(),
                output: reference.output.clone(),
                key: key.into(),
            });
            Ok(())
        };
        add(
            &PlanOutputRef {
                package: package.id().clone(),
                output: command.output().to_owned(),
            },
            &result.application,
        )?;
        match (command.loader(), &result.loader) {
            (Some(file), Some(key)) => add(&file.output, key)?,
            (None, None) => {}
            _ => return Err(invalid("bundle loader differs from recipe")),
        }
        for (reference, key) in command.libraries().zip(&result.libraries) {
            add(reference, key)?;
        }
        let application = &manifest.outputs()[&result.application];
        if text("action")? != application.action.to_string()
            || text("artifact")? != application.artifact.to_string()
        {
            return Err(invalid("qualification output changed"));
        }
        entries.push(ArtifactEntry {
            locked,
            recipe_sha256,
            bundle,
            bundle_sha256,
            manifest_sha256,
            manifest,
            toolchain,
            outputs,
        });
    }
    let descriptor = ArtifactDescriptor {
        schema: 1,
        catalog_lock_sha256: catalog_pin,
        project_lock_sha256: project_pin,
        release_sha256: ContentDigest::sha256(&release_bytes).to_string(),
        entries,
    };
    descriptor.validate()?;
    Ok(descriptor)
}

fn copy_catalog(
    loaded: &crate::project::LoadedProject,
    destination: &Path,
    checks: &CheckConfiguration,
) -> Result<(), ArtifactError> {
    std::fs::create_dir(destination)?;
    std::fs::write(
        destination.join("main.srx"),
        loaded.main_source().text(),
    )?;
    for input in loaded.inputs() {
        let directory = input
            .locator()
            .strip_prefix("modules:")
            .ok_or_else(|| {
                invalid("local artifact authorization requires a catalog with local module inputs")
            })?;
        for source in input.files() {
            let path = destination
                .join(directory)
                .join(source.relative_path());
            std::fs::create_dir_all(
                path.parent()
                    .ok_or_else(|| invalid("module source has no directory"))?,
            )?;
            let text = loaded
                .sources()
                .get(source.source_id())
                .ok_or_else(|| invalid("missing authenticated source"))?
                .text();
            std::fs::write(path, text)?;
        }
    }
    for asset in loaded.assets() {
        let bytes = read_file(
            &loaded.path().join(asset.relative_path()),
            asset.size(),
        )?;
        if bytes.len() as u64 != asset.size()
            || ContentDigest::sha256(&bytes).as_bytes() != asset.digest()
        {
            return Err(invalid(
                "catalog asset changed during authorization",
            ));
        }
        let path = destination.join(asset.relative_path());
        std::fs::create_dir_all(
            path.parent()
                .ok_or_else(|| invalid("asset has no directory"))?,
        )?;
        std::fs::write(path, bytes)?;
    }
    crate::project::lock_project_with(destination, checks)?;
    Ok(())
}

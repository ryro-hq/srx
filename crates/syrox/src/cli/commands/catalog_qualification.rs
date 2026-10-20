//! Build, execute and transport one pinned catalog combination.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use syrox_engine::{
    bundle::{export_bundle, import_bundle},
    cancellation::Cancellation,
    catalog::{
        Catalog, CatalogLock, HttpQualification, LOCK_FILE, LockedVersion, Qualification,
        ServiceQualification,
    },
    config::UserConfiguration,
    project::{CheckConfiguration, check_project_lock_with},
    realize::{RealizeOptions, realize_build, realize_command, resolve_build, resolve_command},
    result::{ResultCommand, ResultManifest, admit_result},
    runtime::{
        RuntimeClosure, RuntimeConfiguration, RuntimeError,
        run_runtime_configured_with_cancellation,
    },
    store::{RootName, Store},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(super) fn qualify(
    path: &Path,
    identity: &str,
    config: &Path,
    store_path: &Path,
    output: &Path,
    checks: &CheckConfiguration,
) -> Result<()> {
    let catalog = Catalog::load(path)?;
    let old: CatalogLock = serde_json::from_slice(&fs::read(path.join(LOCK_FILE))?)?;
    let mut lock = catalog.lock(path)?;
    lock.retain_previous(&old, false)?;
    if lock != old {
        return Err("catalog lock is stale".into());
    }
    check_project_lock_with(path, checks)?;
    if catalog.schema == 2 {
        syrox_engine::project::check_catalog_with(path, &catalog, checks)?;
    }
    let entry = lock
        .versions
        .iter()
        .find(|entry| entry.identity == identity)
        .ok_or("unknown required combination")?;
    let qualification = Qualification::load(path, &entry.package)?;
    let source_catalog = Catalog {
        schema: 1,
        defaults: BTreeMap::from([(
            entry.package.name.clone(),
            entry.package.version.clone(),
        )]),
        channels: catalog
            .channels
            .iter()
            .filter(|channel| channel.name == entry.package.name)
            .cloned()
            .collect(),
        packages: vec![entry.package.clone()],
    };
    let provenance = source_catalog.verify_sources(path)?;
    let signals = crate::signals::OperationSignals::install()?;
    let cancellation = &signals.cancellation;
    let user = UserConfiguration::load_with_store(Some(config), Some(store_path))?;
    let worker = crate::cli::worker_path::build_candidate()?;
    let selection = SelectedProject::new(path, entry, checks)?;
    let reference = format!("{}#selected", selection.path().display());
    let selected = resolve_build(&reference, &user, checks)?;
    let result = realize_build(
        &selected,
        RealizeOptions {
            configuration: &user,
            worker: &worker,
            offline: false,
        },
        cancellation,
        |_| {},
    )?;
    let command = resolve_command(
        &reference,
        Some(&qualification.command),
        &user,
        checks,
    )?;
    let closure = realize_command(
        &command,
        &user,
        &worker,
        false,
        cancellation,
        |_, _| {},
    )?;
    if let Some(service) = &qualification.service {
        qualify_service_configuration(
            path,
            entry,
            service,
            checks,
            &user,
            &worker,
            cancellation,
        )?;
    }
    qualify_runtime(&closure, path, &qualification, cancellation)?;
    fs::create_dir_all(output)?;
    let producer = Store::open(store_path)?;
    let manifest = manifest(&closure, &qualification.command)?;
    let digest = manifest.digest()?;
    let root = RootName::new(format!("catalog_{identity}"))?;
    admit_result(&producer, &root, &manifest, digest, cancellation)?;
    let bundle_path = output.join(format!("{identity}.bundle"));
    let mut bundle = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&bundle_path)?;
    export_bundle(
        &producer,
        &root,
        digest,
        &mut bundle,
        cancellation,
    )?;
    bundle.sync_all()?;
    let receiver_directory = tempfile::tempdir_in(output)?;
    let receiver = Store::initialize(receiver_directory.path())?;
    let imported = import_bundle(
        &receiver,
        &root,
        digest,
        &mut File::open(&bundle_path)?,
        cancellation,
    )?;
    let imported_runtime = imported
        .command(&qualification.command)
        .ok_or("import lost runtime command")?
        .open(&receiver, cancellation)?;
    drop(imported);
    qualify_runtime(
        &imported_runtime,
        path,
        &qualification,
        cancellation,
    )?;
    let evidence = serde_json::json!({
        "schema": 1, "identity": identity, "name": entry.package.name,
        "version": entry.package.version, "variant": entry.package.variant, "system": entry.package.system,
        "action": result.action.to_string(), "artifact": result.artifact.to_string(), "receipt": result.receipt.to_string(),
        "toolchain": result.toolchain.map(|pin| pin.to_string()), "manifest": digest.to_string(),
        "bundle_sha256": file_digest(&bundle_path, cancellation)?, "provenance": provenance,
        "native_execution": true, "offline_import_and_execution": true,
        "service_preparation": qualification.service.is_some(),
    });
    let mut report = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join(format!("{identity}.json")))?;
    report.write_all(serde_json::to_string_pretty(&evidence)?.as_bytes())?;
    report.sync_all()?;
    Ok(())
}

pub(super) fn file_digest(path: &Path, cancellation: &Cancellation) -> Result<String> {
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file()
        || file.metadata()?.len() > syrox_engine::bundle::MAX_BUNDLE_BYTES
    {
        return Err("qualification input exceeds its byte limit".into());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 8 * 1024];
    let mut total = 0_u64;
    loop {
        cancellation.check()?;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += u64::try_from(read)?;
        if total > syrox_engine::bundle::MAX_BUNDLE_BYTES {
            return Err("qualification input grew beyond the byte limit".into());
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn manifest(closure: &RuntimeClosure, name: &str) -> Result<ResultManifest> {
    let mut outputs = BTreeMap::from([(
        "application".to_owned(),
        &closure.application().output,
    )]);
    let loader = closure.loader().map(|file| {
        outputs.insert("loader".to_owned(), &file.output);
        "loader".to_owned()
    });
    let libraries = closure
        .libraries()
        .iter()
        .enumerate()
        .map(|(index, view)| {
            let key = format!("library_{index}");
            outputs.insert(key.clone(), view);
            key
        })
        .collect();
    Ok(ResultManifest::from_views(
        outputs,
        BTreeMap::from([(
            name.to_owned(),
            ResultCommand {
                application: "application".to_owned(),
                application_path: closure.application().path.clone(),
                loader,
                loader_path: closure.loader().map(|file| file.path.clone()),
                libraries,
            },
        )]),
    )?)
}

fn qualify_runtime(
    closure: &RuntimeClosure,
    path: &Path,
    qualification: &Qualification,
    cancellation: &Cancellation,
) -> Result<()> {
    let configuration = RuntimeConfiguration::default();
    let working_directory = tempfile::tempdir()?;
    if !run_runtime_configured_with_cancellation(
        closure,
        &qualification
            .version_arguments
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>(),
        working_directory.path(),
        &configuration,
        cancellation,
    )?
    .success()
    {
        return Err("native version command failed".into());
    }
    if let Some(http) = &qualification.http {
        qualify_http(closure, path, http, cancellation)?;
    }
    Ok(())
}

fn qualify_http(
    closure: &RuntimeClosure,
    path: &Path,
    http: &HttpQualification,
    cancellation: &Cancellation,
) -> Result<()> {
    let working_directory = tempfile::tempdir()?;
    let port_reservation = TcpListener::bind("127.0.0.1:0")?;
    let port = port_reservation.local_addr()?.port();
    let text =
        Qualification::text(path, &http.configuration)?.replace("@{port}", &port.to_string());
    let directory = NativeConfiguration::new(&http.filename, &text, &http.response)?;
    let configuration = directory.configuration()?;
    let config_argument = format!("/syrox/config/qualification/{}", http.filename);
    let arguments = |values: &[String]| {
        values
            .iter()
            .map(|value| OsString::from(value.replace("@{config}", &config_argument)))
            .collect::<Vec<_>>()
    };
    let valid = run_runtime_configured_with_cancellation(
        closure,
        &arguments(&http.validate_arguments),
        working_directory.path(),
        &configuration,
        cancellation,
    )?;
    if !valid.success() {
        return Err("native HTTP service validator rejected valid configuration".into());
    }
    let invalid_directory = NativeConfiguration::new(
        &http.filename,
        &Qualification::text(path, &http.invalid_configuration)?,
        &http.response,
    )?;
    let invalid_configuration = invalid_directory.configuration()?;
    let invalid = run_runtime_configured_with_cancellation(
        closure,
        &arguments(&http.validate_arguments),
        working_directory.path(),
        &invalid_configuration,
        cancellation,
    )?;
    if invalid.success() {
        return Err("native HTTP service validator accepted invalid extraConfig".into());
    }
    drop(port_reservation);
    let stop = Cancellation::default();
    let deadline = Instant::now() + Duration::from_secs(20);
    std::thread::scope(|scope| -> Result<()> {
        let server = scope.spawn(|| {
            run_runtime_configured_with_cancellation(
                closure,
                &arguments(&http.run_arguments),
                working_directory.path(),
                &configuration,
                &stop,
            )
        });
        let response = (|| -> Result<()> {
            loop {
                cancellation.check()?;
                if Instant::now() >= deadline {
                    return Err("HTTP service HTTP qualification deadline elapsed".into());
                }
                if let Ok(mut stream) = TcpStream::connect_timeout(
                    &format!("127.0.0.1:{port}").parse()?,
                    Duration::from_millis(100),
                ) {
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
                    let mut bytes = Vec::new();
                    stream.take(4096).read_to_end(&mut bytes)?;
                    if !bytes
                        .windows(http.response.len())
                        .any(|window| window == http.response.as_bytes())
                    {
                        return Err("HTTP service HTTP response differs".into());
                    }
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        })();
        stop.cancel();
        match server
            .join()
            .map_err(|_| "HTTP service runtime thread failed")?
        {
            Ok(_) | Err(RuntimeError::Cancelled) => {}
            Err(error) => return Err(error.into()),
        }
        response?;
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse()?,
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return Err("HTTP service listener survived runtime settlement".into());
        }
        Ok(())
    })
}

struct NativeConfiguration(tempfile::TempDir);

/// A locked consumer invokes the shared selector with the exact matrix request.
struct SelectedProject(tempfile::TempDir);

impl SelectedProject {
    fn path(&self) -> std::path::PathBuf {
        self.0.path().join("consumer")
    }

    fn new(path: &Path, entry: &LockedVersion, checks: &CheckConfiguration) -> Result<Self> {
        Self::with_configuration(path, entry, checks, None)
    }

    fn with_configuration(
        path: &Path,
        entry: &LockedVersion,
        checks: &CheckConfiguration,
        extra: Option<&str>,
    ) -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        let catalog = syrox_engine::project::open_locked_project_with(path, checks)?;
        let loaded = catalog.loaded();
        let catalog_path = temporary.path().join("pkgs");
        fs::create_dir(&catalog_path)?;
        fs::write(
            catalog_path.join("main.srx"),
            loaded.main_source().text(),
        )?;
        for input in loaded.inputs() {
            let directory = input
                .locator()
                .strip_prefix("modules:")
                .ok_or("catalog qualification requires local module inputs")?;
            for source in input.files() {
                let destination = catalog_path
                    .join(directory)
                    .join(source.relative_path());
                fs::create_dir_all(
                    destination
                        .parent()
                        .ok_or("module source has no directory")?,
                )?;
                fs::write(
                    destination,
                    loaded
                        .sources()
                        .get(source.source_id())
                        .ok_or("missing catalog source")?
                        .text(),
                )?;
            }
        }
        for asset in loaded.assets() {
            let mut bytes = Vec::new();
            File::open(loaded.path().join(asset.relative_path()))?
                .take(asset.size().saturating_add(1))
                .read_to_end(&mut bytes)?;
            if u64::try_from(bytes.len())? != asset.size()
                || <[u8; 32]>::from(Sha256::digest(&bytes)) != *asset.digest()
            {
                return Err("catalog asset changed while preparing the selected project".into());
            }
            let destination = catalog_path.join(asset.relative_path());
            fs::create_dir_all(
                destination
                    .parent()
                    .ok_or("catalog asset has no directory")?,
            )?;
            fs::write(destination, bytes)?;
        }
        syrox_engine::project::lock_project_with(&catalog_path, checks)?;
        let package = &entry.package;
        let project_path = temporary.path().join("consumer");
        fs::create_dir_all(project_path.join("recipes/selected"))?;
        fs::write(
            project_path.join("main.srx"),
            format!(
                r#"
            inputs {{ pkgs = "path:../pkgs"; catalog = "modules:recipes"; }}
            pub fn selected_recipe() -> std::Recipe {{
                std::recipe_value(std::package_recipe(pkgs.{} {{ version = {:?}; variant = {:?}; system = {:?}; }}))
            }}
            pub publish(catalog, recipe): std::Recipe;
        "#,
                package.factory, package.version, package.variant, package.system
            ),
        )?;
        fs::write(
            project_path.join("recipes/selected/package.srx"),
            "pub fn recipe() -> std::Recipe { project::selected_recipe() }\n",
        )?;
        if let Some(extra) = extra {
            let mut main = OpenOptions::new()
                .append(true)
                .open(project_path.join("main.srx"))?;
            writeln!(main, "{extra}")?;
        }
        syrox_engine::project::lock_project_with(&project_path, checks)?;
        Ok(Self(temporary))
    }
}

fn qualify_service_configuration(
    path: &Path,
    entry: &LockedVersion,
    service: &ServiceQualification,
    checks: &CheckConfiguration,
    user: &UserConfiguration,
    worker: &Path,
    cancellation: &Cancellation,
) -> Result<()> {
    use syrox_engine::{
        deployment::manifest::{DeploymentError, prepare_consumer},
        project::prepare_project_consumer_with,
    };
    for (settings, valid) in [
        (&service.valid_settings, true),
        (&service.invalid_settings, false),
    ] {
        let literal =
            |text: &str| -> Result<String> { Ok(serde_json::to_string(text)?.replace('$', "\\$")) };
        let project = Qualification::text(path, &service.project)?
            .replace("@{version}", &literal(&entry.package.version)?)
            .replace("@{variant}", &literal(&entry.package.variant)?)
            .replace("@{system}", &literal(&entry.package.system)?)
            .replace(
                "@{settings}",
                &Qualification::text(path, settings)?,
            );
        let selection = SelectedProject::with_configuration(path, entry, checks, Some(&project))?;
        let plan = prepare_project_consumer_with(&selection.path(), checks, "os")?;
        match prepare_consumer(
            plan,
            "os",
            user,
            worker,
            false,
            cancellation,
            |_, _| {},
        ) {
            Ok(_) if valid => {}
            Err(DeploymentError::ConfigurationValidation {
                ..
            }) if !valid => {}
            Ok(_) => {
                return Err(
                    "selected HTTP service accepted invalid extraConfig during service preparation"
                        .into(),
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

impl NativeConfiguration {
    fn new(filename: &str, text: &str, response: &str) -> Result<Self> {
        let result = Self(tempfile::tempdir()?);
        for (name, content) in [
            (filename, text),
            ("index.html", response),
        ] {
            let path = result.0.path().join(name);
            fs::write(&path, content)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
        }
        fs::set_permissions(result.0.path(), fs::Permissions::from_mode(0o500))?;
        Ok(result)
    }

    fn configuration(&self) -> Result<RuntimeConfiguration> {
        Ok(RuntimeConfiguration::new(
            "qualification",
            File::open(self.0.path())?,
            BTreeMap::new(),
        )?)
    }
}

impl Drop for NativeConfiguration {
    fn drop(&mut self) {
        let _ = fs::set_permissions(self.0.path(), fs::Permissions::from_mode(0o700));
    }
}

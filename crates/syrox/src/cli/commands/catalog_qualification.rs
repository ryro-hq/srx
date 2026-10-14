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
    catalog::{Catalog, CatalogLock, LOCK_FILE, LockedVersion},
    config::UserConfiguration,
    project::{CheckConfiguration, check_project_lock_with},
    realize::{RealizeOptions, realize_build, realize_command, resolve_build, resolve_command},
    result::{ResultCommand, ResultManifest, admit_result},
    runtime::{
        RuntimeClosure, RuntimeConfiguration, RuntimeError,
        run_runtime_configured_with_cancellation,
    },
    store::{ContentDigest, RootName, Store},
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
    let entry = lock
        .versions
        .iter()
        .find(|entry| entry.identity == identity)
        .ok_or("unknown required combination")?;
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
    let reference = format!("{}#{}", path.display(), entry.package.export);
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
        Some(&entry.package.name),
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
    qualify_runtime(&closure, entry, cancellation)?;
    fs::create_dir_all(output)?;
    let producer = Store::open(store_path)?;
    let manifest = manifest(&closure, &entry.package.name)?;
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
        .command(&entry.package.name)
        .ok_or("import lost runtime command")?
        .open(&receiver, cancellation)?;
    drop(imported);
    qualify_runtime(&imported_runtime, entry, cancellation)?;
    let evidence = serde_json::json!({
        "schema": 1, "identity": identity, "name": entry.package.name,
        "version": entry.package.version, "variant": entry.package.variant, "system": entry.package.system,
        "action": result.action.to_string(), "artifact": result.artifact.to_string(), "receipt": result.receipt.to_string(),
        "toolchain": result.toolchain.map(|pin| pin.to_string()), "manifest": digest.to_string(),
        "bundle_sha256": file_digest(&bundle_path, cancellation)?, "provenance": provenance,
        "native_execution": true, "offline_import_and_execution": true,
    });
    let mut report = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join(format!("{identity}.json")))?;
    report.write_all(serde_json::to_string_pretty(&evidence)?.as_bytes())?;
    report.sync_all()?;
    Ok(())
}

pub(super) fn release_manifest(
    path: &Path,
    evidence: &Path,
    output: &Path,
    checks: &CheckConfiguration,
) -> Result<String> {
    let catalog = Catalog::load(path)?;
    check_project_lock_with(path, checks)?;
    let previous: CatalogLock = serde_json::from_slice(&fs::read(path.join(LOCK_FILE))?)?;
    let mut lock = catalog.lock(path)?;
    lock.retain_previous(&previous, false)?;
    if lock != previous {
        return Err("catalog lock is stale".into());
    }
    let cancellation = Cancellation::default();
    let mut reports = Vec::new();
    let temporary = tempfile::tempdir()?;
    let receiver = Store::initialize(temporary.path())?;
    for entry in &lock.versions {
        let report: serde_json::Value = serde_json::from_slice(&fs::read(
            evidence.join(format!("{}.json", entry.identity)),
        )?)?;
        if report["schema"] != 1
            || report["identity"] != entry.identity
            || report["system"] != entry.package.system
            || report["version"] != entry.package.version
            || report["native_execution"] != true
            || report["offline_import_and_execution"] != true
        {
            return Err("required combination lacks successful native qualification".into());
        }
        let bundle = evidence.join(format!("{}.bundle", entry.identity));
        if report["bundle_sha256"].as_str() != Some(file_digest(&bundle, &cancellation)?.as_str()) {
            return Err("qualification bundle changed content".into());
        }
        let pin = report["manifest"]
            .as_str()
            .ok_or("qualification has no manifest pin")?
            .parse::<ContentDigest>()?;
        let root = RootName::new(format!("qualification_{}", entry.identity))?;
        let admitted = import_bundle(
            &receiver,
            &root,
            pin,
            &mut File::open(bundle)?,
            &cancellation,
        )?;
        let app = admitted
            .manifest()
            .outputs()
            .get("application")
            .ok_or("qualification lacks application artifact")?;
        if report["action"].as_str() != Some(app.action.to_string().as_str())
            || report["artifact"].as_str() != Some(app.artifact.to_string().as_str())
        {
            return Err("qualification receipt differs from the distributed artifact".into());
        }
        if report["toolchain"]
            .as_str()
            .and_then(|pin| pin.parse::<ContentDigest>().ok())
            .is_none()
        {
            return Err("qualification lacks a verified toolchain identity".into());
        }
        reports.push(report);
    }
    let manifest = serde_json::json!({"schema":1,"catalog_lock_sha256":file_digest(&path.join(LOCK_FILE), &cancellation)?,"project_lock_sha256":file_digest(&path.join("Syrox.lock"), &cancellation)?,"packages":reports});
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())?;
    file.sync_all()?;
    Ok(format!(
        "verified all {} required combinations",
        lock.versions.len()
    ))
}

fn file_digest(path: &Path, cancellation: &Cancellation) -> Result<String> {
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
    entry: &LockedVersion,
    cancellation: &Cancellation,
) -> Result<()> {
    let configuration = RuntimeConfiguration::default();
    let working_directory = tempfile::tempdir()?;
    let argument = if entry.package.name == "hello" {
        "--version"
    } else {
        "-v"
    };
    if !run_runtime_configured_with_cancellation(
        closure,
        &[OsString::from(argument)],
        working_directory.path(),
        &configuration,
        cancellation,
    )?
    .success()
    {
        return Err("native version command failed".into());
    }
    if entry.package.name == "nginx" {
        nginx_http(closure, cancellation)?;
    }
    Ok(())
}

fn nginx_http(closure: &RuntimeClosure, cancellation: &Cancellation) -> Result<()> {
    let working_directory = tempfile::tempdir()?;
    let port_reservation = TcpListener::bind("127.0.0.1:0")?;
    let port = port_reservation.local_addr()?.port();
    let directory = NativeConfiguration::new(&format!(
        "daemon off; error_log stderr; pid /tmp/nginx.pid; events {{}} http {{ access_log off; server {{ listen 127.0.0.1:{port}; location / {{ root /syrox/config/qualification; }} }} }}"
    ))?;
    let configuration = directory.configuration()?;
    let config_argument = OsString::from("/syrox/config/qualification/nginx.conf");
    let valid = run_runtime_configured_with_cancellation(
        closure,
        &[
            "-t".into(),
            "-c".into(),
            config_argument.clone(),
        ],
        working_directory.path(),
        &configuration,
        cancellation,
    )?;
    if !valid.success() {
        return Err("native nginx validator rejected valid configuration".into());
    }
    let invalid_directory = NativeConfiguration::new("invalid_syrox_directive;")?;
    let invalid_configuration = invalid_directory.configuration()?;
    let invalid = run_runtime_configured_with_cancellation(
        closure,
        &[
            "-t".into(),
            "-c".into(),
            config_argument.clone(),
        ],
        working_directory.path(),
        &invalid_configuration,
        cancellation,
    )?;
    if invalid.success() {
        return Err("native nginx validator accepted invalid extraConfig".into());
    }
    drop(port_reservation);
    let stop = Cancellation::default();
    let deadline = Instant::now() + Duration::from_secs(20);
    std::thread::scope(|scope| -> Result<()> {
        let server = scope.spawn(|| {
            run_runtime_configured_with_cancellation(
                closure,
                &["-c".into(), config_argument],
                working_directory.path(),
                &configuration,
                &stop,
            )
        });
        let response = (|| -> Result<()> {
            loop {
                cancellation.check()?;
                if Instant::now() >= deadline {
                    return Err("nginx HTTP qualification deadline elapsed".into());
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
                        .windows(b"syrox-qualified".len())
                        .any(|window| window == b"syrox-qualified")
                    {
                        return Err("nginx HTTP response differs".into());
                    }
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        })();
        stop.cancel();
        match server
            .join()
            .map_err(|_| "nginx runtime thread failed")?
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
            return Err("nginx listener survived runtime settlement".into());
        }
        Ok(())
    })
}

struct NativeConfiguration(tempfile::TempDir);

impl NativeConfiguration {
    fn new(text: &str) -> Result<Self> {
        let result = Self(tempfile::tempdir()?);
        for (name, content) in [
            ("nginx.conf", text),
            ("index.html", "syrox-qualified"),
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

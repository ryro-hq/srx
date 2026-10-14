use super::config::{Config, doctor, read_config, root};
use super::{
    Result,
    common::{self},
    process::Control,
};
use microsandbox::{ExecEvent, LocalBackend, Sandbox};
use serde_json::{Value, json};
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn run_id() -> Result<String> {
    Ok(format!(
        "{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos(),
        std::process::id()
    ))
}

pub(super) fn lock(path: &Path, control: &Control) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(fs::TryLockError::WouldBlock) => {
                control.check()?;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub fn main(args: &[String]) -> Result<()> {
    if args
        .first()
        .is_some_and(|value| value == "--qualify-catalog")
    {
        return super::catalog_qualification::main(&args[1..]);
    }
    if args
        .first()
        .is_some_and(|value| value == "--prepare")
    {
        return super::prepare::main(&args[1..]);
    }
    main_with_ecosystem(args, false)
}

pub fn main_with_ecosystem(args: &[String], ecosystem: bool) -> Result<()> {
    let selection = common::Selection::parse(args)?;
    let selected = if ecosystem || (selection.suite == common::Suite::Native) {
        Vec::new()
    } else {
        selection.selected()
    };
    if selection.list {
        if ecosystem {
            println!("ecosystem::local_catalogue_and_editors: test");
            return Ok(());
        }
        if selection.suite == common::Suite::Native {
            println!("native::workspace: test");
            return Ok(());
        }
        for gate in &selected {
            println!("{}: test", gate.label());
        }
        println!("\n{} tests, 0 benchmarks", selected.len());
        return Ok(());
    }
    if selected.is_empty() && !ecosystem && !(selection.suite == common::Suite::Native) {
        return Err("VM filter selected no registered gates".into());
    }
    if ecosystem
        && selection
            .filters
            .iter()
            .any(|filter| !"ecosystem::local_catalogue_and_editors".contains(filter))
    {
        return Err("ecosystem filter selected no registered test".into());
    }
    let control = Control::new(std::env::var_os("SYROX_VM_CANCEL_FILE").map(PathBuf::from))?;
    let fault: Option<common::Fault> = std::env::var("SYROX_VM_FAULT")
        .ok()
        .map(|value| serde_json::from_value(json!(value)))
        .transpose()?;
    let evidence = std::env::var_os("SYROX_VM_EVIDENCE").map_or_else(
        || {
            Ok(root()
                .join("target/test-evidence")
                .join(run_id()?))
        },
        |value| Ok::<_, Box<dyn std::error::Error + Send + Sync>>(PathBuf::from(value)),
    )?;
    // An explicit evidence parent may already exist; report.json is never overwritten.
    common::private(&evidence)?;
    if evidence.join("report.json").exists() {
        return Err("evidence run already exists".into());
    }
    let profile = if selection.suite == common::Suite::Native {
        super::config::Profile::Native
    } else {
        super::config::Profile::Acceptance
    };
    common::save(
        &evidence.join("profile.json"),
        &serde_json::to_value(profile)?,
    )?;
    let mut report = json!({"schema":1,"status":"preparing","profile":profile,"sdk":common::SDK_VERSION,
        "cpus":super::resources::CPUS,"max_cpus":super::resources::CPUS,"memory_mib":profile.memory_mib(),"max_memory_mib":profile.memory_mib(),"cache_quota_mib":32768,"workspace_filesystem":"guest tmpfs","workspace_limit_mib":profile.workspace_mib(),"selected":selected,"vm_cleanup":"not-started",
        "harness_sha256":super::snapshot::digest(&std::env::current_exe()?)?,
        "fault":fault,
        "coverage":if profile == super::config::Profile::Native {"complete nonignored workspace libtests in qualified kernel"} else {"selected VM gates only"},
        "pending":common::gates().into_iter().filter(|gate|gate.category != common::Category::Gate).collect::<Vec<_>>()});
    super::evidence::save(&evidence.join("report.json"), &report)?;
    eprintln!("VM evidence: {}", evidence.display());
    let outcome = (|| {
        report["resource_admission"] = super::resources::host()?;
        common::private(&root().join("target/vm-cache"))?;
        let _lock = lock(
            &root().join("target/vm-cache/execution.lock"),
            &control,
        )?;
        control.check()?;
        report["resource_admission"] = super::resources::host()?;
        report["sources"] = super::snapshot::snapshot(&root(), &evidence.join("sources"))?;
        common::private(&evidence.join("ecosystem"))?;
        if ecosystem {
            super::ecosystem::capture(&root(), &evidence)?;
        }
        report["host"] = doctor();
        common::save(
            &evidence.join("source-manifest.json"),
            &report["sources"],
        )?;
        common::save(&evidence.join("selected.json"), &selected)?;
        common::save(&evidence.join("fault.json"), &fault)?;
        super::evidence::save(&evidence.join("report.json"), &report)?;
        if report["host"]["ready"] != true {
            return Err("VM host preflight failed; inspect report.json".into());
        }
        let config = read_config()?;
        if profile != config.profile || ((selection.suite == common::Suite::Native) && ecosystem) {
            return Err("suite and configured VM profile differ".into());
        }
        report["environment"] = serde_json::to_value(&config)?;
        let vendor = prepare_vendor(&evidence, &control)?;
        report["vendor"] = json!(vendor);
        super::evidence::save(&evidence.join("report.json"), &report)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        runtime.block_on(run_vm(&config, &evidence, &control, &mut report))?;
        let files: BTreeMap<String, String> =
            serde_json::from_value(report["sources"]["files"].clone())?;
        super::snapshot::verify_files(&evidence.join("sources"), &files)?;
        config.validate()?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })();
    report["status"] = json!(if outcome.is_ok() {
        "passed"
    } else if control.check().is_err() {
        "cancelled"
    } else {
        "failed"
    });
    if let Err(error) = &outcome {
        report["error"] = json!(error.to_string());
    }
    if let Ok(text) = super::process::read_log(&evidence.join("capabilities-early.log"))
        && let Some(probe) = text
            .lines()
            .find_map(|line| serde_json::from_str::<Value>(line).ok())
    {
        report["capabilities_early"] = probe;
    }
    super::evidence::save(&evidence.join("report.json"), &report)?;
    outcome
}

fn prepare_vendor(evidence: &Path, control: &Control) -> Result<PathBuf> {
    let lock_pin = super::snapshot::digest(&evidence.join("sources/Cargo.lock"))?;
    let vendor = root()
        .join("target/vm-cache/vendor")
        .join(&lock_pin);
    if !vendor.join(".syrox-ready").is_file() {
        super::process::command(
            std::process::Command::new(env!("CARGO"))
                .args(["fetch", "--locked"])
                .current_dir(evidence.join("sources")),
            &evidence.join("dependencies.log"),
            Duration::from_mins(10),
            control,
        )?;
        super::process::command(
            std::process::Command::new(env!("CARGO"))
                .args(["vendor", "--locked", "--offline"])
                .arg(&vendor)
                .current_dir(evidence.join("sources")),
            &evidence.join("vendor.log"),
            Duration::from_mins(5),
            control,
        )?;
        fs::write(vendor.join(".syrox-ready"), lock_pin)?;
    }
    Ok(vendor)
}

async fn run_vm(
    config: &Config,
    evidence: &Path,
    control: &Control,
    report: &mut Value,
) -> Result<()> {
    microsandbox::config::set_sdk_msb_path(&config.runtime);
    microsandbox::set_libkrunfw_path(&config.firmware);
    let cache = root().join("target/vm-cache");
    common::private(&cache.join("guest"))?;
    let environment_key = format!(
        "{:x}",
        sha2::Sha256::digest(serde_json::to_vec(&json!({
            "schema":5, "sdk":config.sdk, "preparation_image":config.preparation_image.as_deref().unwrap_or(&config.image),
            "lock":super::snapshot::digest(&evidence.join("sources/Cargo.lock"))?,
            "target":"x86_64-unknown-linux-gnu", "rustflags":"-C target-feature=+crt-static",
            "incremental":false, "debug_info":false,
            "candidate_profile":"release", "fixture_profile":"test", "policy":"single-producer-host-inherited-v2"
        }))?)
    );
    let cache_key = format!(
        "{:x}",
        sha2::Sha256::digest(serde_json::to_vec(&json!({
            "schema":3, "build_jobs":super::resources::build_jobs()?, "compilation":environment_key, "environment":config, "release_bundle":config.candidate_bundle.as_ref().map(|directory| super::snapshot::digest(&directory.join("manifest.json"))).transpose()?, "sources":report["sources"]["sha256"], "selected":report["selected"]
        }))?)
    );
    fs::write(evidence.join("cache-key"), &cache_key)?;
    fs::write(evidence.join("compilation-key"), &environment_key)?;
    report["cache_key"] = json!(cache_key);
    report["compilation_key"] = json!(environment_key);
    let compilation_root = cache.join("guest/target");
    let compilation = super::cache::acquire(&compilation_root, &environment_key, control)?;
    report["compilation_directory"] = json!(compilation.directory);
    report["compilation_cache_before"] = super::cache::prune(
        &compilation_root,
        super::cache::COMPILATION_LIMIT,
        control,
    )?;
    // Unix socket limits apply independently of source/evidence paths. Keep
    // runtime state short while image layers and compilation stay cached.
    let vendor = PathBuf::from(
        report["vendor"]
            .as_str()
            .ok_or("vendored dependencies required")?,
    );
    report["preparation"] = super::candidates::prepare(
        config,
        evidence,
        &vendor,
        &compilation.directory,
        control,
    )?;
    report["resource_admission_before_vm"] =
        super::resources::host_for(config.profile.host_margin())?;
    super::resources::require_host_for(config.profile.host_margin())?;
    super::evidence::save(&evidence.join("report.json"), report)?;
    let runtime_directory = tempfile::Builder::new()
        .prefix("srx-vm-")
        .tempdir_in("/tmp")?;
    let runtime_home = runtime_directory.path().to_path_buf();
    report["vm_runtime_home"] = json!(runtime_home);
    let backend: Arc<dyn microsandbox::Backend> = Arc::new(
        control
            .bounded(
                "backend preparation",
                Duration::from_mins(2),
                LocalBackend::builder()
                    .home(&runtime_home)
                    .cache_dir(cache.join("microsandbox/cache"))
                    .logs_dir(evidence.join("runtime-logs"))
                    .config_path(cache.join("sdk-config.json"))
                    .build(),
            )
            .await?,
    );
    // Check the paths actually resolved by the SDK, after managed policy too.
    let local = backend
        .as_local()
        .ok_or("local VM backend required")?;
    if let Some(archive) = &config.image_archive {
        let images = control
            .bounded(
                "image preparation",
                Duration::from_mins(5),
                microsandbox::Image::load_local(local, archive, vec![config.image.clone()]),
            )
            .await?;
        let expected = config
            .image
            .rsplit_once('@')
            .ok_or("image digest")?
            .1;
        if !images.iter().any(|image| {
            image.reference() == config.image && image.manifest_digest() == Some(expected)
        }) {
            return Err("imported guest image has a different manifest digest".into());
        }
    }
    if local
        .config()
        .resolve_msb_path()?
        .canonicalize()?
        != config.runtime.canonicalize()?
        || local
            .config()
            .resolve_libkrunfw_path()?
            .canonicalize()?
            != config.firmware.canonicalize()?
    {
        return Err("SDK did not resolve the pinned runtime pair".into());
    }
    let name = format!("srx-{}", run_id()?);
    let vendor = PathBuf::from(
        report["vendor"]
            .as_str()
            .ok_or("vendored dependencies required")?,
    );
    report["vm_name"] = json!(name);
    report["vm_cleanup"] = json!("pending");
    super::evidence::save(&evidence.join("report.json"), report)?;
    compilation.mark_active()?;
    let _preserved_runtime_home = runtime_directory.keep();
    let outcome = Box::pin(microsandbox::with_backend(backend, async {
        let created = control
            .bounded(
                "VM creation",
                Duration::from_mins(3),
                Sandbox::builder(&name)
                    .image(config.image.clone())
                    .init("/usr/lib/systemd/systemd")
                    .cpus(super::resources::CPUS)
                    .max_cpus(super::resources::CPUS)
                    .memory(config.profile.memory_mib())
                    .max_memory(config.profile.memory_mib())
                    .volume("/sources", |volume| {
                        volume.bind(evidence.join("sources")).readonly()
                    })
                    .volume("/evidence", |volume| {
                        volume
                            .bind(evidence)
                            .owner(1000, 1000)
                            .quota(8192)
                    })
                    .volume("/ecosystem-sources", |volume| {
                        volume.bind(evidence.join("ecosystem")).readonly()
                    })
                    .volume("/cache", |volume| {
                        volume
                            .bind(cache.join("guest"))
                            .owner(1000, 1000)
                            .quota(32768)
                    })
                    .volume("/vendor", |volume| {
                        volume.bind(&vendor).owner(1000, 1000).readonly()
                    })
                    .create(),
            )
            .await;
        let sandbox = match created {
            Ok(sandbox) => sandbox,
            Err(failure) => {
                // The SDK owns cancellation of in-progress creation. Check the
                // unique name as well so partial startup cannot report success.
                let cleanup_control = Control::uncancelled();
                let found = cleanup_control
                    .bounded(
                        "partial VM lookup",
                        Duration::from_secs(30),
                        async {
                            match Sandbox::get(&name).await {
                                Ok(handle) => Ok(Some(handle)),
                                Err(microsandbox::MicrosandboxError::SandboxNotFound(_)) => {
                                    Ok(None)
                                }
                                Err(error) => Err(error),
                            }
                        },
                    )
                    .await;
                let cleanup = match found {
                    Ok(Some(handle)) => {
                        cleanup_control
                            .bounded(
                                "partial VM destruction",
                                Duration::from_secs(30),
                                handle.destroy(),
                            )
                            .await
                    }
                    Ok(None) => Ok(()),
                    Err(error) => Err(error),
                };
                report["vm_cleanup"] = json!(
                    cleanup
                        .as_ref()
                        .map_or("unconfirmed", |()| "confirmed absent")
                );
                if let Err(error) = cleanup {
                    report["cleanup_error"] = json!(error.to_string());
                }
                super::evidence::save(&evidence.join("report.json"), report)?;
                let error = failure.to_string();
                return Err(format!("VM creation failed or timed out: {error}").into());
            }
        };
        report["vm_id"] = json!(sandbox.id().to_string());
        let saved = super::evidence::save(&evidence.join("report.json"), report);
        let effective = (|| -> Result<()> {
            let effective_config = serde_json::to_value(sandbox.config())?;
            report["sdk_effective_config"] = effective_config.clone();
            super::resources::verify_vm_for(&effective_config, config.profile.memory_mib())?;
            super::evidence::save(&evidence.join("report.json"), report)?;
            Ok(())
        })();
        let outcome = if let Err(error) = saved.and(effective) {
            Err(error)
        } else {
            execute(
                &sandbox,
                &BOOTSTRAP.replace(
                    "size=128M",
                    &format!("size={}M", config.profile.workspace_mib()),
                ),
                "guest.log",
                evidence,
                control,
                Duration::from_hours(2),
            )
            .await
        };
        // Diagnostics are collected before destroying the VM, even on failure.
        let diagnostics = execute(
            &sandbox,
            DIAGNOSTICS,
            "journal.log",
            evidence,
            &Control::uncancelled(),
            Duration::from_secs(15),
        )
        .await;
        if let Err(error) = diagnostics {
            report["diagnostic_error"] = json!(error.to_string());
        }
        if let Ok(entries) = Control::uncancelled()
            .bounded(
                "VM logs",
                Duration::from_secs(15),
                sandbox.logs(&microsandbox::logs::LogOptions {
                    tail: Some(4096),
                    sources: vec![
                        microsandbox::logs::LogSource::System,
                        microsandbox::logs::LogSource::Stdout,
                        microsandbox::logs::LogSource::Stderr,
                        microsandbox::logs::LogSource::Output,
                    ],
                    ..Default::default()
                }),
            )
            .await
        {
            for entry in entries {
                if let Err(error) = super::process::append(&evidence.join("vm.log"), &entry.data) {
                    report["vm_log_error"] = json!(error.to_string());
                    break;
                }
            }
        }
        let cleanup = Control::uncancelled()
            .bounded(
                "VM destruction",
                Duration::from_secs(30),
                sandbox.destroy(),
            )
            .await;
        match cleanup {
            Ok(()) => report["vm_cleanup"] = json!("destroyed; runtime ownership released"),
            failure => {
                report["vm_cleanup"] = json!("unconfirmed");
                report["cleanup_error"] = json!(format!("{failure:?}"));
                super::evidence::save(&evidence.join("report.json"), report)?;
                return Err("VM cleanup not confirmed; inspect evidence".into());
            }
        }
        super::evidence::save(&evidence.join("report.json"), report)?;
        if let Ok(bytes) = fs::read(evidence.join("guest-report.json"))
            && let Ok(guest) = serde_json::from_slice::<Value>(&bytes)
        {
            report["guest"] = guest;
        }
        outcome?;
        let guest = report["guest"].clone();
        if guest["status"] != "passed"
            || guest["selected"] != report["selected"]
            || guest["profile"] != serde_json::to_value(config.profile)?
        {
            return Err("guest did not prove every selected gate".into());
        }
        if config.profile == super::config::Profile::Native {
            report["native"] = guest["native"].clone();
        }
        report["guest"] = guest;
        Ok(())
    }))
    .await;
    if report["vm_cleanup"]
        .as_str()
        .is_some_and(|status| status == "confirmed absent" || status.starts_with("destroyed;"))
    {
        compilation.confirm_inactive()?;
        drop(compilation);
        let cleanup_control = Control::uncancelled();
        report["compilation_cache_after"] = super::cache::prune(
            &compilation_root,
            super::cache::COMPILATION_LIMIT,
            &cleanup_control,
        )?;
        report["vendor_bytes"] = json!(super::cache::bytes(
            &cache.join("vendor"),
            &cleanup_control
        )?);
        report["image_cache_bytes"] = json!(super::cache::bytes(
            &cache.join("microsandbox/cache"),
            &cleanup_control
        )?);
    }
    if report["vm_cleanup"]
        .as_str()
        .is_some_and(|status| status == "confirmed absent" || status.starts_with("destroyed;"))
    {
        fs::remove_dir_all(&runtime_home)?;
        report["vm_runtime_home_cleanup"] = json!("removed after confirmed VM cleanup");
    } else {
        report["vm_runtime_home_cleanup"] = json!("preserved for diagnosis");
    }
    outcome
}

pub(super) async fn execute(
    sandbox: &Sandbox,
    script: &str,
    name: &str,
    evidence: &Path,
    control: &Control,
    timeout: Duration,
) -> Result<()> {
    control.check()?;
    let mut stream = control
        .bounded(
            "guest exec startup",
            Duration::from_secs(30),
            sandbox.exec_stream_with("/bin/bash", |options| {
                options
                    .args(["-euxo", "pipefail", "-c", script])
                    .timeout(timeout)
            }),
        )
        .await?;
    let started = std::time::Instant::now();
    loop {
        tokio::select! {
            event = stream.recv() => match event {
                Some(ExecEvent::Stdout(bytes) | ExecEvent::Stderr(bytes)) => {
                    if let Err(error) = super::process::append(&evidence.join(name), &bytes) {
                        let _ = Control::uncancelled().bounded("guest exec termination", Duration::from_secs(5), stream.kill()).await;
                        return Err(error);
                    }
                    eprint!("{}", String::from_utf8_lossy(&bytes));
                }
                Some(ExecEvent::Exited { code: 0 }) => return Ok(()),
                Some(ExecEvent::Exited { code }) => return Err(format!("guest command exited {code}; {name}").into()),
                Some(ExecEvent::Failed(error)) => return Err(format!("guest exec failed: {error:?}").into()),
                Some(ExecEvent::StdinError(error)) => return Err(format!("guest stdin failed: {error:?}").into()),
                Some(ExecEvent::Started { .. }) => {},
                None => return Err("guest stream ended without an exit status".into()),
            },
            () = tokio::time::sleep(Duration::from_millis(100)) => {
                if control.check().is_err() || started.elapsed() >= timeout {
                    let _ = Control::uncancelled().bounded("guest exec termination", Duration::from_secs(5), stream.kill()).await;
                    control.check()?;
                    return Err("guest command timed out".into());
                }
            }
        }
    }
}

// Provisioning affects only the new guest. The image already carries systemd,
// a non-root user and pinned Rust; never install packages into the caller host.
const BOOTSTRAP: &str = r#"
test "$(cat /proc/1/comm)" = systemd
for attempt in {1..100}; do test -d /run/systemd/system && break; sleep .1; done
test -d /run/systemd/system
for attempt in {1..300}; do
    if test -S /run/systemd/private && systemctl show --property=Version --value >/dev/null; then break; fi
    sleep .1
done
test -S /run/systemd/private
systemctl show --property=Version --value
test "$(id -u syrox)" = "$(stat -c %u /evidence)"
mkdir -p /cache/target /cache/cargo /work
mount -t tmpfs -o size=128M,nosuid,nodev tmpfs /work
test "$(stat -f -c %T /work)" = tmpfs
chown syrox:syrox /cache /work
for profile in release debug; do
    mkdir -p /target/x86_64-unknown-linux-gnu/$profile
    chown syrox:syrox /target/x86_64-unknown-linux-gnu/$profile
    ln -s /work/candidates/srx /target/x86_64-unknown-linux-gnu/$profile/srx
    ln -s /work/candidates/syrox-worker /target/x86_64-unknown-linux-gnu/$profile/syrox-worker
done
cat > /cache/cargo/config.toml <<'CONFIG'
[source.crates-io]
replace-with = "syrox-vendored"
[source.syrox-vendored]
directory = "/vendor"
CONFIG
systemctl start user@$(id -u syrox).service
for attempt in {1..100}; do test -S /run/user/$(id -u syrox)/bus && break; sleep .1; done
cp -a /sources /work/src
chown -R syrox:syrox /work/src
chmod -R u+w /work/src
if test -f /evidence/ecosystem-plan.json; then
    cp -a /ecosystem-sources /work/ecosystem
    chown -R syrox:syrox /work/ecosystem
    chmod -R u+w /work/ecosystem
fi
export XDG_RUNTIME_DIR=/run/user/$(id -u syrox)
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
/evidence/libtests/fixtures/deps/syrox--vm_guest --measure /evidence &
observer=$!
trap 'touch /evidence/measurement-stop; wait "$observer"' EXIT
for attempt in {1..100}; do test -f /evidence/measurement-ready && break; sleep .01; done
test -f /evidence/measurement-ready
/usr/sbin/runuser -u syrox -- env XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" PATH=/opt/node/bin:/opt/nvim/bin:/opt/rust/bin:/usr/bin:/bin bash -euxo pipefail -c '
cd /work/src
export RUST_TEST_THREADS=1 CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CARGO_HOME=/cache/cargo CARGO_TARGET_DIR=/cache/target/$(cat /evidence/compilation-key)
exec /evidence/libtests/fixtures/deps/syrox--vm_guest /evidence
'
"#;

const DIAGNOSTICS: &str = r#"
systemctl --no-pager --failed || true
uid=$(id -u syrox)
journalctl --no-pager -n 1000 _UID="$uid"
cat /proc/1/comm
cat /proc/version
cat /sys/fs/cgroup/cgroup.controllers
"#;

//! Run the native catalog qualifier under the pinned Linux VM kernel.
use super::{Result, common, config, host, process::Control, snapshot};
use microsandbox::{LocalBackend, Sandbox};
use serde_json::json;
use std::{fs, path::Path, sync::Arc, time::Duration};

pub fn main(args: &[String]) -> Result<()> {
    let [
        catalog,
        identity,
        build,
        store,
        evidence,
    ] = args
    else {
        return Err(
            "--qualify-catalog requires CATALOG IDENTITY BUILD_CONFIG STORE EVIDENCE".into(),
        );
    };
    if !snapshot::valid_digest(identity) {
        return Err("invalid catalog identity".into());
    }
    let catalog = Path::new(catalog).canonicalize()?;
    let build = Path::new(build).canonicalize()?;
    let store = Path::new(store);
    let evidence = Path::new(evidence);
    common::private(store)?;
    common::private(evidence)?;
    let store = store.canonicalize()?;
    let evidence = evidence.canonicalize()?;
    if evidence.join("qualification-vm.json").exists() {
        return Err("qualification evidence already exists".into());
    }
    let config = config::read_config()?;
    if config.profile != config::Profile::Native {
        return Err("catalog qualification requires the native VM profile".into());
    }
    let candidate = config
        .candidate_bundle
        .as_ref()
        .ok_or("pinned candidate bundle is required")?;
    let sources = snapshot::snapshot(&config::root(), &evidence.join("sources"))?;
    let catalog_sources = snapshot::snapshot(&catalog, &evidence.join("catalog"))?;
    let files = serde_json::from_value(sources["files"].clone())?;
    let bundle = super::candidate_bundle::load(candidate, &files, env!("CARGO_PKG_RUST_VERSION"))?;
    fs::write(evidence.join("build.toml"), fs::read(build)?)?;
    super::resources::require_host_for(config.profile.host_margin())?;
    let control = Control::new(None)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    let mut report = json!({"schema":1,"identity":identity,"environment":config,"candidate":{"target":bundle.target,"binaries":bundle.pins},"sources":sources,"catalog":catalog_sources,"status":"preparing","vm_cleanup":"not-started"});
    let outcome = runtime.block_on(async {
        microsandbox::config::set_sdk_msb_path(&config.runtime);
        microsandbox::set_libkrunfw_path(&config.firmware);
        let home = tempfile::Builder::new().prefix("srx-catalog-").tempdir()?;
        let backend: Arc<dyn microsandbox::Backend> = Arc::new(control.bounded("backend", Duration::from_mins(2), LocalBackend::builder().home(home.path()).cache_dir(config::root().join("target/vm-cache/microsandbox/cache")).logs_dir(evidence.join("runtime-logs")).build()).await?);
        if let Some(archive) = &config.image_archive {
            let images = control.bounded("guest image", Duration::from_mins(5), microsandbox::Image::load_local(backend.as_local().ok_or("local backend")?, archive, vec![config.image.clone()])).await?;
            if !images.iter().any(|image| image.reference() == config.image && image.manifest_digest() == config.image.rsplit_once('@').map(|(_,pin)|pin)) { return Err("guest image pin changed".into()); }
        }
        Box::pin(microsandbox::with_backend(backend, async {
            let name = format!("catalog-{}", host::run_id()?);
            let created = control.bounded("VM creation",Duration::from_mins(3), Sandbox::builder(&name).image(config.image.clone()).init("/usr/lib/systemd/systemd").cpus(1).max_cpus(1).memory(2048).max_memory(2048)
                .volume("/catalog",|v|v.bind(evidence.join("catalog")).readonly())
                .volume("/candidate",|v|v.bind(candidate).readonly())
                .volume("/store",|v|v.bind(&store).owner(1000,1000).quota(16384))
                .volume("/evidence",|v|v.bind(&evidence).owner(1000,1000).quota(8192)).create()).await;
            let sandbox = match created {
                Ok(sandbox) => sandbox,
                Err(error) => {
                    if let Ok(sandbox) = Sandbox::get(&name).await { sandbox.destroy().await?; }
                    report["vm_cleanup"] = json!("partial creation cleaned");
                    return Err(error);
                }
            };
            report["effective_config"] = serde_json::to_value(sandbox.config())?;
            let command = format!("{BOOTSTRAP}\n/usr/sbin/runuser -u syrox -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus /candidate/srx catalog qualify /work/catalog --identity {identity} --config /evidence/build.toml --store /store --output /evidence/results");
            let effective = super::resources::verify_vm_for(&report["effective_config"], 2048);
            let outcome = if let Err(error) = effective { Err(error) } else { host::execute(&sandbox,&command,"qualification.log",&evidence,&control,Duration::from_hours(2)).await };
            let cleanup = Control::uncancelled().bounded("VM destruction",Duration::from_secs(30),sandbox.destroy()).await;
            report["vm_cleanup"] = json!(if cleanup.is_ok() {"destroyed"} else {"unconfirmed"});
            if cleanup.is_err() { let _ = home.keep(); }
            cleanup?;
            outcome
        })).await
    });
    config.validate()?;
    snapshot::verify_files(&evidence.join("sources"), &files)?;
    report["status"] = json!(if outcome.is_ok() {
        "passed"
    } else {
        "failed"
    });
    if let Err(error) = &outcome {
        report["error"] = json!(error.to_string());
    }
    common::save(&evidence.join("qualification-vm.json"), &report)?;
    outcome
}

const BOOTSTRAP: &str = r#"
test "$(cat /proc/1/comm)" = systemd
for attempt in {1..300}; do test -S /run/systemd/private && break; sleep .1; done
systemctl start user@1000.service
for attempt in {1..100}; do test -S /run/user/1000/bus && break; sleep .1; done
mkdir -p /work
mount -t tmpfs -o size=128M,nosuid,nodev tmpfs /work
cp -a /catalog /work/catalog
chown -R syrox:syrox /work/catalog
chmod -R u+w /work/catalog
"#;
